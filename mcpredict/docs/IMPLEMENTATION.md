# mcpredict — 구현 종합 정리

> 작성: 팀, 2026-04-26 17:00
> 9시간 해커톤 MVP 구현 결과·아키텍처·테스트·라이브 검증·협업 메타 단일 문서.
>
> 관련 문서: [`design/ARCHITECTURE.md`](../design/ARCHITECTURE.md) (계획·합의), [`docs/PITCH.md`](PITCH.md) (발표), [`docs/DEMO_SCRIPT.md`](DEMO_SCRIPT.md) (라이브 데모), [`README.md`](../README.md) (사용자 문서).

---

## 0. 한 줄 정의

Claude Code의 PreToolUse/PostToolUse Hook을 통해 모든 도구 호출(Bash·Read·Write·WebFetch·MCP)을 가로채, **LLM이 표명한 의도(직전 assistant 메시지)와 실제 도구 호출 인자(`tool_input`)의 의미적 정합성**을 host-side에서 검증하는 보안 가드레일. 단일 Go 정적 바이너리 (~3.2MB).

**차별 축**: 의도 컨텍스트 + 행위 인자의 hook 시점 교차 검증.
- AXME = 사람 정책 / Pipelock = 시그니처 / AgentArmor = 정적 PDG / KAIJU = plan-upfront
- mcpredict = **ReAct 동적 + 의도-행위 정합성**

---

## 1. 시스템 아키텍처

### 1.1 컴포넌트 다이어그램

```
사용자 ─► Claude Code
              │
              ├──► [PreToolUse hook] ──► mcpredict pre ──► allow/deny/ask
              │                              │
              │                              ▼
              │     ┌──────────────────────────────────────────┐
              │     │ stdin JSON                                │
              │     │   ↓                                       │
              │     │ hookio.Read → HookInput                   │
              │     │   ↓                                       │
              │     │ intent.Extract(transcript_path)           │
              │     │   ↓ (직전 assistant text)                 │
              │     │ scanner.Scan(tool_input) → DLP hits       │
              │     │ policy.Match(tool, args, intent, secret)  │
              │     │   ↓                                       │
              │     │ verdict.Combine([]Verdict) → 최엄결정     │
              │     │   ↓                                       │
              │     │ session.Touch + audit.Append (hash only)  │
              │     │   ↓                                       │
              │     │ hookio.Write → stdout JSON                │
              │     │   `{"hookSpecificOutput": {               │
              │     │      "permissionDecision": "deny",...}}`  │
              │     └──────────────────────────────────────────┘
              │
              ├──► (도구 실행 또는 차단)
              │
              └──► [PostToolUse hook] ──► mcpredict post ──► block/sanitize/pass
                                              │
                                              ▼ (응답 텍스트 분석)
                                     scanner.Scan(response) + injection.Scan
                                     verdict.Combine
                                     stdout `{"decision":"block",
                                              "additionalContext":"..."}`

저장소
├── ~/.claude/hooks/mcpredict          # 단일 정적 바이너리 (3.2MB)
├── ~/.mcpredict/policies/*.yaml       # 정책 (사용자 편집)
├── ~/.mcpredict/audit.jsonl           # append-only 감사 로그 (hash only)
└── ~/.mcpredict/sessions/*            # session.Recorder (현재 메모리 stub)
```

### 1.2 데이터 흐름 — 결정 트리

| 단계 | 입력 | 출력 |
|---|---|---|
| 1. hook 발화 | `stdin` JSON: `{session_id, transcript_path, hook_event_name, tool_name, tool_input, [tool_response], cwd, permission_mode}` | `hookio.HookInput` struct |
| 2. 의도 추출 | `transcript_path` (JSONL) | 마지막 `type:"assistant"` record의 content blocks 중 `type:"text"` 시간순 concat |
| 3. DLP scan | `string(tool_input)` (Pre) / `tool_response.result` (Post) | `[]scanner.Hit` (Gitleaks 11 패턴 + Shannon 엔트로피) |
| 4. 정책 매칭 | `(tool_name, tool_input map, intent, has_secret, prior_calls)` | `[]verdict.Verdict` |
| 5. injection scan (Post 전용) | response text | `[]injection.Hit` (12 패턴 + hidden Unicode Cf) |
| 6. verdict 결합 | 모든 verdict slice | 최엄 결정 (Allow < Warn < Deny), 동률 시 source별 reason 결합 |
| 7. 감사 기록 | verdict + meta | `audit.jsonl` 1줄 (intent_hash + tool_input_hash + verdict + reason + latency_ms) |
| 8. stdout 응답 | verdict | Pre: `hookSpecificOutput.permissionDecision` / Post: top-level `decision:"block"` + `additionalContext` |

### 1.3 fail-safe 정책

mcpredict 자체가 panic/timeout 시 — 사용자 영향 최소화:

| 모드 | 동작 | 설정 |
|---|---|---|
| **fail-warn** (기본) | `permissionDecision:"ask"` — 사용자 확인 요청 | 기본값 |
| fail-open | `allow` — 보안 약화 | `MCPREDICT_FAIL_MODE=open` |
| fail-closed | `deny` — 사용성 약화 | `MCPREDICT_FAIL_MODE=closed` |

타임아웃: hook 5s 예산 안에서 mcpredict는 자체 400ms 타임아웃 → exceed 시 fail-warn.

---

## 2. 모듈 구조 (실제 구현)

```
mcpredict/                                    총 ~2,500 LOC Go
├── cmd/mcpredict/                            # entry point (~424 LOC)
│   ├── main.go         57   서브커맨드 라우팅 (pre|post|init|version)
│   ├── pre.go         155   PreToolUse 파이프라인
│   ├── post.go        108   PostToolUse 파이프라인 + sanitize
│   ├── init.go         43   ~/.mcpredict 초기화
│   └── state.go        61   audit/session 핸들 공유
│
├── internal/
│   ├── hookio/io.go        107   stdin JSON 파싱 + stdout 응답 직렬화
│   ├── intent/intent.go    275   transcript JSONL 파서 + Verifier interface stub
│   ├── policy/policy.go    290   YAML 로더 + 매처 (intent_check 3 모드, sequence_prior, description_regex)
│   ├── scanner/scanner.go  114   Gitleaks 11 패턴 + Shannon 엔트로피
│   ├── injection/injection.go  155   prompt-injection 12 패턴 + hidden Unicode Cf 카테고리
│   ├── session/session.go   59   메모리 stub (sequence_prior 비활성, schema 보존)
│   ├── audit/audit.go      115   JSONL append + canonical-JSON sha256 + sync.Mutex
│   └── verdict/verdict.go  100   Decision/Verdict struct + Combine (최엄결정 + dedup)
│
├── examples/policies/baseline.yaml  146   11 룰 (RE2 호환, FP/FN 보강 후)
├── testdata/fixtures/                      9 시나리오 fixture
├── tests/e2e/binary_test.go               실 binary stdin pipe 테스트 9종
├── tools/audit-viewer/index.html          정적 HTML 9KB (verdict 카드 시각화)
├── install.sh                             멱등 patch + uninstall + V6 안내
├── design/ARCHITECTURE.md                 합의 문서 v1.1
├── docs/{PITCH,DEMO_SCRIPT,IMPLEMENTATION}.md
└── README.md
```

### 2.1 모듈별 책임 + 핵심 결정

| 모듈 | 책임 | 핵심 결정 |
|---|---|---|
| `hookio` | stdin/stdout 직접 IO | 입력 1MB cap (regex DoS 방지) / 출력 통일 (exit 2 fallback 폐기, A6) |
| `intent` | transcript JSONL → 직전 assistant text | content blocks 중 `type:"text"`만 시간순 concat / `Verifier` interface stub (룰기반 ↔ 임베딩 swap, A9) |
| `policy` | YAML 룰 매칭 | `tool` glob (`mcp__*`), `*_regex`, `contains_secret`, `sequence_prior`, `intent_check.{required,absent}_keyword` 3 모드 + `description_regex` (V2 발견) |
| `scanner` | DLP secret 검출 | RE2 stdlib, 1MB 입력 cap, 엔트로피 임계 (`generic-high-entropy` ≥ 4.5) |
| `injection` | prompt-injection 검출 | `ExtractText`는 `encoding/json` 재귀 (B-002 fix), Cf 카테고리로 hidden Unicode |
| `session` | 세션 누적 | 현재 메모리 stub. `Schema` const는 SQLite 부활 시 1줄 교체용 보존 |
| `audit` | append-only 로그 | Canonical-JSON sha256 (A11), 평문 미저장 (A8), 0600 perms, sync.Mutex (A10) |
| `verdict` | Decision/Combine | Allow < Warn < Deny, 동률 시 `"source: reason; source2: reason2"` 결합, RuleIDs/Source dedup |

### 2.2 인터페이스 계약

**hookio.HookInput** (Round 2 동결, V2 capture 기반):
```go
type HookInput struct {
    SessionID      string          `json:"session_id"`
    TranscriptPath string          `json:"transcript_path"`
    HookEventName  string          `json:"hook_event_name"`
    ToolName       string          `json:"tool_name"`
    ToolInput      json.RawMessage `json:"tool_input"`
    ToolResponse   json.RawMessage `json:"tool_response,omitempty"`
    CWD            string          `json:"cwd"`
    PermissionMode string          `json:"permission_mode,omitempty"`  // V2 발견
}
```

**verdict.Verdict**:
```go
type Decision string  // "allow" | "warn" | "deny"
type Verdict struct {
    Decision Decision
    Reason   string
    RuleIDs  []string
    Source   string  // "policy" | "dlp" | "injection"
}
func Combine(vs ...Verdict) Verdict  // 최엄결정 + dedup
```

**Pre 응답 vs Post 응답** (Anthropic spec 준수, A6 합의):
```json
// PreToolUse
{"hookSpecificOutput": {"hookEventName":"PreToolUse",
   "permissionDecision":"deny", "permissionDecisionReason":"..."}}

// PostToolUse  (top-level decision + additionalContext)
{"hookSpecificOutput": {"hookEventName":"PostToolUse",
   "additionalContext":"[mcpredict] tool response blocked..."},
 "decision":"block", "reason":"injection: ..."}
```

---

## 3. 정책 카탈로그

`examples/policies/baseline.yaml` — 11 룰. `~/.mcpredict/policies/baseline.yaml`로 install 시 배포.

| ID | 도구 | 트리거 | 의도 검증 | 결정 | 시나리오 |
|---|---|---|---|---|---|
| `bash-curl-pipe-shell` | Bash | `curl ... \| sh` / `<(curl)` / `$(curl)` | required: install/설치/setup/공식설치 | deny | 1 (의도-행위 불일치) |
| `bash-curl-pipe-shell-description-mismatch` | Bash | curl 파이프 + description="install" | required (intent에 install 없음) | warn | description 위장 의심 |
| `bash-wget-pipe-shell` | Bash | wget 파이프/substitution | required: install/설치/setup | deny | curl과 동일 |
| `secret-in-tool-input` | any | scanner Hit ≥ 1 | — | deny | 2 (자격증명) |
| `webfetch-after-secret-read` | WebFetch | sequence_prior: Read `.env`/`.aws/`/`.ssh/id_*` | — | deny | 자격증명 외부 전송 (※ session stub로 비활성) |
| `bash-env-cat-and-curl` | Bash | `cat .env \| curl` 또는 `env \| curl` | — | deny | 2 보강 |
| `webfetch-http-plaintext` | WebFetch | `^http://` (RE2 호환, localhost 별도 처리) | — | warn | MITM/injection 위험 신호 |
| `search-intent-vs-write-action` | Bash/Write/Edit | `^` 또는 `[;&\`$(]` 뒤 `rm -rf`/`git push --force`/`drop table` | absent: 삭제/delete/force push/리셋/초기화 | deny | 검색 의도 + 파괴 행위 (FP 보강 위치 anchor) |
| `bash-rm-rf-root` | Bash | 시작 위치 `rm -rf /(공백/끝/*)` 또는 `--no-preserve-root` | — | deny | 의도 무관 절대 차단 |
| `mcp-filesystem-write-ssh-keys` | `mcp__filesystem__*` | `file_path_regex: \.ssh/(authorized_keys\|id_*)` | — | deny | 5 (MCP 권한 상승) |
| `mcp-github-public-secret` | `mcp__github__*` | `contains_secret: true` | — | deny | MCP issue/comment leak |

**FP/FN 보강 (16:30~16:40)**:
- FN: process substitution `<(curl)` + command substitution `$(curl)` OR로 묶음
- FP: 파괴 행위 정규식에 위치 anchor `(?:^|[;&\`]|\$\()` 추가 → echo 인자 안 패턴 면제

---

## 4. 테스트 — 38종 3계층 PASS

| 계층 | 위치 | 케이스 | 검증 대상 |
|---|---|---|---|
| **단위** 20 | `internal/*/`*_test.go` | verdict 4 + policy 6 + scanner 5 + injection 5 | 함수 단위 입출력 |
| **통합** 9 | `internal/policy/integration_test.go` | sce-1·1-with-intent·2·3·4·5·6·7·8·9 | 실 baseline.yaml + fixture로 deny/allow 결정 |
| **e2e** 9 | `tests/e2e/binary_test.go` | 실 binary `go build` 후 stdin pipe → 응답 JSON 매칭 | hookio → 모든 모듈 → hookio.Write 풀 파이프라인 |

```
$ go test ./internal/... ./tests/e2e/...
ok  internal/injection 0.301s
ok  internal/intent    (cached)
ok  internal/policy    1.110s    9 통합 케이스 PASS
ok  internal/scanner   (cached)
ok  internal/verdict   (cached)
ok  tests/e2e          7.037s    9 e2e 케이스 PASS
```

### 4.1 회귀 방지 fixture (D-014)

| Fixture | 보호 대상 |
|---|---|
| `sce-3-context-poisoning.json` | B-002 (ExtractText 단순 string lookup 회귀) |
| `sce-6-bypass-process-substitution.json` | FN-1 (16:30 정규식 OR 회귀) |
| `sce-7-bypass-command-substitution.json` | FN-2 (cmd substitution 회귀) |
| `sce-8-fp-echo-rm-pattern-allowed.json` | FP-1 (16:35 위치 anchor 회귀) |
| `sce-9-fp-echo-git-force-allowed.json` | FP-2 (echo arg git push 회귀) |

---

## 5. 라이브 검증 결과 (16:00~16:50)

세션 재시작 후 실 Claude Code 환경에서 모든 도구 호출이 mcpredict를 통과.

### 5.1 §7 검증 라이브 PASS

| 항목 | 결과 | 증거 |
|---|---|---|
| **V1 hook 실 발화** | ✓ | `~/.mcpredict/audit.jsonl` 52+ 라인, UUID session_id (`e559c3a1-...`, `361b6637-...`) |
| **V2 tool_input 스키마** | ✓ | `permission_mode` 필드 포함, 도구별 키맵 일치 |
| **V3 transcript JSONL** | ✓ | content blocks `type ∈ {thinking, text, tool_use}` 분리 확인 |
| **V4 deny 실 차단** | ✓ | `PreToolUse:Bash hook blocking error from command... policy: 외부 스크립트... 의도-행위 불일치.` 사용자 화면 노출 |
| **V5 latency** | ✓ | hot path 10~40ms (V5 측정과 일치) |
| **V6 in-session reload** | △ | 미명시 → 재시작 게이트로 해소 (install.sh echo 안내) |

### 5.2 차별 축 라이브 입증

동일 `curl ... | bash` 패턴이 **직전 assistant 의도에 따라 다른 verdict**:

| 시각 | command | 직전 의도 | verdict |
|---|---|---|---|
| 06:40:22.563 | `echo "...curl ... \| bash"` | "install" 키워드 포함 (보고 메시지에 npm install 등) | **allow** |
| 06:41:03.943 | `printf '...curl ... \| bash...'` | "install" 부재 (간단 답변) | **deny** ← rule `bash-curl-pipe-shell` |

> **단순 시그니처 매칭(Pipelock)이라면 둘 다 deny했을 것. 의도 컨텍스트가 결정을 분기시킨다 — 이게 mcpredict의 차별 축이 코드와 라이브 환경 모두에서 동작하는 증거.**

### 5.3 FP/FN 라이브 sweep (16:30~16:40)

| 발견 | 케이스 | 보강 |
|---|---|---|
| **FN-1** allow | `bash <(curl ...)` process substitution | 정규식에 `<\([^)]*\bcurl\b` OR 추가 → deny |
| **FN-2** allow | `eval "$(curl ...)"` cmd substitution | 정규식에 `\$\([^)]*\bcurl\b` OR 추가 → deny |
| **FN-3** allow | `python3 -c "$(curl ...)"` | 동일 OR 매치 → deny |
| **FP-1** deny | `echo "...rm -rf /tmp/x..."` 단순 출력 | `search-intent-vs-write-action` 정규식에 위치 anchor `(?:^|[;&\`]|\$\()` 추가 → allow |
| **FP-2** deny | `echo "...git push --force..."` 단순 출력 | 동일 anchor → allow |
| trade-off | `echo "AKIAIOSFODNN..."` (예시·문서) deny | **의도된 보수성** — 자격증명이 어디든 등장하면 차단 (chat·log 노출 방지). 한계로 명시 |

---

## 6. 알려진 한계 (정직)

### 6.1 SPEC §9 (상위 설계 단계)
- LLM이 의도까지 일관되게 거짓 → 우회 가능 (단 공격 비용 증가)
- MCP 서버 자체 외부 트래픽 비가시 (cross-server 격리는 MCP 설계 원칙)
- Claude Code 종속 (Cursor/Cline 미지원)
- Hook spec 진화 중
- PostToolUse 비가역 (외부 fetch는 일어남, 컨텍스트 진입만 차단)
- 동기 500ms — LLM 호출 검증은 비동기 audit-only

### 6.2 라이브 검증으로 추가 발견
- `tool_input.description` attack vector — LLM이 거짓 부착 가능 (`*-description-mismatch` 룰로 부분 완화)
- `mcp__*` 동적 키맵 — 실 MCP 서버마다 필드명 다름 (matcher 패턴 도구별 추가 필요)
- V6 in-session reload 한계 — 새 settings.json은 새 세션에서만 활성
- Session 누적 비활성 — Go 1.19 ↔ modernc/sqlite v1.50 호환성 → `webfetch-after-secret-read` 같은 sequence_prior 룰 미작동
- DLP 보수성 — 단순 echo로 자격증명 형식 출력해도 차단
- 우회 패턴 무한 — base64·obfuscated 명령은 정규식으로 못 잡음 (임베딩 의미 검증이 미래 보강)

---

## 7. 빌드·배포

### 7.1 의존성

| 패키지 | 용도 |
|---|---|
| Go stdlib (`encoding/json`, `regexp` RE2, `crypto/sha256`, `sync`) | 핵심 |
| `gopkg.in/yaml.v3` | 정책 파싱 |
| (deferred) `modernc.org/sqlite` | session.Recorder Go 1.20+에서 부활 |

### 7.2 빌드

```bash
go build -o mcpredict ./cmd/mcpredict   # 3.2MB 정적 바이너리, Go 1.19+
```

### 7.3 install.sh

1. `go build` → `~/.claude/hooks/mcpredict`
2. `~/.mcpredict/{policies, sessions}` 생성, baseline.yaml 배포 (0600)
3. `~/.claude/settings.json` jq 멱등 patch (Pre matcher `.*`, Post matcher `WebFetch|WebSearch|Read|mcp__.*`, 기존 hook 보존)
4. `--uninstall` 옵션
5. **echo로 "Claude Code 재시작 필요 (V6 게이트)" 사용자 안내**

---

## 8. 디렉토리 구조

```
mcpredict/
├── README.md                          # 사용자 진입 문서
├── CLAUDE.md                          # 협업 컨텍스트 (자동 로드)
├── DEMO.md                            # 빠른 데모 안내
├── go.mod
├── install.sh                         # 멱등 patch + uninstall + V6 안내
├── demo.sh
├── design/
│   └── ARCHITECTURE.md                # v1.1 합의 문서
├── docs/
│   ├── PITCH.md                       # 발표 자료 16+ 슬라이드
│   ├── DEMO_SCRIPT.md                 # 라이브 데모 대본
│   └── IMPLEMENTATION.md              # 본 문서
├── cmd/mcpredict/                     # entry point (~424 LOC)
│   ├── main.go
│   ├── pre.go / post.go
│   ├── init.go / state.go
├── internal/                          # 핵심 로직 (~2,100 LOC)
│   ├── hookio/io.go
│   ├── intent/{intent.go, intent_test.go}
│   ├── policy/{policy.go, policy_test.go, integration_test.go}
│   ├── scanner/{scanner.go, scanner_test.go}
│   ├── injection/{injection.go, injection_test.go}
│   ├── session/session.go             # 메모리 stub
│   ├── audit/audit.go
│   └── verdict/{verdict.go, verdict_test.go}
├── examples/policies/baseline.yaml    # 11 룰
├── testdata/fixtures/                 # 9 시나리오
│   ├── sce-1-curl-pipe-mismatch.json
│   ├── sce-1-curl-pipe-with-intent.json
│   ├── sce-2-credential-exfil.json
│   ├── sce-3-context-poisoning.json
│   ├── sce-4-benign-npm-install.json
│   ├── sce-5-mcp-filesystem-ssh.json
│   ├── sce-6-bypass-process-substitution.json   # 회귀 방지
│   ├── sce-7-bypass-command-substitution.json   # 회귀 방지
│   ├── sce-8-fp-echo-rm-pattern-allowed.json    # 회귀 방지
│   └── sce-9-fp-echo-git-force-allowed.json     # 회귀 방지
├── tests/
│   ├── e2e/binary_test.go             # 실 binary 9 케이스
│   └── coverage/run.sh
├── tools/audit-viewer/
│   ├── index.html                     # 정적 HTML 9KB (verdict 카드)
│   └── README.md
```

---

## 9. 사용 예

### 9.1 install
```bash
# 프로젝트 루트에서
./install.sh
# → ~/.claude/hooks/mcpredict 배포
# → ~/.claude/settings.json hooks 패치
# → "Claude Code 재시작 필요" 안내
```

### 9.2 정책 직접 호출 (테스트)
```bash
cat testdata/fixtures/sce-1-curl-pipe-mismatch.json | \
  env MCPREDICT_POLICY=$PWD/examples/policies/baseline.yaml \
  ~/.claude/hooks/mcpredict pre
# → {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
```

### 9.3 audit 시각화
```bash
open tools/audit-viewer/index.html
# → file picker로 ~/.mcpredict/audit.jsonl 선택 → verdict 카드
```

### 9.4 uninstall
```bash
./install.sh --uninstall
```

---

## 10. 한 줄 마무리

> **MCP 보안의 진짜 진입점은 transport가 아니라 agent lifecycle.** Anthropic 공식 hook spec으로 LLM 표명 의도와 실제 `tool_input`의 정합성을 host-side에서 교차 검증. 38종 테스트 PASS, 라이브 환경에서 V1+V4+차별 축 입증, FP/FN sweep 후 11개 한계 정직 명시.
>
> AXME = 사람 정책 / Pipelock = 시그니처 / AgentArmor = trace
> **mcpredict = 의도 컨텍스트 + 행위 인자의 hook 시점 교차 검증.**
