# mcpredict — 시스템 구조 설계

> 작성: 팀, 2026-04-26 14:55
> 갱신: v1.1 (15:05) — 팀의 A1~A9 회신 반영
> 상태: **검증-비의존부 합의 라운드 진행 중**, 검증-의존부는 §11 Open Questions에서 V1~V5 결과 대기
> 합의 후 본 문서가 mcpredict 구현의 기준 문서가 됨.

---

## 0. 본 문서의 위치

본 문서는 `mcpredict — 최종 설계 문서`(상위 설계, 위협 모델·차별 축·시나리오)의 **하위 구현 설계**다. 상위 결정은 변경하지 않고, 그 결정을 코드 모듈·인터페이스·데이터 스키마로 구체화한다.

차별 축 재확인 (절대 후퇴 금지):
> 직전 assistant 메시지(의도)와 `tool_input`(행위)의 의미적 정합성을 hook 시점 교차 검증.

본 문서의 합의 라운드는 **2단계**로 분리:
- **Round 1 (검증-비의존부)**: 모듈 경계, Verdict struct, 정책 YAML 스키마, audit/SQLite 스키마, 빌드·배포, fail-safe, 작업 분담 — 팀 검증 결과 없이 합의 가능
- **Round 2 (검증-의존부)**: `tool_input` 키맵, deny 인터페이스, latency 모드 — V1~V5 결과 후 동결

---

## 1. 컴포넌트 구성

```
                ┌──────────────────────────────────────────┐
                │              Claude Code                 │
                │                                          │
                │   tool_call ──► [PreToolUse hook] ──┐    │
                │                                     │    │
                │                                     ▼    │
                │              ┌──────────────────────┴──┐ │
                │              │   mcpredict (Go bin)    │ │
                │              │                         │ │
                │              │ ┌──pre / post entry──┐  │ │
                │              │ │                    │  │ │
                │              │ │ ┌─intent──┐        │  │ │
                │              │ │ │ parser  │        │  │ │
                │              │ │ └────┬────┘        │  │ │
                │              │ │      ▼             │  │ │
                │              │ │ ┌─policy─┐ ┌─dlp─┐ │  │ │
                │              │ │ │ matcher│ │ scan│ │  │ │
                │              │ │ └────┬───┘ └──┬──┘ │  │ │
                │              │ │      └───┬────┘    │  │ │
                │              │ │          ▼         │  │ │
                │              │ │     verdict        │  │ │
                │              │ │     ┌──┴──┐        │  │ │
                │              │ │     ▼     ▼        │  │ │
                │              │ │  session  audit    │  │ │
                │              │ │   (SQLite)(JSONL)  │  │ │
                │              │ └────────────────────┘  │ │
                │              └──────────┬──────────────┘ │
                │                         ▼                │
                │              hookSpecificOutput JSON     │
                │   tool_call ◄─── [PreToolUse 결과] ───┘  │
                │                                          │
                │   tool_response ──► [PostToolUse hook]   │
                │                  ──► (위와 동일 흐름)    │
                │                  ──► sanitized response  │
                │                                          │
                └──────────────────────────────────────────┘

저장소:
  ~/.mcpredict/policies/*.yaml   (정적 정책)
  ~/.mcpredict/session.db        (세션 누적)
  ~/.mcpredict/audit.jsonl       (감사 로그)
```

---

## 2. 데이터 흐름

### 2.1 PreToolUse

1. Claude Code → stdin JSON → `mcpredict pre`
2. `intent.Extract(transcript_path)` → 직전 assistant 텍스트
3. `policy.Match(tool_name, tool_input, intent_text)` → []RuleHit
4. `scanner.Scan(serialize(tool_input))` → []DLPHit  ※ 자격증명 외부 전송 사전 차단
5. `verdict := combine(rule_hits, dlp_hits)` (가장 엄격한 결정 채택)
6. `session.Record(session_id, "pre", tool_name, verdict)`
7. `audit.Append(record)` (해시만 저장)
8. stdout `hookSpecificOutput` JSON → Claude Code

### 2.2 PostToolUse

1. Claude Code → stdin JSON (`tool_response` 포함) → `mcpredict post`
2. `scanner.Scan(tool_response)` → DLP 검출 (외부에서 들어온 PII 차단)
3. `injection.Detect(tool_response)` → injection 패턴 검출 (`Ignore previous`, `<system>`, hidden unicode 등)
4. `verdict := combine(...)`
5. 행위는 이미 발생 — 차단 대상은 **응답이 LLM 컨텍스트에 진입하는 것**. sanitize 또는 deny.
6. `session.Record(session_id, "post", tool_name, verdict)`
7. audit append.

---

## 3. 모듈·패키지 경계 (Go)

```
mcpredict/
├── cmd/mcpredict/
│   ├── main.go        # os.Args[1] switch → pre|post|init
│   ├── pre.go         # PreToolUse entry
│   └── post.go        # PostToolUse entry
├── internal/
│   ├── hookio/        # stdin JSON 파싱 / stdout 응답 직렬화 (hookSpecificOutput)
│   ├── intent/        # transcript_path JSONL 파서 + Verifier interface (A9)
│   ├── policy/        # YAML 로더, Rule struct, 매칭 엔진
│   ├── scanner/       # Gitleaks 정규식 + 엔트로피 검출
│   ├── injection/     # PostToolUse용 prompt-injection 패턴 검출
│   ├── session/       # SQLite (modernc.org/sqlite). 세션 누적·시그니처
│   ├── audit/         # JSONL append-only 로거 (해시만, 평문 미저장)
│   └── verdict/       # Verdict struct, Combine(가장 엄격) 함수
├── examples/policies/ # 기본 정책 YAML 3~5개
├── testdata/          # fixture JSON (시나리오별)
├── install.sh         # ~/.claude/settings.json 패치 + 바이너리 배포
└── go.mod
```

**책임 분리 원칙**:
- `hookio`만 stdin/stdout 직접 만짐. 다른 모듈은 struct만 다룸 → 단위 테스트 용이.
- `policy`는 `intent.Result`를 입력으로 받지만 transcript_path를 직접 안 다룸 → mock 가능.
- `audit`은 모든 모듈에서 호출 가능. 단 동기 fail은 무시 (audit 실패가 도구 차단으로 이어지면 안 됨).

---

## 4. 인터페이스 정의

### 4.1 Hook 입력/출력

**입력 (잠정 — V2/V3 확정 후 동결)**:
```go
// internal/hookio
type HookInput struct {
    SessionID      string          `json:"session_id"`
    TranscriptPath string          `json:"transcript_path"`
    HookEventName  string          `json:"hook_event_name"`  // PreToolUse | PostToolUse
    ToolName       string          `json:"tool_name"`
    ToolInput      json.RawMessage `json:"tool_input"`
    ToolResponse   json.RawMessage `json:"tool_response,omitempty"` // Post only
    CWD            string          `json:"cwd"`
}
```

**출력 (A6 합의 — stdout JSON 통일, exit code는 보조용)**:
```go
type HookOutput struct {
    HookSpecificOutput struct {
        HookEventName            string `json:"hookEventName"`            // "PreToolUse"
        PermissionDecision       string `json:"permissionDecision"`       // allow | deny | ask
        PermissionDecisionReason string `json:"permissionDecisionReason"`
    } `json:"hookSpecificOutput"`
    SystemMessage string `json:"systemMessage,omitempty"` // LLM 컨텍스트 주입용
}
```

**Exit code 규약**:
- `0` = 정상 종료. 결정은 stdout JSON 본문이 캐리.
- 그 외 = mcpredict 내부 오류 → fail-safe 정책 적용 (§7).
- exit 2 fallback은 사용 안 함 (stderr 노출 위험 + 상위 전파 모호 — A6 근거).

### 4.2 Verdict

```go
// internal/verdict
type Decision string
const (
    Allow Decision = "allow"
    Warn  Decision = "warn"
    Deny  Decision = "deny"
)

type Verdict struct {
    Decision Decision
    Reason   string
    RuleIDs  []string  // 매칭된 rule ID 목록
    Source   string    // policy | dlp | injection
}

func Combine(vs ...Verdict) Verdict  // 가장 엄격한 결정 채택. 동률은 RuleIDs 합치고 Source는 다중.
```

`Decision`을 `HookOutput.permissionDecision`으로 매핑:
- `Allow` → `"allow"`
- `Warn`  → `"ask"` (사용자 확인 요청)
- `Deny`  → `"deny"`

### 4.3 정책 YAML 스키마

```yaml
version: 1
rules:
  - id: bash-curl-pipe-shell
    description: "curl|bash 패턴은 의존성 설치 의도일 때만 허용"
    when:
      tool: Bash
      command_regex: '\bcurl\b[^|]*\|\s*(?:sh|bash|zsh)'
    intent_check:
      mode: required_keyword       # required_keyword | absent_keyword | none
      keywords: ["install", "설치", "setup", "공식 설치 스크립트"]
      threshold: 1
    action: warn                   # allow | warn | deny
    reason: "외부 스크립트 직접 실행. 의존성 설치 의도가 명시되어야 함."

  - id: secret-in-tool-input
    when:
      tool: any
      contains_secret: true        # scanner.Scan 결과 사용
    action: deny
    reason: "자격증명/PII가 도구 인자에 평문 노출"

  - id: webfetch-after-secret-read
    when:
      tool: WebFetch
      sequence_prior: { tool: Read, path_regex: '(\.env|credentials)' }
    action: deny
    reason: "자격증명 파일 읽기 직후 외부 fetch — 외부 전송 패턴"
```

**`tool_input` 매칭 키맵 (A4 합의 — 잠정, V2 capture로 동결)**:
```yaml
tool_input_keys:
  Bash:     [command]
  Write:    [file_path, content]
  Edit:     [file_path, old_string, new_string]
  Read:     [file_path]
  WebFetch: [url, prompt]
  Glob:     [pattern, path]
  Grep:     [pattern, path]
  "mcp__*": "*"   # server-defined, 동적
```

### 4.4 audit.jsonl 스키마 (A3 합의)

각 라인 1 JSON:
```json
{
  "ts": "2026-04-26T14:55:00.123Z",
  "session_id": "...",
  "hook_event": "PreToolUse",
  "tool_name": "Bash",
  "verdict": "deny",
  "source": "policy",
  "rule_ids": ["bash-curl-pipe-shell"],
  "reason": "...",
  "intent_hash": "sha256:...",       // 직전 assistant text 해시
  "tool_input_hash": "sha256:...",   // canonical tool_input JSON 해시
  "raw_input_path": null,            // 디버그 모드에서만 채움
  "latency_ms": 42
}
```

**원칙 (A3·A8 합의)**:
- append-only, 파일 권한 0600
- intent/tool_input 평문 미저장. hash로 dedup·correlation
- `raw_input_path`는 `MCPREDICT_DEBUG=1` 일 때만 `experiments/captures/<ts>.json` 경로 채움
- HMAC 무결성 서명은 future work

### 4.5 SQLite 스키마 (A5 합의)

```sql
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  started_at INTEGER NOT NULL,    -- unix ms
  cwd TEXT,
  tool_count INTEGER DEFAULT 0
);

CREATE TABLE tool_calls (
  rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  ts INTEGER NOT NULL,
  hook_event TEXT NOT NULL,        -- pre | post
  tool_name TEXT NOT NULL,
  verdict TEXT,                    -- pre: allow|warn|deny / post: ok|sanitized|blocked
  reason TEXT
);

CREATE INDEX idx_tool_calls_session ON tool_calls(session_id, ts);
```

세션 시그니처(언어/CWD/도구 빈도)는 future. `sessions`에 컬럼 추가만.

---

## 5. 외부 의존성

| 의존 | 용도 | 비고 |
|---|---|---|
| `modernc.org/sqlite` | SQLite | cgo-free, cold start 친화 |
| `gopkg.in/yaml.v3` | 정책 파싱 | 표준 |
| `regexp` (stdlib) | DLP / command_regex | RE2, ReDoS 안전 |
| `encoding/json` (stdlib) | hook IO | 충분 |

**임베드 데이터**:
- Gitleaks 룰셋 일부 5~10개 (`go:embed`로 정적 포함)
- 기본 정책 YAML (사용자 정책 부재 시 fallback)

---

## 6. 빌드·배포

- `go build -o mcpredict ./cmd/mcpredict` → 단일 정적 바이너리 (~10MB 추정)
- `install.sh`:
  1. 바이너리를 `~/.claude/hooks/mcpredict`로 복사
  2. `~/.mcpredict/{policies,}` 디렉토리 생성, 기본 정책 YAML 배포
  3. `~/.claude/settings.json`에 hooks 섹션 patch (jq 사용, 기존 hook 보존)
  4. `mcpredict init` 으로 SQLite 스키마 생성

---

## 7. Fail-safe 정책

mcpredict 자체가 panic/crash/timeout → 무엇을 할 것인가?

| 모드 | 동작 | 채택 |
|---|---|---|
| fail-open | 모든 도구 통과 | ✗ 보안 도구로서 약함 |
| fail-closed | 모든 도구 차단 | ✗ 사용성 파괴 |
| **fail-warn** | warn(`ask`)으로 강등, 사용자 confirm 요청 | **✓ 기본** |

env var `MCPREDICT_FAIL_MODE=open|closed|warn` 로 전환 가능.

타임아웃: hook 동기 실행 500ms 예산 안에서 mcpredict는 **400ms 자체 타임아웃** — exceed 시 fail-warn.

---

## 8. 성능 전략 (A2 합의)

### 8.1 모드 1: command (기본)
- 매 hook마다 `mcpredict pre|post` fork+exec
- Cold start: macOS Go 정적 바이너리 30~80ms 예상 (A2)
- 룰 매칭+DLP: <50ms (RE2)
- 합 <130ms 목표 → 500ms 예산 안

### 8.2 모드 2: HTTP daemon (V5에서 200ms 초과 시 fallback)
- `mcpredict daemon` 백그라운드 listen (UNIX socket)
- hook command는 thin shell client
- 9시간 MVP에서는 미구현 — V5 결과로만 결정. **모드 2 미리 짜진 않음** (YAGNI).

### 8.3 비동기 검증 (A9 — 인터페이스 stub만)
```go
// internal/intent
type Verifier interface {
    Score(intent, action string) float64  // 0.0~1.0, 1.0=정합
}
// 룰 기반 구현(기본) + 임베딩 구현(future) swap
```
임베딩 기반 의미 유사도는 audit log에만 사후 score 기록. hook은 차단 안 함.

---

## 9. 보안 / 신뢰 경계

| 입력 | 신뢰 | 처리 |
|---|---|---|
| tool_input (Claude가 만든 인자) | 부분 신뢰 | injection 가능 — regex match 시 size cap, regex timeout |
| transcript의 user content | **불신** | regex로 injection 시그니처 검출 (intent 추출 시 user 부분 제외) |
| transcript의 assistant content | 부분 신뢰 | LLM이 외부 콘텐츠를 echo한 경우 이미 오염 — §9 한계와 연결 |
| tool_response (Pre/Post) | **불신** | DLP + injection scan |
| ~/.mcpredict/policies/*.yaml | 신뢰 | 사용자 작성 |
| settings.json hook 등록 | 신뢰 | 사용자 작성 |

**Regex DoS 방지**: 모든 regex는 RE2(Go stdlib) 사용. 입력 텍스트는 1MB cap.

**Audit log 무결성**: append-only, 권한 0600. (HMAC 서명은 future work)

---

## 10. 에러 처리

- 정책 YAML 파싱 실패 → stderr 로그 + fail-warn (해당 rule만 skip)
- transcript JSONL 파싱 실패 → intent_text="" 로 진행. policy의 intent_check.required_keyword는 모두 fail → warn 또는 deny (정책 결정)
- SQLite write 실패 → silent (audit jsonl은 우선)
- audit.jsonl write 실패 → stderr 로그. hook 결과는 정상 반환 (감사 누락 != 도구 차단)

---

## 11. Open Questions (Round 2 — V1~V5 결과로 확정)

| ID | 질문 | 어떻게 풀리나 | 영향 받는 모듈 |
|---|---|---|---|
| **OQ-1** | PreToolUse가 `mcp__.*` 도구에 발화하는가? matcher 패턴은? | V1 결과 | settings.json patch (`install.sh`) |
| **OQ-2** | hook 입력 JSON의 `tool_input` 필드 스키마. 도구별로 다른가? | V2 결과 (도구 3종 이상 샘플) | `hookio.HookInput`, `policy.Rule.when` 매칭 키 |
| **OQ-3** | `transcript_path` JSONL의 assistant 메시지 구조. content blocks 배열인가? text 블록과 tool_use 블록 분리되는가? text 없이 tool_use만 있는 turn 있는가? | V3 결과 | `internal/intent` 파서 |
| **OQ-4** | deny 신호 검증: stdout `hookSpecificOutput.permissionDecision: "deny"`가 실제로 도구 실행을 차단하는가? `--dangerously-skip-permissions` 모드에서도 작동? | V4 결과 | A6 합의 검증 |
| **OQ-5** | e2e latency (cold start 포함). 500ms 예산 안에 들어오는가? | V5 결과 (3회 측정 평균) | command 모드 vs HTTP daemon 모드 결정 |
| **OQ-6** | session_id가 동일 세션에서 안정적인가? 도구 호출마다 변하는가? | V2 부산물 | session.db 식별자 |
| **OQ-7** | hook이 동시에 여러 번 호출될 수 있는가? (병렬 도구 호출) | V1/V2 부산물 | SQLite 락, audit append concurrency |
| **OQ-8** | (NEW) 팀의 14:51 capture가 **stub**(echo pipe-test)인가 **실 발화**인가? `session_id:"test"` 값으로 보아 stub 의심. 실 발화 capture가 있어야 V1 PASS. | 팀 re-test (settings watcher pickup 또는 `/hooks` reload 또는 Claude Code 재시작) | V1 진위, OQ-1~7 모두의 전제 |

팀은 검증 결과를 공유 게시판에 dump해주기로 함.

---

## 12. 작업 분담 매핑 (제안)

| 모듈 | 팀 | 팀 | 팀 |
|---|---|---|---|
| cmd/mcpredict (entry, 라우팅) | ✓ | | |
| internal/hookio | ✓ | | |
| internal/intent (transcript 파서, Verifier interface) | ✓ | | |
| internal/session (SQLite) | ✓ | | |
| internal/audit (JSONL) | ✓ | | |
| internal/policy (YAML 로더+매처) | | ✓ | |
| internal/scanner (Gitleaks DLP) | | ✓ | |
| internal/injection (PostToolUse) | | ✓ | |
| internal/verdict (combine) | | ✓ | |
| examples/policies/ | | ✓ | |
| testdata/ fixture JSON | 검증 결과 dump | 시나리오 fixture 변형 | |
| install.sh | ✓ | | |
| 발표 자료 / 슬라이드 | | ✓ | |
| 메시지 중계·합의 게이트·블로커 플래그 | | | ✓ |

---

## 13. 테스트 전략

- **단위**: 각 internal/* 모듈은 fixture JSON 입력 → 기대 verdict. testdata/에 체크인.
- **통합**: 검증 단계에서 capture한 raw hook JSON 재생 → end-to-end deny/allow 확인.
- **데모 fixture**: 시나리오 1·2·3 각각 deterministic JSON 1개. 라이브 데모 실패 시 즉시 대체 재생.
- **벤치**: `go test -bench` 로 룰 매칭 latency 측정. 50ms 회귀 시 CI 실패 (해커톤 후 단계).

---

## 14. 합의 게이트 (2-Round)

### Round 1 — 검증-비의존부 (now)

다음 항목 동의 시 코드 골격 작성 시작 가능:

| 항목 | 합의 상태 |
|---|---|
| §3 모듈 경계 | A1 동의 → ✓ |
| §4.2 Verdict struct·Combine | 미회신 — 동의 가정, 이견 시 알려줘 |
| §4.3 정책 YAML 스키마 (intent_check, sequence_prior 포함) | 미회신 — 동의 가정 |
| §4.4 audit.jsonl 키 셋 (hash 정책) | A3 동의 → ✓ |
| §4.5 SQLite 스키마 | A5 동의 → ✓ |
| §6 빌드·배포 (install.sh 단계) | 미회신 — 동의 가정 |
| §7 fail-warn 기본 모드 | 미회신 — 동의 가정 |
| §8 command 모드 1차 (A2) | A2 동의 → ✓ |
| §8.3 Verifier interface (A9) | A9 동의 → ✓ |
| §12 작업 분담 | A1 동의 (양도) → ✓ |
| §4.1 hook 출력 통일 (A6) | A6 동의 → ✓ |

팀·C, Round 1 항목 중 미회신/이견 있는 것만 inbox에 표시 부탁.

### Round 2 — 검증-의존부 (V1~V5 결과 후)

| 항목 | 트리거 |
|---|---|
| §4.1 HookInput 필드 동결 | OQ-2 (V2 capture) |
| §4.3 tool_input 키맵 동결 | OQ-2 (V2 capture) |
| `internal/intent` 파서 구체 구현 | OQ-3 (V3 transcript 샘플) |
| A6 deny 동작 확정 | OQ-4 (V4 실증) |
| 모드 1 vs 모드 2 결정 | OQ-5 (V5 latency) |
| OQ-8 capture 진위 | 팀 re-test |

---

## 15. 변경 로그

- 2026-04-26 14:55 — v1 초안 (팀). 검증 결과 대기.
- 2026-04-26 15:05 — v1.1. 팀의 A1~A9 회신 반영. 합의 게이트를 Round 1 / Round 2로 분리 (팀 제안). OQ-8 추가 (capture 진위 의혹).
