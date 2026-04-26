# mcpredict — 최종 산출물 결정 문서

> **결론 한 줄**: `2/`(member 2)를 코어 기반으로 채택하고, `3/`(member 3)의 **dashboard·bypass scanner·Docker 워크플로·unicode 우회 탐지**를 흡수해 단일 저장소 `mcpredict/`로 통합한다.
>
> 작성: 2026-04-26 | 분석 대상: `2/` (devlop2, ARCHITECTURE 합의 트랙) + `3/` (단독 트랙, dashboard 트랙)

---

## 0. 두 프로젝트의 동일 출발점

| 항목 | 공통 |
|---|---|
| 한 줄 정의 | Claude Code Pre/PostToolUse Hook을 통한 host-side AI agent guardrail |
| 차별 축 | LLM 의도(직전 assistant 메시지) ↔ tool_input(행위) 정합성 hook 시점 교차 검증 |
| 언어 | Go 1.22 (CGO 비활성, 단일 정적 바이너리) |
| 외부 의존 | `gopkg.in/yaml.v3` 단 하나 |
| 정책 | YAML 기반 룰 매처 |
| 검증 시점 | PreToolUse(차단 가능) + PostToolUse(컨텍스트 진입 차단) |
| 데이터 | `~/.mcpredict/{policies/, audit.jsonl, sessions/}` |

→ 동일 SPEC, 두 독립 구현. 차별 축이 단일 구현 우연이 아니라 spec 견고성임이 입증됨.

---

## 1. 심층 비교 — 정량

| 항목 | **`2/` (member 2)** | **`3/` (member 3)** |
|---|---|---|
| 진입점 (`cmd/`) | `cmd/mcpredict/{main,pre,post,init,state}.go` 5파일 ✓ | **❌ `cmd/mcpredict/` 디렉터리 누락** (Dockerfile·install.sh·.gitignore가 참조하나 커밋 안 됨 — `.gitignore`의 `mcpredict` 패턴이 디렉터리 자체를 ignore) |
| internal 패키지 수 | 8 (`hookio, intent, policy, scanner, injection, session, audit, verdict`) | 6 (`hook, intent, policy, scanner, audit, session, dashboard`) |
| 정책 룰 수 | 11 (`baseline.yaml`) | 14 (`default.yaml`) — bypass 룰 비중 ↑ |
| 정책 매처 표현력 | `intent_check` 3 모드 + `sequence_prior` + `description_regex` + `command/file_path/url_regex` + `contains_secret` + `mcp__*` glob | `event` + `tool_pattern` + `input_pattern` (단순 regex) |
| DLP 패턴 수 | 11 (Gitleaks subset + Shannon entropy 임계 4.5) | 10 + 고엔트로피(임계 4.8) + 마스킹 |
| 우회 탐지 | injection 12 패턴 + hidden Unicode Cf 카테고리 | **별도 `bypass.go` 14 패턴** (interpreter escape·base64·xxd·IFS·ANSI-C hex·env·path traversal·exec FD·tmpfile chmod·string concat) + **`ScanUnicodeBypass`(Cyrillic homoglyph + zero-width)** |
| Injection 패턴 | 12 (post용) | 7 (`ignore-previous, system-prompt-override, jailbreak-roleplay, unrestricted-mode, tool-call-injection, data-exfil-instruction, hidden-instruction-marker`) |
| 의도 검증 로직 | YAML `intent_check.{required,absent}_keyword` (정책 외부에서 정의) | **하드코딩된 `intentGroups`** (install/read/delete 3 그룹 — keyword + allowTools + denyBashRe) + 항시 `dangerousBashRe` |
| Audit | canonical-JSON sha256 + sync.Mutex + 0600 + intent/input 평문 미저장 (해시만, A8/A11) | sync.Mutex + 0600 + **input map 평문 저장** (privacy 약함) |
| Session 저장 | 메모리 stub (Go 1.19↔modernc/sqlite 충돌로 보류, schema 보존) | 미상 (코드 발췌 못함) |
| Fail-safe | `MCPREDICT_FAIL_MODE=open\|closed\|warn` (기본 warn) + 400ms self-timeout | (확인 어려움 — main 부재) |
| Hook 출력 | Pre/Post 분리 (Pre: `hookSpecificOutput.permissionDecision`, Post: top-level `decision:"block" + additionalContext`, A6 spec 준수) | `Output{decision, reason}` 단일 구조 (Post 별도 channel 안 보임) |
| 테스트 | **38종 PASS** (단위 20 + 통합 9 + e2e 9) — 실 binary stdin pipe e2e + B-002·FP·FN 회귀 방지 4종 fixture | 단위 테스트 4파일 (`policy, intent, dlp, bypass` *_test.go) — e2e/통합 별도 없음 |
| 시나리오 fixture | 9개 (1·1-with-intent·2·3·4·5·6·7·8·9) | 6개 (intent_mismatch·credential_exfil·prompt_injection·safe·base64_bypass·python_bypass) |
| **Dashboard** | 정적 HTML 9KB (`tools/audit-viewer/index.html`, file picker 로드) | **HTTP 서버 (`internal/dashboard/server.go`) — 임베디드 SPA, 2초 폴링, 실시간 stat 카드, 검색·필터, 다크 테마 (~280 LOC)** |
| 설치 워크플로 | `install.sh` 멱등 jq patch + `--uninstall` + V6 재시작 안내 | `install.sh --auto/--manual/interactive` 3 모드 + 백업(.bak) + Python 기반 settings patch |
| 빌드 환경 | host go build (`go build -o ...`) | **Docker first**: 멀티스테이지 Dockerfile (builder/tester/runtime) + docker-compose 7 서비스 + Makefile 13 타겟 |
| 문서 | `README + CLAUDE + DEMO + design/ARCHITECTURE(v1.1, 463줄) + docs/{PITCH, IMPLEMENTATION, DEMO_SCRIPT, coverage-matrix-results}` | `README + CLAUDE` (압축, 4030 byte) |
| 협업 메타 | 4-세션 병렬 (A·B·두뇌·C) + brain/board/inbox 인프라 + 합의 게이트 2-Round + D-001~D-015 결정 로그 | 단일 세션 (또는 미상) |
| 라이브 검증 | V1~V6 PASS 실증 (audit.jsonl 52+ UUID session_id, 차별 축 라이브 deny/allow 분기) | (미상 — README 기준) |

---

## 2. 심층 비교 — 정성

### 2.1 `2/`의 강점
1. **정책 표현력**. `intent_check`(required/absent keyword) + `sequence_prior`(직전 N 호출) + `description_regex`(LLM 위장 attack vector 부분 완화)는 단순 regex 매처보다 한 단계 위 추상화.
2. **Pre/Post 응답 spec 준수**. Anthropic 공식 hook spec(A6)대로 Pre는 `hookSpecificOutput`, Post는 top-level `decision`+`additionalContext` 분리. `3/`은 단일 출력 구조로 수렴되어 Post 컨텍스트 주입을 spec대로 못함.
3. **Audit privacy**. `intent_hash, tool_input_hash`만 저장(A8/A11 합의). `3/`은 `input map[string]any`를 평문 보관 → 자격증명 검출했더니 audit에 평문이 남는 모순.
4. **테스트 깊이**. 38종 3계층(단위·통합·e2e 실 binary stdin pipe) + B-002·FP·FN 회귀 방지 fixture. `3/`은 단위 테스트 4파일만.
5. **합의·결정 트레이스**. `ARCHITECTURE.md` v1.1, `IMPLEMENTATION.md`, `PITCH.md`, `DEMO_SCRIPT.md`, D-001~D-015 결정 로그 — 9시간 MVP의 의사결정 흐름을 추적 가능.
6. **라이브 검증된 차별 축**. 동일 `curl ... | bash`가 직전 의도("install" 키워드 유무)에 따라 06:40 allow / 06:41 deny로 분기되는 audit 증거가 있음. 단순 시그니처 매칭(Pipelock)이라면 둘 다 deny했을 것 — 차별 축이 코드 + 라이브 환경 모두에서 동작.
7. **Fail-safe 명세**. `MCPREDICT_FAIL_MODE=open|closed|warn` + 400ms self-timeout — 보안 도구로서 기본기.

### 2.2 `3/`의 강점
1. **Dashboard HTTP 서버**. `internal/dashboard/server.go`의 임베디드 SPA(~280 LOC, 다크 테마, 실시간 폴링, 통계 카드, 검색·필터)는 `2/`의 정적 HTML보다 라이브 데모·운영 가시성에서 압도적. **`2/`에 없는 단독 자산**.
2. **Bypass 패턴 카탈로그**. `bash <(curl)`, `eval $(curl)`은 `2/`도 잡지만, `3/`은 추가로:
   - `python -c '...subprocess'`, `perl -e '...system'`, `node -e '...child_process'`, `ruby -e '...IO.popen'` (interpreter sandbox escape)
   - `base64 -d | sh`, `xxd -r | bash` (encoding obfuscation)
   - `${IFS}` (whitespace bypass)
   - `$'\x62\x61\x73\x68'` (ANSI-C hex quoting)
   - `env sh`, `env -i bash` (env exec)
   - `///bin/bash`, `/usr/../bin/bash` (path traversal)
   - `ba''sh`, `b"a"sh`, `b$@ash` (string concatenation)
   - **Cyrillic homoglyph + zero-width Unicode** (`\x{0406} \x{200B}` 등 invisible character)
   
   `2/`은 정규식 OR 묶음 + Cf 카테고리만 — `3/`의 14패턴 카탈로그가 더 체계적.
3. **Docker-first 개발 환경**. 멀티스테이지 Dockerfile(builder/tester/runtime) + docker-compose 7 서비스(unit-test, integration-test, scenario1-6, dashboard) + Makefile 13 타겟. 호스트 Go toolchain 부재해도 `make demo` 한 줄로 6 시나리오 시연 가능. **재현성·온보딩에서 우월**.
4. **Install UX**. `--auto/--manual/interactive` 3 모드 + 자동 백업(.bak) + Python 기반 멱등 patch + 진행 상황 색상 출력. `2/`도 멱등이지만 모드 선택지·UX는 `3/`이 더 친절.
5. **Bypass 시나리오 fixture**. `scenario5_bypass_base64`, `scenario6_bypass_python` — `2/`의 sce-6/7도 process/cmd substitution을 다루지만 `3/`은 base64·python escape까지 별도 시나리오로 노출.

### 2.3 `3/`의 결정적 결함
**`cmd/mcpredict/` 디렉터리 자체가 저장소에 없음.**
- `Dockerfile:14`이 `./cmd/mcpredict/`를 빌드 타겟으로 참조
- `install.sh:63`이 동일 경로 참조
- `Makefile`도 동일 가정
- 그러나 `3/cmd/`는 존재하지 않음 — `ls`로 확인됨
- 원인 추정: `.gitignore`의 `mcpredict` 1행 패턴이 **실행 파일 + cmd 디렉터리 자체**를 모두 ignore. (gitignore에서 슬래시 없는 패턴은 모든 깊이의 동일 이름과 일치)
- 결과: **현재 커밋에서는 빌드 불가**. `internal/*` 모듈만 존재하고 entry point 부재. 통합 산출물에 그대로 채택 불가.

---

## 3. 시나리오별 책임 분기 (통합 근거)

| 책임 영역 | 채택 출처 | 이유 |
|---|---|---|
| Hook entry (`cmd/mcpredict/{main,pre,post,init,state}.go`) | **`2/`** | `3/`은 누락. spec-correct Pre/Post 분리 응답 |
| Hook IO (`internal/hookio`) | **`2/`** | 입력 1MB cap, exit code 정책, 출력 통일 |
| Intent 파서 (`internal/intent`) | **`2/`** | content blocks 파싱, Verifier interface stub |
| Policy 매처 (`internal/policy`) | **`2/`** | `intent_check + sequence_prior + description_regex + mcp__* glob`, YAML 표현력 |
| DLP scanner (`internal/scanner`) | **`2/`** + `3/` 보강 | `2/` Gitleaks 11 base, `3/`의 마스킹(`maskSecret`) 흡수 |
| **Bypass scanner (`internal/scanner/bypass.go`)** | **`3/`** 그대로 흡수 | 14 패턴 + Cyrillic/zero-width Unicode — `2/`에 없음 |
| Injection scanner (`internal/injection`) | **`2/`** + `3/` 7패턴 합치 | 12 + 7 → dedup 후 카탈로그 확장 |
| Session 누적 (`internal/session`) | **`2/`** | schema 보존, Go 업그레이드 시 1줄 교체로 SQLite 부활 |
| Audit (`internal/audit`) | **`2/`** | canonical JSON sha256 + privacy(평문 미저장). `3/`의 `input map` 평문 저장은 후퇴이므로 폐기. |
| Verdict (`internal/verdict`) | **`2/`** | Combine + dedup |
| **Dashboard (`internal/dashboard`)** | **`3/`** 그대로 흡수 | HTTP 서버 + 임베디드 SPA 280 LOC, `2/`의 정적 HTML 대체 |
| Docker 환경 (`Dockerfile`, `docker-compose.yml`, `Makefile`) | **`3/`** | 멀티스테이지·재현성·온보딩 |
| Install (`install.sh`) | **`3/`** UX + **`2/`** `--uninstall` 흡수 | 3 모드 + 백업 + 멱등 patch + 제거 옵션 |
| Policy YAML (`examples/policies/*.yaml`) | **`2/` baseline** + **`3/` bypass 룰** 합치 | 11 + 14 → dedup 후 ~20룰. intent_check 룰은 `2/`, bypass는 `3/`. |
| Fixtures (`testdata/fixtures/`, `examples/fixtures/`) | **`2/` 9개** + **`3/` 6개** 합치 → 13~15개 (중복 제거) | `3/`의 base64/python escape 흡수 |
| Tests (`internal/*/*_test.go`, `tests/e2e/`, `tests/integration/`) | **`2/` 38종** + `3/` bypass 단위 흡수 | 회귀 방지 fixture 포함 |
| Docs (`README, CLAUDE, design/, docs/`) | **`2/`** 골격 + `3/`의 dashboard·docker·install 가이드 추가 섹션 | ARCHITECTURE/IMPLEMENTATION/PITCH는 `2/` 그대로 |
| 협업 메타 (`brain/`, `~/.claude/shared/`) | **`2/`** 보존 | 향후 멀티 세션 운영의 자산 |

---

## 4. 최종 산출물 — `mcpredict v1.0`

### 4.1 단일 저장소 구조 (제안)

```
mcpredict/                                       # 통합 결과물 (저장소 루트)
├── README.md                                    # `2/` README + dashboard·docker 섹션 추가
├── CLAUDE.md                                    # `2/` 협업 컨텍스트
├── DEMO.md                                      # `2/`
├── go.mod / go.sum                              # `2/` 기준 (1.22)
├── Dockerfile                                   # `3/` 멀티스테이지 그대로
├── docker-compose.yml                           # `3/` 7서비스
├── Makefile                                     # `3/` + `2/` make 타겟 합치
├── install.sh                                   # `3/` 3모드 + `2/` --uninstall
├── cleanup.sh                                   # `3/`
├── demo.sh                                      # `2/`
├── design/
│   └── ARCHITECTURE.md                          # `2/` v1.1 그대로
├── docs/
│   ├── PITCH.md                                 # `2/`
│   ├── IMPLEMENTATION.md                        # `2/` (dashboard 단락 추가)
│   ├── DEMO_SCRIPT.md                           # `2/` + `3/` dashboard demo 단락
│   ├── BYPASS_CATALOG.md                        # 신규 — `3/` 14패턴 + Unicode 정리
│   └── coverage-matrix-results.md               # `2/`
├── cmd/mcpredict/                               # `2/` 5 파일 그대로
│   ├── main.go
│   ├── pre.go
│   ├── post.go
│   ├── init.go
│   └── state.go
├── internal/
│   ├── hookio/io.go                             # `2/`
│   ├── intent/{intent.go, intent_test.go}       # `2/` (3/`의 nested message 처리 보강)
│   ├── policy/{policy.go, *_test.go}            # `2/` 표현력 그대로
│   ├── scanner/                                 # `2/` + `3/` 합병
│   │   ├── scanner.go                           # DLP — `2/` 베이스 + `3/` maskSecret 흡수
│   │   ├── bypass.go                            # `3/` 14패턴 그대로
│   │   ├── unicode.go                           # `3/` Cyrillic/zero-width 분리 파일
│   │   └── *_test.go
│   ├── injection/{injection.go, injection_test.go}  # `2/` 12 + `3/` 7 dedup → ~15패턴
│   ├── session/session.go                       # `2/` 메모리 stub + schema 보존
│   ├── audit/audit.go                           # `2/` canonical JSON sha256
│   ├── verdict/{verdict.go, verdict_test.go}    # `2/`
│   └── dashboard/server.go                      # `3/` 그대로 흡수 (신규 패키지)
├── examples/
│   ├── policies/
│   │   ├── baseline.yaml                        # `2/` 11룰
│   │   └── bypass-extended.yaml                 # `3/` 14룰 → 정책 분리(off-by-default 가능)
│   └── fixtures/                                # 통합 13~15 시나리오
├── testdata/fixtures/                           # `2/` 9 + `3/` 6 통합
├── tests/
│   ├── e2e/binary_test.go                       # `2/` 9 케이스
│   ├── coverage/run.sh                          # `2/`
│   └── integration/                             # 신규 — Docker 기반 6 시나리오 검증
├── tools/audit-viewer/                          # `2/` 정적 HTML (대시보드 fallback)
└── experiments/                                 # `2/` (V1~V6 capture 보존)
```

### 4.2 통합 시 처리할 충돌·이슈

| 이슈 | 처리 |
|---|---|
| 두 정책 YAML의 키 스키마 차이 (`name/event/tool_pattern/input_pattern` vs `id/when/intent_check/action`) | **`2/` 스키마로 단일화**. `3/`의 14 bypass 룰을 `2/` 스키마로 변환 (action: deny, intent_check 없음) |
| Injection 패턴 중복 (`ignore-previous` 등) | dedup 후 카탈로그 통합. ID 네임스페이스 `injection.<name>` |
| `internal/hook/types.go` (`3/`) vs `internal/hookio` (`2/`) | `2/` 채택. `3/` types.go 폐기 (Pre/Post 분리 응답이 spec-correct) |
| `3/` audit의 `input map` 평문 저장 | **폐기**. `2/`의 hash-only 정책 유지 (보안 도구로서 dogfooding 원칙) |
| `3/` intent의 하드코딩된 `intentGroups` | YAML로 외부화. 단 `dangerousBashRe`(intent 무관 항시 차단)는 `2/`의 `bash-rm-rf-root` 룰과 동일 역할이므로 통합 |
| Go 버전 | 1.22 (`3/` 기준). `2/`의 modernc/sqlite 부활 가능 |
| `3/cmd/mcpredict/` 부재 | `2/`의 cmd 그대로 채택. `3/`의 dashboard 서브커맨드는 `cmd/mcpredict/dashboard.go` 신규 추가 |

### 4.3 신규 추가 작업

1. **`cmd/mcpredict/dashboard.go`** — `mcpredict dashboard <port>` 서브커맨드 (호출은 `internal/dashboard.New(auditPath).Start(addr)`).
2. **`docs/BYPASS_CATALOG.md`** — `3/`의 14 패턴 + Cyrillic/zero-width Unicode 카테고리·예시·우회 모티프 정리.
3. **정책 분리** — bypass 룰은 별도 `examples/policies/bypass-extended.yaml`로 빼서 사용자가 opt-in 할 수 있게(보수성 trade-off).
4. **통합 e2e 시나리오** — `2/`의 9 + `3/`의 6 = 13 (중복 1~2 제거). 모두 `tests/e2e/binary_test.go`에서 실 binary stdin pipe로 검증.
5. **Dashboard 데모 fixture seeding** — `make dashboard` 1회 명령으로 audit.jsonl seed → HTTP 서버 띄우기 (`3/` Makefile의 `dashboard` 타겟 그대로).

### 4.4 산출물 메타데이터 (목표값)

| 항목 | 목표 |
|---|---|
| LOC | Go 코어 ~3,000 (현 `2/` 2,500 + `3/` dashboard 280 + bypass 200) |
| 패키지 | 9 internal (hookio, intent, policy, scanner, injection, session, audit, verdict, dashboard) |
| 정책 룰 | baseline 11 + bypass-extended ~14 = ~25 |
| 시나리오 fixture | 13~15 |
| 테스트 | 50+ (단위 25 + 통합 11 + e2e 13~15) |
| 바이너리 크기 | ~3.5MB (dashboard HTML 임베드로 약간 증가) |
| 의존성 | `gopkg.in/yaml.v3` 단 하나 (Go 1.22 stdlib `net/http`) |
| 문서 | README + ARCHITECTURE + IMPLEMENTATION + PITCH + DEMO_SCRIPT + BYPASS_CATALOG (한국어 우선, 영어 README 추가 검토) |
| 진입점 | `make demo` (Docker 6 시나리오) / `make dashboard` (HTTP UI) / `./install.sh` (Claude Code 등록) |

---

## 5. 채택·기각 요약

### 채택 (Accept from `2/` as base)
- `cmd/mcpredict/` 5파일 (entry, spec-correct Pre/Post)
- `internal/{hookio, intent, policy, session, audit, verdict}` 전부
- `internal/scanner/scanner.go` (DLP 11 + entropy)
- `internal/injection/injection.go` (12 패턴, 본체 흡수 후 `3/` 7패턴 dedup 추가)
- `examples/policies/baseline.yaml` (11룰, `intent_check + sequence_prior` 표현력)
- `testdata/fixtures/` 9개
- `tests/e2e/binary_test.go` 9 케이스
- `design/ARCHITECTURE.md` v1.1, `docs/{PITCH, IMPLEMENTATION, DEMO_SCRIPT}.md`
- 협업 메타(`brain/`, `~/.claude/shared/`) — 자산으로 보존
- `MCPREDICT_FAIL_MODE` + 400ms self-timeout

### 흡수 (Adopt from `3/`)
- **`internal/dashboard/server.go`** (HTTP UI, 가장 큰 신규 가치)
- **`internal/scanner/bypass.go` 14 패턴** + Cyrillic/zero-width Unicode (별도 파일 `unicode.go` 권장)
- `Dockerfile` 멀티스테이지 + `docker-compose.yml` + `Makefile` Docker 타겟
- `install.sh` 3 모드 UX (interactive/auto/manual + .bak 백업)
- 시나리오 fixture: `scenario5_bypass_base64`, `scenario6_bypass_python`
- `cleanup.sh` (완전 원상복구)
- DLP `maskSecret()` 함수 (audit·로그 출력 시 자격증명 마스킹)

### 기각 (Reject from `3/`)
- `internal/hook/types.go` (Pre/Post 분리 미흡, `2/`의 hookio가 spec-correct)
- `internal/audit/audit.go`의 `Input map[string]any` 평문 저장 (privacy 후퇴)
- `internal/intent/intent.go`의 하드코딩된 `intentGroups` (YAML 외부화로 대체)
- `internal/policy/policy.go`의 단순 regex-only 매처 (`2/`의 표현력으로 대체)
- `.gitignore`의 `mcpredict` 단일 행 (디렉터리까지 ignore되는 결함, `bin/mcpredict` 등으로 명시화 필요)

### 기각 (Reject from `2/`)
- 없음. 단 `tools/audit-viewer/index.html` 정적 HTML은 dashboard 흡수 후 fallback 용도로만 보존.

---

## 6. 통합 작업 순서 (제안 — 4시간 추정)

1. **(20분)** `2/`를 `mcpredict/`로 복사. `cd mcpredict && go build ./...` 통과 확인.
2. **(40분)** `3/internal/dashboard/server.go` 그대로 복사 + `cmd/mcpredict/dashboard.go` 서브커맨드 추가 + `cmd/mcpredict/main.go`에 라우팅 1줄.
3. **(40분)** `3/internal/scanner/bypass.go` 복사 → `2/`의 `internal/scanner/`로 이동 + 패키지 export 함수 통합 + `bypass_test.go` 함께. Unicode 부분은 `unicode.go`로 분리.
4. **(30분)** `3/internal/scanner/injection.go`(7) ↔ `2/internal/injection/injection.go`(12) dedup 통합.
5. **(20분)** `3/`의 14 bypass 룰을 `2/` 정책 스키마로 변환 → `examples/policies/bypass-extended.yaml` 신규.
6. **(20분)** `Dockerfile + docker-compose.yml + Makefile`을 `3/`에서 가져와 경로 조정 (`./cmd/mcpredict/` 빌드 타겟 OK — 이번엔 실제 존재).
7. **(30분)** `install.sh`를 `3/` 베이스로 채택 + `2/`의 `--uninstall` 옵션 흡수.
8. **(20분)** 시나리오 fixture 13~15개 정리, `tests/e2e/binary_test.go`에 `3/`의 base64/python 시나리오 추가.
9. **(20분)** README 갱신 — dashboard 사용법, Docker workflow, `--auto/--manual` 모드 안내.
10. **(20분)** 통합 검증: `make build && make test && make demo && make dashboard` 4-콤보 실행 후 결과 dump.

---

## 7. 한 줄 결론

> **`2/`의 spec 준수·표현력·테스트 깊이·문서를 코어로 두고, `3/`의 dashboard·bypass 카탈로그·Docker UX를 곁가지로 흡수해 단일 저장소 `mcpredict v1.0`으로 통합한다. `3/`의 cmd 디렉터리 누락은 `2/`의 entry로 메우고, `3/`의 audit 평문 저장만 폐기한다.**
>
> 결과물: 9 패키지 + ~25 정책 룰 + 50+ 테스트 + HTTP 대시보드 + Docker-first 워크플로 + `intent_check + sequence_prior + description_regex + bypass-extended` 4-축 검증 + 11 한계 정직 명시.
