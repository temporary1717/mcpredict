# mcpredict v1.0

> **Predict and dictate before the agent acts.**
>
> Host-side AI agent guardrail via Claude Code Pre/PostToolUse hooks — single Go binary.

---

## 한 줄 정의

Claude Code의 PreToolUse/PostToolUse Hook을 통해 모든 도구 호출(Bash·Read·Write·WebFetch·MCP)을 가로채, **LLM이 표명한 의도(직전 assistant 메시지)와 실제 호출 행위(`tool_input`)의 의미적 정합성**을 host-side에서 교차 검증하는 보안 가드레일.

## 차별 축

> 직전 assistant 메시지(의도)와 `tool_input`(행위)의 의미적 정합성을 hook 시점에 교차 검증.

| 도구 | 접근 |
|---|---|
| AXME | 사람이 정책 작성 |
| Pipelock | 시그니처 매칭 |
| AgentArmor | 정적 PDG trace |
| **mcpredict** | **의도 컨텍스트 + 행위 인자 + 우회 패턴 + DLP를 hook 시점에 결합 검증** |

---

## 4-Layer 검증 파이프라인

```
PreToolUse 호출
    ├─[1] 정적 정책 룰 (YAML)   — intent_check + sequence_prior + description_regex
    ├─[2] DLP 스캔              — 11종 비밀키 + Shannon 엔트로피 (RE2, 1MB cap)
    ├─[3] Bypass 탐지           — 14종 우회 (interpreter escape · base64 · IFS · ANSI hex
    │                             · env exec · path traversal · string concat · tmpfile chmod)
    │                          + Cyrillic homoglyph + zero-width Unicode
    └─[4] 의도-행위 정합성      — transcript 최근 assistant 메시지 ↔ tool call

PostToolUse 호출
    ├─[1] DLP 스캔              — 응답 페이로드의 비밀키 유출 감지
    └─[2] Prompt Injection 탐지 — 12+ 패턴 → Claude 컨텍스트에 경고 주입 / 차단
```

---

## Quick Start

### Docker (권장 — 호스트 toolchain 불필요)

```bash
make build              # 멀티스테이지 빌드 + 단위 테스트
make test               # 통합 테스트 (6 시나리오)
make demo               # 시연: 전 시나리오 sequential 실행
make dashboard          # → http://localhost:8080  실시간 audit 대시보드
```

### Native (Go 1.22+)

```bash
go build -o bin/mcpredict ./cmd/mcpredict
go test ./...           # 단위 + 통합 + e2e (38+ 케이스)
./bin/mcpredict version
```

### Claude Code 설치

```bash
./install.sh            # 대화형 (변경 내용 확인 후 Y/N)
./install.sh --auto     # 자동 (즉시 settings.json 수정)
./install.sh --manual   # 바이너리만 + 수동 설정 가이드 출력
```

`install.sh`는:
1. Docker 빌드 → 호스트용 바이너리 크로스 컴파일 → `~/.claude/hooks/mcpredict` 배포
2. `~/.mcpredict/policies/baseline.yaml` 배포
3. `~/.claude/settings.json`에 hooks 섹션 자동 patch (기존 hook 보존, `.bak` 백업)
4. **Claude Code 재시작 필요** 안내 (V6 finding)

---

## 데모 시나리오 (6종)

| # | 상황 | 입력 | 결과 |
|---|---|---|---|
| 1 | **Intent Mismatch** | 직전 의도: 단순 출력 → 실제: `curl \| bash` | **deny** (policy + intent 2중 탐지) |
| 2 | **Credential Exfil** | `WebFetch` URL에 `AKIAIOSFODNN7EXAMPLE` 포함 | **deny** (policy + DLP 2중 탐지) |
| 3 | **Prompt Injection** | WebFetch 응답에 `Ignore previous instructions...` | **block** (Post hook, 컨텍스트 차단) |
| 4 | **Safe Pass-through** | `Bash("ls -la")` | **allow** |
| 5 | **Base64 Bypass** | `echo BASE64 \| base64 -d \| sh` | **deny** (`bypass.base64-pipe-exec`) |
| 6 | **Interpreter Escape** | `python3 -c '...subprocess...'` | **deny** (`bypass.python-shell-escape`) |

```bash
make scenario1   # → deny
make scenario5   # → deny (bypass)
```

---

## 라이브 대시보드

```bash
make dashboard
# 또는 직접
mcpredict dashboard 8080
```

→ `http://127.0.0.1:8080` 에서 실시간 audit 카드 (verdict 색상 코드 · 검색 · 필터 · 2초 폴링).
single-page Go HTTP 서버, 외부 의존성 없음.

---

## 정책 예시

```yaml
version: 1
rules:
  - id: bash-curl-pipe-shell
    description: "외부 스크립트 직접 실행. 의존성 설치 의도일 때만 허용"
    when:
      tool: Bash
      command_regex: '\bcurl\b[^|]*\|\s*(?:sh|bash|zsh)|<\([^)]*\bcurl\b|\$\([^)]*\bcurl\b'
    intent_check:
      mode: required_keyword
      keywords: ["install", "설치", "setup", "공식 설치"]
      threshold: 1
    action: deny
    reason: "외부 스크립트 직접 실행은 의존성 설치 의도가 명시되어야 함."
```

세 가지 정책 파일이 함께 배포됨:
| 파일 | 용도 |
|---|---|
| `examples/policies/baseline.yaml` | 11 룰 — intent_check + sequence_prior + DLP·MCP 룰 (기본) |
| `examples/policies/default.yaml` | baseline.yaml의 alias (Docker workflow 호환) |
| `examples/policies/bypass-extended.yaml` | 14 우회 룰 (코드 측 ScanBypass와 별개로 YAML 옵트인) |

---

## 구성

```
mcpredict/
├── cmd/mcpredict/         # pre · post · init · dashboard 서브커맨드 (5 파일)
├── internal/
│   ├── hookio/            # stdin JSON / stdout hookSpecificOutput
│   ├── intent/            # transcript_path 파서, Verifier interface
│   ├── policy/            # YAML 로더 + 룰 매처 (intent_check + sequence_prior + description_regex)
│   ├── scanner/           # DLP (11) + Bypass (14) + Unicode (Cyrillic + zero-width)
│   ├── injection/         # PostToolUse prompt-injection 패턴 12+
│   ├── session/           # 메모리 stub (Schema 보존, SQLite 부활 대기)
│   ├── audit/             # JSONL append-only (canonical-JSON sha256, 평문 미저장)
│   ├── verdict/           # Verdict struct + Combine (최엄결정)
│   └── dashboard/         # HTTP 서버 + 임베디드 SPA (실시간 카드)
├── examples/
│   ├── policies/          # baseline / default / bypass-extended
│   └── fixtures/          # 6 데모 시나리오 (Docker workflow용)
├── testdata/fixtures/     # 11 unit/integration fixture (회귀 방지 포함)
├── tests/
│   ├── e2e/binary_test.go # 실 binary stdin pipe 9 케이스
│   └── coverage/
├── tools/audit-viewer/    # 정적 HTML fallback (file picker 모드)
├── design/ARCHITECTURE.md # 시스템 구조 합의 문서 v1.1
├── docs/
│   ├── PITCH.md           # 발표 자료
│   ├── IMPLEMENTATION.md  # 구현 종합 정리
│   ├── DEMO_SCRIPT.md     # 라이브 데모 대본
│   └── BYPASS_CATALOG.md  # 14 우회 패턴 + Unicode 카탈로그
├── Dockerfile             # 멀티스테이지 (builder/tester/runtime)
├── docker-compose.yml     # 7 서비스 (unit-test/integration/scenario1-6/dashboard)
├── Makefile               # 13 타겟 (build/test/demo/scenario1-6/dashboard/install/cleanup)
├── install.sh             # 3 모드 (interactive/auto/manual) + 백업
└── cleanup.sh             # 완전 원상복구
```

---

## 데이터 저장

| 경로 | 용도 |
|---|---|
| `~/.mcpredict/policies/*.yaml` | 정적 정책 룰 |
| `~/.mcpredict/audit.jsonl` | append-only 감사 로그 (canonical-JSON sha256, 평문 미저장) |
| `~/.mcpredict/sessions/<id>.json` | 세션 컨텍스트 (메모리 stub, schema 보존) |

`MCPREDICT_HOME` 환경변수로 base path 변경 가능.

---

## Fail-safe

| 모드 | 동작 |
|---|---|
| **fail-warn** (기본) | `permissionDecision:"ask"` — 사용자 확인 요청 |
| fail-open | `allow` — 보안 약화 |
| fail-closed | `deny` — 사용성 약화 |

`MCPREDICT_FAIL_MODE=open|closed|warn` + 400ms self-timeout (hook 5s 예산 안에서 강제 fail-warn).

---

## 알려진 한계 (정직)

### 설계 단계 (SPEC §9)
- LLM이 의도까지 일관되게 거짓을 말하면 정합성 검증 우회됨 (단 공격 비용 증가는 유지)
- MCP 서버 프로세스 자체 외부 트래픽은 비가시 (cross-server 격리는 MCP 설계 원칙)
- Claude Code 종속 (Cursor·Cline 미지원)
- Hook spec 진화 중 (2026 spec 기준)
- PostToolUse는 행위 비가역 — 컨텍스트 진입만 차단
- 동기 500ms 예산 — LLM 호출 기반 검증은 비동기 audit-only

### 라이브 검증 발견
- `tool_input.description` attack vector — `*-description-mismatch` 룰로 부분 완화
- `mcp__*` 동적 키맵 — 실 MCP 서버마다 필드명 다름
- V6 in-session reload 한계 — install 후 Claude Code 재시작 필요
- Session 누적 비활성 — Go 1.19 ↔ modernc/sqlite v1.50 호환성 (schema 보존)
- DLP 보수성 — 단순 echo로 자격증명 형식 출력해도 차단 (의도된 보수성)

---

## 라이센스

(미정 — 해커톤 후)

## 더 읽을거리

- [`design/ARCHITECTURE.md`](design/ARCHITECTURE.md) — 시스템 구조 / 인터페이스 / 합의 게이트
- [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) — 9시간 MVP 구현 종합 정리
- [`docs/PITCH.md`](docs/PITCH.md) — 발표 자료
- [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) — 라이브 데모 대본
- [`docs/BYPASS_CATALOG.md`](docs/BYPASS_CATALOG.md) — 14 우회 패턴 + Unicode 카탈로그
- [`../result.md`](../result.md) — 두 사전 구현 (`2/`, `3/`) 심층 비교 + 통합 결정 문서

