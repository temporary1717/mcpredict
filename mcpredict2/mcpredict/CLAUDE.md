# mcpredict — 개발 컨텍스트

> Host-side AI agent guardrail via Claude Code Pre/PostToolUse hooks.
> 단일 Go 정적 바이너리 (~3.5MB) — LLM 의도와 tool_input의 정합성을 hook 시점에 교차 검증.

---

## 빌드 & 테스트

```bash
# 호스트에서
go build -o bin/mcpredict ./cmd/mcpredict
go test ./...

# Docker로
make build
make test
make demo
```

## 진입점

| 서브커맨드 | 역할 |
|---|---|
| `mcpredict pre` | PreToolUse hook — stdin JSON 읽고 deny/allow JSON 출력 |
| `mcpredict post` | PostToolUse hook — tool_response 검사, 인젝션 탐지 시 컨텍스트 주입 |
| `mcpredict init` | `~/.mcpredict/{policies,sessions}` 초기화 + 기본 정책 복사 |
| `mcpredict state` | 현재 세션 상태 dump |
| `mcpredict dashboard <addr>` | HTTP 대시보드 서버 (audit.jsonl 실시간 조회) |

## 데이터 경로

| 경로 | 용도 |
|---|---|
| `${MCPREDICT_HOME:-~/.mcpredict}/policies/*.yaml` | YAML 정책 |
| `${MCPREDICT_HOME:-~/.mcpredict}/sessions/<id>.json` | 세션 컨텍스트 |
| `${MCPREDICT_HOME:-~/.mcpredict}/audit.jsonl` | append-only 감사 로그 (canonical-JSON sha256 hash만 저장) |

## Hook 응답 규칙

**PreToolUse**:
- Exit 0 + 빈 stdout = 허용
- Exit 0 + JSON `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}` = 차단

**PostToolUse**:
- Exit 0 + 빈 stdout = 통과
- Exit 0 + JSON `{"decision":"block","reason":"...","additionalContext":"..."}` = 컨텍스트 진입 차단

## 코드 규칙

- Go 1.19+, CGO 비활성 (`CGO_ENABLED=0`)
- 외부 의존성: `gopkg.in/yaml.v3` 단 하나
- 성능 예산: PreToolUse < 500ms (DLP+intent+policy 동기 실행 + 400ms self-timeout)
- Fail-safe: `MCPREDICT_FAIL_MODE=open|closed|warn` (기본 warn)

## 검증 파이프라인

**PreToolUse**:
1. YAML 정책 매처 (`internal/policy`)
2. DLP scanner (`internal/scanner` — 11종 secret + 고엔트로피)
3. Bypass scanner (`internal/scanner/bypass.go` — 14패턴 + Cyrillic/zero-width Unicode)
4. 의도-행위 정합성 (`internal/intent` — transcript JSONL 직전 assistant 텍스트와 tool_input 비교)
5. Verdict 결합 (`internal/verdict`)

**PostToolUse**:
1. tool_response DLP scan
2. Injection 패턴 매칭 (`internal/injection` — 12+ 패턴)
3. 탐지 시 컨텍스트 차단 + 경고 메시지 주입

## 알려진 한계

- LLM이 의도까지 일관되게 거짓 표명하면 우회 가능
- MCP 서버 프로세스 자체가 발생시키는 외부 트래픽은 가시성 외
- Claude Code 전용 (Cursor·Cline 등 미지원)
- PostToolUse는 이미 실행된 도구를 되돌리지 않음 (컨텍스트 오염만 차단)
