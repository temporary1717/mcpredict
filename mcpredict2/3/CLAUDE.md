# mcpredict — 개발 가이드

> Host-based AI Agent Guardrail via Claude Code Hooks  
> PreToolUse/PostToolUse 시점에 LLM 의도-행위 정합성을 host-side에서 검증하는 단일 Go 바이너리

---

## 개발 환경

**모든 개발과 테스트는 Docker에서 진행합니다.**

```bash
# 빌드
make build

# 유닛 테스트 (Go 테스트)
make test-unit

# 통합 테스트 (4개 시나리오)
make test-integration

# 전체 테스트
make test

# 데모 실행 (시각적 출력)
make demo

# 개별 시나리오
make scenario1   # intent mismatch → BLOCK
make scenario2   # credential exfil → BLOCK
make scenario3   # prompt injection → WARN
make scenario4   # safe ls → ALLOW
```

---

## 프로젝트 구조

```
cmd/mcpredict/main.go       진입점 — pre/post 서브커맨드 분기
internal/hook/types.go      Claude Code hook I/O 타입
internal/policy/policy.go   YAML 정책 로더 + 룰 매처
internal/intent/intent.go   transcript 파서 + 의도-행위 정합성
internal/scanner/dlp.go     DLP 패턴 (비밀키 10종)
internal/scanner/injection.go  프롬프트 인젝션 탐지 (7종)
internal/session/session.go JSON 파일 기반 세션 트래커
internal/audit/audit.go     JSONL 감사 로그
examples/policies/          YAML 정책 파일
examples/fixtures/          데모 픽스처 JSON + transcript JSONL
```

---

## Hook 프로토콜

### PreToolUse 입력 (stdin)
```json
{
  "session_id": "abc-123",
  "transcript_path": "/path/to/transcript.jsonl",
  "tool_name": "Bash",
  "tool_input": {"command": "..."},
  "hook_event_name": "PreToolUse"
}
```

### PostToolUse 추가 필드
```json
{
  "tool_response": {"output": "...", "error": ""}
}
```

### 응답 규칙
- **Exit 0** = 허용 (아무 것도 출력 안 해도 됨)
- **Exit 2 + stdout JSON** = 차단
  ```json
  {"decision": "block", "reason": "..."}
  ```
- **PostToolUse stdout** = Claude 컨텍스트에 주입 (경고 메시지)

---

## 검증 파이프라인 (PreToolUse)

1. **정적 정책 룰** — `~/.mcpredict/policies/*.yaml` YAML 패턴 매칭
2. **DLP 스캔** — 10종 비밀키 패턴 + 고엔트로피 토큰 탐지
3. **의도-행위 정합성** — transcript 최근 assistant 메시지 ↔ 실제 tool call

## 검증 파이프라인 (PostToolUse)

1. **DLP 스캔** — 응답 텍스트에 비밀키 포함 여부
2. **인젝션 탐지** — 7종 프롬프트 인젝션 패턴
3. **stdout 경고** — 탐지 시 Claude 컨텍스트에 경고 주입

---

## 데이터 저장

| 경로 | 용도 |
|---|---|
| `~/.mcpredict/policies/*.yaml` | 정적 정책 |
| `~/.mcpredict/sessions/<id>.json` | 세션 컨텍스트 |
| `~/.mcpredict/audit.jsonl` | append-only 감사 로그 |

`MCPREDICT_HOME` 환경변수로 base path 변경 가능.

---

## 코드 규칙

- **언어**: Go 1.22, CGO 비활성 (`CGO_ENABLED=0`)
- **외부 의존성**: `gopkg.in/yaml.v3` 단 하나
- **성능 예산**: PreToolUse < 500ms (DLP+intent 동기 실행)
- **테스트**: 모든 핵심 로직은 유닛 테스트 필수
- **에러 처리**: 로그 실패는 무시 (감사 실패가 도구 차단보다 중요하지 않음)

---

## Claude Code 설치

```bash
make install
```

`~/.claude/settings.json`에 추가:
```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": ".*", "hooks": [{"type": "command", "command": "~/.claude/hooks/mcpredict pre"}]}
    ],
    "PostToolUse": [
      {"matcher": ".*", "hooks": [{"type": "command", "command": "~/.claude/hooks/mcpredict post"}]}
    ]
  }
}
```

---

## 알려진 한계 (발표 시 명시)

- LLM이 의도까지 일관되게 거짓으로 선언하면 우회 가능
- MCP 서버 프로세스 자체가 발생시키는 외부 트래픽은 가시성 외
- Claude Code 전용 — Cursor·Cline 미지원
- PostToolUse는 이미 실행된 도구를 되돌리지 않음 (컨텍스트 오염만 차단)
