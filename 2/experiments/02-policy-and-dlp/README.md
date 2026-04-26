# Experiments — 02-policy-and-dlp

> 세션-B 작업 영역. ARCHITECTURE.md v1.1 §4.3 / §4.4 / §11에 종속.
> 검증 V2 (`tool_input` 키맵 동결) 전까지는 잠정 산출물.

## 산출물

- `policies/baseline.yaml` — 시나리오 1·2 룰 8개 + 안전망. ARCHITECTURE §4.3 스키마 기반.
- `patterns/gitleaks-subset.md` — DLP scanner용 정규식 서브셋 11개 (8 결정적 + 1 엔트로피 + 2 보조).
- `fixtures/scenario-{1,2,3}.json` — PreToolUse/PostToolUse hook 입력 fixture. 잠정 키 (`tool_input.command`, `tool_response.content` 등).

## 의존성

- ARCHITECTURE.md v1.1 (`/Users/toor/hackerton/devlop2/design/ARCHITECTURE.md`)
- 세션-A의 V2 capture (실제 `tool_input` 필드명 동결) — 미수신
- 세션-A의 V3 transcript JSONL 샘플 (intent 추출 형식) — 미수신

## 다음 액션 (V2 capture 도착 후)

1. fixture의 `tool_input.command` 등 키 이름이 실제와 일치하는지 비교
2. baseline.yaml의 `command_regex` 등 매칭 키 이름 일치 확인 → 불일치 시 정정
3. `internal/policy` `internal/scanner` Go 코드 작성 진입

## 코드 진입 게이트

- ARCHITECTURE Round 1 합의 ack 1건 이상 (세션-A 또는 세션-C)
- V2 capture 1건 (실 발화, OQ-8 해소) 또는 사용자 명시 GO
