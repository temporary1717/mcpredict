# mcpredict

> **Host-side AI Agent Guardrail via Claude Code Hooks**  
> *"Predict and dictate before the agent acts."*

mcpredict는 Claude Code의 PreToolUse/PostToolUse Hook을 통해 모든 도구 호출을 실행 직전·직후에 가로채, **LLM이 표명한 의도와 실제 도구 호출 행위의 정합성**을 host-side에서 검증하는 보안 가드레일입니다.

---

## 3-Layer 검증 파이프라인

```
PreToolUse 호출
    ├─[1] 정적 정책 룰 (YAML)   — curl|bash, rm -rf /, /etc/passwd 쓰기 등
    ├─[2] DLP 스캔              — 10종 비밀키 + 고엔트로피 토큰 탐지
    └─[3] 의도-행위 정합성      — transcript 최근 assistant 메시지 ↔ tool call

PostToolUse 호출
    ├─[1] DLP 스캔              — 응답 페이로드의 비밀키 유출 감지
    └─[2] Prompt Injection 탐지 — 7종 패턴 → Claude 컨텍스트에 경고 주입
```

---

## Quick Start (Docker)

```bash
# 빌드
make build

# 전체 테스트 (유닛 + 통합)
make test

# 데모 시나리오 실행
make demo
```

---

## 데모 시나리오

| # | 상황 | 입력 | 결과 |
|---|---|---|---|
| 1 | **Intent Mismatch** | 직전: "의존성 설치" → 실제: `curl \| bash` | **BLOCK** (policy + intent 2중 탐지) |
| 2 | **Credential Exfil** | `WebFetch` URL에 `AKIAIOSFODNN7EXAMPLE` 포함 | **BLOCK** (policy + DLP 2중 탐지) |
| 3 | **Prompt Injection** | WebFetch 응답에 "Ignore previous instructions..." | **WARN** (5개 패턴 탐지, 컨텍스트 경고) |
| 4 | **Safe Pass-through** | `Bash("ls -la")` | **ALLOW** (exit 0, 출력 없음) |

```bash
# 개별 시나리오 실행
make scenario1   # → exit 2, {"decision":"block","reason":"policy: ...; intent: ..."}
make scenario2   # → exit 2, {"decision":"block","reason":"policy: ...; DLP[aws-access-key]: ..."}
make scenario3   # → exit 0, [mcpredict SECURITY WARNING — PostToolUse] ...
make scenario4   # → exit 0, (no output)
```

---

## 기존 도구 대비 차별점

| 도구 | 접근 방식 | mcpredict와의 차이 |
|---|---|---|
| AXME | 사람이 정책 작성 | LLM 의도 자체를 자동 교차검증 |
| Pipelock | 시그니처 매칭 | 의도 컨텍스트 + 패턴 결합 |
| AgentArmor | 정적 trace 분석 | hook 시점 런타임, 의미 기반 |
| KAIJU | plan-upfront 모델 | ReAct 스타일 동적 검증 |

---

## 설치 (Claude Code)

```bash
./install.sh
```

또는 수동으로 `~/.claude/settings.json`에 추가:

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

기본 정책 설치:
```bash
mkdir -p ~/.mcpredict/policies
cp examples/policies/default.yaml ~/.mcpredict/policies/
```

---

## 데이터 저장

| 경로 | 용도 |
|---|---|
| `~/.mcpredict/policies/*.yaml` | 정적 정책 룰 |
| `~/.mcpredict/sessions/<id>.json` | 세션 컨텍스트 + anomaly score |
| `~/.mcpredict/audit.jsonl` | append-only 감사 로그 |

`MCPREDICT_HOME` 환경변수로 base path 변경 가능.

---

## 아키텍처

```
cmd/mcpredict/main.go      진입점 — pre/post 서브커맨드 분기
internal/hook/             Claude Code hook I/O 타입
internal/policy/           YAML 정책 로더 + 룰 매처
internal/intent/           transcript 파서 + 의도-행위 정합성
internal/scanner/          DLP (10종) + Prompt Injection (7종) 탐지
internal/session/          JSON 파일 기반 세션 트래커
internal/audit/            JSONL 감사 로그
examples/policies/         기본 정책 YAML
examples/fixtures/         데모 픽스처 + transcript
```

---

## 알려진 한계

- LLM이 의도까지 일관되게 거짓 선언하면 정합성 검증 우회 가능
- MCP 서버 프로세스 자체 외부 트래픽은 가시성 외
- Claude Code 전용 (Cursor·Cline 미지원)
- PostToolUse는 이미 실행된 행위를 되돌리지 않음

---

## 에이전트 명령

- `/critic` — 구현 비판적 검토 (보안 취약점, 우회 경로, 엣지케이스)
- `/test-runner` — Docker 빌드 + 유닛/통합 테스트 실행 + 결과 보고
