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

## 정책 커스터마이징

mcpredict는 룰을 사전 정의하지 않습니다. 각 사용자의 환경과 보안 요구에 맞게 직접 정의하세요.  
`~/.mcpredict/policies/` 안의 `*.yaml` 파일을 저장하면 **즉시 반영**됩니다 — 재시작·재빌드 불필요.

```
~/.mcpredict/policies/
├── my_rules.yaml      ← 직접 작성한 룰
├── secrets.yaml       ← 자격증명 유출 방지 룰
└── ...                ← 파일명 자유, 여러 파일 병합 적용
```

---

### 방법 1 — LLM에게 룰 생성 요청

Claude Code 등 LLM에게 아래와 같이 요청하면 즉시 사용 가능한 YAML 룰을 얻을 수 있습니다.

**예시 프롬프트:**

```
아래는 mcpredict 정책 파일 포맷입니다.

필드 설명:
- name: 룰 고유 ID (영문 소문자 + 하이픈)
- event: PreToolUse | PostToolUse | *
- tool_pattern: 도구 이름 정규식 (Bash / WebFetch / Write / .*)
- input_pattern: 도구 입력 JSON에 매칭할 RE2 정규식
- action: block | warn
- reason: 사용자에게 표시할 차단 사유

이 포맷으로, AWS/GitHub/Slack 등 git secret key가
Bash 명령이나 WebFetch URL을 통해 외부로 유출되지 않도록
차단하는 룰을 작성해줘.
```

**LLM 생성 결과 예시:**

```yaml
version: "1"
rules:
  - name: "block-aws-key-leak"
    event: "PreToolUse"
    tool_pattern: '.*'
    input_pattern: '(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}'
    action: "block"
    reason: "AWS 액세스 키가 도구 입력에 포함되어 있습니다"

  - name: "block-github-token-leak"
    event: "PreToolUse"
    tool_pattern: '.*'
    input_pattern: 'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}'
    action: "block"
    reason: "GitHub Personal Access Token이 감지되었습니다"

  - name: "block-slack-token-leak"
    event: "PreToolUse"
    tool_pattern: '.*'
    input_pattern: 'xox[baprs]-[A-Za-z0-9\-]{10,}'
    action: "block"
    reason: "Slack 토큰이 도구 입력에 포함되어 있습니다"
```

생성된 YAML을 `~/.mcpredict/policies/secrets.yaml` 로 저장하면 즉시 적용됩니다.

---

### 방법 2 — 직접 regex 작성

**YAML 스키마:**

```yaml
version: "1"
rules:
  - name: "룰-이름"           # 필수. 고유 ID (영문 소문자·숫자·하이픈)
    description: "설명"       # 선택
    event: "PreToolUse"       # PreToolUse | PostToolUse | * (기본: *)
    tool_pattern: 'Bash'      # 도구 이름에 매칭할 RE2 정규식
                              #   Bash / WebFetch / Write / Read / .* 등
    input_pattern: '(?i)...'  # 도구 입력 JSON 전체에 매칭할 RE2 정규식
                              #   (?i) = 대소문자 무시
    action: "block"           # block = 실행 차단 (exit 2)
                              # warn  = 허용하되 Claude 컨텍스트에 경고 주입
    reason: "차단 사유"        # 차단 시 표시되는 메시지
```

**자주 쓰는 패턴 예시:**

| 목적 | input_pattern |
|------|---------------|
| curl/wget → 쉘 파이프 | `(?i)(curl\|wget)[^\n]{0,200}\|\s*(sh\|bash)` |
| AWS 액세스 키 | `(AKIA\|ABIA\|ACCA\|ASIA)[A-Z0-9]{16}` |
| GitHub 토큰 | `ghp_[A-Za-z0-9]{36}` |
| PEM 프라이빗 키 | `-----BEGIN (RSA\|EC\|OPENSSH) PRIVATE KEY-----` |
| /etc/passwd 변조 | `(>\|tee)\s*/etc/(passwd\|shadow\|sudoers)` |
| base64 디코드 실행 | `(?i)base64\s*(-d\|--decode)[^\|]*\|\s*(sh\|bash)` |
| 시스템 디렉터리 쓰기 | `"file_path"\s*:\s*"/(etc\|bin\|sbin)/` |

**전체 예시 파일:** `examples/policies/example.yaml` 참고

---

### Docker 환경에서 정책 마운트

Docker로 mcpredict를 실행할 때는 호스트의 정책 디렉터리를 마운트하면
이미지 재빌드 없이 정책을 수정할 수 있습니다:

```bash
docker run --rm \
  -v "$HOME/.mcpredict/policies:/root/.mcpredict/policies:ro" \
  -e MCPREDICT_HOME=/root/.mcpredict \
  mcpredict:dev pre < hook_input.json
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
