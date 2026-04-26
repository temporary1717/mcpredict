# mcpredict

> **Predict and dictate before the agent acts.**
>
> Host-based AI Agent Guardrail via Claude Code Hooks.

---

## 한 줄 정의

Claude Code의 PreToolUse/PostToolUse Hook을 통해 모든 도구 호출(Bash, Read, Write, WebFetch, MCP)을 실행 직전·직후에 가로채, **LLM이 표명한 의도와 실제 호출 행위의 정합성**을 host-side에서 검증하는 보안 가드레일. 단일 Go 바이너리.

## 차별 축

> 직전 assistant 메시지(의도)와 `tool_input`(행위)의 의미적 정합성을 hook 시점에 교차 검증.

| 도구 | 접근 |
|---|---|
| **AXME** | 사람이 정책 작성 |
| **Pipelock** | 시그니처 매칭 |
| **AgentArmor** | 정적 PDG trace |
| **mcpredict** | 의도 컨텍스트 + 행위 인자의 hook 시점 교차 검증 |

## 빠른 시작

```bash
go build -o mcpredict ./cmd/mcpredict
./install.sh
```

`install.sh`는 다음을 수행:
1. `~/.claude/hooks/mcpredict` 바이너리 배포
2. `~/.mcpredict/{policies,}` 생성, 기본 정책 YAML 배포
3. `~/.claude/settings.json` hooks 섹션 patch (기존 hook 보존)
4. SQLite 스키마 init

## 구성

```
mcpredict/
├── cmd/mcpredict/         # pre · post · init 서브커맨드
├── internal/
│   ├── hookio/            # stdin JSON / stdout hookSpecificOutput
│   ├── intent/            # transcript_path 파서, Verifier interface
│   ├── policy/            # YAML 로더 + 룰 매처
│   ├── scanner/           # Gitleaks DLP
│   ├── injection/         # PostToolUse prompt-injection 패턴
│   ├── session/           # SQLite 누적
│   ├── audit/             # JSONL append-only (해시만)
│   └── verdict/           # Verdict + Combine
├── examples/policies/     # 기본 정책 3~5개
├── testdata/              # fixture JSON
└── design/ARCHITECTURE.md # 시스템 구조 설계 문서
```

## 정책 예시

```yaml
version: 1
rules:
  - id: bash-curl-pipe-shell
    description: "curl|bash 패턴은 의존성 설치 의도일 때만 허용"
    when:
      tool: Bash
      command_regex: '\bcurl\b[^|]*\|\s*(?:sh|bash|zsh)'
    intent_check:
      mode: required_keyword
      keywords: ["install", "설치", "setup"]
      threshold: 1
    action: deny
    reason: "외부 스크립트 직접 실행은 의존성 설치 의도가 명시되어야 함."
```

## 알려진 한계

- LLM이 의도까지 일관되게 거짓을 말하면 정합성 검증 우회됨 (공격 비용 증가는 유지)
- MCP 서버 프로세스의 자체 외부 트래픽은 비가시 (transport proxy도 동일 한계)
- Claude Code 종속 (Cursor·Cline 미지원, future: transport proxy 모드)
- Hook spec 진화 중 (2026 spec 기준)
- PostToolUse는 행위 비가역 — 컨텍스트 진입만 차단
- 동기 500ms 예산 — LLM 호출 기반 검증은 비동기 audit-only

## 라이센스

(미정 — 해커톤 후)

## 설계 문서

- [`design/ARCHITECTURE.md`](design/ARCHITECTURE.md) — 시스템 구조 / 인터페이스 / 합의 게이트
- [`docs/PITCH.md`](docs/PITCH.md) — 발표 자료
