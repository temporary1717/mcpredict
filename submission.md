# Hackathon Submission — CMUX x AIM

---

## Project name (프로젝트명)

**mcpredict** — *Predict and dictate before the agent acts.*

---

## Project description (프로젝트 설명)

mcpredict는 Claude Code의 Pre/PostToolUse hook에 꽂히는 단일 Go 정적 바이너리로, **LLM이 직전 assistant 메시지에서 표명한 의도와 실제 `tool_input`(행위)의 의미적 정합성**을 host-side에서 교차 검증하는 보안 가드레일이다. 4-Layer 파이프라인(YAML 정책 + DLP 11종 + Bypass 14종/Unicode + 의도-행위 정합성)으로 모든 도구 호출(Bash·Read·Write·WebFetch·MCP)을 hook 시점에 가로채 deny/warn/allow 결정을 내리고, append-only 감사 로그와 실시간 HTTP 대시보드까지 제공한다.

---

## What problem does it solve? (어떤 문제를 해결하나요?)

**문제**: AI agent가 도구를 직접 실행하는 시대에 (1) 외부 콘텐츠 prompt injection이 도구 실행으로 전이되고, (2) 자격증명·PII가 비의도적으로 외부로 전송되며, (3) LLM 환각으로 의도와 다른 도구 호출이 발생하고, (4) 신뢰할 수 없는 응답이 LLM 컨텍스트로 주입된다. 기존 도구는 각자 다른 한계를 가진다 — **AXME**(사람이 정책 작성), **Pipelock**(시그니처 매칭), **AgentArmor**(정적 PDG trace), **KAIJU**(plan-upfront).

**개선점**: mcpredict는 **의도 컨텍스트 + 행위 인자 + 우회 패턴 + DLP를 hook 시점에 결합 검증**하는 유일한 접근. 라이브 검증으로 입증된 차별 축 — 동일한 `curl ... | bash` 명령이 직전 assistant 의도("install" 키워드 유무)에 따라 06:40 allow / 06:41 deny로 분기. 단순 시그니처 매칭(Pipelock)이라면 둘 다 deny했을 것. 또한 (a) Anthropic 공식 hook spec 준수(Pre/Post 응답 분리), (b) audit 평문 미저장(canonical-JSON sha256 hash만), (c) Cyrillic/zero-width Unicode 우회까지 탐지, (d) Docker-first 워크플로 + 실시간 HTTP 대시보드 — 운영 가능한 수준의 단일 바이너리(~3.5MB).

---

## Chosen track (선택한 트랙)

- [ ] 🛠 Developer Tooling
- [ ] 💡 Business & Applications
- [x] 🔴 AI Safety & Security

---

## Github repo (GitHub 저장소)

https://github.com/temporary1717/mcpredict

> 최종 통합 빌드: 저장소 루트의 [`mcpredict/`](https://github.com/temporary1717/mcpredict/tree/main/mcpredict) 디렉터리.
> 사전 구현 비교 + 통합 결정 문서: [`result.md`](https://github.com/temporary1717/mcpredict/blob/main/result.md).

---

## Video demo link (비디오 데모 링크)

(녹화 후 추가)

> 백업 데모 경로 — 저장소 클론 후:
> ```bash
> cd mcpredict && make demo            # 6 시나리오 sequential 실행 (~30s)
> make dashboard                       # → http://localhost:8080 실시간 대시보드
> ```

---

## Presentation link (프레젠테이션 링크)

저장소 내 [`mcpredict/docs/PITCH.md`](https://github.com/temporary1717/mcpredict/blob/main/mcpredict/docs/PITCH.md) — 16+ 슬라이드 발표 자료.

추가 참고 자료:
- [`mcpredict/design/ARCHITECTURE.md`](https://github.com/temporary1717/mcpredict/blob/main/mcpredict/design/ARCHITECTURE.md) — 시스템 구조 합의 문서 v1.1 (463줄, 합의 게이트 2-Round 분리)
- [`mcpredict/docs/IMPLEMENTATION.md`](https://github.com/temporary1717/mcpredict/blob/main/mcpredict/docs/IMPLEMENTATION.md) — 9시간 MVP 구현 종합 정리
- [`mcpredict/docs/DEMO_SCRIPT.md`](https://github.com/temporary1717/mcpredict/blob/main/mcpredict/docs/DEMO_SCRIPT.md) — 라이브 데모 대본
- [`mcpredict/docs/BYPASS_CATALOG.md`](https://github.com/temporary1717/mcpredict/blob/main/mcpredict/docs/BYPASS_CATALOG.md) — 14 우회 패턴 + Unicode 카탈로그
