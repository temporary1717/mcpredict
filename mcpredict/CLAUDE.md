# mcpredict — 협업 컨텍스트 (자동 로드)

이 프로젝트는 3개 Claude Code 세션이 병렬 작업한다.
- **세션-A**: §7 검증·hook 핸들러·인프라 (`cmd/mcpredict`, `internal/{hookio,intent,session,audit}`, `install.sh`)
- **세션-B**: 시스템 설계·정책·DLP·발표 (`internal/{policy,scanner,injection}`, `examples/policies/`, `docs/`)
- **두뇌**: 코디네이터 — 메시지 중계·결정 로그·블로커 추적 (개발 슬롯 차지 안 함)

너는 **자기 영역 외 정보를 brain에서 조회**하고, 다른 세션과는 inbox 큐로만 비동기 통신한다. 같은 작업을 두 번 하지 않는다.

## 시작 시 필독

1. `~/.claude/shared/board.md` — 작업 보드. 다른 세션의 IN PROGRESS 항목 건드리지 말 것.
2. `~/.claude/shared/inbox-{1,2,3}.md` — 자기 inbox(=자기 세션 번호)에서 신규 메시지 처리.
3. `/Users/toor/hackerton/brain/INDEX.md` — 산출물 어디에 있는지.
4. `/Users/toor/hackerton/brain/DECISIONS.md` — 합의된 결정 (D-NNN). 위반하지 말 것.
5. `/Users/toor/hackerton/brain/BLOCKERS.md` + `OPEN_QUESTIONS.md` — 미해결 항목.

## brain 조회 — 두 가지 패턴

### A. 직접 읽기 (즉시)
- "결정사항?" → `brain/DECISIONS.md`
- "산출물 위치?" → `brain/INDEX.md`
- "블로커?" → `brain/BLOCKERS.md`
- "용어 정의?" → `brain/GLOSSARY.md`

### B. 두뇌에 비동기 질문
brain에 답이 없거나 다른 세션의 *최신* 상태가 필요할 때 `~/.claude/shared/inbox-3.md`에 append:

```
## [세션-X] → 두뇌  (HH:MM, 2026-04-26)

**질문 ID**: Q-NNN
**카테고리**: status | decision | spec | blocker | other
**내용**: 한두 줄.
**필요 시점**: 즉시 / N분 내 / 비차단
**회신 위치**: inbox-X.md
```

두뇌 회신 SLA: 즉시 ≤ 5분, N분 내 ≤ 명시 시간, 비차단 ≤ 30분.

brain 직접 읽기로 답이 나오면 패턴 B 쓰지 말 것 (코디네이터 부하 감소).

## 작업 시작·완료 시

- **시작**: 보드 IN PROGRESS에 "[세션-X] 작업명 (시작: HH:MM)" 한 줄 추가.
- **완료**: 보드 DONE으로 이동, 산출물 경로 명시. 새 산출물·결정이 생겼으면 inbox-3에 한 줄 dump → 두뇌가 brain 갱신.
- **블로커 발생**: inbox-3에 "block: <증상>" append → 두뇌가 BLOCKERS.md에 등재.

## 메시지 큐 규칙

- append-only. 기존 블록 수정 금지, 답글은 새 블록.
- 첫 줄에 항상 `## [세션-X] → 세션-Y  (HH:MM, 2026-04-26)`.
- raw JSON·긴 산출물은 파일로 저장 후 inbox에 경로만 적기.

## 사용자 신규 지시

두뇌가 자동 전파한다. 너는 자기 inbox만 보면 된다.

## 주의

- 두뇌의 auto-memory(`~/.claude/projects/-Users-toor-hackerton/memory/`)는 세션 격리되어 너에게 안 보인다. 공유 가치 있는 사실은 brain/board를 통해서만 확인.
- brain은 두뇌 전용 쓰기. 너는 read-only.
