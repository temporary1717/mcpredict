# audit.jsonl viewer

`~/.mcpredict/audit.jsonl`을 브라우저에서 시각화하는 정적 HTML.

## 사용

```bash
open ./tools/audit-viewer/index.html
```

또는 임의 정적 서버 (예: `python3 -m http.server 8000`).

## 기능

- audit.jsonl 파일 선택 → verdict별 색상 카드로 렌더 (allow=초록 / warn=노랑 / deny=빨강)
- 텍스트 검색 (도구명·session_id·rule_id·reason)
- verdict 필터
- "demo fixture" 버튼 — 시나리오 1·2·3 각각의 deny + allow + ask 5종 샘플
- 외부 fetch 없음. 단일 HTML 파일.

## 발표 데모용

라이브 데모에서 `~/.mcpredict/audit.jsonl`을 file picker로 선택하면 Pre/Post hook이 만들어낸 verdict 흐름이 즉시 카드로 보임. 시나리오 1·2·3가 1턴 안에 차례로 deny되는 시각적 narrative.
