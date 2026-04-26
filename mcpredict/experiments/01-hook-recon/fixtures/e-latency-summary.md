# (e) Hook fork+exec latency 측정

## 환경
- macOS Darwin 23.4.0, M-series
- shell: bash (log-hook.sh)
- Go 1.19.2 darwin/arm64
- 측정: `/usr/bin/time -p sh -c '...'` (real time)

## 결과

### log-hook.sh (bash + python3 nanos + cat redirect)
10회 실행 real time:
```
0.04 0.02 0.03 0.02 0.08 0.09 0.06 0.08 0.09 0.07
```
- 평균 ~58ms, 중앙값 ~70ms, 최대 90ms
- 첫 호출이 더 빠른 건 page cache + python3 warm

### Go 정적 바이너리 stub (JSON parse만, ~2.4MB)
10회 실행 real time:
```
0.51 0.01 0.01 0.01 0.01 0.02 0.01 0.04 0.03 0.01
```
- 첫 호출 510ms (binary not in page cache, OS cold load)
- 이후 10-40ms (hot path)
- 중앙값 ~15ms

## 결론
- **fork+exec 모델로 충분**. HTTP daemon 불필요.
- Hook timeout 5s 안에 첫 호출 cold start (510ms) + 모든 hot path (10-40ms) 포함됨.
- 매 tool call마다 새 fork이지만 binary는 page cache에 살아있음 → 9시간 데모에서 hot path 유지.
- **A2 결정**: fork+exec. daemon은 future work (50+ tool calls/sec 같은 burst 시나리오에서만 유의미).

## 9시간 MVP 영향
- Go 단일 정적 바이너리 + 매 hook 새 fork 패턴 채택
- modernc.org/sqlite cgo-free 빌드로 binary self-contained
- 첫 호출 ~500ms는 데모 시 user-perceived latency로 미미 (sub-second)
