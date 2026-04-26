#!/bin/bash
# §7 검증용 logging-only hook. stdin JSON을 그대로 캡처. 절대 block 하지 않음 (exit 0).
# macOS date에 %N(nanosecond) 미지원. PID + 마이크로초 대신 epoch+nanos via python fallback.

LOG_DIR="$(dirname "$0")/captures"
mkdir -p "$LOG_DIR"

# epoch with nanos via python (macOS-safe). 실패 시 second + PID + RANDOM.
NANOS=$(python3 -c 'import time; print(f"{time.time_ns()}")' 2>/dev/null || echo "$(date +%s)$$$RANDOM")
EVENT="${HOOK_EVENT_NAME:-unknown}"
OUT="$LOG_DIR/${NANOS}-${EVENT}.json"

START_NS=$(python3 -c 'import time; print(time.time_ns())' 2>/dev/null || echo 0)
cat > "$OUT"
END_NS=$(python3 -c 'import time; print(time.time_ns())' 2>/dev/null || echo 0)

# latency record (hook script perspective; not full e2e)
echo "${NANOS} ${EVENT} read_ns=$((END_NS-START_NS))" >> "$LOG_DIR/.latency.log"

exit 0
