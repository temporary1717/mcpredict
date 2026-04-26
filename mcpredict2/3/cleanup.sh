#!/usr/bin/env bash
# cleanup.sh — mcpredict 완전 제거 스크립트
# 설치된 바이너리, hook 설정, 감사 데이터, Docker 이미지를 모두 삭제합니다.
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
warn() { echo -e "  ${YELLOW}!${NC}  $*"; }
skip() { echo -e "  ${YELLOW}-${NC}  $*"; }

echo ""
echo -e "${BOLD}mcpredict cleanup${NC}"
echo "=================================="

# ── 1. 바이너리 제거 ────────────────────────────────────────────────────────
echo ""
echo "1. 바이너리 제거"
HOOK_BIN="$HOME/.claude/hooks/mcpredict"
if [ -f "$HOOK_BIN" ]; then
    rm -f "$HOOK_BIN"
    ok "제거됨: $HOOK_BIN"
else
    skip "없음: $HOOK_BIN"
fi

# ── 2. ~/.claude/settings.json 에서 hook 항목 제거 ──────────────────────────
echo ""
echo "2. ~/.claude/settings.json hook 설정 제거"
SETTINGS="$HOME/.claude/settings.json"
if [ -f "$SETTINGS" ]; then
    # Python으로 mcpredict 관련 hook 항목만 제거 (다른 설정은 유지)
    python3 - "$SETTINGS" << 'PYEOF'
import json, sys, os

path = sys.argv[1]
with open(path) as f:
    s = json.load(f)

hooks = s.get('hooks', {})
changed = False

for event in list(hooks.keys()):
    original = hooks[event]
    filtered = [
        entry for entry in original
        if not any(
            'mcpredict' in h.get('command', '')
            for h in entry.get('hooks', [])
        )
    ]
    if len(filtered) != len(original):
        changed = True
    if filtered:
        hooks[event] = filtered
    else:
        del hooks[event]

if not hooks:
    s.pop('hooks', None)

if changed:
    # 백업 후 덮어쓰기
    backup = path + '.bak'
    os.rename(path, backup)
    with open(path, 'w') as f:
        json.dump(s, f, indent=2)
        f.write('\n')
    print(f"  ✓  mcpredict hook 제거됨 (백업: {backup})")
else:
    print("  -  mcpredict hook 항목 없음 (settings.json 변경 없음)")
PYEOF
else
    skip "없음: $SETTINGS"
fi

# ── 3. ~/.mcpredict 데이터 디렉토리 제거 ────────────────────────────────────
echo ""
echo "3. ~/.mcpredict 데이터 제거 (감사 로그 · 세션 · 정책)"
MCPREDICT_HOME="${MCPREDICT_HOME:-$HOME/.mcpredict}"
if [ -d "$MCPREDICT_HOME" ]; then
    rm -rf "$MCPREDICT_HOME"
    ok "제거됨: $MCPREDICT_HOME"
else
    skip "없음: $MCPREDICT_HOME"
fi

# ── 4. Docker 이미지 제거 ────────────────────────────────────────────────────
echo ""
echo "4. Docker 이미지 제거"
IMAGE="mcpredict:dev"
if docker image inspect "$IMAGE" > /dev/null 2>&1; then
    docker rmi "$IMAGE" > /dev/null 2>&1
    ok "제거됨: $IMAGE"
else
    skip "없음: $IMAGE"
fi

# ── 완료 ─────────────────────────────────────────────────────────────────────
echo ""
echo "=================================="
echo -e "${BOLD}완료${NC} — mcpredict가 완전히 제거되었습니다."
echo ""
