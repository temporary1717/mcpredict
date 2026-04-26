#!/usr/bin/env bash
# install.sh — mcpredict 설치 스크립트
#
# 사용법:
#   ./install.sh              # 대화형 (변경 내용 확인 후 Y/N)
#   ./install.sh --auto       # 자동 (확인 없이 즉시 설치)
#   ./install.sh --manual     # 바이너리만 설치 + 수동 설정 가이드 출력
#
# Makefile:
#   make install              # 대화형
#   make install-auto         # 자동
#   make install-manual       # 바이너리만
set -euo pipefail

# ── 색상 ──────────────────────────────────────────────────────────────────────
BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }
warn() { echo -e "  ${YELLOW}!${NC}  $*"; }

# ── 인자 파싱 ─────────────────────────────────────────────────────────────────
MODE="interactive"   # interactive | auto | manual
for arg in "$@"; do
    case "$arg" in
        --auto)   MODE="auto" ;;
        --manual) MODE="manual" ;;
    esac
done

IMAGE="mcpredict:dev"
BUILDER_IMAGE="mcpredict:builder"
HOOKS_DIR="$HOME/.claude/hooks"
BINARY="$HOOKS_DIR/mcpredict"
SETTINGS="$HOME/.claude/settings.json"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 호스트 OS/아키텍처 감지
HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"  # darwin / linux
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    x86_64)  HOST_ARCH="amd64" ;;
    arm64|aarch64) HOST_ARCH="arm64" ;;
esac

echo ""
echo -e "${BOLD}mcpredict 설치${NC}  [mode: $MODE]"
echo "=================================="

# ── Step 1: Docker 빌드 ───────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}1. Docker 이미지 빌드${NC}"
docker build -t "$IMAGE" "$SCRIPT_DIR" > /dev/null 2>&1
docker build -t "$BUILDER_IMAGE" --target builder "$SCRIPT_DIR" > /dev/null 2>&1
ok "빌드 완료: $IMAGE / $BUILDER_IMAGE"

# ── Step 2: 호스트용 바이너리 크로스 컴파일 + 설치 ─────────────────────────────
echo ""
echo -e "${BOLD}2. 바이너리 설치${NC}  (${HOST_OS}/${HOST_ARCH})"
mkdir -p "$HOOKS_DIR"
docker run --rm --entrypoint sh -v "$HOOKS_DIR:/out" "$BUILDER_IMAGE" \
    -c "CGO_ENABLED=0 GOOS=${HOST_OS} GOARCH=${HOST_ARCH} \
        go build -ldflags='-s -w' -o /out/mcpredict ./cmd/mcpredict/ && \
        chmod +x /out/mcpredict"
ok "설치됨: $BINARY  (${HOST_OS}/${HOST_ARCH})"

# ── Step 3: 기본 정책 파일 설치 ───────────────────────────────────────────────
echo ""
echo -e "${BOLD}3. 기본 정책 설치${NC}"
mkdir -p "$HOME/.mcpredict/policies"
cp "$SCRIPT_DIR/examples/policies/default.yaml" "$HOME/.mcpredict/policies/default.yaml"
ok "설치됨: ~/.mcpredict/policies/default.yaml"

# ── Step 4: settings.json hook 설정 ──────────────────────────────────────────
echo ""
echo -e "${BOLD}4. Claude Code hook 설정${NC}"

# 추가될 내용을 미리 계산
HOOK_PREVIEW=$(python3 - "$SETTINGS" "$BINARY" << 'PYEOF'
import json, sys, os

settings_path = sys.argv[1]
binary_path   = sys.argv[2]

if os.path.exists(settings_path):
    with open(settings_path) as f:
        s = json.load(f)
else:
    s = {}

# 현재 mcpredict 항목이 있는지 확인
hooks = s.get('hooks', {})
already = any(
    'mcpredict' in h.get('command','')
    for event_hooks in hooks.values()
    for entry in event_hooks
    for h in entry.get('hooks', [])
)
print("already" if already else "new")
PYEOF
)

if [ "$HOOK_PREVIEW" = "already" ]; then
    warn "settings.json에 이미 mcpredict hook이 등록되어 있습니다. 업데이트합니다."
fi

# manual 모드: 설정 가이드만 출력하고 종료
if [ "$MODE" = "manual" ]; then
    echo ""
    echo -e "  ${YELLOW}수동 설정 모드${NC} — 아래 내용을 ~/.claude/settings.json에 직접 추가하세요:"
    echo ""
    echo '  ┌─────────────────────────────────────────────────────────────────'
    echo '  │  "hooks": {'
    echo '  │    "PreToolUse": ['
    echo "  │      {\"matcher\": \".*\", \"hooks\": [{\"type\": \"command\", \"command\": \"$BINARY pre\"}]}"
    echo '  │    ],'
    echo '  │    "PostToolUse": ['
    echo "  │      {\"matcher\": \".*\", \"hooks\": [{\"type\": \"command\", \"command\": \"$BINARY post\"}]}"
    echo '  │    ]'
    echo '  │  }'
    echo '  └─────────────────────────────────────────────────────────────────'
    echo ""
    warn "Claude Code를 재시작해야 hook이 적용됩니다."
    echo ""
    exit 0
fi

# interactive 모드: 확인 후 진행
if [ "$MODE" = "interactive" ]; then
    echo ""
    echo "  다음 내용을 $SETTINGS 에 자동으로 추가합니다:"
    echo ""
    echo -e "  ${CYAN}PreToolUse  →${NC}  $BINARY pre"
    echo -e "  ${CYAN}PostToolUse →${NC}  $BINARY post"
    echo ""
    if [ -f "$SETTINGS" ]; then
        warn "기존 settings.json은 .bak 파일로 백업됩니다."
    fi
    echo ""
    printf "  계속할까요? [Y/n] "
    read -r answer
    answer="${answer:-Y}"
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        echo ""
        warn "취소되었습니다. 바이너리($BINARY)는 설치된 상태입니다."
        echo "  수동 설정: ./install.sh --manual"
        echo ""
        exit 0
    fi
fi

# auto / interactive(confirmed): settings.json 자동 수정
python3 - "$SETTINGS" "$BINARY" << 'PYEOF'
import json, sys, os

settings_path = sys.argv[1]
binary_path   = sys.argv[2]

if os.path.exists(settings_path):
    with open(settings_path) as f:
        s = json.load(f)
    # 백업
    with open(settings_path + '.bak', 'w') as f:
        json.dump(s, f, indent=2)
        f.write('\n')
else:
    s = {}

hooks = s.setdefault('hooks', {})

def upsert(event, cmd):
    entries = hooks.setdefault(event, [])
    entries[:] = [e for e in entries if 'mcpredict' not in str(e)]
    entries.append({'matcher': '.*', 'hooks': [{'type': 'command', 'command': cmd}]})

upsert('PreToolUse',  binary_path + ' pre')
upsert('PostToolUse', binary_path + ' post')

with open(settings_path, 'w') as f:
    json.dump(s, f, indent=2)
    f.write('\n')
PYEOF

ok "등록됨: PreToolUse  → $BINARY pre"
ok "등록됨: PostToolUse → $BINARY post"
if [ -f "${SETTINGS}.bak" ]; then
    info "백업됨: ${SETTINGS}.bak"
fi

# ── 완료 ─────────────────────────────────────────────────────────────────────
echo ""
echo "=================================="
echo -e "${BOLD}설치 완료${NC}"
echo ""
echo "  Claude Code를 재시작하면 모든 도구 호출에 mcpredict가 적용됩니다."
echo ""
echo "  대시보드:  $BINARY dashboard 8080"
echo "  감사 로그: ~/.mcpredict/audit.jsonl"
echo "  원상복구:  make cleanup  (또는 ./cleanup.sh)"
echo ""
