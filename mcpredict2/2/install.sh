#!/bin/bash
# mcpredict installer — ARCHITECTURE.md v1.1 §6.
#
# Usage:
#   ./install.sh                    # build + install for current user
#   ./install.sh --uninstall        # remove hooks from settings.json (binary stays)
#
# Steps:
#   1. go build → ~/.claude/hooks/mcpredict
#   2. mcpredict init → ~/.mcpredict/{policies,audit.jsonl,session.db}
#   3. patch ~/.claude/settings.json with PreToolUse + PostToolUse hooks
#      (preserves existing hook entries; refuses to add duplicates)
#
# A new Claude Code session is required for the hooks to activate (V6 finding —
# settings watcher does not in-session reload new hook entries).

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DEST="${HOME}/.claude/hooks/mcpredict"
SETTINGS="${HOME}/.claude/settings.json"
HOOK_CMD_PRE="${BIN_DEST} pre"
HOOK_CMD_POST="${BIN_DEST} post"

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }
}

uninstall() {
  require jq
  [ -f "$SETTINGS" ] || { echo "$SETTINGS not present, nothing to remove"; exit 0; }
  tmp="$(mktemp)"
  jq --arg cpre  "$HOOK_CMD_PRE" \
     --arg cpost "$HOOK_CMD_POST" '
    .hooks.PreToolUse  |= map(.hooks |= map(select(.command != $cpre)))  |
    .hooks.PostToolUse |= map(.hooks |= map(select(.command != $cpost))) |
    .hooks.PreToolUse  |= map(select((.hooks // []) | length > 0))       |
    .hooks.PostToolUse |= map(select((.hooks // []) | length > 0))
  ' "$SETTINGS" > "$tmp"
  mv "$tmp" "$SETTINGS"
  echo "removed mcpredict hook entries from $SETTINGS"
  echo "binary at $BIN_DEST left in place"
  exit 0
}

case "${1:-}" in
  --uninstall|-u) uninstall ;;
  -h|--help)
    sed -n '2,20p' "$0"
    exit 0
    ;;
esac

require go
require jq

echo "[1/3] building mcpredict..."
( cd "$SCRIPT_DIR" && go build -o "$BIN_DEST" ./cmd/mcpredict )
mkdir -p "$(dirname "$BIN_DEST")"
echo "      installed → $BIN_DEST"

echo "[2/3] initializing state directory..."
"$BIN_DEST" init

echo "[3/3] patching $SETTINGS..."
mkdir -p "$(dirname "$SETTINGS")"
[ -f "$SETTINGS" ] || echo '{}' > "$SETTINGS"

tmp="$(mktemp)"
jq --arg cpre  "$HOOK_CMD_PRE" \
   --arg cpost "$HOOK_CMD_POST" '
  .hooks //= {} |
  .hooks.PreToolUse  //= [] |
  .hooks.PostToolUse //= [] |

  # add a matcher-".*" group if no existing one. Preserve everything else.
  if (.hooks.PreToolUse | map(.matcher) | index(".*")) == null then
    .hooks.PreToolUse  += [{matcher: ".*", hooks: []}]
  else . end |
  if (.hooks.PostToolUse | map(.matcher) | index(".*")) == null then
    .hooks.PostToolUse += [{matcher: ".*", hooks: []}]
  else . end |

  # Inside the matcher-".*" group, add our command unless already present.
  .hooks.PreToolUse  |= map(
    if .matcher == ".*"
    then if ((.hooks // []) | map(.command) | index($cpre)) == null
         then .hooks += [{type:"command", command:$cpre,  timeout:5}]
         else . end
    else . end
  ) |
  .hooks.PostToolUse |= map(
    if .matcher == ".*"
    then if ((.hooks // []) | map(.command) | index($cpost)) == null
         then .hooks += [{type:"command", command:$cpost, timeout:5}]
         else . end
    else . end
  )
' "$SETTINGS" > "$tmp"

if jq -e . >/dev/null 2>&1 < "$tmp"; then
  mv "$tmp" "$SETTINGS"
  echo "      patched."
else
  echo "ERROR: settings.json would be malformed; aborting (kept $tmp for inspection)" >&2
  exit 1
fi

cat <<'EOF'

✓ mcpredict installed.

⚠ Start a NEW Claude Code session to activate the hooks. The settings watcher
  does not reload new hook entries within a running session (V6 finding).

Inspect:    less ~/.mcpredict/audit.jsonl
Reset:      ./install.sh --uninstall  &&  rm -rf ~/.mcpredict
EOF
