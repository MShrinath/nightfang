#!/usr/bin/env bash
# ============================================================
# NIGHTFANG -> Hermes Uninstaller (Linux/macOS)
# ============================================================
set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
NF_HERMES_HOME="$HERMES_HOME/nightfang"
NF_SKILL_LINK="$HERMES_HOME/skills/nightfang"
HERMES_BIN_DIR="$HERMES_HOME/bin"

echo "Uninstalling NIGHTFANG from Hermes ($HERMES_HOME)..."

rm -rf "$NF_SKILL_LINK"
rm -rf "$NF_HERMES_HOME"
rm -f "$HERMES_BIN_DIR/nightfang"
rm -f "$HERMES_BIN_DIR/nightfang-gate"
rm -f "$HOME/.local/bin/nightfang" 2>/dev/null || true

# Restore original config if backup exists
LATEST_BACKUP=$(ls -t "$HERMES_HOME"/config.yaml.backup.* 2>/dev/null | head -n 1 || true)
if [[ -n "$LATEST_BACKUP" && -f "$LATEST_BACKUP" ]]; then
    mv "$LATEST_BACKUP" "$HERMES_HOME/config.yaml"
    echo "[✓] Restored previous Hermes config.yaml"
fi

echo "[✓] NIGHTFANG successfully uninstalled from Hermes."
