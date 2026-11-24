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

# Restore original config and SOUL.md if backup exists
LATEST_CONFIG_BACKUP=$(ls -t "$HERMES_HOME"/config.yaml.backup.* 2>/dev/null | head -n 1 || true)
if [[ -n "$LATEST_CONFIG_BACKUP" && -f "$LATEST_CONFIG_BACKUP" ]]; then
    mv "$LATEST_CONFIG_BACKUP" "$HERMES_HOME/config.yaml"
    echo "[✓] Restored previous Hermes config.yaml"
fi

LATEST_SOUL_BACKUP=$(ls -t "$HERMES_HOME"/SOUL.md.backup.* 2>/dev/null | head -n 1 || true)
if [[ -n "$LATEST_SOUL_BACKUP" && -f "$LATEST_SOUL_BACKUP" ]]; then
    mv "$LATEST_SOUL_BACKUP" "$HERMES_HOME/SOUL.md"
    echo "[✓] Restored previous Hermes SOUL.md"
fi

echo "[✓] NIGHTFANG successfully uninstalled from Hermes."
