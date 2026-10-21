#!/usr/bin/env bash
# ============================================================
# NIGHTFANG -> Hermes Status Inspector (Linux/macOS)
# ============================================================
set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
NIGHTFANG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NF_HERMES_HOME="$HERMES_HOME/nightfang"
HERMES_BIN_DIR="$HERMES_HOME/bin"
NF_SKILL_LINK="$HERMES_HOME/skills/nightfang"

BOLD='\033[1m'
GREEN='\033[1;32m'
RED='\033[1;31m'
CYAN='\033[1;36m'
NC='\033[0m'

echo -e "${CYAN}==========================================================${NC}"
echo -e "${CYAN}   NIGHTFANG -> Hermes Health & Integration Status${NC}"
echo -e "${CYAN}==========================================================${NC}"
echo
echo "NIGHTFANG Root : $NIGHTFANG_ROOT"
echo "Hermes Home    : $HERMES_HOME"
echo

ALL_PASSED=1

check_item() {
    local name="$1"
    local path="$2"
    if [[ -e "$path" || -L "$path" ]]; then
        printf "  ${GREEN}[OK]${NC} %s (%s)\n" "$name" "$path"
    else
        printf "  ${RED}[FAIL]${NC} %s missing at %s\n" "$name" "$path"
        ALL_PASSED=0
    fi
}

check_item "Skills Link" "$NF_SKILL_LINK"
check_item "System Prompt" "$NF_HERMES_HOME/system.md"
check_item "Config Overlay" "$NF_HERMES_HOME/config.yaml"
check_item "Scope Storage" "$NF_HERMES_HOME/memory/scope.yaml"
check_item "Findings Store" "$NF_HERMES_HOME/memory/findings.json"
check_item "Gateway Wrapper" "$HERMES_BIN_DIR/nightfang-gate"
check_item "Launcher CLI" "$HERMES_BIN_DIR/nightfang"
check_item "Metadata Record" "$NF_HERMES_HOME/installation.json"

echo
if [[ $ALL_PASSED -eq 1 ]]; then
    printf "${GREEN}${BOLD}Overall Status: NIGHTFANG IS FULLY OPERATIONAL IN HERMES${NC}\n"
else
    printf "${RED}${BOLD}Overall Status: INCOMPLETE INTEGRATION - Run ./install/install.sh${NC}\n"
fi
echo
