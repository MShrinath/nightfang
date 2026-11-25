#!/usr/bin/env bash
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
if [ -z "${NIGHTFANG_ROOT:-}" ]; then
    if [ -f "$(dirname "${BASH_SOURCE[0]}")/tools/gateway.py" ]; then
        NIGHTFANG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [ -f "$(dirname "${BASH_SOURCE[0]}")/../../tools/gateway.py" ]; then
        NIGHTFANG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    elif [ -f "$HERMES_HOME/nightfang/installation.json" ]; then
        INST_FILE="$HERMES_HOME/nightfang/installation.json"
        NIGHTFANG_ROOT="$(python3 -c "import json; d=json.load(open('$INST_FILE', encoding='utf-8-sig')); print(d.get('nightfang_root') or d.get('root', ''))" 2>/dev/null || grep -E -o '"(nightfang_)?root": *"[^"]*"' "$INST_FILE" | head -n1 | cut -d'"' -f4)"
    fi
fi

PYTHON_BIN="python3"
if ! command -v python3 >/dev/null 2>&1 || ! python3 --version >/dev/null 2>&1; then
    if command -v python >/dev/null 2>&1 && python --version >/dev/null 2>&1; then
        PYTHON_BIN="python"
    fi
fi

exec "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/gateway.py" "$@"

