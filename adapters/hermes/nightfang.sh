#!/usr/bin/env bash
set -e

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
if [ -z "${NIGHTFANG_ROOT:-}" ]; then
    if [ -f "$(dirname "${BASH_SOURCE[0]}")/tools/gateway.py" ]; then
        NIGHTFANG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [ -f "$(dirname "${BASH_SOURCE[0]}")/../../tools/gateway.py" ]; then
        NIGHTFANG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    elif [ -f "$HERMES_HOME/nightfang/installation.json" ]; then
        NIGHTFANG_ROOT="$(grep -o '"root": *"[^"]*"' "$HERMES_HOME/nightfang/installation.json" | cut -d'"' -f4)"
    fi
fi

PYTHON_BIN="python3"
if ! command -v python3 >/dev/null 2>&1 || ! python3 --version >/dev/null 2>&1; then
    if command -v python >/dev/null 2>&1 && python --version >/dev/null 2>&1; then
        PYTHON_BIN="python"
    fi
fi

export HERMES_HOME
export NIGHTFANG_ROOT
export HERMES_SYSTEM_PROMPT="$HERMES_HOME/nightfang/system.md"
export HERMES_CONFIG="$HERMES_HOME/nightfang/config.yaml"

if [ -t 1 ]; then
    printf '\033[1;36m🦇 NIGHTFANG Security Intelligence Layer (Active)\033[0m\n'
    printf '\033[1;35m46 Specialized Agents | 42 Capabilities | Autonomous Hunter: READY\033[0m\n\n'
fi

if [ "$1" = "--daemon" ]; then
    shift
    exec "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/daemon.py" "$@"
elif [ "$1" = "--hunt" ]; then
    shift
    exec "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/daemon.py" --continuous "$@"
elif [ "$1" = "--status-card" ]; then
    shift
    exec "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/daemon.py" --card status "$@"
elif [ "$1" = "--sync" ]; then
    shift
    exec "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/findings.py" --sync "$@"
elif [ "$1" = "--verify" ]; then
    shift
    exec "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/findings.py" --verify "$@"
elif [ "$1" = "--verify-canary" ]; then
    shift
    exec "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/findings.py" --verify-canary "$@"
elif [ "$1" = "--ingest" ]; then
    shift
    exec "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/findings.py" --ingest "$@"
elif [ "$1" = "--list-findings" ]; then
    shift
    exec "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/findings.py" --list-findings "$@"
elif [ "$1" = "--test" ]; then
    "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/daemon.py" --test
    "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/gateway.py" --test
    "$PYTHON_BIN" "$NIGHTFANG_ROOT/schemas/validator.py" --test
    "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/findings.py" --test
    echo ""
    echo "[*] All 3 unified engine self-tests and schema validator passed successfully!"
    exit 0
elif [ "$1" = "--test-all" ]; then
    "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/daemon.py" --test
    "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/gateway.py" --test
    "$PYTHON_BIN" "$NIGHTFANG_ROOT/schemas/validator.py" --test
    "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/findings.py" --test
    "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/simulation.py" --test
    echo ""
    echo "[*] All 3 unified engines and E2E simulation passed successfully!"
    exit 0
fi

if command -v hermes >/dev/null 2>&1; then
    exec hermes "$@"
else
    echo "[*] Hermes binary not detected in PATH."
    if [ "$#" -gt 0 ]; then
        exec "$PYTHON_BIN" "$NIGHTFANG_ROOT/tools/daemon.py" "$@"
    else
        echo "Usage:"
        echo "  nightfang --daemon --target <domain>    Run continuous autonomous hunter"
        echo "  nightfang --hunt <domain>               Launch autonomous attack chain"
        echo "  nightfang --test                        Run tool self-tests"
        echo "  nightfang --test-all                    Run all self-tests and E2E simulation"
        echo ""
        echo "Starting interactive Autonomous Hunter session..."
        "$PYTHON_BIN" -i -c "import sys; sys.path.insert(0, '$NIGHTFANG_ROOT/tools'); from daemon import AutonomousHunterDaemon; from gateway import ExecutionPolicyGateway; print('[*] NIGHTFANG Autonomous Hunter and Gateway loaded.')"
    fi
fi
