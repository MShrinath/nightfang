#!/usr/bin/env bash
set -e

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
NIGHTFANG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

export HERMES_HOME
export NIGHTFANG_ROOT
export HERMES_SYSTEM_PROMPT="$HERMES_HOME/nightfang/system.md"
export HERMES_CONFIG="$HERMES_HOME/nightfang/config.yaml"

if [ -t 1 ]; then
    printf '\033[1;36m🦇 NIGHTFANG Security Intelligence Layer (Active)\033[0m\n'
    printf '\033[1;35m37 Specialized Agents | 33 Capabilities | Autonomous Hunter: READY\033[0m\n\n'
fi

if [ "$1" = "--daemon" ]; then
    shift
    exec python3 "$NIGHTFANG_ROOT/tools/daemon.py" "$@"
elif [ "$1" = "--hunt" ]; then
    shift
    exec python3 "$NIGHTFANG_ROOT/tools/daemon.py" --continuous "$@"
elif [ "$1" = "--test" ]; then
    python3 "$NIGHTFANG_ROOT/tools/daemon.py" --test
    python3 "$NIGHTFANG_ROOT/tools/gateway.py"
    exit 0
fi

if command -v hermes >/dev/null 2>&1; then
    exec hermes --system-prompt "$HERMES_SYSTEM_PROMPT" --config "$HERMES_CONFIG" "$@"
else
    echo "[*] Hermes binary not detected in PATH."
    if [ "$#" -gt 0 ]; then
        exec python3 "$NIGHTFANG_ROOT/tools/daemon.py" "$@"
    else
        echo "Usage:"
        echo "  nightfang --daemon --target <domain>    Run continuous autonomous hunter"
        echo "  nightfang --hunt <domain>               Launch autonomous attack chain"
        echo "  nightfang --test                        Run gateway and daemon self-tests"
        echo ""
        echo "Starting interactive Autonomous Hunter session..."
        python3 -i -c "import sys; sys.path.insert(0, '$NIGHTFANG_ROOT/tools'); from daemon import AutonomousHunterDaemon; from gateway import ExecutionPolicyGateway; print('[*] NIGHTFANG Autonomous Hunter and Gateway loaded.')"
    fi
fi
