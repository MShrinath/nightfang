#!/usr/bin/env bash
NIGHTFANG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 "$NIGHTFANG_ROOT/tools/gateway.py" "$@"
