#!/usr/bin/env python3
"""
NIGHTFANG Containerized Sandbox Runner (tools/sandbox.py)
[DEPRECATED] Consolidated into tools/gateway.py.
This module is maintained as a backward-compatibility shim.
"""

from __future__ import annotations

import sys
try:
    from tools.gateway import (
        SandboxMode,
        SandboxConfig,
        SandboxProbeReport,
        SandboxRunner,
        _command_name,
        check_command_allowlist,
        run_sandbox_tests as run_self_tests,
    )
except ImportError:
    from gateway import (
        SandboxMode,
        SandboxConfig,
        SandboxProbeReport,
        SandboxRunner,
        _command_name,
        check_command_allowlist,
        run_sandbox_tests as run_self_tests,
    )

if __name__ == "__main__":
    success = run_self_tests()
    sys.exit(0 if success else 1)
