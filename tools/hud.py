#!/usr/bin/env python3
"""
NIGHTFANG Autonomous Hunter Real-Time Terminal HUD (tools/hud.py)
[DEPRECATED] Consolidated into tools/daemon.py.
This module is maintained as a backward-compatibility shim.
"""

from __future__ import annotations

import sys
try:
    from tools.daemon import (
        HunterHUD,
        TerminalHUD,
        get_aggregated_state,
        run_hud_tests as run_self_tests,
    )
except ImportError:
    from daemon import (
        HunterHUD,
        TerminalHUD,
        get_aggregated_state,
        run_hud_tests as run_self_tests,
    )

def run_demo() -> None:
    hud = HunterHUD()
    state = get_aggregated_state()
    print(hud.render(state))

if __name__ == "__main__":
    if "--demo" in sys.argv:
        run_demo()
        sys.exit(0)
    success = run_self_tests()
    sys.exit(0 if success else 1)
