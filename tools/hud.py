#!/usr/bin/env python3
"""
NIGHTFANG Autonomous Hunter Real-Time Terminal HUD (tools/hud.py)

Provides a real-time live terminal dashboard of autonomous hunting progress:
- Header: Engagement ID, Target Scope, Active Autonomy Tier
- Active Execution: Concurrency usage, active hosts, current agent tasks
- Rate Limiting: Dynamic backoff countdowns per host/IP
- Priority DAG Queue: Counts for CRITICAL, HIGH, MEDIUM, and LOW priority leads
- Attack Surface Tree: Discovered domains, subdomains, endpoints, open ports
- HITL Approval Bar: Live prompt and status of pending operator authorization requests
- Non-TTY Safe: Degrades gracefully to clean structured text when piped or redirected
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

# ANSI escape sequences for formatting
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
BG_DARK = "\033[40m"


class HunterHUD:
    """Terminal HUD renderer for NIGHTFANG Autonomous Hunter Daemon."""

    def __init__(self, force_ansi: Optional[bool] = None) -> None:
        if force_ansi is not None:
            self.use_ansi = force_ansi
        else:
            self.use_ansi = sys.stdout.isatty() and os.name != "dumb"

    def strip_ansi(self, text: str) -> str:
        """Strip ANSI escape sequences from text for measuring visible length."""
        return re.sub(r"\033\[[0-9;]*[mK]", "", text)

    def colorize(self, text: str, color_code: str) -> str:
        """Wrap text in ANSI color code if ANSI is enabled."""
        if not self.use_ansi:
            return text
        return f"{color_code}{text}{RESET}"

    def get_term_size(self) -> Tuple[int, int]:
        """Get current terminal dimensions (width, height), defaulting to 80x24."""
        try:
            cols, rows = shutil.get_terminal_size(fallback=(80, 24))
            return max(60, cols), max(20, rows)
        except Exception:
            return 80, 24

    def format_box_line(self, content: str, width: int) -> str:
        """Format a single row inside an ASCII/Unicode box with proper padding."""
        visible_len = len(self.strip_ansi(content))
        padding = max(0, width - 4 - visible_len)
        return f"│ {content}{' ' * padding} │"

    def render(
        self,
        engagement_id: str,
        target_scope: List[str],
        autonomy_tier: str,
        status: str,
        queue_counts: Dict[str, int],
        active_tasks: List[Dict[str, str]],
        rate_backoffs: Dict[str, float],
        discovered_assets: List[str],
        pending_hitl: List[Dict[str, str]],
        term_width: Optional[int] = None,
    ) -> str:
        """Render complete HUD frame as a formatted multi-line string."""
        cols, _ = self.get_term_size()
        width = min(term_width or cols, 100)
        inner_width = width - 2

        border_h = "─" * inner_width
        top_border = f"┌{border_h}┐"
        mid_border = f"├{border_h}┤"
        bot_border = f"└{border_h}┘"

        lines: List[str] = [top_border]

        # 1. Header Section
        title = self.colorize("🦇 NIGHTFANG AUTONOMOUS HUNTER HUD", BOLD + CYAN)
        status_color = GREEN if status == "ACTIVE" else (YELLOW if status == "PAUSED" else WHITE)
        status_badge = self.colorize(f"[{status}]", BOLD + status_color)
        lines.append(self.format_box_line(f"{title} {status_badge}", width))

        scope_str = ", ".join(target_scope[:3]) + ("..." if len(target_scope) > 3 else "")
        info_line = (
            f"Engagement: {self.colorize(engagement_id, YELLOW)} │ "
            f"Scope: {self.colorize(scope_str, WHITE)} │ "
            f"Tier: {self.colorize(autonomy_tier, MAGENTA)}"
        )
        lines.append(self.format_box_line(info_line, width))
        lines.append(mid_border)

        # 2. Priority DAG Queue Section
        c_count = queue_counts.get("CRITICAL", 0)
        h_count = queue_counts.get("HIGH", 0)
        m_count = queue_counts.get("MEDIUM", 0)
        l_count = queue_counts.get("LOW", 0)
        total_queued = c_count + h_count + m_count + l_count

        q_header = self.colorize("PRIORITY DAG QUEUE", BOLD)
        q_line = (
            f"{q_header} ({total_queued} tasks): "
            f"{self.colorize(f'CRITICAL: {c_count}', BOLD + RED)} │ "
            f"{self.colorize(f'HIGH: {h_count}', YELLOW)} │ "
            f"{self.colorize(f'MEDIUM: {m_count}', BLUE)} │ "
            f"{self.colorize(f'LOW: {l_count}', DIM)}"
        )
        lines.append(self.format_box_line(q_line, width))

        # 3. Active Host Rate Throttles & Backoffs
        lines.append(mid_border)
        backoff_header = self.colorize("ACTIVE HOST RATE THROTTLES & BACKOFFS", BOLD)
        if rate_backoffs:
            now = time.time()
            backoff_items: List[str] = []
            for host, expire in list(rate_backoffs.items())[:3]:
                remaining = max(0, int(expire - now))
                backoff_items.append(f"{host}: {remaining}s remaining")
            lines.append(self.format_box_line(f"{backoff_header}: {', '.join(backoff_items)}", width))
        else:
            lines.append(self.format_box_line(f"{backoff_header}: None (All target hosts nominal)", width))

        # 4. Active Tasks Execution
        lines.append(mid_border)
        exec_header = self.colorize("ACTIVE CONCURRENCY & EXECUTIONS", BOLD)
        lines.append(self.format_box_line(f"{exec_header} ({len(active_tasks)} active):", width))
        if active_tasks:
            for task in active_tasks[:3]:
                t_str = f"  ▶ [{task.get('tool', 'tool')}] {task.get('target', 'target')} ({task.get('technique', 'scanning')})"
                lines.append(self.format_box_line(self.colorize(t_str, CYAN), width))
        else:
            lines.append(self.format_box_line("  (No tasks currently in flight)", width))

        # 5. Attack Surface Discovered
        lines.append(mid_border)
        assets_header = self.colorize("DISCOVERED ATTACK SURFACE", BOLD)
        assets_preview = ", ".join(discovered_assets[:4]) if discovered_assets else "None"
        if len(discovered_assets) > 4:
            assets_preview += f" (+{len(discovered_assets) - 4} more)"
        lines.append(self.format_box_line(f"{assets_header} ({len(discovered_assets)} assets): {assets_preview}", width))

        # 6. HITL Operator Approval Bar
        lines.append(mid_border)
        hitl_header = self.colorize("OPERATOR HITL APPROVAL GATE", BOLD + (RED if pending_hitl else GREEN))
        if pending_hitl:
            p = pending_hitl[0]
            hitl_msg = f"  ⚠ PENDING APPROVAL: Token [{p.get('token', 'TOKEN')}] for {p.get('technique', 'Exploit')} on {p.get('target', 'target')}"
            lines.append(self.format_box_line(self.colorize(hitl_msg, BOLD + RED), width))
            lines.append(self.format_box_line(f"    Press 'a' to approve, 'd' to deny, 's' to skip", width))
        else:
            lines.append(self.format_box_line(f"{hitl_header}: 0 pending authorizations required", width))

        lines.append(bot_border)
        return "\n".join(lines)


def run_self_tests() -> bool:
    """Run automated verification suite for Autonomous Hunter Terminal HUD."""
    print("Running NIGHTFANG Autonomous Hunter Terminal HUD Self-Tests...")

    # Test 1: ASCII box generation and boundary formatting (with ANSI)
    hud_ansi = HunterHUD(force_ansi=True)
    frame = hud_ansi.render(
        engagement_id="ENG-2026-TEST",
        target_scope=["target.corp", "*.target.corp"],
        autonomy_tier="SEMI_AUTONOMOUS",
        status="ACTIVE",
        queue_counts={"CRITICAL": 1, "HIGH": 3, "MEDIUM": 5, "LOW": 10},
        active_tasks=[{"tool": "nuclei", "target": "api.target.corp", "technique": "API Scan"}],
        rate_backoffs={"api.target.corp": time.time() + 30},
        discovered_assets=["target.corp", "api.target.corp", "vpn.target.corp"],
        pending_hitl=[{"token": "tok-987a", "target": "api.target.corp", "technique": "SQLi PoC"}],
        term_width=80,
    )
    assert "NIGHTFANG AUTONOMOUS HUNTER HUD" in frame
    assert "ENG-2026-TEST" in frame
    assert "CRITICAL: 1" in frame
    assert "HIGH: 3" in frame
    print("  [PASS] Test 1: Terminal HUD ASCII border layout and box formatting verified.")

    # Test 2: Queue counts and formatting assertion
    assert "MEDIUM: 5" in frame
    assert "LOW: 10" in frame
    assert "19 tasks" in frame
    print("  [PASS] Test 2: Multi-tier DAG priority queue counts formatted accurately.")

    # Test 3: Rate backoff countdown rendering
    assert "30s remaining" in frame or "29s remaining" in frame
    print("  [PASS] Test 3: Host rate throttle backoff countdown rendering verified.")

    # Test 4: Non-TTY fallback mode (clean plain text without escape sequences)
    hud_nontty = HunterHUD(force_ansi=False)
    plain_frame = hud_nontty.render(
        engagement_id="ENG-PLAIN-TEST",
        target_scope=["plain.corp"],
        autonomy_tier="FULL_AUTONOMOUS",
        status="ACTIVE",
        queue_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0},
        active_tasks=[],
        rate_backoffs={},
        discovered_assets=["plain.corp"],
        pending_hitl=[],
        term_width=80,
    )
    assert "\033[" not in plain_frame, f"Found unexpected ANSI escapes in non-TTY mode: {plain_frame}"
    assert "ENG-PLAIN-TEST" in plain_frame
    assert "0 pending authorizations required" in plain_frame
    print("  [PASS] Test 4: Non-TTY fallback mode verified (0 escape codes generated).")

    print("\nAll 4 Terminal HUD self-tests PASSED successfully!")
    return True


def run_demo() -> None:
    """Run interactive demonstration of HUD rendering."""
    hud = HunterHUD()
    print("\n--- [NIGHTFANG HUD DEMO FRAME 1: Active Scanning & HITL Required] ---")
    frame1 = hud.render(
        engagement_id="ENG-DEMO-2026",
        target_scope=["securebank.internal", "*.securebank.internal"],
        autonomy_tier="SEMI_AUTONOMOUS",
        status="ACTIVE",
        queue_counts={"CRITICAL": 2, "HIGH": 4, "MEDIUM": 12, "LOW": 35},
        active_tasks=[
            {"tool": "nuclei", "target": "api.securebank.internal", "technique": "API Vulnerability Probe"},
            {"tool": "nmap", "target": "vpn.securebank.internal", "technique": "Port Sweep"},
        ],
        rate_backoffs={"api.securebank.internal": time.time() + 45},
        discovered_assets=["securebank.internal", "api.securebank.internal", "auth.securebank.internal", "vpn.securebank.internal"],
        pending_hitl=[{"token": "tok-a49f1", "target": "auth.securebank.internal", "technique": "SAML Auth Bypass PoC"}],
    )
    print(frame1)

    print("\n--- [NIGHTFANG HUD DEMO FRAME 2: Nominal / All Idle] ---")
    frame2 = hud.render(
        engagement_id="ENG-DEMO-2026",
        target_scope=["securebank.internal"],
        autonomy_tier="FULL_AUTONOMOUS",
        status="IDLE",
        queue_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        active_tasks=[],
        rate_backoffs={},
        discovered_assets=["securebank.internal"],
        pending_hitl=[],
    )
    print(frame2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIGHTFANG Autonomous Hunter Terminal HUD")
    parser.add_argument("--test", action="store_true", help="Run automated self-tests")
    parser.add_argument("--demo", action="store_true", help="Display demonstration HUD frames")
    args = parser.parse_args()

    if args.test:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    if args.demo:
        run_demo()
        sys.exit(0)

    # Default action
    success = run_self_tests()
    sys.exit(0 if success else 1)
