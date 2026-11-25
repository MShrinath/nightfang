#!/usr/bin/env python3
"""
NIGHTFANG Telegram & Remote Channel Card Formatter (tools/channel_card.py)
[DEPRECATED] Consolidated into tools/daemon.py.
This module is maintained as a backward-compatibility shim.
"""

from __future__ import annotations

import sys
try:
    from tools.daemon import (
        TELEGRAM_MAX_LENGTH,
        escape_markdown,
        truncate_message,
        normalize_target_host,
        is_ip_address,
        extract_root_domain,
        ChannelCardFormatter,
        get_aggregated_state,
        run_channel_card_tests as run_self_tests,
    )
except ImportError:
    from daemon import (
        TELEGRAM_MAX_LENGTH,
        escape_markdown,
        truncate_message,
        normalize_target_host,
        is_ip_address,
        extract_root_domain,
        ChannelCardFormatter,
        get_aggregated_state,
        run_channel_card_tests as run_self_tests,
    )

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NIGHTFANG Telegram Channel Card Formatter (Compatibility Shim)")
    parser.add_argument("--test", action="store_true", help="Run automated self-tests")
    parser.add_argument("--status", "--status-card", dest="status_card", action="store_true", help="Print formatted Telegram status card")
    parser.add_argument("--findings", action="store_true", help="Print formatted Telegram findings card")
    parser.add_argument("--target", type=str, help="Filter findings by root scope or subdomain")
    parser.add_argument("--scope", action="store_true", help="Print formatted Telegram scope card")
    args, unknown = parser.parse_known_args()

    if args.test:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    formatter = ChannelCardFormatter()

    if args.findings:
        try:
            from tools.findings import FindingSyncManager
        except ImportError:
            try:
                from tools.finding_sync import FindingSyncManager
            except ImportError:
                FindingSyncManager = None
        findings = FindingSyncManager().get_all_findings() if FindingSyncManager else []
        print(formatter.format_findings_overview(findings, filter_target=args.target))
        sys.exit(0)

    if args.scope:
        scope_cfg = {
            "target": args.target or "target.corp",
            "allowed_domains": [args.target] if args.target else ["target.corp", "api.target.corp"],
            "allowed_cidrs": ["10.0.0.0/8"],
            "out_of_scope_exclusions": ["169.254.169.254 (IMDS)"],
            "max_requests_per_second": 20,
        }
        print(formatter.format_scope_card(scope_cfg))
        sys.exit(0)

    state = get_aggregated_state(target_scope=[args.target] if args.target else None)
    print(formatter.format_status_card(state))
    sys.exit(0)
