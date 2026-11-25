#!/usr/bin/env python3
"""
NIGHTFANG Finding Persistence & Knowledge Graph Bridge (tools/finding_sync.py)
[DEPRECATED] Consolidated into tools/findings.py.
This module is maintained as a backward-compatibility shim.
"""

from __future__ import annotations

import json
import os
import sys
try:
    from tools.findings import (
        normalize_target_host,
        is_ip_address,
        extract_root_domain,
        FindingSyncManager,
        run_finding_sync_tests as run_self_tests,
    )
except ImportError:
    from findings import (
        normalize_target_host,
        is_ip_address,
        extract_root_domain,
        FindingSyncManager,
        run_finding_sync_tests as run_self_tests,
    )

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NIGHTFANG Finding Sync Bridge (Compatibility Shim)")
    parser.add_argument("--test", action="store_true", help="Run automated self-tests")
    parser.add_argument("--sync", nargs="?", const="default", type=str, help="Path to JSON file containing findings to sync")
    parser.add_argument("--target", type=str, help="Target override or target filter")
    parser.add_argument("--list", action="store_true", help="List stored findings summary")
    args, unknown = parser.parse_known_args()

    if args.sync:
        sync_path = args.sync
        if sync_path == "default":
            repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            sync_path = os.path.join(repo_root, "memory", "findings.json")
        if not os.path.exists(sync_path):
            print(f"[!] Input file '{sync_path}' not found.")
            sys.exit(1)
        with open(sync_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings_list = data if isinstance(data, list) else (list(data["findings"].values()) if isinstance(data, dict) and "findings" in data else [data])
        mgr = FindingSyncManager()
        res = mgr.sync_batch(findings_list, target_override=args.target)
        print(f"[*] Sync Complete: Ingested={res['ingested']}, Failed={res['failed']}")
        sys.exit(0 if res["failed"] == 0 else 1)

    if args.list:
        mgr = FindingSyncManager()
        store = mgr.load_findings_store()
        scopes = store.get("scopes", {})
        print(f"[*] Total Scopes: {len(scopes)} | Total Findings: {len(store.get('findings', {}))}")
        for s_name, s_data in scopes.items():
            print(f"  Scope: {s_name} ({s_data.get('total_findings', 0)} findings across {len(s_data.get('hosts', {}))} hosts)")
            for h_name, h_keys in s_data.get("hosts", {}).items():
                print(f"    Host: {h_name} -> {len(h_keys)} findings")
        sys.exit(0)

    success = run_self_tests()
    sys.exit(0 if success else 1)
