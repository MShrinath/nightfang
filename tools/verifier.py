#!/usr/bin/env python3
"""
NIGHTFANG Adversarial Validation Gate & Canary Engine (tools/verifier.py)
[DEPRECATED] Consolidated into tools/findings.py.
This module is maintained as a backward-compatibility shim.
"""

from __future__ import annotations

import json
import os
import sys
try:
    from tools.findings import (
        WAF_BLOCK_PATTERNS,
        AdversarialGateEvaluation,
        AdversarialVerifier,
        run_verifier_tests as run_self_tests,
    )
except ImportError:
    from findings import (
        WAF_BLOCK_PATTERNS,
        AdversarialGateEvaluation,
        AdversarialVerifier,
        run_verifier_tests as run_self_tests,
    )

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NIGHTFANG Adversarial Gate & Canary Engine (Compatibility Shim)")
    parser.add_argument("--test", action="store_true", help="Run automated self-tests")
    parser.add_argument("--verify", nargs="?", const="default", type=str, help="Path to finding JSON file to evaluate")
    parser.add_argument("--verify-canary", dest="verify_canary", type=str, help="Canary ID to verify cleanup")
    parser.add_argument("--register-canary", dest="register_canary", type=str, help="Canary ID to register")
    parser.add_argument("--target", type=str, default="target.corp", help="Target domain for canary registration")
    parser.add_argument("--type", type=str, default="test_file", help="Canary type")
    parser.add_argument("--path", type=str, default="/tmp/canary.txt", help="Resource path for canary")
    parser.add_argument("--mock-status", type=int, default=404, help="Mock HTTP status code for cleanup check")
    args, unknown = parser.parse_known_args()

    verifier = AdversarialVerifier()

    if args.verify:
        v_path = args.verify
        if v_path == "default":
            repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            v_path = os.path.join(repo_root, "memory", "findings.json")
        if not os.path.exists(v_path):
            print(f"[!] Finding file '{v_path}' not found.")
            sys.exit(1)
        with open(v_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        finding_items = list(data["findings"].values()) if (isinstance(data, dict) and "findings" in data) else (data if isinstance(data, list) else [data])
        disqualified = 0
        confirmed = 0
        for item in finding_items:
            eval_res = verifier.evaluate_finding(item)
            fid = item.get("finding", item).get("id", "finding")
            print(f"[*] Adversarial Gate Evaluation [{fid}]:")
            print(f"    Verdict:    {eval_res.verdict}")
            print(f"    Confidence: {eval_res.confidence_score}/10")
            print(f"    Reason:     {eval_res.reason}")
            if eval_res.failed_gate:
                print(f"    Failed:     {eval_res.failed_gate}")
                disqualified += 1
            else:
                confirmed += 1
        print(f"[*] Evaluation Complete: Confirmed/Likely={confirmed}, Disqualified={disqualified}")
        sys.exit(0 if disqualified == 0 else 1)

    if args.register_canary:
        rec = verifier.register_canary(args.register_canary, args.target, args.type, args.path)
        print(f"[*] Canary Registered: {rec['canary_id']} ({rec['status']}) at {rec['resource_path']}")
        sys.exit(0)

    if args.verify_canary:
        if args.verify_canary not in verifier.active_canaries:
            verifier.register_canary(args.verify_canary, args.target, "canary", args.path)
        ok, msg = verifier.verify_cleanup(args.verify_canary, mock_http_status=args.mock_status)
        print(f"[*] Canary Cleanup: {msg}")
        sys.exit(0 if ok else 1)

    success = run_self_tests()
    sys.exit(0 if success else 1)
