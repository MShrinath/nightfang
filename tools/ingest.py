#!/usr/bin/env python3
"""
NIGHTFANG Multi-Tool Finding Ingestion Pipeline (tools/ingest.py)
[DEPRECATED] Consolidated into tools/findings.py.
This module is maintained as a backward-compatibility shim.
"""

from __future__ import annotations

import json
import os
import sys
try:
    from tools.findings import (
        SEVERITY_LEVEL_MAP,
        FindingIngestor,
        run_ingest_tests as run_self_tests,
    )
except ImportError:
    from findings import (
        SEVERITY_LEVEL_MAP,
        FindingIngestor,
        run_ingest_tests as run_self_tests,
    )

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NIGHTFANG Finding Ingestion Pipeline (Compatibility Shim)")
    parser.add_argument("--test", action="store_true", help="Run automated self-tests")
    parser.add_argument("--tool", type=str, help="Tool format hint (nuclei, nmap, semgrep, zap)")
    parser.add_argument("--input", type=str, help="Path to raw tool output file")
    parser.add_argument("--out", type=str, help="Output destination file for normalized JSON findings")
    args = parser.parse_args()

    if args.input:
        if not os.path.exists(args.input):
            print(f"[!] Input file '{args.input}' not found.")
            sys.exit(1)
        with open(args.input, "r", encoding="utf-8", errors="replace") as f:
            raw_text = f.read()
        ingestor = FindingIngestor()
        findings, errors = ingestor.ingest(raw_text, tool_hint=args.tool)
        print(f"[*] Ingested {len(findings)} valid findings ({len(errors)} errors recorded).")
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2)
            print(f"[*] Saved normalized findings to {args.out}")
        else:
            print(json.dumps(findings, indent=2))
        sys.exit(0)

    success = run_self_tests()
    sys.exit(0 if success else 1)
