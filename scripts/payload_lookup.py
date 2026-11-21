#!/usr/bin/env python3
"""Agent-side payload lookup utility.

Loads references/payloads/index.json and exposes a simple API for agents to
retrieve non-destructive payloads by vuln class, CWE, or OWASP category.

Usage:
    python scripts/payload_lookup.py --class "SQL Injection"
    python scripts/payload_lookup.py --cwe CWE-89
    python scripts/payload_lookup.py --owasp A03:2021 --safe-only
"""
import argparse
import json
import os
import sys

INDEX_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "references", "payloads", "index.json"
)
# Reference payload repo path (relative to repository root; override via env)
REF_PATH = os.environ.get(
    "NIGHTFANG_PAYLOADS_REF",
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "refs", "payloadsallthethings"
    )
)


def load_index():
    with open(INDEX_PATH, encoding="utf-8") as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description="NIGHTFANG Payload Lookup")
    parser.add_argument("--class", dest="vuln_class", help="Vulnerability class name")
    parser.add_argument("--cwe", help="CWE identifier (e.g. CWE-89)")
    parser.add_argument("--owasp", help="OWASP identifier (e.g. A03:2021)")
    parser.add_argument("--safe-only", action="store_true", help="Only return safe/non-destructive payloads")
    parser.add_argument("--list", action="store_true", help="List all available classes")
    args = parser.parse_args()

    catalog = load_index()

    if args.list:
        for name, meta in sorted(catalog.items()):
            flag = "SAFE" if meta["safe_default"] else "DESTRUCTIVE"
            print(f"{name:45s} [{flag}] cwe={meta['cwe']} owasp={meta['owasp']}")
        return

    if not args.vuln_class and not args.cwe and not args.owasp:
        parser.error("Provide --class, --cwe, --owasp, or --list")

    matches = {}
    for name, meta in catalog.items():
        if args.vuln_class and name.lower() != args.vuln_class.lower():
            continue
        if args.cwe and meta["cwe"].lower() != args.cwe.lower():
            continue
        if args.owasp and meta["owasp"].lower() != args.owasp.lower():
            continue
        if args.safe_only and not meta["safe_default"]:
            continue
        matches[name] = meta

    if not matches:
        print("No matching payload classes found.", file=sys.stderr)
        sys.exit(1)

    for name, meta in matches.items():
        print(f"\n=== {name} ===")
        print(f"CWE: {meta['cwe']} | OWASP: {meta['owasp']} | Safe-by-default: {meta['safe_default']}")
        print(f"Payload files ({len(meta['payload_files'])}):")
        for f in meta["payload_files"][:20]:
            print(f"  {REF_PATH}/{f}")
        if len(meta["payload_files"]) > 20:
            print(f"  ... and {len(meta['payload_files']) - 20} more")


if __name__ == "__main__":
    main()