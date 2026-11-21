#!/usr/bin/env python3
"""
File Hash & Integrity Verifier
Computes SHA-256/SHA-1/MD5 hashes for files/directories — used for evidence
preservation (chain-of-custody per SOP-06) and integrity validation of acquired
artifacts throughout any VAPT engagement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List


ALGORITHMS = ("sha256", "sha1", "md5")


@dataclass
class HashResult:
    path: str
    size_bytes: int
    modified_iso: str
    hashes: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "modified_iso": self.modified_iso,
            "hashes": self.hashes,
            "errors": self.errors,
        }


def hash_file(filepath: str, algorithms: tuple = ALGORITHMS) -> HashResult:
    """Compute cryptographic hashes for a single file."""
    result = HashResult(path=filepath, size_bytes=0, modified_iso="")
    try:
        stat = os.stat(filepath)
        result.size_bytes = stat.st_size
        result.modified_iso = datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z"
    except OSError as exc:
        result.errors.append(f"os.stat failed: {exc}")
        return result

    hmods = {alg: hashlib.new(alg) for alg in algorithms}
    try:
        with open(filepath, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)  # 1 MiB
                if not chunk:
                    break
                for hm in hmods.values():
                    hm.update(chunk)
    except OSError as exc:
        result.errors.append(f"read failed: {exc}")
        return result

    result.hashes = {alg: hm.hexdigest() for alg, hm in hmods.items()}
    return result


def hash_directory(root_path: str, algorithms: tuple = ALGORITHMS) -> List[HashResult]:
    """Recursively hash every regular file under root_path."""
    results: List[HashResult] = []
    for dirpath, _, filenames in os.walk(root_path):
        for fname in sorted(filenames):
            full = os.path.join(dirpath, fname)
            if os.path.isfile(full):
                results.append(hash_file(full, algorithms))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG File Hash & Integrity Verifier",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="File or directory to hash")
    parser.add_argument("-a", "--algorithms", default=",".join(ALGORITHMS),
                        help=f"Comma-separated hash algorithms (default: {','.join(ALGORITHMS)})")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    parser.add_argument("--plain", action="store_true",
                        help="Print plain text hash lines (like shasum output)")
    args = parser.parse_args()

    target = args.target
    if not os.path.exists(target):
        print(f"[!] Target does not exist: {target}", file=sys.stderr)
        return 2

    algos = [a.strip().lower() for a in args.algorithms.split(",") if a.strip()]
    algo_set = set(algos) & set(ALGORITHMS)
    if not algo_set:
        print(f"[!] No valid algorithms from: {', '.join(algos)}", file=sys.stderr)
        return 2

    is_dir = os.path.isdir(target)
    if is_dir:
        results = hash_directory(target, tuple(algo_set))
    else:
        results = [hash_file(target, tuple(algo_set))]

    if args.plain:
        for r in results:
            for alg, digest in r.hashes.items():
                alg_upper = alg.upper()
                print(f"{digest}  {r.path}")
    else:
        report = {
            "target": target,
            "is_directory": is_dir,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "algorithm": list(algo_set),
            "items_count": len(results),
            "items": [r.to_dict() for r in results],
        }
        print(json.dumps(report, indent=2))

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({
                "target": target,
                "is_directory": is_dir,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "algorithm": list(algo_set),
                "items_count": len(results),
                "items": [r.to_dict() for r in results],
            }, fh, indent=2)
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    print(f"\n  [*] Hashed {len(results)} item(s) using {', '.join(sorted(algo_set))}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
