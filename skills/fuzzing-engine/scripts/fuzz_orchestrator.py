#!/usr/bin/env python3
"""
Fuzzing Engine Orchestrator — scaffolds fuzz targets, manages corpus, and
parses crash reports from common fuzzers (AFL++, libFuzzer, honggfuzz).
Read-only analysis mode; never launches a fuzzer against a live target without
explicit authorisation per SOP-01 scope verification.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class CrashReport:
    fuzzer: str
    crash_id: str
    testcase_path: str
    signal: str
    backtrace_snippet: str
    timestamp: str
    corpus_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "fuzzer": self.fuzzer, "crash_id": self.crash_id,
            "testcase_path": self.testcase_path, "signal": self.signal,
            "backtrace_snippet": self.backtrace_snippet[:500],
            "timestamp": self.timestamp, "corpus_hash": self.corpus_hash,
        }


@dataclass
class FuzzReport:
    target_name: str
    timestamp: str
    fuzzers_used: List[str] = field(default_factory=list)
    corpus_size: int = 0
    crashes: List[CrashReport] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)

    def add_crash(self, c: CrashReport) -> None:
        self.crashes.append(c)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "target_name": self.target_name,
            "timestamp": self.timestamp,
            "fuzzers_used": self.fuzzers_used,
            "corpus_size": self.corpus_size,
            "crash_count": len(self.crashes),
            "stats": self.stats,
            "crashes": [c.to_dict() for c in self.crashes],
        }, indent=indent, default=str)


def parse_afl_qemu_crash(crash_dir: str) -> List[CrashReport]:
    """Parse AFL++ QEMU crash directory structure."""
    crashes: List[CrashReport] = []
    # AFL stores crashes in <dir>/crashes/id:<timestamp>:<seq>
    patterns = glob.glob(os.path.join(crash_dir, "id:*"))
    for crash_path in sorted(patterns):
        basename = os.path.basename(crash_path)
        m = re.match(r"id:(?P<ts>\d+),(?P<seq>\d+)", basename)
        sig = "unknown"
        bt = ""
        try:
            info_file = os.path.join(crash_path, "info", "human_readable_report.txt")
            if os.path.isfile(info_file):
                with open(info_file, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
                for line in lines:
                    if line.startswith("Signal:"):
                        sig = line.split(":", 1)[1].strip()
                    elif line.startswith("Backtrace:"):
                        bt = line.split(":", 1)[1].strip()
        except OSError:
            pass
        corpus_hash = hashlib.sha256(open(crash_path, "rb").read()[:4096]).hexdigest()[:16]
        crashes.append(CrashReport(
            fuzzer="afl-qemu",
            crash_id=f"{basename}",
            testcase_path=crash_path,
            signal=sig,
            backtrace_snippet=bt,
            timestamp=datetime.utcnow().isoformat() + "Z",
            corpus_hash=corpus_hash,
        ))
    return crashes


def parse_libfuzzer_crash(output_log: str) -> List[CrashReport]:
    """Parse libFuzzer stdout log for unique crash signatures."""
    crashes: List[CrashReport] = []
    if not os.path.isfile(output_log):
        return crashes
    with open(output_log, encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    # libFuzzer marks UNIQUE_CRASH and DUPLICATE_CRASH blocks
    blocks = re.split(r"\nUnique.*?Crashes?\s*\n", content, flags=re.I)
    for block in blocks[1:]:
        lines = block.strip().splitlines()
        sig_line = next((l for l in lines if l.startswith("SUMMARY:")), "")
        sig = re.sub(r"^SUMMARY:\s*", "", sig_line).strip() if sig_line else "unknown"
        # first few stack lines
        bt_lines = [l for l in lines if re.search(r"#[0-9]+\s+", l)][:5]
        bt = "\n".join(bt_lines)[:500]
        h = hashlib.sha256(block.encode("utf-8", errors="replace")).hexdigest()[:16]
        crashes.append(CrashReport(
            fuzzer="libfuzzer",
            crash_id=h,
            testcase_path=output_log,
            signal=sig,
            backtrace_snippet=bt,
            timestamp=datetime.utcnow().isoformat() + "Z",
            corpus_hash=h,
        ))
    return crashes


def analyse_corpus(corpus_dir: str) -> int:
    """Return number of files in a fuzzing corpus directory."""
    count = 0
    try:
        count = sum(1 for _ in os.scandir(corpus_dir))
    except OSError:
        pass
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Fuzzing Engine Orchestrator (Analysis Mode)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Path to crash directory, fuzzer log, or corpus")
    parser.add_argument("--fuzzer", choices=["afl-qemu", "libfuzzer", "honggfuzz", "auto"],
                        default="auto", help="Fuzzer type (default: auto-detect)")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    fuzz_type = args.fuzzer
    report = FuzzReport(target_name=args.target, timestamp=datetime.utcnow().isoformat() + "Z")

    if os.path.isdir(args.target):
        report.corpus_size = analyse_corpus(args.target)
        # Check for AFL crash subdir
        crash_sub = os.path.join(args.target, "crashes")
        if os.path.isdir(crash_sub) and fuzz_type in ("auto", "afl-qemu"):
            report.fuzzers_used.append("afl-qemu")
            report.crashes.extend(parse_afl_qemu_crash(crash_sub))
        # Check for Honggfuzz output
        hf_log = os.path.join(args.target, "hfuzz_workspace", "*", "report.txt")
        for log_path in glob.glob(hf_log):
            if fuzz_type in ("auto", "honggfuzz"):
                report.fuzzers_used.append("honggfuzz")
                break
        # Any *_dict/* or *.cov files indicate libfuzzer
        if glob.glob(os.path.join(args.target, "*_dict")) or glob.glob(os.path.join(args.target, "*.cov")):
            if fuzz_type in ("auto", "libfuzzer"):
                if "libfuzzer" not in report.fuzzers_used:
                    report.fuzzers_used.append("libfuzzer")
                    # Look for log files
                    for log in glob.glob(os.path.join(args.target, "*.log")):
                        report.crashes.extend(parse_libfuzzer_crash(log))
    elif os.path.isfile(args.target):
        if args.target.endswith(".log") or "fuzzer" in args.target.lower():
            report.fuzzers_used.append("libfuzzer")
            report.crashes.extend(parse_libfuzzer_crash(args.target))
        else:
            print(f"[!] Unrecognised single-file target: {args.target}", file=sys.stderr)
            return 2
    else:
        print(f"[!] Target path does not exist: {args.target}", file=sys.stderr)
        return 2

    report.stats = {"corpus_size": report.corpus_size, "unique_crashes": len(report.crashes)}

    print(f"\n  [*] Analysed target: {args.target}")
    print(f"  [*] Fuzzer(s): {', '.join(report.fuzzers_used) or 'none detected'}")
    print(f"  [*] Corpus size : {report.corpus_size} file(s)")
    print(f"  [*] Unique crashes: {len(report.crashes)}\n")
    for c in report.crashes[:10]:
        print(f"  [CRASH] [{c.fuzzer}] {c.crash_id[:16]} | Signal: {c.signal}")
        print(f"          Testcase : {c.testcase_path}")

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report.to_json())
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    return 1 if report.crashes else 0


if __name__ == "__main__":
    sys.exit(main())
