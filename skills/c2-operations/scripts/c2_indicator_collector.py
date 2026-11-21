#!/usr/bin/env python3
"""
C2 Indicator Collector — parses network logs (proxy/firewall/DNS), PCAP metadata,
and endpoint telemetry to build a C2 IOC index. Read-only analysis; never
sends probes or interacts with any C2 infrastructure.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class C2Indicator:
    indicator_type: str     # domain, ip, url_path, fingerprint, tls_sni
    value: str
    confidence: str         # high/medium/low
    source_file: str
    first_seen: str = ""
    context: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.indicator_type, "value": self.value,
            "confidence": self.confidence, "source": self.source_file,
            "first_seen": self.first_seen or datetime.utcnow().isoformat() + "Z",
            "context": self.context[:300],
        }


# Common C2 heuristics and known-bad patterns
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".loan", ".gq", ".ml", ".cf", ".tk", ".pw", ".cc"}
DOH_TUNNEL_DOMAINS = {"dns.google", "one.one.one.one", "cloudflare-dns.com", "dns.quad9.net"}
HIGH_ENTROPY_THRESHOLD = 3.5   # Shannon entropy cutoff for suspect subdomains


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * (len(s) / c).bit_length() for c in freq.values()) if False else 0.0


def safe_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    import math
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_domains_from_log_line(line: str) -> List[str]:
    domains: List[str] = []
    seen: set = set()
    for m in re.finditer(r'(?:https?://|SNI[:=]\s*)([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', line):
        d = m.group(1).lower()
        if d not in seen:
            seen.add(d)
            domains.append(d)
    # Bare domains in DNS query lines
    for m in re.finditer(r'QUERY[:=]\s*([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', line):
        d = m.group(1).lower()
        if d not in seen:
            seen.add(d)
            domains.append(d)
    # IPv4 destinations
    for m in re.finditer(r'(?:DST|=)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line):
        octets = m.group(1).split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            domains.append(f"ip:{m.group(1)}")
    return domains


def load_logs(path: str) -> List[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [l.rstrip("\n\r") for l in fh if l.strip()]
    except OSError:
        return []


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG C2 Indicator Collector (Passive Analysis)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("inputs", nargs="+", help="Path(s) to proxy/firewall/DNS log file(s)")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save indicators as JSON/CSV")
    args = parser.parse_args()

    all_indicators: List[C2Indicator] = []
    domain_counter: Counter = Counter()
    suspicious_domain_set: set = set()

    for path in args.inputs:
        if not os.path.isfile(path):
            print(f"[!] Skipping non-existent: {path}", file=sys.stderr)
            continue
        lines = load_logs(path)
        for line in lines:
            domains = extract_domains_from_log_line(line)
            for d in domains:
                domain_counter[d] += 1
                if any(d.endswith(tld) for tld in SUSPICIOUS_TLDS):
                    suspicious_domain_set.add(d)
                elif "." in d and len(d.split(".")[0]) > 20 and safe_entropy(d.split(".")[0]) > 3.8:
                    suspicious_domain_set.add(d)

    for domain, count in domain_counter.items():
        if domain.startswith("ip:"):
            conf = "medium"
        elif domain in suspicious_domain_set:
            conf = "high"
        elif count >= 50:
            conf = "medium"
        else:
            conf = "low"
        all_indicators.append(C2Indicator(
            indicator_type="domain", value=domain, confidence=conf,
            source_file=path, context=f"observed {count} time(s)" if count > 1 else "",
        ))

    # Sort by confidence then frequency
    priority_order = {"high": 0, "medium": 1, "low": 2}
    all_indicators.sort(key=lambda x: (priority_order.get(x.confidence, 9), -domain_counter[x.value]))

    print(f"\n  [*] Analysed {len(args.inputs)} log file(s)")
    print(f"  [*] Unique domains/IPs observed : {len(domain_counter)}")
    print(f"  [*] Suspicious candidates       : {len(suspicious_domain_set)}")
    print(f"  [*] Total indicators generated  : {len(all_indicators)}\n")

    top = all_indicators[:20]
    for ind in top:
        print(f"  [{ind.confidence.upper():>6}] {ind.value:<50} from {os.path.basename(ind.source_file)}")
        if ind.context:
            print(f"           ~ {ind.context}")

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "input_files": [os.path.basename(p) for p in args.inputs],
        "unique_domains": len(domain_counter),
        "suspicious_candidates": len(suspicious_domain_set),
        "indicators": [i.to_dict() for i in all_indicators],
    }
    print(json.dumps(report, indent=2))

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        if args.output.endswith(".csv"):
            with open(args.output, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["type", "value", "confidence", "source", "first_seen", "context"])
                for i in all_indicators:
                    w.writerow([i.indicator_type, i.value, i.confidence, i.source_file, i.first_seen, i.context])
        else:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
        print(f"\n  [*] Saved: {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
