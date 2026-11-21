#!/usr/bin/env python3
"""
Indicator of Compromise (IOC) & STIX Bundle Parser & Validator
Parses STIX 2.x cyber-observable objects and Indicators, validates against
schema rules, and cross-references against known TTP patterns. Read-only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set


@dataclass
class IOCFinding:
    rule_id: str
    severity: str
    title: str
    description: str
    ioc_type: str  # ipv4-addr, domain-name, file, url, etc.
    value: str
    confidence: str
    evidence: str
    remediation: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id, "severity": self.severity,
            "title": self.title, "description": self.description[:300],
            "ioc_type": self.ioc_type, "value": self.value,
            "confidence": self.confidence, "evidence": self.evidence[:400],
        }
        if self.remediation:
            d["remediation"] = self.remediation
        if self.mitre_tactic:
            d["mitre_attack"] = {"tactic": self.mitre_tactic, "technique": self.mitre_technique}
        return d


@dataclass
class CTIReport:
    target: str
    timestamp: str
    findings: List[IOCFinding] = field(default_factory=list)
    indicators_parsed: int = 0
    stix_version: str = ""

    def add(self, f: IOCFinding) -> None:
        self.findings.append(f)
        self.indicators_parsed += 1

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "target": self.target, "timestamp": self.timestamp,
            "stix_version": self.stix_version,
            "indicators_parsed": self.indicators_parsed,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }, indent=indent, default=str)


# ---------------------------------------------------------------------------
# Pattern库 — domain IoC heuristics
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".win", ".click", ".link", ".date",
                   ".loan", ".racing", ".stream", ".accountant", ".science",
                   ".trade", ".review", ".work", ".download", ".today", ".site"}

DNS_HIJACK_PATTERNS = [
    re.compile(r"(?:login|secure|verify|account|bank|update|security|admin)", re.I),
    re.compile(r"(?:paypal|google|apple|microsoft|amazon|facebook)", re.I),
]


def classify_ioc(stix_obj: dict) -> Optional[IOCFinding]:
    """Classify and validate a single STIX Cyber-Observable or Indicator object."""
    obj_type = stix_obj.get("type", "")
    value = ""
    finding_attrs: dict = {}

    # --- IPv4 ---
    if obj_type == "ipv4-addr":
        value = stix_obj.get("value", "")
        finding_attrs = {"title": "IPv4 Address Indicator", "severity": "informational",
                         "description": f"IP address observed in threat feed.", "mitre_tactic": "Command and Control"}
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            finding_attrs["severity"] = "medium"
            finding_attrs["title"] = "Malformed IPv4 indicator"
            finding_attrs["description"] = f"Value '{value}' does not match standard IPv4 notation."
            finding_attrs["mitre_tactic"] = ""
    # --- Domain ---
    elif obj_type == "domain-name":
        value = stix_obj.get("value", "").lower()
        finding_attrs = {"title": "Domain Name Indicator", "severity": "informational",
                         "description": f"Domain observed in threat intelligence feed.", "mitre_tactic": "Command and Control"}
        tld_part = re.search(r"\.([a-z]{2,})$", value)
        if tld_part and tld_part.group(1) in {"xyz", "top", "club", "win", "click", "link", "date", "loan", "racing", "stream"}:
            finding_attrs["severity"] = "high"
            finding_attrs["title"] = "High-risk TLD domain indicator"
            finding_attrs["description"] = f"Domain uses a commonly abused TLD: .{tld_part.group(1)}"
        for pat in DNS_HIJACK_PATTERNS:
            if pat.search(value):
                finding_attrs["severity"] = "high"
                finding_attrs["title"] = "Phish-like domain detected"
                finding_attrs["description"] = f"Domain contains keyword associated with credential phishing."
                finding_attrs["mitre_tactic"] = "Initial Access"
                break
    # --- File hash ---
    elif obj_type == "file" and "hashes" in stix_obj:
        hashes = stix_obj["hashes"]
        for algo, hval in hashes.items():
            if isinstance(hval, str) and len(hval) in (32, 40, 64):
                value = f"{algo}:{hval}"
                finding_attrs = {"title": "File Hash Indicator", "severity": "informational",
                                 "description": f"File artifact hash noted in feed.", "mitre_tactic": "Execution"}
                break
    # --- URL ---
    elif obj_type == "url":
        value = stix_obj.get("value", "")
        finding_attrs = {"title": "URL Indicator", "severity": "informational",
                         "description": "URL observed in threat intelligence feed.", "mitre_tactic": "Execution"}
    # --- Indicator (STIX pattern type) ---
    elif obj_type == "indicator":
        pattern = stix_obj.get("pattern", "")
        valid_since = stix_obj.get("valid_from", "")
        vals = re.findall(r"[\"'][^\"']+[\"']", pattern)
        value = vals[0].strip('"\'') if vals else pattern[:80]
        finding_attrs = {"title": "STIX Indicator Object", "severity": "medium",
                         "description": "Parsed indicator pattern from STIX bundle.", "mitre_tactic": "Collection"}
    else:
        return None

    confidence = stix_obj.get("confidence", "unknown")
    desc_extra = finding_attrs.pop("description", "")
    title_val = finding_attrs.pop("title", "Generic IOC")
    severity_val = finding_attrs.pop("severity", "informational")
    tactic_val = finding_attrs.pop("mitre_tactic", "")
    technique_val = finding_attrs.pop("mitre_technique", "")
    return IOCFinding(
        rule_id=f"CTI-{obj_type.upper().replace('-', '_')}",
        severity=severity_val,
        title=title_val,
        description=desc_extra,
        ioc_type=obj_type,
        value=value or str(stix_obj)[:120],
        confidence=str(confidence),
        evidence=json.dumps(stix_obj, ensure_ascii=False)[:400],
        remediation="",
        mitre_tactic=tactic_val,
        mitre_technique=technique_val,
    )


def parse_stix_bundle(data: str, source: str) -> CTIReport:
    """Parse a STIX 2.x bundle JSON string and extract IOCs."""
    report = CTIReport(target=source, timestamp=datetime.utcnow().isoformat() + "Z")
    try:
        doc = json.loads(data)
    except json.JSONDecodeError as exc:
        report.findings.append(IOCFinding(
            rule_id="CTI-JSON-01", severity="high", title="Invalid STIX JSON",
            description=str(exc)[:200], ioc_type="bundle", value=source,
            confidence="none", evidence=data[:300],
        ))
        return report

    report.stix_version = doc.get("specification_version", doc.get("type", "unknown"))

    # Handle top-level bundle
    objects = []
    if doc.get("type") == "bundle":
        objects = doc.get("objects", []) or []
    elif doc.get("type") == "indicator" or doc.get("type") == "observed-data":
        objects = [doc]
    else:
        # Try to find objects key at any level
        for key in ("objects", "indicators", "observables"):
            if key in doc:
                val = doc[key]
                if isinstance(val, list):
                    objects = val
                    break

    seen_values: Set[str] = set()
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        obj_type = obj.get("type", "")
        if obj_type in ("indicator", "ipv4-addr", "domain-name", "file", "url", "network-traffic", "artifact"):
            finding = classify_ioc(obj)
            if finding and finding.value not in seen_values:
                seen_values.add(finding.value)
                report.add(finding)

    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG CTI / STIX Indicator Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("path", help="Path to STIX 2.x JSON bundle or indicator file")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    try:
        with open(args.path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        print(f"[!] Could not read {args.path}: {exc}", file=sys.stderr)
        return 2

    report = parse_stix_bundle(content, args.path)
    print(f"\n  [*] Parsed {report.indicators_parsed} indicator(s) from {args.path}")
    print(f"  [*] Extracted {len(report.findings)} unique IOC(s)\n")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for f in sorted(report.findings, key=lambda x: sev_order.get(x.severity, 9)):
        tactic_str = f" [{f.mitre_tactic}]" if f.mitre_tactic else ""
        print(f"  [{f.severity.upper():>9s}] {f.title}{tactic_str}")
        print(f"           {f.ioc_type}: {f.value[:100]}")

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report.to_json())
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    crit_high = sum(1 for f in report.findings if f.severity in ("critical", "high"))
    return 2 if crit_high > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
