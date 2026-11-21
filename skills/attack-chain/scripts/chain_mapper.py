#!/usr/bin/env python3
"""
Attack Chain Mapper — takes VAPT findings and maps them onto MITRE ATT&CK
tactics/techniques to surface multi-stage kill-chain patterns. Purely analytical;
reads existing finding data only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class AttackPhase:
    tactic: str
    technique_id: str
    technique_name: str
    evidence_finding_ids: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "tactic": self.tactic, "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "evidence_finding_ids": self.evidence_finding_ids,
            "description": self.description[:300],
        }


# Lightweight ATT&CK tactic-to-phase mapping keyed by finding category keywords.
# In production this would query the official ATT&CK Navigator layer or API.
TACTIC_KEYWORD_MAP = {
    "reconnaissance": ("TA0043", "Reconnaissance", [
        "keyword_scan", "dorking", "shodan", "crt.sh", "subdomain", "port.scan"]),
    "resource_development": ("TA0417", "Resource Development", [
        "phishing.domain", "malware.register", "exploit.kit"]),
    "initial_access": ("TA0001", "Initial Access", [
        "xss", "sqli", "rce", "open.redirect", "file.upload", "unauth",
        "credential stuffing", "phishing.link", "typosquatting"]),
    "execution": ("TA0002", "Execution", [
        "command.injection", "os.command", "powershell", "script.execution"]),
    "persistence": ("TA0003", "Persistence", [
        "web.shell", "backdoor", "registry.runkey", "scheduled.task",
        "daemon.registration", "startup.folder"]),
    "privilege_escalation": ("TA0004", "Privilege Escalation", [
        "sudo.abuse", "setuid", "capabilities.leak", "kernel.exploit",
        "uac.bypass", "improper.privilege"]),
    "defense_evasion": ("TA0005", "Defense Evasion", [
        "obfuscated.payload", "masquerade", "rootkit.indicator",
        "log.tamper", "anti.debug"]),
    "credential_access": ("TA0006", "Credential Access", [
        "credential.dump", "hash.crack", "keylogger", "kerberoasting",
        "ntlm.relay", "smb.hash", "lsass.access"]),
    "discovery": ("TA0007", "Discovery", [
        "internal.scan", "network.discovery", "arp.spray", "host.enumeration"]),
    "lateral_movement": ("TA0008", "Lateral Movement", [
        "remote.exec", "psexec", "wmi", "rdp.share", "smb.lateral"]),
    "collection": ("TA0009", "Collection", [
        "data.staging", "screen.capture", "keylogging"]),
    "command_and_control": ("TA0011", "Command and Control", [
        "c2.beacon", "dns.tunnel", "https.c2", "icmp.covert",
        "proxy.chains", "tunnel.port"]),
    "exfiltration": ("TA0010", "Exfiltration", [
        "data.exfil", "cp.to.external", "compress.data"]),
    "impact": ("TA0040", "Impact", [
        "ransomware", "ddos", "data.destroy", "encryption.locked"]),
}


def classify_phase(findings: List[dict]) -> List[AttackPhase]:
    """Map findings to ATT&CK phases based on keyword matching."""
    seen_phases: Dict[str, AttackPhase] = {}
    for f in findings:
        text = " ".join(str(v).lower() for v in f.values())
        for key, (tid, tname, keywords) in TACTIC_KEYWORD_MAP.items():
            if any(kw in text for kw in keywords):
                if tid not in seen_phases:
                    seen_phases[tid] = AttackPhase(tactic=tname, technique_id=tid,
                                                   technique_name=tname, description=f.get("title", "")[:120])
                found_id = f.get("id") or f.get("finding_id") or ""
                if found_id and found_id not in seen_phases[tid].evidence_finding_ids:
                    seen_phases[tid].evidence_finding_ids.append(found_id)
    return list(seen_phases.values())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Attack Chain Mapper",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input", help="Path to findings JSON/JSONL file")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save mapped chain as JSON")
    args = parser.parse_args()

    try:
        with open(args.input, encoding="utf-8", errors="replace") as fh:
            raw = fh.read().strip()
        try:
            data = json.loads(raw)
            findings = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            findings = [json.loads(line) for line in raw.splitlines() if line.strip()]
    except OSError as exc:
        print(f"[!] Could not read input: {exc}", file=sys.stderr)
        return 2

    phases = classify_phase(findings)
    if not phases:
        print("[!] No ATT&CK phase matches found in provided findings.", file=sys.stderr)
        return 2

    tactics_ordered = ["TA0043","TA0417","TA0001","TA0002","TA0003","TA0004","TA0005",
                       "TA0006","TA0007","TA0008","TA0009","TA0011","TA0010","TA0040"]
    ordered = sorted(phases, key=lambda p: tactics_ordered.index(p.technique_id)
                     if p.technique_id in tactics_ordered else 99)

    print(f"\n  [*] Mapped {len(findings)} finding(s) onto {len(ordered)} ATT&CK phase(s)\n")
    print("| # | Tactic                   | Technique  | Evidence Findings |")
    print("|---|--------------------------|------------|-------------------|")
    for i, p in enumerate(ordered, 1):
        ids = ", ".join(p.evidence_finding_ids[:3]) or "-"
        print(f"| {i:>2} | {p.tactic:<24} | {p.technique_id:<10} | {ids:<19} |")

    chain = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "input_findings_count": len(findings),
        "mapped_phases_count": len(ordered),
        "chain": [p.to_dict() for p in ordered],
    }
    print(json.dumps(chain, indent=2))

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(chain, fh, indent=2)
        print(f"\n  [*] Saved: {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
