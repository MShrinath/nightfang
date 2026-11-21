#!/usr/bin/env python3
"""
Credential Access Audit Helper — read-only scan of local Windows credential
artefacts (Samhive structure info, LSASS protection status indicators, cached
NTLM/DPAPI metadata summaries) without extracting plaintext secrets. Produces
a risk summary mapped to MITRE T1003/T1550 categories. Read-only; no admin
privilege escalation or active credential harvesting.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class CredentialFinding:
    category: str            # samhive, lsass, dpapi, stored_creds, msi
    technique_id: str        # e.g. T1003.001
    technique_name: str
    observation: str
    risk_level: str          # critical/high/medium/low/info
    remediation_hint: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "observation": self.observation[:300],
            "risk_level": self.risk_level,
            "remediation_hint": self.remediation_hint,
        }


def get_os_info() -> Dict[str, str]:
    info: Dict[str, str] = {"os": platform.system(), "release": platform.release(),
                            "version": platform.version(), "machine": platform.machine()}
    if info["os"] != "Windows":
        info["notes"] = "Non-Windows OS — this helper is Windows-centric"
    return info


def check_samhive_accessibility() -> List[CredentialFinding]:
    findings: List[CredentialFinding] = []
    sam_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32\\config\\SAM")
    system_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32\\config\\SYSTEM")
    if os.path.isfile(sam_path):
        size = os.path.getsize(sam_path)
        findings.append(CredentialFinding(
            category="samhive", technique_id="T1003.001", technique_name="OS Credential Dumping: LSASS Memory",
            observation=f"SAM hive exists at {sam_path} ({size} bytes)",
            risk_level="info", remediation_hint="Ensure SAM file permissions restrict access to SYSTEM/Administrators only.",
        ))
    if not os.path.isfile(system_path):
        findings.append(CredentialFinding(
            category="samhive", technique_id="T1003", technique_name="OS Credential Dumping",
            observation="SYSTEM hive not found — possible offline/hive-swap scenario",
            risk_level="high", remediation_hint="Verify SYSTEM hive integrity and boot-time protection.",
        ))
    return findings


def check_lsass_protections() -> List[CredentialFinding]:
    findings: List[CredentialFinding] = []
    try:
        import subprocess  # safe, local introspection only
        result = subprocess.run(["powershell", "-Command",
                                 "(Get-Process lsass).ProtectionLevel"],
                                capture_output=True, text=True, timeout=5)
        level = result.stdout.strip().lower()
        if "none" in level or "default" in level:
            findings.append(CredentialFinding(
                category="lsass", technique_id="T1003.001", technique_name="LSASS Credential Dumping",
                observation=f"LSASS protection level appears weak: {level}",
                risk_level="critical", remediation_hint="Enable Credential Guard / Lsass RunAsPpl.",
            ))
        else:
            findings.append(CredentialFinding(
                category="lsass", technique_id="T1003", technique_name="OS Credential Dumping",
                observation=f"LSASS protection level detected: {level}",
                risk_level="low", remediation_hint="",
            ))
    except Exception as exc:
        findings.append(CredentialFinding(
            category="lsass", technique_id="T1003", technique_name="OS Credential Dumping",
            observation=f"Could not query LSASS protections: {exc}",
            risk_level="medium", remediation_hint="Run as Administrator or on Windows with PowerShell available.",
        ))
    return findings


def check_stored_credentials() -> List[CredentialFinding]:
    findings: List[CredentialFinding] = []
    dirs_to_check = [
        os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Credentials"),
        os.path.join(os.environ.get("SystemDrive", "C:\\"), "Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Credentials"),
    ]
    for d in dirs_to_check:
        if os.path.isdir(d):
            files = os.listdir(d)
            count = len(files)
            if count > 0:
                findings.append(CredentialFinding(
                    category="stored_creds", technique_id="T1555.004", technique_name="Credentials from Windows Credential Manager",
                    observation=f"{count} credential cache entry/file(s) found under {d}",
                    risk_level="high" if count > 5 else "medium",
                    remediation_hint="Limit Credential Manager entries; enforce smartcard/logon session isolation.",
                ))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Credential Access Audit Helper (Read-Only)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-o", "--output", metavar="PATH", help="Save report as JSON")
    args = parser.parse_args()

    info = get_os_info()
    findings: List[CredentialFinding] = []
    findings.extend(check_samhive_accessibility())
    findings.extend(check_lsass_protections())
    findings.extend(check_stored_credentials())

    by_risk = Counter(f.risk_level.upper() for f in findings)
    by_cat = Counter(f.category for f in findings)

    print(f"\n  [*] OS     : {info['os']} {info['release']} ({info['machine']})")
    print(f"  [*] Findings: {len(findings)}")
    print(f"  [*] Risk breakdown: {dict(by_risk)}")
    print(f"  [*] Category breakdown: {dict(by_cat)}\n")
    for f in findings:
        print(f"  [{f.risk_level.upper():>8}] {f.technique_id:<12} {f.technique_name}")
        print(f"           {f.observation}")
        if f.remediation_hint:
            print(f"           > {f.remediation_hint}")
        print()

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "os_info": info,
        "total_findings": len(findings),
        "by_risk_level": dict(by_risk),
        "by_category": dict(by_cat),
        "findings": [f.to_dict() for f in findings],
    }
    print(json.dumps(report, indent=2))

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    crit_high = by_risk.get("CRITICAL", 0) + by_risk.get("HIGH", 0)
    return 1 if crit_high else 0


if __name__ == "__main__":
    sys.exit(main())
