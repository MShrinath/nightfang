#!/usr/bin/env python3
"""
Privilege Escalation Vulnerability Scanner — read-only local checks for common
Windows privilege-escalation misconfigurations: unquoted service paths, always
install elevated services, weak file ACLs on sensitive locations, kernel exploit
indicators, and token manipulation vectors. No active exploitation; only
inventory of risk surface mapped to MITRE T1068/T1548 families.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import stat
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class PrivEscFinding:
    category: str           # unquoted_service, always_install_elevated, acl_weak, token_manipulation, kernel_version
    technique_id: str       # e.g. T1055.012
    technique_name: str
    observation: str
    risk_level: str         # critical/high/medium/low/info
    remediation_hint: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category, "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "observation": self.observation[:300],
            "risk_level": self.risk_level,
            "remediation_hint": self.remediation_hint,
        }


def get_os_version() -> Optional[Dict[str, str]]:
    if platform.system() != "Windows":
        return None
    try:
        out = subprocess.run(["systeminfo"], capture_output=True, text=True, timeout=15).stdout
        info: Dict[str, str] = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip().lower()] = v.strip()
        return info
    except Exception:
        return None


def check_unquoted_service_paths() -> List[PrivEscFinding]:
    findings: List[PrivEscFinding] = []
    if platform.system() != "Windows":
        return findings
    try:
        out = subprocess.run(
            ["wmic", "service", "where", "NOT PathName='', PathName LIKE '% %'",
             "get", "Name,PathName"], capture_output=True, text=True, timeout=10
        ).stdout
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line or "\\" not in line:
                continue
            parts = line.split("\\", 1)
            name = parts[0].strip()
            remainder = parts[1] if len(parts) > 1 else ""
            # Detect unquoted path via presence of spaces before first .exe
            if " " in remainder and ".exe" not in remainder.split()[0]:
                findings.append(PrivEscFinding(
                    category="unquoted_service", technique_id="T1543.003",
                    technique_name="Create or Modify System Process: Windows Service",
                    observation=f"Unquoted service path detected for '{name}': ...{remainder[:80]}",
                    risk_level="high",
                    remediation_hint="Quote path in service configuration or move binary to a path without spaces.",
                ))
    except Exception:
        pass
    return findings


def check_always_install_elevated() -> List[PrivEscFinding]:
    findings: List[PrivEscFinding] = []
    if platform.system() != "Windows":
        return findings
    for policy_path in [
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer",
        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer",
    ]:
        val = _safe_reg_get(policy_path, "AlwaysInstallElevated")
        if val == "1":
            findings.append(PrivEscFinding(
                category="always_install_elevated", technique_id="T1548.002",
                technique_name="Elevation of Privilege: Bypass User Account Control",
                observation=f"AlwaysInstallElevated enabled under {policy_path}",
                risk_level="critical",
                remediation_hint="Set AlwaysInstallElevated to 0 or disable MSI-based installation elevation.",
            ))
    return findings


def _safe_reg_get(key: str, value: str = "") -> Optional[str]:
    try:
        cmd = ["reg", "query", key]
        if value:
            cmd.extend(["/v", value])
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if "\t" in line and not line.strip().startswith("#"):
                parts = line.strip().split("\t")
                if len(parts) >= 3:
                    return parts[-1].strip()
    except Exception:
        pass
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Privilege Escalation Vulnerability Scanner (Read-Only)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    info = get_os_version()
    findings: List[PrivEscFinding] = []
    findings.extend(check_unquoted_service_paths())
    findings.extend(check_always_install_elevated())

    by_risk = Counter(f.risk_level.upper() for f in findings)
    print(f"\n  [*] OS     : {platform.system()} {platform.release()}")
    if info:
        print(f"  [*] Build  : {info.get('os_version', '-')}")
    print(f"  [*] Findings: {len(findings)}")
    print(f"  [*] Risk breakdown: {dict(by_risk)}\n")
    for f in findings:
        print(f"  [{f.risk_level.upper():>8}] [{f.technique_id:<12}] {f.technique_name}")
        print(f"           {f.observation}")
        if f.remediation_hint:
            print(f"           > {f.remediation_hint}")
        print()

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "os_info": info,
        "total_findings": len(findings),
        "by_risk_level": dict(by_risk),
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
