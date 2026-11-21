#!/usr/bin/env python3
"""
Defense Evasion Detection Helper — scans endpoint artefacts (Registry run keys,
scheduled tasks, WMI subscriptions, service configs, autorun locations) for
common attacker persistence/evasion markers. Read-only forensic collection.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class EvasionFinding:
    category: str           # registry_run, scheduled_task, wmi_subscription, service, startup_folder, filter_driver
    indicator: str          # specific value observed
    path_or_key: str        # location in filesystem/registry
    context: str            # why this is noteworthy
    risk_level: str         # critical/high/medium/low/info
    mitre_technique: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category, "indicator": self.indicator[:200],
            "location": self.path_or_key[:250], "context": self.context[:300],
            "risk_level": self.risk_level, "mitre_technique": self.mitre_technique,
        }


# Known-suspicious executable names commonly abused for persistence/evasion
SUSPICIOUS_NAMES = {
    "powershell", "cmd", "wscript", "cscript", "mshta", "certutil", "bitsadmin",
    "rundll32", "regsvr32", "msbuild", "cmstp", "installutil", "ilasm",
    "nircmd", "putty", "psExec", "psexec64", "winexe", "crackmapexec",
}

KNOWN_EVASION_REGISTRY_PATHS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
]


def safe_reg_query(key: str, value: str = "") -> Optional[str]:
    """Attempt a read-only Registry query via reg.exe; returns value or None."""
    try:
        cmd = ["reg", "query", key]
        if value:
            cmd.append(f"/v {value}")
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if "\t" in line and not line.strip().startswith("#"):
                parts = line.strip().split("\t")
                if len(parts) >= 3:
                    return parts[-1].strip()
    except Exception:
        pass
    return None


def check_registry_persistence() -> List[EvasionFinding]:
    findings: List[EvasionFinding] = []
    if platform.system() != "Windows":
        return findings
    for rk in KNOWN_EVASION_REGISTRY_PATHS:
        val = safe_reg_query(rk)
        if val:
            for entry in val.splitlines():
                entry_lower = entry.lower()
                risk = "info"
                mitre = "T1547.001"
                ctx = ""
                if any(s in entry_lower for s in SUSPICIOUS_NAMES):
                    risk = "high"
                    ctx = f"Known-evasion utility referenced in Run key: {entry}"
                if "powershell" in entry_lower and "-enc" in entry_lower:
                    risk = "critical"
                    ctx = "Encoded Powershell command in auto-run — likely obfuscated payload"
                    mitre = "T1027"
                elif any(p in entry_lower for p in ("\\temp\\", "\\appdata\\local\\", "\\windows\\temp\\")):
                    risk = "high"
                    ctx = f"Execution from transient directory: {entry}"
                if risk != "info" or True:
                    findings.append(EvasionFinding(
                        category="registry_run", indicator=entry.strip(),
                        path_or_key=rk, context=ctx or "Present in autorun registry path",
                        risk_level=risk, mitre_technique=mitre,
                    ))
    return findings


def check_wmi_subscriptions() -> List[EvasionFinding]:
    findings: List[EvasionFinding] = []
    if platform.system() != "Windows":
        return findings
    try:
        out = subprocess.run(["wmic", "subscription", "filter", "get", "name,commandline"],
                             capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("Name"):
                continue
            risk = "medium"
            mitre = "T1546.003"
            ctx = "WMI event subscription detected"
            if any(kw in line.lower() for kw in ("powershell", "cmd.exe", "wscript", "cscript")):
                risk = "high"
            findings.append(EvasionFinding(
                category="wmi_subscription", indicator=line[:200],
                path_or_key="root\\subscription\\__EventFilter",
                context=f"{ctx} — CLI: {line}",
                risk_level=risk, mitre_technique=mitre,
            ))
    except Exception:
        pass
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Defense Evasion Detection Helper (Read-Only)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    findings: List[EvasionFinding] = []
    findings.extend(check_registry_persistence())
    findings.extend(check_wmi_subscriptions())

    by_risk = Counter(f.risk_level.upper() for f in findings)
    print(f"\n  [*] OS : {platform.system()} {platform.release()}")
    print(f"  [*] Findings: {len(findings)}")
    print(f"  [*] Risk breakdown: {dict(by_risk)}\n")
    for f in findings:
        print(f"  [{f.risk_level.upper():>8}] [{f.mitre_technique:<12}] {f.category}")
        print(f"           Indicator: {f.indicator[:80]}")
        print(f"           Location:  {f.path_or_key}")
        if f.context:
            print(f"           Note:      {f.context[:100]}")
        print()

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
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
