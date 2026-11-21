#!/usr/bin/env python3
"""
Threat Emulation Environment Detector — passive inventory of virtualisation,
sandboxing, and forensics-tool indicators on the running host to help analysts
understand whether current execution context is emulated or live. Outputs risk
context for both red-team (avoid false positives in simulated environments)
and blue-team (identify hosts masquerading as VMs). Read-only; no probing of
live C2 infrastructure.
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
class EnvIndicator:
    category: str           # vm_hardware, sandbox_tool, forensic_tool, system_anomaly
    indicator_name: str
    observed_value: str
    significance: str
    risk_level: str         # high/medium/low/info

    def to_dict(self) -> dict:
        return {
            "category": self.category, "indicator_name": self.indicator_name[:120],
            "observed_value": self.observed_value[:200],
            "significance": self.significance[:300],
            "risk_level": self.risk_level,
        }


def safe_command(cmd: list, timeout: int = 5) -> Optional[str]:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
        return out.strip()
    except Exception:
        return None


def check_vm_indicators() -> List[EnvIndicator]:
    findings: List[EnvIndicator] = []
    products = {"virtualbox": False, "vmware": False, "hyper-v": False, "parallels": False, "qemu": False}
    if platform.system() == "Windows":
        for key in ["SYSTEM", "SOFTWARE"]:
            hive_key = f"HKLM\\{key}"
            val = safe_command(["reg", "query", hive_key, "/f", "virtualbox", "/s", "/e"], timeout=8)
            if val and ("VirtualBox" in val or "vbox" in val.lower()):
                products["virtualbox"] = True
            val2 = safe_command(["reg", "query", hive_key, "/f", "vmware", "/s", "/e"], timeout=8)
            if val2 and ("VMware" in val2 or "vmware" in val2.lower()):
                products["vmware"] = True
            val3 = safe_command(["wmic", "computersystem", "get", "manufacturer"], timeout=5)
            if "microsoft corporation" in str(val3).lower() or "vmware" in str(val3).lower():
                products["hyper-v"] = True if "microsoft" in str(val3).lower() else True
        serial = safe_command(["wmic", "bios", "get", "serialnumber"], timeout=5)
        if serial and any(k in (serial or "").upper() for k in ["VMW-", "VBOX", "XEN"]):
            findings.append(EnvIndicator("vm_hardware", "BIOS serial number", serial or "",
                                         "BIOS serial matches known hypervisor prefix", "high"))
        model = safe_command(["wmic", "computersystem", "get", "model"], timeout=5)
        if model and any(kw in (model or "").upper() for kw in ["VIRTUAL", "VMWARE", "VBOX"]):
            findings.append(EnvIndicator("vm_hardware", "Computer model", model or "",
                                         "Model string suggests virtual hardware", "high"))
    mac = safe_command(["ipconfig", "/all"]) or safe_command(["ifconfig"]) or ""
    mac_vals = re.findall(r"(?:MAC Address|Address)\s*[:=]?\s*([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})", mac)
    oui_map = {
        "080027": "VirtualBox", "000C29": "VMware", "001C42": "VMware (workstation)",
        "005056": "VMware", "00163E": "Oracle VM VirtualBox",
        "0A0027": "VirtualBox", "00000C": "Parallels", "525400": "QEMU/KVM",
    }
    seen_ouis: set = set()
    for raw in mac_vals:
        cleaned = raw.replace("-", "").replace(":", "").upper()
        oui = cleaned[:6]
        if oui in oui_map and oui not in seen_ouis:
            seen_ouis.add(oui)
            findings.append(EnvIndicator("vm_hardware", f"MAC OUI {raw}", oui_map[oui],
                                         "Network adapter OUI indicates virtual NIC", "medium"))
    for product, flagged in products.items():
        if flagged:
            findings.append(EnvIndicator("vm_hardware", f"{product} present", "Detected via registry/wmic",
                                         f"Hypervisor/toolkit '{product}' found on host", "high"))
    return findings


def check_forensic_tools() -> List[EnvIndicator]:
    findings: List[EnvIndicator] = []
    tools = ["volatility", "autopsy", "ftk", "xplico", "capwap", "forensic explorer",
             "nirsoft", "process explorer", "procmon", "procexp", "tcpview", "strings.exe"]
    common_paths = [
        os.path.expandvars(r"%ProgramFiles%\*"),
        os.path.expandvars(r"%ProgramFiles(x86)%\*"),
        os.path.expandvars(r"C:\Tools\*"),
        os.path.expanduser(r"~\Documents\Forensic\*"),
    ]
    found_tools: set = set()
    for pat in common_paths:
        try:
            parent = os.path.dirname(os.path.abspath(pat))
            pattern_base = os.path.basename(pat.rstrip("*"))
            for entry in os.listdir(parent):
                full = os.path.join(parent, entry)
                if os.path.isdir(full):
                    for sub in os.listdir(full)[:200]:
                        if any(t in sub.lower() for t in tools):
                            found_tools.add(sub)
        except OSError:
            continue
    for t in sorted(found_tools):
        findings.append(EnvIndicator("forensic_tool", t, "Found under Program Files tree",
                                     "Common forensic/investigation utility present", "info"))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Threat Emulation / Sandbox Environment Detector",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    findings: List[EnvIndicator] = []
    findings.extend(check_vm_indicators())
    findings.extend(check_forensic_tools())

    by_risk = Counter(f.risk_level.upper() for f in findings)
    by_cat = Counter(f.category for f in findings)
    print(f"\n  [*] OS     : {platform.system()} {platform.release()} {platform.machine()}")
    print(f"  [*] Findings: {len(findings)}")
    print(f"  [*] Risk breakdown: {dict(by_risk)}")
    print(f"  [*] Category breakdown: {dict(by_cat)}\n")
    for f in findings:
        print(f"  [{f.risk_level.upper():>8}] [{f.category:<16}] {f.indicator_name}")
        print(f"           Observed : {f.observed_value[:100]}")
        print(f"           Significance: {f.significance[:120]}")
        print()

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
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
