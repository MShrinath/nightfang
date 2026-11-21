#!/usr/bin/env python3
"""
Purple Team Exercise Planner — orchestrates coordinated red/blue/yellow team
activities by generating playbooks, kill-chain scenarios, and observation
checklists aligned to MITRE ATT&CK. Read-only planning aid; does not execute
or deploy test payloads.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class KillChainPhase:
    tactic: str
    technique_id: str
    technique_name: str
    red_action: str
    blue_detection: str
    yellow_response: str
    data_source: str
    confidence: str = "medium"

    def to_dict(self) -> dict:
        return {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "red_action": self.red_action,
            "blue_detection": self.blue_detection,
            "yellow_response": self.yellow_response,
            "data_source": self.data_source,
            "confidence": self.confidence,
        }


EXERCISE_TEMPLATES: Dict[str, List[KillChainPhase]] = {
    "phishing-lateral-movement": [
        KillChainPhase(
            tactic="Initial Access",
            technique_id="T1566.001",
            technique_name="Spearphishing Attachment",
            red_action="Send spear-phished document with macro-enabled payload to target user.",
            blue_detection="Email gateway blocks/quarantines attachment; macro execution logged via AMSI.",
            yellow_response="Investigate endpoint macro event; isolate host via EDR quarantine.",
            data_source="Exchange mailbox audit + AMSI + Sysmon EventID 1",
            confidence="high",
        ),
        KillChainPhase(
            tactic="Execution",
            technique_id="T1059.005",
            technique_name="(Visual) Basic Script",
            red_action="Run VBA macro that downloads second-stage payload via PowerShell.",
            blue_detection="PowerShell encoded-command invocation; suspicious child-process tree from WINWORD.EXE.",
            yellow_response="Kill malicious process; capture process tree; preserve memory dump.",
            data_source="Sysmon EventID 1/7/8 + PowerShell Operational Log",
            confidence="high",
        ),
        KillChainPhase(
            tactic="Persistence",
            technique_id="T1547.001",
            technique_name="Registry Run Keys / Startup Folder",
            red_action="Insert Run key pointing to downloaded dropper under HKCU Run.",
            blue_detection="Registry modification on Run key detected via Sysmon EventID 12/13.",
            yellow_response="Remove persistence key; hunt for related files; scope lateral movement.",
            data_source="Sysmon Registry events + autoruns artefact",
            confidence="high",
        ),
        KillChainPhase(
            tactic="Lateral Movement",
            technique_id="T1021.002",
            technique_name="Remote Services: SMB/Windows Admin Shares",
            red_action="Use stolen credentials over PsExec to access remote admin$ share.",
            blue_detection="SMB session from non-console source; new process creation on remote host matching PsExec signature.",
            yellow_response="Disable targeted admin account; force password reset across domain; review SMB logs.",
            data_source="Security EventLog 4624/4625 + Sysmon Network Connection events",
            confidence="high",
        ),
        KillChainPhase(
            tactic="Collection",
            technique_id="T1005",
            technique_name="Data from Local System",
            red_action="Stage sensitive documents in a hidden temp directory on compromised host.",
            blue_detection="New hidden directory with document-write activity from unauthorised process.",
            yellow_response="Capture file artifacts; determine data classification; check exfil channel.",
            data_source="Sysmon File Create/Write + forensic image of affected volume",
            confidence="medium",
        ),
    ],
    "supply-chain-compromise": [
        KillChainPhase(
            tactic="Resource Development",
            technique_id="T1588.005",
            technique_name="Vulnerabilities — Exploitable Code Repository",
            red_action="Compromise a low-trust open-source package and publish update containing backdoor.",
            blue_detection="Supply-chain anomaly flagged by SBOM comparison vs previous version hash.",
            yellow_response="Quarantine affected packages; rotate credentials in CI/CD runner; notify registry.",
            data_source="Dependency lockfile hashes + build-system logs + GitHub advisory feed",
            confidence="medium",
        ),
        KillChainPhase(
            tactic="Initial Access",
            technique_id="T1195.002",
            technique_name="Supply Chain — Compromise Software Supply Chain",
            red_action="Inject malicious artifact into internal package repository mirror.",
            blue_detection="Artifact hash mismatch against upstream source; anomalous commit by service account.",
            yellow_response="Roll back package repo to known-good snapshot; re-scan all consumers.",
            data_source="Package repository audit log + SCM commit history",
            confidence="high",
        ),
    ],
    "insider-threat-data-exfil": [
        KillChainPhase(
            tactic="Exfiltration",
            technique_id="T1048.002",
            technique_name="Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
            red_action="Upload staged data over HTTPS to attacker-controlled storage API.",
            blue_detection="DLP policy triggers on outbound HTTPS request with large JSON payload to unknown SaaS.",
            yellow_response="Block destination domain at proxy; pull browser history and USB logs from insider workstation.",
            data_source="Proxy/firewall TLS SNI + DLP logs + endpoint telemetry",
            confidence="medium",
        ),
        KillChainPhase(
            tactic="Exfiltration",
            technique_id="T1041",
            technique_name="Exfiltration Over C2 Channel",
            red_action="Encode stolen data into DNS TXT queries aimed at attacker-owned subdomain.",
            blue_detection="Abnormally long/frequent DNS TXT queries from single host to rarely-seen domain.",
            yellow_response="Sinkhole attacker subdomain; isolate host; collect DNS query logs for IOCs.",
            data_source="DNS resolver logs + Netflow + endpoint sandbox traces",
            confidence="high",
        ),
    ],
}


def generate_playbook(template_name: str) -> tuple:
    phases = EXERCISE_TEMPLATES.get(template_name, [])
    desc_map = {
        "phishing-lateral-movement": "Simulate a spear-phishing chain ending in lateral movement and data staging.",
        "supply-chain-compromise":   "Simulate a compromised software dependency introducing backdoors.",
        "insider-threat-data-exfil": "Simulate an insider using legitimate access to stage and exfiltrate data.",
    }
    return phases, desc_map.get(template_name, f"ATT&CK-aligned exercise: {template_name}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Purple Team Exercise Planner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--template", choices=list(EXERCISE_TEMPLATES.keys()),
                        default="phishing-lateral-movement",
                        help="Pre-built ATT&CK kill-chain scenario")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save exercise plan as JSON")
    args = parser.parse_args()

    phases, description = generate_playbook(args.template)
    total_high_conf = sum(1 for p in phases if p.confidence == "high")

    print(f"\n  [*] Exercise: {args.template}")
    print(f"  [*] Description:\n      {description}\n")
    print(f"  [*] Total phases: {len(phases)} | High-confidence detections: {total_high_conf}\n")

    header = ("| Phase | Tactic          | Technique  | Red Action (abbrev)      | Blue Detection              | Yellow Response             | Conf |")
    sep = "|-------|-----------------|------------|--------------------------|-----------------------------|-------------------------------|------|"
    print(header)
    print(sep)
    for i, p in enumerate(phases, 1):
        red_short = p.red_action[:24].replace("\n", " ")
        blue_short = p.blue_detection[:27].replace("\n", " ")
        yellow_short = p.yellow_response[:27].replace("\n", " ")
        print(f"| {i:>2} | {p.tactic:<15} | {p.technique_id:<10} | {red_short:<24} | {blue_short:<27} | {yellow_short:<29} | {p.confidence:>6} |")

    plan = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "template": args.template,
        "description": description,
        "phase_count": len(phases),
        "high_confidence_detections": total_high_conf,
        "phases": [p.to_dict() for p in phases],
    }
    print(json.dumps(plan, indent=2))

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(plan, fh, indent=2)
        print(f"\n  [*] Plan saved: {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
