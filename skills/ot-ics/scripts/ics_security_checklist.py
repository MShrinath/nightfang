#!/usr/bin/env python3
"""
OT/ICS Security Assessment Helper — builds asset inventory checklists and
remediation prioritisation matrices for PLC/SCADA/HMI components based on
NERC CIP v6, IEC 62443-3-3, and ISA/IEC 62443 surrogacy mapping.
Read-only checklist generator; does not interact with any OT device or network.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class ControlRequirement:
    ref_id: str              # e.g. NERC-CIP-003-R5, IEC62443-3-3-SR1.1
    framework: str           # nerc-cip, iec-62443, isa-62443
    category: str
    description: str
    requirement_level: int   # 1..4 per IEC 62443-Zone-Conduit model
    evidence_hint: str = ""

    def to_dict(self) -> dict:
        return {
            "ref_id": self.ref_id,
            "framework": self.framework,
            "category": self.category,
            "description": self.description[:300],
            "requirement_level": self.requirement_level,
            "evidence_hint": self.evidence_hint,
        }


# ---------------------------------------------------------------------------
# Curated control sets (subsets of NERC CIP v6 / IEC 62443-3-3 SRs)
# ---------------------------------------------------------------------------

NERC_CIP_SUBSET: List[ControlRequirement] = [
    ControlRequirement("NERC-CIP-002", "nerc-cip", "Critical Cyber Asset Identification",
                       "Identify and document all critical cyber assets and their associated BAPA.", 4,
                       "Asset inventory with BAPA tagging per substation/controller."),
    ControlRequirement("NERC-CIP-003", "nerc-cip", "Security Management Controls",
                       "Establish and maintain security management controls including access authorization.", 4,
                       "Written access-control policy with role-based permissions documented."),
    ControlRequirement("NERC-CIP-004", "nerc-cip", "Personnel & Training",
                       "Verify personnel have appropriate training and are background-checked for privileged roles.", 3,
                       "Training records and background-check sign-offs."),
    ControlRequirement("NERC-CIP-005", "nerc-cip", "Security Controls",
                       "Implement technical security controls: anti-malware, port management, media control.", 3,
                       "Anti-malware deployment report; removable-media policy."),
    ControlRequirement("NERC-CIP-006", "nerc-cip", "Technical Security Controls",
                       "Configure firewall/router rules restricting inbound/outbound connections.", 3,
                       "Network segmentation diagram with firewall rule inventory."),
    ControlRequirement("NERC-CIP-007", "nerc-cip", "Monitoring & Resilience",
                       "Monitor system activity and maintain incident-response capability.", 3,
                       "Log retention policy and IR runbook."),
    ControlRequirement("NERC-CIP-008", "nerc-cip", "Incident Reporting",
                       "Report suspected cybersecurity incidents within defined timeframes.", 2,
                       "Incident-reporting workflow with escalation matrix."),
    ControlRequirement("NERC-CIP-009", "nerc-cip", "Recovery Plans",
                       "Maintain and test recovery plans for critical cyber assets.", 2,
                       "Test logs showing annual recovery-plan exercise."),
    ControlRequirement("NERC-CIP-010", "nerc-cip", "Vulnerability Assessments",
                       "Perform periodic vulnerability assessments and remediate within SLA.", 3,
                       "Recent scan report (≤ 12 months) with closure tracking."),
    ControlRequirement("NERC-CIP-011", "nerc-cip", "Maintenance",
                       "Patch and update operating software within vendor-recommended timeframes.", 3,
       "   Patch management policy with exception documentation."),
]

IEC_62443_SR33_SUBSET: List[ControlRequirement] = [
    ControlRequirement("IEC-62443-3-3-SR1.1", "iec-62443", "Zone & Conduit Analysis",
                       "Define defensive zones and conduits for OT segments.", 4,
                       "Network diagram annotated with zone/conduit boundaries and trust levels."),
    ControlRequirement("IEC-62443-3-3-SR1.2", "iec-62443", "Zone & Conduit Analysis",
                       "Document information flows between zones and conduits.", 4,
                       "Data-flow matrix for each conduit."),
    ControlRequirement("IEC-62443-3-3-SR2.1", "iec-62443", "Identification & Authentication Control",
                       "Authenticate users and devices before granting access.", 3,
                       "MFA enforcement report for HMI/operator workstations."),
    ControlRequirement("IEC-62443-3-3-SR2.2", "iec-62443", "Identification & Authentication Control",
                       "Use unique IDs; prevent credential sharing.", 3,
       "   Account audit log confirming per-user authentication."),
    ControlRequirement("IEC-62443-3-3-SR2.3", "iec-62443", "Identification & Authentication Control",
                       "Protect stored credentials from unauthorized disclosure.", 3,
       "   Credential storage config (password policy, hashing algorithm)."),
    ControlRequirement("IEC-62443-3-3-SR2.4", "iec-62443", "Identification & Authentication Control",
                       "Manage authentication factor provisioning, generation, and lifecycle.", 2,
       "   Key/certificate rotation procedure documented."),
    ControlRequirement("IEC-62443-3-3-SR3.1", "iec-62443", "Device Hardening",
                       "Disable unused ports, services, and protocols on PLCs/HMIs.", 3,
       "   Device configuration baseline applied per device type."),
    ControlRequirement("IEC-62443-3-3-SR3.2", "iec-62443", "Device Hardening",
                       "Enforce least-privilege OS configurations on operator stations.", 3,
       "   Hardened baseline images deployed to all HMI/EMS nodes."),
    ControlRequirement("IEC-62443-3-3-SR3.3", "iec-62443", "Device Hardening",
                       "Ensure only authorized software runs on OT endpoints.", 3,
       "   Application allowlisting or whitelisting in place."),
    ControlRequirement("IEC-62443-3-3-SR3.4", "iec-62443", "Device Hardening",
                       "Apply timely security patches/updates to OT systems.", 3,
       "   Maintenance window schedule with rollback plan."),
    ControlRequirement("IEC-62443-3-3-SR4.1", "iec-62443", "Network Protection",
                       "Segment OT networks from IT and external zones.", 4,
       "   Firewall rules at zone boundary with change-control logs."),
    ControlRequirement("IEC-62443-3-3-SR4.2", "iec-62443", "Network Protection",
                       "Restrict communications to only required protocols/ports.", 4,
       "   Allowed protocol list (Modbus/TCP, DNP3, IEC 60870-5-104) validated."),
    ControlRequirement("IEC-62443-3-3-SR4.3", "iec-62443", "Network Protection",
                       "Detect and respond to suspicious network activity.", 3,
       "   IDS/monitoring on critical conduits with alerting SLA."),
    ControlRequirement("IEC-62443-3-3-SR5.1", "iec-62443", "System Integrity",
                       "Detect and resist malware on OT endpoints.", 3,
       "   Anti-malware or application control deployed on engineering workstations."),
    ControlRequirement("IEC-62443-3-3-SR6.1", "iec-62443", "Security Monitoring",
                       "Collect and analyse OT event logs for forensic readiness.", 3,
       "   Centralised SIEM pipeline ingesting PLC/HMI syslog."),
    ControlRequirement("IEC-62443-3-3-SR7.1", "iec-62443", "Incident Handling",
                       "Develop and maintain an incident-response plan covering OT.", 3,
       "   OT-specific IR playbook with escalation contacts."),
    ControlRequirement("IEC-62443-3-3-SR8.1", "iec-62443", "Resilience",
                       "Perform periodic testing of recovery capabilities.", 2,
       "   Recovery test report demonstrating data-restoration SLA met."),
]


def build_assessment(target_name: str, scope: List[str]) -> tuple:
    """Return list of requirements and a summary dict."""
    requirements: List[ControlRequirement] = []
    scope_lower = [s.lower().replace("-", "") for s in scope]
    if "nerc" in scope_lower or "cip" in scope_lower:
        requirements.extend(NERC_CIP_SUBSET)
    if "iec" in scope_lower or "62443" in scope_lower:
        requirements.extend(IEC_62443_SR33_SUBSET)
    if not requirements:
        requirements.extend(NERC_CIP_SUBSET + IEC_62443_SR33_SUBSET)
    summary = {
        "total_requirements": len(requirements),
        "by_framework": {},
        "by_level": {},
    }
    for r in requirements:
        summary["by_framework"][r.framework] = summary["by_framework"].get(r.framework, 0) + 1
        lvl = r.requirement_level
        summary["by_level"][f"L{lvl}"] = summary["by_level"].get(f"L{lvl}", 0) + 1
    return requirements, summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG OT/ICS Security Assessment Helper",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--scope", nargs="+", default=["nerc-cip", "iec-62443"],
                        help="Frameworks to include")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON or CSV report")
    args = parser.parse_args()

    requirements, summary = build_assessment("otsystem-assessment", args.scope)

    print(f"\n  [*] Target : {args.scope}")
    print(f"  [*] Requirements loaded: {len(requirements)}")
    print(f"  [*] Framework breakdown: {json.dumps(summary['by_framework'])}")
    print(f"  [*] Level breakdown:     {json.dumps(summary['by_level'])}\n")

    print("| Ref ID | Framework | Lvl | Category | Description | Evidence Hint |")
    print("|--------|-----------|-----|----------|-------------|---------------|")
    for r in requirements:
        desc_short = r.description[:50].replace("\n", " ")
        hint_short = r.evidence_hint[:50].replace("\n", " ") if r.evidence_hint else "-"
        print(f"| {r.ref_id} | {r.framework} | {r.requirement_level} | {r.category} | {desc_short} | {hint_short} |")

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        rows = [[r.ref_id, r.framework, r.requirement_level, r.category, r.description, r.evidence_hint]
                for r in requirements]
        if args.output.endswith(".csv"):
            with open(args.output, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["ref_id", "framework", "level", "category", "description", "evidence_hint"])
                w.writerows(rows)
        else:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump({"generated_at": datetime.utcnow().isoformat() + "Z",
                           "requirements": [r.to_dict() for r in requirements],
                           "summary": summary}, fh, indent=2)
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
