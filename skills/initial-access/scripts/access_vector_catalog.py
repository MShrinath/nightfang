#!/usr/bin/env python3
"""
Initial Access Vector Catalog — reference catalog of common initial-access
techniques mapped to OWASP Top 10 / ATT&CK TA0001 with defensive checklist
and detection guidance. Read-only reference tool; no active exploitation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List


@dataclass
class AccessVector:
    technique_id: str
    technique_name: str
    attack_surface: str           # web, email, physical, cloud, supply-chain, etc.
    precondition: str
    defender_checklist: List[str] = field(default_factory=list)
    detection_guidance: str = ""
    related_vulnerabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "attack_surface": self.attack_surface,
            "precondition": self.precondition[:250],
            "defender_checklist": self.defender_checklist,
            "detection_guidance": self.detection_guidance[:300],
            "related_vulnerabilities": self.related_vulnerabilities,
        }


INITIAL_ACCESS_VECTORS: List[AccessVector] = [
    AccessVector(
        technique_id="T1566",
        technique_name="Phishing",
        attack_surface="email/web",
        precondition="User receives malicious link or attachment that executes payload.",
        defender_checklist=[
            "Enforce DMARC policy with p=reject on all inbound domains.",
            "Deploy email gateway with sandboxed macro execution.",
            "User-awareness program covering spear-phish indicators.",
        ],
        detection_guidance="Look for unusual sender domains, URL shortener use, macro-enabled attachments, and POST-to-login-page patterns from non-browser UAs.",
        related_vulnerabilities=["CWE-79", "CWE-89"],
    ),
    AccessVector(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        attack_surface="web/API/VPN",
        precondition="Internet-exposed service has an exploitable vulnerability (e.g. RCE, SQLi).",
        defender_checklist=[
            "Maintain asset inventory with external exposure mapping.",
            "Run regular DAST/SAST scans on public endpoints.",
            "Apply vendor patches within vendor SLA windows.",
        ],
        detection_guidance="Watch for anomalous HTTP methods, suspicious user-agent strings, abnormal query-parameter lengths, and outbound connections from web-process context.",
        related_vulnerabilities=["CWE-79", "CWE-89", "CWE-94", "CWE-287"],
    ),
    AccessVector(
        technique_id="T1078",
        technique_name="Valid Accounts",
        attack_surface="internal/cloud",
        precondition="Legitimate credentials are stolen, misused, or default creds left intact.",
        defender_checklist=[
            "Enforce MFA on all remote and privileged access.",
            "Audit default credentials on all services quarterly.",
            "Implement privileged-access management (PAM).",
        ],
        detection_guidance="Flag login-from-new-geo, impossible-travel, unusual time-of-day logins, and credential-use across multiple workstations simultaneously.",
        related_vulnerabilities=["CWE-287", "CWE-798"],
    ),
    AccessVector(
        technique_id="T1195.002",
        technique_name="Supply Chain Compromise",
        attack_surface="software-dependencies/build-pipeline",
        precondition="Malicious artifact introduced into trusted software supply chain.",
        defender_checklist=[
        "Generate and verify SBOM for critical dependencies.",
        "Pin dependency versions and verify hash against upstream.",
        "Segment CI/CD runner environments from production networks.",
        ],
        detection_guidance="Monitor for unexpected network egress from build runners, new package publication events, and hash mismatches in lockfiles vs known-good baselines.",
        related_vulnerabilities=["CWE-829"],
    ),
    AccessVector(
        technique_id="T1078.004",
        technique_name="Cloud Accounts",
        attack_surface="cloud-console/IAM",
        precondition="Compromised or over-permissioned IAM principal grants console/API access.",
        defender_checklist=[
            "Require MFA on all IAM users/roles.",
            "Remove unused access keys older than 90 days.",
            "Enable CloudTrail/Activity Log with immutable storage.",
        ],
        detection_guidance="Alert on API calls from unfamiliar IPs, new access-key creation, privilege-escalation IAM actions, and console logins outside business hours.",
        related_vulnerabilities=["CWE-287", "CWE-862"],
    ),
    AccessVector(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        attack_surface="endpoint/powershell",
        precondition="Execution environment allows unauthorised script invocation.",
        defender_checklist=[
            "Enable PowerShell constrained language mode and AMSI.",
            "Apply AppLocker/WDAC rules restricting script directories.",
            "Log all script-block invocations via ScriptBlockLogging.",
        ],
        detection_guidance="Look for encoded commands (-enc/-enct), parent-child process anomalies (WINWORD->powershell), and unusual WMI/CIM consumer activity.",
        related_vulnerabilities=["CWE-78", "CWE-79"],
    ),
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Initial Access Vector Catalog",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--surface", nargs="*",
                        choices=["email", "web", "API", "VPN", "cloud", "supply-chain", "endpoint", "all"],
                        default=["all"], help="Filter by attack surface")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    surfaces = set(s.lower() for s in args.surface)
    filtered = INITIAL_ACCESS_VECTORS if "all" in surfaces else [
        v for v in INITIAL_ACCESS_VECTORS
        if any(s in v.attack_surface.lower() for s in surfaces)
    ]

    print(f"\n  [*] Vectors shown : {len(filtered)} / {len(INITIAL_ACCESS_VECTORS)}")
    print(f"  [*] Attack surfaces: {', '.join(sorted(surfaces))}\n")
    print("| Technique | Name                          | Surface         | Checklist Items | Related CWEs |")
    print("|-----------|-------------------------------|-----------------|-----------------|--------------|")
    for v in filtered:
        name_short = v.technique_name[:29]
        checks = str(len(v.defender_checklist))
        cwes = ", ".join(v.related_vulnerabilities[:3]) or "-"
        print(f"| {v.technique_id:<9} | {name_short:<29} | {v.attack_surface:<13} | {checks:<13} | {cwes:<12} |")

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_vectors": len(INITIAL_ACCESS_VECTORS),
        "filtered_count": len(filtered),
        "vectors": [v.to_dict() for v in filtered],
    }
    print(json.dumps(report, indent=2))

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
