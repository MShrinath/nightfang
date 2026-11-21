#!/usr/bin/env python3
"""
GRC (Governance, Risk & Compliance) Checklist Generator
Maps OWASP ASVS, NIST CSF, and CIS Controls categories to actionable
remediation checks — produces an evidence-ready compliance matrix for audits.
Read-only output; does not connect to any external GRC platform.
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
class GRCCheck:
    control_id: str           # e.g. OWASP-ASVS-4.1.1, NIST-CSF-PR.DS-1
    framework: str            # owasp-asvs, nist-csf, cis-controls, soc2
    category: str
    description: str
    requirement_type: str     # must, should, could
    evidence_hint: str
    remediation_path: str = ""

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "framework": self.framework,
            "category": self.category,
            "description": self.description[:300],
            "requirement_type": self.requirement_type,
            "evidence_hint": self.evidence_hint,
            "remediation_path": self.remediation_path,
        }


@dataclass
class GRCReport:
    target: str
    timestamp: str
    framework_scope: List[str]
    checks: List[GRCCheck] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)

    def add(self, c: GRCCheck) -> None:
        self.checks.append(c)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "target": self.target,
            "timestamp": self.timestamp,
            "framework_scope": self.framework_scope,
            "total_checks": len(self.checks),
            "checks": [c.to_dict() for c in self.checks],
            "summary": self.summary,
        }, indent=indent, default=str)


# ---------------------------------------------------------------------------
# Control catalog — curated subsets of OWASP ASVS v4, NIST CSF v1.1, CIS v8
# ---------------------------------------------------------------------------

OWASP_ASVS_LEVEL3: List[GRCCheck] = [
    GRCCheck("OWASP-ASVS-1.1", "owasp-asvs", "Identity & Authentication",
             "Verify unique user IDs are issued after registration.",
             "must", "Screenshot or log of registration flow with unique ID assignment."),
    GRCCheck("OWASP-ASVS-1.2", "owasp-asvs", "Identity & Authentication",
             "Enforce minimum password complexity and length.",
             "must", "Password policy config file excerpt showing min-length >= 12 and character class requirements."),
    GRCCheck("OWASP-ASVS-1.3", "owasp-asvs", "Identity & Authentication",
             "Implement MFA for privileged and remote-access accounts.",
             "must", "Configuration screenshot of MFA enforcement on admin pathways."),
    GRCCheck("OWASP-ASVS-2.1", "owasp-asvs", "Authentication",
             "Authenticate users via secure, hashed credentials (bcrypt/scrypt/argon2).",
             "must", "Code review confirming no plaintext or reversible encryption for passwords."),
    GRCCheck("OWASP-ASVS-2.2", "owasp-asvs", "Authentication",
             "Lock accounts after repeated failed authentication attempts.",
             "must", "Evidence of lockout policy with exponential back-off configured."),
    GRCCheck("OWASP-ASVS-2.3", "owasp-asvs", "Authentication",
             "Provide secure password-recovery flow without revealing account existence.",
             "must", "Flow diagram or PoC showing reset token is single-use and time-bounded."),
    GRCCheck("OWASP-ASVS-3.1", "owasp-asvs", "Authorization",
             "Enforce server-side access-control checks on every protected resource.",
             "must", "Review of route handlers confirming middleware authorisation gate."),
    GRCCheck("OWASP-ASVS-3.2", "owasp-asvs", "Authorization",
             "Prevent IDOR by validating object ownership against the authenticated principal.",
             "must", "Code trace showing ownership check before sensitive read/write operations."),
    GRCCheck("OWASP-ASVS-3.3", "owasp-asvs", "Authorization",
             "Restrict bulk property assignment (mass-assignment) via allowlist.",
             "must", "DTO/view-model review confirming only expected fields accepted."),
    GRCCheck("OWASP-ASVS-4.1", "owasp-asvs", "Secure Transport",
             "Enforce TLS 1.2+ for all web and API endpoints.",
             "must", "TLS scan report showing no protocols below 1.2 enabled."),
    GRCCheck("OWASP-ASVS-4.2", "owasp-asvs", "Secure Transport",
             "Enable HSTS with includeSubDomains and long max-age.",
             "must", "Response header capture showing Strict-Transport-Security present."),
    GRCCheck("OWASP-ASVS-5.1", "owasp-asvs", "Validation, Sanitisation & Filtering",
             "Apply output encoding for all user-supplied data rendered in HTML.",
             "must", "Template review showing auto-escaping enabled or manual encode calls."),
    GRCCheck("OWASP-ASVS-5.2", "owasp-asvs", "Validation, Sanitisation & Filtering",
             "Use parameterised queries for all database interactions.",
             "must", "Static analysis report from bandit/sqlmap-free tool confirming zero string-concatenated SQL."),
    GRCCheck("OWASP-ASVS-6.1", "owasp-asvs", "Error Handling & Logging",
             "Log security-relevant events (auth success/fail, privilege changes, policy violations).",
             "must", "Log sample redacted showing timestamp, user, event-type, source-IP present."),
    GRCCheck("OWASP-ASVS-6.2", "owasp-asvs", "Error Handling & Logging",
             "Do not expose stack traces or internal paths in production error responses.",
             "must", "Production error page inspection confirming generic message returned."),
    GRCCheck("OWASP-ASVS-7.1", "owasp-asvs", "Data Protection",
             "Encrypt sensitive data at rest using AES-256-GCM or equivalent.",
             "must", "Database or storage configuration showing encryption enabled for PII columns."),
    GRCCheck("OWASP-ASVS-7.2", "owasp-asvs", "Data Protection",
             "Mask or tokenize cardholder data per PCI-DSS requirements.",
             "should", "Tokenisation service config confirming PAN never stored in cleartext."),
    GRCCheck("OWASP-ASVS-8.1", "owasp-asvs", "Cryptography",
             "Use established, peer-reviewed cryptographic libraries; do not roll custom crypto.",
             "must", "Dependency audit listing only recognised crypto libs (cryptography, libsodium, etc.)."),
    GRCCheck("OWASP-ASVS-8.2", "owasp-asvs", "Cryptography",
             "Random values used for security purposes must be generated with CSPRNG.",
             "must", "Code review confirming use of secrets.token_bytes / os.urandom / SystemRandom."),
    GRCCheck("OWASP-ASVS-9.1", "owasp-asvs", "Session Management",
             "Issue a new, unpredictable session identifier on every login.",
             "must", "Traffic capture showing session cookie value rotates after authn."),
    GRCCheck("OWASP-ASVS-9.2", "owasp-asvs", "Session Management",
             "Set Secure, HttpOnly, and SameSite flags on session cookies.",
             "must", "Cookie attribute dump showing Set-Cookie header with required flags."),
    GRCCheck("OWASP-ASVS-9.3", "owasp-asvs", "Session Management",
             "Implement absolute session timeout and idle timeout.",
             "must", "Config showing max_age and idle_timeout values set for session store."),
]

NIST_CSF_PR_DE_LOW: List[GRCCheck] = [
    GRCCheck("NIST-CSF-PR.DS-1", "nist-csf", "Protect — Data Security",
             "Process data assets and related information to support ongoing risk management.",
             "must", "Asset inventory listing data classification per asset."),
    GRCCheck("NIST-CSF-PR.DS-2", "nist-csf", "Protect — Data Security",
             "Map data to classifications (confidentiality, integrity, availability).",
             "must", "Classification policy document mapping data types to tiers."),
    GRCCheck("NIST-CSF-PR.DS-5", "nist-csf", "Protect — Data Security",
             "Protect confidentiality using encryption, access controls, and DLP.",
             "should", "Encryption-at-rest and in-transit configuration evidence."),
    GRCCheck("NIST-CSF-PR.IP-1", "nist-csf", "Protect — IT Infrastructure",
             "Baseline and maintain inventories of end-user devices.",
             "must", "Device inventory with assigned owners and patch status."),
    GRCCheck("NIST-CSF-PR.IP-4", "nist-csf", "Protect — IT Infrastructure",
             "Implement vulnerability scanning on systems and applications.",
             "must", "Scan schedule and recent results demonstrating recurring assessment."),
    GRCCheck("NIST-CSF-PR.PT-3", "nist-csf", "Protect — Protective Technology",
             "Implement compensating controls where primary controls are insufficient.",
             "should", "Compensating-control register with rationale and effectiveness testing."),
]

CIS_CONTROLS_V8_SELECT: List[GRCCheck] = [
    GRCCheck("CIS-v8-1.1", "cis-controls", "Inventory and Control of Enterprise Assets",
             "Maintain an up-to-date inventory of all authorised enterprise devices.",
             "must", "CMDB or endpoint-management export current within 30 days."),
    GRCCheck("CIS-v8-3.1", "cis-controls", "Inventory and Control of Software Assets",
             "Maintain an inventory of all application software.",
             "must", "Software asset list including vendor, version, and patch state."),
    GRCCheck("CIS-v8-4.1", "cis-controls", "Secure Configuration",
             "Establish and maintain secure configuration for hardware and software.",
             "should", "Baseline configs derived from CIS Benchmarks applied to servers and workstations."),
    GRCCheck("CIS-v8-5.1", "cis-controls", "Account Management",
             "Require multifactor authentication for human access to corporate systems.",
             "must", "MFA enforcement report across identities (cloud + on-prem)."),
    GRCCheck("CIS-v8-8.1", "cis-controls", "Audit Log Management",
             "Collect audit logs from enterprise assets.",
             "must", "Centralised logging pipeline confirming log ingestion from critical systems."),
    GRCCheck("CIS-v8-9.1", "cis-controls", "Email and Web Browser Protections",
             "Deploy email gateway filtering and web-proxy blacklisting.",
             "should", "Email security gateway configuration verifying SPF/DKIM/DMARC enforcement."),
    GRCCheck("CIS-v8-13.1", "cis-controls", "Malware Defences",
             "Deploy anti-malware on all endpoints and servers.",
             "must", "EDR/AV coverage report showing >95 % endpoint protection rate."),
    GRCCheck("CIS-v8-16.1", "cis-controls", "Application Software Security",
             "Ensure application development follows secure SDLC practices.",
             "should", "SDLC documentation including SAST/DAST gates and threat modelling."),
    GRCCheck("CIS-v8-17.1", "cis-controls", " Incident Management",
             "Develop and implement incident-response procedures.",
             "must", "Incident-response plan documenting roles, escalation, and post-mortem process."),
    GRCCheck("CIS-v8-18.1", "cis-controls", "Penetration Testing",
             "Conduct periodic penetration tests and vulnerability assessments.",
             "must", "Recent pen-test report (≤ 12 months) with findings and remediation tracking."),
]


def resolve_framework(scope: List[str]) -> List[GRCCheck]:
    """Return checks matching the requested framework scope."""
    all_checks: List[GRCCheck] = []
    scope_lower = [s.lower().replace("-", "") for s in scope]
    if "owasp" in scope_lower or "asvs" in scope_lower:
        all_checks.extend(OWASP_ASVS_LEVEL3)
    if "nist" in scope_lower or "csf" in scope_lower:
        all_checks.extend(NIST_CSF_PR_DE_LOW)
    if "cis" in scope_lower or "controls" in scope_lower:
        all_checks.extend(CIS_CONTROLS_V8_SELECT)
    if not all_checks:
        # Default: include everything
        all_checks.extend(OWASP_ASVS_LEVEL3)
        all_checks.extend(NIST_CSF_PR_DE_LOW)
        all_checks.extend(CIS_CONTROLS_V8_SELECT)
    return all_checks


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG GRC Compliance Checklist Generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--scope", nargs="+", default=["owasp-asvs", "nist-csf", "cis-controls"],
                        help="Frameworks to include (default: all)")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args()

    checks = resolve_framework(args.scope)
    report = GRCReport(
        target="multi-framework-assessment",
        timestamp=datetime.utcnow().isoformat() + "Z",
        framework_scope=args.scope,
        checks=checks,
        summary={
            "total": len(checks),
            "by_framework": {},
            "by_requirement": {"must": 0, "should": 0, "could": 0},
        },
    )
    for c in checks:
        report.summary["by_framework"][c.framework] = report.summary["by_framework"].get(c.framework, 0) + 1
        report.summary["by_requirement"][c.requirement_type] = report.summary["by_requirement"].get(c.requirement_type, 0) + 1

    if args.format == "markdown":
        lines = [
            "# GRC Compliance Checklist",
            f"\nGenerated: {report.timestamp}",
            f"\nFrameworks: {', '.join(args.scope)}\n",
            "| Control | Framework | Requirement | Category | Description | Evidence Hint |",
            "|---------|-----------|-------------|----------|-------------|---------------|",
        ]
        for c in checks:
            lines.append(f"| {c.control_id} | {c.framework} | {c.requirement_type.upper()} | {c.category} | {c.description[:60]} | {c.evidence_hint[:60]} |")
        print("\n".join(lines))
    else:
        print(report.to_json())

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report.to_json())
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    print(f"\n  [*] {len(checks)} control(s) loaded across {len(args.scope)} framework(s).\n", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
