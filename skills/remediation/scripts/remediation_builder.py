#!/usr/bin/env python3
"""
Remediation Guidance Builder
Maps CVE/CWE identifiers to actionable remediation playbooks with severity-tiered
prioritization and evidence linkage — used after proof-of-concept validation per SOP-04.
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
class RemediationStep:
    order: int
    action: str
    command_or_path: str = ""
    explanation: str = ""
    verification: str = ""

    def to_dict(self) -> dict:
        d = {"order": self.order, "action": self.action}
        if self.command_or_path:
            d["command_or_path"] = self.command_or_path
        if self.explanation:
            d["explanation"] = self.explanation
        if self.verification:
            d["verification"] = self.verification
        return d


@dataclass
class RemediationPlan:
    finding_id: str
    title: str
    severity: str
    cwe_id: str
    cvss_score: Optional[float]
    exploitability: str  # confirmed, theoretical, unproven
    playbook: List[RemediationStep] = field(default_factory=list)
    related_cves: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    risk_acceptance_note: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "exploitability": self.exploitability,
            "playbook_steps": [s.to_dict() for s in self.playbook],
            "related_cves": self.related_cves,
            "references": self.references,
            "risk_acceptance_note": self.risk_acceptance_note,
        }


# ---------------------------------------------------------------------------
# CWE → default remediation templates
# ---------------------------------------------------------------------------

CWE_TEMPLATES: Dict[str, List[RemediationStep]] = {
    "CWE-79": [  # XSS
        RemediationStep(1, "Implement output encoding", "",
                        "Encode all user-supplied data before rendering in HTML context.",
                        "Reproduce PoC and confirm payload is neutralised."),
        RemediationStep(2, "Apply Content-Security-Policy header", "",
                        "Set Content-Security-Policy: default-src 'self'; script-src 'self'.",
                        "Verify CSP header present via response inspection."),
        RemediationStep(3, "Use parameterised DOM APIs", "",
                        "Replace innerHTML with textContent or validated insertAdjacentHTML.",
                        "Code review confirms no raw HTML interpolation."),
    ],
    "CWE-89": [  # SQL Injection
        RemediationStep(1, "Switch to parameterised queries", "",
                        "Use prepared statements / parameter binding in all database interactions.",
                        "Static analysis (semgrep/bandit) reports zero string-concatenation queries."),
        RemediationStep(2, "Validate and whitelist input", "",
                        "Apply allowlist validation on all user-supplied parameters.",
                        "Fuzz-tested inputs rejected by validator."),
        RemediationStep(3, "Reduce database privileges", "",
                        "Run the app DB account with only required permissions (no DROP/ALTER).",
                        "Permission audit confirms least-privilege model."),
    ],
    "CWE-287": [  # Improper Authentication
        RemediationStep(1, "Enforce MFA on all privileged accounts", "",
                        "Deploy TOTP or FIDO2 second factor; require for admin paths.",
                        "Login flow demands second factor for role escalation."),
        RemediationStep(2, "Implement account lockout", "",
                        "Lock accounts after 5 failed attempts with exponential back-off.",
                        "Attack tool returns 423 Locked after threshold."),
        RemediationStep(3, "Rotate compromised credentials", "",
                        "Invalidate existing sessions and force password reset.",
                        "Session store returns 401 Unauthorized for old tokens."),
    ],
    "CWE-798": [  # Hardcoded Credentials
        RemediationStep(1, "Remove hardcoded secrets from source", "",
                        "Delete credential literals; move to environment variables or secret manager.",
                        "grep -r on repo finds no remaining literals."),
        RemediationStep(2, "Rotate exposed credentials immediately", "",
                        "Assume compromise; rotate all affected service accounts.",
                        "Credential provider confirms rotation successful."),
        RemediationStep(3, "Integrate pre-commit secret scanning", "",
                        "Add gitleaks or trivy secret scan to CI gate.",
                        "CI pipeline blocks commits containing key patterns."),
    ],
    "CWE-200": [  # Info Exposure
        RemediationStep(1, "Strip debug/metadata from responses", "",
                        "Remove X-Debug-Token, stack traces, and verbose error bodies in production.",
                        "Response headers verified clean against staging config."),
        RemediationStep(2, "Restrict internal endpoints", "",
                        "Firewall/admin-panel routes behind VPN or bastion host.",
                        "Network-level check denies direct Internet access to admin path."),
    ],
    "CWE-327": [  # Broken Crypto
        RemediationStep(1, "Upgrade cipher suite", "",
                        "Disable 3DES/RC4/null ciphers; prefer AES-GCM and CHACHA20.",
                        "SSL Labs grade A or equivalent."),
        RemediationStep(2, "Increase key lengths", "",
                        "RSA ≥ 2048 bits, EC curves P-256 or stronger.",
                        "Certificate inspector confirms key sizes."),
    ],
    "CWE-78": [  # OS Command Injection
        RemediationStep(1, "Avoid shell execution where possible", "",
                        "Replace subprocess with shell=True using list-argument form.",
                        "Code review confirms no shell invocations in hot path."),
        RemediationStep(2, "Sanitise and validate all arguments", "",
                        "Whitelist allowed command names; reject shell metacharacters.",
                        "Input fuzz tester cannot inject semicolons or pipes."),
    ],
    "CWE-434": [  # Unrestricted File Upload
        RemediationStep(1, "Restrict MIME types and extensions", "",
                        "Accept only expected MIME types and deny executable extensions.",
                        "Upload test with .php/.jsp rejected."),
        RemediationStep(2, "Store uploads outside web root", "",
                        "Serve files via a proxy that never interprets them as code.",
                        "Direct URL to upload path returns 403."),
        RemediationStep(3, "Scan uploaded files for malware", "",
                        "Integrate ClamAV or equivalent on upload path.",
                        "Malware sample not served/executed by handler."),
    ],
    "CWE-611": [  # XXE
        RemediationStep(1, "Disable external entity processing", "",
                        "Configure XML parser with disallow_doctype_decl=true and resolve externally-referenced entities=false.",
                        "XXE PoC returns parse error instead of file contents."),
        RemediationStep(2, "Prefer JSON over XML for APIs", "",
                        "Replace legacy XML endpoints with JSON equivalents.",
                        "API docs no longer expose XML content type."),
    ],
    "CWE-1067": [  # TLS Downgrade / Insecure Protocol
        RemediationStep(1, "Disable TLS 1.0 and 1.1", "",
                        "Configure server to only accept TLS 1.2+ connections.",
                        "Nmap ssl-enum-ciphers shows no weak protocols."),
        RemediationStep(2, "Enforce HSTS", "",
                        "Add Strict-Transport-Security header with includeSubDomains and max-age ≥ 31536000.",
                        "HTTP request to HTTP origin redirects to HTTPS."),
    ],
}

DEFAULT_PLAYBOOK = [
    RemediationStep(1, "Acknowledge the finding and document exploitability context", "",
                    "Record whether the vulnerability is actively exploitable in the target environment.", ""),
    RemediationStep(2, "Prioritise remediation based on CVSS score and business impact", "",
                    "Critical/High findings should be addressed within 72 hours; Medium within 30 days.", ""),
    RemediationStep(3, "Implement the technical fix following vendor guidance", "",
                    "Reference the CWE-specific best practices listed in NIST SP 800-53 or OWASP guidance.", ""),
    RemediationStep(4, "Verify the fix with targeted retesting", "",
                    "Run the original PoC (in safe sandbox if needed) to confirm remediation succeeded.", ""),
    RemediationStep(5, "Document the change and close the finding", "",
                    "Link the fix commit or ticket to the original finding for audit trail.", ""),
]


def build_remediation(finding: dict) -> RemediationPlan:
    """Generate a remediation plan from a single VAPT finding dict."""
    cwe = finding.get("cwe_id", "")
    severity = finding.get("severity", "informational").lower()
    title = finding.get("title") or finding.get("finding_title", "Untitledd Finding")
    finding_id = finding.get("id") or finding.get("finding_id", "UNKNOWN")
    cvss = finding.get("cvss_v4_base_score") or finding.get("cvss_v31_score")
    exploit = finding.get("exploitability", "theoretical")

    steps = CWE_TEMPLATES.get(cwe, []) or []
    if not steps:
        steps = DEFAULT_PLAYBOOK

    plan = RemediationPlan(
        finding_id=finding_id,
        title=title,
        severity=severity,
        cwe_id=cwe,
        cvss_score=cvss,
        exploitability=exploit,
        playbook=[*steps],
        related_cves=finding.get("related_cves") or [],
        references=finding.get("references") or [],
        risk_acceptance_note=finding.get("risk_acceptance_note") or "",
    )

    # Add severity-based escalation note
    if severity in ("critical", "high"):
        plan.playbook.insert(0, RemediationStep(
            order=0,
            action="ESCALATE to security team lead within 4 hours",
            explanation=f"Severity {severity.upper()} — immediate triage required per incident-response policy.",
            verification="",
        ))
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Remediation Guidance Builder",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input", help="Path to findings JSON or JSONL file")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save remediation plans as JSON")
    args = parser.parse_args()

    try:
        with open(args.input, encoding="utf-8", errors="replace") as fh:
            content = fh.read().strip()
        if not content:
            print("[!] Empty input file.", file=sys.stderr)
            return 2
        try:
            data = json.loads(content)
            findings = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            findings = [json.loads(line) for line in content.splitlines() if line.strip()]
    except OSError as exc:
        print(f"[!] Could not read {args.input}: {exc}", file=sys.stderr)
        return 2

    plans: List[RemediationPlan] = [build_remediation(f) for f in findings]

    summary_by_severity: Dict[str, int] = {}
    for p in plans:
        summary_by_severity[p.severity] = summary_by_severity.get(p.severity, 0) + 1

    print(f"\n  [*] Generated {len(plans)} remediation plan(s)")
    print(f"  [*] Severity breakdown: {json.dumps(summary_by_severity)}\n")
    for p in sorted(plans, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 9)):
        cwe_tag = f" [{p.cwe_id}]" if p.cwe_id else ""
        print(f"  [{p.severity.upper():>9s}] {p.title}{cwe_tag}")
        print(f"           Steps: {len(p.playbook)}  |  Exploitability: {p.exploitability}")

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "plans_count": len(plans),
                "plans": [p.to_dict() for p in plans],
            }, fh, indent=2, default=str)
        print(f"\n  [*] Plans saved: {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
