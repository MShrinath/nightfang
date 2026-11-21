#!/usr/bin/env python3
"""
CI/CD Pipeline Security Analyzer
Parses pipeline configuration files (GitHub Actions, GitLab CI, Jenkinsfile)
and identifies common security misconfigurations. Read-only analysis only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class PipelineFinding:
    rule_id: str
    severity: str  # critical, high, medium, low, informational
    title: str
    description: str
    file_path: str
    line_number: Optional[int]
    evidence: str
    remediation: str
    cwe_id: str = ""
    mitre_attack: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description[:300],
            "file": self.file_path,
            "line": self.line_number,
            "evidence": self.evidence[:500],
            "remediation": self.remediation,
            "cwe": self.cwe_id,
            "mitre_attacks": self.mitre_attack,
        }


@dataclass
class PipelineReport:
    target: str
    timestamp: str
    findings: List[PipelineFinding] = field(default_factory=list)
    files_analyzed: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add_finding(self, f: PipelineFinding) -> None:
        self.findings.append(f)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "target": self.target,
            "timestamp": self.timestamp,
            "finding_count": len(self.findings),
            "files_analyzed": self.files_analyzed,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors[:5],
        }, indent=indent, default=str)


# ---------------------------------------------------------------------------
# Rule definitions — each function returns a list of PipelineFinding or []
# ---------------------------------------------------------------------------

SECRET_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("AWS_ACCESS_KEY",   re.compile(r"AKIA[0-9A-Z]{16}"),                "Remove AWS access keys from pipeline source; use OIDC or environment secrets."),
    ("GITHUB_TOKEN_EXP", re.compile(r"github_token.*\$\{"),              "Avoid embedding tokens in workflow strings; use secrets context explicitly."),
    ("PRIVATE_KEY",      re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Never commit private keys; use external secret management."),
    ("PASSWORD_ASSIGN",  re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{8,}[\"']", re.I), "Store passwords in CI/CD secret stores, not inline assignments."),
    ("CONN_STRING",      re.compile(r"(?:connectionstring|conn_str)\s*[:=]\s*[\"'][^\"']*(?:server|database|password)", re.I), "Use secret references for database connection strings."),
]

INSECURE_INSTALL: List[re.Pattern] = [
    re.compile(r"curl\s+.*\|\s*bash", re.I),           # curl piped to bash
    re.compile(r"wget\s+.*\|\s*sh", re.I),             # wget piped to shell
    re.compile(r"apt-get\s+install.*-y", re.I),         # unattended install without pinning
    re.compile(r"pip\s+install\s+.*--break-system-packages", re.I),
]

PRIVILEGED_RUNNER: List[re.Pattern] = [
    re.compile(r"privileged:\s*true", re.I),            # Docker privileged mode
    re.compile(r"docker:\s*\{[^}]*privileged", re.I),
    re.compile(r"-v\s+/var/run/docker\.sock", re.I),     # Docker socket mount
    re.compile(r"host.docker.internal", re.I),          # Host network namespace access
]

EXPOSED_ENV_SECRETS: List[re.Pattern] = [
    re.compile(r"env:\s*\n\s+\w+:\s*\S+[A-Za-z0-9+/=]{20,}"),  # long base64-looking env values
    re.compile(r"echo\s+.*['\"](sk-[a-zA-Z0-9]{20,})", re.I),    # API key echoing
]


def analyze_gha(content: str, path: str) -> List[PipelineFinding]:
    """Analyze GitHub Actions workflow YAML content."""
    findings: List[PipelineFinding] = []

    # Parse as YAML for structure-aware checks
    try:
        doc = yaml.safe_load(content) or {}
    except yaml.YAMLError:
        doc = {}

    lines = content.splitlines()

    # Check for hardcoded secrets across all lines
    for idx, line in enumerate(lines, start=1):
        for pattern_name, pat, remedy in SECRET_PATTERNS:
            if pat.search(line):
                findings.append(PipelineFinding(
                    rule_id=f"GHA-SEC-{pattern_name}",
                    severity="critical" if pattern_name in ("PRIVATE_KEY", "AWS_ACCESS_KEY") else "high",
                    title=f"Hardcoded secret detected: {pattern_name}",
                    description=f"Secret pattern '{pattern_name}' found in {path}:{idx}",
                    file_path=path,
                    line_number=idx,
                    evidence=line.strip()[:200],
                    remediation=remedy,
                    cwe_id="CWE-798" if "KEY" in pattern_name or "PRIVATE" in pattern_name else "CWE-256",
                ))

    # Check runner configuration
    jobs = doc.get("jobs", {}) or {}
    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue
        runs_on = str(job_def.get("runs-on", ""))
        if "self-hosted" in runs_on.lower():
            findings.append(PipelineFinding(
                rule_id="GHA-RUNNER-01",
                severity="medium",
                title="Self-hosted runner in use",
                description=f"Job '{job_name}' uses a self-hosted runner ({runs_on}). Verify runner isolation and patching.",
                file_path=path,
                line_number=None,
                evidence=f"runs-on: {runs_on}",
                remediation="Prefer GitHub-managed runners for public repositories; isolate self-hosted runners to dedicated networks.",
                cwe_id="CWE-250",
                mitre_attack=["TA0001"],
            ))

    # Check container jobs for privileged mode
    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue
        services = job_def.get("services", {}) or {}
        steps = job_def.get("steps", []) or []
        all_steps = list(steps) + [{"run": str(svc)} for svc in services.values()]
        for step in all_steps:
            if isinstance(step, dict):
                run_val = str(step.get("run", ""))
                for pat in PRIVILEGED_RUNNER:
                    if pat.search(run_val):
                        findings.append(PipelineFinding(
                            rule_id="GHA-DOCKER-01",
                            severity="high",
                            title="Insecure Docker configuration detected",
                            description=f"Docker privilege escalation risk in job '{job_name}'",
                            file_path=path,
                            line_number=None,
                            evidence=pat.pattern,
                            remediation="Remove privileged:true, avoid docker socket mounts, and usekaniko or buildah for container builds.",
                            cwe_id="CWE-250",
                            mitre_attack=["TA0004", "TA0005"],
                        ))

    # Inline script blocks containing curl|bash patterns
    for idx, line in enumerate(lines, start=1):
        for pat in INSECURE_INSTALL:
            if pat.search(line):
                findings.append(PipelineFinding(
                    rule_id="GHA-SHELL-01",
                    severity="medium",
                    title="Insecure package installation pattern",
                    description=f"Insecure install pattern at {path}:{idx}",
                    file_path=path,
                    line_number=idx,
                    evidence=line.strip()[:200],
                    remediation="Pin package versions, verify checksums before execution, avoid piping remote content to shells.",
                    cwe_id="CWE-829",
                ))

    return findings


def analyze_gitlab_ci(content: str, path: str) -> List[PipelineFinding]:
    """Analyze .gitlab-ci.yml content."""
    findings: List[PipelineFinding] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        for pattern_name, pat, remedy in SECRET_PATTERNS:
            if pat.search(line):
                findings.append(PipelineFinding(
                    rule_id=f"GLAB-SEC-{pattern_name}",
                    severity="critical" if "KEY" in pattern_name else "high",
                    title=f"Hardcoded secret: {pattern_name}",
                    description=f"Found at {path}:{idx}",
                    file_path=path,
                    line_number=idx,
                    evidence=line.strip()[:200],
                    remediation=remedy,
                    cwe_id="CWE-798" if "KEY" in pattern_name else "CWE-256",
                ))

    # Check for allow_failure masking real failures
    if "allow_failure: true" in content:
        findings.append(PipelineFinding(
            rule_id="GLAB-FAIL-01",
            severity="informational",
            title="Allow failure flag used — may mask pipeline errors",
            description="Pipeline allows failure on a step, potentially hiding security scan failures.",
            file_path=path,
            line_number=None,
            evidence="allow_failure: true detected",
            remediation="Review whether this step's failure should block the pipeline. Consider allowing failure only for non-critical post-deploy tasks.",
            cwe_id="CWE-1068",
        ))

    return findings


def analyze_jenkins(content: str, path: str) -> List[PipelineFinding]:
    """Analyze Jenkinsfile (Groovy DSL)."""
    findings: List[PipelineFinding] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        for pattern_name, pat, remedy in SECRET_PATTERNS:
            if pat.search(line):
                findings.append(PipelineFinding(
                    rule_id=f"JENK-SEC-{pattern_name}",
                    severity="critical" if "KEY" in pattern_name else "high",
                    title=f"Hardcoded secret in Jenkinsfile: {pattern_name}",
                    description=f"Found at {path}:{idx}",
                    file_path=path,
                    line_number=idx,
                    evidence=line.strip()[:200],
                    remediation=remedy,
                    cwe_id="CWE-798",
                ))
        # Credential binding by variable name rather than ID
        if re.search(r"withCredentials\s*\(\s*\[", line):
            findings.append(PipelineFinding(
                rule_id="JENK-CRED-01",
                severity="informational",
                title="Credential binding detected",
                description=f"Credential usage at {path}:{idx} — verify credential scope is appropriate.",
                file_path=path,
                line_number=idx,
                evidence=line.strip()[:200],
                remediation="Ensure credential IDs reference Jenkins credentials store entries, not plaintext values.",
            ))

    return findings


def analyze_pipeline(path: str, content: str) -> PipelineReport:
    """Dispatch to the correct analyzer based on file type."""
    report = PipelineReport(target=path, timestamp=datetime.utcnow().isoformat() + "Z")
    filename = os.path.basename(path).lower()
    report.files_analyzed.append(path)

    if "github" in filename or filename.endswith(".yml") or filename.endswith(".yaml"):
        if "workflow" in filename.lower() or "/.github/workflows/" in path:
            report.findings.extend(analyze_gha(content, path))
        elif "gitlab-ci" in filename.lower():
            report.findings.extend(analyze_gitlab_ci(content, path))
        elif "jenkins" in filename.lower() or filename == "jenkinsfile":
            report.findings.extend(analyze_jenkins(content, path))
        else:
            # Try GHA first, then generic YAML checks
            report.findings.extend(analyze_gha(content, path))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG CI/CD Pipeline Security Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("path", help="Path to pipeline config file or directory containing configs")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        targets = [
            os.path.join(root, f)
            for root, _, files in os.walk(args.path)
            for f in files
            if f.endswith((".yml", ".yaml")) and not f.startswith(".")
        ]
    else:
        targets = [args.path]

    combined = PipelineReport(target=args.path, timestamp=datetime.utcnow().isoformat() + "Z")

    for tp in targets:
        try:
            with open(tp, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            report = analyze_pipeline(tp, content)
            combined.findings.extend(report.findings)
            combined.files_analyzed.extend(report.files_analyzed)
        except OSError as exc:
            combined.errors.append(f"Could not read {tp}: {exc}")

    print(f"\n  [*] Analyzed {len(combined.files_analyzed)} pipeline file(s)")
    print(f"  [*] Found {len(combined.findings)} potential security issues\n")
    for f in combined.findings:
        marker = {"critical": "!!!", "high": "!! ", "medium": "!  ", "low": "   ", "informational": " i "}.get(f.severity, "   ")
        print(f"  [{marker}] [{f.severity.upper():>9s}] {f.title}")
        if f.line_number:
            print(f"         File: {f.file_path}:{f.line_number}")

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(combined.to_json())
        print(f"\n  [*] Report saved: {args.output}")

    return 1 if any(f.severity in ("critical", "high") for f in combined.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
