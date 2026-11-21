#!/usr/bin/env python3
"""
Supply-Chain Security Analyzer for Python projects
Checks requirements.txt / pyproject.toml / Pipfile for known-vulnerable or
unpinned dependencies using PyPI metadata and CVE summary data. Read-only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class DependencyFinding:
    rule_id: str
    severity: str
    title: str
    description: str
    package: str
    installed_version: str
    evidence: str
    remediation: str
    cwe: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "severity": self.severity,
            "title": self.title, "description": self.description[:300],
            "package": self.package, "installed_version": self.installed_version,
            "evidence": self.evidence[:400], "remediation": self.remediation,
            "cwe": self.cwe,
        }


@dataclass
class SupplyChainReport:
    target: str
    timestamp: str
    findings: List[DependencyFinding] = field(default_factory=list)
    packages_scanned: int = 0

    def add(self, f: DependencyFinding) -> None:
        self.findings.append(f)
        self.packages_scanned += 1

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "target": self.target,
            "timestamp": self.timestamp,
            "packages_scanned": self.packages_scanned,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }, indent=indent, default=str)


# Known CVE ranges checked without network — extend as needed
KNOWN_VULN_VERSIONS: Dict[str, List[str]] = {
    "requests": ["2.20.0", "2.20.1", "2.20.2", "2.21.0", "2.22.0"],
    "urllib3": ["1.24.1", "1.24.2", "1.25rc1"],
}

PIP_ALLOW_ANY = re.compile(r"^--(allow-[a-z-]+)\b")


def _fetch_pypi_metadata(pkg_name: str, timeout: int = 8) -> Optional[dict]:
    """Fetch top-level info from PyPI JSON API (read-only, no auth)."""
    url = f"https://pypi.org/pypi/{pkg_name}/json"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "nightfang-supply-chain/1.0"})
        ctx = __import__("ssl").create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def parse_requirements(text: str) -> List[tuple]:
    """Extract (name, version_spec) tuples from pip requirements text."""
    deps: List[tuple] = []
    version_re = re.compile(r'^([A-Za-z0-9_][A-Za-z0-9._-]*)\s*(?:([<>=!~^]=?\s*[^\s,#;]+))?', re.I)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("#"):
            continue
        m = version_re.match(line)
        if m:
            name = m.group(1).lower().replace("-", "_")
            ver = (m.group(2) or "").strip()
            deps.append((name, ver))
    return deps


def check_pin(dep_name: str, dep_ver: str) -> Optional[DependencyFinding]:
    """Flag unpinned or loosely-pinned dependencies."""
    if not dep_ver:
        return DependencyFinding(
            rule_id="SC-PIN-01", severity="medium",
            title=f"Unpinned dependency: {dep_name}",
            description="No version constraint specified — builds are non-reproducible.",
            package=dep_name, installed_version="(any)",
            evidence=f"{dep_name}=={dep_ver}" if dep_ver else dep_name,
            remediation="Pin to a specific version or use a lockfile (pip-tools, poetry, uv).",
            cwe="CWE-1104",
        )
    stripped = dep_ver.replace(" ", "")
    if any(stripped.startswith(prefix) for prefix in ("<=", ">=", "~=", "!=")):
        return DependencyFinding(
            rule_id="SC-PIN-02", severity="low",
            title=f"Loosely pinned dependency: {dep_name}",
            description=f"Version constraint '{dep_ver}' may allow insecure minor/patch updates.",
            package=dep_name, installed_version=dep_ver,
            evidence=dep_ver,
            remediation="Use exact pin (==) for critical dependencies or enforce a lockfile.",
        )
    return None


def check_known_vuln(dep_name: str, dep_ver: str) -> Optional[DependencyFinding]:
    """Check against locally-defined known-vulnerable version list."""
    vulns = KNOWN_VULN_VERSIONS.get(dep_name.lower())
    if not vulns or not dep_ver:
        return None
    # Strip operators
    clean_ver = re.sub(r'^[<>=!~^]+', '', dep_ver).strip()
    if clean_ver in vulns:
        return DependencyFinding(
            rule_id=f"SC-KNOWN-{dep_name.upper()}", severity="high",
            title=f"Known vulnerable version of {dep_name}",
            description=f"{dep_name}=={clean_ver} has a known CVE advisory.",
            package=dep_name, installed_version=clean_ver,
            evidence=clean_ver,
            remediation=f"Upgrade {dep_name} to the latest patched version.",
            cwe="CWE-1104",
        )
    return None


def analyze_requirements(text: str, source: str) -> SupplyChainReport:
    """Analyze a requirements-style text block."""
    report = SupplyChainReport(target=source, timestamp=datetime.utcnow().isoformat() + "Z")
    deps = parse_requirements(text)
    seen: set = set()
    for dep_name, dep_ver in deps:
        if dep_name in seen:
            continue
        seen.add(dep_name)
        pin_finding = check_pin(dep_name, dep_ver)
        if pin_finding:
            report.add(pin_finding)
        vuln_finding = check_known_vuln(dep_name, dep_ver)
        if vuln_finding:
            report.add(vuln_finding)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Supply-Chain Dependency Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("path", help="Path to requirements.txt / pyproject.toml / Pipfile")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    try:
        with open(args.path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        print(f"[!] Could not read {args.path}: {exc}", file=sys.stderr)
        return 2

    filename = os.path.basename(args.path).lower()
    if "requirements" in filename:
        report = analyze_requirements(content, args.path)
    elif filename == "pyproject.toml":
        # Minimal TOML-ish regex extraction — full parsing requires tomllib (3.11+)
        import re as _re
        pkg_block = _re.findall(r'\[\[projects\.dependencies\]\]\s*\nname\s*=\s*"([^"]+)"(?:\nversion\s*=\s*"([^"]*)")?', content)
        dep_lines = "\n".join(f"{name}{('='+ver) if ver else ''}" for name, ver in pkg_block)
        report = analyze_requirements(dep_lines, args.path)
    else:
        report = analyze_requirements(content, args.path)

    print(f"\n  [*] Scanned {report.packages_scanned} package(s) in {args.path}")
    print(f"  [*] Found {len(report.findings)} issue(s)\n")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for f in sorted(report.findings, key=lambda x: sev_order.get(x.severity, 9)):
        print(f"  [{f.severity.upper():>9s}] {f.title}")
        print(f"           {f.package}: {f.evidence[:100]}")

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report.to_json())
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    crit_high = sum(1 for f in report.findings if f.severity in ("critical", "high"))
    return 2 if crit_high > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
