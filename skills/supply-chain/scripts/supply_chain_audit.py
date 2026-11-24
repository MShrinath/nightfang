#!/usr/bin/env python3
"""Supply chain registry audit — extract inventory, detect typosquats, scan for known-malicious patterns."""
import sys
import os
import json
import subprocess
from typing import List, Dict, Set


class SupplyChainAuditor:
    """Audit software supply chain across multiple registries."""

    # Homoglyph maps: Latin → visually similar Unicode
    HOMOGLYPHS = {
        'a': '\u0430\u00e0\u00e1\u00e2\u00e3\u00e4\u00e5',
        'c': '\u00e7\u0107',
        'e': '\u00eb\u00e8\u00e9\u00ea',
        'i': '\u0131\u00ef\u00ec\u00ed\u00ee\u0456',
        'l': '\u0142\u043b\u041b',
        'o': '\u00f3\u00f2\u00f4\u00f5\u00f6\u043e\u041e',
        's': '\u015f\u00df',
        't': '\u0163',
        'z': '\u0437',
    }

    SUSPICIOUS_KEYWORDS = {'eval', 'exec', 'base64_decode', 'shell_exec', 'child_process',
                           'require(\'child', 'import(os)', 'system(', 'wget', 'curl'}

    def __init__(self, project_root: str):
        self.root = project_root
        self.packages: Dict[str, str] = {}      # name -> version
        self.registry_types: Set[str] = set()

    def discover_packages(self) -> Dict[str, Dict]:
        """Extract package inventory using registry-specific tools."""
        results = {"packages": {}, "typosquats": [], "flags": []}

        # npm
        if os.path.exists(os.path.join(self.root, "package.json")):
            self.registry_types.add("npm")
            try:
                out = subprocess.check_output(
                    ["npm", "ls", "--all", "--json"], cwd=self.root, stderr=subprocess.DEVNULL, timeout=30
                )
                data = json.loads(out)
                for dep_path, info in data.get("dependencies", {}).items():
                    if isinstance(info, dict):
                        name = info.get("name", dep_path)
                        ver = info.get("version", "?")
                        self.packages[name] = ver
            except Exception:
                pass

        # pip
        req_file = os.path.join(self.root, "requirements.txt")
        if os.path.exists(req_file):
            self.registry_types.add("pypi")
            for line in open(req_file):
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    name, _, ver = line.partition("=")
                    self.packages[name.strip()] = ver.strip().strip("\"'")

        results["packages"] = self.packages
        results["typosquats"] = self._detect_typosquats()
        return results

    def _detect_typosquats(self) -> List[Dict]:
        """Check package names for suspicious patterns."""
        findings = []
        normal_names = {
            "requests", "flask", "django", "numpy", "pandas", "scipy", "matplotlib",
            "express", "axios", "lodash", "webpack", "babel", "react", "vue",
            "flask-cors", "python-dotenv", "gunicorn", "sqlalchemy", "psycopg2",
        }
        for pkg in self.packages:
            lower = pkg.lower()
            # Direct match
            if lower in normal_names and lower != pkg.lower():
                findings.append({"package": pkg, "type": "normal-case", "severity": "low"})
            # Check for digits or special chars in name
            if any(c.isdigit() or c in "_-" for c in pkg):
                findings.append({"package": pkg, "type": "anomalous_name", "severity": "medium"})
            # Check for suspicious keyword in metadata
            for kw in self.SUSPICIOUS_KEYWORDS:
                if kw in pkg.lower():
                    findings.append({"package": pkg, "type": "keyword_match", "severity": "high", "keyword": kw})
        return findings

    def generate_sbom_summary(self) -> Dict:
        """Produce a CycloneDX-style summary of the supply chain posture."""
        return {
            "component_count": len(self.packages),
            "registries_covered": sorted(self.registry_types),
            "typosquat_alerts": len([f for f in self._detect_typosquats() if f.get("severity") in ("medium", "high")]),
            "risk_level": "CRITICAL" if any(f.get("severity") == "high" for f in self._detect_typosquats())
                          else "ELEVATED" if self._detect_typosquats() else "LOW",
        }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Supply chain audit tool")
    ap.add_argument("--root", default=".")
    args = ap.parse_args()
    auditor = SupplyChainAuditor(args.root)
    result = auditor.discover_packages()
    print(json.dumps({
        "audit_results": result,
        "sbom_summary": auditor.generate_sbom_summary(),
    }, indent=2))
