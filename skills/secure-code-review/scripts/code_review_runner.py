#!/usr/bin/env python3
"""
Secure Code Review Checklist Runner — scans source repos against OWASP ASVS,
CWE Top 25, and SAST output formats (Semgrep SARIF, Bandit JSON). Produces an
evidence-ready report. Read-only; does not modify source or run active tools.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class Finding:
    file_path: str
    line: int
    rule_id: str
    severity: str
    confidence: str = ""
    message: str = ""
    cwe_id: str = ""
    source_tool: str = ""

    def to_dict(self) -> dict:
        return {
            "file": self.file_path, "line": self.line,
            "rule_id": self.rule_id, "severity": self.severity,
            "confidence": self.confidence, "message": self.message[:300],
            "cwe_id": self.cwe_id, "source_tool": self.source_tool,
        }


# ---------------------------------------------------------------------------
# Heuristic rules for offline/static scanning without external tooling
# ---------------------------------------------------------------------------

HEURISTIC_RULES = [
    (re.compile(r"(?i)(?:password|passwd|pwd)\s*=\s*[\"'][^\"']{4,}[\"']"),
     "HARDCODED_CREDENTIAL", "high", "Potential hardcoded credential"),
    (re.compile(r'(?m)os\.system\s*\('),
     "OS_COMMAND_INJECTION", "critical", "os.system() call — use subprocess.list"),
    (re.compile(r'(?m)exec\s*\('),
     "DYNA_EXEC", "critical", "eval/exec usage detected"),
    (re.compile(r'''(?m).*(?:cursor\.execute|connection\.execute)\s*\(\s*f['"]'''),
     "SQL_INJECTION_FSTRING", "critical", "Formatted SQL string construction"),
    (re.compile(r"requests\.(get|post|put|delete)\(.*format\("),
     "SSRF_FORMAT_INTERP", "high", "Potentially unsafe URL interpolation"),
    (re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*=\s*[\"'][A-Za-z0-9+/]{16,}[\"']"),
     "EXPOSED_API_KEY", "high", "Potential API key in source"),
    (re.compile(r"(?i)#.*(?:password|secret|key)\s*:\s*\S+"),
     "COMMENTED_CREDENTIAL", "medium", "Credential in comment"),
]


def classify_rule(rule_id: str, message: str) -> str:
    low_kw = message.lower()
    if any(k in low_kw for k in ("sql", "injection")):
        return "CWE-89"
    if any(k in low_kw for k in ("xss", "cross.site")):
        return "CWE-79"
    if any(k in low_kw for k in ("credential", "password", "secret", "api.key")):
        return "CWE-798"
    if any(k in low_kw for k in ("command", "system()", "exec(")):
        return "CWE-78"
    if any(k in low_kw for k in ("ssrf", "url", "request")):
        return "CWE-918"
    return ""


def scan_text(path: str, text: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = text.splitlines()
    for pat, rid, sev, msg in HEURISTIC_RULES:
        for idx, line in enumerate(lines, start=1):
            if pat.search(line):
                cwe = classify_rule(rid, msg)
                findings.append(Finding(
                    file_path=path, line=idx, rule_id=rid,
                    severity=sev, confidence="high", message=msg,
                    cwe_id=cwe, source_tool="heuristic-scan",
                ))
    return findings


def parse_bandit_json(path: str) -> List[Finding]:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    results: List[Finding] = []
    for item in raw.get("results", []):
        results.append(Finding(
            file_path=item.get("filename", ""),
            line=item.get("line_number", 0),
            rule_id=item.get("test_id", "bandit-" + str(item.get("test_id", "?"))),
            severity=item.get("issue_severity", "low").lower(),
            confidence=item.get("issue_confidence", "medium").lower(),
            message=item.get("issue_text", "")[:200],
            cwe_id="", source_tool="bandit",
        ))
    return results


def parse_sarif(path: str) -> List[Finding]:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    findings: List[Finding] = []
    rule_map: Dict[str, str] = {}
    for rule in raw.get("runs", [{}])[0].get("tool", {}).get("driver", {}).get("rules", []):
        rule_map[rule.get("id", "")] = rule.get("shortDescription", {}).get("text", "")
    for run in raw.get("runs", []):
        for result in run.get("results", []):
            loc = result.get("locations", [{}])[0]
            physical = loc.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            path_str = artifact.get("uri", "")
            line_num = physical.get("region", {}).get("startLine", 0)
            rule_id = result.get("ruleId", "unknown")
            desc = result.get("message", {}).get("text", rule_map.get(rule_id, ""))
            sev = "medium"
            for tag in ["critical", "error", "high", "warning", "note"]:
                if tag in str(result).lower():
                    sev = tag
                    break
            findings.append(Finding(
                file_path=path_str, line=line_num, rule_id=rule_id,
                severity=sev, message=desc[:300], source_tool="sarif",
            ))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Secure Code Review Checklist Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Path to directory (scan) or SARIF/Bandit JSON file (parse)")
    parser.add_argument("--extensions", nargs="*", default=[".py", ".js", ".ts", ".go", ".java", ".rb", ".cs"],
                        help="File extensions to scan")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    all_findings: List[Finding] = []
    if os.path.isfile(args.target):
        lower = args.target.lower()
        if lower.endswith(".sarif"):
            all_findings.extend(parse_sarif(args.target))
        elif lower.endswith(".json") and os.path.isfile(args.target):
            all_findings.extend(parse_bandit_json(args.target))
        else:
            with open(args.target, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            findings = scan_text(args.target, text)
            all_findings.extend(findings)
    elif os.path.isdir(args.target):
        count_files = 0
        for root, _dirs, files in os.walk(args.target):
            # Skip venv/.git/node_modules
            skip = any(p in root for p in ("/.git/", "/node_modules/", "/venv/", "/.venv/", "/__pycache__/"))
            if skip:
                continue
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in args.extensions:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as fh:
                        text = fh.read(500_000)  # cap per file
                    findings = scan_text(fpath, text)
                    all_findings.extend(findings)
                    count_files += 1
                except OSError:
                    pass
        print(f"\n  [*] Scanned {count_files} file(s) in {args.target}")
    else:
        print(f"[!] Target not found: {args.target}", file=sys.stderr)
        return 2

    if not all_findings:
        print("\n  [*] No findings.")
        return 0

    by_severity = Counter(f.severity.upper() for f in all_findings)
    by_cwe = Counter(f.cwe_id for f in all_findings if f.cwe_id)

    print(f"\n  [*] Total findings: {len(all_findings)}")
    print(f"  [*] Severity distribution:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cnt = by_severity.get(sev, 0)
        bar = "#" * min(cnt, 50)
        print(f"      {sev:<8} {cnt:>3d}  {bar}")
    if by_cwe:
        print(f"  [*] Top CWEs:")
        for cwe, cnt in by_cwe.most_common(5):
            print(f"      {cwe}: {cnt}")

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": args.target,
        "total_findings": len(all_findings),
        "by_severity": dict(by_severity),
        "findings": [f.to_dict() for f in all_findings],
    }
    print(json.dumps(report, indent=2))

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    return max(0, by_severity.get("CRITICAL", 0))


if __name__ == "__main__":
    sys.exit(main())
