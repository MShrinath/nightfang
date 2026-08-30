#!/usr/bin/env python3
"""
OPENCLAW / HERMES — Report Compiler with Framework Mapping
Compiles structured findings into Markdown assessment reports mapped to MITRE ATT&CK & D3FEND.
"""

import sys
import json
import yaml
from datetime import datetime
from pathlib import Path

def generate_report(engagement_config_path: str, findings_file: str, output_report_path: str):
    with open(engagement_config_path, "r", encoding="utf-8") as f:
        engagement = yaml.safe_load(f)

    findings = []
    if Path(findings_file).exists():
        with open(findings_file, "r", encoding="utf-8") as f:
            findings = yaml.safe_load(f) or []

    # Count by severity
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        sev = item.get("severity", 1)
        if sev >= 9:
            stats["critical"] += 1
        elif sev >= 7:
            stats["high"] += 1
        elif sev >= 5:
            stats["medium"] += 1
        elif sev >= 3:
            stats["low"] += 1
        else:
            stats["info"] += 1

    report_lines = [
        f"# 🦅 Penetration Testing Assessment Report",
        f"**Engagement:** {engagement.get('engagement', {}).get('name', 'Security Assessment')}",
        f"**Client:** {engagement.get('engagement', {}).get('client', 'Target Organization')}",
        f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Orchestrated By:** HERMES Swarm Agent (OPENCLAW Framework)\n",
        f"---",
        f"## 1. Executive Summary\n",
        f"| Severity Level | Count |",
        f"| :--- | :--- |",
        f"| 🔴 Critical (9-10) | {stats['critical']} |",
        f"| 🟠 High (7-8) | {stats['high']} |",
        f"| 🟡 Medium (5-6) | {stats['medium']} |",
        f"| 🟢 Low (3-4) | {stats['low']} |",
        f"| ℹ️ Informational (1-2) | {stats['info']} |\n",
        f"---",
        f"## 2. Master Findings & Framework Mapping Table\n",
        f"| ID | Title | Target | Conf/Sev | MITRE ATT&CK | D3FEND Defense | Status |",
        f"| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
    ]

    for f_item in findings:
        attack_id = f_item.get('mitre_attack', 'T1190')
        d3fend_id = f_item.get('d3fend', 'D3-PSA')
        report_lines.append(
            f"| {f_item.get('id', 'HERMES-XXX')} | {f_item.get('title')} | `{f_item.get('target')}` | {f_item.get('confidence')}/10 (C) / {f_item.get('severity')}/10 (S) | `{attack_id}` | `{d3fend_id}` | `{f_item.get('status', 'Confirmed')}` |"
        )

    report_lines.append("\n---\n## 3. Detailed Findings Walkthroughs\n")
    for f_item in findings:
        report_lines.extend([
            f"### Finding #{f_item.get('id')}: {f_item.get('title')}",
            f"- **Target:** `{f_item.get('target')}`",
            f"- **Confidence Score:** {f_item.get('confidence')}/10 | **Severity Score:** {f_item.get('severity')}/10",
            f"- **MITRE ATT&CK ID:** `{f_item.get('mitre_attack', 'N/A')}`",
            f"- **D3FEND Countermeasure:** `{f_item.get('d3fend', 'N/A')}`",
            f"- **Description:** {f_item.get('description', 'N/A')}\n",
            f"#### Reproduction Walkthrough:",
            f"```bash\n{f_item.get('reproduction', '# Command here')}\n```\n",
            f"#### Remediation Advice:",
            f"{f_item.get('remediation', 'Apply latest vendor security patches.')}\n",
            f"---\n"
        ])

    with open(output_report_path, "w", encoding="utf-8") as out:
        out.write("\n".join(report_lines))

    print(f"[+] Framework-mapped report compiled at: {output_report_path}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python report_compiler.py <config.yaml> <findings.yaml> <output_report.md>")
        sys.exit(1)
    generate_report(sys.argv[1], sys.argv[2], sys.argv[3])
