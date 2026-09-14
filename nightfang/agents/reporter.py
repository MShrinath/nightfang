"""Reporter Agent - Generates final reports."""
import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset, TimelineEvent
from ..core.telegram_bot import TelegramBot
from .base import BaseAgent, ToolResult

logger = logging.getLogger(__name__)


class ReporterAgent(BaseAgent):
    """Report generation - executive summary, technical findings, remediation roadmap."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "REPORTER"
        self.role = "Report Generator"
        self.tools_required = []
        self.hitl_required = False
        self.max_runtime_minutes = 30
    
    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final report."""
        self.log_event("reporting", "Generating final report", "started")
        
        all_findings = self.memory.load_findings()
        evidence = inputs.get('evidence_artifacts', [])
        attack_chains = self.memory.load_chains()
        operator_decisions = self.memory.load_decisions()
        timeline = self.memory.load_timeline()
        assets = self.memory.load_assets()
        scope = self.memory.load_scope()
        
        report = self._generate_report(
            findings=all_findings,
            evidence=evidence,
            attack_chains=attack_chains,
            decisions=operator_decisions,
            timeline=timeline,
            assets=assets,
            scope=scope,
            engagement_name=self.config.name,
            client=self.config.client,
            operator=self.config.operator
        )
        
        # Save report
        report_path = self.memory.engagement_dir / "reports" / f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
        report_path.parent.mkdir(exist_ok=True)
        with open(report_path, 'w') as f:
            f.write(report)
        
        # Send Telegram summary
        await self._send_telegram_summary(all_findings)
        
        self.log_event("reporting", f"Report generated: {report_path}", "completed")
        
        return {
            'report_path': str(report_path),
            'report_content': report,
            'findings_count': len(all_findings)
        }
    
    def _generate_report(self, findings: List[Dict], evidence: List, attack_chains: List,
                        decisions: List, timeline: List, assets: List, scope: Dict,
                        engagement_name: str, client: str, operator: str) -> str:
        """Generate full markdown report."""
        
        # Count by severity
        sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 0)
            if sev >= 9: sev_counts['critical'] += 1
            elif sev >= 7: sev_counts['high'] += 1
            elif sev >= 5: sev_counts['medium'] += 1
            elif sev >= 3: sev_counts['low'] += 1
            else: sev_counts['info'] += 1
        
        lines = []
        
        # Title
        lines.append(f"# {engagement_name} — Security Assessment Report")
        lines.append("")
        lines.append(f"**Client:** {client}")
        lines.append(f"**Operator:** {operator}")
        lines.append(f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}")
        lines.append(f"**Type:** {self.config.type}")
        lines.append("")
        
        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"This report details the findings of a security assessment conducted against **{client}**.")
        lines.append(f"A total of **{len(findings)} vulnerabilities** were identified across the tested scope.")
        lines.append("")
        lines.append("### Findings by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| 🔴 Critical (9-10) | {sev_counts['critical']} |")
        lines.append(f"| 🟠 High (7-8) | {sev_counts['high']} |")
        lines.append(f"| 🟡 Medium (5-6) | {sev_counts['medium']} |")
        lines.append(f"| 🟢 Low (3-4) | {sev_counts['low']} |")
        lines.append(f"| ℹ️ Informational (1-2) | {sev_counts['info']} |")
        lines.append("")
        
        if sev_counts['critical'] > 0 or sev_counts['high'] > 0:
            lines.append("> ⚠️ **Immediate Attention Required**: Critical and High severity findings pose significant risk and should be remediated as a priority.")
            lines.append("")
        
        # Top 3 Findings
        sorted_findings = sorted(findings, key=lambda x: (x.get('severity', 0), x.get('confidence', 0)), reverse=True)
        if sorted_findings:
            lines.append("### Top Findings")
            lines.append("")
            for i, f in enumerate(sorted_findings[:3], 1):
                sev = f.get('severity', 0)
                conf = f.get('confidence', 0)
                sev_emoji = '🔴' if sev >= 9 else '🟠' if sev >= 7 else '🟡' if sev >= 5 else '🟢' if sev >= 3 else 'ℹ️'
                lines.append(f"{i}. {sev_emoji} **{f.get('title', 'Untitled')}** (Confidence: {conf}/10, Severity: {sev}/10)")
                lines.append(f"   - Target: {f.get('target', 'N/A')}")
                lines.append(f"   - Type: {f.get('type', 'N/A')}")
                lines.append("")
        
        # Scope & Methodology
        lines.append("## Scope & Methodology")
        lines.append("")
        lines.append("### Targets Tested")
        lines.append("")
        for k, v in scope.get('in_scope', {}).items():
            if v:
                lines.append(f"- **{k.capitalize()}:** {', '.join(v)}")
        lines.append("")
        
        lines.append("### Testing Methodology")
        lines.append("")
        lines.append("The assessment followed the NIGHTFANG methodology:")
        lines.append("1. **Passive Reconnaissance** (OSINT, DNS, Certificate Transparency)")
        lines.append("2. **Active Reconnaissance** (Port Scanning, Service Enumeration)")
        lines.append("3. **Vulnerability Scanning** (Web, API, Network, SSL/TLS, Cloud)")
        lines.append("4. **Threat Hunting** (Logic Flaws, Attack Chain Analysis)")
        lines.append("5. **Exploitation** (Operator-Approved Only)")
        lines.append("6. **Reporting** (Executive + Technical)")
        lines.append("")
        
        lines.append("### Tools Employed")
        lines.append("")
        tools_used = set()
        for f in findings:
            tools_used.add(f.get('discovered_by', 'Unknown'))
        for tool in sorted(tools_used):
            lines.append(f"- {tool}")
        lines.append("")
        
        # Findings Summary Table
        lines.append("## Findings Summary")
        lines.append("")
        lines.append("| # | Finding | Confidence | Severity | Status |")
        lines.append("|---|---------|------------|----------|--------|")
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get('severity', 0)
            conf = f.get('confidence', 0)
            status = f.get('status', 'suspected')
            decision = f.get('operator_decision', 'pending')
            lines.append(f"| {i} | {f.get('title', 'Untitled')} | {conf}/10 | {sev}/10 | {status}/{decision} |")
        lines.append("")
        
        # Detailed Findings
        lines.append("## Detailed Findings")
        lines.append("")
        for i, f in enumerate(sorted_findings, 1):
            lines.append(self._format_finding(i, f))
        
        # Attack Chains
        if attack_chains:
            lines.append("## Attack Chains")
            lines.append("")
            for j, chain in enumerate(attack_chains, 1):
                lines.append(f"### Attack Chain #{j}: {chain.get('name', 'Unnamed Chain')}")
                lines.append("")
                lines.append(f"**Chain Confidence:** {chain.get('confidence', 0)}/10 | **Chain Severity:** {chain.get('severity', 0)}/10")
                lines.append(f"**Steps:** {chain.get('steps', 0)} | **Complexity:** {chain.get('complexity', 'Unknown')}")
                lines.append("")
                lines.append(chain.get('narrative', 'No narrative provided.'))
                lines.append("")
                lines.append("#### Impact")
                lines.append(chain.get('impact', 'Not specified.'))
                lines.append("")
        
        # Remediation Roadmap
        lines.append("## Remediation Roadmap")
        lines.append("")
        lines.append("### Priority 1 — Critical (Immediate)")
        for f in sorted_findings:
            if f.get('severity', 0) >= 9:
                lines.append(f"- **{f.get('title')}**: {f.get('remediation', 'No remediation provided.')}")
        lines.append("")
        
        lines.append("### Priority 2 — High (Within 30 days)")
        for f in sorted_findings:
            if 7 <= f.get('severity', 0) < 9:
                lines.append(f"- **{f.get('title')}**: {f.get('remediation', 'No remediation provided.')}")
        lines.append("")
        
        lines.append("### Priority 3 — Medium (Within 90 days)")
        for f in sorted_findings:
            if 5 <= f.get('severity', 0) < 7:
                lines.append(f"- **{f.get('title')}**: {f.get('remediation', 'No remediation provided.')}")
        lines.append("")
        
        lines.append("### Priority 4 — Low (Next Release Cycle)")
        for f in sorted_findings:
            if 3 <= f.get('severity', 0) < 5:
                lines.append(f"- **{f.get('title')}**: {f.get('remediation', 'No remediation provided.')}")
        lines.append("")
        
        # Appendices
        lines.append("## Appendices")
        lines.append("")
        lines.append("### A. Engagement Timeline")
        lines.append("")
        lines.append("| Timestamp | Phase | Agent | Action | Result |")
        lines.append("|-----------|-------|-------|--------|--------|")
        for event in timeline:
            lines.append(f"| {event.get('timestamp', '')} | {event.get('phase', '')} | {event.get('agent', '')} | {event.get('action', '')} | {event.get('result', '')} |")
        lines.append("")
        
        lines.append("### B. Decision Audit Log")
        lines.append("")
        lines.append("| Timestamp | Finding ID | Action | Response | Notes |")
        lines.append("|-----------|------------|--------|----------|-------|")
        for d in decisions:
            lines.append(f"| {d.get('timestamp', '')} | {d.get('finding_id', '')} | {d.get('action_requested', '')} | {d.get('operator_response', '')} | {d.get('notes', '')} |")
        lines.append("")
        
        lines.append("### C. Scope Definition")
        lines.append("")
        lines.append("```yaml")
        lines.append(json.dumps(scope, indent=2))
        lines.append("```")
        lines.append("")
        
        return '\n'.join(lines)
    
    def _format_finding(self, num: int, finding: Dict) -> str:
        """Format a single finding for the detailed section."""
        sev = finding.get('severity', 0)
        conf = finding.get('confidence', 0)
        sev_emoji = '🔴' if sev >= 9 else '🟠' if sev >= 7 else '🟡' if sev >= 5 else '🟢' if sev >= 3 else 'ℹ️'
        
        lines = []
        lines.append(f"### Finding #{num}: {finding.get('title', 'Untitled')}")
        lines.append("")
        lines.append(f"**Confidence:** {conf}/10 | **Severity:** {sev}/10 {sev_emoji}")
        lines.append(f"**Status:** {finding.get('status', 'suspected').capitalize()} | **Operator Decision:** {finding.get('operator_decision', 'pending').capitalize()}")
        if finding.get('cvss'):
            lines.append(f"**CVSS:** {finding['cvss']}")
        if finding.get('cwe'):
            lines.append(f"**CWE:** {finding['cwe']}")
        if finding.get('cve'):
            lines.append(f"**CVE:** {', '.join(finding['cve'])}")
        lines.append("")
        
        # Frameworks
        frameworks = []
        if finding.get('mitre_attack'):
            frameworks.append(f"MITRE ATT&CK: {', '.join(finding['mitre_attack'])}")
        if finding.get('mitre_atlas'):
            frameworks.append(f"MITRE ATLAS: {', '.join(finding['mitre_atlas'])}")
        if finding.get('d3fend'):
            frameworks.append(f"MITRE D3FEND: {', '.join(finding['d3fend'])}")
        if frameworks:
            lines.append("**Frameworks:** " + " | ".join(frameworks))
            lines.append("")
        
        lines.append("#### Description")
        lines.append(finding.get('evidence', 'No description provided.'))
        lines.append("")
        
        if finding.get('reproduction_steps'):
            lines.append("#### Steps to Reproduce")
            for j, step in enumerate(finding['reproduction_steps'], 1):
                lines.append(f"{j}. {step}")
            lines.append("")
        
        if finding.get('remediation'):
            lines.append("#### Remediation")
            lines.append(finding['remediation'])
            lines.append("")
        
        return '\n'.join(lines)
    
    async def _send_telegram_summary(self, findings: List[Dict]):
        """Send summary to Telegram."""
        sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 0)
            if sev >= 9: sev_counts['critical'] += 1
            elif sev >= 7: sev_counts['high'] += 1
            elif sev >= 5: sev_counts['medium'] += 1
            elif sev >= 3: sev_counts['low'] += 1
            else: sev_counts['info'] += 1
        
        sorted_findings = sorted(findings, key=lambda x: (x.get('severity', 0), x.get('confidence', 0)), reverse=True)
        
        text = f"""📋 NIGHTFANG Engagement Report
━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Target: {self.config.client}
📅 Date: {datetime.utcnow().strftime('%Y-%m-%d')}

🔴 Critical: {sev_counts['critical']}
🟠 High: {sev_counts['high']}
🟡 Medium: {sev_counts['medium']}
🟢 Low: {sev_counts['low']}
ℹ️ Info: {sev_counts['info']}

🏆 Top Findings:"""
        
        for i, f in enumerate(sorted_findings[:3], 1):
            sev = f.get('severity', 0)
            conf = f.get('confidence', 0)
            text += f"\n{i}. {f.get('title', 'Untitled')} — Sev: {sev}/10, Conf: {conf}/10"
        
        text += "\n\n📄 Full report generated."
        
        await self.telegram.send_message(text)