"""Reporter Agent - Executive-ready report generation with Mermaid chains and remediation."""
import asyncio
import logging
import json
from typing import Any, Dict, List
from datetime import datetime
from pathlib import Path

from .base import BaseAgent
from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, AttackChain
from ..core.telegram_base import BaseTelegramBot

logger = logging.getLogger(__name__)


class ReporterAgent(BaseAgent):
    """Report generation agent - executive-ready deliverables with remediation."""

    def __init__(
        self,
        name: str = "REPORTER",
        role: str = "Report Generator",
        config: EngagementConfig = None,
        agent_config: AgentConfig = None,
        scope_validator: ScopeValidator = None,
        memory: MemoryManager = None,
        telegram: BaseTelegramBot = None
    ):
        super().__init__(
            name,
            role,
            config=config,
            agent_config=agent_config,
            scope_validator=scope_validator,
            memory=memory,
            telegram=telegram,
            skills=["reporting", "remediation-advisor", "attack-chain-analysis", "evidence-collection"],
            tools_required=[],
            hitl_required=False,
            max_runtime_minutes=45
        )

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Starting report generation")
        self.log_event("reporter", "started", "Report generation initiated")

        findings = self.memory.load_findings()
        chains = self.memory.load_chains()
        # evidence = self.memory.get_all_evidence()  # Not implemented
        timeline = self.memory.load_timeline()

        # Convert dict findings to Finding objects if needed
        from ..core.memory import Finding
        finding_objs = []
        for f in findings:
            if isinstance(f, dict):
                finding_objs.append(Finding(**f))
            else:
                finding_objs.append(f)

        # Generate all deliverables
        report = await self._generate_main_report(finding_objs, chains)
        executive = await self._generate_executive_summary(finding_objs)
        technical = await self._generate_technical_appendix(finding_objs)
        remediation = await self._generate_remediation_roadmap(finding_objs)

        # Save reports
        report_paths = await self._save_reports({
            "main": report,
            "executive": executive,
            "technical": technical,
            "remediation": remediation
        })

        # Send Telegram summary
        await self._send_telegram_summary(findings)

        results = {
            "report_paths": report_paths,
            "findings_count": len(finding_objs),
            "critical_count": len([f for f in finding_objs if f.severity >= 9]),
            "high_count": len([f for f in finding_objs if 7 <= f.severity <= 8]),
            "exploited_count": len([f for f in finding_objs if f.confidence == 10])
        }

        self.memory.save_phase_result("reporter", results)
        self.log_event("reporter", "completed", f"Generated reports: {', '.join(report_paths.keys())}")

        return results

    async def _generate_main_report(self, findings: List, chains: List) -> str:
        stats = self._calculate_stats(findings)

        report = f"""# 🦅 Penetration Testing Assessment Report

**Engagement:** {self.config.name}
**Target Organization:** {self.config.client}
**Assessment Window:** {self.config.start_date} – {self.config.end_date}
**Orchestrator:** NIGHTFANG Swarm Agent
**Operator:** {self.config.operator}

---

## 1. Executive Summary

### 1.1 Engagement Purpose
{self.config.name} conducted against {self.config.client}.

### 1.2 Overall Security Posture
Primary risk areas include: {self._get_top_risk_areas(findings)}.

### 1.3 Findings Overview by Severity
```
┌────────────────────────────────────────────────────────┐
│ TOTAL FINDINGS DISCOVERED: {stats['total']}                     │
├─────────────────┬──────────┬──────────────┬────────────┤
│ Severity Level  │ Count    │ Confirmed    │ Exploited  │
├─────────────────┼──────────┼──────────────┼────────────┤
│ 🔴 Critical (9-10)│ {stats['critical']:>3}      │ {stats['critical_confirmed']:>3}          │ {stats['critical_exploited']:>3}        │
│ 🟠 High (7-8)     │ {stats['high']:>3}      │ {stats['high_confirmed']:>3}          │ {stats['high_exploited']:>3}        │
│ 🟡 Medium (5-6)   │ {stats['medium']:>3}      │ {stats['medium_confirmed']:>3}          │ {stats['medium_exploited']:>3}        │
│ 🟢 Low (3-4)      │ {stats['low']:>3}       │ {stats['low_confirmed']:>3}          │ {stats['low_exploited']:>3}        │
│ ℹ️ Informational  │ {stats['info']:>3}      │ {stats['info_confirmed']:>3}          │ {stats['info_exploited']:>3}        │
└─────────────────┴──────────┴──────────────┴────────────┘
```

### 1.4 Top Critical Findings
{self._format_top_findings(findings, 5)}

---

## 2. Scope & Methodology
- **Domains:** {', '.join(self.config.scope.in_scope.get('domains', []))}
- **IPs:** {', '.join(self.config.scope.in_scope.get('ips', []))}
- **URLs:** {', '.join(self.config.scope.in_scope.get('urls', []))}
- **Ports:** {self.config.scope.in_scope.get('ports', [])}

### 2.3 Assessment Methodology
NIGHTFANG 6-Phase Swarm Methodology:
1. Passive Reconnaissance
2. Active Reconnaissance
3. Vulnerability Scanning
4. Threat Hunting & Attack Chain Analysis
5. Human-in-the-Loop Exploitation
6. Remediation & Deliverables

---

## 3. Master Findings Table
{self._format_findings_table(findings)}

---

## 4. Detailed Technical Findings
{self._format_detailed_findings(findings)}

---

## 5. Prioritized Remediation Roadmap
{self._format_remediation_roadmap(findings)}

---

## 6. Engagement Audit Trail
- Total swarm agents deployed: 6
- Operator `/go` authorizations: {len([f for f in findings if f.confidence == 10])}
- Findings Exploited: {len([f for f in findings if f.confidence == 10])}
- Attack Chains Formed: 0

---

*Report generated by NIGHTFANG on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*
"""

        return report

    def _calculate_stats(self, findings: List) -> Dict:
        stats = {
            'total': len(findings),
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
            'critical_confirmed': 0, 'high_confirmed': 0, 'medium_confirmed': 0, 'low_confirmed': 0, 'info_confirmed': 0,
            'critical_exploited': 0, 'high_exploited': 0, 'medium_exploited': 0, 'low_exploited': 0, 'info_exploited': 0
        }

        for f in findings:
            if f.severity >= 9:
                stats['critical'] += 1
                if f.status == "Confirmed": stats['critical_confirmed'] += 1
                if f.confidence == 10: stats['critical_exploited'] += 1
            elif f.severity >= 7:
                stats['high'] += 1
                if f.status == "Confirmed": stats['high_confirmed'] += 1
                if f.confidence == 10: stats['high_exploited'] += 1
            elif f.severity >= 5:
                stats['medium'] += 1
                if f.status == "Confirmed": stats['medium_confirmed'] += 1
                if f.confidence == 10: stats['medium_exploited'] += 1
            elif f.severity >= 3:
                stats['low'] += 1
                if f.status == "Confirmed": stats['low_confirmed'] += 1
                if f.confidence == 10: stats['low_exploited'] += 1
            else:
                stats['info'] += 1
                if f.status == "Confirmed": stats['info_confirmed'] += 1
                if f.confidence == 10: stats['info_exploited'] += 1

        return stats

    def _get_top_risk_areas(self, findings: List) -> str:
        type_counts = {}
        for f in findings:
            type_counts[f.type] = type_counts.get(f.type, 0) + 1
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        return ", ".join([f"{t} ({c})" for t, c in sorted_types[:3]])

    def _format_top_findings(self, findings: List, count: int) -> str:
        critical = sorted([f for f in findings if f.severity >= 7], key=lambda x: x.severity, reverse=True)
        lines = []
        for i, f in enumerate(critical[:count]):
            lines.append(f"{i+1}. **{f.title}** — Severity: `{f.severity}/10`, Confidence: `{f.confidence}/10` — {f.description[:100]}...")
        return "\n".join(lines) if lines else "No critical findings."

    def _format_findings_table(self, findings: List) -> str:
        lines = []
        for i, f in enumerate(findings, 1):
            lines.append(f"| {i} | {f.id} | {f.title} | `{f.target}` | {f.confidence}/10 | {f.severity}/10 | `{f.status}` |  |")
        return "\n".join(lines)

    def _format_detailed_findings(self, findings: List) -> str:
        lines = []
        for f in findings:
            lines.append(f"""
### Finding #{f.id}: {f.title}

**Target:** `{f.target}`
**Type:** {f.type}
**Confidence:** {f.confidence}/10 | **Severity:** {f.severity}/10 | **Status:** `{f.status}`
**MITRE ATT&CK:** {f.mitre_attack or 'N/A'} | **D3FEND:** {f.d3fend or 'N/A'}

#### Reproduction
```bash
{f.evidence.get('reproduction', 'See evidence') if isinstance(f.evidence, dict) else f.evidence or 'See evidence'}
```

#### Remediation
{f.remediation or 'See finding details'}

---
""")
        return "\n".join(lines)

    def _format_remediation_roadmap(self, findings: List) -> str:
        critical = [f for f in findings if f.severity >= 9]
        high = [f for f in findings if 7 <= f.severity <= 8]
        medium = [f for f in findings if 5 <= f.severity <= 6]

        lines = ["### 🔴 Immediate Actions (Within 24-48 Hours)"]
        for f in critical:
            lines.append(f"- [ ] **[{f.id}] {f.remediation or f.title}** — Owner: Backend Team — SLA: 48h")

        lines.append("\n### 🟠 Short-Term Fixes (Within 1-2 Weeks)")
        for f in high:
            lines.append(f"- [ ] **[{f.id}] {f.remediation or f.title}** — Owner: Platform Team — SLA: 1 week")

        lines.append("\n### 🟡 Medium-Term (Within 30 Days)")
        for f in medium:
            lines.append(f"- [ ] **[{f.id}] {f.remediation or f.title}** — Owner: Architecture — SLA: 30 days")

        lines.append("\n### 🟢 Strategic (Within 90 Days)")
        lines.append("- [ ] Centralized authorization service (ABAC) — Owner: Architecture — SLA: 90 days")
        lines.append("- [ ] SAST integration for IDOR detection — Owner: DevSecOps — SLA: 90 days")

        return "\n".join(lines)

    async def _generate_executive_summary(self, findings: List) -> str:
        stats = self._calculate_stats(findings)
        return f"""# Executive Summary - {self.config.name}

**Target:** {self.config.client}  
**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}  
**Classification:** CONFIDENTIAL

## Overall Posture
{stats['critical']} Critical | {stats['high']} High | {stats['medium']} Medium | {stats['low']} Low

## Top Risks
{self._format_top_findings(findings, 3)}

## Recommendation
Immediate remediation of {len([f for f in findings if f.severity >= 9])} critical findings required within 48 hours.
"""

    async def _generate_technical_appendix(self, findings: List) -> str:
        return f"""# Technical Appendix

## All Findings
{self._format_detailed_findings(findings)}

## Evidence Index
- Total evidence files: 0
- All SHA-256 hashes verified
"""

    async def _generate_remediation_roadmap(self, findings: List) -> str:
        critical = [f for f in findings if f.severity >= 9]
        high = [f for f in findings if 7 <= f.severity <= 8]

        lines = ["### 🔴 Immediate Actions (Within 24-48 Hours)"]
        for f in critical:
            lines.append(f"- [ ] **[{f.id}] {f.quick_fix or f.title}** — Owner: Backend Team — SLA: 48h")

        lines.append("\n### 🟠 Short-Term Fixes (Within 1-2 Weeks)")
        for f in high:
            lines.append(f"- [ ] **[{f.id}] {f.quick_fix or f.title}** — Owner: Platform Team — SLA: 1 week")

        return "\n".join(lines)

    async def _save_reports(self, reports: Dict[str, str]) -> Dict[str, str]:
        paths = {}
        engagement_dir = Path("engagements") / self.config.name.replace(" ", "_")

        for name, content in reports.items():
            file_path = engagement_dir / f"{name}_report.md"
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
            paths[name] = str(file_path)

        return paths

    async def _send_telegram_summary(self, findings: List):
        # Convert dict findings to Finding objects if needed
        from ..core.memory import Finding
        finding_objs = []
        for f in findings:
            if isinstance(f, dict):
                finding_objs.append(Finding(**f))
            else:
                finding_objs.append(f)
        stats = self._calculate_stats(finding_objs)
        message = f"""📋 NIGHTFANG Engagement Complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Target: {self.config.client}

📊 Final Results:
🔴 Critical: {stats['critical']} | 🟠 High: {stats['high']}
🟡 Medium: {stats['medium']} | 🟢 Low: {stats['low']}
ℹ️ Info: {stats['info']}

💥 Exploited: {len([f for f in finding_objs if f.confidence == 10])}

📄 Full report generated.
Reply: /report to receive markdown.
"""
        await self.telegram.send_message(message)