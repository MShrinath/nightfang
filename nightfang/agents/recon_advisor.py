"""Recon Advisor Agent - Expert reconnaissance and enumeration analyst."""
import asyncio
import logging
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset, TimelineEvent
from ..core.telegram_base import BaseTelegramBot
from .base import BaseAgent, ToolResult, AgentTier

logger = logging.getLogger(__name__)


class ReconAdvisorAgent(BaseAgent):
    """Expert reconnaissance and enumeration analyst."""

    def __init__(
        self,
        config: EngagementConfig,
        agent_config: AgentConfig,
        scope_validator: ScopeValidator,
        memory: MemoryManager,
        telegram: BaseTelegramBot
    ):
        super().__init__(
            name="RECON-ADVISOR",
            role="Reconnaissance & Enumeration Analyst",
            config=config,
            agent_config=agent_config,
            scope_validator=scope_validator,
            memory=memory,
            telegram=telegram,
            skills=["recon-passive", "recon-active", "scope-management", "osint-collection"],
            tools_required=["nmap", "masscan", "subfinder", "amass", "dnsrecon", "theharvester", "shodan", "censys", "whois", "dig"],
            hitl_required=True,
            hitl_checkpoints=["Before active scanning", "Before brute force enumeration"],
            max_runtime_minutes=120,
            tier=AgentTier.TIER_2_EXECUTION,
            trigger_phrases=["recon", "enumeration", "subdomain", "dns", "osint", "attack surface", "scope"],
            model="sonnet",
            description="Parses tool output, identifies attack surface, prioritizes targets, recommends next steps, and executes reconnaissance commands directly when authorized."
        )

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Run reconnaissance based on mode."""
        self.log_event("recon_advisor", "Starting reconnaissance", "started")

        mode = inputs.get('mode', 'passive')
        scope_declared = inputs.get('scope_declared', False)

        if not scope_declared:
            await self._request_scope_declaration(inputs)

        if mode == 'passive':
            return await self._run_passive_recon(inputs)
        elif mode == 'active':
            return await self._run_active_recon(inputs)
        elif mode == 'analyze':
            return await self._analyze_scan_output(inputs)

        return {}

    async def _request_scope_declaration(self, inputs: Dict):
        """Request scope from operator."""
        await self.telegram.send_message(
            "📍 **Scope Declaration Required**\n\n"
            "Please provide:\n"
            "1. Engagement type (external/internal/webapp/cloud/wireless)\n"
            "2. Authorized IP ranges/CIDRs\n"
            "3. Authorized domains (support *.wildcard)\n"
            "4. Authorized URLs\n"
            "5. Rate limits / time restrictions\n"
            "6. Are destructive actions authorized? (yes/no)\n\n"
            "Reply with: `/scope declare <json>`"
        )

    async def _run_passive_recon(self, inputs: Dict) -> Dict:
        """Run passive reconnaissance."""
        domains = inputs.get('target_domains', [])
        org_name = inputs.get('target_organization_name', self.config.client)

        results = {
            'subdomains': [],
            'dns_records': {},
            'whois_data': {},
            'certificates': [],
            'technologies': {},
            'osint_findings': []
        }

        for domain in domains:
            if not self.check_scope(domain, "passive recon"):
                continue

            # Run passive tools
            tasks = [
                self._run_subfinder(domain),
                self._run_amass_passive(domain),
                self._run_dnsrecon(domain),
                self._run_theharvester(org_name),
                self._run_cert_transparency(domain),
                self._run_shodan(domain),
            ]

            tool_results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(tool_results):
                if isinstance(result, ToolResult) and result.returncode == 0:
                    await self._process_recon_result(domain, result, results)

        return results

    async def _run_active_recon(self, inputs: Dict) -> Dict:
        """Run active reconnaissance (requires HITL)."""
        targets = inputs.get('targets', [])
        results = {'hosts': [], 'ports': {}, 'services': {}, 'os_fingerprints': {}}

        for target in targets:
            if not self.check_scope(target, "active scan"):
                continue

            # Port scanning
            nmap_result = await self.execute_tool('nmap', [
                '-sS', '-sV', '-sC', '-T4', '--min-rate', '2000',
                '--top-ports', '1000', target
            ], timeout=600)

            if nmap_result.returncode == 0:
                parsed = self._parse_nmap(nmap_result.stdout)
                results['hosts'].append(parsed)

        return results

    async def _analyze_scan_output(self, inputs: Dict) -> Dict:
        """Analyze pasted scan output."""
        scan_output = inputs.get('scan_output', '')
        tool = inputs.get('tool', 'nmap')

        findings = []

        if tool == 'nmap':
            findings = self._parse_nmap_findings(scan_output)
        elif tool == 'masscan':
            findings = self._parse_masscan(scan_output)
        elif tool == 'nessus':
            findings = self._parse_nessus(scan_output)

        return {'findings': findings, 'recommendations': self._generate_recommendations(findings)}

    async def _run_subfinder(self, domain: str) -> ToolResult:
        return await self.execute_tool('subfinder', ['-d', domain, '-silent', '-all'], timeout=300)

    async def _run_amass_passive(self, domain: str) -> ToolResult:
        return await self.execute_tool('amass', ['enum', '-passive', '-d', domain], timeout=600)

    async def _run_dnsrecon(self, domain: str) -> ToolResult:
        return await self.execute_tool('dnsrecon', ['-d', domain, '-t', 'std'], timeout=300)

    async def _run_theharvester(self, org: str) -> ToolResult:
        return await self.execute_tool('theharvester', ['-d', org, '-b', 'all'], timeout=300)

    async def _run_cert_transparency(self, domain: str) -> ToolResult:
        return await self.execute_tool('curl', [
            '-s', f'https://crt.sh/?q=%.{domain}&output=json'
        ], timeout=60)

    async def _run_shodan(self, domain: str) -> ToolResult:
        return await self.execute_tool('shodan', ['domain', domain], timeout=60)

    async def _process_recon_result(self, domain: str, result: ToolResult, results: Dict):
        """Process reconnaissance tool output."""
        tool = result.tool

        if tool == 'subfinder':
            for line in result.stdout.strip().split('\n'):
                if line and self.check_scope(line.strip(), "subdomain enumeration"):
                    results['subdomains'].append(line.strip())

        elif tool == 'amass':
            for line in result.stdout.strip().split('\n'):
                if line and self.check_scope(line.strip(), "subdomain enumeration"):
                    results['subdomains'].append(line.strip())

        elif tool == 'dnsrecon':
            results['dns_records'][domain] = result.stdout

        elif tool == 'theharvester':
            results['osint_findings'].append({
                'tool': 'theharvester',
                'output': result.stdout[:2000]
            })

        elif tool == 'curl':
            try:
                certs = json.loads(result.stdout)
                results['certificates'].extend(certs)
            except:
                pass

    def _parse_nmap(self, output: str) -> Dict:
        """Parse nmap output into structured data."""
        result = {'target': '', 'open_ports': [], 'services': {}, 'os': ''}
        # Simplified parsing
        return result

    def _parse_nmap_findings(self, output: str) -> List:
        """Extract findings from nmap output."""
        findings = []
        # Parse for open ports, services, vulnerabilities
        return findings

    def _parse_masscan(self, output: str) -> List:
        return []

    def _parse_nessus(self, output: str) -> List:
        return []

    def _generate_recommendations(self, findings: List) -> List[str]:
        """Generate next-step recommendations."""
        recs = []
        if any('ssh' in f.get('type', '').lower() for f in findings):
            recs.append("Run SSH credential testing and version audit")
        if any('smb' in f.get('type', '').lower() for f in findings):
            recs.append("Enumerate SMB shares and test for null sessions")
        if any('web' in f.get('type', '').lower() for f in findings):
            recs.append("Run web application scanner (nikto, nuclei, ffuf)")
        return recs