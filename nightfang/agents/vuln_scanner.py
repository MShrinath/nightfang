"""Vulnerability Scanner Agent - Automated CVE scanning with Nuclei, Nikto, OpenVAS integration."""
import asyncio
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset, TimelineEvent
from ..core.telegram_base import BaseTelegramBot
from .base import BaseAgent, ToolResult

logger = logging.getLogger(__name__)


class VulnerabilityScannerAgent(BaseAgent):
    """Automated vulnerability scanning with CVE correlation."""

    def __init__(
        self,
        name: str = "VULN-SCANNER",
        role: str = "Vulnerability Scanner",
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
            skills=["vulnerability-scanning", "scope-management", "memory-management", "evidence-collection"],
            tools_required=[
                'nuclei', 'nikto', 'searchsploit', 'nmap', 'vulners', 'vulscan'
            ],
            hitl_required=False,
            max_runtime_minutes=180
        )

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute automated vulnerability scanning."""
        self.log_event("vuln_scanning", "Starting vulnerability scanning", "started")

        targets = inputs.get('targets', [])
        web_endpoints = inputs.get('web_endpoints_list', [])
        host_inventory = inputs.get('host_inventory', [])

        # Aggregate all targets
        all_targets = []
        all_targets.extend(targets)
        all_targets.extend(web_endpoints)
        
        for host in host_inventory:
            target = host.get('target') or host.get('ip')
            if target:
                for port in host.get('open_ports', []):
                    proto = 'https' if port in [443, 8443, 9443] else 'http'
                    all_targets.append(f"{proto}://{target}:{port}")

        results = {
            'nuclei_findings': [],
            'nikto_findings': [],
            'cve_correlations': [],
            'exploit_matches': [],
            'misconfigurations': [],
            'exposed_panels': [],
            'outdated_components': []
        }

        for target in all_targets:
            if not target or not self.validate_target(target):
                continue

            logger.info(f"[{self.name}] Scanning: {target}")

            tasks = [
                self._run_nuclei(target),
                self._run_nikto(target),
                self._run_nmap_vuln_scan(target),
                self._check_exposed_panels(target),
            ]

            tool_results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(tool_results):
                if isinstance(result, Exception):
                    continue
                if isinstance(result, ToolResult) and result.returncode == 0:
                    await self._process_vuln_result(target, result, results)

        # CVE correlation across all findings
        results['cve_correlations'] = await self._correlate_cves(results)

        self.log_event("vuln_scanning", f"Vulnerability scanning complete. Found {len(results['nuclei_findings'])} nuclei findings", "completed")
        return results

    async def _run_nuclei(self, target: str) -> ToolResult:
        """Run Nuclei with comprehensive templates."""
        # Check for custom templates
        custom_templates = self.config.rules.technique_config.get('web_app_testing', {}).get('nuclei_tags', '')
        
        args = ['-u', target, '-json', '-silent']
        if custom_templates:
            for tag in custom_templates.split(','):
                args.extend(['-tags', tag.strip()])
        else:
            args.extend(['-tags', 'cve,misconfig,exposures,vuln,tech,fuzz'])

        # Add rate limiting
        args.extend(['-rate-limit', '50', '-concurrency', '25'])

        return await self.execute_tool('nuclei', args, timeout=900)

    async def _run_nikto(self, target: str) -> ToolResult:
        """Run Nikto web server scanner."""
        return await self.execute_tool('nikto', ['-h', target, '-Format', 'json', '-Tuning', 'x'], timeout=300)

    async def _run_nmap_vuln_scan(self, target: str) -> ToolResult:
        """Run Nmap with vulners and vulscan scripts."""
        # Extract hostname from URL
        import urllib.parse
        parsed = urllib.parse.urlparse(target if '://' in target else f'http://{target}')
        hostname = parsed.hostname or target

        return await self.execute_tool('nmap', [
            '--script', 'vulners,vulscan',
            '-sV', '-p-', '--min-rate', '1000',
            hostname
        ], timeout=600)

    async def _check_exposed_panels(self, target: str) -> ToolResult:
        """Check for exposed admin panels and debug endpoints."""
        common_panels = [
            '/admin', '/administrator', '/admin/login', '/wp-admin', '/phpmyadmin',
            '/pma', '/mysql', '/dbadmin', '/sqladmin', '/manager', '/console',
            '/actuator', '/health', '/metrics', '/debug', '/swagger', '/api-docs',
            '/.git', '/.env', '/config', '/backup', '/test', '/dev', '/staging',
            '/grafana', '/kibana', '/prometheus', '/jenkins', '/sonarqube',
            '/jira', '/confluence', '/gitlab', '/harbor', '/rancher', '/portainer'
        ]

        findings = []
        for panel in common_panels:
            test_url = target.rstrip('/') + panel
            result = await self.execute_tool('curl', ['-s', '-o', '/dev/null', '-w', '%{http_code}', '-m', '5', test_url], timeout=10)
            if result.returncode == 0:
                code = result.stdout.strip()
                if code in ['200', '301', '302', '401', '403']:
                    findings.append({
                        'panel': panel,
                        'url': test_url,
                        'status': code,
                        'type': 'exposed_panel'
                    })

        return ToolResult('exposed_panels', f'exposed_panels {target}', json.dumps(findings), '', 0, 0)

    async def _process_vuln_result(self, target: str, result: ToolResult, results: Dict):
        """Process vulnerability scan results."""
        try:
            if result.tool == 'nuclei':
                for line in result.stdout.strip().split('\n'):
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        info = data.get('info', {})
                        severity = info.get('severity', 'info').lower()
                        
                        sev_map = {'critical': 9, 'high': 7, 'medium': 5, 'low': 3, 'info': 1}
                        sev_score = sev_map.get(severity, 1)

                        finding = Finding(
                            id=f"HERMES-VULN-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{len(results['nuclei_findings'])}",
                            title=info.get('name', 'Nuclei Finding'),
                            target=target,
                            type='vulnerability_scan',
                            confidence=7,
                            severity=sev_score,
                            status="confirmed",
                            evidence=json.dumps(data, indent=2),
                            discovered_by=self.name,
                            mitre_attack=info.get('tags', []),
                            cve=info.get('cve', []),
                            cwe=info.get('cwe', '')
                        )
                        self.add_finding(finding)
                        results['nuclei_findings'].append(finding.__dict__)

                        # Check for exploit availability
                        if info.get('cve') or 'exploit' in str(info.get('tags', [])).lower():
                            results['exploit_matches'].append(finding.__dict__)

                    except json.JSONDecodeError:
                        pass

            elif result.tool == 'nikto':
                try:
                    data = json.loads(result.stdout)
                    for vuln in data.get('vulnerabilities', []):
                        finding = Finding(
                            id=f"HERMES-NIKTO-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{len(results['nikto_findings'])}",
                            title=vuln.get('msg', 'Nikto Finding'),
                            target=target,
                            type='web_misconfig',
                            confidence=6,
                            severity=3,
                            status="confirmed",
                            evidence=json.dumps(vuln),
                            discovered_by=self.name
                        )
                        self.add_finding(finding)
                        results['nikto_findings'].append(finding.__dict__)
                except json.JSONDecodeError:
                    pass

            elif result.tool == 'nmap':
                # Parse nmap vuln output for CVEs
                cves = re.findall(r'CVE-\d{4}-\d{4,}', result.stdout)
                for cve in set(cves):
                    results['cve_correlations'].append({
                        'target': target,
                        'cve': cve,
                        'source': 'nmap_vulners'
                    })

            elif result.tool == 'exposed_panels':
                panels = json.loads(result.stdout)
                for panel in panels:
                    finding = Finding(
                        id=f"HERMES-PANEL-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{len(results['exposed_panels'])}",
                        title=f"Exposed Panel: {panel['panel']}",
                        target=target,
                        type='exposed_admin_panel',
                        confidence=8,
                        severity=5 if panel['status'] == '200' else 3,
                        status="confirmed",
                        evidence=f"Status {panel['status']} at {panel['url']}",
                        discovered_by=self.name
                    )
                    self.add_finding(finding)
                    results['exposed_panels'].append(finding.__dict__)

        except Exception as e:
            logger.error(f"[{self.name}] Error processing vuln result: {e}")

    async def _correlate_cves(self, results: Dict) -> List:
        """Correlate CVEs across findings and check exploit availability."""
        correlations = []
        
        # Collect all CVEs from nuclei findings
        all_cves = set()
        for finding in results['nuclei_findings']:
            for cve in finding.get('cve', []):
                all_cves.add(cve)

        # Check searchsploit for each CVE
        for cve in all_cves:
            result = await self.execute_tool('searchsploit', ['--cve', cve], timeout=60)
            if result.returncode == 0 and 'Exploits' in result.stdout:
                correlations.append({
                    'cve': cve,
                    'has_public_exploit': True,
                    'exploit_info': result.stdout[:1000]
                })
            else:
                correlations.append({
                    'cve': cve,
                    'has_public_exploit': False
                })

        return correlations