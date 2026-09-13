"""Web Application Scanner Agent."""
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
from ..core.telegram_bot import TelegramBot
from .base import BaseAgent, ToolResult

logger = logging.getLogger(__name__)


class WebAppScannerAgent(BaseAgent):
    """Web application security testing - OWASP Top 10."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "SCANNER-WEBAPP"
        self.role = "Web Application Security Tester"
        self.tools_required = [
            'nikto', 'gobuster', 'ffuf', 'sqlmap', 'nuclei', 
            'dalfox', 'commix', 'katana', 'arjun', 'paramspider', 'wpscan', 'jwt_tool'
        ]
        self.hitl_required = True
        self.hitl_checkpoints = [
            "Before SQLMap exploitation (--os-shell, --dump)",
            "Before command injection exploitation",
            "Before any file upload testing with shells"
        ]
        self.max_runtime_minutes = 120
    
    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute web application scanning."""
        self.log_event("scanning", "Starting web application scanning", "started")
        
        endpoints = inputs.get('web_endpoints_list', [])
        credentials = inputs.get('credentials', [])
        tech_stack = inputs.get('technology_stack', {})
        custom_wordlists = inputs.get('custom_wordlists', {})
        custom_nuclei_templates = inputs.get('custom_nuclei_templates', [])
        
        # Get endpoints from recon if not provided
        if not endpoints:
            assets = self.memory.load_assets()
            for asset in assets:
                for port in asset.get('ports', []):
                    if port in [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000]:
                        proto = 'https' if port in [443, 8443] else 'http'
                        endpoints.append(f"{proto}://{asset['host']}:{port}")
        
        results = {
            'vulnerability_findings': [],
            'injection_test_results': [],
            'access_control_findings': [],
            'session_management_findings': [],
            'evidence_artifacts': []
        }
        
        for endpoint in endpoints:
            if not self.validate_target(endpoint):
                continue
            
            logger.info(f"[{self.name}] Scanning: {endpoint}")
            
            # Run scanning tools
            tasks = [
                self._run_nikto(endpoint),
                self._run_nuclei(endpoint, custom_nuclei_templates),
                self._run_katana(endpoint),
                self._run_ffuf(endpoint, custom_wordlists),
                self._run_arjun(endpoint),
            ]
            
            # Add authenticated tests if credentials provided
            if credentials:
                tasks.append(self._run_authenticated_tests(endpoint, credentials))
            
            tool_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results for findings
            for i, result in enumerate(tool_results):
                if isinstance(result, Exception):
                    continue
                if isinstance(result, ToolResult) and result.returncode == 0:
                    await self._process_scan_result(endpoint, result, results)
        
        self.log_event("scanning", f"Web app scanning complete. Found {len(results['vulnerability_findings'])} vulnerabilities", "completed")
        
        return results
    
    async def _run_nikto(self, endpoint: str) -> ToolResult:
        return await self.execute_tool('nikto', ['-h', endpoint, '-Format', 'json'], timeout=300)
    
    async def _run_nuclei(self, endpoint: str, custom_templates: List[str]) -> ToolResult:
        args = ['-u', endpoint, '-json', '-silent']
        if custom_templates:
            for t in custom_templates:
                args.extend(['-t', t])
        else:
            args.extend(['-tags', 'cve,misconfig,exposures,tech,fuzz'])
        return await self.execute_tool('nuclei', args, timeout=900)
    
    async def _run_katana(self, endpoint: str) -> ToolResult:
        return await self.execute_tool('katana', ['-u', endpoint, '-jc', '-kf', 'all', '-ef', 'woff,woff2,ttf,png,jpg,css,js,map', '-silent'], timeout=600)
    
    async def _run_ffuf(self, endpoint: str, wordlists: Dict) -> ToolResult:
        dir_wordlist = wordlists.get('directories', '/usr/share/wordlists/dirb/common.txt')
        return await self.execute_tool('ffuf', [
            '-u', f'{endpoint}/FUZZ',
            '-w', dir_wordlist,
            '-mc', '200,204,301,302,307,401,403,405,500',
            '-t', str(self.calibration.get('ffuf_threads', 50)),
            '-rate', str(self.calibration.get('ffuf_rate', 100)),
            '-json', '-o', '/tmp/ffuf_out.json'
        ], timeout=600)
    
    async def _run_arjun(self, endpoint: str) -> ToolResult:
        return await self.execute_tool('arjun', ['-u', endpoint, '-o', '/tmp/arjun_out.json'], timeout=300)
    
    async def _run_authenticated_tests(self, endpoint: str, credentials: List[Dict]) -> ToolResult:
        # Placeholder for authenticated scanning
        return ToolResult('auth_tests', '', 'Authenticated tests not implemented', '', 0, 0)
    
    async def _process_scan_result(self, endpoint: str, result: ToolResult, results: Dict):
        """Process tool output and extract findings."""
        tool = result.tool
        output = result.stdout
        
        if tool == 'nuclei':
            await self._parse_nuclei(endpoint, output, results)
        elif tool == 'nikto':
            await self._parse_nikto(endpoint, output, results)
        elif tool == 'ffuf':
            await self._parse_ffuf(endpoint, output, results)
        elif tool == 'katana':
            await self._parse_katana(endpoint, output, results)
    
    async def _parse_nuclei(self, endpoint: str, output: str, results: Dict):
        """Parse nuclei JSON output."""
        for line in output.strip().split('\n'):
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get('info', {})
                severity = info.get('severity', 'info').lower()
                
                sev_map = {'critical': 9, 'high': 7, 'medium': 5, 'low': 3, 'info': 1}
                sev_score = sev_map.get(severity, 1)
                
                finding = Finding(
                    id=f"HERMES-WEB-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{len(results['vulnerability_findings'])}",
                    title=info.get('name', 'Nuclei Finding'),
                    target=endpoint,
                    type=info.get('type', 'webapp'),
                    confidence=7,
                    severity=sev_score,
                    status="confirmed",
                    evidence=json.dumps(data, indent=2),
                    discovered_by=self.name,
                    mitre_attack=info.get('tags', []),
                    cve=info.get('cve', [])
                )
                self.add_finding(finding)
                results['vulnerability_findings'].append(finding.__dict__)
            except json.JSONDecodeError:
                pass
    
    async def _parse_nikto(self, endpoint: str, output: str, results: Dict):
        """Parse nikto output."""
        try:
            data = json.loads(output)
            for vuln in data.get('vulnerabilities', []):
                finding = Finding(
                    id=f"HERMES-NIKTO-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{len(results['vulnerability_findings'])}",
                    title=vuln.get('msg', 'Nikto Finding'),
                    target=endpoint,
                    type='webapp_misconfig',
                    confidence=6,
                    severity=3,
                    status="confirmed",
                    evidence=json.dumps(vuln),
                    discovered_by=self.name
                )
                self.add_finding(finding)
                results['vulnerability_findings'].append(finding.__dict__)
        except json.JSONDecodeError:
            pass
    
    async def _parse_ffuf(self, endpoint: str, output: str, results: Dict):
        """Parse ffuf JSON output."""
        try:
            data = json.loads(output)
            for result in data.get('results', []):
                status = result.get('status', 0)
                if status in [200, 204, 301, 302, 307]:
                    finding = Finding(
                        id=f"HERMES-FFUF-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{len(results['vulnerability_findings'])}",
                        title=f"Discovered path: {result.get('url', '')}",
                        target=endpoint,
                        type='directory_enumeration',
                        confidence=8,
                        severity=2,
                        status="confirmed",
                        evidence=f"Status: {status}, Length: {result.get('length', 0)}",
                        discovered_by=self.name
                    )
                    self.add_finding(finding)
                    results['vulnerability_findings'].append(finding.__dict__)
        except json.JSONDecodeError:
            pass
    
    async def _parse_katana(self, endpoint: str, output: str, results: Dict):
        """Parse katana output for discovered endpoints."""
        urls = output.strip().split('\n')
        for url in urls:
            url = url.strip()
            if url and url not in results.get('entry_point_list', []):
                results.setdefault('entry_point_list', []).append(url)