"""Passive Reconnaissance Agent."""
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


class ReconPassiveAgent(BaseAgent):
    """Passive reconnaissance - OSINT, DNS enumeration, subdomain discovery, certificate transparency."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "RECON-PASSIVE"
        self.role = "Passive Reconnaissance Specialist"
        self.tools_required = [
            'whois', 'dig', 'nslookup', 'subfinder', 'amass', 
            'theharvester', 'shodan', 'whatweb', 'wafw00f', 'dnsrecon'
        ]
        self.hitl_required = False
        self.max_runtime_minutes = 30
    
    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute passive reconnaissance."""
        self.log_event("recon", "Starting passive reconnaissance", "started")
        
        scope = inputs.get('scope_definition', {})
        domains = inputs.get('target_domains', [])
        org_name = inputs.get('target_organization_name', '')
        
        if not domains and scope.get('in_scope', {}).get('domains'):
            domains = scope['in_scope']['domains']
        
        results = {
            'subdomain_list': [],
            'dns_records': {},
            'technology_stack': {},
            'whois_data': {},
            'certificate_inventory': [],
            'attack_surface_map': {}
        }
        
        for domain in domains:
            if not self.validate_target(domain):
                logger.warning(f"[{self.name}] Skipping out-of-scope domain: {domain}")
                continue
            
            logger.info(f"[{self.name}] Recon on: {domain}")
            
            # Run tools in parallel where possible
            tasks = [
                self._run_subfinder(domain),
                self._run_amass(domain),
                self._run_dnsrecon(domain),
                self._run_whatweb(domain),
                self._run_wafw00f(domain),
                self._run_whois(domain),
                self._run_cert_transparency(domain),
            ]
            
            if org_name:
                tasks.append(self._run_theharvester(org_name))
            
            tool_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            subdomains = set()
            for i, result in enumerate(tool_results):
                if isinstance(result, Exception):
                    logger.error(f"[{self.name}] Tool {self.tools_required[i] if i < len(self.tools_required) else 'unknown'} failed: {result}")
                    continue
                if isinstance(result, ToolResult) and result.returncode == 0:
                    subdomains.update(self._extract_subdomains(result.stdout, domain))
            
            # Deduplicate and validate subdomains
            valid_subdomains = []
            for sub in subdomains:
                if self.validate_target(sub):
                    valid_subdomains.append(sub)
            
            results['subdomain_list'].extend(valid_subdomains)
            
            # Store as assets
            for sub in valid_subdomains:
                asset = Asset(host=sub, status="discovered")
                self.add_asset(asset)
        
        # Deduplicate
        results['subdomain_list'] = list(set(results['subdomain_list']))
        
        self.log_event("recon", f"Passive recon complete. Found {len(results['subdomain_list'])} subdomains", "completed", 
                      finding_ids=[f"subdomain_{i}" for i in range(len(results['subdomain_list']))])
        
        return results
    
    async def _run_subfinder(self, domain: str) -> ToolResult:
        return await self.execute_tool('subfinder', ['-d', domain, '-silent', '-all'], timeout=300)
    
    async def _run_amass(self, domain: str) -> ToolResult:
        return await self.execute_tool('amass', ['enum', '-passive', '-d', domain], timeout=600)
    
    async def _run_dnsrecon(self, domain: str) -> ToolResult:
        return await self.execute_tool('dnsrecon', ['-d', domain, '-t', 'std'], timeout=300)
    
    async def _run_whatweb(self, domain: str) -> ToolResult:
        return await self.execute_tool('whatweb', ['--no-errors', '-q', f'https://{domain}'], timeout=120)
    
    async def _run_wafw00f(self, domain: str) -> ToolResult:
        return await self.execute_tool('wafw00f', [f'https://{domain}'], timeout=120)
    
    async def _run_whois(self, domain: str) -> ToolResult:
        return await self.execute_tool('whois', [domain], timeout=60)
    
    async def _run_cert_transparency(self, domain: str) -> ToolResult:
        # Use crt.sh via curl
        return await self.execute_tool('curl', [
            '-s', f'https://crt.sh/?q=%.{domain}&output=json'
        ], timeout=60)
    
    async def _run_theharvester(self, org_name: str) -> ToolResult:
        return await self.execute_tool('theharvester', [
            '-d', org_name, '-b', 'all', '-f', '/tmp/theharvester_out'
        ], timeout=300)
    
    def _extract_subdomains(self, output: str, base_domain: str) -> List[str]:
        """Extract subdomains from tool output."""
        subdomains = set()
        # Match subdomains of the base domain
        pattern = rf'([a-zA-Z0-9.-]+\.{re.escape(base_domain)})'
        matches = re.findall(pattern, output)
        for match in matches:
            # Clean up
            match = match.strip().lower().rstrip('.')
            if match != base_domain and not match.startswith('*.'):
                subdomains.add(match)
        return list(subdomains)