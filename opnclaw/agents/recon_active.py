"""Active Reconnaissance Agent."""
import asyncio
import json
import logging
import re
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset, TimelineEvent
from ..core.telegram_bot import TelegramBot
from .base import BaseAgent, ToolResult

logger = logging.getLogger(__name__)


class ReconActiveAgent(BaseAgent):
    """Active reconnaissance - port scanning, service enumeration, version detection."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "RECON-ACTIVE"
        self.role = "Active Reconnaissance Specialist"
        self.tools_required = ['nmap', 'masscan', 'rustscan', 'enum4linux', 'snmpwalk', 'nbtscan']
        self.hitl_required = True
        self.hitl_checkpoints = ["Before active scanning begins"]
        self.max_runtime_minutes = 60
    
    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute active reconnaissance."""
        self.log_event("recon", "Starting active reconnaissance", "started")
        
        # Request HITL approval for active scanning
        if self.hitl_required:
            await self._request_scan_approval(inputs)
        
        passive_results = inputs.get('passive_recon_results', {})
        targets = passive_results.get('subdomain_list', [])
        scope = inputs.get('scope_definition', {})
        ips = scope.get('in_scope', {}).get('ips', [])
        
        # Add IPs from scope
        for ip_spec in ips:
            targets.append(ip_spec)
        
        # Also add assets from memory
        assets = self.memory.load_assets()
        for asset in assets:
            if asset.get('host') and asset['host'] not in targets:
                targets.append(asset['host'])
        
        results = {
            'host_inventory': [],
            'port_service_map': {},
            'os_fingerprints': {},
            'nse_script_results': [],
            'entry_point_list': []
        }
        
        for target in targets:
            if not self.validate_target(target):
                continue
            
            logger.info(f"[{self.name}] Active scan on: {target}")
            
            # Run port scans
            scan_results = await self._run_port_scans(target)
            
            if scan_results:
                results['host_inventory'].append({
                    'target': target,
                    'open_ports': scan_results.get('open_ports', []),
                    'services': scan_results.get('services', {}),
                    'os': scan_results.get('os', '')
                })
                
                results['port_service_map'][target] = scan_results.get('services', {})
                if scan_results.get('os'):
                    results['os_fingerprints'][target] = scan_results['os']
                
                # Create/update asset
                asset = Asset(
                    host=target,
                    ip=scan_results.get('ip', ''),
                    ports=list(scan_results.get('services', {}).keys()),
                    services=list(scan_results.get('services', {}).values()),
                    os=scan_results.get('os', ''),
                    status="scanned"
                )
                self.add_asset(asset)
        
        self.log_event("recon", f"Active recon complete. Scanned {len(results['host_inventory'])} hosts", "completed")
        
        return results
    
    async def _request_scan_approval(self, inputs: Dict):
        """Request operator approval for active scanning."""
        target_count = len(inputs.get('passive_recon_results', {}).get('subdomain_list', []))
        target_count += len(inputs.get('scope_definition', {}).get('in_scope', {}).get('ips', []))
        
        finding = Finding(
            id=f"HERMES-ACTIVE-SCAN-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            title="Active Reconnaissance Authorization",
            target=f"{target_count} targets",
            type="active_recon",
            confidence=10,
            severity=3,
            status="suspected",
            evidence=f"Passive recon identified {target_count} targets for active scanning",
            discovered_by=self.name,
            proposed_action=f"Port scanning and service enumeration on {target_count} targets",
            risk="Network traffic generated against targets. May trigger IDS/IPS."
        )
        
        decision = await self.request_approval(finding, finding.proposed_action, finding.risk)
        if decision != 'go':
            raise PermissionError("Operator denied active scanning")
    
    async def _run_port_scans(self, target: str) -> Optional[Dict]:
        """Run port scanning tools."""
        # Try rustscan first (fast), fallback to nmap
        if await self.check_tool('rustscan'):
            result = await self.execute_tool('rustscan', ['-a', target, '--', '-sV', '-sC'], timeout=300)
            if result.returncode == 0:
                return self._parse_rustscan(result.stdout)
        
        # Fallback to nmap
        nmap_timing = self.calibration.get('nmap_timing', 'T4')
        nmap_flags = self.calibration.get('nmap_flags', '-sS -sV -sC --version-intensity 5')
        
        result = await self.execute_tool('nmap', nmap_flags.split() + [target], timeout=1800)
        if result.returncode == 0:
            return self._parse_nmap(result.stdout)
        
        return None
    
    def _parse_nmap(self, output: str) -> Dict:
        """Parse nmap output."""
        result = {'open_ports': [], 'services': {}, 'os': ''}
        
        # Simple parsing for open ports and services
        port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)'
        for match in re.finditer(port_pattern, output):
            port = int(match.group(1))
            proto = match.group(2)
            service = match.group(3)
            version = match.group(4).strip()
            result['open_ports'].append(port)
            result['services'][port] = f"{service} {version}".strip()
        
        # OS detection
        os_match = re.search(r'OS details: (.+)', output)
        if os_match:
            result['os'] = os_match.group(1)
        
        return result
    
    def _parse_rustscan(self, output: str) -> Dict:
        """Parse rustscan output (delegates to nmap parsing)."""
        # rustscan with -- passes args to nmap, so output is nmap format
        return self._parse_nmap(output)