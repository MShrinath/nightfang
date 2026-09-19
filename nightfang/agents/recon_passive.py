"""Recon Passive Agent - Passive intelligence gathering without direct target contact."""
import asyncio
import json
import logging
from typing import Any, Dict, List
from datetime import datetime
from pathlib import Path

from .base import BaseAgent, ToolResult
from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset
from ..core.telegram_base import BaseTelegramBot

logger = logging.getLogger(__name__)


class ReconPassiveAgent(BaseAgent):
    """Passive reconnaissance agent - OSINT, DNS, Cert Transparency without direct contact."""
    
    def __init__(
        self,
        name: str = "RECON-PASSIVE",
        role: str = "Passive Reconnaissance Specialist",
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
            skills=["recon-passive", "scope-management", "memory-management", "evidence-collection"],
            tools_required=["subfinder", "amass", "dig", "dnsrecon", "curl", "whatweb", "wafw00f", "crt.sh"],
            hitl_required=False,
            max_runtime_minutes=45
        )
    
    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute passive reconnaissance against all in-scope domains."""
        logger.info(f"[{self.name}] Starting passive reconnaissance")
        self.log_event("recon_passive", "started", "Passive reconnaissance initiated")
        
        domains = inputs.get("domains", [])
        results = {
            "subdomains": [],
            "dns_records": [],
            "certificates": [],
            "technologies": [],
            "waf_detected": [],
            "assets": []
        }
        
        for domain in domains:
            if not self.validate_target(domain):
                continue
            
            logger.info(f"[{self.name}] Processing domain: {domain}")
            
            # Subdomain enumeration
            subs = await self._enumerate_subdomains(domain)
            results["subdomains"].extend(subs)
            
            # DNS records
            dns = await self._get_dns_records(domain)
            results["dns_records"].extend(dns)
            
            # Certificate transparency
            certs = await self._query_cert_transparency(domain)
            results["certificates"].extend(certs)
            
            # Technology fingerprinting
            tech = await self._fingerprint_technology(domain)
            results["technologies"].extend(tech)
            
            # WAF detection
            waf = await self._detect_waf(domain)
            results["waf_detected"].extend(waf)
            
            # Register assets
            for sub in subs:
                asset = Asset(
                    identifier=sub,
                    type="subdomain",
                    metadata={"parent_domain": domain, "source": "passive_recon"}
                )
                self.add_asset(asset)
                results["assets"].append(asset.to_dict())
        
        # Save findings to memory
        self.memory.save_phase_result("recon_passive", results)
        self.log_event("recon_passive", "completed", f"Discovered {len(results['subdomains'])} subdomains across {len(domains)} domains")
        
        return results
    
    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using passive sources."""
        subdomains = set()
        
        # subfinder
        result = await self.execute_tool("subfinder", ["-d", domain, "-silent", "-oJ", "-"])
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        subdomains.add(data.get("host", ""))
                    except json.JSONDecodeError:
                        pass
        
        # amass passive
        result = await self.execute_tool("amass", ["enum", "-passive", "-d", domain, "-o", "-"])
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    subdomains.add(line.strip())
        
        # Filter by scope
        valid = [s for s in subdomains if s and self.validate_target(s)]
        logger.info(f"[{self.name}] Found {len(valid)} valid subdomains for {domain}")
        return list(valid)
    
    async def _get_dns_records(self, domain: str) -> List[Dict[str, Any]]:
        """Query DNS records for a domain."""
        records = []
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]
        
        for rtype in record_types:
            result = await self.execute_tool("dig", [domain, rtype, "+noall", "+answer"])
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        records.append({
                            "domain": domain,
                            "type": rtype,
                            "value": line.strip(),
                            "source": "dig"
                        })
        
        # Also use dnsrecon
        result = await self.execute_tool("dnsrecon", ["-d", domain, "-t", "std", "-j", "-"])
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                for rec in data:
                    records.append({
                        "domain": domain,
                        "type": rec.get("type", ""),
                        "value": rec.get("value", ""),
                        "source": "dnsrecon"
                    })
            except json.JSONDecodeError:
                pass
        
        return records
    
    async def _query_cert_transparency(self, domain: str) -> List[Dict[str, Any]]:
        """Query Certificate Transparency logs via crt.sh."""
        certs = []
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        
        result = await self.execute_tool("curl", ["-s", url, "-H", "Accept: application/json"])
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                for entry in data:
                    certs.append({
                        "domain": domain,
                        "issuer": entry.get("issuer_ca_id", ""),
                        "not_before": entry.get("not_before", ""),
                        "not_after": entry.get("not_after", ""),
                        "serial_number": entry.get("serial_number", ""),
                        "source": "crt.sh"
                    })
            except json.JSONDecodeError:
                pass
        
        return certs
    
    async def _fingerprint_technology(self, domain: str) -> List[Dict[str, Any]]:
        """Identify technology stack."""
        tech = []
        
        # whatweb
        result = await self.execute_tool("whatweb", ["-a", "1", "--log-json=-", domain])
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                for entry in data:
                    for plugin in entry.get("plugins", {}):
                        tech.append({
                            "target": domain,
                            "technology": plugin,
                            "version": entry["plugins"][plugin].get("version", [""])[0],
                            "source": "whatweb"
                        })
            except (json.JSONDecodeError, KeyError):
                pass
        
        return tech
    
    async def _detect_waf(self, domain: str) -> List[Dict[str, Any]]:
        """Detect WAF presence."""
        wafs = []
        
        result = await self.execute_tool("wafw00f", [domain, "-a"])
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if "is behind" in line.lower() or "generic" in line.lower():
                    wafs.append({
                        "target": domain,
                        "waf": line.strip(),
                        "source": "wafw00f"
                    })
        
        return wafs