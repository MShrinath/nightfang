"""Recon Active Agent - Active network discovery and port enumeration."""
import asyncio
import logging
import re
from typing import Any, Dict, List
from datetime import datetime
from pathlib import Path

from .base import BaseAgent, ToolResult
from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset
from ..core.telegram_bot import TelegramBot

logger = logging.getLogger(__name__)


class ReconActiveAgent(BaseAgent):
    """Active reconnaissance agent - port scanning, service enumeration, OS fingerprinting."""
    
    def __init__(
        self,
        config: EngagementConfig,
        agent_config: AgentConfig,
        scope_validator: ScopeValidator,
        memory: MemoryManager,
        telegram: TelegramBot
    ):
        super().__init__(
            name="RECON-ACTIVE",
            role="Active Reconnaissance Specialist",
            config=config,
            agent_config=agent_config,
            scope_validator=scope_validator,
            memory=memory,
            telegram=telegram,
            skills=["recon-active", "scope-management", "memory-management", "evidence-collection"],
            tools_required=["nmap", "masscan", "rustscan"],
            hitl_required=True,
            hitl_checkpoints=["before_port_scan", "before_service_enum"],
            max_runtime_minutes=90
        )
    
    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute active reconnaissance against in-scope targets."""
        logger.info(f"[{self.name}] Starting active reconnaissance")
        self.log_event("recon_active", "started", "Active reconnaissance initiated")
        
        # Request approval for active scanning
        if self.hitl_required:
            approval = await self._request_scan_approval(inputs.get("targets", []))
            if approval != "go":
                return {"status": "cancelled", "reason": "Operator denied approval"}
        
        targets = inputs.get("targets", [])
        results = {
            "hosts": [],
            "ports": [],
            "services": [],
            "os_fingerprints": [],
            "assets": []
        }
        
        # Phase 1: Quick port discovery with masscan
        logger.info(f"[{self.name}] Phase 1: Port discovery")
        open_ports = await self._port_discovery(targets)
        results["ports"] = open_ports
        
        # Phase 2: Service enumeration with nmap
        logger.info(f"[{self.name}] Phase 2: Service enumeration")
        services = await self._service_enumeration(open_ports)
        results["services"] = services
        
        # Phase 3: OS fingerprinting
        logger.info(f"[{self.name}] Phase 3: OS fingerprinting")
        os_fps = await self._os_fingerprinting(targets)
        results["os_fingerprints"] = os_fps
        
        # Phase 4: Targeted NSE scripts
        logger.info(f"[{self.name}] Phase 4: NSE enumeration")
        nse_results = await self._nse_enumeration(open_ports)
        
        # Register assets
        for port_info in open_ports:
            asset = Asset(
                identifier=f"{port_info['host']}:{port_info['port']}",
                type="service",
                metadata={
                    "host": port_info["host"],
                    "port": port_info["port"],
                    "protocol": port_info["protocol"],
                    "state": port_info["state"]
                }
            )
            self.add_asset(asset)
        
        self.memory.save_phase_result("recon_active", results)
        self.log_event("recon_active", "completed", f"Scanned {len(targets)} targets, found {len(open_ports)} open ports")
        
        return results
    
    async def _request_scan_approval(self, targets: List[str]) -> str:
        """Request operator approval for active scanning."""
        from ..core.memory import Finding
        
        finding = Finding(
            id=f"RECON-ACTIVE-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            target=", ".join(targets),
            type="RECON_APPROVAL",
            confidence=10,
            severity=1,
            title=f"Request approval for active port scanning of {len(targets)} targets",
            description=f"Targets: {', '.join(targets)}\nScan type: T4 aggressive port scan with service enumeration\nEstimated time: 5-15 minutes",
            proposed_action="nmap -sS -T4 -sV -sC -p- --min-rate 2000",
            risk="Active port scanning will send packets directly to targets",
            mitre_attack="T1046",
            d3fend="D3-NTA"
        )
        
        decision = await self.request_approval(
            finding,
            "Full TCP port scan with service version detection",
            "Network traffic sent to target hosts"
        )
        return decision
    
    async def _port_discovery(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Quick port discovery using masscan/rustscan."""
        open_ports = []
        
        for target in targets:
            if not self.validate_target(target):
                continue
            
            # Use masscan for fast port scan
            result = await self.execute_tool(
                "masscan",
                [target, "-p1-65535", "--rate", "5000", "-oJ", "-"],
                timeout=300
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            for port_info in data.get("ports", []):
                                if port_info["status"] == "open":
                                    open_ports.append({
                                        "host": data["ip"],
                                        "port": port_info["port"],
                                        "protocol": port_info["proto"],
                                        "state": "open",
                                        "source": "masscan"
                                    })
                        except json.JSONDecodeError:
                            pass
            
            # Verify with nmap for accuracy
            if open_ports:
                ports_str = ",".join(str(p["port"]) for p in open_ports if p["host"] == target)
                if ports_str:
                    verify = await self.execute_tool(
                        "nmap",
                        ["-sS", "-T4", "-p", ports_str, target, "-oJ", "-"],
                        timeout=180
                    )
                    if verify.returncode == 0:
                        # Parse nmap JSON output for verification
                        pass
        
        return open_ports
    
    async def _service_enumeration(self, open_ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Service version detection on open ports."""
        services = []
        
        # Group ports by host
        by_host = {}
        for p in open_ports:
            host = p["host"]
            if host not in by_host:
                by_host[host] = []
            by_host[host].append(p["port"])
        
        for host, ports in by_host.items():
            if not self.validate_target(host):
                continue
            
            ports_str = ",".join(str(p) for p in ports)
            result = await self.execute_tool(
                "nmap",
                ["-sV", "-sC", "--version-intensity", "5", "-p", ports_str, host, "-oJ", "-"],
                timeout=300
            )
            
            if result.returncode == 0:
                # Parse nmap JSON output
                # Simplified - in production use proper nmap XML/JSON parser
                pass
        
        return services
    
    async def _os_fingerprinting(self, targets: List[str]) -> List[Dict[str, Any]]:
        """OS fingerprinting using nmap -O."""
        os_results = []
        
        for target in targets:
            if not self.validate_target(target):
                continue
            
            result = await self.execute_tool(
                "nmap",
                ["-O", "--osscan-guess", target, "-oJ", "-"],
                timeout=180
            )
            
            if result.returncode == 0:
                os_results.append({
                    "host": target,
                    "output": result.stdout,
                    "source": "nmap -O"
                })
        
        return os_results
    
    async def _nse_enumeration(self, open_ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Targeted safe NSE script enumeration."""
        results = []
        
        # Safe NSE scripts for enumeration
        safe_scripts = [
            "http-enum",
            "ssl-enum-ciphers", 
            "smb-os-discovery",
            "dns-zone-transfer",
            "ftp-anon",
            "ssh-hostkey"
        ]
        
        by_host = {}
        for p in open_ports:
            host = p["host"]
            if host not in by_host:
                by_host[host] = []
            by_host[host].append(p["port"])
        
        for host, ports in by_host.items():
            if not self.validate_target(host):
                continue
            
            ports_str = ",".join(str(p) for p in ports)
            scripts_str = ",".join(safe_scripts)
            
            result = await self.execute_tool(
                "nmap",
                ["--script", scripts_str, "-p", ports_str, host, "-oJ", "-"],
                timeout=180
            )
            
            if result.returncode == 0:
                results.append({
                    "host": host,
                    "scripts": safe_scripts,
                    "output": result.stdout
                })
        
        return results