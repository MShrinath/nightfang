"""Scanner Network Agent - Network infrastructure and service vulnerability testing."""
import asyncio
import logging
import json
from typing import Any, Dict, List
from datetime import datetime
from pathlib import Path

from .base import BaseAgent, ToolResult
from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding
from ..core.telegram_bot import TelegramBot

logger = logging.getLogger(__name__)


class ScannerNetworkAgent(BaseAgent):
    """Network infrastructure and service vulnerability testing agent."""

    def __init__(
        self,
        config: EngagementConfig,
        agent_config: AgentConfig,
        scope_validator: ScopeValidator,
        memory: MemoryManager,
        telegram: TelegramBot
    ):
        super().__init__(
            name="SCANNER-NETWORK",
            role="Network Security Tester",
            config=config,
            agent_config=agent_config,
            scope_validator=scope_validator,
            memory=memory,
            telegram=telegram,
            skills=["network-testing", "scope-management", "memory-management", "evidence-collection"],
            tools_required=["nmap", "crackmapexec", "enum4linux", "hydra", "nmap"],
            hitl_required=True,
            hitl_checkpoints=["before_brute_force", "before_exploit"],
            max_runtime_minutes=120
        )

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Starting network security testing")
        self.log_event("scanner_network", "started", "Network security testing initiated")

        targets = inputs.get("targets", [])
        credentials = inputs.get("credentials", {})

        results = {
            "smb": [],
            "ssh": [],
            "rdp": [],
            "databases": [],
            "active_directory": [],
            "vulnerabilities": []
        }

        for target in targets:
            if not self.validate_target(target):
                continue

            logger.info(f"[{self.name}] Testing network target: {target}")

            # 1. SMB/Samba testing
            smb = await self._test_smb(target, credentials)
            results["smb"].extend(smb)

            # 2. SSH testing
            ssh = await self._test_ssh(target, credentials)
            results["ssh"].extend(ssh)

            # 3. RDP testing
            rdp = await self._test_rdp(target)
            results["rdp"].extend(rdp)

            # 3. Database ports
            db = await self._test_databases(target)
            results["databases"].extend(db)

            # 4. Active Directory (if applicable)
            ad = await self._test_active_directory(target, credentials)
            results["active_directory"].extend(ad)

            # 5. Vulnerability scanning with nmap
            vulns = await self._nmap_vuln_scan(target)
            results["vulnerabilities"].extend(vulns)

        self.memory.save_phase_result("scanner_network", results)
        self.log_event("scanner_network", "completed", f"Tested {len(targets)} network targets")

        return results

    async def _test_smb(self, target: str, credentials: Dict) -> List:
        findings = []

        # Null session / anonymous access
        result = await self.execute_tool(
            "crackmapexec",
            ["smb", target, "-u", "''", "-p", "''", "--shares"],
            timeout=60
        )

        if "READ" in result.stdout or "WRITE" in result.stdout:
            finding = Finding(
                id=f"SMB-ANON-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                target=target,
                type="SMB_ANONYMOUS_ACCESS",
                confidence=10,
                severity=7,
                title="SMB Anonymous Share Access",
                description="SMB shares accessible without authentication",
                evidence={"tool": "crackmapexec", "stdout": result.stdout[:2000]},
                mitre_attack="T1021.002",
                d3fend="D3-NA",
                proposed_action="Restrict anonymous access",
                risk="Information disclosure, lateral movement"
            )
            return [finding]

        return []

    async def _test_ssh(self, target: str, credentials: Dict) -> List:
        findings = []

        # Check SSH version and algorithms
        result = await self.execute_tool(
            "nmap",
            ["-sV", "-p", "22", "--script", "ssh2-enum-algos,ssh-hostkey", target, "-oJ", "-"],
            timeout=60
        )

        return []

    async def _test_rdp(self, target: str) -> List:
        findings = []

        # Check RDP version and security
        result = await self.execute_tool(
            "nmap",
            ["-sV", "-p", "3389", "--script", "rdp-enum-encryption,rdp-vuln-ms12-020", target, "-oJ", "-"],
            timeout=60
        )

        return []

    async def _test_databases(self, target: str) -> List:
        findings = []

        db_ports = [3306, 5432, 1433, 27017, 6379, 9200]

        for port in db_ports:
            result = await self.execute_tool(
                "nmap",
                ["-sV", "-p", str(port), "--script", "vuln", target, "-oJ", "-"],
                timeout=60
            )

        return []

    async def _test_active_directory(self, target: str, credentials: Dict) -> List:
        findings = []

        # enum4linux for AD enumeration
        result = await self.execute_tool(
            "enum4linux",
            ["-a", target],
            timeout=120
        )

        if "Kerberos" in result.stdout or "LDAP" in result.stdout:
            finding = Finding(
                id=f"AD-ENUM-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                target=target,
                type="ACTIVE_DIRECTORY_EXPOSED",
                confidence=8,
                severity=6,
                title="Active Directory Services Exposed",
                description="AD services (LDAP, Kerberos, RPC) accessible",
                evidence={"tool": "enum4linux", "stdout": result.stdout[:2000]},
                mitre_attack="T1069.002",
                d3fend="D3-NA",
                proposed_action="Restrict AD services to management network",
                risk="Credential theft, privilege escalation"
            )
            return [finding]

        return []

    async def _nmap_vuln_scan(self, target: str) -> List:
        findings = []

        result = await self.execute_tool(
            "nmap",
            ["--script", "vuln", "-sV", target, "-oJ", "-"],
            timeout=300
        )

        return findings