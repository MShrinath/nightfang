"""Scanner WebApp Agent - Web application penetration testing against OWASP Top 10."""
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


class ScannerWebAppAgent(BaseAgent):
    """Web application security testing agent - OWASP Top 10 testing."""

    def __init__(
        self,
        config: EngagementConfig,
        agent_config: AgentConfig,
        scope_validator: ScopeValidator,
        memory: MemoryManager,
        telegram: TelegramBot
    ):
        super().__init__(
            name="SCANNER-WEBAPP",
            role="Web Application Security Tester",
            config=config,
            agent_config=agent_config,
            scope_validator=scope_validator,
            memory=memory,
            telegram=telegram,
            skills=["webapp-testing", "scope-management", "memory-management", "evidence-collection"],
            tools_required=["ffuf", "nuclei", "dalfox", "sqlmap", "nikto", "katana", "arjun"],
            hitl_required=True,
            hitl_checkpoints=[
                "before_sqli_exploitation",
                "before_cmd_injection_exploitation",
                "before_file_upload_testing"
            ],
            max_runtime_minutes=180
        )

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Starting web application security testing")
        self.log_event("scanner_webapp", "started", "Web application security testing initiated")

        targets = inputs.get("targets", [])
        urls = inputs.get("urls", [])
        credentials = inputs.get("credentials", {})

        results = {
            "findings": [],
            "injection_tests": [],
            "access_control": [],
            "session_management": [],
            "client_side": [],
            "ssrf_tests": []
        }

        for url in urls:
            if not self.validate_target(url):
                continue

            logger.info(f"[{self.name}] Testing web application: {url}")

            endpoints = await self._crawl_application(url)
            directories = await self._enumerate_directories(url)
            params = await self._discover_parameters(url)

            injection_findings = await self._test_injections(url, params, {})
            results["injection_tests"].extend(injection_findings)

            nuclei_findings = await self._run_nuclei(url)
            results["findings"].extend(nuclei_findings)

        self.memory.save_phase_result("scanner_webapp", results)
        self.log_event("scanner_webapp", "completed", f"Tested {len(urls)} web applications")

        return results

    async def _crawl_application(self, url: str) -> List[str]:
        endpoints = []
        result = await self.execute_tool(
            "katana",
            ["-u", url, "-d", "3", "-jc", "-kf", "all", "-ef", "woff,woff2,ttf,png,jpg,css,js,map", "-silent"],
            timeout=600
        )

        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    endpoints.append(line.strip())

        return endpoints

    async def _enumerate_directories(self, url: str) -> List[str]:
        directories = []
        wordlist = self.config.rules.custom_wordlists.get("directories", "/usr/share/wordlists/raft-medium-directories.txt")

        result = await self.execute_tool(
            "ffuf",
            ["-u", f"{url}/FUZZ", "-w", wordlist, "-t", "50", "-rate", "150",
             "-mc", "200,201,204,301,302,307,401,403,405,500", "-of", "json", "-o", "-"],
            timeout=600
        )

        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                for item in data.get("results", []):
                    if item.get("status") in [200, 201, 204, 301, 302, 307, 403]:
                        directories.append({
                            "url": f"{url}/{item['input']['FUZZ']}",
                            "status": item["status"],
                            "length": item.get("length", 0)
                        })
            except json.JSONDecodeError:
                pass

        return directories

    async def _discover_parameters(self, url: str) -> List[Dict[str, Any]]:
        params = []
        result = await self.execute_tool("arjun", ["-u", url, "-m", "GET,POST", "-oJ", "-"], timeout=300)

        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                for param, methods in data.items():
                    params.append({"name": param, "methods": methods})
            except json.JSONDecodeError:
                pass

        return params

    async def _test_injections(self, url: str, params: List[Dict], credentials: Dict) -> List:
        findings = []

        for param in params:
            param_name = param["name"]
            test_url = f"{url}?{param_name}=test"

            if not self.validate_target(test_url):
                continue

            result = await self.execute_tool(
                "sqlmap",
                ["-u", test_url, "--batch", "--technique", "B", "--level", "1", "--risk", "1"],
                timeout=300
            )

            if "SQL injection" in result.stdout or "vulnerable" in result.stdout.lower():
                finding = Finding(
                    id=f"SQLI-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    target=test_url,
                    type="SQL_INJECTION",
                    confidence=8,
                    severity=8,
                    title=f"SQL Injection in parameter '{param_name}'",
                    description=f"Boolean-based SQL injection detected in parameter {param_name}",
                    evidence={"tool": "sqlmap", "stdout": result.stdout[:2000]},
                    mitre_attack="T1190",
                    d3fend="D3-PSA",
                    proposed_action="Exploit to demonstrate database access",
                    risk="Database compromise, data exfiltration"
                )
                findings.append(finding)
                await self.request_approval(finding, "Exploit to enumerate databases", "Database access")

        result = await self.execute_tool(
            "commix",
            ["--url", url, "--batch", "--risk=1", "--level=1"],
            timeout=300
        )

        if "command injection" in result.stdout.lower():
            finding = Finding(
                id=f"CMDI-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                target=url,
                type="COMMAND_INJECTION",
                confidence=8,
                severity=9,
                title="Command Injection",
                description="OS command injection detected",
                evidence={"tool": "commix", "stdout": result.stdout[:2000]},
                mitre_attack="T1059",
                d3fend="D3-PSA",
                proposed_action="Execute benign command (id, whoami)",
                risk="Remote code execution"
            )
            findings.append(finding)
            await self.request_approval(finding, "Execute benign command (id)", "RCE")

        result = await self.execute_tool("dalfox", ["url", url, "--silence"], timeout=300)
        if "vulnerable" in result.stdout.lower() or "xss" in result.stdout.lower():
            finding = Finding(
                id=f"XSS-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                target=url,
                type="XSS",
                confidence=7,
                severity=6,
                title="Cross-Site Scripting (XSS)",
                description="Reflected or stored XSS detected",
                evidence={"tool": "dalfox", "stdout": result.stdout[:2000]},
                mitre_attack="T1059.007",
                d3fend="D3-PSA",
                proposed_action="Confirm with manual PoC",
                risk="Session hijacking, credential theft"
            )
            findings.append(finding)

        return findings

    async def _run_nuclei(self, url: str) -> List:
        findings = []

        tags = "cve,misconfig,exposure,tech,fuzz"
        result = await self.execute_tool(
            "nuclei",
            ["-u", url, "-tags", "cve,misconfig,exposure,tech,fuzz", "-c", "25", "-rl", "150", "-json", "-silent"],
            timeout=900
        )

        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        sev_map = {"critical": 10, "high": 8, "medium": 6, "low": 4, "info": 2}
                        sev = data.get("info", {}).get("severity", "info").lower()
                        finding = Finding(
                            id=f"NUCLEI-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                            target=url,
                            type=data.get("info", {}).get("name", "Nuclei Finding"),
                            confidence=7,
                            severity=sev_map.get(sev, 5),
                            title=data.get("info", {}).get("name", "Nuclei Finding"),
                            description=data.get("info", {}).get("description", ""),
                            evidence={"template": data.get("template", ""), "matched": data.get("matched-at", "")},
                            mitre_attack=data.get("info", {}).get("classification", {}).get("cve", [""])[0] if data.get("info", {}).get("classification", {}).get("cve") else "T1190",
                            d3fend="D3-PSA"
                        )
                        findings.append(finding)
                    except json.JSONDecodeError:
                        pass

        return findings