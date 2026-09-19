"""SSL/TLS Testing Agent - Certificate and TLS configuration analysis."""
import asyncio
import json
import logging
import re
import ssl
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset, TimelineEvent
from ..core.telegram_bot import TelegramBot
from .base import BaseAgent, ToolResult

logger = logging.getLogger(__name__)


class SSLTLSTestingAgent(BaseAgent):
    """SSL/TLS security assessment - cert validity, cipher suites, vulnerabilities."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "SCANNER-SSL"
        self.role = "SSL/TLS Security Tester"
        self.tools_required = [
            'testssl.sh', 'sslscan', 'sslyze', 'nmap', 'openssl'
        ]
        self.hitl_required = False
        self.max_runtime_minutes = 30

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute SSL/TLS testing."""
        self.log_event("ssl_tls_testing", "Starting SSL/TLS security testing", "started")

        host_inventory = inputs.get('host_inventory', [])

        if not host_inventory:
            assets = self.memory.load_assets()
            for asset in assets:
                for port in asset.get('ports', []):
                    if port in [443, 8443, 9443, 465, 993, 995, 587, 25, 110, 143]:
                        host_inventory.append({
                            'target': asset['host'],
                            'port': port,
                            'ip': asset.get('ip', '')
                        })

        results = {
            'certificate_issues': [],
            'protocol_issues': [],
            'cipher_issues': [],
            'vulnerability_findings': [],
            'configuration_issues': [],
            'grade_summary': {}
        }

        for host in host_inventory:
            target = host.get('target')
            port = host.get('port', 443)
            ip = host.get('ip', target)

            if not target or not self.validate_target(target, port):
                continue

            logger.info(f"[{self.name}] Testing TLS on: {target}:{port}")

            tasks = [
                self._run_testssl(target, port),
                self._run_sslscan(target, port),
                self._run_sslyze(target, port),
                self._run_nmap_ssl(target, port),
                self._check_certificate_details(target, port),
            ]

            tool_results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(tool_results):
                if isinstance(result, Exception):
                    continue
                if isinstance(result, ToolResult) and result.returncode == 0:
                    await self._process_ssl_result(f"{target}:{port}", result, results)

            # Calculate grade
            grade = self._calculate_grade(results, target, port)
            results['grade_summary'][f"{target}:{port}"] = grade

        self.log_event("ssl_tls_testing", f"SSL/TLS testing complete. Grades: {results['grade_summary']}", "completed")
        return results

    async def _run_testssl(self, target: str, port: int) -> ToolResult:
        """Run testssl.sh for comprehensive TLS analysis."""
        if not await self.check_tool('testssl.sh'):
            return ToolResult('testssl', f'testssl {target}:{port}', '', 'testssl.sh not found', -1, 0)

        result = await self.execute_tool('testssl.sh', [
            '--jsonfile', '/tmp/testssl_out.json',
            '--quiet',
            f'{target}:{port}'
        ], timeout=300)

        if result.returncode == 0:
            try:
                with open('/tmp/testssl_out.json') as f:
                    data = json.load(f)
                result.stdout = json.dumps(data)
            except Exception:
                pass

        return result

    async def _run_sslscan(self, target: str, port: int) -> ToolResult:
        """Run sslscan for cipher enumeration."""
        return await self.execute_tool('sslscan', [f'{target}:{port}'], timeout=120)

    async def _run_sslyze(self, target: str, port: int) -> ToolResult:
        """Run sslyze for detailed TLS analysis."""
        return await self.execute_tool('sslyze', [f'{target}:{port}'], timeout=180)

    async def _run_nmap_ssl(self, target: str, port: int) -> ToolResult:
        """Run nmap SSL scripts."""
        return await self.execute_tool('nmap', [
            '-p', str(port),
            '--script', 'ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params,sslv2,ssl-date',
            target
        ], timeout=180)

    async def _check_certificate_details(self, target: str, port: int) -> ToolResult:
        """Check certificate details using openssl."""
        cmd = f'echo | openssl s_client -connect {target}:{port} -servername {target} 2>/dev/null | openssl x509 -noout -text'
        return await self.execute_tool('bash', ['-c', cmd], timeout=60)

    async def _process_ssl_result(self, target_port: str, result: ToolResult, results: Dict):
        """Process SSL/TLS test results and create findings."""
        target, port = target_port.rsplit(':', 1)
        port = int(port)

        try:
            # Parse testssl.sh JSON
            if result.tool == 'testssl.sh' and result.stdout:
                data = json.loads(result.stdout)
                for item in data:
                    if isinstance(item, dict):
                        finding = self._parse_testssl_finding(target, port, item)
                        if finding:
                            results['vulnerability_findings'].append(finding)
                            self.add_finding(finding)

            # Parse sslscan output
            elif result.tool == 'sslscan':
                findings = self._parse_sslscan(target, port, result.stdout)
                for finding in findings:
                    results['cipher_issues'].append(finding)
                    self.add_finding(finding)

            # Parse nmap SSL output
            elif result.tool == 'nmap':
                findings = self._parse_nmap_ssl(target, port, result.stdout)
                for finding in findings:
                    results['vulnerability_findings'].append(finding)
                    self.add_finding(finding)

            # Parse certificate details
            elif result.tool == 'bash' and 'openssl' in result.command:
                finding = self._parse_certificate(target, port, result.stdout)
                if finding:
                    results['certificate_issues'].append(finding)
                    self.add_finding(finding)

        except Exception as e:
            logger.error(f"[{self.name}] Error parsing SSL result: {e}")

    def _parse_testssl_finding(self, target: str, port: int, item: Dict) -> Optional[Finding]:
        """Parse testssl.sh finding into Finding object."""
        finding_id = item.get('id', '')
        finding_title = item.get('finding', '')
        severity = item.get('severity', 'UNKNOWN').lower()

        sev_map = {'critical': 9, 'high': 7, 'medium': 5, 'low': 3, 'info': 1, 'ok': 0, 'unknown': 0}
        sev_score = sev_map.get(severity, 0)

        if sev_score == 0:
            return None

        mitre_map = {
            'heartbleed': ['T1040'],
            'poodle': ['T1557'],
            'beast': ['T1557'],
            'crime': ['T1557'],
            'breach': ['T1557'],
            'robot': ['T1557'],
            'drown': ['T1557'],
            'freak': ['T1557'],
            'logjam': ['T1557'],
            'sweet32': ['T1557'],
            'lucky13': ['T1557'],
            'rc4': ['T1557'],
            'des': ['T1557'],
            'null': ['T1557'],
            'export': ['T1557'],
            'sslv2': ['T1557'],
            'sslv3': ['T1557'],
            'tls10': ['T1557'],
            'tls11': ['T1557'],
            'weak_cipher': ['T1557'],
            'forward_secrecy': ['T1557'],
            'cert_expired': ['T1557'],
            'cert_selfsigned': ['T1557'],
            'cert_weak_key': ['T1557'],
            'cert_sha1': ['T1557'],
            'cert_md5': ['T1557'],
            'hsts': ['T1557'],
            'ocsp': ['T1557'],
        }

        mitre = mitre_map.get(finding_id, ['T1557'])
        d3fend = ['D3-CTA', 'D3-CH'] if 'cert' in finding_id else ['D3-PSA', 'D3-CH']

        return Finding(
            id=f"HERMES-SSL-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{finding_id}",
            title=f"SSL/TLS: {finding_title}",
            target=f"{target}:{port}",
            type=f"ssl_{finding_id}",
            confidence=8 if severity in ['critical', 'high'] else 7,
            severity=sev_score,
            status="confirmed",
            evidence=json.dumps(item, indent=2),
            discovered_by=self.name,
            mitre_attack=mitre,
            d3fend=d3fend
        )

    def _parse_sslscan(self, target: str, port: int, output: str) -> List[Finding]:
        """Parse sslscan output for weak ciphers."""
        findings = []
        lines = output.split('\n')

        for line in lines:
            line = line.strip()
            if any(weak in line.lower() for weak in ['rc4', 'des ', '3des', 'null', 'export', 'anonymous', 'md5', 'sha1']) and 'accepted' in line.lower():
                finding = Finding(
                    id=f"HERMES-SSL-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-cipher",
                    title=f"Weak Cipher Accepted: {line.split()[0] if line.split() else 'Unknown'}",
                    target=f"{target}:{port}",
                    type="ssl_weak_cipher",
                    confidence=9,
                    severity=6,
                    status="confirmed",
                    evidence=line,
                    discovered_by=self.name,
                    mitre_attack=['T1557'],
                    d3fend=['D3-CH', 'D3-PSA']
                )
                findings.append(finding)

        return findings

    def _parse_nmap_ssl(self, target: str, port: int, output: str) -> List[Finding]:
        """Parse nmap SSL script output."""
        findings = []

        # Heartbleed
        if 'heartbleed' in output.lower() and 'VULNERABLE' in output.upper():
            findings.append(Finding(
                id=f"HERMES-SSL-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-heartbleed",
                title="OpenSSL Heartbleed Vulnerability (CVE-2014-0160)",
                target=f"{target}:{port}",
                type="ssl_heartbleed",
                confidence=10,
                severity=9,
                status="confirmed",
                evidence=output[:1000],
                discovered_by=self.name,
                mitre_attack=['T1040'],
                d3fend=['D3-CTA', 'D3-PSA']
            ))

        # POODLE
        if 'poodle' in output.lower() and 'VULNERABLE' in output.upper():
            findings.append(Finding(
                id=f"HERMES-SSL-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-poodle",
                title="POODLE Vulnerability (CVE-2014-3566)",
                target=f"{target}:{port}",
                type="ssl_poodle",
                confidence=10,
                severity=7,
                status="confirmed",
                evidence=output[:1000],
                discovered_by=self.name,
                mitre_attack=['T1557'],
                d3fend=['D3-CH', 'D3-PSA']
            ))

        # SSLv2/SSLv3/TLS1.0/TLS1.1
        for proto in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
            if proto in output and 'supported' in output.lower():
                sev_map = {'SSLv2': 9, 'SSLv3': 8, 'TLSv1.0': 5, 'TLSv1.1': 4}
                findings.append(Finding(
                    id=f"HERMES-SSL-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{proto.lower().replace('.', '')}",
                    title=f"Deprecated Protocol Supported: {proto}",
                    target=f"{target}:{port}",
                    type="ssl_deprecated_protocol",
                    confidence=9,
                    severity=sev_map.get(proto, 5),
                    status="confirmed",
                    evidence=f"{proto} is supported",
                    discovered_by=self.name,
                    mitre_attack=['T1557'],
                    d3fend=['D3-CH']
                ))

        # Certificate issues
        if 'self-signed' in output.lower():
            findings.append(Finding(
                id=f"HERMES-SSL-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-selfsigned",
                title="Self-Signed Certificate",
                target=f"{target}:{port}",
                type="ssl_self_signed",
                confidence=10,
                severity=5,
                status="confirmed",
                evidence="Certificate is self-signed",
                discovered_by=self.name,
                mitre_attack=['T1557'],
                d3fend=['D3-CTA']
            ))

        return findings

    def _parse_certificate(self, target: str, port: int, output: str) -> Optional[Finding]:
        """Parse certificate details."""
        findings = []

        # Check expiration
        if 'Not After' in output:
            # Would need to parse date and check
            pass

        # Check key size
        if 'RSA' in output and '2048' not in output and '4096' not in output and '3072' not in output:
            if '1024' in output or '512' in output:
                return Finding(
                    id=f"HERMES-SSL-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-weak_key",
                    title="Weak Certificate Key Size (< 2048 bits)",
                    target=f"{target}:{port}",
                    type="ssl_weak_key",
                    confidence=9,
                    severity=7,
                    status="confirmed",
                    evidence=output[:1000],
                    discovered_by=self.name,
                    mitre_attack=['T1557'],
                    d3fend=['D3-CTA', 'D3-CH']
                )

        # Check signature algorithm
        if 'sha1' in output.lower() or 'md5' in output.lower():
            return Finding(
                id=f"HERMES-SSL-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-weak_sig",
                title="Weak Certificate Signature Algorithm (SHA1/MD5)",
                target=f"{target}:{port}",
                type="ssl_weak_signature",
                confidence=9,
                severity=6,
                status="confirmed",
                evidence=output[:1000],
                discovered_by=self.name,
                mitre_attack=['T1557'],
                d3fend=['D3-CTA', 'D3-CH']
            )

        return None

    def _calculate_grade(self, results: Dict, target: str, port: int) -> str:
        """Calculate TLS grade based on findings."""
        key = f"{target}:{port}"
        all_findings = results['certificate_issues'] + results['protocol_issues'] + \
                      results['cipher_issues'] + results['vulnerability_findings'] + \
                      results['configuration_issues']

        relevant = [f for f in all_findings if f.get('target') == key]

        if not relevant:
            return 'A+'

        max_sev = max(f.get('severity', 0) for f in relevant)
        crit_count = sum(1 for f in relevant if f.get('severity', 0) >= 9)
        high_count = sum(1 for f in relevant if 7 <= f.get('severity', 0) < 9)

        if crit_count > 0:
            return 'F'
        elif high_count > 0:
            return 'D'
        elif max_sev >= 5:
            return 'C'
        elif max_sev >= 3:
            return 'B'
        else:
            return 'A'