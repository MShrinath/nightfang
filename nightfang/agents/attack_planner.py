"""Attack Planner Agent - Builds optimal attack chains from findings."""
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset, TimelineEvent
from ..core.telegram_base import BaseTelegramBot
from .base import BaseAgent, ToolResult, AgentTier

logger = logging.getLogger(__name__)


class AttackPlannerAgent(BaseAgent):
    """Attack chain strategist - correlates findings into optimal exploitation paths."""

    def __init__(
        self,
        config: EngagementConfig,
        agent_config: AgentConfig,
        scope_validator: ScopeValidator,
        memory: MemoryManager,
        telegram: BaseTelegramBot
    ):
        super().__init__(
            name="ATTACK-PLANNER",
            role="Attack Chain Strategist",
            config=config,
            agent_config=agent_config,
            scope_validator=scope_validator,
            memory=memory,
            telegram=telegram,
            skills=["attack-chain-analysis", "threat-modeling", "risk-prioritization"],
            tools_required=[],
            hitl_required=True,
            hitl_checkpoints=[
                "Before presenting attack chains for exploitation",
                "Before recommending destructive exploitation paths"
            ],
            max_runtime_minutes=180,
            tier=AgentTier.TIER_1_ADVISORY,
            trigger_phrases=["attack chain", "exploitation path", "prioritize targets", "build attack narrative", "correlate findings"],
            model="sonnet",
            description="Correlates findings from multiple tools/agents to build multi-step attack chains, identifies optimal exploitation paths through target environments, and prioritizes attack vectors across an engagement."
        )

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Build attack chains from all available findings."""
        self.log_event("attack_planner", "Starting attack chain construction", "started")

        all_findings = self.memory.load_findings()
        chains = await self._build_attack_chains(all_findings)
        prioritized = self._prioritize_chains(chains)
        diagrams = self._generate_chain_diagrams(chains)

        # Request approval for each chain
        approved_chains = []
        for chain in chains:
            if await self._request_chain_approval(chain):
                approved_chains.append(chain)

        results = {
            "attack_chains": chains,
            "prioritized_chains": prioritized,
            "approved_chains": approved_chains,
            "mermaid_diagrams": diagrams,
            "exploitation_roadmap": self._generate_exploitation_roadmap(approved_chains)
        }

        self.memory.save_chains(chains)
        self.log_event("attack_planner", f"Built {len(chains)} attack chains", "completed")
        return results

    async def _build_attack_chains(self, findings: List) -> List:
        """Build attack chains using known templates and dynamic correlation."""
        chains = []

        # Template 1: BOLA -> JWT -> Admin
        chains.extend(self._template_bola_jwt_admin(findings))

        # Template 2: Subdomain -> SSRF -> Cloud Metadata
        chains.extend(self._template_subdomain_ssrf_metadata(findings))

        # Template 3: Credential Spray -> Valid Creds -> Lateral Movement
        chains.extend(self._template_credential_reuse(findings))

        # Template 4: Info Disclosure -> SSRF -> RCE
        chains.extend(self._template_info_ssrf_rce(findings))

        # Template 5: XSS -> Session Hijack -> Account Takeover
        chains.extend(self._template_xss_hijack(findings))

        # Template 6: Misconfig -> Container Escape -> Cloud Access
        chains.extend(self._template_container_cloud(findings))

        # Template 7: Deserialization -> RCE -> Persistence
        chains.extend(self._template_deserial_persistence(findings))

        # Template 8: Weak Crypto -> MITM -> Credential Theft
        chains.extend(self._template_crypto_mitm(findings))

        # Dynamic correlation for novel chains
        chains.extend(await self._dynamic_correlation(findings))

        return chains

    def _template_bola_jwt_admin(self, findings: List) -> List:
        """BOLA/IDOR -> Weak JWT -> Admin Panel."""
        bola = [f for f in findings if any(t in f.get('type', '').upper() for t in ['BOLA', 'IDOR', 'OBJECT_LEVEL_AUTH'])]
        jwt = [f for f in findings if 'JWT' in f.get('type', '').upper()]
        admin = [f for f in findings if any(t in f.get('type', '').upper() for t in ['ADMIN', 'PRIVILEGE_ESCALATION', 'AUTHORIZATION_BYPASS'])]

        if bola and jwt:
            return [{
                'id': f"CHAIN-BOLA-JWT-ADMIN-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                'name': 'BOLA → Weak JWT → Admin Panel',
                'priority': 'P0',
                'score': 8.4,
                'steps': [
                    {'finding': bola[0].get('id'), 'role': 'initial_access', 'technique': 'T1190', 'description': 'BOLA/IDOR on user object'},
                    {'finding': jwt[0].get('id'), 'role': 'privilege_escalation', 'technique': 'T1552.004', 'description': 'Weak JWT secret/algorithm confusion'},
                    {'finding': admin[0].get('id') if admin else 'N/A', 'role': 'objective', 'technique': 'T1078', 'description': 'Admin panel access'}
                ],
                'mitre_path': ['T1190', 'T1552.004', 'T1078'],
                'd3fend_counters': ['D3-PSA', 'D3-KDU', 'D3-AA'],
                'business_impact': 'Full administrative access to application'
            }]
        return []

    def _template_subdomain_ssrf_metadata(self, findings: List) -> List:
        """Subdomain Takeover -> SSRF -> Cloud Metadata."""
        subdomain = [f for f in findings if 'SUBDOMAIN' in f.get('type', '').upper() or 'TAKEOVER' in f.get('type', '').upper()]
        ssrf = [f for f in findings if 'SSRF' in f.get('type', '').upper()]

        if subdomain and ssrf:
            return [{
                'id': f"CHAIN-SUBDOMAIN-SSRF-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                'name': 'Subdomain Takeover → SSRF → Cloud Metadata',
                'priority': 'P0',
                'score': 8.2,
                'steps': [
                    {'finding': subdomain[0].get('id'), 'role': 'initial_access', 'technique': 'T1590.005', 'description': 'Dangling subdomain takeover'},
                    {'finding': ssrf[0].get('id'), 'role': 'pivot', 'technique': 'T1190', 'description': 'SSRF to internal metadata'},
                    {'finding': 'METADATA', 'role': 'objective', 'technique': 'T1552.005', 'description': 'Cloud credential extraction'}
                ],
                'mitre_path': ['T1590.005', 'T1190', 'T1552.005'],
                'd3fend_counters': ['D3-DNST', 'D3-SFI', 'D3-CSM'],
                'business_impact': 'Full cloud account compromise'
            }]
        return []

    def _template_credential_reuse(self, findings: List) -> List:
        """Credential Spray -> Valid Creds -> Lateral Movement."""
        spray = [f for f in findings if 'SPRAY' in f.get('type', '').upper() or 'BRUTE' in f.get('type', '').upper()]
        valid = [f for f in findings if 'VALID_CRED' in f.get('type', '').upper() or 'CREDENTIAL_REUSE' in f.get('type', '').upper()]
        lateral = [f for f in findings if any(t in f.get('type', '').upper() for t in ['SSH', 'RDP', 'WINRM', 'SMB', 'LATERAL'])]

        if spray and valid and lateral:
            return [{
                'id': f"CHAIN-CRED-REUSE-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                'name': 'Credential Spray → Valid Creds → Lateral Movement',
                'priority': 'P1',
                'score': 7.5,
                'steps': [
                    {'finding': spray[0].get('id'), 'role': 'credential_access', 'technique': 'T1110.003', 'description': 'Password spray attack'},
                    {'finding': valid[0].get('id'), 'role': 'initial_access', 'technique': 'T1078', 'description': 'Valid credential reuse'},
                    {'finding': lateral[0].get('id'), 'role': 'lateral_movement', 'technique': 'T1021.004', 'description': 'Lateral movement via SSH/RDP/WinRM'}
                ],
                'mitre_path': ['T1110.003', 'T1078', 'T1021.004'],
                'd3fend_counters': ['D3-BA', 'D3-ARA', 'D3-NA'],
                'business_impact': 'Network-wide lateral movement'
            }]
        return []

    def _template_info_ssrf_rce(self, findings: List) -> List:
        """Info Disclosure -> SSRF -> RCE."""
        info = [f for f in findings if 'INFO_DISC' in f.get('type', '').upper() or 'DISCLOSURE' in f.get('type', '').upper()]
        ssrf = [f for f in findings if 'SSRF' in f.get('type', '').upper()]
        rce = [f for f in findings if any(t in f.get('type', '').upper() for t in ['RCE', 'COMMAND_INJECTION', 'DESERIALIZATION'])]

        if info and ssrf and rce:
            return [{
                'id': f"CHAIN-INFO-SSRF-RCE-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                'name': 'Info Disclosure → SSRF → RCE',
                'priority': 'P0',
                'score': 8.5,
                'steps': [
                    {'finding': info[0].get('id'), 'role': 'reconnaissance', 'technique': 'T1592', 'description': 'Internal endpoint disclosure'},
                    {'finding': ssrf[0].get('id'), 'role': 'pivot', 'technique': 'T1190', 'description': 'SSRF to internal service'},
                    {'finding': rce[0].get('id'), 'role': 'execution', 'technique': 'T1059', 'description': 'Remote code execution'}
                ],
                'mitre_path': ['T1592', 'T1190', 'T1059'],
                'd3fend_counters': ['D3-PSA', 'D3-SFI', 'D3-EAA'],
                'business_impact': 'Full system compromise via internal service'
            }]
        return []

    def _template_xss_hijack(self, findings: List) -> List:
        """XSS -> Session Hijack -> Account Takeover."""
        xss = [f for f in findings if 'XSS' in f.get('type', '').upper() or 'CROSS_SITE' in f.get('type', '').upper()]
        session = [f for f in findings if 'SESSION' in f.get('type', '').upper() or 'HIJACK' in f.get('type', '').upper()]

        if xss:
            return [{
                'id': f"CHAIN-XSS-HIJACK-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                'name': 'XSS → Session Hijack → Account Takeover',
                'priority': 'P1',
                'score': 7.0,
                'steps': [
                    {'finding': xss[0].get('id'), 'role': 'initial_access', 'technique': 'T1190', 'description': 'Stored/Reflected XSS payload'},
                    {'finding': session[0].get('id') if session else 'N/A', 'role': 'credential_access', 'technique': 'T1552.004', 'description': 'Session token theft'},
                    {'finding': 'ACCOUNT', 'role': 'objective', 'technique': 'T1078', 'description': 'Victim account takeover'}
                ],
                'mitre_path': ['T1190', 'T1552.004', 'T1078'],
                'd3fend_counters': ['D3-WAF', 'D3-PSA', 'D3-ARA'],
                'business_impact': 'User/admin account compromise'
            }]
        return []

    def _template_container_cloud(self, findings: List) -> List:
        """Misconfig -> Container Escape -> Cloud Access."""
        container = [f for f in findings if 'CONTAINER' in f.get('type', '').upper() or 'ESCAPE' in f.get('type', '').upper()]
        cloud = [f for f in findings if 'CLOUD' in f.get('type', '').upper() or 'IAM' in f.get('type', '').upper()]

        if container and cloud:
            return [{
                'id': f"CHAIN-CONTAINER-CLOUD-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                'name': 'Container Misconfig → Escape → Cloud Access',
                'priority': 'P0',
                'score': 8.0,
                'steps': [
                    {'finding': container[0].get('id'), 'role': 'initial_access', 'technique': 'T1610', 'description': 'Container escape via misconfiguration'},
                    {'finding': cloud[0].get('id'), 'role': 'credential_access', 'technique': 'T1552.005', 'description': 'Cloud metadata/credential access'},
                    {'finding': 'CLOUD_ACCOUNT', 'role': 'objective', 'technique': 'T1078.004', 'description': 'Cloud account compromise'}
                ],
                'mitre_path': ['T1610', 'T1552.005', 'T1078.004'],
                'd3fend_counters': ['D3-CSM', 'D3-IAM', 'D3-SFI'],
                'business_impact': 'Full cloud infrastructure compromise'
            }]
        return []

    def _template_deserial_persistence(self, findings: List) -> List:
        """Deserialization -> RCE -> Persistence."""
        deserial = [f for f in findings if 'DESERIAL' in f.get('type', '').upper()]
        rce = [f for f in findings if 'RCE' in f.get('type', '').upper() or 'COMMAND_INJECTION' in f.get('type', '').upper()]
        persist = [f for f in findings if 'PERSIST' in f.get('type', '').upper() or 'BACKDOOR' in f.get('type', '').upper()]

        if deserial and rce:
            return [{
                'id': f"CHAIN-DESERIAL-PERSIST-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                'name': 'Insecure Deserialization → RCE → Persistence',
                'priority': 'P0',
                'score': 8.8,
                'steps': [
                    {'finding': deserial[0].get('id'), 'role': 'initial_access', 'technique': 'T1059', 'description': 'Insecure deserialization RCE'},
                    {'finding': rce[0].get('id'), 'role': 'execution', 'technique': 'T1059.001', 'description': 'Arbitrary command execution'},
                    {'finding': persist[0].get('id') if persist else 'N/A', 'role': 'persistence', 'technique': 'T1505', 'description': 'Persistence mechanism'}
                ],
                'mitre_path': ['T1059', 'T1059.001', 'T1505'],
                'd3fend_counters': ['D3-EAA', 'D3-SCA', 'D3-HSA'],
                'business_impact': 'Persistent full system access'
            }]
        return []

    def _template_crypto_mitm(self, findings: List) -> List:
        """Weak Crypto -> MITM -> Credential Theft."""
        crypto = [f for f in findings if 'WEAK_CRYPTO' in f.get('type', '').upper() or 'TLS' in f.get('type', '').upper() or 'SSL' in f.get('type', '').upper()]
        mitm = [f for f in findings if 'MITM' in f.get('type', '').upper() or 'INTERCEPT' in f.get('type', '').upper()]

        if crypto:
            return [{
                'id': f"CHAIN-CRYPTO-MITM-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                'name': 'Weak TLS/Crypto → MITM → Credential Theft',
                'priority': 'P1',
                'score': 6.5,
                'steps': [
                    {'finding': crypto[0].get('id'), 'role': 'reconnaissance', 'technique': 'T1557', 'description': 'Weak cipher/protocol identified'},
                    {'finding': mitm[0].get('id') if mitm else 'N/A', 'role': 'credential_access', 'technique': 'T1040', 'description': 'Network traffic interception'},
                    {'finding': 'CREDENTIALS', 'role': 'objective', 'technique': 'T1552', 'description': 'Credential harvesting via MITM'}
                ],
                'mitre_path': ['T1557', 'T1040', 'T1552'],
                'd3fend_counters': ['D3-CH', 'D3-CTA', 'D3-NTA'],
                'business_impact': 'Credential theft and session hijacking'
            }]
        return []

    async def _dynamic_correlation(self, findings: List) -> List:
        """Dynamically correlate findings based on shared targets, techniques, and prerequisites."""
        chains = []

        # Group by target
        by_target = {}
        for f in findings:
            target = f.get('target', '')
            if target not in by_target:
                by_target[target] = []
            by_target[target].append(f)

        # For each target with multiple findings, try to build chains
        for target, target_findings in by_target.items():
            if len(target_findings) < 2:
                continue

            # Sort by severity and confidence
            target_findings.sort(key=lambda x: (x.get('severity', 0), x.get('confidence', 0)), reverse=True)

            # Build chain if we have a plausible progression
            if len(target_findings) >= 2:
                chain = {
                    'id': f"CHAIN-DYNAMIC-{target}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    'name': f'Dynamic Chain: {target}',
                    'priority': 'P2',
                    'score': min(6.0, max(f.get('severity', 0) for f in target_findings) / 10 * 7),
                    'steps': [],
                    'mitre_path': [],
                    'd3fend_counters': [],
                    'business_impact': 'Target-specific compound risk'
                }

                role_map = {
                    'initial_access': ['reconnaissance', 'initial_access'],
                    'execution': ['execution', 'rce', 'command_injection'],
                    'persistence': ['persistence'],
                    'privilege_escalation': ['privilege_escalation', 'escalation'],
                    'defense_evasion': ['evasion', 'bypass'],
                    'credential_access': ['credential_access', 'credential'],
                    'discovery': ['discovery', 'enumeration'],
                    'lateral_movement': ['lateral_movement', 'movement'],
                    'collection': ['collection', 'exfiltration'],
                    'objective': ['objective', 'impact']
                }

                for i, f in enumerate(target_findings[:5]):
                    role = 'initial_access'
                    for r, keywords in role_map.items():
                        if any(k in f.get('type', '').lower() for k in keywords):
                            role = r
                            break

                    chain['steps'].append({
                        'finding': f.get('id'),
                        'role': role,
                        'technique': f.get('mitre_attack', 'T1190')[0] if f.get('mitre_attack') else 'T1190',
                        'description': f.get('title', 'Unknown')
                    })
                    if f.get('mitre_attack'):
                        chain['mitre_path'].extend(f.get('mitre_attack', []))
                    if f.get('d3fend'):
                        chain['d3fend_counters'].extend(f.get('d3fend', []))

                if chain['steps']:
                    chains.append(chain)

        return chains

    def _prioritize_chains(self, chains: List) -> List:
        """Prioritize chains for exploitation."""
        priority_order = {'P0': 0, 'P1': 1, 'P2': 2, 'P3': 3}
        chains.sort(key=lambda c: (priority_order.get(c.get('priority', 'P3'), 3), -c.get('score', 0)))
        return chains

    def _generate_chain_diagrams(self, chains: List) -> List[str]:
        """Generate Mermaid diagrams for attack chains."""
        diagrams = []
        for chain in chains:
            mermaid = f"```mermaid\ngraph LR\n    subgraph \"{chain['name']} [{chain['priority']}]\"\n"
            for i, step in enumerate(chain['steps']):
                role_color = {
                    'reconnaissance': '#ffff00',
                    'initial_access': '#ffcc00',
                    'credential_access': '#ff9900',
                    'execution': '#ff6600',
                    'pivot': '#ff6600',
                    'privilege_escalation': '#ff3300',
                    'persistence': '#cc0066',
                    'lateral_movement': '#cc0000',
                    'objective': '#990000'
                }.get(step.get('role', ''), '#cccccc')

                step_id = f"S{i}"
                mermaid += f'    {step_id}["{step.get("finding", "N/A")}"]:::role{step.get("role", "")}\n'
                if i > 0:
                    mermaid += f'    S{str(i-1)} -->|Enables| {step_id}\n'

            mermaid += f"""    end
    classDef rolereconnaissance fill:#ffff00,stroke:#333,stroke-width:1px;
    classDef roleinitial_access fill:#ffcc00,stroke:#333,stroke-width:1px;
    classDef rolecredential_access fill:#ff9900,stroke:#333,stroke-width:1px;
    classDef roleexecution fill:#ff6600,stroke:#333,stroke-width:1px;
    classDef rolepivot fill:#ff6600,stroke:#333,stroke-width:1px;
    classDef roleprivilege_escalation fill:#ff3300,stroke:#333,stroke-width:1px;
    classDef rolepersistence fill:#cc0066,stroke:#333,stroke-width:1px;
    classDef rolelateral_movement fill:#cc0000,stroke:#333,stroke-width:1px;
    classDef roleobjective fill:#990000,stroke:#333,stroke-width:2px,color:#fff;
```"""
            diagrams.append(mermaid)
        return diagrams

    def _generate_exploitation_roadmap(self, approved_chains: List) -> List[Dict]:
        """Generate step-by-step exploitation roadmap."""
        roadmap = []
        for chain in approved_chains:
            for i, step in enumerate(chain['steps']):
                roadmap.append({
                    'chain': chain['name'],
                    'step': i + 1,
                    'finding_id': step.get('finding'),
                    'role': step.get('role'),
                    'technique': step.get('technique'),
                    'action': f"Exploit {step.get('role', '').replace('_', ' ')}: {step.get('description', '')}",
                    'approval_required': True,
                    'estimated_time': '15-30 min'
                })
        return roadmap

    async def _request_chain_approval(self, chain: Dict) -> bool:
        """Request operator approval for chain exploitation."""
        chain_text = f"""⚔️ **Attack Chain for Approval**

**Chain:** {chain['name']} [{chain['priority']}]
**Score:** {chain['score']}/10
**Steps:** {len(chain['steps'])}

**Path:**
"""
        for i, step in enumerate(chain['steps'], 1):
            chain_text += f"{i}. {step.get('role', '').replace('_', ' ').title()}: {step.get('description', '')} (MITRE: {step.get('technique', 'N/A')})\n"

        chain_text += f"""\n**MITRE Path:** {', '.join(chain.get('mitre_path', []))}
**D3FEND Counters:** {', '.join(chain.get('d3fend_counters', []))}
**Business Impact:** {chain.get('business_impact', 'Not specified')}

Reply: `/go chain {chain['id']}` or `/hold chain {chain['id']} [reason]`"""

        await self.telegram.send_message(chain_text)

        # In real implementation, wait for HITL response
        # For now, return True for demo
        return True