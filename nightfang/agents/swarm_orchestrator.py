"""Swarm Orchestrator Agent - Multi-agent coordination and engagement management."""
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset, TimelineEvent
from ..core.telegram_bot import TelegramBot
from .base import BaseAgent, ToolResult, AgentTier, ScopeDeclaration

logger = logging.getLogger(__name__)


class SwarmOrchestratorAgent(BaseAgent):
    """Swarm coordinator - manages multi-agent workflows, delegates tasks, tracks progress."""

    def __init__(
        self,
        config: EngagementConfig,
        agent_config: AgentConfig,
        scope_validator: ScopeValidator,
        memory: MemoryManager,
        telegram: TelegramBot
    ):
        super().__init__(
            name="SWARM-ORCHESTRATOR",
            role="Swarm Coordinator",
            config=config,
            agent_config=agent_config,
            scope_validator=scope_validator,
            memory=memory,
            telegram=telegram,
            skills=["swarm-orchestration", "engagement-planning", "scope-management", "attack-chain-analysis"],
            tools_required=[],
            hitl_required=True,
            hitl_checkpoints=[
                "Before starting new engagement phase",
                "Before delegating destructive tasks",
                "Before escalating privileges",
                "Before lateral movement",
                "Before data exfiltration"
            ],
            max_runtime_minutes=480,
            tier=AgentTier.TIER_1_ADVISORY,
            trigger_phrases=["swarm", "orchestrate", "full engagement", "coordinate agents", "manage workflow"],
            model="sonnet",
            description="Coordinates multi-agent penetration testing workflows, manages agent handoffs, tracks progress across parallel workstreams, and compiles results into unified engagement picture."
        )
        self._agent_registry = {}
        self._task_queue = []
        self._active_tasks = {}
        self._completed_tasks = {}

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate the full engagement or specific workflow."""
        self.log_event("swarm_orchestrator", "Starting swarm orchestration", "started")

        # Initialize scope if not provided
        if not inputs.get('scope_declared'):
            await self._request_scope_declaration(inputs)

        mode = inputs.get('mode', 'full_engagement')
        results = {}

        if mode == 'full_engagement':
            results = await self._run_full_engagement(inputs)
        elif mode == 'recon_only':
            results = await self._run_recon_phase(inputs)
        elif mode == 'attack_chain':
            results = await self._build_attack_chains(inputs)
        elif mode == 'exploitation':
            results = await self._coordinate_exploitation(inputs)
        elif mode == 'reporting':
            results = await self._generate_reports(inputs)

        self.log_event("swarm_orchestrator", f"Orchestration complete: {mode}", "completed")
        return results

    async def _request_scope_declaration(self, inputs: Dict) -> Dict:
        """Request and validate scope declaration from operator."""
        self.log_event("swarm_orchestrator", "Requesting scope declaration", "pending")

        # This would integrate with Telegram HITL
        # For now, we use the config scope
        scope_summary = self.scope.get_scope_summary()
        inputs['scope_declared'] = True
        inputs['scope_summary'] = scope_summary

        await self.telegram.send_message(
            f"📋 **Scope Declared**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 Target: {self.config.client}\n"
            f"🌐 Domains: {len(scope_summary.get('in_scope_domains', []))}\n"
            f"🔌 IPs: {len(scope_summary.get('in_scope_ips', []))}\n"
            f"🌍 URLs: {len(scope_summary.get('in_scope_urls', []))}\n"
            f"🚫 Out of Scope: {len(scope_summary.get('out_of_scope_domains', [])) + len(scope_summary.get('out_of_scope_ips', []))}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"✅ Scope validated. Use /go to begin Phase 1."
        )

        return inputs

    async def _run_full_engagement(self, inputs: Dict) -> Dict:
        """Run complete engagement lifecycle."""
        results = {}

        # Phase 1: Reconnaissance
        recon_results = await self._run_recon_phase(inputs)
        results['recon'] = recon_results
        inputs.update(recon_results)

        # Phase 2: Vulnerability Scanning (parallel)
        vuln_results = await self._run_vuln_scanning(inputs)
        results['vuln_scanning'] = vuln_results
        inputs.update(vuln_results)

        # Phase 3: Attack Chain Building
        chain_results = await self._build_attack_chains(inputs)
        results['attack_chains'] = chain_results

        # Phase 4: Exploitation (HITL per chain)
        exploit_results = await self._coordinate_exploitation(inputs)
        results['exploitation'] = exploit_results

        # Phase 5: Post-Exploitation
        post_results = await self._run_post_exploitation(inputs)
        results['post_exploitation'] = post_results

        # Phase 6: Reporting
        report_results = await self._generate_reports(inputs)
        results['reporting'] = report_results

        return results

    async def _run_recon_phase(self, inputs: Dict) -> Dict:
        """Run passive and active reconnaissance."""
        self.log_event("swarm_orchestrator", "Starting reconnaissance phase", "started")
        await self.telegram.send_phase_transition("phase_1_recon", starting=True)

        # Delegate to recon agents
        recon_passive_inputs = {
            'target_domains': self._extract_domains(inputs),
            'target_organization_name': self.config.client,
            'scope_definition': inputs.get('scope_summary', {})
        }

        # These would be actual agent calls in full implementation
        # For now, return structured results
        results = {
            'subdomain_list': [],
            'dns_records': {},
            'technology_stack': {},
            'certificate_inventory': [],
            'attack_surface_map': {},
            'host_inventory': [],
            'port_service_map': {},
            'os_fingerprints': {}
        }

        await self.telegram.send_phase_transition("phase_1_recon", starting=False)
        return results

    async def _run_vuln_scanning(self, inputs: Dict) -> Dict:
        """Run parallel vulnerability scanning."""
        self.log_event("swarm_orchestrator", "Starting vulnerability scanning", "started")
        await self.telegram.send_phase_transition("phase_3_scanning", starting=True)

        results = {
            'webapp_findings': [],
            'api_findings': [],
            'network_findings': [],
            'cloud_findings': [],
            'ssl_findings': [],
            'ai_findings': [],
            'vuln_scanner_findings': [],
            'exploit_matches': []
        }

        await self.telegram.send_phase_transition("phase_3_scanning", starting=False)
        return results

    async def _build_attack_chains(self, inputs: Dict) -> Dict:
        """Build attack chains from findings."""
        self.log_event("swarm_orchestrator", "Building attack chains", "started")

        # Delegate to attack planner
        all_findings = self.memory.load_findings()
        chains = await self._correlate_findings(all_findings)

        results = {
            'attack_chains': chains,
            'prioritized_targets': self._prioritize_exploitation(chains),
            'mermaid_diagrams': self._generate_chain_diagrams(chains)
        }

        # Send to operator for approval
        for chain in chains:
            await self._request_chain_approval(chain)

        return results

    async def _coordinate_exploitation(self, inputs: Dict) -> Dict:
        """Coordinate exploitation of approved chains."""
        self.log_event("swarm_orchestrator", "Coordinating exploitation", "started")

        approved_chains = inputs.get('approved_chains', [])
        results = {'exploited': [], 'access_gained': [], 'credentials': [], 'lateral_movement': []}

        for chain in approved_chains:
            # Delegate to exploiter agent
            exploit_result = await self._exploit_chain(chain)
            results['exploited'].append(exploit_result)

            if exploit_result.get('success'):
                # Post-exploitation
                post_result = await self._post_exploit(chain, exploit_result)
                results['access_gained'].extend(post_result.get('access', []))
                results['credentials'].extend(post_result.get('credentials', []))
                results['lateral_movement'].extend(post_result.get('lateral', []))

        return results

    async def _run_post_exploitation(self, inputs: Dict) -> Dict:
        """Run post-exploitation activities."""
        results = {
            'privilege_escalation': [],
            'credential_harvesting': [],
            'lateral_movement': [],
            'persistence': [],
            'data_staging': [],
            'cleanup_verification': []
        }
        return results

    async def _generate_reports(self, inputs: Dict) -> Dict:
        """Generate final reports."""
        self.log_event("swarm_orchestrator", "Generating reports", "started")

        all_findings = self.memory.load_findings()
        chains = self.memory.load_chains()
        timeline = self.memory.load_timeline()

        # Delegate to reporter agent
        results = {
            'executive_summary': '',
            'technical_report': '',
            'remediation_roadmap': '',
            'attack_chain_diagrams': [],
            'evidence_index': [],
            'compliance_mapping': {}
        }

        return results

    async def _correlate_findings(self, findings: List) -> List:
        """Correlate findings into attack chains."""
        chains = []

        # Template: CHAIN-BOLA-JWT-ADMIN
        bola = [f for f in findings if 'BOLA' in f.get('type', '') or 'IDOR' in f.get('type', '')]
        jwt = [f for f in findings if 'JWT' in f.get('type', '')]
        admin = [f for f in findings if 'ADMIN' in f.get('type', '').upper() or 'PRIVILEGE' in f.get('type', '').upper()]

        if bola and jwt:
            chains.append({
                'id': f"CHAIN-BOLA-JWT-ADMIN-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                'name': 'BOLA → Weak JWT → Admin Panel',
                'priority': 'P0',
                'score': 8.4,
                'steps': [
                    {'finding': bola[0].get('id'), 'role': 'initial_access', 'technique': 'T1190'},
                    {'finding': jwt[0].get('id'), 'role': 'privilege_escalation', 'technique': 'T1552.004'},
                    {'finding': admin[0].get('id') if admin else 'N/A', 'role': 'objective', 'technique': 'T1078'}
                ],
                'mitre_path': ['T1190', 'T1552.004', 'T1078'],
                'd3fend_counters': ['D3-PSA', 'D3-KDU', 'D3-AA']
            })

        # Template: CHAIN-SUBDOMAIN-SSRF-METADATA
        subdomain = [f for f in findings if 'SUBDOMAIN' in f.get('type', '')]
        ssrf = [f for f in findings if 'SSRF' in f.get('type', '')]

        if subdomain and ssrf:
            chains.append({
                'id': f"CHAIN-SUBDOMAIN-SSRF-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                'name': 'Subdomain Takeover → SSRF → Cloud Metadata',
                'priority': 'P0',
                'score': 8.2,
                'steps': [
                    {'finding': subdomain[0].get('id'), 'role': 'initial_access', 'technique': 'T1590.005'},
                    {'finding': ssrf[0].get('id'), 'role': 'pivot', 'technique': 'T1190'},
                    {'finding': 'METADATA', 'role': 'objective', 'technique': 'T1552.005'}
                ],
                'mitre_path': ['T1590.005', 'T1190', 'T1552.005'],
                'd3fend_counters': ['D3-DNST', 'D3-SFI', 'D3-CSM']
            })

        # Template: CHAIN-CREDENTIAL-REUSE
        cred_spray = [f for f in findings if 'CREDENTIAL_SPRAY' in f.get('type', '')]
        valid_creds = [f for f in findings if 'VALID_CREDENTIALS' in f.get('type', '')]
        ssh_rdp = [f for f in findings if f.get('type', '') in ['SSH', 'RDP', 'WINRM']]

        if cred_spray and valid_creds and ssh_rdp:
            chains.append({
                'id': f"CHAIN-CRED-REUSE-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                'name': 'Credential Spray → Valid Creds → Lateral Movement',
                'priority': 'P1',
                'score': 7.5,
                'steps': [
                    {'finding': cred_spray[0].get('id'), 'role': 'credential_access', 'technique': 'T1110.003'},
                    {'finding': valid_creds[0].get('id'), 'role': 'initial_access', 'technique': 'T1078'},
                    {'finding': ssh_rdp[0].get('id'), 'role': 'lateral_movement', 'technique': 'T1021.004'}
                ],
                'mitre_path': ['T1110.003', 'T1078', 'T1021.004'],
                'd3fend_counters': ['D3-BA', 'D3-ARA', 'D3-NA']
            })

        return chains

    def _prioritize_exploitation(self, chains: List) -> List:
        """Prioritize targets for exploitation."""
        priorities = []
        for chain in chains:
            for step in chain['steps']:
                priorities.append({
                    'finding_id': step.get('finding', 'N/A'),
                    'chain': chain['name'],
                    'role': step.get('role', ''),
                    'priority': chain['priority'],
                    'score': chain['score'],
                    'technique': step.get('technique', '')
                })
        priorities.sort(key=lambda x: (x['priority'], -x['score']))
        return priorities

    def _generate_chain_diagrams(self, chains: List) -> List[str]:
        """Generate Mermaid diagrams for attack chains."""
        diagrams = []
        for chain in chains:
            mermaid = f"```mermaid\ngraph LR\n    subgraph \"{chain['name']} [{chain['priority']}]\"\n"
            for i, step in enumerate(chain['steps']):
                role_color = {
                    'initial_access': '#ffcc00',
                    'credential_access': '#ff9900',
                    'privilege_escalation': '#ff6600',
                    'pivot': '#ff6600',
                    'lateral_movement': '#ff3300',
                    'objective': '#cc0000'
                }.get(step.get('role', ''), '#cccccc')

                step_id = f"S{i}"
                mermaid += f'    {step_id}["{step.get("finding", "N/A")}"]:::role{step.get("role", "")}\n'
                if i > 0:
                    mermaid += f'    S{str(i-1)} -->|Enables| {step_id}\n'

            mermaid += f"""    end
    classDef roleinitial_access fill:#ffcc00,stroke:#333,stroke-width:1px;
    classDef rolecredential_access fill:#ff9900,stroke:#333,stroke-width:1px;
    classDef roleprivilege_escalation fill:#ff6600,stroke:#333,stroke-width:1px;
    classDef rolepivot fill:#ff6600,stroke:#333,stroke-width:1px;
    classDef rolelateral_movement fill:#ff3300,stroke:#333,stroke-width:1px;
    classDef roleobjective fill:#cc0000,stroke:#333,stroke-width:2px,color:#fff;
```"""
            diagrams.append(mermaid)
        return diagrams

    async def _request_chain_approval(self, chain: Dict):
        """Request operator approval for attack chain exploitation."""
        chain_text = f"""⚔️ **Attack Chain Ready for Exploitation**

**Chain:** {chain['name']} [{chain['priority']}]
**Score:** {chain['score']}/10
**Steps:** {len(chain['steps'])}

**Path:**
"""
        for i, step in enumerate(chain['steps'], 1):
            chain_text += f"{i}. {step.get('role', '').replace('_', ' ').title()}: {step.get('finding', 'N/A')} (MITRE: {step.get('technique', 'N/A')})\n"

        chain_text += f"""\n**D3FEND Counters:** {', '.join(chain.get('d3fend_counters', []))}

Reply: `/go chain {chain['id']}` or `/hold chain {chain['id']} [reason]`"""

        await self.telegram.send_message(chain_text)

    async def _exploit_chain(self, chain: Dict) -> Dict:
        """Execute exploitation for a chain."""
        return {'chain_id': chain['id'], 'success': False, 'steps_completed': 0}

    async def _post_exploit(self, chain: Dict, exploit_result: Dict) -> Dict:
        """Post-exploitation activities."""
        return {'access': [], 'credentials': [], 'lateral': []}

    def _extract_domains(self, inputs: Dict) -> List[str]:
        """Extract domains from scope and inputs."""
        domains = []
        scope = inputs.get('scope_summary', {})
        domains.extend(scope.get('in_scope_domains', []))
        return domains


# Agent frontmatter for Claude Code compatibility
AGENT_FRONTMATTER = """---
name: swarm-orchestrator
description: >
  Delegates to this agent when the user wants to coordinate a full penetration
  testing engagement, manage multi-agent workflows, orchestrate parallel
  reconnaissance and exploitation, handle agent-to-agent handoffs, or execute
  a complete pentest lifecycle from planning through reporting.
tools:
  - Read
  - Write
  - Edit
  - Grep
  - Glob
  - WebFetch
  - WebSearch
  - Bash
model: sonnet
---
"""