"""Hunter Agent - Threat hunting and attack chain correlation."""
import asyncio
import logging
import json
from typing import Any, Dict, List
from datetime import datetime
from pathlib import Path

from .base import BaseAgent
from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, AttackChain
from ..core.telegram_bot import TelegramBot

logger = logging.getLogger(__name__)


class HunterAgent(BaseAgent):
    """Threat hunting and attack chain correlation agent."""

    def __init__(
        self,
        config: EngagementConfig,
        agent_config: AgentConfig,
        scope_validator: ScopeValidator,
        memory: MemoryManager,
        telegram: TelegramBot
    ):
        super().__init__(
            name="HUNTER",
            role="Threat Hunter & Chain Builder",
            config=config,
            agent_config=agent_config,
            scope_validator=scope_validator,
            memory=memory,
            telegram=telegram,
            skills=["hunting", "attack-chain-analysis", "memory-management", "evidence-collection"],
            tools_required=[],
            hitl_required=True,
            max_runtime_minutes=180
        )

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Starting threat hunting and attack chain analysis")
        self.log_event("hunter", "started", "Threat hunting and chain building initiated")

        # Load all findings from previous phases
        all_findings = self.memory.get_all_findings()

        results = {
            "attack_chains": [],
            "logic_flaws": [],
            "compound_risk": [],
            "novel_findings": [],
            "mermaid_diagrams": []
        }

        # 1. Build attack chains from existing findings
        chains = await self._build_attack_chains(all_findings)
        results["attack_chains"] = chains

        # 2. Logic flaw hunting
        logic_flaws = await self._hunt_logic_flaws()
        results["logic_flaws"] = logic_flaws

        # 3. Creative testing (race conditions, HPP, smuggling)
        novel = await self._creative_testing()
        results["novel_findings"] = novel

        # 4. Generate Mermaid diagrams for chains
        diagrams = await self._generate_chain_diagrams(results["attack_chains"])
        results["mermaid_diagrams"] = diagrams

        # 5. Prioritize exploitation targets
        prioritized = self._prioritize_exploitation(results["attack_chains"])
        results["prioritized_targets"] = prioritized

        self.memory.save_phase_result("hunter", results)
        self.log_event("hunter", "completed", f"Built {len(results['attack_chains'])} attack chains")

        return results

    async def _build_attack_chains(self, findings: List) -> List:
        """Build attack chains from existing findings."""
        chains = []

        # Template: CHAIN-BOLA-JWT-ADMIN
        bola_findings = [f for f in findings if "BOLA" in f.type or "IDOR" in f.type]
        jwt_findings = [f for f in findings if "JWT" in f.type]
        admin_findings = [f for f in findings if "ADMIN" in f.type.upper() or "PRIVILEGE" in f.type.upper()]

        if bola_findings and jwt_findings:
            chain = AttackChain(
                id=f"CHAIN-BOLA-JWT-ADMIN-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                name="BOLA → Weak JWT → Admin Panel",
                priority="P0",
                score=8.4,
                steps=[
                    {"finding": bola_findings[0].id, "role": "initial_access", "technique": "T1190"},
                    {"finding": jwt_findings[0].id, "role": "privilege_escalation", "technique": "T1552.004"},
                    {"finding": admin_findings[0].id if admin_findings else "N/A", "role": "objective", "technique": "T1078"}
                ],
                mitre_path=["T1190", "T1552.004", "T1078"],
                d3fend_counters=["D3-PSA", "D3-KDU", "D3-AA"]
            )
            self.memory.add_attack_chain(chain)
            results["attack_chains"].append(chain.to_dict())

        # Template: CHAIN-SUBDOMAIN-SSRF-METADATA
        subdomain_findings = [f for f in findings if "SUBDOMAIN" in f.type]
        ssrf_findings = [f for f in findings if "SSRF" in f.type]

        if subdomain_findings and ssrf_findings:
            chain = AttackChain(
                id=f"CHAIN-SUBDOMAIN-SSRF-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                name="Subdomain Takeover → SSRF → Cloud Metadata",
                priority="P0",
                score=8.2,
                steps=[
                    {"finding": subdomain_findings[0].id, "role": "initial_access", "technique": "T1590.005"},
                    {"finding": ssrf_findings[0].id, "role": "pivot", "technique": "T1190"},
                    {"finding": "METADATA", "role": "objective", "technique": "T1552.005"}
                ],
                mitre_path=["T1590.005", "T1190", "T1552.005"],
                d3fend_counters=["D3-DNST", "D3-SFI", "D3-CSM"]
            )
            self.memory.add_attack_chain(chain)
            results["attack_chains"].append(chain.to_dict())

        return results["attack_chains"]

    async def _hunt_logic_flaws(self) -> List:
        """Hunt for business logic flaws."""
        findings = []

        # 1. Race conditions
        # 2. Workflow bypasses
        # 3. Parameter pollution
        # 4. Payment logic
        # 5. Auth workflow bypasses

        return []

    async def _creative_testing(self) -> List:
        """Creative testing for novel bypasses."""
        findings = []

        # HTTP Parameter Pollution
        # HTTP Request Smuggling
        # Cache Poisoning
        # HTTP/2 specific attacks
        # Unicode normalization bypasses

        return []

    async def _generate_chain_diagrams(self, chains: List) -> List[str]:
        """Generate Mermaid diagrams for attack chains."""
        diagrams = []

        for chain in chains:
            mermaid = f"""```mermaid
graph LR
    subgraph "{chain['name']} [{chain['priority']}]"
"""

            for i, step in enumerate(chain['steps']):
                role_color = {
                    'initial_access': '#ffcc00',
                    'privilege_escalation': '#ff6600',
                    'pivot': '#ff6600',
                    'objective': '#cc0000'
                }.get(step.get('role', ''), '#cccccc')

                step_id = f"S{i}"
                mermaid += f'    {step_id}["{step.get("finding", "N/A")}"]:::role{step.get("role", "")}\n'
                if i > 0:
                    mermaid += f'    S{str(i-1)} -->|Enables| {step_id}\n'

            mermaid += f"""    end
    classDef roleinitial_access fill:#ffcc00,stroke:#333,stroke-width:1px;
    classDef roleprivilege_escalation fill:#ff6600,stroke:#333,stroke-width:1px;
    classDef rolepivot fill:#ff6600,stroke:#333,stroke-width:1px;
    classDef roleobjective fill:#cc0000,stroke:#333,stroke-width:2px,color:#fff;
```"""
            diagrams.append(mermaid)

        return diagrams

    def _prioritize_exploitation(self, chains: List) -> List:
        """Prioritize targets for exploitation phase."""
        priorities = []

        for chain in chains:
            for step in chain['steps']:
                priorities.append({
                    "finding_id": step.get("finding", "N/A"),
                    "chain": chain['name'],
                    "role": step.get("role", ""),
                    "priority": chain['priority'],
                    "score": chain['score']
                })

        # Sort by priority and score
        priorities.sort(key=lambda x: (x['priority'], -x['score']))
        return priorities