"""NIGHTFANG Orchestrator - Main engagement coordinator."""
import asyncio
import logging
import signal
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import load_config, EngagementConfig, TelegramConfig, RulesConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager
from ..core.mock_telegram_bot import MockTelegramBot

from nightfang.agents.recon_passive import ReconPassiveAgent
from nightfang.agents.recon_active import ReconActiveAgent
from nightfang.agents.scanner_webapp import ScannerWebAppAgent
from nightfang.agents.scanner_api import ScannerAPIAgent
from nightfang.agents.scanner_network import ScannerNetworkAgent
from nightfang.agents.scanner_ai import ScannerAIAgent
from nightfang.agents.scanner_cloud import CloudTestingAgent
from nightfang.agents.scanner_ssl import SSLTLSTestingAgent
from nightfang.agents.vuln_scanner import VulnerabilityScannerAgent
from nightfang.agents.payload_crafter import PayloadCrafterAgent
from nightfang.agents.hunter import HunterAgent
from nightfang.agents.exploiter import ExploiterAgent
from nightfang.agents.reporter import ReporterAgent
from nightfang.agents.swarm_orchestrator import SwarmOrchestratorAgent
from nightfang.agents.attack_planner import AttackPlannerAgent
from nightfang.agents.recon_advisor import ReconAdvisorAgent

logger = logging.getLogger(__name__)


class NightfangOrchestrator:
    """Master orchestrator for NIGHTFANG engagements."""

    def __init__(self, config_path: str, engagement_id: Optional[str] = None):
        self.config_path = config_path
        self.engagement_id = engagement_id or f"ENG-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

        # Load configuration
        self.config = load_config(config_path)

        # Setup directories
        self.engagement_dir = Path("engagements") / self.engagement_id
        self.engagement_dir.mkdir(parents=True, exist_ok=True)

        # Initialize core components
        self.scope = ScopeValidator(self.config.scope)
        self.memory = MemoryManager(self.engagement_dir)
        self.telegram = MockTelegramBot(
            self.config.telegram or TelegramConfig(bot_token="", chat_id=""),
            self.config.rules,
            self.memory,
            self.engagement_dir
        )

        # Save initial scope
        self.memory.save_scope(self.scope.get_scope_summary())

        # Agent instances (lazy-loaded)
        self._agents = {}

        # State
        self.running = False
        self.current_phase = "intake"

        # Setup signal handlers
        self._setup_signals()

    def _setup_signals(self):
        """Setup signal handlers for graceful shutdown."""
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._signal_handler)
            except Exception:
                pass  # Not in main thread

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self.running = False

    async def initialize(self):
        """Initialize all components."""
        logger.info(f"Initializing engagement: {self.engagement_id}")

        # Initialize Telegram bot
        await self.telegram.initialize()

        # Send startup notification
        await self.telegram.send_message(
            f"🦅 NIGHTFANG Online — Engagement: {self.engagement_id}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 Target: {self.config.client}\n"
            f"📋 Type: {self.config.type}\n"
            f"🔧 Agents: {self.config.agent.max_concurrent_agents} max concurrent\n"
            f"⚡ Caveman Mode: {'ON' if self.config.rules.token_efficiency else 'OFF'}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Ready for Phase 1. Use /go to begin passive reconnaissance."
        )

        self.current_phase = "initialized"

    def _get_agent(self, agent_name: str):
        """Get or create agent instance."""
        if agent_name in self._agents:
            return self._agents[agent_name]

        agent_map = {
            'recon_passive_agent': lambda: ReconPassiveAgent(
                "RECON-PASSIVE",
                "Passive Reconnaissance Specialist",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'recon_active_agent': lambda: ReconActiveAgent(
                "RECON-ACTIVE",
                "Active Reconnaissance Specialist",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'webapp_scanner_agent': lambda: ScannerWebAppAgent(
                "SCANNER-WEBAPP",
                "Web Application Security Tester",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'api_scanner_agent': lambda: ScannerAPIAgent(
                "SCANNER-API",
                "API Security Tester",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'network_scanner_agent': lambda: ScannerNetworkAgent(
                "SCANNER-NETWORK",
                "Network Security Tester",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'cloud_scanner_agent': lambda: CloudTestingAgent(
                "SCANNER-CLOUD",
                "Cloud Security Tester",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'ssl_scanner_agent': lambda: SSLTLSTestingAgent(
                "SCANNER-SSL",
                "SSL/TLS Security Tester",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'ai_scanner_agent': lambda: ScannerAIAgent(
                "SCANNER-AI",
                "AI/LLM Security Specialist",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'vuln_scanner_agent': lambda: VulnerabilityScannerAgent(
                "VULN-SCANNER",
                "Vulnerability Scanner",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'payload_crafter_agent': lambda: PayloadCrafterAgent(
                "PAYLOAD-CRAFTER",
                "Payload Crafting Specialist",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'swarm_orchestrator_agent': lambda: SwarmOrchestratorAgent(
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'attack_planner_agent': lambda: AttackPlannerAgent(
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'recon_advisor_agent': lambda: ReconAdvisorAgent(
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'hunter_agent': lambda: HunterAgent(
                "HUNTER",
                "Threat Hunter & Chain Builder",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'exploiter_agent': lambda: ExploiterAgent(
                "EXPLOITER",
                "Exploitation Specialist",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
            'reporter_agent': lambda: ReporterAgent(
                "REPORTER",
                "Report Generator",
                self.config,
                self.config.agent,
                self.scope,
                self.memory,
                self.telegram
            ),
        }

        if agent_name not in agent_map:
            raise ValueError(f"Unknown agent: {agent_name}")

        agent = agent_map[agent_name]()
        self._agents[agent_name] = agent
        return agent

    async def run_phase(self, phase: str, agent_names: List[str], inputs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run a phase with multiple agents."""
        self.current_phase = phase
        inputs = inputs or {}

        await self.telegram.send_phase_transition(phase, starting=True)

        results = {}

        for agent_name in agent_names:
            agent = self._get_agent(agent_name)

            # Check required tools
            tool_status = await agent.check_all_tools()
            missing = [t for t, ok in tool_status.items() if not ok]
            if missing:
                logger.warning(f"[{agent.name}] Missing tools: {missing}")
                await self.telegram.send_message(f"⚠️ [{agent.name}] Missing tools: {', '.join(missing)}")

            # Run agent
            logger.info(f"[{agent.name}] Starting...")
            try:
                result = await agent.run(inputs)
                results[agent_name] = result

                # Merge inputs for next agent
                inputs.update(result)

                logger.info(f"[{agent.name}] Completed successfully")
            except PermissionError as e:
                logger.warning(f"[{agent.name}] Stopped by operator: {e}")
                await self.telegram.send_message(f"⏸️ {agent.name}: {e}")
                break
            except Exception as e:
                logger.error(f"[{agent.name}] Failed: {e}")
                await self.telegram.send_message(f"❌ {agent.name} failed: {e}")
                if not self.config.agent.retry_on_failure:
                    raise

        await self.telegram.send_phase_transition(phase, starting=False)
        return results

    async def run_full_engagement(self):
        """Execute the complete engagement workflow."""
        self.running = True

        try:
            # Phase 1: Passive Reconnaissance
            if self.running:
                await self.run_phase("phase_1_recon", ["recon_passive_agent", "recon_advisor_agent"])

            # Phase 1.5: Recon Analysis
            if self.running:
                await self.run_phase("phase_1_5_recon_analysis", ["recon_advisor_agent"])

            # Phase 2: Active Reconnaissance (requires HITL)
            if self.running:
                await self.run_phase("phase_2_active_recon", ["recon_active_agent"])

            # Phase 3: Vulnerability Scanning (parallel)
            if self.running:
                await self.run_phase("phase_3_scanning", [
                    "webapp_scanner_agent",
                    "api_scanner_agent",
                    "network_scanner_agent",
                    "cloud_scanner_agent",
                    "ssl_scanner_agent",
                    "ai_scanner_agent",
                    "vuln_scanner_agent"
                ])

            # Phase 3.5: Payload Crafting (after vuln scanning)
            if self.running:
                await self.run_phase("phase_3_5_payload_crafting", [
                    "payload_crafter_agent"
                ])

            # Phase 4: Attack Planning & Threat Hunting
            if self.running:
                await self.run_phase("phase_4_attack_planning", ["attack_planner_agent"])

            # Phase 4.5: Threat Hunting & Attack Chains
            if self.running:
                await self.run_phase("phase_4_5_hunting", ["hunter_agent"])

            # Phase 5: Exploitation (HITL required per finding)
            if self.running:
                await self.run_phase("phase_5_exploitation", ["exploiter_agent"])

            # Phase 5.5: Swarm Coordination for post-exploitation
            if self.running:
                await self.run_phase("phase_5_5_swarm_coordination", ["swarm_orchestrator_agent"])

            # Phase 6: Reporting
            if self.running:
                await self.run_phase("phase_6_reporting", ["reporter_agent"])

            # Final summary
            findings = self.memory.load_findings()
            await self.telegram.send_engagement_complete({
                'target': self.config.client,
                'duration': 'TBD',
                'total_findings': len(findings),
                'critical': len([f for f in findings if f.get('severity', 0) >= 9]),
                'high': len([f for f in findings if 7 <= f.get('severity', 0) < 9]),
                'medium': len([f for f in findings if 5 <= f.get('severity', 0) < 7]),
                'low': len([f for f in findings if 3 <= f.get('severity', 0) < 5]),
                'info': len([f for f in findings if f.get('severity', 0) < 3])
            })

        except Exception as e:
            logger.error(f"Engagement failed: {e}")
            await self.telegram.send_message(f"💥 Engagement failed: {e}")
            raise
        finally:
            await self.telegram.close()
            self.running = False

    async def run_single_phase(self, phase: str):
        """Run a single phase by name."""
        phase_map = {
            'recon': ["recon_passive_agent", "recon_advisor_agent"],
            'recon_analysis': ["recon_advisor_agent"],
            'active_recon': ["recon_active_agent"],
            'webapp': ["webapp_scanner_agent"],
            'api': ["api_scanner_agent"],
            'network': ["network_scanner_agent"],
            'cloud': ["cloud_scanner_agent"],
            'ssl': ["ssl_scanner_agent"],
            'ai': ["ai_scanner_agent"],
            'vuln': ["vuln_scanner_agent"],
            'payload': ["payload_crafter_agent"],
            'attack_plan': ["attack_planner_agent"],
            'hunt': ["hunter_agent"],
            'exploit': ["exploiter_agent"],
            'swarm': ["swarm_orchestrator_agent"],
            'report': ["reporter_agent"]
        }

        if phase not in phase_map:
            raise ValueError(f"Unknown phase: {phase}. Available: {list(phase_map.keys())}")

        await self.initialize()
        await self.run_phase(phase, phase_map[phase])
        await self.telegram.close()


async def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m nightfang.core.orchestrator <config_path> [phase]")
        print("  config_path: Path to engagement YAML config")
        print("  phase: Optional phase to run (recon, active_recon, webapp, api, network, ai, hunt, exploit, report, full)")
        sys.exit(1)

    config_path = sys.argv[1]
    phase = sys.argv[2] if len(sys.argv) > 2 else 'full'

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    orchestrator = NightfangOrchestrator(config_path)
    await orchestrator.initialize()

    if phase == 'full':
        await orchestrator.run_full_engagement()
    else:
        await orchestrator.run_single_phase(phase)
        await orchestrator.telegram.close()


if __name__ == "__main__":
    asyncio.run(main())