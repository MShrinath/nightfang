"""NIGHTFANG Agents Package"""
from .base import BaseAgent, ToolResult, AgentTier, ScopeDeclaration
from .recon_passive import ReconPassiveAgent
from .recon_active import ReconActiveAgent
from .scanner_webapp import ScannerWebAppAgent
from .scanner_api import ScannerAPIAgent
from .scanner_network import ScannerNetworkAgent
from .scanner_ai import ScannerAIAgent
from .scanner_cloud import CloudTestingAgent
from .scanner_ssl import SSLTLSTestingAgent
from .vuln_scanner import VulnerabilityScannerAgent
from .payload_crafter import PayloadCrafterAgent
from .hunter import HunterAgent
from .exploiter import ExploiterAgent
from .reporter import ReporterAgent
from .swarm_orchestrator import SwarmOrchestratorAgent
from .attack_planner import AttackPlannerAgent
from .recon_advisor import ReconAdvisorAgent

__all__ = [
    'BaseAgent',
    'ToolResult',
    'AgentTier',
    'ScopeDeclaration',
    'ReconPassiveAgent',
    'ReconActiveAgent',
    'ScannerWebAppAgent',
    'ScannerAPIAgent',
    'ScannerNetworkAgent',
    'ScannerAIAgent',
    'CloudTestingAgent',
    'SSLTLSTestingAgent',
    'VulnerabilityScannerAgent',
    'PayloadCrafterAgent',
    'HunterAgent',
    'ExploiterAgent',
    'ReporterAgent',
    'SwarmOrchestratorAgent',
    'AttackPlannerAgent',
    'ReconAdvisorAgent'
]