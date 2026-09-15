"""NIGHTFANG Agents Package"""
from .base import BaseAgent, ToolResult
from .recon_passive import ReconPassiveAgent
from .recon_active import ReconActiveAgent
from .scanner_webapp import ScannerWebAppAgent
from .scanner_api import ScannerAPIAgent
from .scanner_network import ScannerNetworkAgent
from .scanner_ai import ScannerAIAgent
from .hunter import HunterAgent
from .exploiter import ExploiterAgent
from .reporter import ReporterAgent

__all__ = [
    'BaseAgent',
    'ToolResult',
    'ReconPassiveAgent',
    'ReconActiveAgent',
    'ScannerWebAppAgent',
    'ScannerAPIAgent',
    'ScannerNetworkAgent',
    'ScannerAIAgent',
    'HunterAgent',
    'ExploiterAgent',
    'ReporterAgent'
]