"""NIGHTFANG Agents Package"""
from .base import BaseAgent, ToolResult
from .recon_passive import ReconPassiveAgent
from .recon_active import ReconActiveAgent
from .scanner_webapp import WebAppScannerAgent
from .reporter import ReporterAgent

__all__ = [
    'BaseAgent',
    'ToolResult',
    'ReconPassiveAgent',
    'ReconActiveAgent',
    'WebAppScannerAgent',
    'ReporterAgent'
]