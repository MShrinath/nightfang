"""Telegram bot for Human-in-the-Loop communication."""
import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional
from dataclasses import dataclass

import aiohttp
from aiohttp import web

from ..core.config import TelegramConfig, RulesConfig
from ..core.memory import MemoryManager, Decision
from .telegram_base import BaseTelegramBot

logger = logging.getLogger(__name__)


class TelegramBot(BaseTelegramBot):
    """Telegram bot for operator communication and HITL approvals."""
    
    def __init__(self, config: TelegramConfig, rules_config: RulesConfig, memory: MemoryManager, engagement_dir: Path):
        super().__init__(config, memory, engagement_dir)
        self.rules_config = rules_config
        
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def initialize(self):
        """Initialize the bot session."""
        self.session = aiohttp.ClientSession()
        # Test bot token
        await self._api_call('getMe')
        logger.info("Telegram bot initialized")
    
    async def close(self):
        if self.session:
            await self.session.close()
    
    async def _api_call(self, method: str, **params) -> dict:
        """Make a Telegram API call."""
        if not self.session:
            raise RuntimeError("Bot not initialized")
        
        url = f"{self.base_url}/{method}"
        async with self.session.post(url, json=params) as resp:
            data = await resp.json()
            if not data.get('ok'):
                raise Exception(f"Telegram API error: {data}")
            return data['result']
    
    async def send_message(self, text: str, chat_id: Optional[str] = None, parse_mode: Optional[str] = None) -> dict:
        """Send a message to the operator."""
        chat_id = chat_id or self.chat_id
        parse_mode = parse_mode or self.parse_mode
        
        # Truncate if needed
        if len(text) > self.max_length:
            text = text[:self.max_length - 50] + "\n\n... [truncated]"
        
        return await self._api_call('sendMessage', 
            chat_id=chat_id, 
            text=text, 
            parse_mode=parse_mode,
            disable_web_page_preview=True
        )
    
    async def send_finding_alert(self, finding: dict, terse: bool = False):
        """Send a finding alert to the operator requesting approval."""
        finding_id = finding.get('id', 'UNKNOWN')
        
        if terse or self.compact_mode:
            text = self._format_terse_finding(finding)
        else:
            text = self._format_verbose_finding(finding)
        
        await self.send_message(text)
        
        # Create future for approval
        future = asyncio.Future()
        self.pending_approvals[finding_id] = future
        return future
    
    async def _api_call(self, method: str, **params) -> dict:
        """Make a Telegram API call."""
        if not self.session:
            raise RuntimeError("Bot not initialized")
        
        url = f"{self.base_url}/{method}"
        async with self.session.post(url, json=params) as resp:
            data = await resp.json()
            if not data.get('ok'):
                raise Exception(f"Telegram API error: {data}")
            return data['result']
    
    async def send_status_update(self, phase: str, duration: str, targets_tested: str, findings: dict, queue: str, next_action: str):
        """Send a status update to the operator."""
        terse = self.compact_mode
        
        if terse:
            text = f"""📊 Status: {phase} | {duration}
Tested: {targets_tested} | Findings: {findings.get('critical',0)}C {findings.get('high',0)}H {findings.get('medium',0)}M {findings.get('low',0)}L
Queue: {queue}
Next: {next_action}"""
        else:
            text = f"""📊 NIGHTFANG Status Update
━━━━━━━━━━━━━━━━━━━━━━
🕐 Phase: {phase}
⏱️ Duration: {duration}
🎯 Targets Tested: {targets_tested}
🔍 Findings: Critical:{findings.get('critical',0)} High:{findings.get('high',0)} Medium:{findings.get('medium',0)} Low:{findings.get('low',0)} Info:{findings.get('info',0)}
⏳ Queue: {queue}

Next: {next_action}"""
        
        await self.send_message(text)
    
    async def send_phase_transition(self, phase: str, starting: bool = True):
        """Send phase transition notification."""
        action = "STARTED" if starting else "COMPLETED"
        text = f"🔄 Phase {action}: {phase}"
        await self.send_message(text)
    
    async def send_engagement_complete(self, summary: dict):
        """Send engagement completion summary."""
        text = f"""✅ Engagement Complete
━━━━━━━━━━━━━━━━━━━━━━
🎯 Target: {summary.get('target', 'N/A')}
📅 Duration: {summary.get('duration', 'N/A')}
🔍 Total Findings: {summary.get('total_findings', 0)}
🔴 Critical: {summary.get('critical', 0)}
🟠 High: {summary.get('high', 0)}
🟡 Medium: {summary.get('medium', 0)}
🟢 Low: {summary.get('low', 0)}
ℹ️ Info: {summary.get('info', 0)}

📄 Full report generated. Use /report to retrieve."""
        await self.send_message(text)
    
    async def _api_call(self, method: str, **params) -> dict:
        """Make a Telegram API call."""
        if not self.session:
            raise RuntimeError("Bot not initialized")
        
        url = f"{self.base_url}/{method}"
        async with self.session.post(url, json=params) as resp:
            data = await resp.json()
            if not data.get('ok'):
                raise Exception(f"Telegram API error: {data}")
            return data['result']
    
    async def send_message(self, text: str, chat_id: Optional[str] = None, parse_mode: Optional[str] = None) -> dict:
        """Send a message to the operator."""
        chat_id = chat_id or self.chat_id
        parse_mode = parse_mode or self.parse_mode
        
        # Truncate if needed
        if len(text) > self.max_length:
            text = text[:self.max_length - 50] + "\n\n... [truncated]"
        
        return await self._api_call('sendMessage', 
            chat_id=chat_id, 
            text=text, 
            parse_mode=parse_mode,
            disable_web_page_preview=True
        )
    
    async def send_finding_alert(self, finding: dict, terse: bool = False):
        """Send a finding alert to the operator requesting approval."""
        finding_id = finding.get('id', 'UNKNOWN')
        
        if terse or self.compact_mode:
            text = self._format_terse_finding(finding)
        else:
            text = self._format_verbose_finding(finding)
        
        await self.send_message(text)
        
        # Create future for approval
        future = asyncio.Future()
        self.pending_approvals[finding_id] = future
        return future
    
    async def wait_for_approval(self, finding_id: str, timeout: int = 300) -> str:
        """Wait for operator approval on a finding."""
        if finding_id not in self.pending_approvals:
            return 'hold'  # Not pending, default to hold
        
        try:
            return await asyncio.wait_for(self.pending_approvals[finding_id], timeout=timeout)
        except asyncio.TimeoutError:
            self.pending_approvals.pop(finding_id, None)
            self._log_decision(finding_id, 'timeout', 'Operator did not respond in time')
            return 'hold'