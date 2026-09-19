"""Mock Telegram Bot for testing without real Telegram credentials."""
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional
from dataclasses import dataclass

from ..core.config import TelegramConfig, RulesConfig
from ..core.memory import MemoryManager, Decision

logger = logging.getLogger(__name__)


@dataclass
class TelegramMessage:
    chat_id: str
    text: str
    parse_mode: str = "Markdown"
    disable_web_page_preview: bool = True


class MockTelegramBot:
    """Mock Telegram bot for testing without real Telegram credentials."""
    
    def __init__(self, config: TelegramConfig, rules_config: RulesConfig, memory: MemoryManager, engagement_dir: Path):
        self.config = config
        self.rules_config = rules_config
        self.memory = memory
        self.engagement_dir = engagement_dir
        self.bot_token = config.bot_token
        self.chat_id = config.chat_id
        self.parse_mode = config.parse_mode
        self.compact_mode = config.compact_mode
        self.max_length = config.max_message_length
        
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
        self.session = None
        
        # Command handlers
        self.handlers: Dict[str, Callable] = {}
        self._register_default_handlers()
        
        # Pending approvals
        self.pending_approvals: Dict[str, asyncio.Future] = {}
        
        # Decision log file
        self.decision_log = self.engagement_dir / "logs" / "decision_audit.log"
        self.decision_log.parent.mkdir(exist_ok=True)
        
        # Mock message log
        self.sent_messages: List[Dict] = []
        
    def _register_default_handlers(self):
        self.handlers = {
            '/start': self._handle_start,
            '/go': self._handle_go,
            '/hold': self._handle_hold,
            '/stop': self._handle_stop,
            '/status': self._handle_status,
            '/findings': self._handle_findings,
            '/report': self._handle_report,
            '/terse': self._handle_terse,
            '/caveman': self._handle_terse,
            '/scope': self._handle_scope,
            '/evidence': self._handle_evidence,
            '/help': self._handle_help,
        }
    
    async def initialize(self):
        """Initialize the mock bot."""
        logger.info("Mock Telegram bot initialized (no real Telegram connection)")
        # Send startup message
        await self.send_message(
            f"🦅 NIGHTFANG Online — Test Engagement\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 Target: Local Test Environment\n"
            f"📋 Type: whitebox\n"
            f"🔧 Agents: 2 max concurrent\n"
            f"⚡ Caveman Mode: {'ON' if self.rules_config.token_efficiency else 'OFF'}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Ready for Phase 1. Use /go to begin passive reconnaissance."
        )
    
    async def close(self):
        pass
    
    async def send_message(self, text: str, chat_id: Optional[str] = None, parse_mode: Optional[str] = None) -> dict:
        """Log message instead of sending to Telegram."""
        chat_id = chat_id or self.chat_id
        parse_mode = parse_mode or self.parse_mode
        
        # Truncate if needed
        if len(text) > self.max_length:
            text = text[:self.max_length - 50] + "\n\n... [truncated]"
        
        message = {
            'chat_id': chat_id,
            'text': text,
            'parse_mode': parse_mode,
            'timestamp': datetime.utcnow().isoformat()
        }
        self.sent_messages.append(message)
        
        # Print to console for testing
        print(f"\n{'='*60}")
        print(f"📱 TELEGRAM MESSAGE:")
        print(f"{'='*60}")
        print(text)
        print(f"{'='*60}\n")
        
        return {'ok': True, 'result': {'message_id': len(self.sent_messages)}}
    
    async def send_finding_alert(self, finding: dict, terse: bool = False):
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
    
    def _format_verbose_finding(self, finding: dict) -> str:
        fid = finding.get('id', 'UNKNOWN')
        target = finding.get('target', 'Unknown')
        ftype = finding.get('type', 'Unknown')
        conf = finding.get('confidence', 0)
        sev = finding.get('severity', 0)
        mitre = finding.get('mitre_attack', [])
        atlas = finding.get('mitre_atlas', [])
        d3fend = finding.get('d3fend', [])
        summary = finding.get('title', 'No summary')
        details = finding.get('evidence', 'No details')
        action = finding.get('proposed_action', 'Exploitation test')
        risk = finding.get('risk', 'Potential system compromise')
        
        conf_bar = '█' * (conf // 2) + '░' * (5 - conf // 2)
        sev_bar = '█' * (sev // 2) + '░' * (5 - sev // 2)
        
        framework_tags = []
        if mitre: framework_tags.append(f"ATT&CK: {', '.join(mitre)}")
        if atlas: framework_tags.append(f"ATLAS: {', '.join(atlas)}")
        if d3fend: framework_tags.append(f"D3FEND: {', '.join(d3fend)}")
        
        return f"""🔍 NIGHTFANG Finding #[{fid}]
━━━━━━━━━━━━━━━━━━━━━━
📎 Target: {target}
🎯 Type: {ftype}
📊 Confidence: {conf}/10 [{conf_bar}]
🔴 Severity: {sev}/10 [{sev_bar}]
🛡️ Frameworks: {', '.join(framework_tags) if framework_tags else 'N/A'}
📝 Summary: {summary}
💡 Details: {details}

🔧 Proposed Action: {action}
⚠️ Risk: {risk}

Reply: /go {fid} or /hold {fid}"""
    
    def _format_terse_finding(self, finding: dict) -> str:
        fid = finding.get('id', 'UNKNOWN')
        target = finding.get('target', 'Unknown')
        ftype = finding.get('type', 'Unknown')
        conf = finding.get('confidence', 0)
        sev = finding.get('severity', 0)
        action = finding.get('proposed_action', 'Exploit test')
        
        return f"""🔍 #{fid}: {ftype}
Target: {target} | Conf: {conf}/10 | Sev: {sev}/10
Action: {action}
Reply: /go {fid} or /hold {fid}"""
    
    async def send_status_update(self, phase: str, duration: str, targets_tested: str, findings: dict, queue: str, next_action: str):
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
        action = "STARTED" if starting else "COMPLETED"
        text = f"🔄 Phase {action}: {phase}"
        await self.send_message(text)
    
    async def send_engagement_complete(self, summary: dict):
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
    
    async def _handle_start(self, message: dict) -> str:
        return "🦅 NIGHTFANG Online — Ready for engagement. Use /help for commands."
    
    async def _handle_go(self, message: dict) -> str:
        parts = message.get('text', '').split()
        if len(parts) < 2:
            return "Usage: /go <finding_id>"
        
        finding_id = parts[1]
        if finding_id in self.pending_approvals:
            future = self.pending_approvals.pop(finding_id)
            future.set_result('go')
            self._log_decision(finding_id, 'go', 'Operator approved exploitation')
            return f"✅ Approved: {finding_id} — Proceeding with exploitation"
        else:
            return f"❌ No pending approval for {finding_id}"
    
    async def _handle_hold(self, message: dict) -> str:
        parts = message.get('text', '').split()
        if len(parts) < 2:
            return "Usage: /hold <finding_id>"
        
        finding_id = parts[1]
        reason = ' '.join(parts[2:]) if len(parts) > 2 else 'Operator denied/paused'
        
        if finding_id in self.pending_approvals:
            future = self.pending_approvals.pop(finding_id)
            future.set_result('hold')
            self._log_decision(finding_id, 'hold', reason)
            return f"⏸️ Held: {finding_id} — {reason}"
        else:
            self._log_decision(finding_id, 'hold', reason)
            return f"⏸️ Logged hold for {finding_id}: {reason}"
    
    async def _handle_stop(self, message: dict) -> str:
        self._log_decision('GLOBAL', 'stop', 'Emergency stop by operator')
        for fid, future in self.pending_approvals.items():
            if not future.done():
                future.set_result('stop')
        self.pending_approvals.clear()
        return "🛑 EMERGENCY STOP — All testing halted"
    
    async def _handle_status(self, message: dict) -> str:
        findings = self.memory.load_findings()
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 0)
            if sev >= 9: stats['critical'] += 1
            elif sev >= 7: stats['high'] += 1
            elif sev >= 5: stats['medium'] += 1
            elif sev >= 3: stats['low'] += 1
            else: stats['info'] += 1
        
        assets = self.memory.load_assets()
        
        return f"""📊 NIGHTFANG Status
━━━━━━━━━━━━━━━━━━
🎯 Assets Discovered: {len(assets)}
🔍 Findings: {stats['critical']}C {stats['high']}H {stats['medium']}M {stats['low']}L {stats['info']}I
⏳ Pending Approvals: {len(self.pending_approvals)}
🤖 Active Agents: {len([a for a in assets if a.get('status') in ['scanned', 'tested', 'exploited']])}"""
    
    async def _handle_findings(self, message: dict) -> str:
        findings = self.memory.load_findings()
        if not findings:
            return "No findings yet."
        
        lines = ["📋 Findings Summary\n━━━━━━━━━━━━━━━━━━"]
        for i, f in enumerate(findings, 1):
            sev_emoji = '🔴' if f.get('severity', 0) >= 9 else '🟠' if f.get('severity', 0) >= 7 else '🟡' if f.get('severity', 0) >= 5 else '🟢' if f.get('severity', 0) >= 3 else 'ℹ️'
            status = f.get('status', 'suspected')
            decision = f.get('operator_decision', 'pending')
            lines.append(f"{i}. {sev_emoji} [{f.get('id')}] {f.get('title')} (Conf:{f.get('confidence')}/10 Sev:{f.get('severity')}/10) [{status}/{decision}]")
        
        return '\n'.join(lines)
    
    async def _handle_report(self, message: dict) -> str:
        return "📄 Report generation not yet implemented. Use the reporter agent."
    
    async def _handle_terse(self, message: dict) -> str:
        parts = message.get('text', '').split()
        if len(parts) < 2:
            return f"Caveman mode: {'ON' if self.compact_mode else 'OFF'}. Use /terse on|off"
        
        if parts[1].lower() in ('on', 'true', 'enable'):
            self.compact_mode = True
            return "🪨 Caveman mode ENABLED — terse updates active"
        elif parts[1].lower() in ('off', 'false', 'disable'):
            self.compact_mode = False
            return "📝 Caveman mode DISABLED — verbose updates active"
        return "Usage: /terse on|off"
    
    async def _handle_scope(self, message: dict) -> str:
        scope = self.memory.load_scope()
        if not scope:
            return "No scope loaded."
        
        lines = ["📍 Current Scope\n━━━━━━━━━━━━━━━━━━"]
        lines.append("In Scope:")
        for k, v in scope.get('in_scope', {}).items():
            lines.append(f"  {k}: {', '.join(v) if v else 'None'}")
        lines.append("\nOut of Scope:")
        for k, v in scope.get('out_of_scope', {}).items():
            lines.append(f"  {k}: {', '.join(v) if v else 'None'}")
        if scope.get('rules_of_engagement'):
            lines.append("\nRules of Engagement:")
            for r in scope['rules_of_engagement']:
                lines.append(f"  - {r}")
        
        return '\n'.join(lines)
    
    async def _handle_evidence(self, message: dict) -> str:
        parts = message.get('text', '').split()
        if len(parts) < 2:
            return "Usage: /evidence <finding_id>"
        
        finding_id = parts[1]
        evidence = self.memory.get_evidence_for_finding(finding_id)
        if not evidence:
            return f"No evidence found for {finding_id}"
        
        lines = [f"📁 Evidence for {finding_id}:\n━━━━━━━━━━━━━━━━━━"]
        for e in evidence:
            lines.append(f"- {e['type']}: {e['file']} ({e['timestamp']})")
        
        return '\n'.join(lines)
    
    async def _handle_help(self, message: dict) -> str:
        return """🤖 NIGHTFANG Commands
━━━━━━━━━━━━━━━━━━
/start — Initialize engagement
/go <id> — Approve exploitation for finding
/go chain <id> — Approve attack chain
/hold <id> [reason] — Pause/deny finding
/hold chain <id> — Pause/deny chain
/hold — Pause current phase
/stop — Emergency kill all testing
/status — Show engagement status
/findings — List all findings
/report — Generate full report
/terse on|off — Toggle Caveman mode
/scope — Show current scope
/evidence <id> — Show evidence for finding
/chain <id> — Show attack chain diagram
/help — This help"""
    
    def _log_decision(self, finding_id: str, response: str, notes: str):
        decision = Decision(
            timestamp=datetime.utcnow().isoformat(),
            finding_id=finding_id,
            action_requested='exploitation' if response != 'stop' else 'emergency_stop',
            operator_response=response,
            notes=notes
        )
        self.memory.log_decision(decision)
        
        with open(self.decision_log, 'a') as f:
            f.write(f"{decision.timestamp} | {finding_id} | {response} | {notes}\n")
    
    async def process_update(self, update: dict):
        """Process a simulated Telegram update."""
        message = update.get('message') or update.get('edited_message')
        if not message:
            return
        
        chat_id = str(message.get('chat', {}).get('id', ''))
        # In mock mode, accept all chats
        
        text = message.get('text', '').strip()
        if not text:
            return
        
        # Find matching command
        for cmd, handler in self.handlers.items():
            if text.startswith(cmd):
                try:
                    response = await handler(message)
                    if response:
                        await self.send_message(response)
                except Exception as e:
                    logger.error(f"Handler error for {cmd}: {e}")
                    await self.send_message(f"❌ Error: {e}")
                return
        
        await self.send_message(f"Unknown command: {text}. Use /help")
    
    async def wait_for_approval(self, finding_id: str, timeout: int = 300) -> str:
        """Wait for operator approval on a finding."""
        if finding_id not in self.pending_approvals:
            return 'hold'
        
        # In test mode, auto-approve after a short delay
        if self.config.bot_token in ('your_bot_token_here', '', 'test'):
            await asyncio.sleep(0.1)
            future = self.pending_approvals.pop(finding_id, None)
            if future and not future.done():
                future.set_result('go')
            return 'go'
        
        try:
            return await asyncio.wait_for(self.pending_approvals[finding_id], timeout=timeout)
        except asyncio.TimeoutError:
            self.pending_approvals.pop(finding_id, None)
            self._log_decision(finding_id, 'timeout', 'Operator did not respond in time')
            return 'hold'
    
    def simulate_command(self, text: str):
        """Simulate a Telegram command for testing."""
        update = {
            'message': {
                'chat': {'id': self.chat_id},
                'text': text
            }
        }
        return asyncio.create_task(self.process_update(update))


# Factory function to create appropriate bot
async def create_telegram_bot(config: TelegramConfig, rules_config: RulesConfig, memory: MemoryManager, engagement_dir: Path, mock: bool = False):
    """Factory to create real or mock Telegram bot."""
    if mock or config.bot_token in ('your_bot_token_here', '', 'test'):
        logger.info("Using MOCK Telegram bot for testing")
        return MockTelegramBot(config, rules_config, memory, engagement_dir)
    else:
        # Import real bot dynamically to avoid import errors if aiohttp not available
        from .telegram_bot import TelegramBot
        return TelegramBot(config, memory, engagement_dir)