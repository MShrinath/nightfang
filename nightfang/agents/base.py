"""Base agent class for all swarm agents."""
import asyncio
import logging
import os
import shlex
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset, TimelineEvent
from ..core.telegram_bot import TelegramBot

logger = logging.getLogger(__name__)


class AgentTier(Enum):
    """Agent tier classification - Tier 1: read-only/advisory, Tier 2: Bash/execution capable."""
    TIER_1_ADVISORY = "advisory"  # Read, Write, Edit, Grep, Glob, WebFetch, WebSearch
    TIER_2_EXECUTION = "execution"  # Tier 1 + Bash


@dataclass
class ToolResult:
    tool: str
    command: str
    stdout: str
    stderr: str
    returncode: int
    duration: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ScopeDeclaration:
    """Mandatory scope declaration for session."""
    engagement_type: str  # external, internal, webapp, cloud, wireless, etc.
    authorized_ips: List[str]
    authorized_domains: List[str]
    authorized_urls: List[str]
    authorized_cloud_accounts: List[str]
    rate_limits: Dict[str, Any] = field(default_factory=dict)
    time_restrictions: Dict[str, str] = field(default_factory=dict)
    destructive_actions_allowed: bool = False
    declared_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    declared_by: str = "operator"


class BaseAgent(ABC):
    """Base class for all swarm agents with mandatory scope enforcement."""

    def __init__(
        self,
        name: str,
        role: str,
        config: EngagementConfig,
        agent_config: AgentConfig,
        scope_validator: ScopeValidator,
        memory: MemoryManager,
        telegram: TelegramBot,
        skills: List[str] = None,
        tools_required: List[str] = None,
        hitl_required: bool = False,
        hitl_checkpoints: List[str] = None,
        max_runtime_minutes: int = 60,
        tier: AgentTier = AgentTier.TIER_1_ADVISORY,
        trigger_phrases: List[str] = None,
        model: str = "sonnet",
        description: str = ""
    ):
        self.name = name
        self.role = role
        self.config = config
        self.agent_config = agent_config
        self.scope = scope_validator
        self.memory = memory
        self.telegram = telegram
        self.skills = skills or []
        self.tools_required = tools_required or []
        self.hitl_required = hitl_required
        self.hitl_checkpoints = hitl_checkpoints or []
        self.max_runtime_minutes = max_runtime_minutes
        self.tier = tier
        self.trigger_phrases = trigger_phrases or []
        self.model = model
        self.description = description

        self.calibration = agent_config.calibration
        self.terse_mode = config.rules.token_efficiency
        self.findings: List[Finding] = []
        self.assets: List[Asset] = []

        # Scope enforcement state
        self._scope_declaration: Optional[ScopeDeclaration] = None
        self._scope_declared = False
        self._scope_guard_enabled = True

        # Tool availability cache
        self._tool_cache: Dict[str, bool] = {}
    
    @abstractmethod
    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Main execution method. Must be implemented by subclasses."""
        pass
    
    async def execute_tool(
        self,
        tool: str,
        args: List[str],
        timeout: int = 300,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ToolResult:
        """Execute a tool command and capture output as evidence."""
        start = datetime.utcnow()
        cmd = [tool] + args
        cmd_str = ' '.join(shlex.quote(c) for c in cmd)
        
        logger.info(f"[{self.name}] Executing: {cmd_str}")
        
        # Prepare environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=run_env
            )
            
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            duration = (datetime.utcnow() - start).total_seconds()
            
            result = ToolResult(
                tool=tool,
                command=cmd_str,
                stdout=stdout.decode('utf-8', errors='replace'),
                stderr=stderr.decode('utf-8', errors='replace'),
                returncode=proc.returncode,
                duration=duration
            )
            
            # Save as evidence
            await self._save_command_evidence(result)
            
            return result
            
        except asyncio.TimeoutError:
            duration = (datetime.utcnow() - start).total_seconds()
            return ToolResult(
                tool=tool,
                command=cmd_str,
                stdout="",
                stderr=f"TIMEOUT after {timeout}s",
                returncode=-1,
                duration=duration
            )
        except FileNotFoundError:
            return ToolResult(
                tool=tool,
                command=cmd_str,
                stdout="",
                stderr=f"Tool not found: {tool}",
                returncode=-1,
                duration=0
            )
        except Exception as e:
            duration = (datetime.utcnow() - start).total_seconds()
            return ToolResult(
                tool=tool,
                command=cmd_str,
                stdout="",
                stderr=str(e),
                returncode=-1,
                duration=duration
            )
    
    async def _save_command_evidence(self, result: ToolResult):
        """Save tool execution as evidence."""
        content = f"""COMMAND: {result.command}
RETURN CODE: {result.returncode}
DURATION: {result.duration:.2f}s
TIMESTAMP: {result.timestamp}

STDOUT:
{result.stdout}

STDERR:
{result.stderr}
"""
        self.memory.save_evidence(
            finding_id=f"{self.name}_{result.tool}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            evidence_type="commands",
            content=content,
            metadata={
                'tool': result.tool,
                'returncode': result.returncode,
                'duration': result.duration,
                'agent': self.name
            }
        )
    
    async def check_tool(self, tool: str) -> bool:
        """Check if a tool is available."""
        if tool in self._tool_cache:
            return self._tool_cache[tool]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                'which', tool,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.communicate()
            available = proc.returncode == 0
        except Exception:
            available = False
        
        self._tool_cache[tool] = available
        if not available:
            logger.warning(f"[{self.name}] Tool not found: {tool}")
        return available
    
    async def check_all_tools(self) -> Dict[str, bool]:
        """Check all required tools."""
        results = {}
        for tool in self.tools_required:
            results[tool] = await self.check_tool(tool)
        return results
    
    def validate_target(self, target: str, port: int = None) -> bool:
        """Validate target against scope."""
        result = self.scope.validate_target(target, port)
        if not result.allowed:
            logger.warning(f"[{self.name}] Target blocked: {target} - {result.reason}")
            self.memory.log_event(TimelineEvent(
                timestamp=datetime.utcnow().isoformat(),
                phase=self.name.lower().replace('_agent', ''),
                agent=self.name,
                action=f"Scope validation failed for {target}",
                result=result.reason
            ))
        return result.allowed

    def declare_scope(self, scope: ScopeDeclaration) -> None:
        """Declare and store the authorized scope for this session."""
        self._scope_declaration = scope
        self._scope_declared = True
        logger.info(f"[{self.name}] Scope declared: {scope.engagement_type}")

    def check_scope(self, target: str, action: str = "execute command") -> bool:
        """
        Mandatory pre-execution scope check.
        Must be called before ANY Bash command execution against a target.
        """
        if not self._scope_guard_enabled:
            return True

        if not self._scope_declared or self._scope_declaration is None:
            logger.error(f"[{self.name}] SCOPE VIOLATION: No scope declared before {action}")
            self.memory.log_event(TimelineEvent(
                timestamp=datetime.utcnow().isoformat(),
                phase="scope_enforcement",
                agent=self.name,
                action=f"Blocked {action} - no scope declared",
                result="SCOPE_GUARD_BLOCKED"
            ))
            return False

        # Validate target against declared scope
        scope = self._scope_declaration
        allowed = False

        if target in scope.authorized_ips:
            allowed = True
        elif any(self._domain_match(target, d) for d in scope.authorized_domains):
            allowed = True
        elif any(target.startswith(u) for u in scope.authorized_urls):
            allowed = True

        if not allowed:
            logger.error(f"[{self.name}] SCOPE VIOLATION: Target {target} not in declared scope")
            self.memory.log_event(TimelineEvent(
                timestamp=datetime.utcnow().isoformat(),
                phase="scope_enforcement",
                agent=self.name,
                action=f"Blocked {action} - target out of scope",
                result="SCOPE_GUARD_BLOCKED"
            ))
            return False

        # Check for destructive actions
        destructive_keywords = ['delete', 'drop', 'remove', 'destroy', 'wipe', 'format', 'dos', 'flood', 'spray']
        if any(k in action.lower() for k in destructive_keywords) and not scope.destructive_actions_allowed:
            logger.error(f"[{self.name}] SCOPE VIOLATION: Destructive action not authorized: {action}")
            return False

        return True

    def _domain_match(self, target: str, domain_pattern: str) -> bool:
        """Check if target matches domain pattern (supports wildcards)."""
        if domain_pattern.startswith('*.'):
            return target.endswith(domain_pattern[2:]) or target == domain_pattern[2:]
        return target == domain_pattern
    
    async def request_approval(self, finding: Finding, proposed_action: str, risk: str) -> str:
        """Request operator approval for exploitation."""
        finding.proposed_action = proposed_action
        finding.risk = risk
        
        # Save finding first
        self.memory.add_finding(finding)
        
        # Send to Telegram
        future = await self.telegram.send_finding_alert(
            finding={
                'id': finding.id,
                'target': finding.target,
                'type': finding.type,
                'confidence': finding.confidence,
                'severity': finding.severity,
                'title': finding.title,
                'evidence': finding.evidence,
                'mitre_attack': finding.mitre_attack,
                'mitre_atlas': finding.mitre_atlas,
                'd3fend': finding.d3fend,
                'proposed_action': proposed_action,
                'risk': risk
            },
            terse=self.terse_mode
        )
        
        # Wait for approval
        decision = await self.telegram.wait_for_approval(finding.id)
        
        # Update finding with decision
        self.memory.update_finding(finding.id, operator_decision=decision)
        
        return decision
    
    def log_event(self, phase: str, action: str, result: str, finding_ids: List[str] = None):
        """Log a timeline event."""
        self.memory.log_event(TimelineEvent(
            timestamp=datetime.utcnow().isoformat(),
            phase=phase,
            agent=self.name,
            action=action,
            result=result,
            finding_ids=finding_ids or []
        ))
    
    def add_finding(self, finding: Finding):
        """Add a finding to memory and local list."""
        self.memory.add_finding(finding)
        self.findings.append(finding)
    
    def add_asset(self, asset: Asset):
        """Add an asset to memory and local list."""
        self.memory.add_asset(asset)
        self.assets.append(asset)


import os  # for environ