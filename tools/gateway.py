#!/usr/bin/env python3
"""
NIGHTFANG Execution Policy Gateway (Executable Implementation)
Reference Specification: integration/execution-policy-gateway.md
SOP Mappings: SOP-01, SOP-02, SOP-04, SOP-05, SOP-06, SOP-07

The Execution Policy Gateway is the mandatory fail-closed enforcement layer
positioned between NIGHTFANG agents/skills and external tool execution
(network I/O, binary execution, shell commands, and API requests).
"""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


# ============================================================================
# Enums and Constants
# ============================================================================

class NoiseProfile(str, Enum):
    QUIET = "QUIET"
    MODERATE = "MODERATE"
    LOUD = "LOUD"


class AutonomyTier(str, Enum):
    REACTIVE = "REACTIVE"              # Halts on any moderate/loud active probe for manual confirmation
    SEMI_AUTONOMOUS = "SEMI_AUTONOMOUS"# Traffic Light: Auto-runs GREEN (passive) & YELLOW (moderate) at safe rates; queues RED (exploits) asynchronously
    FULL_AUTONOMOUS = "FULL_AUTONOMOUS"# Continuous: Auto-runs GREEN, YELLOW, and safe non-destructive RED PoCs within scope


class ActionType(str, Enum):
    PASSIVE_READ = "PASSIVE_READ"
    ACTIVE_PROBE = "ACTIVE_PROBE"
    EXPLOIT_POC = "EXPLOIT_POC"


class DispositionStatus(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    HELD = "HELD"
    QUEUED = "QUEUED"
    HITL_REQUIRED = "HITL_REQUIRED"


# Gateway Error and Reason Codes
CODE_SCOPE_VIOLATION = "SCOPE_VIOLATION"
CODE_CLOUD_EDGE_VIOLATION = "CLOUD_EDGE_SCAN_PROHIBITED"
CODE_MISSING_OPSEC_DECLARATION = "MISSING_OPSEC_DECLARATION"
CODE_OPSEC_PROFILE_EXCEEDED = "OPSEC_PROFILE_EXCEEDED"
CODE_EMERGENCY_STOP_ACTIVE = "EMERGENCY_STOP_ACTIVE"
CODE_CONCURRENCY_EXCEEDED = "CONCURRENCY_EXCEEDED"
CODE_PORT_LOCKED = "PORT_LOCKED"
CODE_RATE_BACKOFF_ACTIVE = "RATE_BACKOFF_ACTIVE"
CODE_HITL_APPROVAL_REQUIRED = "OPERATOR_APPROVAL_REQUIRED"
CODE_HITL_TOKEN_INVALID = "HITL_TOKEN_INVALID"
CODE_DESTRUCTIVE_PAYLOAD_DETECTED = "DESTRUCTIVE_PAYLOAD_DETECTED"
CODE_UNAUTHORIZED_OPERATOR = "UNAUTHORIZED_OPERATOR"
CODE_TOKEN_EXPIRED = "TOKEN_EXPIRED"
CODE_EXECUTION_ERROR = "EXECUTION_ERROR"

# Defaults
DEFAULT_SAFE_RATE = 20  # req/sec safe default
PERMISSIBLE_CEILING_RATE = 100  # req/sec hard maximum ceiling
DEFAULT_BACKOFF_DURATION = 30.0  # seconds
DEFAULT_MAX_CONCURRENCY = 7

# SOP-05 Destructive Command Filter Pattern
DESTRUCTIVE_COMMAND_REGEX = re.compile(
    r"(?i)(?:\b(rm\s+-[rf]{1,2}|DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+|DELETE\s+FROM|"
    r"UPDATE\s+.*SET|shutdown|reboot|netcat\s+-e|nc\s+-e|useradd|adduser|mkfs)\b|"
    r"\bdd\s+if=|:\(\)\{.*?\}|\brm\s+-[a-zA-Z]*r[a-zA-Z]*\b)"
)

# Shared Cloud / Edge Multi-Tenant Providers
SHARED_CLOUD_EDGE_PATTERNS = [
    re.compile(r"(?i)(?:\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|s3\.amazonaws\.com)$"),
    re.compile(r"(?i)\.blob\.core\.windows\.net$"),
    re.compile(r"(?i)\.cloudflare\.com$"),
    re.compile(r"(?i)\.azureedge\.net$"),
    re.compile(r"(?i)\.cloudfront\.net$"),
    re.compile(r"(?i)\.fastly\.net$"),
    re.compile(r"(?i)(?:\.storage\.googleapis\.com|storage\.googleapis\.com)$"),
    re.compile(r"(?i)(?:\.akamaihd\.net|\.edgekey\.net|\.akamaiedge\.net)$"),
]


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class TargetSpec:
    raw_target: str
    hostname: str = ""
    ip: str = ""
    port: int = 0
    scheme: str = "http"

    def parse_target(self) -> None:
        """Parse raw target string into constituent components."""
        target_str = self.raw_target.strip()
        if not target_str:
            return

        # Check for URL scheme
        if "://" in target_str:
            parsed = urllib.parse.urlparse(target_str)
            self.scheme = parsed.scheme.lower() or "http"
            self.hostname = (parsed.hostname or "").strip("[]")
            if parsed.port:
                self.port = parsed.port
            elif self.scheme == "https":
                self.port = 443
            elif self.scheme == "http":
                self.port = 80
        elif target_str.startswith("["):
            # Bracketed IPv6 notation, possibly with port: [2001:db8::1] or [2001:db8::1]:8080
            bracket_end = target_str.find("]")
            if bracket_end != -1:
                self.hostname = target_str[1:bracket_end]
                rest = target_str[bracket_end + 1:]
                if rest.startswith(":") and rest[1:].isdigit():
                    self.port = int(rest[1:])
            else:
                self.hostname = target_str.strip("[]")
        elif ":" in target_str:
            # Could be host:port (IPv4/domain) or unbracketed IPv6
            try:
                ipaddress.IPv6Address(target_str)
                self.hostname = target_str
            except ValueError:
                parts = target_str.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    self.hostname = parts[0].strip("[]")
                    self.port = int(parts[1])
                else:
                    self.hostname = target_str.strip("[]")
        else:
            self.hostname = target_str.strip("[]")

        # Automatically populate ip if hostname is a valid IP address
        if self.hostname and not self.ip:
            try:
                ipaddress.ip_address(self.hostname)
                self.ip = self.hostname
            except ValueError:
                pass


@dataclass
class OpsecSpec:
    noise: NoiseProfile
    rationale: str = ""


@dataclass
class ToolInvocationRequest:
    request_id: str
    engagement_id: str
    agent_id: str
    skill_id: str
    tool_name: str
    target: TargetSpec
    opsec: Optional[OpsecSpec]
    command_template: str
    action_type: ActionType
    technique: str
    payload: str = ""
    canaries: List[str] = field(default_factory=list)
    finding_id: str = ""
    severity_hint: int = 5


@dataclass
class HitlApprovalToken:
    token_id: str
    engagement_id: str
    operator_id: str
    finding_id: str
    technique: str
    tool_name: str
    expires_at: float  # Unix timestamp
    created_at: float = field(default_factory=time.time)

    def is_valid_for(self, req: ToolInvocationRequest, authorized_operator: str) -> Tuple[bool, str]:
        now = time.time()
        if now > self.expires_at:
            return False, f"Token expired at {self.expires_at} (current: {now})"
        if self.engagement_id != req.engagement_id:
            return False, f"Engagement ID mismatch: {self.engagement_id} != {req.engagement_id}"
        if self.operator_id != authorized_operator:
            return False, f"Operator mismatch: {self.operator_id} != {authorized_operator}"
        if self.finding_id and req.finding_id and self.finding_id != req.finding_id:
            return False, f"Finding ID mismatch: {self.finding_id} != {req.finding_id}"
        if self.technique != req.technique:
            return False, f"Technique mismatch: {self.technique} != {req.technique}"
        if self.tool_name != req.tool_name:
            return False, f"Tool mismatch: {self.tool_name} != {req.tool_name}"
        return True, "Valid"


@dataclass
class GatewayDisposition:
    status: DispositionStatus
    code: str
    reason: str
    modified_command: str = ""
    hitl_request: Optional[Dict[str, Any]] = None


@dataclass
class ToolExecutionResult:
    request_id: str
    status: str  # SUCCESS, FAILED, TIMEOUT
    exit_code: int
    raw_stdout: str
    raw_stderr: str
    stdout_sha256: str
    stderr_sha256: str
    payload_sha256: str
    execution_duration_ms: int
    timestamp: str


# ============================================================================
# Engagement Context & State Store
# ============================================================================

@dataclass
class EngagementConfig:
    engagement_id: str
    authorized_operator: str = "operator"
    authorized_cidrs: List[str] = field(default_factory=list)
    authorized_domains: List[str] = field(default_factory=list)
    max_opsec_noise: NoiseProfile = NoiseProfile.LOUD
    operator_defined_rate: Optional[int] = None
    max_concurrency_per_host: int = DEFAULT_MAX_CONCURRENCY
    strict_hitl: bool = False
    autonomy_tier: AutonomyTier = AutonomyTier.SEMI_AUTONOMOUS


class EngagementState:
    def __init__(self, config: EngagementConfig):
        self.config = config
        self.is_emergency_stopped = False
        self.active_hosts_concurrency: Dict[str, int] = {}
        self.active_port_locks: Set[str] = set()  # "ip:port"
        self.crawled_endpoints: Dict[str, str] = {}  # endpoint -> cached_result
        self.active_finding_locks: Set[str] = set()  # finding_id
        self.rate_state: Dict[str, Dict[str, Any]] = {}  # host -> {backoff_until, current_rate}
        self.hitl_tokens: Dict[str, HitlApprovalToken] = {}
        self.pending_hitl_requests: Dict[str, ToolInvocationRequest] = {}
        self.cleanup_inventory: List[str] = []
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "details": details,
        }
        self.audit_log.append(entry)

    def trigger_emergency_stop(self, reason: str = "Operator commanded /stop") -> None:
        self.is_emergency_stopped = True
        self.log_audit("EMERGENCY_STOP_TRIGGERED", {"reason": reason})

    def resume_emergency_stop(self) -> None:
        self.is_emergency_stopped = False
        self.log_audit("EMERGENCY_STOP_RESUMED", {})

    def trigger_rate_backoff(self, hostname: str, reason: str = "HTTP 429/503 received") -> None:
        state = self.rate_state.get(hostname, {})
        current_rate = state.get("current_rate", self.config.operator_defined_rate or DEFAULT_SAFE_RATE)
        new_rate = max(1, current_rate // 2)
        backoff_until = time.time() + DEFAULT_BACKOFF_DURATION
        self.rate_state[hostname] = {
            "current_rate": new_rate,
            "backoff_until": backoff_until,
        }
        self.log_audit("RATE_BACKOFF_TRIGGERED", {
            "hostname": hostname,
            "old_rate": current_rate,
            "new_rate": new_rate,
            "backoff_until": backoff_until,
            "reason": reason,
        })


# ============================================================================
# Execution Policy Gateway Pipeline
# ============================================================================

class ExecutionPolicyGateway:
    def __init__(self, state: EngagementState, resolve_dns: bool = False):
        self.state = state
        self.resolve_dns = resolve_dns

    # ------------------------------------------------------------------------
    # Stage 1: Scope & Target Boundary Enforcement (SOP-01)
    # ------------------------------------------------------------------------
    def stage1_scope_and_opsec(self, req: ToolInvocationRequest) -> Optional[GatewayDisposition]:
        target = req.target
        target.parse_target()

        # 1. OPSEC declaration check
        if not req.opsec or not req.opsec.noise:
            return GatewayDisposition(
                status=DispositionStatus.REJECTED,
                code=CODE_MISSING_OPSEC_DECLARATION,
                reason="Every tool invocation request must declare an OPSEC noise classification (QUIET, MODERATE, LOUD) and rationale.",
            )

        req_noise = req.opsec.noise
        max_noise = self.state.config.max_opsec_noise

        noise_hierarchy = {NoiseProfile.QUIET: 1, NoiseProfile.MODERATE: 2, NoiseProfile.LOUD: 3}
        if noise_hierarchy.get(req_noise, 3) > noise_hierarchy.get(max_noise, 3):
            return GatewayDisposition(
                status=DispositionStatus.REJECTED,
                code=CODE_OPSEC_PROFILE_EXCEEDED,
                reason=f"Requested action noise profile [{req_noise.value}] exceeds engagement configured threshold [{max_noise.value}].",
            )

        # 2. Scope verification (Domain & CIDR)
        hostname = target.hostname.lower()
        if not hostname:
            return GatewayDisposition(
                status=DispositionStatus.REJECTED,
                code=CODE_SCOPE_VIOLATION,
                reason="Target specification does not contain a valid hostname or IP address.",
            )

        # Check multi-tenant shared cloud guardrail
        for pattern in SHARED_CLOUD_EDGE_PATTERNS:
            if pattern.search(hostname):
                # Disallow raw cloud edge infrastructure scanning
                if req.action_type in (ActionType.ACTIVE_PROBE, ActionType.EXPLOIT_POC) and req.opsec.noise == NoiseProfile.LOUD:
                    return GatewayDisposition(
                        status=DispositionStatus.REJECTED,
                        code=CODE_CLOUD_EDGE_VIOLATION,
                        reason=f"Target [{hostname}] is a multi-tenant cloud/CDN edge domain. LOUD active probing is prohibited per SOP-01.",
                    )

        # Domain whitelist matching
        in_scope_domain = False
        for auth_domain in self.state.config.authorized_domains:
            auth_domain = auth_domain.lower()
            if auth_domain.startswith("*."):
                wildcard_base = auth_domain[2:]
                if hostname == wildcard_base or hostname.endswith("." + wildcard_base):
                    in_scope_domain = True
                    break
            elif hostname == auth_domain:
                in_scope_domain = True
                break

        # Check IP/CIDR matching
        in_scope_ip = False
        target_ip = target.ip
        clean_host = hostname.strip("[]")
        if not target_ip:
            try:
                # Test if hostname itself is an IP address
                ipaddress.ip_address(clean_host)
                target_ip = clean_host
                target.ip = target_ip
            except ValueError:
                pass

        if not target_ip and self.resolve_dns:
            try:
                target_ip = socket.gethostbyname(clean_host)
                target.ip = target_ip
            except Exception:
                pass

        if target_ip:
            try:
                ip_obj = ipaddress.ip_address(target_ip.strip("[]"))
                for cidr_str in self.state.config.authorized_cidrs:
                    net_obj = ipaddress.ip_network(cidr_str, strict=False)
                    if ip_obj in net_obj:
                        in_scope_ip = True
                        break
            except Exception:
                pass

        # If both domains and CIDRs are configured, either matching can authorize
        if self.state.config.authorized_domains or self.state.config.authorized_cidrs:
            if not in_scope_domain and not in_scope_ip:
                return GatewayDisposition(
                    status=DispositionStatus.REJECTED,
                    code=CODE_SCOPE_VIOLATION,
                    reason=f"Target [{hostname}] (IP: {target_ip or 'unresolved'}) is not within authorized engagement domains or CIDRs.",
                )

        return None

    # ------------------------------------------------------------------------
    # Stage 2: Emergency Stop & Deconfliction (SOP-07, Heuristics §4)
    # ------------------------------------------------------------------------
    def stage2_emergency_stop_and_locking(self, req: ToolInvocationRequest) -> Optional[GatewayDisposition]:
        # 1. Emergency stop check
        if self.state.is_emergency_stopped:
            return GatewayDisposition(
                status=DispositionStatus.REJECTED,
                code=CODE_EMERGENCY_STOP_ACTIVE,
                reason="Engagement is halted under SOP-07 emergency stop. No tool execution permitted.",
            )

        target_host = req.target.hostname.lower()

        # 2. Concurrency limit check
        current_concurrency = self.state.active_hosts_concurrency.get(target_host, 0)
        if current_concurrency >= self.state.config.max_concurrency_per_host:
            return GatewayDisposition(
                status=DispositionStatus.QUEUED,
                code=CODE_CONCURRENCY_EXCEEDED,
                reason=f"Active concurrency cap of {self.state.config.max_concurrency_per_host} reached for host [{target_host}]. Request queued.",
            )

        # 3. Port lock check
        if req.target.ip and req.target.port:
            port_key = f"{req.target.ip}:{req.target.port}"
            if port_key in self.state.active_port_locks:
                return GatewayDisposition(
                    status=DispositionStatus.QUEUED,
                    code=CODE_PORT_LOCKED,
                    reason=f"Port lock active on {port_key}. Awaiting subagent release.",
                )

        # 4. Passive read deduplication
        if req.action_type == ActionType.PASSIVE_READ:
            cached = self.state.crawled_endpoints.get(req.target.raw_target)
            if cached:
                return GatewayDisposition(
                    status=DispositionStatus.APPROVED,
                    code="CACHE_HIT",
                    reason="Endpoint already crawled; returning cached output without network I/O.",
                    modified_command="CACHED",
                )

        return None

    # ------------------------------------------------------------------------
    # Stage 3: Rate Limiting & Backoff Throttle (SOP-02)
    # ------------------------------------------------------------------------
    def stage3_rate_limiting(self, req: ToolInvocationRequest) -> Tuple[Optional[GatewayDisposition], str]:
        hostname = req.target.hostname.lower()
        now = time.time()

        # Check backoff window
        rate_info = self.state.rate_state.get(hostname, {})
        backoff_until = rate_info.get("backoff_until", 0.0)
        if now < backoff_until:
            wait_sec = round(backoff_until - now, 1)
            return (
                GatewayDisposition(
                    status=DispositionStatus.QUEUED,
                    code=CODE_RATE_BACKOFF_ACTIVE,
                    reason=f"Host [{hostname}] is in 30-second backoff window ({wait_sec}s remaining) following HTTP 429/503.",
                ),
                req.command_template,
            )

        # Determine active rate
        if self.state.config.operator_defined_rate:
            active_rate = self.state.config.operator_defined_rate
        else:
            active_rate = rate_info.get("current_rate", DEFAULT_SAFE_RATE)

        # Apply ceiling
        active_rate = min(active_rate, PERMISSIBLE_CEILING_RATE)
        active_rate = max(1, active_rate)

        # Parameter injection and clamping into command template
        cmd = req.command_template
        tool_name = req.tool_name.lower()

        if "ffuf" in tool_name or tool_name == "ffuf":
            rate_match = re.search(r"(?:^|\s)-rate\s+(\d+)", cmd)
            if rate_match:
                specified_rate = int(rate_match.group(1))
                if specified_rate > active_rate:
                    cmd = re.sub(r"(?<=\s-rate\s)\d+", str(active_rate), cmd)
            else:
                cmd = f"{cmd} -rate {active_rate}"
        elif "nmap" in tool_name or tool_name == "nmap":
            rate_match = re.search(r"(?:^|\s)--max-rate\s+(\d+)", cmd)
            if rate_match:
                specified_rate = int(rate_match.group(1))
                if specified_rate > active_rate:
                    cmd = re.sub(r"(?<=\s--max-rate\s)\d+", str(active_rate), cmd)
            else:
                cmd = f"{cmd} --max-rate {active_rate}"

        return None, cmd

    # ------------------------------------------------------------------------
    # Stage 4: Action Classification & HITL Approval Gate (SOP-04, Heuristics §1b)
    # ------------------------------------------------------------------------
    def stage4_hitl_gate(self, req: ToolInvocationRequest) -> Optional[GatewayDisposition]:
        opsec_noise = req.opsec.noise if req.opsec else NoiseProfile.LOUD
        tier = self.state.config.autonomy_tier

        # Passive read + QUIET: auto-pass across all autonomy tiers
        if req.action_type == ActionType.PASSIVE_READ and opsec_noise == NoiseProfile.QUIET:
            return None

        # SEMI_AUTONOMOUS & FULL_AUTONOMOUS: Auto-pass MODERATE active probes (recon/directory/parameters)
        if (
            tier in (AutonomyTier.SEMI_AUTONOMOUS, AutonomyTier.FULL_AUTONOMOUS)
            and opsec_noise in (NoiseProfile.QUIET, NoiseProfile.MODERATE)
            and not self.state.config.strict_hitl
        ):
            return None

        # FULL_AUTONOMOUS: Auto-pass LOUD actions (relies on Stage 5 safety filter for protection)
        if tier == AutonomyTier.FULL_AUTONOMOUS and not self.state.config.strict_hitl:
            return None

        # Invasive, LOUD, or EXPLOIT_POC actions require valid 5-D HITL token
        token_found = None
        for tok in self.state.hitl_tokens.values():
            valid, msg = tok.is_valid_for(req, self.state.config.authorized_operator)
            if valid:
                token_found = tok
                break

        if token_found:
            return None  # Approved!

        # Token missing or invalid: pause execution and emit HITL request
        hitl_payload = {
            "event_type": "OPERATOR_APPROVAL_REQUIRED",
            "request_id": req.request_id,
            "finding_id": req.finding_id or "NONE",
            "target": req.target.raw_target,
            "proposed_action": req.technique,
            "opsec_noise": opsec_noise.value,
            "tool_name": req.tool_name,
            "command_preview": req.command_template,
            "severity_score": req.severity_hint,
            "reversible": len(req.canaries) > 0,
            "prompt": (
                f"⚠️ [HITL APPROVAL GATE]\n"
                f"Target: {req.target.raw_target}\n"
                f"Tool: {req.tool_name} (Noise: {opsec_noise.value})\n"
                f"Technique: {req.technique}\n"
                f"Command: {req.command_template}\n"
                f"Action: [ APPROVE ] or [ DENY ]\n"
                f"Reply: approve {req.request_id}\n"
                f"       deny {req.request_id}"
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        self.state.pending_hitl_requests[req.request_id] = req

        return GatewayDisposition(
            status=DispositionStatus.HITL_REQUIRED,
            code=CODE_HITL_APPROVAL_REQUIRED,
            reason="LOUD active probe or exploit PoC requires operator authorization via 5-D approval token.",
            hitl_request=hitl_payload,
        )

    # ------------------------------------------------------------------------
    # Stage 5: Non-Destructive PoC Safety Filter & Canaries (SOP-05)
    # ------------------------------------------------------------------------
    def stage5_safety_filter(self, req: ToolInvocationRequest, cmd: str) -> Optional[GatewayDisposition]:
        # 1. Prohibited destructive patterns filter
        match = DESTRUCTIVE_COMMAND_REGEX.search(cmd)
        if match:
            return GatewayDisposition(
                status=DispositionStatus.REJECTED,
                code=CODE_DESTRUCTIVE_PAYLOAD_DETECTED,
                reason=f"Command matches prohibited destructive pattern [{match.group(0)}] under SOP-05.",
            )

        if req.payload:
            payload_match = DESTRUCTIVE_COMMAND_REGEX.search(req.payload)
            if payload_match:
                return GatewayDisposition(
                    status=DispositionStatus.REJECTED,
                    code=CODE_DESTRUCTIVE_PAYLOAD_DETECTED,
                    reason=f"Payload contains prohibited destructive pattern [{payload_match.group(0)}] under SOP-05.",
                )

        # 2. Canary tracking
        if req.canaries:
            for c in req.canaries:
                if c not in self.state.cleanup_inventory:
                    self.state.cleanup_inventory.append(c)
            self.state.log_audit("CANARIES_REGISTERED", {"canaries": req.canaries, "request_id": req.request_id})

        return None

    # ------------------------------------------------------------------------
    # Full Evaluation Pipeline
    # ------------------------------------------------------------------------
    def evaluate(self, req: ToolInvocationRequest) -> GatewayDisposition:
        """Run Stages 1 through 5. Returns final disposition."""
        # Stage 1
        d1 = self.stage1_scope_and_opsec(req)
        if d1:
            self.state.log_audit("STAGE1_DISPOSITION", {"req_id": req.request_id, "code": d1.code, "reason": d1.reason})
            return d1

        # Stage 2
        d2 = self.stage2_emergency_stop_and_locking(req)
        if d2:
            self.state.log_audit("STAGE2_DISPOSITION", {"req_id": req.request_id, "code": d2.code, "reason": d2.reason})
            return d2

        # Stage 3
        d3, modified_cmd = self.stage3_rate_limiting(req)
        if d3:
            self.state.log_audit("STAGE3_DISPOSITION", {"req_id": req.request_id, "code": d3.code, "reason": d3.reason})
            return d3

        # Stage 4
        d4 = self.stage4_hitl_gate(req)
        if d4:
            self.state.log_audit("STAGE4_DISPOSITION", {"req_id": req.request_id, "code": d4.code, "reason": d4.reason})
            return d4

        # Stage 5
        d5 = self.stage5_safety_filter(req, modified_cmd)
        if d5:
            self.state.log_audit("STAGE5_DISPOSITION", {"req_id": req.request_id, "code": d5.code, "reason": d5.reason})
            return d5

        # All 5 gates passed
        return GatewayDisposition(
            status=DispositionStatus.APPROVED,
            code="PERMITTED",
            reason="Tool invocation request passed all 5 gateway verification gates.",
            modified_command=modified_cmd,
        )

    # ------------------------------------------------------------------------
    # Stage 6: Evidence Capture & Cryptographic Hashing Wrapper (SOP-06)
    # ------------------------------------------------------------------------
    def execute_and_wrap(
        self,
        req: ToolInvocationRequest,
        disposition: GatewayDisposition,
        sandbox_runner: Optional[Any] = None,
        timeout_seconds: int = 60,
    ) -> ToolExecutionResult:
        if disposition.status != DispositionStatus.APPROVED:
            raise ValueError(f"Cannot execute non-approved disposition: {disposition.status}")

        cmd = disposition.modified_command or req.command_template
        host = req.target.hostname.lower()

        # Update concurrency tracker
        self.state.active_hosts_concurrency[host] = self.state.active_hosts_concurrency.get(host, 0) + 1
        t0 = time.time()

        stdout_data = ""
        stderr_data = ""
        exit_code = 0
        status = "SUCCESS"

        try:
            if sandbox_runner is not None and hasattr(sandbox_runner, "run"):
                # Delegate to container sandbox
                res = sandbox_runner.run(cmd, timeout=timeout_seconds)
                exit_code = res.get("exit_code", 0)
                stdout_data = res.get("stdout", "")
                stderr_data = res.get("stderr", "")
                status = res.get("status", "SUCCESS")
            else:
                # Local safe execution fallback
                proc = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                )
                exit_code = proc.returncode
                stdout_data = proc.stdout
                stderr_data = proc.stderr
                status = "SUCCESS" if exit_code == 0 else "FAILED"
        except subprocess.TimeoutExpired:
            status = "TIMEOUT"
            exit_code = -1
            stderr_data = f"Tool execution timed out after {timeout_seconds}s."
        except Exception as e:
            status = "FAILED"
            exit_code = -1
            stderr_data = str(e)
        finally:
            self.state.active_hosts_concurrency[host] = max(0, self.state.active_hosts_concurrency.get(host, 1) - 1)

        duration_ms = int((time.time() - t0) * 1000)

        # Inspect for HTTP 429/503 response codes for auto-backoff
        if " 429 " in stdout_data or "429 Too Many" in stdout_data or " 503 " in stdout_data or "503 Service" in stdout_data:
            self.state.trigger_rate_backoff(host, reason="HTTP 429/503 detected in tool response stream")

        # Cryptographic Evidence Hashing (SOP-06)
        stdout_hash = hashlib.sha256(stdout_data.encode("utf-8")).hexdigest()
        stderr_hash = hashlib.sha256(stderr_data.encode("utf-8")).hexdigest()
        payload_hash = hashlib.sha256(req.payload.encode("utf-8")).hexdigest() if req.payload else ""

        result = ToolExecutionResult(
            request_id=req.request_id,
            status=status,
            exit_code=exit_code,
            raw_stdout=stdout_data,
            raw_stderr=stderr_data,
            stdout_sha256=stdout_hash,
            stderr_sha256=stderr_hash,
            payload_sha256=payload_hash,
            execution_duration_ms=duration_ms,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        self.state.log_audit("TOOL_EXECUTION_COMPLETED", {
            "request_id": req.request_id,
            "status": status,
            "stdout_sha256": stdout_hash,
            "duration_ms": duration_ms,
        })

        return result


# ============================================================================
# Token Management Helpers (Approve / Deny, /go and /hold)
# ============================================================================

def approve_request(
    state: EngagementState,
    request_id: str,
    operator_id: str = "operator",
    ttl_seconds: int = 300,
) -> HitlApprovalToken:
    """Approves a pending HITL request, minting a cryptographic 5-D execution token."""
    return issue_approval_token(state, request_id, operator_id, ttl_seconds)


def deny_request(state: EngagementState, request_id: str) -> bool:
    """Denies/cancels a pending HITL request, preventing active execution."""
    return hold_request(state, request_id)


def issue_approval_token(
    state: EngagementState,
    request_id: str,
    operator_id: str,
    ttl_seconds: int = 300,
) -> HitlApprovalToken:
    req = state.pending_hitl_requests.get(request_id)
    if not req:
        raise KeyError(f"No pending HITL request found with ID [{request_id}]")

    token_hash = hashlib.sha256(
        f"{req.engagement_id}:{operator_id}:{req.finding_id}:{req.technique}:{time.time()}".encode("utf-8")
    ).hexdigest()[:16]

    token = HitlApprovalToken(
        token_id=f"tok-{token_hash}",
        engagement_id=req.engagement_id,
        operator_id=operator_id,
        finding_id=req.finding_id,
        technique=req.technique,
        tool_name=req.tool_name,
        expires_at=time.time() + ttl_seconds,
    )

    state.hitl_tokens[token.token_id] = token
    state.log_audit("HITL_TOKEN_ISSUED", {"token_id": token.token_id, "request_id": request_id, "operator": operator_id})
    return token


def hold_request(state: EngagementState, request_id: str) -> bool:
    if request_id in state.pending_hitl_requests:
        req = state.pending_hitl_requests.pop(request_id)
        state.log_audit("HITL_REQUEST_HELD", {"request_id": request_id, "target": req.target.raw_target})
        return True
    return False


# ============================================================================
# Self Test & Verification Routine
# ============================================================================

def run_self_tests() -> bool:
    """Verifies all 6 stages of the Execution Policy Gateway."""
    print("Running NIGHTFANG Execution Policy Gateway Self-Tests...")

    cfg = EngagementConfig(
        engagement_id="ENG-2026-ALPHA",
        authorized_operator="lead-operator",
        authorized_cidrs=["192.168.1.0/24", "10.0.0.0/8"],
        authorized_domains=["*.target.corp", "target.corp", "api.internal"],
        max_opsec_noise=NoiseProfile.LOUD,
    )
    state = EngagementState(cfg)
    gw = ExecutionPolicyGateway(state, resolve_dns=False)

    # Test 1: Scope Violation
    req_out_of_scope = ToolInvocationRequest(
        request_id="req-01",
        engagement_id="ENG-2026-ALPHA",
        agent_id="recon",
        skill_id="skills/recon",
        tool_name="nmap",
        target=TargetSpec(raw_target="https://evil.external.com/"),
        opsec=OpsecSpec(noise=NoiseProfile.QUIET),
        command_template="nmap -sV evil.external.com",
        action_type=ActionType.PASSIVE_READ,
        technique="banner-grab",
    )
    d1 = gw.evaluate(req_out_of_scope)
    assert d1.status == DispositionStatus.REJECTED and d1.code == CODE_SCOPE_VIOLATION
    print("  [PASS] Test 1: Scope violation correctly blocked.")

    # Test 2: Missing OPSEC Declaration
    req_missing_opsec = ToolInvocationRequest(
        request_id="req-02",
        engagement_id="ENG-2026-ALPHA",
        agent_id="recon",
        skill_id="skills/recon",
        tool_name="curl",
        target=TargetSpec(raw_target="https://target.corp/"),
        opsec=None,
        command_template="curl https://target.corp/",
        action_type=ActionType.PASSIVE_READ,
        technique="banner-grab",
    )
    d2 = gw.evaluate(req_missing_opsec)
    assert d2.status == DispositionStatus.REJECTED and d2.code == CODE_MISSING_OPSEC_DECLARATION
    print("  [PASS] Test 2: Missing OPSEC declaration correctly rejected.")

    # Test 3: Emergency Stop Intercept
    state.trigger_emergency_stop("Test Stop")
    req_pass = ToolInvocationRequest(
        request_id="req-03",
        engagement_id="ENG-2026-ALPHA",
        agent_id="recon",
        skill_id="skills/recon",
        tool_name="curl",
        target=TargetSpec(raw_target="https://target.corp/"),
        opsec=OpsecSpec(noise=NoiseProfile.QUIET),
        command_template="curl https://target.corp/",
        action_type=ActionType.PASSIVE_READ,
        technique="banner-grab",
    )
    d3 = gw.evaluate(req_pass)
    assert d3.status == DispositionStatus.REJECTED and d3.code == CODE_EMERGENCY_STOP_ACTIVE
    print("  [PASS] Test 3: Emergency stop intercept enforced.")
    state.resume_emergency_stop()

    # Test 4: Rate Limiting Parameter Injection (FFUF)
    req_ffuf = ToolInvocationRequest(
        request_id="req-04",
        engagement_id="ENG-2026-ALPHA",
        agent_id="scanner",
        skill_id="skills/web",
        tool_name="ffuf",
        target=TargetSpec(raw_target="https://api.internal/v1"),
        opsec=OpsecSpec(noise=NoiseProfile.MODERATE),
        command_template="ffuf -u https://api.internal/v1/FUZZ -w wordlist.txt",
        action_type=ActionType.ACTIVE_PROBE,
        technique="fuzz-endpoints",
    )
    d4 = gw.evaluate(req_ffuf)
    assert d4.status == DispositionStatus.APPROVED
    assert "-rate 20" in d4.modified_command
    print("  [PASS] Test 4: Rate parameter auto-injection into tool command verified.")

    # Test 5: HITL Gate on LOUD Exploit PoC
    req_exploit = ToolInvocationRequest(
        request_id="req-05",
        engagement_id="ENG-2026-ALPHA",
        agent_id="validation",
        skill_id="skills/attack-chain",
        tool_name="nuclei",
        target=TargetSpec(raw_target="https://target.corp/login"),
        opsec=OpsecSpec(noise=NoiseProfile.LOUD),
        command_template="nuclei -target https://target.corp/login -id sqli-probe",
        action_type=ActionType.EXPLOIT_POC,
        technique="sqli-validation",
        finding_id="NF-2026-0001",
    )
    d5 = gw.evaluate(req_exploit)
    assert d5.status == DispositionStatus.HITL_REQUIRED
    assert d5.hitl_request is not None
    print("  [PASS] Test 5: HITL requirement triggered for LOUD exploit PoC.")

    # Test 5b: Issue Token & Re-evaluate
    tok = issue_approval_token(state, "req-05", "lead-operator", ttl_seconds=60)
    d5b = gw.evaluate(req_exploit)
    assert d5b.status == DispositionStatus.APPROVED
    print("  [PASS] Test 5b: Token validation and gate pass successful.")

    # Test 6: Destructive Command Filter (SOP-05)
    req_destructive = ToolInvocationRequest(
        request_id="req-06",
        engagement_id="ENG-2026-ALPHA",
        agent_id="validation",
        skill_id="skills/attack-chain",
        tool_name="curl",
        target=TargetSpec(raw_target="https://target.corp/"),
        opsec=OpsecSpec(noise=NoiseProfile.QUIET),
        command_template="curl -d 'cmd=rm -rf /' https://target.corp/",
        action_type=ActionType.PASSIVE_READ,
        technique="rce-test",
    )
    d6 = gw.evaluate(req_destructive)
    assert d6.status == DispositionStatus.REJECTED and d6.code == CODE_DESTRUCTIVE_PAYLOAD_DETECTED
    print("  [PASS] Test 6: Destructive command filter successfully blocked rm -rf.")

    # Test 7: IPv6 Parsing & CIDR Matching
    state.config.authorized_cidrs.append("2001:db8::/32")
    req_ipv6 = ToolInvocationRequest(
        request_id="req-07",
        engagement_id="ENG-2026-ALPHA",
        agent_id="scanner",
        skill_id="skills/network",
        tool_name="nmap",
        target=TargetSpec(raw_target="[2001:db8::1]:8080"),
        opsec=OpsecSpec(noise=NoiseProfile.MODERATE),
        command_template="nmap -6 [2001:db8::1] -p 8080",
        action_type=ActionType.ACTIVE_PROBE,
        technique="ipv6-port-scan",
    )
    d7 = gw.evaluate(req_ipv6)
    assert d7.status == DispositionStatus.APPROVED, f"IPv6 failed: {d7.code} {d7.reason}"
    assert req_ipv6.target.hostname == "2001:db8::1"
    assert req_ipv6.target.port == 8080
    assert req_ipv6.target.ip == "2001:db8::1"
    print("  [PASS] Test 7: IPv6 bracketed address parsing and CIDR matching verified.")

    # Test 8: Multi-tenant Cloud Edge S3 Detection
    req_s3 = ToolInvocationRequest(
        request_id="req-08",
        engagement_id="ENG-2026-ALPHA",
        agent_id="scanner",
        skill_id="skills/cloud",
        tool_name="curl",
        target=TargetSpec(raw_target="https://mybucket.s3.amazonaws.com/"),
        opsec=OpsecSpec(noise=NoiseProfile.LOUD),
        command_template="curl https://mybucket.s3.amazonaws.com/",
        action_type=ActionType.ACTIVE_PROBE,
        technique="s3-bucket-probe",
    )
    d8 = gw.evaluate(req_s3)
    assert d8.status == DispositionStatus.REJECTED and d8.code == CODE_CLOUD_EDGE_VIOLATION
    print("  [PASS] Test 8: Multi-tenant S3 edge domain LOUD active probing blocked.")

    # Test 9: Rate Clamping
    req_excessive_rate = ToolInvocationRequest(
        request_id="req-09",
        engagement_id="ENG-2026-ALPHA",
        agent_id="scanner",
        skill_id="skills/web",
        tool_name="ffuf",
        target=TargetSpec(raw_target="https://target.corp/"),
        opsec=OpsecSpec(noise=NoiseProfile.MODERATE),
        command_template="ffuf -rate 500 -u https://target.corp/FUZZ -w wordlist.txt",
        action_type=ActionType.ACTIVE_PROBE,
        technique="fuzz",
    )
    d9 = gw.evaluate(req_excessive_rate)
    assert d9.status == DispositionStatus.APPROVED
    assert "-rate 20" in d9.modified_command and "-rate 500" not in d9.modified_command
    print("  [PASS] Test 9: Excessive rate parameter clamped to active ceiling.")

    print("\nAll 9 Gateway self-tests PASSED successfully!")
    return True


if __name__ == "__main__":
    run_self_tests()
