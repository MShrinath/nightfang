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
import shutil
import sys
import tempfile
import re
import shlex
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
            try:
                if parsed.port:
                    self.port = parsed.port
                elif self.scheme == "https":
                    self.port = 443
                elif self.scheme == "http":
                    self.port = 80
            except (ValueError, TypeError):
                self.port = 443 if self.scheme == "https" else 80
        elif target_str.startswith("["):
            # Bracketed IPv6 notation, possibly with port: [2001:db8::1] or [2001:db8::1]:8080
            bracket_end = target_str.find("]")
            if bracket_end != -1:
                self.hostname = target_str[1:bracket_end]
                rest = target_str[bracket_end + 1:]
                if rest.startswith(":"):
                    try:
                        self.port = int(rest[1:])
                    except (ValueError, TypeError):
                        self.port = 0
            else:
                self.hostname = target_str.strip("[]")
        elif ":" in target_str:
            # Could be host:port (IPv4/domain) or unbracketed IPv6
            try:
                ipaddress.IPv6Address(target_str)
                self.hostname = target_str
            except ValueError:
                parts = target_str.rsplit(":", 1)
                if len(parts) == 2:
                    self.hostname = parts[0].strip("[]")
                    try:
                        self.port = int(parts[1])
                    except (ValueError, TypeError):
                        self.port = 0
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
    def __init__(self, state: EngagementState | EngagementConfig, resolve_dns: bool = False):
        if isinstance(state, EngagementConfig):
            self.state = EngagementState(state)
        else:
            self.state = state
        self.resolve_dns = resolve_dns

    def _is_in_scope(self, target_host: str) -> bool:
        """Check if a hostname, domain, or IP is within authorized engagement scope (supporting wildcards and ports)."""
        if not target_host:
            return False
        raw = target_host.lower().strip()
        # Strip URL scheme and path if present
        if "://" in raw:
            import urllib.parse
            parsed = urllib.parse.urlparse(raw)
            host = (parsed.hostname or "").strip("[]")
        elif raw.startswith("["):
            # Bracketed IPv6 notation with optional port: [2001:db8::1] or [2001:db8::1]:8080
            b_end = raw.find("]")
            host = raw[1:b_end] if b_end != -1 else raw.strip("[]")
        elif ":" in raw:
            try:
                ipaddress.IPv6Address(raw)
                host = raw
            except ValueError:
                parts = raw.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    host = parts[0].strip("[]")
                else:
                    host = raw.strip("[]")
        else:
            host = raw.strip("[]")

        # Strip trailing dot for RFC 1035 FQDN compliance
        host = host.rstrip(".")

        if not host:
            return False

        # Domain whitelist matching
        for auth_domain in self.state.config.authorized_domains:
            auth = auth_domain.lower().strip().rstrip(".")
            if auth.startswith("*."):
                wildcard_base = auth[2:]
                if host == wildcard_base or host.endswith("." + wildcard_base):
                    return True
            elif auth.startswith("."):
                wildcard_base = auth[1:]
                if host == wildcard_base or host.endswith("." + wildcard_base):
                    return True
            elif host == auth:
                return True

        # IP / CIDR matching
        try:
            ip_obj = ipaddress.ip_address(host)
            for cidr in self.state.config.authorized_cidrs:
                net_obj = ipaddress.ip_network(cidr, strict=False)
                if ip_obj in net_obj:
                    return True
        except ValueError:
            pass
        return False

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
        in_scope_domain = self._is_in_scope(hostname)

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

        # 3. Command template scope validation (Command Scope Decoupling Prevention)
        if req.command_template:
            cmd_hosts = set()
            # Extract destination URLs: e.g. https?://...
            url_matches = re.findall(r"https?://[^\s\"'<>]+", req.command_template)
            for u in url_matches:
                clean_u = u.rstrip(".,;)\"'>")
                try:
                    p = urllib.parse.urlparse(clean_u)
                    h = (p.hostname or "").strip("[]").rstrip(".")
                    if h:
                        cmd_hosts.add(h)
                except Exception:
                    pass

            # Inspect command tokens for target hostnames and IPs
            try:
                tokens = shlex.split(req.command_template, posix=(os.name != "nt"))
            except ValueError:
                tokens = req.command_template.strip().split()

            target_flags = {"-u", "--url", "-target", "--target", "--host"}
            domain_regex = re.compile(
                r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
            )
            common_file_exts = (
                ".txt", ".py", ".json", ".yaml", ".yml", ".sh", ".cmd", ".md",
                ".csv", ".xml", ".html", ".log", ".tar", ".gz", ".zip", ".conf",
                ".cfg", ".ini", ".bak", ".tmp", ".so", ".dll", ".exe", ".bin"
            )
            for i, tok in enumerate(tokens):
                clean_tok = tok.strip("'\"").rstrip(".,;")
                if not clean_tok or clean_tok.startswith("-"):
                    continue

                is_flag_target = i > 0 and tokens[i - 1].lower() in target_flags
                ip_cand = clean_tok.strip("[]")
                is_ip = False
                try:
                    ipaddress.ip_address(ip_cand)
                    is_ip = True
                except ValueError:
                    pass

                if is_flag_target or is_ip:
                    if "://" in clean_tok:
                        try:
                            p = urllib.parse.urlparse(clean_tok)
                            h = (p.hostname or "").strip("[]").rstrip(".")
                            if h:
                                cmd_hosts.add(h)
                        except Exception:
                            pass
                    elif is_ip:
                        cmd_hosts.add(ip_cand.rstrip("."))
                    elif domain_regex.match(clean_tok) and not any(clean_tok.lower().endswith(ext) for ext in common_file_exts):
                        cmd_hosts.add(clean_tok.rstrip("."))

            for dest_host in cmd_hosts:
                if not self._is_in_scope(dest_host):
                    return GatewayDisposition(
                        status=DispositionStatus.REJECTED,
                        code=CODE_SCOPE_VIOLATION,
                        reason=f"Command template targets out-of-scope host [{dest_host}] under SOP-01: {req.command_template}",
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
            rate_match = re.search(r"(?:^|\s)-rate(?:\s*=\s*|\s+)(\d+)", cmd)
            if rate_match:
                specified_rate = int(rate_match.group(1))
                if specified_rate > active_rate:
                    cmd = re.sub(
                        r"((?:^|\s)-rate(?:\s*=\s*|\s+))\d+",
                        rf"\g<1>{active_rate}",
                        cmd,
                        count=1,
                    )
            else:
                cmd = f"{cmd} -rate {active_rate}"
        elif "nmap" in tool_name or tool_name == "nmap":
            rate_match = re.search(r"(?:^|\s)--max-rate(?:\s*=\s*|\s+)(\d+)", cmd)
            if rate_match:
                specified_rate = int(rate_match.group(1))
                if specified_rate > active_rate:
                    cmd = re.sub(
                        r"((?:^|\s)--max-rate(?:\s*=\s*|\s+))\d+",
                        rf"\g<1>{active_rate}",
                        cmd,
                        count=1,
                    )
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
                repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                res = sandbox_runner.run(cmd, timeout=timeout_seconds, host_mount_dir=repo_root)
                exit_code = res.get("exit_code", 0)
                stdout_data = res.get("stdout", "")
                stderr_data = res.get("stderr", "")
                status = res.get("status", "SUCCESS")
            else:
                # Local safe execution fallback — split command to avoid shell injection
                repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                cmd_args = shlex.split(cmd, posix=(os.name != "nt")) if isinstance(cmd, str) else list(cmd)
                proc = subprocess.run(
                    cmd_args,
                    shell=False,
                    cwd=repo_root,
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

# ============================================================================
# Consolidated Sandbox Runner
# ============================================================================

class SandboxMode(str, Enum):
    DOCKER = "DOCKER"
    SUBPROCESS_FALLBACK = "SUBPROCESS_FALLBACK"


# ---------------------------------------------------------------------------
# Command Allowlist
# ---------------------------------------------------------------------------

# Categories of commands permitted in the sandbox.
# Each entry maps a category name to a list of allowed command prefixes.
# A command is allowed if its executable name matches any entry in the
# category that is enabled via SandboxConfig.allow_categories.
COMMAND_ALLOWLIST: Dict[str, List[str]] = {
    "read_only": [
        "python", "python3", "py",
        "echo", "cat", "head", "tail", "wc", "sort", "uniq", "grep", "egrep", "fgrep",
        "find", "ls", "pwd", "stat", "file", "xxd", "hexdump", "strings", "od",
        "whoami", "id", "uname", "hostname", "ip", "ifconfig", "netstat",
        "env", "printenv", "date", "uptime", "df", "du", "ps", "top", "sleep",
        "sha256sum", "sha1sum", "md5sum", "cksum",
        "nmap", "nslookup", "dig", "host", "traceroute", "ping",
        "curl", "wget", "httpx", "nikto",
        "sublist3r", "theHarvester", "amass", "dnsenum",
        "whois", "shodan", "censys",
        "git", "gh",
        "jq", "yq",
    ],
    "write_safe": [
        "mkdir", "touch", "cp", "mv", "chmod", "chown",
        "tee",
    ],
    "restricted": [
        "rm", "rmdir", "kill", "pkill",
        "iptables", "ufw", "dd",
    ],
}


def _command_name(command: str) -> str:
    """Extract the base command name from a shell command string using shlex parsing."""
    import shlex
    try:
        tokens = shlex.split(command, posix=(os.name != "nt"))
    except ValueError:
        # Fallback: simple split on whitespace
        tokens = command.strip().split()
    if not tokens:
        return ""
    # Strip leading env assignments and shell builtins
    cmd = tokens[0]
    for prefix in ("sh", "bash", "/bin/sh", "/bin/bash"):
        if cmd == prefix and len(tokens) > 1:
            cmd = tokens[1]
            break
    # Normalize command to base filename (e.g. /usr/bin/python3 -> python3, python.exe -> python)
    cmd = os.path.basename(cmd)
    if cmd.lower().endswith(".exe"):
        cmd = cmd[:-4]
    return cmd


def check_command_allowlist(command: str, allowed_categories: Set[str]) -> Tuple[bool, str]:
    """Check whether a command is permitted by the allowlist.

    Returns (allowed, reason).
    """
    if not command or not command.strip():
        return False, "Empty command"

    # Forbid newline characters (shell command separation)
    if "\n" in command or "\r" in command:
        return False, "Shell chaining forbidden: newline characters detected in command"

    import shlex
    try:
        tokens = shlex.split(command, posix=(os.name != "nt"))
    except ValueError:
        tokens = command.strip().split()

    # Forbid unquoted shell chaining operators (&, &&, |, ||, ;) across parsed tokens
    chain_ops = {"&", "&&", "|", "||", ";", ";;"}
    for tok in tokens:
        if tok in chain_ops:
            return False, f"Shell chaining forbidden: command contains chaining operator ({tok})"
        if any(tok.startswith(op) or tok.endswith(op) for op in ("&&", "||")):
            return False, f"Shell chaining forbidden: command contains chaining operator ({tok})"
        if tok.startswith("&") or tok.endswith("&"):
            return False, f"Shell chaining forbidden: command contains chaining operator ({tok})"
        if tok.startswith(";") or tok.endswith(";"):
            return False, f"Shell chaining forbidden: command contains chaining operator ({tok})"
        if tok.startswith("|") or tok.endswith("|"):
            return False, f"Shell chaining forbidden: command contains chaining operator ({tok})"

    cmd_name = _command_name(command)
    if not cmd_name:
        return False, "Empty command"

    # Check basename (strip path and .exe)
    basename = os.path.basename(cmd_name)
    base_stem = basename[:-4] if basename.lower().endswith(".exe") else basename

    for category in allowed_categories:
        allowed_cmds = COMMAND_ALLOWLIST.get(category, [])
        if basename in allowed_cmds or base_stem in allowed_cmds:
            return True, f"Allowed via category '{category}'"

    return False, f"Command '{basename}' not found in any allowed category: {allowed_categories}"


@dataclass
class SandboxConfig:
    image: str = "alpine:latest"
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    pids_limit: int = 100
    network_mode: str = "bridge"  # "bridge", "none", or custom network
    read_only_root: bool = True
    timeout_seconds: int = 60
    workdir: str = "/workspace"
    enable_fallback: bool = True
    # Command allowlist: set of category names to permit.
    # Default: read_only + write_safe (no destructive commands).
    allow_categories: Set[str] = field(
        default_factory=lambda: {"read_only", "write_safe"}
    )
    # When True, enforce the allowlist before execution.
    enforce_allowlist: bool = True
    # When True, verify artifact cleanup after each run.
    verify_cleanup: bool = True


@dataclass
class SandboxProbeReport:
    daemon_reachable: bool
    mode: SandboxMode
    daemon_info: str = ""
    container_runtime: str = ""
    isolation_level: str = "HIGH"
    details: Dict[str, Any] = field(default_factory=dict)


class SandboxRunner:
    """
    Containerized tool dispatcher modeled after PentAGI's Docker runner.
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self.mode = self._detect_mode()

    def _detect_mode(self) -> SandboxMode:
        """Probe Docker availability; fallback to subprocess if unavailable."""
        if shutil.which("docker") is not None:
            try:
                proc = subprocess.run(
                    ["docker", "info", "--format", "{{json .}}"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if proc.returncode == 0:
                    return SandboxMode.DOCKER
            except Exception:
                pass

        if self.config.enable_fallback:
            return SandboxMode.SUBPROCESS_FALLBACK
        raise RuntimeError("Docker daemon is unreachable and fallback mode is disabled.")

    def probe(self) -> SandboxProbeReport:
        """Run diagnostic probe similar to PentAGI's sandbox_probe.sh."""
        if self.mode == SandboxMode.DOCKER:
            try:
                proc = subprocess.run(
                    ["docker", "version", "--format", "{{json .}}"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                return SandboxProbeReport(
                    daemon_reachable=True,
                    mode=SandboxMode.DOCKER,
                    container_runtime="docker",
                    isolation_level="CONTAINER_ISOLATED",
                    daemon_info="Docker Engine (Daemon Active)",
                    details={"version_json": proc.stdout.strip()},
                )
            except Exception as e:
                return SandboxProbeReport(
                    daemon_reachable=False,
                    mode=SandboxMode.SUBPROCESS_FALLBACK,
                    isolation_level="LOCAL_PROCESS_RESTRICTED",
                    daemon_info=f"Docker probe failed: {e}",
                )

        return SandboxProbeReport(
            daemon_reachable=False,
            mode=SandboxMode.SUBPROCESS_FALLBACK,
            isolation_level="LOCAL_PROCESS_RESTRICTED",
            daemon_info="Docker CLI not found or daemon down; running in restricted subprocess sandbox",
        )

    def run(
        self,
        command: str,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        host_mount_dir: Optional[str] = None,
        allow_categories: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """Execute command inside the sandbox container (or fallback isolated subprocess).

        Returns a dict matching the tool_result schema:
        {
            "status": "SUCCESS" | "FAILED" | "TIMEOUT" | "ALLOWLIST_BLOCKED",
            "exit_code": int,
            "stdout": str,
            "stderr": str,
            "duration_ms": int,
            "mode": str,
            "allowlist_reason": str (only when blocked),
            "cleanup_verified": bool (only when verify_cleanup is enabled),
        }
        """
        effective_timeout = timeout or self.config.timeout_seconds

        # 1. Command Allowlist Check
        if self.config.enforce_allowlist:
            categories = allow_categories or self.config.allow_categories
            allowed, reason = check_command_allowlist(command, categories)
            if not allowed:
                return {
                    "status": "ALLOWLIST_BLOCKED",
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": reason,
                    "duration_ms": 0,
                    "mode": self.mode.value,
                    "allowlist_reason": reason,
                }

        # 2. Execute
        if self.mode == SandboxMode.DOCKER:
            result = self._run_docker(command, effective_timeout, env, host_mount_dir)
        else:
            result = self._run_subprocess(command, effective_timeout, env, host_mount_dir)

        # 3. Artifact Cleanup Verification
        if self.config.verify_cleanup:
            result["cleanup_verified"] = self._verify_cleanup(host_mount_dir)

        return result

    def _verify_cleanup(self, host_mount_dir: Optional[str]) -> bool:
        """Verify that temporary artifacts from the last run were cleaned up."""
        import glob
        if host_mount_dir and os.path.exists(host_mount_dir):
            leftovers = glob.glob(os.path.join(host_mount_dir, "nf_sandbox_*"))
            return len(leftovers) == 0
        leftovers = glob.glob(os.path.join(tempfile.gettempdir(), "nf_sandbox_*"))
        return len(leftovers) == 0

    def _run_docker(
        self,
        command: str,
        timeout: int,
        env: Optional[Dict[str, str]] = None,
        host_mount_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        t0 = time.time()
        docker_cmd = [
            "docker", "run", "--rm",
            "--network", self.config.network_mode,
            "--memory", self.config.memory_limit,
            f"--cpus={self.config.cpu_limit}",
            f"--pids-limit={self.config.pids_limit}",
            "--security-opt", "no-new-privileges:true",
        ]

        if self.config.read_only_root:
            docker_cmd.extend(["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])

        if host_mount_dir and os.path.exists(host_mount_dir):
            abs_mount = os.path.abspath(host_mount_dir).replace("\\", "/")
            docker_cmd.extend(["-v", f"{abs_mount}:{self.config.workdir}:rw"])
            docker_cmd.extend(["-w", self.config.workdir])

        if env:
            for k, v in env.items():
                docker_cmd.extend(["-e", f"{k}={v}"])

        docker_cmd.extend([self.config.image, "sh", "-c", command])

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            duration_ms = int((time.time() - t0) * 1000)
            status = "SUCCESS" if proc.returncode == 0 else "FAILED"
            return {
                "status": status,
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "duration_ms": duration_ms,
                "mode": SandboxMode.DOCKER.value,
            }
        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - t0) * 1000)
            return {
                "status": "TIMEOUT",
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Sandbox container execution timed out after {timeout} seconds.",
                "duration_ms": duration_ms,
                "mode": SandboxMode.DOCKER.value,
            }
        except Exception as e:
            duration_ms = int((time.time() - t0) * 1000)
            return {
                "status": "FAILED",
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Docker runner execution error: {e}",
                "duration_ms": duration_ms,
                "mode": SandboxMode.DOCKER.value,
            }

    def _run_subprocess(
        self,
        command: str,
        timeout: int,
        env: Optional[Dict[str, str]] = None,
        host_mount_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Subprocess fallback running in an isolated temp directory with sanitized environment."""
        t0 = time.time()
        temp_dir = tempfile.mkdtemp(prefix="nf_sandbox_")
        work_dir = host_mount_dir if (host_mount_dir and os.path.exists(host_mount_dir)) else temp_dir

        # Sanitize environment: only permit essential system variables
        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "SYSTEMDRIVE": os.environ.get("SYSTEMDRIVE", "C:"),
            "COMSPEC": os.environ.get("COMSPEC", ""),
            "PATHEXT": os.environ.get("PATHEXT", ""),
            "WINDIR": os.environ.get("WINDIR", ""),
            "TEMP": temp_dir,
            "TMP": temp_dir,
        }
        if os.name != "nt":
            safe_env["HOME"] = temp_dir
            safe_env["USER"] = "sandbox"
        if env:
            safe_env.update(env)

        try:
            # Parse command into tokens and execute with shell=False to prevent injection
            import shlex as _shlex
            try:
                cmd_tokens = _shlex.split(command, posix=(os.name != "nt"))
            except ValueError:
                cmd_tokens = command.strip().split()
            if not cmd_tokens:
                raise ValueError("Empty command")

            if os.name == "nt":
                cmd_tokens = [tok[1:-1] if ((tok.startswith('"') and tok.endswith('"')) or (tok.startswith("'") and tok.endswith("'"))) and len(tok) >= 2 else tok for tok in cmd_tokens]

            # Windows shell builtins need cmd.exe /c wrapper when shell=False
            exec_tokens = list(cmd_tokens)
            if os.name == "nt" and cmd_tokens and cmd_tokens[0].lower() in (
                "echo", "dir", "type", "cls", "ver", "cd", "chdir", "ren", "rename",
                "move", "copy", "del", "erase", "mkdir", "md", "rmdir", "rd",
            ):
                exec_tokens = ["cmd.exe", "/c"] + exec_tokens

            proc = subprocess.run(
                exec_tokens,
                shell=False,
                cwd=work_dir,
                env=safe_env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            duration_ms = int((time.time() - t0) * 1000)
            status = "SUCCESS" if proc.returncode == 0 else "FAILED"
            return {
                "status": status,
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "duration_ms": duration_ms,
                "mode": SandboxMode.SUBPROCESS_FALLBACK.value,
            }
        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - t0) * 1000)
            return {
                "status": "TIMEOUT",
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Subprocess execution timed out after {timeout} seconds.",
                "duration_ms": duration_ms,
                "mode": SandboxMode.SUBPROCESS_FALLBACK.value,
            }
        except Exception as e:
            duration_ms = int((time.time() - t0) * 1000)
            return {
                "status": "FAILED",
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Subprocess runner error: {e}",
                "duration_ms": duration_ms,
                "mode": SandboxMode.SUBPROCESS_FALLBACK.value,
            }
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)



# ============================================================================
# Consolidated MCP Gateway Proxy Middleware
# ============================================================================

DANGEROUS_MCP_TOOLS: Set[str] = {
    "browser_run_code_unsafe",
    "execute_arbitrary_code",
    "system_exec",
    "run_destructive_exploit",
    "shell_exec",
    "file_delete",
    "write_root_file",
}


class MCPGatewayProxy:
    """Interceps MCP JSON-RPC tool calls, evaluates scope and OPSEC, and cryptographically tags evidence."""

    def __init__(
        self,
        gateway: Optional[ExecutionPolicyGateway] = None,
        config: Optional[EngagementConfig] = None,
    ) -> None:
        if gateway is not None:
            self.gateway = gateway
        else:
            cfg = config or EngagementConfig(
                engagement_id=f"ENG-MCP-{int(time.time())}",
                authorized_operator="hermes-operator",
                authorized_cidrs=["10.0.0.0/8", "127.0.0.1/32"],
                authorized_domains=["target.corp", "*.target.corp", "localhost"],
                autonomy_tier=AutonomyTier.SEMI_AUTONOMOUS,
            )
            self.gateway = ExecutionPolicyGateway(cfg)

    def extract_targets(self, tool_name: str, arguments: Dict[str, Any]) -> List[str]:
        """Extract candidate target hostnames, URLs, or IPs from tool call arguments."""
        if not isinstance(arguments, dict):
            return ["localhost"]

        targets: List[str] = []
        target_keys = ["url", "target", "domain", "host", "ip", "hostname", "endpoint", "uri"]

        for k in target_keys:
            if k in arguments and isinstance(arguments[k], str) and arguments[k].strip():
                targets.append(arguments[k].strip())

        # Also search command or script arguments for embedded URLs or domains
        for k in ["command", "cmd", "script", "query"]:
            if k in arguments and isinstance(arguments[k], str):
                text = arguments[k]
                found_urls = re.findall(r"https?://[^\s\"'>]+", text)
                targets.extend(found_urls)

        # Parse and normalize hostnames
        normalized: List[str] = []
        for t in targets:
            if "://" in t:
                try:
                    parsed = urllib.parse.urlparse(t)
                    if parsed.hostname:
                        normalized.append(parsed.hostname)
                    else:
                        normalized.append(t)
                except Exception:
                    normalized.append(t)
            else:
                # Handle bracketed IPv6 addresses: e.g. [::1]:8080 or [::1]
                if t.startswith("["):
                    bracket_end = t.find("]")
                    if bracket_end != -1:
                        normalized.append(t[1:bracket_end])
                    else:
                        normalized.append(t)
                else:
                    # Strip port if present
                    h = t.split(":")[0] if ":" in t else t
                    normalized.append(h)

        return list(dict.fromkeys(normalized)) if normalized else ["localhost"]

    def classify_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[ActionType, NoiseProfile, bool]:
        """Classify tool action type, noise level, and whether it requires strict HITL."""
        name_lower = tool_name.lower()
        if name_lower in DANGEROUS_MCP_TOOLS or any(bad in name_lower for bad in ["unsafe", "destroy", "drop_db", "overwrite"]):
            return ActionType.EXPLOIT_POC, NoiseProfile.LOUD, True

        if any(term in name_lower for term in ["exploit", "inject", "payload", "poc"]):
            return ActionType.EXPLOIT_POC, NoiseProfile.LOUD, True

        if any(term in name_lower for term in ["scan", "fuzz", "nuclei", "zap", "audit", "security_scanner"]):
            return ActionType.ACTIVE_PROBE, NoiseProfile.MODERATE, False

        # Default to PASSIVE_READ / QUIET
        return ActionType.PASSIVE_READ, NoiseProfile.QUIET, False

    def filter_tool_call(
        self, tool_name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Evaluate tool call against Execution Policy Gateway.
        Returns:
            (is_allowed: bool, rejection_reason: Optional[str], modified_arguments: Optional[dict])
        """
        args_dict = arguments if isinstance(arguments, dict) else {}
        targets = self.extract_targets(tool_name, args_dict)
        action_type, noise_profile, is_dangerous = self.classify_tool(tool_name, args_dict)

        # Verify scope for all extracted targets
        for tgt in targets:
            if not self.gateway._is_in_scope(tgt):
                reason = f"POLICY VIOLATION: Target '{tgt}' is outside authorized engagement scope."
                self.gateway.state.log_audit("MCP_SCOPE_REJECTED", {"tool": tool_name, "target": tgt, "reason": reason})
                return False, reason, None

        # Check dangerous tool restrictions
        if is_dangerous:
            if self.gateway.state.config.strict_hitl or self.gateway.state.config.autonomy_tier != AutonomyTier.FULL_AUTONOMOUS:
                reason = f"HITL REQUIRED: Tool '{tool_name}' performs dangerous/invasive operations requiring operator authorization."
                self.gateway.state.log_audit("MCP_HITL_TRIGGERED", {"tool": tool_name, "reason": reason})
                return False, reason, None

        # Construct ToolInvocationRequest
        primary_target = targets[0] if targets else "localhost"
        req = ToolInvocationRequest(
            request_id=f"mcp-req-{int(time.time() * 1000)}",
            engagement_id=self.gateway.state.config.engagement_id,
            agent_id="mcp-agent",
            skill_id="mcp-policy-gate",
            tool_name=tool_name,
            target=TargetSpec(raw_target=primary_target, hostname=primary_target),
            opsec=OpsecSpec(noise=noise_profile, rationale="MCP tool invocation intercept"),
            command_template=json.dumps(args_dict),
            action_type=action_type,
            technique="MCP_INVOCATION",
        )

        disp = self.gateway.evaluate(req)
        if disp.status != DispositionStatus.APPROVED:
            return False, f"GATEWAY DISPOSITION: {disp.reason} (code: {disp.code})", None

        return True, None, args_dict

    @staticmethod
    def hash_and_tag_evidence(response_data: Any) -> Tuple[str, str]:
        """Compute SHA-256 evidence hash and format standard NIGHTFANG evidence tag [EVD-XXXXXXXX]."""
        if isinstance(response_data, (dict, list)):
            serialized = json.dumps(response_data, sort_keys=True)
        else:
            serialized = str(response_data)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        tag = f"[EVD-{digest[:8].upper()}]"
        return tag, digest

    def process_jsonrpc_message(self, message_str: str) -> str:
        """Parse, evaluate, and handle a JSON-RPC message string."""
        if not message_str or not message_str.strip():
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: empty input"},
            })

        # Strip Content-Length / LSP style header prefixes if present
        clean_msg = message_str.strip()
        if clean_msg.startswith("Content-Length:"):
            parts = clean_msg.split("\r\n\r\n", 1)
            if len(parts) == 1:
                parts = clean_msg.split("\n\n", 1)
            if len(parts) > 1:
                clean_msg = parts[1].strip()

        try:
            req_json = json.loads(clean_msg)
        except Exception as e:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
            })

        if not isinstance(req_json, dict):
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: expected JSON-RPC object"},
            })

        req_id = req_json.get("id")
        method = req_json.get("method")
        raw_params = req_json.get("params")
        params = raw_params if isinstance(raw_params, dict) else {}

        if method == "tools/call":
            tool_name = params.get("name", "") if isinstance(params.get("name"), str) else ""
            raw_args = params.get("arguments")
            arguments = raw_args if isinstance(raw_args, dict) else {}

            allowed, reason, modified_args = self.filter_tool_call(tool_name, arguments)
            if not allowed:
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32000,
                        "message": f"Execution Policy Gateway Blocked: {reason}",
                        "data": {"tool": tool_name, "arguments": arguments, "blocked": True},
                    },
                })

            # Simulate or forward execution
            mock_output = {
                "status": "SUCCESS",
                "tool": tool_name,
                "output": f"Executed {tool_name} successfully within policy.",
            }
            evd_tag, digest = self.hash_and_tag_evidence(mock_output)
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"{evd_tag} {json.dumps(mock_output)}",
                        }
                    ],
                    "evidence_tag": evd_tag,
                    "evidence_sha256": digest,
                },
            })

        elif method == "tools/list":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {"name": "browser_navigate", "description": "Navigate to URL within scope"},
                        {"name": "security_scan", "description": "Run non-destructive scan"},
                    ]
                },
            })

        return json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"status": "ok", "message": f"Echoed unintercepted method {method}"},
        })

    def run_proxy(self) -> None:
        """Run stdio JSON-RPC loop reading lines from stdin."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            response = self.process_jsonrpc_message(line)
            sys.stdout.write(response + "\n")
            sys.stdout.flush()



# ============================================================================
# Test Suites
# ============================================================================

def run_gateway_tests() -> bool:
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
    # Verify _is_in_scope endpoint & port resilience
    assert gw._is_in_scope("target.corp:8080") is True
    assert gw._is_in_scope("https://target.corp/api/v1") is True
    assert gw._is_in_scope("out-of-scope.net") is False
    assert gw._is_in_scope("10.5.0.1:443") is True
    assert gw._is_in_scope("[2001:db8::1]:8080") is True
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

    # Test 10: Command Scope Decoupling Intercept
    req_decoupled = ToolInvocationRequest(
        request_id="req-10",
        engagement_id="ENG-2026-ALPHA",
        agent_id="scanner",
        skill_id="skills/web",
        tool_name="curl",
        target=TargetSpec(raw_target="https://target.corp/"),
        opsec=OpsecSpec(noise=NoiseProfile.QUIET),
        command_template="curl https://out-of-scope.net/malicious",
        action_type=ActionType.PASSIVE_READ,
        technique="banner-grab",
    )
    d10 = gw.evaluate(req_decoupled)
    assert d10.status == DispositionStatus.REJECTED and d10.code == CODE_SCOPE_VIOLATION
    print("  [PASS] Test 10: Command scope decoupling blocked out-of-scope command target.")

    # Test 11: RFC 1035 FQDN Trailing Dot Scope Matching
    assert gw._is_in_scope("target.corp.") is True
    assert gw._is_in_scope("https://target.corp./api") is True
    assert gw._is_in_scope("out-of-scope.net.") is False
    print("  [PASS] Test 11: RFC 1035 FQDN trailing dots handled correctly.")

    # Test 12: Hardened Rate Limit Clamping
    req_rate_eq = ToolInvocationRequest(
        request_id="req-12a",
        engagement_id="ENG-2026-ALPHA",
        agent_id="scanner",
        skill_id="skills/web",
        tool_name="ffuf",
        target=TargetSpec(raw_target="https://target.corp/"),
        opsec=OpsecSpec(noise=NoiseProfile.MODERATE),
        command_template="ffuf -rate=500 -u https://target.corp/FUZZ",
        action_type=ActionType.ACTIVE_PROBE,
        technique="fuzz",
    )
    d12a = gw.evaluate(req_rate_eq)
    assert d12a.status == DispositionStatus.APPROVED
    assert "-rate=20" in d12a.modified_command and "500" not in d12a.modified_command

    req_nmap_eq = ToolInvocationRequest(
        request_id="req-12b",
        engagement_id="ENG-2026-ALPHA",
        agent_id="scanner",
        skill_id="skills/network",
        tool_name="nmap",
        target=TargetSpec(raw_target="https://target.corp/"),
        opsec=OpsecSpec(noise=NoiseProfile.MODERATE),
        command_template="nmap --max-rate=500 target.corp",
        action_type=ActionType.ACTIVE_PROBE,
        technique="port-scan",
    )
    d12b = gw.evaluate(req_nmap_eq)
    assert d12b.status == DispositionStatus.APPROVED
    assert "--max-rate=20" in d12b.modified_command and "500" not in d12b.modified_command
    print("  [PASS] Test 12: Hardened rate limit regexes clamped = and whitespace variants.")

    # Test 13: TargetSpec Port Resilience
    ts_bad_port = TargetSpec(raw_target="http://target.corp:invalid/")
    ts_bad_port.parse_target()
    assert ts_bad_port.port == 80
    ts_bad_colon = TargetSpec(raw_target="target.corp:notaport")
    ts_bad_colon.parse_target()
    assert ts_bad_colon.port == 0
    print("  [PASS] Test 13: Malformed ports handled cleanly without uncaught exceptions.")

    print("\nAll 13 Gateway self-tests PASSED successfully!")
    return True



def run_sandbox_tests() -> bool:
    print("Running NIGHTFANG Sandbox Runner Self-Tests...")
    sandbox = SandboxRunner()
    probe = sandbox.probe()
    print(f"  [INFO] Detected mode: {probe.mode.value} | Isolation: {probe.isolation_level}")

    # Test 1: Basic command execution
    res = sandbox.run("echo 'NIGHTFANG_SANDBOX_OK'", timeout=10)
    assert res["status"] == "SUCCESS", f"Execution failed: {res}"
    assert "NIGHTFANG_SANDBOX_OK" in res["stdout"], f"Output missing: {res}"
    print("  [PASS] Test 1: Command dispatch and output capture verified.")

    # Test 2: Timeout enforcement
    t_start = time.time()
    # Use a command that will run long enough to timeout
    # ping is in read_only allowlist; use it without shell redirects
    if os.name == "nt":
        sleep_cmd = "ping -n 5 127.0.0.1"
    else:
        sleep_cmd = "sleep 3"
    res_timeout = sandbox.run(sleep_cmd, timeout=1)
    duration = time.time() - t_start
    assert res_timeout["status"] == "TIMEOUT", f"Expected TIMEOUT, got: {res_timeout}"
    assert duration < 2.5, f"Timeout took too long: {duration}s"
    print("  [PASS] Test 2: Timeout guardrail properly terminated execution.")

    # Test 3: Command allowlist enforcement
    res_block = sandbox.run("rm -rf /", timeout=5)
    assert res_block["status"] == "ALLOWLIST_BLOCKED", f"Expected ALLOWLIST_BLOCKED, got: {res_block}"
    assert "rm" in res_block.get("allowlist_reason", ""), f"Expected rm in reason: {res_block}"
    print("  [PASS] Test 3: Command allowlist blocked destructive command (rm).")

    # Test 4: Allowed write command
    res_write = sandbox.run("mkdir nf_test_dir", timeout=10)
    assert res_write["status"] == "SUCCESS", f"Write command failed: {res_write}"
    print("  [PASS] Test 4: Allowed write command (mkdir) executed successfully.")

    # Test 5: Cleanup verification
    assert "cleanup_verified" in res, f"Expected cleanup_verified in result: {res}"
    print("  [PASS] Test 5: Artifact cleanup verification present.")

    # Test 6: Shell chaining operators blocked
    chain_cmds = [
        "echo safe & whoami",
        "echo safe && whoami",
        "echo safe | whoami",
        "echo safe || whoami",
        "echo safe ; whoami",
        "echo safe\nwhoami",
    ]
    for c in chain_cmds:
        res_chain = sandbox.run(c, timeout=5)
        assert res_chain["status"] == "ALLOWLIST_BLOCKED", f"Expected chaining blocked for {c}, got: {res_chain}"
        assert "chaining" in res_chain.get("allowlist_reason", "").lower()
    print("  [PASS] Test 6: Shell chaining operators blocked (&, &&, |, ||, ;, newlines).")

    # Test 7: Reconciled destructive dd classification blocked
    res_dd = sandbox.run("dd if=/dev/zero of=test bs=1 count=1", timeout=5)
    assert res_dd["status"] == "ALLOWLIST_BLOCKED", f"Expected dd blocked, got: {res_dd}"
    print("  [PASS] Test 7: Destructive command (dd) blocked under default allow_categories.")

    print("\nAll Sandbox Runner self-tests PASSED successfully!")
    return True



def run_mcp_proxy_tests() -> bool:
    """Run automated verification suite for MCP Gateway Policy Proxy."""
    print("Running NIGHTFANG MCP Gateway Policy Proxy Self-Tests...")

    cfg = EngagementConfig(
        engagement_id="ENG-TEST-MCP",
        authorized_operator="test-operator",
        authorized_cidrs=["10.0.0.0/8"],
        authorized_domains=["target.corp", "*.target.corp"],
        autonomy_tier=AutonomyTier.SEMI_AUTONOMOUS,
    )
    proxy = MCPGatewayProxy(config=cfg)

    # Test 1: Scope enforcement - In-scope target passes
    allowed, reason, _ = proxy.filter_tool_call(
        "browser_navigate", {"url": "https://api.target.corp/v1/health"}
    )
    assert allowed, f"In-scope target was unexpectedly rejected: {reason}"
    print("  [PASS] Test 1: In-scope target allowed through gateway policy.")

    # Test 2: Scope enforcement - Out-of-scope target blocked
    allowed, reason, _ = proxy.filter_tool_call(
        "browser_navigate", {"url": "https://evil.corp/leak"}
    )
    assert not allowed, "Out-of-scope target was unexpectedly allowed!"
    assert "POLICY VIOLATION" in reason, f"Unexpected reason: {reason}"
    print("  [PASS] Test 2: Out-of-scope target blocked by gateway policy.")

    # Test 3: Dangerous MCP tool blocking / HITL required
    allowed, reason, _ = proxy.filter_tool_call(
        "browser_run_code_unsafe", {"code": "process.exit(1)", "target": "https://api.target.corp"}
    )
    assert not allowed, "Dangerous tool was unexpectedly allowed without HITL!"
    assert "HITL REQUIRED" in reason, f"Unexpected reason: {reason}"
    print("  [PASS] Test 3: Dangerous MCP tool triggers mandatory HITL gate.")

    # Test 4: Evidence hashing and tagging
    sample_data = {"vuln": "SQLi", "payload": "' OR 1=1--"}
    tag, sha = proxy.hash_and_tag_evidence(sample_data)
    assert tag.startswith("[EVD-") and tag.endswith("]"), f"Invalid tag format: {tag}"
    assert len(sha) == 64, f"Invalid SHA-256 length: {sha}"
    assert sha[:8].upper() in tag, f"Tag did not embed hash prefix: {tag} vs {sha}"
    print("  [PASS] Test 4: Cryptographic evidence hashing and tag generation verified.")

    # Test 5: JSON-RPC message handling and malformed error parsing
    malformed_resp = json.loads(proxy.process_jsonrpc_message("{invalid_json"))
    assert malformed_resp.get("error", {}).get("code") == -32700, f"Expected -32700 error: {malformed_resp}"

    valid_req = json.dumps({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {
            "name": "browser_navigate",
            "arguments": {"url": "https://api.target.corp/login"},
        },
    })
    valid_resp = json.loads(proxy.process_jsonrpc_message(valid_req))
    assert "result" in valid_resp, f"Expected result in response: {valid_resp}"
    assert "evidence_tag" in valid_resp["result"], "Missing evidence_tag in result"
    print("  [PASS] Test 5: JSON-RPC tool intercept and JSON-RPC error dispatch verified.")

    # Test 6: Robustness on edge cases (null arguments, null params, non-dict payloads, Content-Length header)
    null_args_req = json.dumps({"jsonrpc": "2.0", "id": "req-2", "method": "tools/call", "params": {"name": "test", "arguments": None}})
    null_args_resp = json.loads(proxy.process_jsonrpc_message(null_args_req))
    assert "result" in null_args_resp or "error" in null_args_resp

    null_params_req = json.dumps({"jsonrpc": "2.0", "id": "req-3", "method": "tools/call", "params": None})
    null_params_resp = json.loads(proxy.process_jsonrpc_message(null_params_req))
    assert "result" in null_params_resp or "error" in null_params_resp

    non_dict_resp = json.loads(proxy.process_jsonrpc_message("12345"))
    assert non_dict_resp.get("error", {}).get("code") == -32600

    content_len_msg = f"Content-Length: {len(valid_req)}\r\n\r\n{valid_req}"
    cl_resp = json.loads(proxy.process_jsonrpc_message(content_len_msg))
    assert "result" in cl_resp
    print("  [PASS] Test 6: Edge cases (null arguments/params, non-dict input, Content-Length header) handled cleanly.")

    print("\nAll 6 MCP Gateway Proxy self-tests PASSED successfully!")
    return True




def run_self_tests() -> bool:
    """Run comprehensive test suite across Execution Gateway, Sandbox Runner & MCP Proxy."""
    print("==========================================================")
    print("  NIGHTFANG Consolidated Execution Gateway Self-Tests")
    print("==========================================================\n")
    ok1 = run_gateway_tests()
    print()
    ok2 = run_sandbox_tests()
    print()
    ok3 = run_mcp_proxy_tests()
    print()
    if ok1 and ok2 and ok3:
        print("[*] All 26 Execution Gateway, Sandbox & MCP Proxy self-tests PASSED successfully!")
        return True
    return False


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NIGHTFANG Consolidated Execution Policy Gateway & Sandbox")
    parser.add_argument("--test", action="store_true", help="Run all 26 automated self-tests")
    parser.add_argument("--stdio", action="store_true", help="Run stdio JSON-RPC MCP proxy middleware loop")
    parser.add_argument("--sandbox", dest="sandbox_cmd", type=str, help="Execute a command inside the containerized sandbox")
    parser.add_argument("--timeout", type=int, default=30, help="Sandbox execution timeout in seconds")
    args, unknown = parser.parse_known_args()

    if args.stdio:
        proxy = MCPGatewayProxy()
        proxy.run_proxy()
        sys.exit(0)

    if args.sandbox_cmd:
        runner = SandboxRunner()
        res = runner.run(args.sandbox_cmd, timeout=args.timeout)
        print(json.dumps(res, indent=2))
        sys.exit(0 if res.get("status") == "SUCCESS" else 1)

    # Default: run self-tests
    success = run_self_tests()
    sys.exit(0 if success else 1)
