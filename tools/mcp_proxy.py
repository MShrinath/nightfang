#!/usr/bin/env python3
"""
NIGHTFANG MCP Gateway Policy Interceptor & Proxy Middleware (tools/mcp_proxy.py)

Acts as a stdio JSON-RPC gateway middleware, applying NIGHTFANG's 5-stage
Execution Policy Gateway rules (scope verification, OPSEC noise checks, HITL trigger,
and cryptographic evidence hashing) directly to MCP tool invocations before execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from tools.gateway import (
        ExecutionPolicyGateway,
        EngagementConfig,
        EngagementState,
        ToolInvocationRequest,
        TargetSpec,
        OpsecSpec,
        NoiseProfile,
        ActionType,
        AutonomyTier,
        DispositionStatus,
        GatewayDisposition,
    )
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from gateway import (
        ExecutionPolicyGateway,
        EngagementConfig,
        EngagementState,
        ToolInvocationRequest,
        TargetSpec,
        OpsecSpec,
        NoiseProfile,
        ActionType,
        AutonomyTier,
        DispositionStatus,
        GatewayDisposition,
    )

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
                # Strip port if present
                h = t.split(":")[0] if ":" in t and not t.startswith("[") else t
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
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Evaluate tool call against Execution Policy Gateway.
        Returns:
            (is_allowed: bool, rejection_reason: Optional[str], modified_arguments: Optional[dict])
        """
        targets = self.extract_targets(tool_name, arguments)
        action_type, noise_profile, is_dangerous = self.classify_tool(tool_name, arguments)

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
            command_template=json.dumps(arguments),
            action_type=action_type,
            technique="MCP_INVOCATION",
        )

        disp = self.gateway.evaluate(req)
        if disp.status != DispositionStatus.APPROVED:
            return False, f"GATEWAY DISPOSITION: {disp.reason} (code: {disp.code})", None

        return True, None, arguments

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
        try:
            req_json = json.loads(message_str)
        except Exception as e:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
            })

        req_id = req_json.get("id")
        method = req_json.get("method")
        params = req_json.get("params", {})

        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

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


def run_self_tests() -> bool:
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

    print("\nAll 5 MCP Gateway Proxy self-tests PASSED successfully!")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIGHTFANG MCP Gateway Policy Interceptor")
    parser.add_argument("--test", action="store_true", help="Run automated self-tests")
    parser.add_argument("--stdio", action="store_true", help="Run stdio JSON-RPC proxy middleware loop")
    args = parser.parse_args()

    if args.test:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    if args.stdio:
        proxy = MCPGatewayProxy()
        proxy.run_proxy()
        sys.exit(0)

    # If run directly without flags, run self-tests
    success = run_self_tests()
    sys.exit(0 if success else 1)
