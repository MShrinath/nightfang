#!/usr/bin/env python3
"""Integration tests for NIGHTFANG end-to-end flows.

Runs without network access — mocks tool execution via SandboxRunner.
Tests: daemon lifecycle, CLI phases, payload resolver wiring, finding validation pipeline.
"""
import unittest
import os
import sys
import json
import tempfile
import shutil
from unittest.mock import patch, MagicMock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools.gateway import (
    ExecutionPolicyGateway,
    EngagementConfig,
    EngagementState,
    ToolInvocationRequest,
    TargetSpec,
    OpsecSpec,
    NoiseProfile,
    ActionType,
    DispositionStatus,
    issue_approval_token,
)
from tools.daemon import (
    AutonomousHunterDaemon,
    HunterTask,
    TaskPriority,
    AutonomyTier,
)
from tools.sandbox import SandboxRunner
from schemas.validator import FindingValidator
from scripts.agent_payloads import AgentPayloadResolver


class TestDaemonLifecycle(unittest.TestCase):
    """End-to-end daemon runs with mocked tool execution."""

    def setUp(self):
        cfg = EngagementConfig(
            engagement_id="ENG-INTEGRATION-TEST",
            authorized_operator="lead-tester",
            authorized_domains=["target.corp", "*.target.corp", "api.internal"],
            authorized_cidrs=["10.0.0.0/8"],
            autonomy_tier=AutonomyTier.SEMI_AUTONOMOUS,
        )
        self.daemon = AutonomousHunterDaemon(cfg)
        self.sandbox = SandboxRunner()

    def test_passive_recon_auto_executes(self):
        """Passive recon tasks should auto-execute and complete without HITL."""
        # Drain queue
        while self.daemon.queue.pop() is not None:
            pass

        task = HunterTask.create(
            "t-recon", TaskPriority.MEDIUM, "target.corp", "recon", "recon",
            "subfinder", "echo 'api.target.corp\\ncdn.target.corp'", NoiseProfile.QUIET,
            ActionType.PASSIVE_READ, technique="Subdomain Enumeration"
        )
        self.daemon.queue.push(task)

        # Mock sandbox to return our output
        with patch.object(self.sandbox, 'run', return_value={
            "status": "SUCCESS", "exit_code": 0,
            "stdout": "api.target.corp\ncdn.target.corp", "stderr": ""
        }):
            res = self.daemon.execute_next_task()

        self.assertEqual(res["status"], "COMPLETED")
        self.assertIn("api.target.corp", self.daemon.discovered_assets)
        self.assertIn("ncdn.target.corp", self.daemon.discovered_assets)

    def test_lead_expansion_generates_new_tasks(self):
        """Completed tasks should expand attack surface and enqueue follow-ups."""
        while self.daemon.queue.pop() is not None:
            pass

        task = HunterTask.create(
            "t-nmap", TaskPriority.HIGH, "api.target.corp", "scanner", "scanner",
            "nmap", "echo 'Nmap scan report for api.target.corp\\n80/tcp open  http\\n443/tcp open https'",
            NoiseProfile.MODERATE, ActionType.ACTIVE_PROBE, technique="Port & Service Scan"
        )
        self.daemon.queue.push(task)

        with patch.object(self.sandbox, 'run', return_value={
            "status": "SUCCESS", "exit_code": 0,
            "stdout": "Nmap scan report for api.target.corp\n80/tcp open  http\n443/tcp open https",
            "stderr": ""
        }):
            res = self.daemon.execute_next_task()

        self.assertEqual(res["status"], "COMPLETED")
        # Should have enqueued web inspection for the discovered ports
        self.assertGreater(self.daemon.queue.pending_count(), 0)

    def test_non_blocking_hitl_allows_background_work(self):
        """HITL pause should not block other queued tasks."""
        while self.daemon.queue.pop() is not None:
            pass

        # Loud exploit - requires HITL
        t_exp = HunterTask.create(
            "t-exp", TaskPriority.CRITICAL, "target.corp", "validation", "validation",
            "sqlmap", "echo 'simulated sqlmap exploit'", NoiseProfile.LOUD,
            ActionType.EXPLOIT_POC, technique="SQL Injection Verification"
        )
        # Quiet passive - should run while exploit is paused
        t_passive = HunterTask.create(
            "t-pass", TaskPriority.LOW, "target.corp", "recon", "recon",
            "echo", "echo 'passive dns done'", NoiseProfile.QUIET,
            ActionType.PASSIVE_READ, technique="Passive DNS"
        )
        self.daemon.queue.push(t_exp)
        self.daemon.queue.push(t_passive)

        with patch.object(self.sandbox, 'run', return_value={
            "status": "SUCCESS", "exit_code": 0,
            "stdout": "passive dns done", "stderr": ""
        }):
            # First task: exploit pauses for HITL
            res1 = self.daemon.execute_next_task()
            self.assertEqual(res1["status"], "PAUSED_FOR_APPROVAL")

            # Second task: passive completes
            res2 = self.daemon.execute_next_task()
            self.assertEqual(res2["status"], "COMPLETED")

    def test_approve_resume_completes(self):
        """Approved HITL task should resume and complete."""
        while self.daemon.queue.pop() is not None:
            pass

        t_exp = HunterTask.create(
            "t-exp2", TaskPriority.CRITICAL, "target.corp", "validation", "validation",
            "sqlmap", "echo 'exploit executed'", NoiseProfile.LOUD,
            ActionType.EXPLOIT_POC, technique="SQL Injection Verification"
        )
        self.daemon.queue.push(t_exp)

        with patch.object(self.sandbox, 'run', return_value={
            "status": "SUCCESS", "exit_code": 0,
            "stdout": "exploit executed", "stderr": ""
        }):
            res1 = self.daemon.execute_next_task()
            self.assertEqual(res1["status"], "PAUSED_FOR_APPROVAL")

            approved = self.daemon.approve_hitl_task("t-exp2", operator_id="lead-tester")
            self.assertTrue(approved)

            res2 = self.daemon.execute_next_task()
            self.assertEqual(res2["status"], "COMPLETED")

    def test_self_healing_rate_backoff(self):
        """Rate backoff should throttle subsequent requests to same host."""
        self.daemon.state.trigger_rate_backoff("target.corp", "HTTP 429")
        rate_info = self.daemon.state.rate_state.get("target.corp")
        self.assertIsNotNone(rate_info)
        self.assertLess(rate_info["current_rate"], 20)


class TestPayloadResolverIntegration(unittest.TestCase):
    """Verify AgentPayloadResolver works for agents."""

    def setUp(self):
        self.resolver = AgentPayloadResolver()

    def test_resolver_loads_catalog(self):
        classes = self.resolver.list_classes()
        self.assertGreater(len(classes), 10)
        for c in classes:
            self.assertIn("class", c)
            self.assertIn("cwe", c)
            self.assertIn("owasp", c)
            self.assertIn("safe_default", c)
            self.assertIn("payload_count", c)

    def test_resolver_by_class(self):
        jwt = self.resolver.get_by_class("jwt_manipulation")
        self.assertIsNotNone(jwt)
        self.assertEqual(jwt["cwe"], "CWE-327")
        self.assertEqual(jwt["owasp"], "A02:2021")
        self.assertTrue(jwt["safe_default"])
        self.assertGreater(len(jwt["payload_files"]), 0)

    def test_resolver_by_cwe(self):
        matches = self.resolver.get_by_cwe("CWE-943")
        self.assertGreaterEqual(len(matches), 3)  # coap_injection + lmq_fuzzing + mqtt_injection
        classes = [m["class"] for m in matches]
        self.assertIn("coap_injection", classes)
        self.assertIn("mqtt_injection", classes)

    def test_resolver_by_owasp(self):
        matches = self.resolver.get_by_owasp("A02:2021")
        self.assertGreaterEqual(len(matches), 2)  # jwt_manipulation + BOLA at minimum

    def test_safe_vs_destructive_split(self):
        safe = self.resolver.get_safe_payloads("jwt_manipulation")
        dest = self.resolver.get_destructive_payloads("jwt_manipulation")
        self.assertGreater(len(safe), 0)
        self.assertEqual(len(dest), 0)

        safe2 = self.resolver.get_safe_payloads("BOLA")
        dest2 = self.resolver.get_destructive_payloads("BOLA")
        self.assertGreater(len(safe2), 0)
        self.assertEqual(len(dest2), 0)


class TestFindingValidationPipeline(unittest.TestCase):
    """Full pipeline: gateway -> execution -> validator."""

    def setUp(self):
        self.cfg = EngagementConfig(
            engagement_id="ENG-VALIDATION-TEST",
            authorized_operator="lead-tester",
            authorized_domains=["target.corp", "*.target.corp"],
        )
        self.state = EngagementState(self.cfg)
        self.gateway = ExecutionPolicyGateway(self.state, resolve_dns=False)
        self.validator = FindingValidator()

    def make_request(self, **kwargs):
        defaults = {
            "request_id": "req-test",
            "engagement_id": "ENG-VALIDATION-TEST",
            "agent_id": "scanner",
            "skill_id": "skills/web",
            "tool_name": "nuclei",
            "target": TargetSpec(raw_target="https://target.corp/"),
            "opsec": OpsecSpec(noise=NoiseProfile.MODERATE),
            "command_template": "nuclei -u https://target.corp/ -id sqli",
            "action_type": ActionType.ACTIVE_PROBE,
            "technique": "SQL Injection",
        }
        defaults.update(kwargs)
        return ToolInvocationRequest(**defaults)

    def test_gateway_approval_to_validation(self):
        """Approved gateway request produces finding that passes validator."""
        req = self.make_request(request_id="req-valid")
        disp = self.gateway.evaluate(req)
        self.assertEqual(disp.status, DispositionStatus.APPROVED)

        # Simulate successful execution
        finding = {
            "finding": {
                "id": "NF-2026-INT-001",
                "title": "SQL Injection in Login Endpoint",
                "target": "https://target.corp/login",
                "category": "web",
                "timestamp": "2026-01-01T00:00:00Z",
                "tool_used": "nuclei",
                "cve": "",
                "confidence": {"score": 9, "rationale": "Benign canary reflected in response"},
                "severity": {"score": 8, "level": "high", "rationale": "Auth bypass potential"},
                "evidence_grounding": {"score": 0.95, "bucket": "CERTAIN", "rationale": "Raw response captured"},
                "evidence": [{"type": "http_response", "description": "SQLi reflected", "data": "HTTP/1.1 200 OK"}],
                "reproduction": [{"step": 1, "action": "POST /login", "command": "curl -d '...' https://target.corp/login"}],
                "impact": {"technical": "Authentication bypass", "business": "Account takeover"},
                "remediation": {"guidance": "Use parameterized queries", "mitre_d3fend": [], "references": []},
                "validated_by_blue_skill": "skills/remediation",
                "detection_status": "detection",
                "detection_rule": {"sigma_id": "test-sqli", "splunk_spl": "", "sentinel_kql": "", "elastic_eql": ""},
                "validation_gate": {
                    "status": "PASS",
                    "evaluator": "agents/validation.md",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "provenance_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "q1_in_scope": {"result": True, "notes": ""},
                    "q2_grounded": {"result": True, "evidence_ref": "EVD-101", "notes": ""},
                    "q3_reachable": {"result": True, "notes": ""},
                    "q4_controllable": {"result": True, "notes": ""},
                    "q5_impactful": {"result": True, "notes": ""},
                    "q6_default_vs_custom": {"result": "DEFAULT", "notes": ""},
                    "q7_severity_honest": {"result": True, "notes": ""},
                    "verdict": {"status": "PASS", "failed_gate": None, "reason": "All gates passed", "evidence_refs": []},
                },
                "emulation": {"atomic_test_id": "", "caldera_ability_id": "", "coverage_tier": "none", "mttd_seconds": 0},
                "supply_chain": {"package_name": "", "package_version": "", "ecosystem": "", "confusion_type": ""},
                "threat_intel": {"actor": "", "campaign": "", "confidence": "low", "tlp": "TLP:CLEAR"},
                "ics": {"protocol": "", "purdue_level": 0, "safety_impact": "none"},
                "classifications": {
                    "cvss_v31": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "base_score": 9.1},
                    "cvss_v40": {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", "base_score": 9.3},
                    "epss": {"score": 0.8, "percentile": 90.0},
                    "cisa_kev": False,
                    "mitre_attack": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
                    "mitre_atlas": [],
                    "cwe": [{"id": "CWE-89", "name": "SQL Injection"}],
                    "owasp": [{"id": "A03:2021", "name": "Injection"}],
                },
            }
        }
        report = self.validator.validate(finding)
        self.assertTrue(report.is_valid, f"Validation failed: {report.errors}")


class TestSkillWiring(unittest.TestCase):
    """Verify skill reference docs reference the payload resolver."""

    def test_recon_skill_documents_payload_lookup(self):
        recon_skill = os.path.join(ROOT, "skills", "recon", "SKILL.md")
        self.assertTrue(os.path.exists(recon_skill))
        with open(recon_skill, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("payload_lookup", content.lower() or "agent_payloads" in content.lower())

    def test_attack_chain_skill_documents_payload_lookup(self):
        attack_skill = os.path.join(ROOT, "skills", "attack-chain", "SKILL.md")
        self.assertTrue(os.path.exists(attack_skill))
        with open(attack_skill, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("payload_lookup", content.lower() or "agent_payloads" in content.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)