#!/usr/bin/env python3
"""Standard unittest suite for NIGHTFANG core components.

Runs under plain Python stdlib (no pytest required).

Usage:
    python tests/test_core.py
"""
import unittest
import os
import sys
import time
import importlib.util

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
    CODE_SCOPE_VIOLATION,
    CODE_MISSING_OPSEC_DECLARATION,
    CODE_EMERGENCY_STOP_ACTIVE,
    CODE_DESTRUCTIVE_PAYLOAD_DETECTED,
    CODE_CLOUD_EDGE_VIOLATION,
)
from tools.daemon import (
    AutonomousHunterDaemon,
    HunterTask,
    TaskPriority,
    AutonomyTier,
)
from schemas.validator import FindingValidator
from tools.sandbox import SandboxRunner


class TestGateway(unittest.TestCase):
    def setUp(self):
        self.cfg = EngagementConfig(
            engagement_id="ENG-TEST",
            authorized_operator="test-operator",
            authorized_cidrs=["192.168.1.0/24", "10.0.0.0/8"],
            authorized_domains=["*.target.corp", "target.corp", "api.internal"],
            max_opsec_noise=NoiseProfile.LOUD,
        )
        self.state = EngagementState(self.cfg)
        self.gateway = ExecutionPolicyGateway(self.state, resolve_dns=False)

    def make_request(self, **kwargs):
        defaults = {
            "request_id": "req-test",
            "engagement_id": "ENG-TEST",
            "agent_id": "recon",
            "skill_id": "skills/recon",
            "tool_name": "curl",
            "target": TargetSpec(raw_target="https://target.corp/"),
            "opsec": OpsecSpec(noise=NoiseProfile.QUIET),
            "command_template": "curl https://target.corp/",
            "action_type": ActionType.PASSIVE_READ,
            "technique": "banner-grab",
        }
        defaults.update(kwargs)
        return ToolInvocationRequest(**defaults)

    def test_scope_violation_blocked(self):
        req = self.make_request(
            request_id="req-01",
            target=TargetSpec(raw_target="https://evil.external.com/"),
            command_template="nmap -sV evil.external.com",
            tool_name="nmap",
        )
        d = self.gateway.evaluate(req)
        self.assertEqual(d.status, DispositionStatus.REJECTED)
        self.assertEqual(d.code, CODE_SCOPE_VIOLATION)

    def test_missing_opsec_rejected(self):
        req = self.make_request(request_id="req-02", opsec=None)
        d = self.gateway.evaluate(req)
        self.assertEqual(d.status, DispositionStatus.REJECTED)
        self.assertEqual(d.code, CODE_MISSING_OPSEC_DECLARATION)

    def test_emergency_stop_intercept(self):
        self.state.trigger_emergency_stop("Test Stop")
        req = self.make_request(request_id="req-03")
        d = self.gateway.evaluate(req)
        self.assertEqual(d.status, DispositionStatus.REJECTED)
        self.assertEqual(d.code, CODE_EMERGENCY_STOP_ACTIVE)
        self.state.resume_emergency_stop()

    def test_rate_injection_ffuf(self):
        req = self.make_request(
            request_id="req-04",
            agent_id="scanner",
            skill_id="skills/web",
            tool_name="ffuf",
            target=TargetSpec(raw_target="https://api.internal/v1"),
            opsec=OpsecSpec(noise=NoiseProfile.MODERATE),
            command_template="ffuf -u https://api.internal/v1/FUZZ -w wordlist.txt",
            action_type=ActionType.ACTIVE_PROBE,
        )
        d = self.gateway.evaluate(req)
        self.assertEqual(d.status, DispositionStatus.APPROVED)
        self.assertIn("-rate 20", d.modified_command)

    def test_hitl_required_on_loud_exploit(self):
        req = self.make_request(
            request_id="req-05",
            agent_id="validation",
            skill_id="skills/attack-chain",
            tool_name="nuclei",
            target=TargetSpec(raw_target="https://target.corp/login"),
            opsec=OpsecSpec(noise=NoiseProfile.LOUD),
            command_template="nuclei -target https://target.corp/login -id sqli-probe",
            action_type=ActionType.EXPLOIT_POC,
            finding_id="NF-2026-0001",
        )
        d = self.gateway.evaluate(req)
        self.assertEqual(d.status, DispositionStatus.HITL_REQUIRED)
        self.assertIsNotNone(d.hitl_request)

    def test_token_resumption(self):
        req = self.make_request(
            request_id="req-05b",
            agent_id="validation",
            skill_id="skills/attack-chain",
            tool_name="nuclei",
            target=TargetSpec(raw_target="https://target.corp/login"),
            opsec=OpsecSpec(noise=NoiseProfile.LOUD),
            command_template="nuclei -target https://target.corp/login -id sqli-probe",
            action_type=ActionType.EXPLOIT_POC,
            finding_id="NF-2026-0001",
        )
        d1 = self.gateway.evaluate(req)
        self.assertEqual(d1.status, DispositionStatus.HITL_REQUIRED)

        tok = issue_approval_token(self.state, "req-05b", "test-operator", ttl_seconds=60)
        self.assertIsNotNone(tok)

        d2 = self.gateway.evaluate(req)
        self.assertEqual(d2.status, DispositionStatus.APPROVED)

    def test_destructive_filter_blocks_rm(self):
        req = self.make_request(
            request_id="req-06",
            agent_id="validation",
            skill_id="skills/attack-chain",
            tool_name="curl",
            command_template="curl -d 'cmd=rm -rf /' https://target.corp/",
        )
        d = self.gateway.evaluate(req)
        self.assertEqual(d.status, DispositionStatus.REJECTED)
        self.assertEqual(d.code, CODE_DESTRUCTIVE_PAYLOAD_DETECTED)

    def test_ipv6_cidr_match(self):
        self.state.config.authorized_cidrs.append("2001:db8::/32")
        req = self.make_request(
            request_id="req-07",
            agent_id="scanner",
            skill_id="skills/network",
            tool_name="nmap",
            target=TargetSpec(raw_target="[2001:db8::1]:8080"),
            opsec=OpsecSpec(noise=NoiseProfile.MODERATE),
            command_template="nmap -6 [2001:db8::1] -p 8080",
            action_type=ActionType.ACTIVE_PROBE,
        )
        d = self.gateway.evaluate(req)
        self.assertEqual(d.status, DispositionStatus.APPROVED)
        self.assertEqual(req.target.hostname, "2001:db8::1")
        self.assertEqual(req.target.port, 8080)

    def test_s3_cloud_edge_blocked(self):
        req = self.make_request(
            request_id="req-08",
            agent_id="scanner",
            skill_id="skills/cloud",
            tool_name="curl",
            target=TargetSpec(raw_target="https://mybucket.s3.amazonaws.com/"),
            opsec=OpsecSpec(noise=NoiseProfile.LOUD),
            command_template="curl https://mybucket.s3.amazonaws.com/",
            action_type=ActionType.ACTIVE_PROBE,
        )
        d = self.gateway.evaluate(req)
        self.assertEqual(d.status, DispositionStatus.REJECTED)
        self.assertEqual(d.code, CODE_CLOUD_EDGE_VIOLATION)

    def test_rate_clamping(self):
        req = self.make_request(
            request_id="req-09",
            agent_id="scanner",
            skill_id="skills/web",
            tool_name="ffuf",
            opsec=OpsecSpec(noise=NoiseProfile.MODERATE),
            command_template="ffuf -rate 500 -u https://target.corp/FUZZ -w wordlist.txt",
            action_type=ActionType.ACTIVE_PROBE,
        )
        d = self.gateway.evaluate(req)
        self.assertEqual(d.status, DispositionStatus.APPROVED)
        self.assertIn("-rate 20", d.modified_command)
        self.assertNotIn("-rate 500", d.modified_command)


class TestDaemon(unittest.TestCase):
    def setUp(self):
        cfg = EngagementConfig(
            engagement_id="ENG-DAEMON-TEST",
            authorized_operator="lead-tester",
            authorized_domains=["target.corp", "*.target.corp"],
            autonomy_tier=AutonomyTier.SEMI_AUTONOMOUS,
        )
        self.daemon = AutonomousHunterDaemon(cfg)

    def test_priority_queue_ordering(self):
        t_low = HunterTask.create("t-low", TaskPriority.LOW, "t.c", "r", "r", "e", "echo low", NoiseProfile.QUIET, ActionType.PASSIVE_READ)
        t_high = HunterTask.create("t-high", TaskPriority.HIGH, "t.c", "r", "r", "e", "echo high", NoiseProfile.QUIET, ActionType.PASSIVE_READ)
        t_crit = HunterTask.create("t-crit", TaskPriority.CRITICAL, "t.c", "r", "r", "e", "echo crit", NoiseProfile.QUIET, ActionType.PASSIVE_READ)
        t_med = HunterTask.create("t-med", TaskPriority.MEDIUM, "t.c", "r", "r", "e", "echo med", NoiseProfile.QUIET, ActionType.PASSIVE_READ)

        self.daemon.queue.push(t_low)
        self.daemon.queue.push(t_high)
        self.daemon.queue.push(t_crit)
        self.daemon.queue.push(t_med)

        self.assertEqual(self.daemon.queue.pop().task_id, "t-crit")
        self.assertEqual(self.daemon.queue.pop().task_id, "t-high")
        self.assertEqual(self.daemon.queue.pop().task_id, "t-med")
        self.assertEqual(self.daemon.queue.pop().task_id, "t-low")

    def test_semi_autonomous_auto_execution(self):
        t_passive = HunterTask.create(
            "t-pass", TaskPriority.MEDIUM, "target.corp", "recon", "recon",
            "echo", "echo 'api.target.corp discovered'", NoiseProfile.QUIET, ActionType.PASSIVE_READ
        )
        self.daemon.queue.push(t_passive)
        res = self.daemon.execute_next_task()
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertIn("api.target.corp", self.daemon.discovered_assets)

    def test_non_blocking_hitl(self):
        while self.daemon.queue.pop() is not None:
            pass

        t_exploit = HunterTask.create(
            "t-exp", TaskPriority.CRITICAL, "target.corp", "scanner", "scanner",
            "sqlmap", "echo 'simulated exploit'", NoiseProfile.LOUD, ActionType.EXPLOIT_POC,
            technique="SQL Injection Verification"
        )
        t_background = HunterTask.create(
            "t-bg", TaskPriority.LOW, "target.corp", "recon", "recon",
            "echo", "echo 'crawling background'", NoiseProfile.QUIET, ActionType.PASSIVE_READ
        )
        self.daemon.queue.push(t_exploit)
        self.daemon.queue.push(t_background)

        res_exp = self.daemon.execute_next_task()
        self.assertIsNotNone(res_exp)
        self.assertEqual(res_exp["status"], "PAUSED_FOR_APPROVAL")
        self.assertEqual(self.daemon.queue.paused_count(), 1)

        res_bg = self.daemon.execute_next_task()
        self.assertIsNotNone(res_bg)
        self.assertEqual(res_bg["status"], "COMPLETED")

    def test_approve_deny_resumption(self):
        while self.daemon.queue.pop() is not None:
            pass
        t_exploit = HunterTask.create(
            "t-exp2", TaskPriority.CRITICAL, "target.corp", "scanner", "scanner",
            "sqlmap", "echo 'simulated exploit'", NoiseProfile.LOUD, ActionType.EXPLOIT_POC,
        )
        self.daemon.queue.push(t_exploit)

        res = self.daemon.execute_next_task()
        self.assertEqual(res["status"], "PAUSED_FOR_APPROVAL")

        approved = self.daemon.approve_hitl_task("t-exp2", operator_id="lead-tester")
        self.assertTrue(approved)

        resumed = self.daemon.execute_next_task()
        self.assertIsNotNone(resumed)
        self.assertEqual(resumed["task_id"], "t-exp2")
        self.assertEqual(resumed["status"], "COMPLETED")

    def test_self_healing_backoff(self):
        self.daemon.state.trigger_rate_backoff("target.corp", "Simulated 429")
        rate_info = self.daemon.state.rate_state.get("target.corp")
        self.assertIsNotNone(rate_info)
        self.assertLess(rate_info["current_rate"], 20)


class TestValidator(unittest.TestCase):
    def setUp(self):
        self.validator = FindingValidator()

    def test_valid_finding_passes(self):
        valid = {
            "finding": {
                "id": "NF-2026-001",
                "title": "Test Finding",
                "target": "https://target.corp/",
                "category": "web",
                "timestamp": "2026-01-01T00:00:00Z",
                "tool_used": "nuclei",
                "cve": "CVE-2026-1234",
                "confidence": {"score": 8, "rationale": "Confirmed via benign canary"},
                "severity": {"score": 8, "level": "high", "rationale": "High impact"},
                "evidence_grounding": {"score": 0.95, "bucket": "CERTAIN", "rationale": "Raw artifact verified"},
                "evidence": [{"type": "http_response", "description": "Test", "data": "HTTP/1.1 200 OK"}],
                "reproduction": [{"step": 1, "action": "Test", "command": "curl ..."}],
                "impact": {"technical": "Test", "business": "Test"},
                "remediation": {"guidance": "Fix it", "mitre_d3fend": [], "references": []},
                "validated_by_blue_skill": "skills/remediation",
                "detection_status": "detection",
                "detection_rule": {"sigma_id": "test", "splunk_spl": "", "sentinel_kql": "", "elastic_eql": ""},
                "validation_gate": {
                    "status": "PASS",
                    "evaluator": "agents/validation.md",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "provenance_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "q1_in_scope": {"result": True, "notes": ""},
                    "q2_grounded": {"result": True, "evidence_ref": "EVD-042", "notes": ""},
                    "q3_reachable": {"result": True, "notes": ""},
                    "q4_controllable": {"result": True, "notes": ""},
                    "q5_impactful": {"result": True, "notes": ""},
                    "q6_default_vs_custom": {"result": "DEFAULT", "notes": ""},
                    "q7_severity_honest": {"result": True, "notes": ""},
                    "verdict": {"status": "PASS", "failed_gate": None, "reason": "All 7 adversarial gates passed with evidence grounding.", "evidence_refs": []},
                },
                "emulation": {"atomic_test_id": "", "caldera_ability_id": "", "coverage_tier": "none", "mttd_seconds": 0},
                "supply_chain": {"package_name": "", "package_version": "", "ecosystem": "", "confusion_type": ""},
                "threat_intel": {"actor": "", "campaign": "", "confidence": "low", "tlp": "TLP:CLEAR"},
                "ics": {"protocol": "", "purdue_level": 0, "safety_impact": "none"},
                "classifications": {
                    "cvss_v31": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "base_score": 9.8},
                    "cvss_v40": {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", "base_score": 9.3},
                    "epss": {"score": 0.5, "percentile": 50.0},
                    "cisa_kev": False,
                    "mitre_attack": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
                    "mitre_atlas": [],
                    "cwe": [{"id": "CWE-89", "name": "SQL Injection"}],
                    "owasp": [{"id": "A03:2021", "name": "Injection"}],
                },
            }
        }
        report = self.validator.validate(valid)
        self.assertTrue(report.is_valid)

    def test_malformed_finding_catches_errors(self):
        invalid = {
            "finding": {
                "id": "INVALID",
                "title": "Test",
                "target": "https://target.corp/",
                "category": "web",
                "timestamp": "not-iso-8601",
                "tool_used": "nuclei",
                "cve": "",
                "confidence": {"score": 15, "rationale": ""},
                "severity": {"score": 10, "level": "medium", "rationale": ""},
                "evidence_grounding": {"score": 0.95, "bucket": "WEAK", "rationale": ""},
                "evidence": [{"type": "INVALID_TYPE", "data": "bad"}],
                "reproduction": [],
                "impact": {},
                "remediation": {},
                "validated_by_blue_skill": "",
                "detection_status": "INVALID_DET_STATUS",
                "detection_rule": {"sigma_id": "", "splunk_spl": "", "sentinel_kql": "", "elastic_eql": ""},
                "validation_gate": {
                    "status": "INVALID_STATUS",
                    "provenance_hash": "not_a_sha256",
                    "q1_in_scope": {"result": False, "notes": ""},
                    "q2_grounded": {"result": False, "evidence_ref": "", "notes": ""},
                    "q3_reachable": {"result": False, "notes": ""},
                    "q4_controllable": {"result": False, "notes": ""},
                    "q5_impactful": {"result": False, "notes": ""},
                    "q6_default_vs_custom": {"result": "INVALID", "notes": ""},
                    "q7_severity_honest": {"result": False, "notes": ""},
                    "verdict": {"status": "PASS", "failed_gate": None, "reason": "", "evidence_refs": []},
                },
                "emulation": {"atomic_test_id": "", "caldera_ability_id": "", "coverage_tier": "none", "mttd_seconds": 0},
                "supply_chain": {"package_name": "", "package_version": "", "ecosystem": "", "confusion_type": ""},
                "threat_intel": {"actor": "", "campaign": "", "confidence": "low", "tlp": "TLP:CLEAR"},
                "ics": {"protocol": "", "purdue_level": 0, "safety_impact": "none"},
                "classifications": {
                    "cvss_v31": {"vector": "INVALID_CVSS", "base_score": 15.0},
                    "cvss_v40": {"vector": "", "base_score": 0.0},
                    "epss": {"score": 9.9, "percentile": 200.0},
                    "cisa_kev": "maybe",
                    "mitre_attack": [{"id": "INVALID_ATTACK_ID"}],
                    "mitre_atlas": [],
                    "cwe": [{"id": "CWE-89", "name": "SQL Injection"}],
                    "owasp": [{"name": "Missing ID"}],
                },
            }
        }
        report = self.validator.validate(invalid)
        self.assertFalse(report.is_valid)
        self.assertGreaterEqual(len(report.errors), 12)


class TestSandbox(unittest.TestCase):
    def setUp(self):
        self.sandbox = SandboxRunner()

    def test_command_dispatch(self):
        res = self.sandbox.run("echo NIGHTFANG_SANDBOX_OK", timeout=10)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIn("NIGHTFANG_SANDBOX_OK", res["stdout"])

    def test_timeout_enforcement(self):
        t_start = time.time()
        sleep_cmd = "ping -n 5 127.0.0.1" if os.name == "nt" else "sleep 3"
        res = self.sandbox.run(sleep_cmd, timeout=1)
        duration = time.time() - t_start
        self.assertEqual(res["status"], "TIMEOUT")
        self.assertLess(duration, 2.5)


class TestPayloadLookup(unittest.TestCase):
    def test_script_loads_and_lists(self):
        spec = importlib.util.spec_from_file_location(
            "payload_lookup", os.path.join(ROOT, "scripts", "payload_lookup.py")
        )
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        catalog = module.load_index()
        self.assertGreater(len(catalog), 10)
        # Every class must have CWE + payload file list
        for name, meta in catalog.items():
            self.assertIn("cwe", meta)
            self.assertIn("payload_files", meta)


if __name__ == "__main__":
    unittest.main(verbosity=2)