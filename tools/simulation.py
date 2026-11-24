#!/usr/bin/env python3
"""
NIGHTFANG Integrated End-to-End Engagement Simulation Harness (tools/simulation.py)

Simulates and verifies the full autonomous offensive engagement lifecycle:
1. Target Scoping & Configuration Boundary
2. Passive Reconnaissance & Attack Surface Lead Expansion
3. Active Service & Vulnerability Discovery
4. Multi-Tool Finding Ingestion & Schema Normalization
5. Non-Blocking Human-in-the-Loop (HITL) Gate Assertion
6. Operator Approval & Sandbox PoC Verification
7. Master Assessment Report Synthesis (templates/full_report_template.md)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

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
        HitlApprovalToken,
        approve_request,
    )
    from tools.daemon import (
        AutonomousHunterDaemon,
        HunterTask,
        TaskPriority,
        TaskStatus,
    )
    from tools.sandbox import SandboxRunner
    from tools.ingest import FindingIngestor
    from schemas.validator import FindingValidator
    from tools.channel_card import ChannelCardFormatter
    from tools.finding_sync import FindingSyncManager
    from tools.verifier import AdversarialVerifier
except ImportError:
    sys.path.insert(0, os.path.join(repo_root, "tools"))
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
        HitlApprovalToken,
        approve_request,
    )
    from daemon import (
        AutonomousHunterDaemon,
        HunterTask,
        TaskPriority,
        TaskStatus,
    )
    from sandbox import SandboxRunner
    from ingest import FindingIngestor
    from schemas.validator import FindingValidator
    from channel_card import ChannelCardFormatter
    from finding_sync import FindingSyncManager
    from verifier import AdversarialVerifier


class EngagementSimulator:
    """Executes a complete simulated penetration testing engagement lifecycle."""

    def __init__(
        self,
        target_domain: str = "target.corp",
        cidr: str = "10.0.0.0/8",
        operator: str = "sim-operator",
    ) -> None:
        self.target_domain = target_domain
        self.cidr = cidr
        self.operator = operator
        self.engagement_id = f"ENG-SIM-{int(time.time())}"

        self.config = EngagementConfig(
            engagement_id=self.engagement_id,
            authorized_operator=self.operator,
            authorized_cidrs=[self.cidr, "127.0.0.1/32"],
            authorized_domains=[self.target_domain, f"*.{self.target_domain}"],
            autonomy_tier=AutonomyTier.SEMI_AUTONOMOUS,
            strict_hitl=True,
        )

        self.daemon = AutonomousHunterDaemon(self.config)
        self.ingestor = FindingIngestor()
        self.sandbox = SandboxRunner()
        self.findings: List[Dict[str, Any]] = []
        self.execution_logs: List[str] = []

    def log(self, message: str) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{timestamp}] [SIMULATION] {message}"
        self.execution_logs.append(entry)

    def phase1_initialize(self) -> bool:
        """Phase 1: Initialize target scope and verify boundaries."""
        self.log(f"Phase 1: Initializing scope for '{self.target_domain}' within CIDR '{self.cidr}'...")
        assert self.daemon.gateway._is_in_scope(self.target_domain)
        assert self.daemon.gateway._is_in_scope(f"sub.{self.target_domain}")
        assert not self.daemon.gateway._is_in_scope("unauthorized.com")
        self.daemon.seed_target(self.target_domain)
        self.log("Phase 1 Complete: Engagement scope boundaries locked.")
        return True

    def phase2_recon_expansion(self) -> List[str]:
        """Phase 2: Simulate passive reconnaissance & attack surface expansion."""
        self.log("Phase 2: Running passive reconnaissance and attack surface lead expansion...")
        # Pop seed task
        seed_task = self.daemon.queue.pop()
        assert seed_task is not None
        self.log(f"Popped initial task: {seed_task.task_id} ({seed_task.technique})")

        # Simulate discovery of newly identified subdomains
        discovered_subdomains = [f"api.{self.target_domain}", f"admin.{self.target_domain}"]
        for sub in discovered_subdomains:
            self.daemon.discovered_assets.add(sub)
            scan_task = HunterTask.create(
                task_id=f"task-scan-{sub.replace('.', '-')}",
                priority=TaskPriority.HIGH,
                target_str=sub,
                capability_id="web-vulnerability-scanning",
                agent_id="scanner",
                tool_name="nuclei",
                command_template=f"nuclei -target https://{sub} -severity critical,high",
                noise_profile=NoiseProfile.MODERATE,
                action_type=ActionType.ACTIVE_PROBE,
                technique="Targeted Service Vulnerability Probe",
            )
            self.daemon.queue.push(scan_task)
            self.log(f"Queued active scan task for discovered asset: {sub}")

        self.log(f"Phase 2 Complete: Discovered {len(discovered_subdomains)} subdomains and expanded queue.")
        return discovered_subdomains

    def phase3_active_scanning(self) -> Dict[str, Any]:
        """Phase 3: Execute active scan task and produce vulnerability evidence."""
        self.log("Phase 3: Dispatching active scan against discovered assets...")
        task = self.daemon.queue.pop()
        assert task is not None
        self.log(f"Executing active scan task {task.task_id} against {task.target_str}...")

        # Mock raw scanner finding output (Nuclei JSONL)
        mock_nuclei_output = json.dumps({
            "template-id": "sqli-auth-bypass-cve-2024-001",
            "info": {
                "name": "SQL Injection in Authentication API",
                "severity": "critical",
                "remediation": "Utilize parameterized SQL queries and input validation.",
            },
            "matched-at": f"https://{task.target_str}/v1/auth/login",
            "host": task.target_str,
            "curl-command": f"curl -X POST https://{task.target_str}/v1/auth/login -d \"user=' OR 1=1--\"",
            "extracted-results": "Database syntax error: unexpected quote near OR 1=1",
        })

        self.log(f"Phase 3 Complete: Active scan completed for {task.target_str}.")
        return {"raw_output": mock_nuclei_output, "target": task.target_str}

    def phase4_ingest_and_validate(self, raw_scan: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 4: Ingest raw scan output into normalized and validated finding schema."""
        self.log("Phase 4: Ingesting raw scanner telemetry into Finding Ingestor...")
        parsed_findings, errors = self.ingestor.ingest(raw_scan["raw_output"], tool_hint="nuclei")
        assert len(parsed_findings) > 0, f"Ingestion failed: {errors}"
        finding = parsed_findings[0]
        self.findings.append(finding)
        self.log(f"Phase 4 Complete: Finding {finding['finding']['id']} normalized and validated 100%.")
        return finding

    def phase5_hitl_trigger(self, finding: Dict[str, Any]) -> Tuple[ToolInvocationRequest, str]:
        """Phase 5: Queue invasive exploit PoC and assert non-blocking HITL gate pauses task."""
        self.log("Phase 5: Enqueuing Stage 3 Invasive Exploit PoC requiring operator authorization...")
        target_str = finding["finding"]["target"]
        hostname = finding["finding"]["target"].split("//")[-1].split("/")[0]

        req = ToolInvocationRequest(
            request_id="poc-exploit-task-1",
            engagement_id=self.engagement_id,
            agent_id="exploit",
            skill_id="skills/exploit",
            tool_name="sqlmap_poc",
            target=TargetSpec(raw_target=target_str, hostname=hostname),
            opsec=OpsecSpec(noise=NoiseProfile.LOUD, rationale="Invasive PoC validation"),
            command_template="echo '[SIMULATED_POC] Exploitation verified non-destructively'",
            action_type=ActionType.EXPLOIT_POC,
            technique="Automated SQL Injection Exploit Verification",
            finding_id=finding["finding"]["id"],
        )

        disp = self.daemon.gateway.evaluate(req)
        assert disp.status == DispositionStatus.HITL_REQUIRED, f"Expected HITL_REQUIRED, got {disp.status}"
        assert req.request_id in self.daemon.state.pending_hitl_requests
        self.log(f"Phase 5 Complete: HITL Gate triggered successfully. Request ID: {req.request_id}")
        return req, req.request_id

    def phase6_operator_approval_and_execution(self, req: ToolInvocationRequest, req_id: str) -> Dict[str, Any]:
        """Phase 6: Simulate operator approval, mint cryptographic token, and execute sandbox PoC."""
        self.log(f"Phase 6: Operator '{self.operator}' approving pending HITL request {req_id}...")
        token = approve_request(self.daemon.state, req_id, operator_id=self.operator)
        assert token is not None and token.token_id in self.daemon.state.hitl_tokens
        self.log(f"Cryptographic 5-D HITL token minted: {token.token_id}")

        # Re-evaluate through gateway
        disp = self.daemon.gateway.evaluate(req)
        assert disp.status == DispositionStatus.APPROVED, f"Expected APPROVED with token, got {disp.status}"

        # Dispatch via SandboxRunner
        self.log("Dispatching non-destructive PoC in Containerized Sandbox...")
        sandbox_res = self.sandbox.run(req.command_template, timeout=10)
        assert sandbox_res["status"] == "SUCCESS", f"Sandbox execution failed: {sandbox_res}"

        # Cryptographic evidence artifact
        evd_hash = hashlib.sha256(sandbox_res["stdout"].encode("utf-8")).hexdigest()
        evd_tag = f"[EVD-{evd_hash[:8].upper()}]"
        self.log(f"Phase 6 Complete: PoC executed in sandbox. Evidence tag: {evd_tag} (SHA: {evd_hash[:16]}...)")
        return {"result": sandbox_res, "evidence_tag": evd_tag, "sha256": evd_hash}

    def phase7_synthesize_master_report(self) -> str:
        """Phase 7: Synthesize master report deliverable formatted per templates/full_report_template.md."""
        self.log("Phase 7: Synthesizing master assessment report deliverable...")
        start_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        findings_markdown = ""
        for idx, f in enumerate(self.findings, 1):
            fd = f["finding"]
            findings_markdown += f"""
### 2.{idx} {fd['title']}
- **Finding ID**: `{fd['id']}`
- **Target**: `{fd['target']}`
- **Severity**: **{fd['severity']['level'].upper()}** (Score: {fd['severity']['score']}/10)
- **Confidence**: {fd['confidence']['score']}/10 ({fd['confidence']['rationale']})
- **Remediation Guidance**: {fd['remediation']['guidance']}
- **Validation Gate Verdict**: {fd['validation_gate']['verdict']['status']}
"""

        report = f"""# Penetration Testing & Security Assessment Master Report

> **Schema Contract:** [`schemas/finding.md`](schemas/finding.md)  
> **Security Pack:** NIGHTFANG  
> **Host Runtime:** Hermes  

---

## 1. Document Control

| Property | Value |
| :--- | :--- |
| **Engagement Name** | `Autonomous Security Assessment: {self.target_domain}` |
| **Engagement ID** | `{self.engagement_id}` |
| **Target Organization** | `Target Corp` |
| **Assessment Window** | `{start_date}` to `{start_date}` |
| **Document Version** | `1.0.0 (Final)` |
| **Lead Operator** | `{self.operator}` (Host Runtime: Hermes) |
| **Orchestration Layer** | NIGHTFANG Security Capability Pack |
| **Classification** | **CONFIDENTIAL / RESTRICTED** |

---

## 2. Assessment Findings Summary

{findings_markdown}

---

## 3. Autonomous Execution Audit Log
```
{chr(10).join(self.execution_logs)}
```
"""
        self.log("Phase 7 Complete: Master report generated successfully.")
        return report

    def phase8_channel_cards_and_sync_verification(self, finding: Dict[str, Any], req: Any, req_id: str) -> None:
        """Phase 8: Verify Telegram channel cards formatting, finding sync & knowledge graph emission."""
        formatter = ChannelCardFormatter()
        state = {
            "engagement_id": self.engagement_id,
            "target_scope": [self.target_domain],
            "autonomy_tier": "SEMI_AUTONOMOUS",
            "status": "ACTIVE",
            "progress": 100.0,
            "queue_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "active_tasks": [],
            "rate_backoffs": {},
            "pending_hitl": [],
        }
        status_card = formatter.format_status_card(state)
        assert "NIGHTFANG HUNT STATUS" in status_card
        assert "[██████████] 100%" in status_card

        hitl_dict = {
            "token": req_id,
            "target": req.target.hostname or req.target.raw_target,
            "tool": req.tool_name,
            "noise_profile": req.opsec.noise.value if hasattr(req.opsec.noise, "value") else str(req.opsec.noise),
            "technique": req.technique,
            "command": "sqlmap -u 'https://api.target.corp/v1/search' --batch --banner",
        }
        hitl_card = formatter.format_hitl_card(hitl_dict)
        assert f"/go {req_id}" in hitl_card
        assert f"/hold {req_id}" in hitl_card

        alert_card = formatter.format_finding_alert(finding)
        assert "NIGHTFANG FINDING ALERT" in alert_card

        # Verify target-partitioned overview
        overview = formatter.format_findings_overview([finding])
        assert self.target_domain in overview

        # Verify Adversarial Verifier Gate
        verifier = AdversarialVerifier()
        eval_res = verifier.evaluate_finding(finding)
        assert eval_res.verdict == "CONFIRMED"

        # Verify Canary Registration & Cleanup
        canary = verifier.register_canary("sim-canary-01", self.target_domain, "test_file", "/tmp/poc_test.txt")
        clean_ok, _ = verifier.verify_cleanup("sim-canary-01", mock_http_status=404)
        assert clean_ok

        self.log("Phase 8 Complete: Channel cards, adversarial verification & canary cleanup verified.")

    def run_full_simulation(self) -> str:
        """Execute all phases sequentially and return the completed report."""
        self.phase1_initialize()
        subs = self.phase2_recon_expansion()
        raw_scan = self.phase3_active_scanning()
        finding = self.phase4_ingest_and_validate(raw_scan)
        req, req_id = self.phase5_hitl_trigger(finding)
        self.phase6_operator_approval_and_execution(req, req_id)
        report = self.phase7_synthesize_master_report()
        self.phase8_channel_cards_and_sync_verification(finding, req, req_id)
        return report


def run_self_tests() -> bool:
    """Run automated verification suite for End-to-End Engagement Simulation."""
    print("Running NIGHTFANG End-to-End Engagement Lifecycle Simulation Self-Tests...")
    sim = EngagementSimulator()
    report = sim.run_full_simulation()

    assert "Penetration Testing & Security Assessment Master Report" in report
    assert sim.engagement_id in report
    assert len(sim.findings) == 1
    assert sim.findings[0]["finding"]["severity"]["level"] == "critical"
    print("  [PASS] Phase 1: Target scoping boundary and CIDR locks verified.")
    print("  [PASS] Phase 2: Passive recon discovery & queue DAG expansion verified.")
    print("  [PASS] Phase 3: Active service and vulnerability scan telemetry captured.")
    print("  [PASS] Phase 4: Ingestion normalizer passed schema validation 100%.")
    print("  [PASS] Phase 5: Invasive exploit paused by non-blocking HITL gate.")
    print("  [PASS] Phase 6: Operator token issued, authorized, and sandbox PoC verified.")
    print("  [PASS] Phase 7: Master assessment markdown report synthesized.")
    print("  [PASS] Phase 8: Telegram channel cards, adversarial gate & canary cleanup verified.")

    print("\nAll Engagement Simulation self-tests PASSED successfully!")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIGHTFANG End-to-End Engagement Simulator")
    parser.add_argument("--test", action="store_true", help="Run automated lifecycle self-tests")
    parser.add_argument("--target", type=str, default="target.corp", help="Target domain for simulated engagement")
    parser.add_argument("--out", type=str, help="Output destination path for markdown engagement report")
    args = parser.parse_args()

    if args.test:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    sim = EngagementSimulator(target_domain=args.target)
    report = sim.run_full_simulation()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[*] Engagement report written to {args.out}")
    else:
        print(report)
    sys.exit(0)
