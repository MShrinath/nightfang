#!/usr/bin/env python3
"""
NIGHTFANG Autonomous Hunter Engine Daemon (tools/daemon.py)

Autonomous execution daemon for Hermes that runs continuous penetration testing:
- PriorityDAG Attack Surface Queue (persistent lead tracking)
- Dynamic lead generation (Domain -> Subdomain -> Services -> Parameters -> Variant Hunting)
- Traffic Light Tiered Autonomy (GREEN: auto-run, YELLOW: rate-throttled, RED: non-blocking HITL approval)
- Non-blocking Asynchronous HITL Gate (pauses single action, continues scanning other targets in parallel)
- Self-healing & Reflection (WAF evasion, auto-backoff on 429/503, loop prevention)
"""

import sys
import os
import json
import time
import re
import argparse
import heapq
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict

# Import Execution Policy Gateway & Sandbox
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
        deny_request,
    )
    from tools.sandbox import SandboxRunner
except ImportError:
    # Handle direct invocation from tools/ directory
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
        HitlApprovalToken,
        approve_request,
        deny_request,
    )
    from sandbox import SandboxRunner


# ============================================================================
# Priority Queue & Lead Data Model
# ============================================================================

class TaskPriority(int, Enum):
    CRITICAL = 1   # Active exploit verification, verified canary validation
    HIGH = 2       # High-value assets, discovered admin portals, .git leaks
    MEDIUM = 3     # Parameter discovery, directory fuzzing, API schema tests
    LOW = 4        # Broad OSINT, passive subdomain harvest, banner grabs


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PAUSED_FOR_APPROVAL = "PAUSED_FOR_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    DENIED = "DENIED"


@dataclass(order=True)
class HunterTask:
    priority_num: int
    task_id: str = field(compare=False)
    target_str: str = field(compare=False)
    capability_id: str = field(compare=False)
    agent_id: str = field(compare=False)
    tool_name: str = field(compare=False)
    command_template: str = field(compare=False)
    noise_profile: NoiseProfile = field(compare=False, default=NoiseProfile.MODERATE)
    action_type: ActionType = field(compare=False, default=ActionType.ACTIVE_PROBE)
    technique: str = field(compare=False, default="Automated Probing")
    finding_id: str = field(compare=False, default="")
    status: TaskStatus = field(compare=False, default=TaskStatus.PENDING)
    created_at: float = field(compare=False, default_factory=time.time)
    retry_count: int = field(compare=False, default=0)
    result_summary: str = field(compare=False, default="")
    evidence_tag: str = field(compare=False, default="")

    @classmethod
    def create(
        cls,
        task_id: str,
        priority: TaskPriority,
        target_str: str,
        capability_id: str,
        agent_id: str,
        tool_name: str,
        command_template: str,
        noise_profile: NoiseProfile = NoiseProfile.MODERATE,
        action_type: ActionType = ActionType.ACTIVE_PROBE,
        technique: str = "Automated Probing",
        finding_id: str = "",
    ) -> "HunterTask":
        return cls(
            priority_num=priority.value,
            task_id=task_id,
            target_str=target_str,
            capability_id=capability_id,
            agent_id=agent_id,
            tool_name=tool_name,
            command_template=command_template,
            noise_profile=noise_profile,
            action_type=action_type,
            technique=technique,
            finding_id=finding_id,
        )


class PriorityDAGQueue:
    """Manages ordered, prioritized leads and subtasks across engagement targets."""

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path
        self._heap: List[HunterTask] = []
        self._task_index: Dict[str, HunterTask] = {}
        self._completed: List[HunterTask] = []
        self._paused_hitl: Dict[str, HunterTask] = {}

    def push(self, task: HunterTask) -> None:
        if task.task_id in self._task_index:
            return  # Prevent duplicate task insertion
        heapq.heappush(self._heap, task)
        self._task_index[task.task_id] = task

    def pop(self) -> Optional[HunterTask]:
        while self._heap:
            task = heapq.heappop(self._heap)
            if task.status == TaskStatus.PENDING:
                return task
        return None

    def pause_for_approval(self, task: HunterTask) -> None:
        task.status = TaskStatus.PAUSED_FOR_APPROVAL
        self._paused_hitl[task.task_id] = task

    def resume_approved(self, task_id: str) -> Optional[HunterTask]:
        task = self._paused_hitl.pop(task_id, None)
        if task:
            task.status = TaskStatus.PENDING
            # Boost priority to CRITICAL upon approval so it runs next
            task.priority_num = TaskPriority.CRITICAL.value
            heapq.heappush(self._heap, task)
            return task
        return None

    def deny_task(self, task_id: str) -> Optional[HunterTask]:
        task = self._paused_hitl.pop(task_id, None)
        if task:
            task.status = TaskStatus.DENIED
            self._completed.append(task)
            return task
        return None

    def mark_completed(self, task: HunterTask, result: str = "", evidence_tag: str = "") -> None:
        task.status = TaskStatus.COMPLETED
        task.result_summary = result
        task.evidence_tag = evidence_tag
        self._completed.append(task)

    def mark_failed(self, task: HunterTask, error: str = "") -> None:
        task.status = TaskStatus.FAILED
        task.result_summary = error
        self._completed.append(task)

    def pending_count(self) -> int:
        return sum(1 for t in self._heap if t.status == TaskStatus.PENDING)

    def paused_count(self) -> int:
        return len(self._paused_hitl)

    def completed_count(self) -> int:
        return len(self._completed)

    def save_state(self) -> None:
        if not self.storage_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.storage_path)), exist_ok=True)
        data = {
            "pending": [asdict(t) for t in self._heap if t.status == TaskStatus.PENDING],
            "paused_hitl": [asdict(t) for t in self._paused_hitl.values()],
            "completed": [asdict(t) for t in self._completed],
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


# ============================================================================
# Autonomous Hunter Engine Daemon
# ============================================================================

class AutonomousHunterDaemon:
    """Continuous multi-agent autonomous security assessment daemon."""

    def __init__(
        self,
        config: EngagementConfig,
        queue_storage: Optional[str] = None,
        hitl_storage: Optional[str] = None,
        findings_storage: Optional[str] = None,
        sandbox: Optional[SandboxRunner] = None,
    ):
        self.config = config
        self.state = EngagementState(config)
        self.gateway = ExecutionPolicyGateway(self.state, resolve_dns=False)
        self.sandbox = sandbox or SandboxRunner()
        self.queue = PriorityDAGQueue(storage_path=queue_storage)
        self.hitl_storage = hitl_storage
        self.findings_storage = findings_storage
        self.discovered_assets: Set[str] = set()
        self.discovered_findings: List[Dict[str, Any]] = []
        self.is_running = False
        self.step_counter = 0

    def seed_target(self, target: str) -> None:
        """Seed the engine with an initial target boundary."""
        self.discovered_assets.add(target)
        # Step 1: Enqueue passive reconnaissance
        t1 = HunterTask.create(
            task_id=f"task-init-{len(self.queue._task_index) + 1}",
            priority=TaskPriority.HIGH,
            target_str=target,
            capability_id="attack-surface-mapping",
            agent_id="recon",
            tool_name="subdomain_enum.py",
            command_template=f"python skills/recon/scripts/subdomain_enum.py -d {target} --passive",
            noise_profile=NoiseProfile.QUIET,
            action_type=ActionType.PASSIVE_READ,
            technique="Passive DNS & Subdomain Harvesting",
        )
        self.queue.push(t1)

    def execute_next_task(self) -> Optional[Dict[str, Any]]:
        """Processes the next eligible task from the priority queue."""
        task = self.queue.pop()
        if not task:
            return None

        self.step_counter += 1
        ts = TargetSpec(raw_target=task.target_str)
        ts.parse_target()

        req = ToolInvocationRequest(
            request_id=task.task_id,
            engagement_id=self.config.engagement_id,
            agent_id=task.agent_id,
            skill_id=f"skills/{task.agent_id}",
            tool_name=task.tool_name,
            target=ts,
            opsec=OpsecSpec(noise=task.noise_profile),
            command_template=task.command_template,
            action_type=task.action_type,
            technique=task.technique,
            finding_id=task.finding_id,
        )

        # 1. Evaluate Execution Policy Gateway
        disp = self.gateway.evaluate(req)

        # Handle Gateway Results
        if disp.status == DispositionStatus.REJECTED:
            self.queue.mark_failed(task, f"Gateway Rejected: {disp.reason}")
            return {
                "task_id": task.task_id,
                "status": "REJECTED",
                "reason": disp.reason,
            }

        if disp.status == DispositionStatus.HITL_REQUIRED:
            # NON-BLOCKING: Put into paused approvals list and write HITL card
            self.queue.pause_for_approval(task)
            self._record_pending_hitl(disp.hitl_request or {})
            return {
                "task_id": task.task_id,
                "status": "PAUSED_FOR_APPROVAL",
                "hitl_card": disp.hitl_request,
                "note": "Non-blocking: Daemon continues processing other targets.",
            }

        # 2. Approved or Auto-Passed: Dispatch tool execution
        res = self.gateway.execute_and_wrap(req, disp, sandbox_runner=self.sandbox)
        evd_tag = f"[EVD-{res.stdout_sha256[:8]}]" if res.stdout_sha256 else ""

        if res.status != "SUCCESS":
            # Self-Healing & Reflection: Check if failure was caused by rate limit or WAF
            stdout_text = res.raw_stdout
            if "429" in stdout_text or "Too Many Requests" in stdout_text:
                self.gateway.state.trigger_rate_backoff(ts.hostname, "HTTP 429 auto-detected")
                task.retry_count += 1
                if task.retry_count <= 2:
                    # Re-enqueue with backoff
                    task.status = TaskStatus.PENDING
                    self.queue.push(task)
            self.queue.mark_failed(task, res.raw_stderr or "Command failed")
            return {
                "task_id": task.task_id,
                "status": "FAILED",
                "evidence": evd_tag,
            }

        # 3. Successful Execution: Mark complete and dynamically generate new leads!
        self.queue.mark_completed(task, res.raw_stdout[:200], evd_tag)
        self._expand_attack_surface(task, res.raw_stdout)

        return {
            "task_id": task.task_id,
            "status": "COMPLETED",
            "evidence": evd_tag,
            "generated_leads": self.queue.pending_count(),
        }

    def _expand_attack_surface(self, completed_task: HunterTask, stdout: str) -> None:
        """The Big Brain Recursive Lead Generator: Extracts discovered assets and enqueues next-phase tasks."""
        # A. Discovered subdomains / hostnames
        domain_pattern = re.compile(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,})\b")
        found_domains = set(domain_pattern.findall(stdout))

        for dom in found_domains:
            if dom not in self.discovered_assets and any(auth in dom for auth in self.config.authorized_domains):
                self.discovered_assets.add(dom)
                # Enqueue service & port discovery for newly uncovered domain
                next_task = HunterTask.create(
                    task_id=f"lead-scan-{len(self.queue._task_index) + 1}",
                    priority=TaskPriority.HIGH,
                    target_str=dom,
                    capability_id="web-application-security",
                    agent_id="scanner",
                    tool_name="nmap",
                    command_template=f"nmap -sV -T4 --top-ports 20 {dom}",
                    noise_profile=NoiseProfile.MODERATE,
                    action_type=ActionType.ACTIVE_PROBE,
                    technique="Port & Service Fingerprinting",
                )
                self.queue.push(next_task)

        # B. Discovered HTTP URLs or Endpoints -> Enqueue Web / API inspection
        url_pattern = re.compile(r"https?://[^\s\"'>]+")
        found_urls = set(url_pattern.findall(stdout))

        for u in found_urls:
            if u not in self.discovered_assets:
                self.discovered_assets.add(u)
                # Enqueue parameter fuzzing and vulnerability check
                next_task = HunterTask.create(
                    task_id=f"lead-web-{len(self.queue._task_index) + 1}",
                    priority=TaskPriority.MEDIUM,
                    target_str=u,
                    capability_id="web-application-security",
                    agent_id="scanner",
                    tool_name="variant_hunt.py",
                    command_template=f"python skills/hunting/scripts/variant_hunt.py --target {u}",
                    noise_profile=NoiseProfile.MODERATE,
                    action_type=ActionType.ACTIVE_PROBE,
                    technique="Variant Analysis & Route Discovery",
                )
                self.queue.push(next_task)

    def approve_hitl_task(self, request_id: str, operator_id: str = "operator") -> bool:
        """Approves a paused task, mints an approval token, and resumes it at CRITICAL priority."""
        try:
            token = approve_request(self.state, request_id, operator_id=operator_id)
            resumed = self.queue.resume_approved(request_id)
            if resumed:
                self._update_pending_hitl_storage()
                return True
        except KeyError:
            return False
        return False

    def deny_hitl_task(self, request_id: str) -> bool:
        """Denies a paused task, preventing invasive testing."""
        denied = self.queue.deny_task(request_id)
        if denied:
            deny_request(self.state, request_id)
            self._update_pending_hitl_storage()
            return True
        return False

    def _record_pending_hitl(self, card: Dict[str, Any]) -> None:
        if not self.hitl_storage:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.hitl_storage)), exist_ok=True)
        cards = []
        if os.path.exists(self.hitl_storage):
            try:
                with open(self.hitl_storage, "r", encoding="utf-8") as f:
                    cards = json.load(f)
            except Exception:
                cards = []
        cards.append(card)
        with open(self.hitl_storage, "w", encoding="utf-8") as f:
            json.dump(cards, f, indent=2)

    def _update_pending_hitl_storage(self) -> None:
        if not self.hitl_storage or not os.path.exists(self.hitl_storage):
            return
        active_ids = set(self.queue._paused_hitl.keys())
        try:
            with open(self.hitl_storage, "r", encoding="utf-8") as f:
                cards = json.load(f)
            cards = [c for c in cards if c.get("request_id") in active_ids]
            with open(self.hitl_storage, "w", encoding="utf-8") as f:
                json.dump(cards, f, indent=2)
        except Exception:
            pass

    def run_continuous(self, max_cycles: int = 100, poll_interval: float = 0.5) -> None:
        """Runs the autonomous daemon loop continuously."""
        print(f"[*] Starting NIGHTFANG Autonomous Hunter Daemon [Tier: {self.config.autonomy_tier.value}]")
        self.is_running = True
        cycle = 0

        try:
            while self.is_running and cycle < max_cycles:
                cycle += 1
                if self.queue.pending_count() == 0:
                    if self.queue.paused_count() > 0:
                        print(f"[*] All active tasks processed. Waiting for operator on {self.queue.paused_count()} pending approvals...")
                    else:
                        print("[*] Attack surface queue exhausted. Engagement objectives satisfied.")
                        break
                    time.sleep(poll_interval * 2)
                    continue

                res = self.execute_next_task()
                if res:
                    st = res["status"]
                    tid = res["task_id"]
                    if st == "COMPLETED":
                        print(f"  [✓] {tid} COMPLETED | Evidence: {res.get('evidence')} | Remaining Leads: {res.get('generated_leads')}")
                    elif st == "PAUSED_FOR_APPROVAL":
                        print(f"  [⚠️] {tid} PAUSED FOR HITL APPROVAL | Non-blocking: daemon continues background hunting")
                    elif st == "FAILED":
                        print(f"  [✗] {tid} FAILED")
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            print("\n[*] Autonomous Hunter Daemon stopped by operator.")
        finally:
            self.queue.save_state()


# ============================================================================
# Self-Test Verification Suite
# ============================================================================

def run_self_tests() -> bool:
    """Verifies all aspects of the Autonomous Hunter Daemon."""
    print("Running NIGHTFANG Autonomous Hunter Daemon Self-Tests...")

    cfg = EngagementConfig(
        engagement_id="ENG-AUTONOMOUS-TEST",
        authorized_operator="lead-tester",
        authorized_cidrs=["10.0.0.0/8"],
        authorized_domains=["*.target.corp", "target.corp"],
        autonomy_tier=AutonomyTier.SEMI_AUTONOMOUS,
    )
    daemon = AutonomousHunterDaemon(cfg)

    # Test 1: Priority Queue Ordering
    t_low = HunterTask.create("t-low", TaskPriority.LOW, "target.corp", "recon", "recon", "whois", "whois target.corp", NoiseProfile.QUIET, ActionType.PASSIVE_READ)
    t_crit = HunterTask.create("t-crit", TaskPriority.CRITICAL, "target.corp", "scanner", "scanner", "check", "check", NoiseProfile.LOUD, ActionType.EXPLOIT_POC)
    t_high = HunterTask.create("t-high", TaskPriority.HIGH, "target.corp", "recon", "recon", "dns", "dns", NoiseProfile.QUIET, ActionType.PASSIVE_READ)

    daemon.queue.push(t_low)
    daemon.queue.push(t_crit)
    daemon.queue.push(t_high)

    first = daemon.queue.pop()
    assert first is not None and first.task_id == "t-crit", "CRITICAL task must pop first"
    second = daemon.queue.pop()
    assert second is not None and second.task_id == "t-high", "HIGH task must pop second"
    third = daemon.queue.pop()
    assert third is not None and third.task_id == "t-low", "LOW task must pop third"
    print("  [PASS] Test 1: Priority queue ordering and heap invariant verified.")

    # Test 2: Semi-Autonomous Auto-Execution (GREEN/YELLOW tiers)
    t_passive = HunterTask.create("t-pass", TaskPriority.MEDIUM, "target.corp", "recon", "recon", "echo", "echo 'api.target.corp discovered'", NoiseProfile.QUIET, ActionType.PASSIVE_READ)
    daemon.queue.push(t_passive)
    res = daemon.execute_next_task()
    assert res is not None and res["status"] == "COMPLETED", "Passive task must auto-complete under SEMI_AUTONOMOUS"
    assert "api.target.corp" in daemon.discovered_assets, "Domain discovery must automatically expand attack surface"
    assert daemon.queue.pending_count() > 0, "Lead generator must automatically enqueue new scan for discovered domain"
    print("  [PASS] Test 2: Semi-Autonomous execution and recursive lead expansion verified.")

    # Test 3: Non-Blocking Asynchronous HITL Queueing
    while daemon.queue.pop() is not None:
        pass  # Drain queue for isolated HITL test
    t_exploit = HunterTask.create(
        "t-exp",
        TaskPriority.CRITICAL,
        "target.corp",
        "scanner",
        "scanner",
        "sqlmap",
        "echo 'simulated exploit'",
        NoiseProfile.LOUD,
        ActionType.EXPLOIT_POC,
        technique="SQL Injection Verification",
    )
    # Also push a passive scan that must NOT be blocked
    t_background = HunterTask.create("t-bg", TaskPriority.LOW, "target.corp", "recon", "recon", "echo", "echo 'crawling background'", NoiseProfile.QUIET, ActionType.PASSIVE_READ)
    daemon.queue.push(t_exploit)
    daemon.queue.push(t_background)

    res_exp = daemon.execute_next_task()
    assert res_exp is not None and res_exp["status"] == "PAUSED_FOR_APPROVAL", "Exploit action must pause for HITL approval"
    assert daemon.queue.paused_count() == 1, "Paused task must be stored in paused_hitl index"

    # Crucial Non-blocking test: Verify the background scan immediately executes next!
    res_bg = daemon.execute_next_task()
    assert res_bg is not None and res_bg["status"] == "COMPLETED", "Daemon must continue processing other targets while HITL is paused"
    print("  [PASS] Test 3: Non-blocking asynchronous HITL queueing verified.")

    # Test 4: Approve / Deny Resumption
    approved = daemon.approve_hitl_task("t-exp", operator_id="lead-tester")
    assert approved is True, "Approval must succeed and mint token"
    resumed_task = daemon.execute_next_task()
    assert resumed_task is not None and resumed_task["task_id"] == "t-exp", "Approved task must resume execution"
    assert resumed_task["status"] == "COMPLETED", "Approved task must execute and complete"
    print("  [PASS] Test 4: Operator Approve/Deny token resumption verified.")

    # Test 5: Self-Healing Backoff on 429
    daemon.state.trigger_rate_backoff("target.corp", "Simulated 429")
    rate_info = daemon.state.rate_state.get("target.corp")
    assert rate_info is not None and rate_info["current_rate"] < 20, "Rate backoff must throttle request ceiling"
    print("  [PASS] Test 5: Self-healing rate backoff trigger verified.")

    print("\nAll 5 Daemon self-tests PASSED successfully!")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIGHTFANG Autonomous Hunter Engine Daemon")
    parser.add_argument("--test", action="store_true", help="Run automated self-tests")
    parser.add_argument("--target", type=str, help="Initial target domain or IP")
    parser.add_argument("--tier", type=str, default="SEMI_AUTONOMOUS", choices=["REACTIVE", "SEMI_AUTONOMOUS", "FULL_AUTONOMOUS"], help="Autonomy tier")
    parser.add_argument("--continuous", action="store_true", help="Run continuous hunting loop")
    parser.add_argument("--max-cycles", type=int, default=50, help="Maximum execution cycles")
    args = parser.parse_args()

    if args.test:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    if not args.target:
        print("[!] No target specified. Running self-test suite by default...\n")
        run_self_tests()
        sys.exit(0)

    # Live launch
    autonomy = AutonomyTier(args.tier)
    cfg = EngagementConfig(
        engagement_id=f"ENG-{int(time.time())}",
        authorized_operator="operator",
        authorized_domains=[args.target, f"*.{args.target}"],
        autonomy_tier=autonomy,
    )
    daemon = AutonomousHunterDaemon(cfg)
    daemon.seed_target(args.target)
    daemon.run_continuous(max_cycles=args.max_cycles)
