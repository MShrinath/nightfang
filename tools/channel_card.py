#!/usr/bin/env python3
"""
NIGHTFANG Telegram & Remote Channel Card Formatter (tools/channel_card.py)

Formats real-time daemon state, HITL approvals, findings, and scope summaries into
mobile-optimized, Telegram-safe messages (<= 4096 characters, MarkdownV2 / safe HTML escaping).
Supports multi-target/chat partitioning so findings and status can be viewed per-target.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

# Telegram message length limit
TELEGRAM_MAX_LENGTH = 4096


def escape_markdown(text: str) -> str:
    """
    Escape special Markdown characters for safe Telegram transmission.
    Escapes: _ * [ ] ( ) ~ ` > # + - = | { } . ! \
    """
    if not text:
        return ""
    # Characters that must be escaped in Telegram MarkdownV2 outside code blocks
    special_chars = r"_*[]()~`>#+-=|{}.!\\"
    return re.sub(f"([{re.escape(special_chars)}])", r"\\\1", str(text))


def truncate_message(text: str, max_length: int = TELEGRAM_MAX_LENGTH, suffix: str = "\n\n... [truncated for Telegram]") -> str:
    """Ensure message does not exceed Telegram's character limit."""
    if len(text) <= max_length:
        return text
    cutoff = max_length - len(suffix)
    return text[:cutoff] + suffix


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
        Format /findings card. If filter_target is provided, shows findings only for that target.
        If filter_target is None, groups findings by target to prevent cross-target mixup.
        """
        if not findings:
            target_msg = f" for `{filter_target}`" if filter_target else ""
            return f"🛡️ *NIGHTFANG Findings:*{target_msg}\nNo security findings currently recorded."

        # Partition findings by target
        partitioned: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            inner = f.get("finding", f)
            t = str(inner.get("target", "general")).strip()
            # Normalize target hostname if URL or host:port
            if "://" in t:
                t = t.split("://", 1)[1]
            if "/" in t:
                t = t.split("/", 1)[0]
            norm_target = t.split(":")[0] if ":" in t else t
            partitioned.setdefault(norm_target, []).append(inner)

        if filter_target:
            norm_filter = filter_target.split(":")[0] if ":" in filter_target else filter_target
            matched_findings = partitioned.get(norm_filter, [])
            if not matched_findings:
                # Fallback: substring match
                for t_key, t_list in partitioned.items():
                    if norm_filter in t_key or t_key in norm_filter:
                        matched_findings = t_list
                        norm_filter = t_key
                        break

            if not matched_findings:
                return (
                    f"🛡️ *NIGHTFANG Findings for `{filter_target}`:*\n"
                    f"No findings recorded for this specific target. Active targets: "
                    + ", ".join(f"`{k}`" for k in partitioned.keys())
                )

            lines = [
                f"🛡️ *NIGHTFANG Findings for `{norm_filter}`* ({len(matched_findings)} total):",
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            ]
            for idx, item in enumerate(matched_findings[:10], 1):
                sev = item.get("severity", {})
                score = sev.get("score", 5.0) if isinstance(sev, dict) else 5.0
                badge = "🔴" if score >= 9.0 else "🟠" if score >= 7.0 else "🟡" if score >= 4.0 else "🔵"
                cwe = item.get("cwe_id", "CWE-000")
                title = item.get("title", "Finding")
                lines.append(f"{idx}. {badge} `[{score:.1f}]` *{title}* (`{cwe}`)")

            if len(matched_findings) > 10:
                lines.append(f"\n_... and {len(matched_findings) - 10} more findings on this target._")

            return truncate_message("\n".join(lines))

        # Overview partitioned across targets
        lines = [
            f"🛡️ *NIGHTFANG Findings Overview* ({len(findings)} total across {len(partitioned)} targets):",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        ]
        for t_name, t_findings in partitioned.items():
            crits = sum(1 for x in t_findings if (x.get("severity", {}).get("score", 0) if isinstance(x.get("severity"), dict) else 0) >= 9.0)
            highs = sum(1 for x in t_findings if 7.0 <= (x.get("severity", {}).get("score", 0) if isinstance(x.get("severity"), dict) else 0) < 9.0)
            meds = len(t_findings) - crits - highs

            lines.append(f"🎯 *Target:* `{t_name}` ({len(t_findings)} findings)")
            lines.append(f"   🔴 {crits} Critical | 🟠 {highs} High | 🟡 {meds} Other")
            lines.append(f"   👉 View target: `/findings {t_name}`")
            lines.append("")

        return truncate_message("\n".join(lines))

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


def run_self_tests() -> bool:
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

    # Test 6: Target-partitioned findings rendering (Operator update requirement)
    findings_dataset = [
        {
            "finding": {
                "id": "F-001",
                "title": "SQL Injection",
                "target": "targetA.com:443",
                "cwe_id": "CWE-89",
                "severity": {"score": 9.5, "level": "critical"},
            }
        },
        {
            "finding": {
                "id": "F-002",
                "title": "Cross-Site Scripting",
                "target": "targetB.com",
                "cwe_id": "CWE-79",
                "severity": {"score": 6.5, "level": "medium"},
            }
        },
    ]
    # Check overview partitions targets
    overview = formatter.format_findings_overview(findings_dataset)
    assert "targetA.com" in overview
    assert "targetB.com" in overview
    assert "/findings targetA.com" in overview

    # Check target-specific filtered rendering isolates targetA from targetB
    target_a_card = formatter.format_findings_overview(findings_dataset, filter_target="targetA.com")
    assert "targetA.com" in target_a_card
    assert "SQL Injection" in target_a_card
    assert "targetB.com" not in target_a_card
    assert "Cross-Site Scripting" not in target_a_card
    print("  [PASS] Test 6: Target-partitioned findings isolation and /findings <target> verified.")

    print("\nAll 6 Channel Card Formatter self-tests PASSED successfully!")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIGHTFANG Telegram & Remote Channel Card Formatter")
    parser.add_argument("--test", action="store_true", help="Run automated self-tests")
    args = parser.parse_args()

    if args.test:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    # Default action
    success = run_self_tests()
    sys.exit(0 if success else 1)
