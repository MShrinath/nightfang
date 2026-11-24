#!/usr/bin/env python3
"""
NIGHTFANG Telegram & Remote Channel Card Formatter (tools/channel_card.py)

Formats real-time daemon state, HITL approvals, findings, and scope summaries into
mobile-optimized, Telegram-safe messages (<= 4096 characters, MarkdownV2 / safe HTML escaping).
Supports 2-tier hierarchical scope partitioning (Root Domain -> Subdomains -> Findings)
so subdomains do not become separate top-level targets while maintaining per-host clarity.
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIGHTFANG Telegram & Remote Channel Card Formatter")
    parser.add_argument("--test", action="store_true", help="Run automated self-tests")
    parser.add_argument("--status", "--status-card", dest="status_card", action="store_true", help="Print formatted Telegram status card")
    parser.add_argument("--findings", action="store_true", help="Print formatted Telegram findings card")
    parser.add_argument("--target", type=str, help="Filter findings by root scope or subdomain")
    parser.add_argument("--scope", action="store_true", help="Print formatted Telegram scope card")
    args, unknown = parser.parse_known_args()

    if args.test:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    formatter = ChannelCardFormatter()

    if args.findings:
        try:
            from tools.finding_sync import FindingSyncManager
            mgr = FindingSyncManager()
            findings = mgr.get_all_findings()
        except Exception:
            findings = []
        card = formatter.format_findings_overview(findings, filter_target=args.target)
        print(card)
        sys.exit(0)

    if args.scope:
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

    # Default action: render status card
    try:
        from tools.hud import get_aggregated_state
        state = get_aggregated_state(target_scope=[args.target] if args.target else None)
    except Exception:
        state = {
            "engagement_id": "ENG-CLI",
            "target_scope": [args.target or "target.corp"],
            "autonomy_tier": "SEMI_AUTONOMOUS",
            "status": "IDLE",
            "progress": 0.0,
            "queue_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "active_tasks": [],
            "rate_backoffs": {},
            "pending_hitl": [],
        }
    card = formatter.format_status_card(state)
    print(card)
    sys.exit(0)
