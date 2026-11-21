#!/usr/bin/env python3
"""
Phishing Email Header Analyzer — performs passive forensic analysis on eml/msg/raw
email files to detect phishing indicators without sending or interacting with any
mail server. Outputs a structured risk profile per message.
Read-only: reads local files only; no network egress.
"""
from __future__ import annotations

import argparse
import base64
import email
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class EmailIndicators:
    from_domain: str = ""
    reply_to_domain: str = ""
    body_domains: List[str] = field(default_factory=list)
    url_count: int = 0
    suspicious_tlds: List[str] = field(default_factory=list)
    header_anomalies: List[str] = field(default_factory=list)
    spoofing_score: float = 0.0
    phishing_indicators: List[str] = field(default_factory=list)
    raw_subject: str = ""
    raw_from: str = ""
    received_chain: List[str] = field(default_factory=list)

    def risk_level(self) -> str:
        score = (len(self.suspicious_tlds) * 2 + len(self.header_anomalies) +
                 self.spoofing_score + len([d for d in self.body_domains if not re.match(r'^[a-zA-Z0-9.-]+\.(com|net|org|edu|gov)$', d)]))
        if score >= 6:
            return "critical"
        if score >= 4:
            return "high"
        if score >= 2:
            return "medium"
        return "low"


def extract_domains_from_text(text: str) -> List[str]:
    """Return unique domains found in URLs or bare text within the provided text."""
    seen: set = set()
    results: List[str] = []
    # URLs
    for match in re.findall(r'https?://([^\s/\"<>]+)', text):
        parts = match.split("/")
        if parts:
            domain = parts[0].lower().rstrip(".,;:")
            if domain not in seen and "." in domain and len(domain) > 3:
                seen.add(domain)
                results.append(domain)
    # Bare domains in body
    for match in re.findall(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text):
        d = match.lower()
        if d not in seen:
            seen.add(d)
            results.append(d)
    return results


SUSPICIOUS_TLD_SET = {
    ".xyz", ".top", ".click", ".loan", ".work", ".racing", ".gq", ".ml", ".cf",
    ".tk", ".pw", ".cc", ".bz", ".su", ".onion", ".bit",
}


def analyse_email(path: str) -> Optional[EmailIndicators]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            msg_raw = fh.read()
    except OSError as exc:
        print(f"[!] Could not read {path}: {exc}", file=sys.stderr)
        return None

    try:
        msg = email.message_from_string(msg_raw)
    except Exception:
        try:
            msg = email.message_from_bytes(msg_raw.encode("utf-8", errors="replace"))
        except Exception:
            return None

    ind = EmailIndicators(
        raw_subject=msg.get("Subject", ""),
        raw_from=msg.get("From", ""),
    )

    # Domains from headers
    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", from_addr)
    m_from = re.search(r"@([\w.-]+\.\w+)", from_addr)
    ind.from_domain = m_from.group(1) if m_from else ""
    m_reply = re.search(r"@([\w.-]+\.\w+)", reply_to)
    ind.reply_to_domain = m_reply.group(1) if m_reply else ""

    # Body domains
    body = msg.get_payload(decode=True) or b""
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except Exception:
            body = body.decode("latin-1", errors="replace")
    body = base64.b64decode(body) if isinstance(body, str) and re.match(r"^[A-Za-z0-9+/=]+$", body) else body
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except Exception:
            body = body.decode("latin-1", errors="replace")
    ind.body_domains = extract_domains_from_text(str(body))

    # Received chain
    for h in msg.get_all("Received", []):
        ind.received_chain.append(h[:120])

    # Suspicious TLD check
    all_domains = set(ind.body_domains + [ind.from_domain, ind.reply_to_domain])
    for d in all_domains:
        if d and any(d.endswith(tld) for tld in SUSPICIOUS_TLD_SET):
            ind.suspicious_tlds.append(d)

    # Header anomalies
    if ind.from_domain and ind.reply_to_domain and ind.from_domain != ind.reply_to_domain:
        ind.header_anomalies.append("From/Reply-To domain mismatch")
    for h in ["X-Mailer", "X-Originating-IP", "X-Google-Smtp-Host"]:
        if msg.get(h):
            val = msg.get(h, "")
            if any(kw in val.lower() for kw in ("php", "sendmail", "unknown")):
                ind.header_anomalies.append(f"Suspicious {h}: {val[:80]}")
    # SPF/DKIM/DMARC hints
    auth_results = msg.get("Authentication-Results", "") or ""
    if "fail" in auth_results.lower():
        ind.header_anomalies.append(f"Auth failure in header: {auth_results[:120]}")

    # Spoofing heuristic score (0–5)
    spoof = 0.0
    if ind.from_domain and ind.from_domain not in ind.body_domains:
        spoof += 1.0
    if len(ind.body_domains) > 3:
        spoof += 1.0
    if ind.raw_subject and any(kw in ind.raw_subject.lower() for kw in
                                ("urgent", "verify", "confirm", "update your", "action required",
                                 "security alert", "locked", "suspended", "immediately", "free")):
        spoof += 1.0
    if any(kw in ind.raw_subject.lower() for kw in ("click", "link", "login", "signin", "secure", "portal")):
        spoof += 0.5
    ind.spoofing_score = min(spoof, 5.0)

    # Phishing indicator phrases
    indicator_phrases = [
        ("subject line contains urgency/corporate action keywords", "URGENT_ACTION"),
        ("body contains embedded short-url or URL shortener service", "SHORTENER"),
        ("reply-to does not match from-domain", "REPLY_TO_MISMATCH"),
        ("sender domain not listed in known body domains (possible impersonation)", "DOMAIN_MISMATCH"),
    ]
    for desc, tag in indicator_phrases:
        if tag in ind.header_anomalies or ind.spoofing_score >= 2.0:
            ind.phishing_indicators.append(desc)
    if ind.url_count > 0 and any(re.search(r'(bit\.ly|tinyurl|goo\.gl|t\.co)', s) for s in ind.body_domains):
        ind.phishing_indicators.append("URL shortener detected in message body")

    return ind


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Phishing Email Header Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("emails", nargs="+", help="Paths to .eml/.msg/raw email files (space-separated)")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    profiles: List[dict] = []
    severity_counts: Counter = Counter()
    for path in args.emails:
        ind = analyse_email(path)
        if ind is None:
            continue
        severity_counts[ind.risk_level()] += 1
        profile = {
            "file": path,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "risk_level": ind.risk_level(),
            "raw_subject": ind.raw_subject[:120],
            "from_domain": ind.from_domain,
            "reply_to_domain": ind.reply_to_domain,
            "suspicious_tlds": ind.suspicious_tlds,
            "header_anomalies": ind.header_anomalies,
            "spoofing_score": round(ind.spoofing_score, 2),
            "phishing_indicators": ind.phishing_indicators,
            "received_chain_hops": len(ind.received_chain),
        }
        profiles.append(profile)
        print(f"\n  [{'{:>8}'.format(ind.risk_level().upper())}] {os.path.basename(path)}")
        print(f"         From     : {profile['from_domain']}")
        print(f"         Subject  : {profile['raw_subject'][:80]}")
        print(f"         Spoofing score: {profile['spoofing_score']}/5 | Anomalies: {len(profile['header_anomalies'])}")
        for anom in profile["header_anomalies"][:5]:
            print(f"           - {anom}")

    print(f"\n  [*] Analysed {len(profiles)} email(s)")
    print(f"  [*] Severity breakdown: {dict(severity_counts)}")

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"generated_at": datetime.utcnow().isoformat() + "Z",
                       "total_analysed": len(profiles), "profiles": profiles},
                      fh, indent=2, default=str)
        print(f"  [*] Report saved: {args.output}", file=sys.stderr)

    critical = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
    return 1 if critical else 0


if __name__ == "__main__":
    sys.exit(main())
