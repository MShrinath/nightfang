#!/usr/bin/env python3
"""
OSINT Domain & Infrastructure Intelligence Collector
Gathers publicly available domain intelligence without active scanning.
Rate-limited per SOP-02 stealth requirements.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


@dataclass
class OSINTResult:
    target: str
    timestamp: str
    domains: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    whois_data: Dict = field(default_factory=dict)
    http_headers: Dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "domain_count": len(self.domains),
            "ip_count": len(self.ip_addresses),
            "domains": list(dict.fromkeys(self.domains)),
            "ips": list(dict.fromkeys(self.ip_addresses)),
            "whois_summary": {k: v for k, v in self.whois_data.items() if k != "raw"},
            "http_headers": self.http_headers,
            "errors": self.errors[:10],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


def _fetch_url(url: str, timeout: int = 10) -> Optional[bytes]:
    """Safely fetch a URL with timeout and error handling."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
        return None


def resolve_domain(domain: str) -> List[str]:
    """Resolve all IPv4 addresses for a domain via system DNS."""
    ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips: List[str] = sorted({str(info[4][0]) for info in addr_info})
    except (socket.gaierror, OSError):
        pass
    return ips


def query_crtsh(domain: str, limit: int = 500) -> List[str]:
    """Query certificate transparency logs for subdomains via crt.sh API."""
    subs: Set[str] = set()
    url = f"https://crt.sh/?q=%.{'.'.join(domain.split('.')[-2:])}&output=json"
    raw = _fetch_url(url, timeout=15)
    if not raw:
        return list(subs)
    try:
        results = json.loads(raw.decode("utf-8", errors="replace"))
        for entry in results[:limit]:
            name = entry.get("common_name", "") or entry.get("name_value", "")
            for part in str(name).split("\n"):
                part = part.strip().lower()
                if part and "." in part and part.endswith(domain.lower()):
                    subs.add(part)
    except (json.JSONDecodeError, KeyError):
        pass
    return sorted(subs)


def extract_http_headers(domain: str) -> Dict[str, str]:
    """Fetch HTTP response headers from the target domain (no body content)."""
    headers: Dict[str, str] = {}
    for proto in ("https", "http"):
        try:
            url = f"{proto}://{domain}/"
            req = urllib.request.Request(url, headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml",
            })
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                for key in ("Server", "X-Powered-By", "X-Frame-Options",
                            "Content-Security-Policy", "Strict-Transport-Security",
                            "X-Content-Type-Options", "Via", "CF-IPCountry"):
                    val = resp.headers.get(key)
                    if val:
                        headers[f"{proto}_{key}"] = val.strip()
                break
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            continue
    return headers


def gather_osint(target: str, verbose: bool = True) -> OSINTResult:
    """Collect OSINT data for a single target domain."""
    result = OSINTResult(target=target, timestamp=datetime.utcnow().isoformat() + "Z")

    if verbose:
        print(f"\n  [*] Resolving {target} ...")
    ips = resolve_domain(target)
    result.ip_addresses = ips
    if ips and verbose:
        print(f"  [+] IPs: {', '.join(ips)}")

    if verbose:
        print(f"  [*] Querying CRT.sh for subdomains ...")
    subs = query_crtsh(target)
    result.domains = [target] + subs
    if subs and verbose:
        print(f"  [+] Found {len(subs)} subdomains")

    if verbose:
        print(f"  [*] Fetching HTTP headers ...")
    hdrs = extract_http_headers(target)
    result.http_headers = hdrs
    tech_indicators = []
    for key, val in hdrs.items():
        lower_val = val.lower()
        if "nginx" in lower_val:
            tech_indicators.append("nginx")
        elif "apache" in lower_val:
            tech_indicators.append("apache")
        elif "cloudflare" in lower_val or "cf-ray" in key:
            tech_indicators.append("cloudflare")
        elif "iis" in lower_val:
            tech_indicators.append("iis")
        elif "express" in lower_val:
            tech_indicators.append("express")
        elif "aspnet" in lower_val or "x-aspnet-version" in key:
            tech_indicators.append("aspnet")
    if tech_indicators and verbose:
        print(f"  [+] Tech indicators: {', '.join(dict.fromkeys(tech_indicators))}")

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG OSINT Domain Intelligence Collector",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report to file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args()

    result = gather_osint(args.target, verbose=not args.quiet)

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(result.to_json())
        print(f"\n  [*] Report saved: {args.output}")

    print(f"\n{'='*60}")
    print(f"  Target     : {result.target}")
    print(f"  Domains    : {len(result.domains)} total ({len(result.domains)-1} subdomains)")
    print(f"  IPs        : {len(result.ip_addresses)} resolved")
    print(f"  Timestamp  : {result.timestamp}")
    if result.errors:
        print(f"  Errors     : {result.errors[:3]}")
    print(f"{'='*60}\n")
    return 0


if __name__ == "__main__":
    import socket
    sys.exit(main())
