#!/usr/bin/env python3
"""
Network Port & Service Enumeration Helper
Identifies open ports, banners, and common service fingerprints.
Safe for authorized engagements only — uses passive SYN scans with rate limiting.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class PortProbe:
    port: int
    protocol: str
    state: str  # open, closed, filtered
    service: str = ""
    banner: str = ""
    raw_response: bytes = b""
    timing_ms: float = 0.0


@dataclass
class ScanResult:
    target: str
    timestamp: str
    total_scanned: int = 0
    open_ports: List[PortProbe] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "total_scanned": self.total_scanned,
            "open_count": len(self.open_ports),
            "ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "banner": p.banner[:200],
                    "timing_ms": round(p.timing_ms, 2),
                }
                for p in self.open_ports
            ],
            "errors": self.errors[:5],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# Well-known service ports mapped by IANA convention
WELL_KNOWN_SERVICES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    27017: "mongodb", 27018: "mongodb-shard", 27019: "mongodb-config",
}

# Banner signatures for common services (case-insensitive regex partial match)
BANNER_SIGNATURES: List[Tuple[re.Pattern, str]] = [
    (re.compile(rb"^SSH-\w", re.I), "ssh"),
    (re.compile(rb"^220\s", re.I), "smtp/POP/IMAP"),
    (re.compile(rb"^FTPS?", re.I), "ftp"),
    (re.compile(rb"apache", re.I), "apache-httpd"),
    (re.compile(rb"nginx", re.I), "nginx"),
    (re.compile(rb"\bMySQL", re.I), "mysql"),
    (re.compile(rb"\bPostgreSQL", re.I), "postgresql"),
    (re.compile(rb"\bRedis", re.I), "redis"),
    (re.compile(rb"\bMongoDB", re.I), "mongodb"),
    (re.compile(rb"\bOracle", re.I), "oracle-db"),
    (re.compile(rb"\bIIS", re.I), "microsoft-iis"),
    (re.compile(rb"\\server", re.I), "smb"),
    (re.compile(rb"Telnet", re.I), "telnet"),
    (re.compile(rb"RDP", re.I), "rdp"),
    (re.compile(rb"VNC", re.I), "vnc"),
]


def tcp_connect(
    host: str,
    port: int,
    timeout: float = 2.0,
    verbose: bool = False,
) -> PortProbe:
    """
    Perform a TCP connect scan against a single port.
    Returns a PortProbe with state, optional banner, and timing info.
    """
    probe = PortProbe(port=port, protocol="tcp", state="closed")
    start = time.monotonic()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn_start = time.monotonic()
        sock.connect((host, port))
        probe.timing_ms = (conn_start - start) * 1000

        if not verbose:
            probe.state = "open"
            probe.service = WELL_KNOWN_SERVICES.get(port, "unknown")
            sock.close()
            return probe

        # Attempt banner grab (up to 512 bytes)
        sock.settimeout(3.0)
        try:
            raw = sock.recv(512)
            probe.raw_response = raw
            probe.banner = raw.decode("utf-8", errors="replace").strip()
        except (socket.timeout, ConnectionResetError, OSError):
            probe.banner = ""

        probe.state = "open"
        probe.service = _classify_service(probe.banner, port)
        sock.close()
        probe.timing_ms += (time.monotonic() - conn_start) * 1000

    except socket.timeout:
        probe.state = "filtered"
        probe.timing_ms = round((time.monotonic() - start) * 1000, 2)
    except ConnectionRefusedError:
        probe.state = "closed"
        probe.timing_ms = round((time.monotonic() - start) * 1000, 2)
    except OSError as exc:
        probe.state = "error"
        probe.timing_ms = round((time.monotonic() - start) * 1000, 2)

    return probe


def _classify_service(banner: str, port: int) -> str:
    """Match banner text against known signature patterns; fall back to IANA mapping."""
    lower_banner = banner.lower()
    for pattern, svc_name in BANNER_SIGNATURES:
        if pattern.search(banner.encode("utf-8", errors="replace")):
            return svc_name
    if port in WELL_KNOWN_SERVICES:
        return WELL_KNOWN_SERVICES[port]
    return "unknown"


def enumerate_ports(
    target: str,
    port_range: Tuple[int, int] = (1, 1024),
    timeout: float = 1.5,
    rate_limit: int = 50,
    verbose: bool = True,
    output_path: Optional[str] = None,
) -> ScanResult:
    """
    Enumerate TCP ports across [start_port, end_port] on the given target.
    Rate-limited to `rate_limit` probes per second to respect SOP-02 stealth requirements.
    """
    result = ScanResult(target=target, timestamp=datetime.utcnow().isoformat() + "Z")
    start_port, end_port = max(1, port_range[0]), min(65535, port_range[1])
    interval = 1.0 / max(rate_limit, 1)

    for port in range(start_port, end_port + 1):
        probe = tcp_connect(target, port, timeout=timeout, verbose=verbose)
        result.total_scanned += 1
        if probe.state == "open":
            result.open_ports.append(probe)
            print(f"  [+] {target}:{port}/{probe.protocol} OPEN  service={probe.service or 'unknown'}")
        elif verbose:
            print(f"  [.] {target}:{port}/{probe.protocol} {probe.state.upper()}")

        time.sleep(interval)

    if output_path:
        _write_report(result, output_path)

    return result


def _write_report(result: ScanResult, path: str) -> None:
    """Persist scan result as JSON alongside the target's finding record."""
    out_dir = os.path.dirname(path) or "."
    os.makedirs(out_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(result.to_json())
    print(f"\n  [*] Report written to: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Network Port & Service Enumerator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument(
        "-p", "--ports",
        metavar="START-END",
        default="1-1024",
        help="Port range (e.g., 1-1024, 80, 8000-8100)",
    )
    parser.add_argument("-t", "--timeout", type=float, default=1.5, help="Per-port timeout (seconds)")
    parser.add_argument("-r", "--rate-limit", type=int, default=50, help="Max probes per second")
    parser.add_argument("-o", "--output", metavar="PATH", help="JSON report output path")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress per-port progress output")
    args = parser.parse_args()

    # Parse port range
    try:
        parts = args.ports.split("-")
        if len(parts) == 1:
            port_range = (int(parts[0]), int(parts[0]))
        else:
            port_range = (int(parts[0]), int(parts[1]))
    except (ValueError, IndexError) as exc:
        print(f"[!] Invalid port range '{args.ports}': {exc}", file=sys.stderr)
        return 2

    print(f"\n  [*] Scanning {args.target} ports {port_range[0]}-{port_range[1]} ...")
    print(f"  [*] Timeout={args.timeout}s  RateLimit={args.rate_limit} pro/s\n")

    result = enumerate_ports(
        target=args.target,
        port_range=port_range,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        verbose=not args.quiet,
        output_path=args.output,
    )

    print(f"\n{'='*60}")
    print(f"  Target       : {result.target}")
    print(f"  Ports scanned: {result.total_scanned}")
    print(f"  Open ports   : {len(result.open_ports)}")
    if result.open_ports:
        print(f"  Services     : {[p.service or 'unknown' for p in result.open_ports]}")
    if result.errors:
        print(f"  Errors       : {result.errors[:3]}")
    print(f"{'='*60}\n")
    return 0 if result.open_ports else 1


if __name__ == "__main__":
    sys.exit(main())
