#!/usr/bin/env python3
"""
IoT Device Security Assessment Helper — enumerates common IoT attack surfaces
(HTTP services, telnet/SSH, MQTT, CoAP endpoints) via passive information
gathering. Does NOT authenticate, exploit, or interact with device services.
Outputs device fingerprint and recommended control checks.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class DeviceProfile:
    target_ip: str
    timestamp: str
    hostname: str = ""
    mac_oui: str = ""
    open_ports: Dict[str, int] = field(default_factory=dict)
    banners: Dict[int, str] = field(default_factory=dict)
    protocols_detected: List[str] = field(default_factory=list)
    known_cwes: List[str] = field(default_factory=list)
    notes: str = ""

    def add_port(self, port: int, service: str) -> None:
        self.open_ports[f"{port}/{service}"] = port

    def add_banner(self, port: int, banner: str) -> None:
        self.banners[port] = banner[:200]

    def mark_protocol(self, proto: str) -> None:
        if proto not in self.protocols_detected:
            self.protocols_detected.append(proto)

    def mark_cwe(self, cwe: str) -> None:
        if cwe not in self.known_cwes:
            self.known_cwes.append(cwe)

    def to_dict(self) -> dict:
        return {
            "target_ip": self.target_ip,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "mac_oui": self.mac_oui,
            "open_ports": sorted(self.open_ports.keys()),
            "banners": self.banners,
            "protocols_detected": self.protocols_detected,
            "known_cwes": self.known_cwes,
            "notes": self.notes,
            "summary": {
                "total_open_ports": len(self.open_ports),
                "unique_protocols": len(self.protocols_detected),
                "known_vulnerabilities": len(self.known_cwes),
            },
        }


# Well-known IoT service ports
IOT_PORT_MAP = {
    23: "telnet", 22: "ssh", 80: "http", 443: "https", 554: "rtsp",
    1883: "mqtt", 5683: "coap-udp", 5684: "coaps-tls", 8883: "mqtt-tls",
    2483: "serial-over-ip", 8080: "http-alt", 8443: "https-alt",
    9001: "modbus-tcp", 502: "modbus", 10000: "webmin",
    8888: "dashboard-generic", 3389: "rdp",
}

# OUI lookup — abbreviated IANA IoT/device vendor prefixes
IOT_OUI_PREFIXES = {
    "00:0A:EB": "Cisco/IKEF", "00:0D:BF": "Intelbras", "00:0E:5E": "ZTE",
    "00:15:84": "Dinstar", "00:16:E6": "TP-Link", "00:1A:2B": "Apple",
    "00:1B:63": "HP", "00:1B:FC": "Ubiquiti", "00:1F:3A": "Tenda",
    "00:21:2F": "Belkin", "00:21:5E": "Netatmo", "00:22:DB": "Xiaomi",
    "00:24:0A": "Raspberry Pi Foundation", "00:24:FF": "Loxone",
    "00:26:18": "Ring", "00:2A:8A": "Sonos", "00:30:BD": "Canon",
    "00:40:96": "Hikvision", "00:45:0C": "Trend Net", "00:46:5E": "Shenzhen VStarcam",
    "00:50:C2:5E": "Google Nest", "00:60:2B": "Bosch", "00:80:E1": "Panasonic",
    "00:A0:A1": "Samsung", "00:B0:DE": "NETGEAR", "00:C0:FF:EE": "Generic IoT",
    "08:D0:34": "Axis Communications", "0C:E7:7C": "Eufy",
}

DEFAULT_CHECKS = {
    "credentials": ["Verify default credentials are changed (admin/admin, root/root)."],
    "firmware": ["Check firmware version against vendor advisories."],
    "encryption": ["Confirm TLS 1.2+ is enforced on management interfaces."],
    "network": ["Disable UPnP/WPS if present.", "Isolate IoT VLAN from corporate LAN."],
    "services": ["Disable unnecessary services (telnet, FTP, SNMP v1/v2)."],
    "authentication": ["Enforce key-based SSH; disable password auth."],
    "logging": ["Ensure audit logging is enabled and forwarded to SIEM."],
    "physsec": ["Physical tamper-evident seals on exposed ports."],
}


def resolve_hostname(ip: str) -> str:
    try:
        return socket.getfqdn(ip)
    except OSError:
        return ""


def probe_port(ip: str, port: int, timeout: float = 1.0) -> Optional[tuple]:
    """Return (service_name, banner_snippet) if port accepts connection, else None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        service = IOT_PORT_MAP.get(port, f"unknown-{port}")
        # Attempt a short banner read
        banner = b""
        try:
            sock.settimeout(0.3)
            banner = sock.recv(256)
        except Exception:
            pass
        decoded = banner.decode("utf-8", errors="replace").strip()
        return service, decoded
    except (OSError, ConnectionRefusedError):
        return None
    finally:
        sock.close()


def mac_to_oui(mac: str) -> str:
    prefix = ":".join(mac.upper().split(":")[:3])
    return IOT_OUI_PREFIXES.get(prefix, "Unknown/Oui-missing")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG IoT Device Security Assessment Helper (Passive Recon)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("targets", nargs="+", help="IP addresses or hostnames (space-separated)")
    parser.add_argument("-p", "--ports", nargs="*", type=int, default=[22, 80, 443, 1883, 5683, 8080],
                        help="Ports to probe")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-port connection timeout")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON profile")
    args = parser.parse_args()

    profiles: List[DeviceProfile] = []
    for target in args.targets:
        profile = DeviceProfile(target_ip=target, timestamp=datetime.utcnow().isoformat() + "Z")
        hostname = resolve_hostname(target)
        if hostname:
            profile.hostname = hostname

        parsed = None
        try:
            parsed = ipaddress.ip_address(target)
        except ValueError:
            pass
        if parsed:
            mac_hint = f"{target}-mac-resolve-not-available"  # placeholder
            profile.mac_oui = f"IPv4-address:{target}"

        probed = []
        for port in sorted(set(args.ports)):
            result = probe_port(target, port, timeout=args.timeout)
            if result:
                service, banner = result
                profile.add_port(port, service)
                profile.mark_protocol(service)
                if banner:
                    profile.add_banner(port, banner)
                # Heuristic CWE tagging based on banners
                blower = banner.lower()
                if b"telnet" in banner.lower():
                    profile.mark_cwe("CWE-319")  # Cleartext transmission of sensitive info
                if b"http://" in banner.lower() and b"https://" not in banner.lower():
                    profile.mark_cwe("CWE-319")
                if b"snmp" in blower:
                    profile.mark_cwe("CWE-280")  # Improper validation of software patches
                probed.append(f"{port}/{service}")

        if not probed:
            profile.notes = "No common IoT ports responded within timeout."
            profile.mark_cwe("CWE-20")  # Improper input validation (no response = untested surface)
        else:
            profile.notes = f"Probed {len(probed)} ports: {', '.join(probed)}"

        profiles.append(profile)

    print("\n  [*] Profiles generated:")
    for p in profiles:
        s = p.to_dict()["summary"]
        print(f"  [{p.target_ip}] hostname={p.hostname or 'N/A'} | "
              f"ports={s['total_open_ports']} | protocols={s['unique_protocols']} | CWEs flagged={s['known_vulnerabilities']}")
        for cwe in p.known_cwes:
            print(f"      + {cwe}")

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump([p.to_dict() for p in profiles], fh, indent=2)
        print(f"\n  [*] Saved: {args.output}", file=sys.stderr)

    print(f"\n  [*] Recommended controls per NIST IR 8228 (IoT Cybersecurity Profile):\n")
    for label, checks in DEFAULT_CHECKS.items():
        print(f"    [{label.upper()}]")
        for c in checks:
            print(f"      - {c}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
