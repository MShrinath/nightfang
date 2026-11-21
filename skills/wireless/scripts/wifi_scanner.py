#!/usr/bin/env python3
"""
Wireless Network Scanner & WPA/WPA2 Handshake Collector
Identifies nearby wireless networks and captures 4-way handshakes for offline analysis.
For authorized security assessments only — complies with SOP-01 scope requirements.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple


@dataclass
class WirelessNetwork:
    bssid: str
    ssid: str
    channel: int
    frequency_mhz: int
    signal_dbm: int
    security: str  # OPEN, WEP, WPA-PSK, WPA2-PSK, WPA3, WPA-WPA2
    capabilities: List[str] = field(default_factory=list)
    first_seen: str = ""

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "frequency_mhz": self.frequency_mhz,
            "signal_dbm": self.signal_dbm,
            "security": self.security,
            "capabilities": self.capabilities,
            "first_seen": self.first_seen,
        }


@dataclass
class HandshakeCapture:
    bssid: str
    ssid: str
    pcap_path: str
    timestamp: str
    handshake_complete: bool = False
    eap_type: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "pcap_path": self.pcap_path,
            "timestamp": self.timestamp,
            "handshake_complete": self.handshake_complete,
            "eap_type": self.eap_type,
            "error": self.error,
        }


def check_privileges() -> bool:
    """Verify the process has sufficient privileges for wireless operations."""
    if os.name != "nt" and os.geteuid() != 0:
        print("[!] Root privileges required for wireless scanning on this platform.", file=sys.stderr)
        return False
    return True


def get_interface_status(interface: str) -> Dict:
    """Return interface mode, state, and current channel info."""
    try:
        output = subprocess.check_output(
            ["iw", "dev", interface, "info"],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="replace")
        lines = output.strip().split("\n")
        mode = "unknown"
        for line in lines:
            if line.startswith("type ") or "monitor" in line.lower():
                mode = "monitor" if "monitor" in line.lower() else "managed"
        return {"mode": mode, "raw": output}
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {"mode": "unavailable", "raw": ""}


def list_interfaces() -> List[str]:
    """Enumerate available wireless network interfaces."""
    try:
        output = subprocess.check_output(
            ["iw", "dev"],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="replace")
        interfaces: List[str] = []
        for line in output.split("\n"):
            m = re.search(r"^Interface\s+(\S+)", line)
            if m:
                interfaces.append(m.group(1))
        return interfaces
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def parse_airbase_ap(line: str) -> Optional[WirelessNetwork]:
    """Parse a single AP entry from airbase-ng / airodump-ng CSV-style output."""
    pattern = (
        r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\s+"
        r"(\d+)\s+(\d+)\s+([+-]\d+)\s+(.+?)\s+(WEP|WPA.*|WP[A-Z].*|NONE|-)\s*"
        r"(.*)"
    )
    m = re.match(pattern, line.strip())
    if not m:
        return None
    bssid, channel_str, freq_str, sig_str, ssid_raw, security_str, _caps = m.groups()
    return WirelessNetwork(
        bssid=bssid.upper(),
        ssid=ssid_raw.strip() if ssid_raw.strip() else f"(hidden-{bssid})",
        channel=int(channel_str),
        frequency_mhz=int(freq_str),
        signal_dbm=int(sig_str),
        security=security_str.upper().replace("NONE", "OPEN").replace("WPA ", "WPA-PSK"),
        capabilities=[],
        first_seen=datetime.utcnow().isoformat() + "Z",
    )


def scan_aps(interface: str, duration_sec: int = 30) -> List[WirelessNetwork]:
    """
    Capture nearby wireless APs using airodump-ng in monitor mode.
    Returns sorted list of WirelessNetwork entries by signal strength.
    """
    aps: List[WirelessNetwork] = []
    tmp_dir = "/tmp/nightfang_wifi_scan" if os.name != "nt" else os.environ.get("TEMP", "C:/Windows/Temp") + "/nightfang_wifi_scan"
    os.makedirs(tmp_dir, exist_ok=True)

    csv_path = os.path.join(tmp_dir, "capture.csv")
    cap_path = os.path.join(tmp_dir, "capture.cap")

    cmd = [
        "airodump-ng",
        "--output-format", "csv",
        "-w", os.path.join(tmp_dir, "net"),
        "--interval", "2",
        interface,
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        proc.wait(timeout=max(duration_sec + 10, 60))
    except subprocess.TimeoutExpired:
        proc.kill()

    if os.path.exists(csv_path):
        with open(csv_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                ap = parse_airbase_ap(line)
                if ap:
                    aps.append(ap)

    # Deduplicate by BSSID
    seen: Dict[str, WirelessNetwork] = {}
    for ap in aps:
        if ap.bssid not in seen or ap.signal_dbm > seen[ap.bssid].signal_dbm:
            seen[ap.bssid] = ap
    return sorted(seen.values(), key=lambda x: x.signal_dbm, reverse=True)


def capture_handshake(
    interface: str,
    target_bssid: str,
    target_channel: int,
    timeout_sec: int = 60,
    output_dir: str = "/tmp",
) -> Optional[HandshakeCapture]:
    """
    Attempt to capture a WPA 4-way handshake from a target BSSID.
    Returns HandshakeCapture with result status; None on failure.
    """
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(output_dir, f"hs_{target_bssid.replace(':', '_')}_{ts}.pcap")

    cmd = [
        "airodump-ng",
        "-c", str(target_channel),
        "--bssid", target_bssid.upper(),
        "-w", pcap_path.rstrip(".cap"),
        interface,
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        proc.wait(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        proc.kill()

    capture = HandshakeCapture(
        bssid=target_bssid.upper(),
        ssid="",
        pcap_path=pcap_path,
        timestamp=datetime.utcnow().isoformat() + "Z",
    )

    if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0:
        try:
            hex_cap = binascii.hexlify(open(pcap_path, "rb").read()).decode()
            # WPA handshake heuristic: look for IEEE 802.11 RSN information element
            if "30140100" in hex_cap or "ac2f" in hex_cap:
                capture.handshake_complete = True
                capture.eap_type = "WPA-PSK"
            elif "3118" in hex_cap:
                capture.handshake_complete = True
                capture.eap_type = "WPA-EAP"
            else:
                capture.error = "Handshake incomplete — retry nearby or wait for client association"
        except OSError:
            capture.error = "Could not read captured PCAP file"
    else:
        capture.error = "No packets captured — verify target is in range and active"

    return capture


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Wireless Network Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--interface", help="Wireless interface (default: auto-detect)")
    parser.add_argument("--duration", type=int, default=30, help="Scan duration in seconds")
    parser.add_argument("--capture-bssid", metavar="AA:BB:CC:DD:EE:FF", help="Capture handshake for specific BSSID")
    parser.add_argument("--channel", type=int, help="Target channel for handshake capture")
    parser.add_argument("--output-dir", default="/tmp", help="Directory for saved PCAP files")
    parser.add_argument("-o", "--json-output", metavar="PATH", help="Save scan results to JSON")
    args = parser.parse_args()

    if not check_privileges():
        return 2

    iface = args.interface
    if not iface:
        interfaces = list_interfaces()
        if not interfaces:
            print("[!] No wireless interfaces detected. Is WiFi enabled?", file=sys.stderr)
            return 2
        print(f"  [*] Detected interfaces: {', '.join(interfaces)}")
        iface = interfaces[0]
        print(f"  [*] Using interface: {iface}")

    print(f"\n  [*] Scanning for APs on {iface} ({args.duration}s) ...\n")
    aps = scan_aps(iface, duration_sec=args.duration)

    if not aps:
        print("  [!] No wireless networks found.")
        return 1

    print(f"  [+] Found {len(aps)} wireless networks:\n")
    print(f"  {'BSSID':<18s} {'SSID':<28s} {'CH':>3s} {'Sig':>6s}  Security")
    print(f"  {'-'*18} {'-'*28} {'-'*3} {'-'*6}  {'-'*12}")
    for ap in aps[:30]:
        ssid_display = ap.ssid[:27] + "…" if len(ap.ssid) > 27 else ap.ssid
        print(f"  {ap.bssid:<18s} {ssid_display:<28s} {ap.channel:>3d}  {ap.signal_dbm:>5d}dBm  {ap.security}")

    if args.capture_bssid:
        ch = args.channel
        if not ch:
            tgt = next((a for a in aps if a.bssid.upper() == args.capture_bssid.upper()), None)
            if tgt:
                ch = tgt.channel
            else:
                print(f"[!] Target BSSID {args.capture_bssid} not found in scan results.", file=sys.stderr)
                return 2
        print(f"\n  [*] Capturing handshake for {args.capture_bssid} on channel {ch} ...")
        hs = capture_handshake(iface, args.capture_bssid, ch, output_dir=args.output_dir)
        if hs:
            print(f"  [{'OK' if hs.handshake_complete else 'FAIL'}] Handshake: {hs.pcap_path}")
            if hs.error:
                print(f"         Note: {hs.error}")

    if args.json_output:
        out_dir = os.path.dirname(args.json_output) or "."
        os.makedirs(out_dir, exist_ok=True)
        data = {"target_interface": iface, "networks": [a.to_dict() for a in aps],
                "scan_time": datetime.utcnow().isoformat() + "Z"}
        with open(args.json_output, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        print(f"\n  [*] Report saved: {args.json_output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
