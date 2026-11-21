#!/usr/bin/env python3
"""
Bluetooth/BLE Security Assessment Helper — parses hcitool/bluetoothctl scan
output and BLE advertisement dumps to identify vulnerable device profiles,
missing encryption flags, and pairing-mode indicators. Does NOT pair, bond,
or interact with target devices. Read-only parsing of captured data only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class BleDevice:
    address: str
    rssi: int = -128
    vendor: str = ""
    advertised_services: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    pairing_mode: bool = False
    encryption_required: bool = False
    known_issues: List[str] = field(default_factory=list)

    def risk_score(self) -> int:
        score = 0
        if not self.encryption_required:
            score += 3
        if self.pairing_mode:
            score += 2
        if "bonding-not-required" in self.flags:
            score += 2
        if any(kw in self.address.lower() for kw in ("00:00:00", "ff:ff:ff")):
            score += 1
        return min(score, 10)

    def to_dict(self) -> dict:
        return {
            "address": self.address, "rssi": self.rssi,
            "vendor": self.vendor,
            "advertised_services": self.advertised_services,
            "flags": self.flags,
            "pairing_mode": self.pairing_mode,
            "encryption_required": self.encryption_required,
            "known_issues": self.known_issues,
            "risk_score": self.risk_score(),
        }


# Known BLE service UUIDs and their typical risk implications
BLE_SERVICE_RISK: Dict[str, str] = {
    "0000180f-0000-1000-8000-00805f9b34fb": "HID-Keyboard/Mouse — keylogging risk",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate — PII leak if unencrypted",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information — firmware version disclosure",
    "0000fef5-0000-1000-8000-00805f9b34fb": "Common IoT vendor (Xiaomi/Philips) — default auth",
    "0000fff0-0000-1000-8000-00805f9b34fb": "Common BLE lock/smart-lock service",
    "0000ffe0-0000-1000-8000-00805f9b34fb": "Often unauthenticated custom/vendor service",
}

VENDOR_OUI: Dict[str, str] = {
    "00:0A:27": "Apple", "00:0B:81": "Sony", "00:0C:E6": "Shenzhen Vichip",
    "00:11:22": "Nordic Semiconductor", "00:13:FA": "Raspberry Pi Foundation",
    "00:17:88": "Texas Instruments", "00:21:2F": "Belkin", "00:24:0A": "Raspberry Pi",
    "00:26:18": "Ring", "00:40:96": "Hikvision", "00:60:2B": "Bosch",
    "00:A0:50": "Texas Instruments", "00:D0:69": "Cisco", "08:D0:34": "Axis",
    "18:B4:30": "Google", "24:0A:C4": "Google Nest", "54:6F:a4": "Sonoff",
}


def parse_mac(mac: str) -> str:
    """Return manufacturer guess from OUI prefix."""
    prefix = ":".join(mac.upper().split(":")[:3])
    return VENDOR_OUI.get(prefix, "Unknown")


def classify_device(service_uuids: List[str], flags: List[str]) -> tuple:
    """Determine pairing mode and encryption requirement from BLE flags/services."""
    pairing = "no" in [f.lower() for f in flags] or len(service_uuids) == 0
    encrypted = "le-secure-connections" in " ".join(flags).lower()
    issues: List[str] = []
    for uuid in service_uuids:
        lower = uuid.lower().strip()
        if lower in BLE_SERVICE_RISK:
            issues.append(BLE_SERVICE_RISK[lower])
        elif not re.match(r"^([0-9a-f]{8}-){3}[0-9a-f]{8}$", lower):
            issues.append(f"Non-standard UUID '{uuid}' may indicate proprietary/unvetted protocol")
    return pairing, encrypted, issues


def parse_hcitool_le_scan(path: str) -> List[BleDevice]:
    """Parse hcitool le scan output lines."""
    devices: List[BleDevice] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return devices
    # Typical format: XX:XX:XX:XX:XX:XX <length> <data> <RSSI>
    # Also common multi-line with name + addr
    pattern_addr = re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
    current: Optional[BleDevice] = None
    for line in content.splitlines():
        m = pattern_addr.search(line)
        if m and not current:
            current = BleDevice(address=m.group(0))
        if current:
            rssi_m = re.search(r"[-]?\d+\s*$", line)
            if rssi_m:
                current.rssi = int(rssi_m.group())
            flag_m = re.findall(r"(le-generic|le-limited|br-edr-not-supported|le-secure-connections|bonding-not-required)", line, re.I)
            current.flags.extend(flag_m)
    if current:
        devices.append(current)
    return devices


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Bluetooth/BLE Security Assessment Helper",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input", nargs="?", help="Path to hcitool/btmon dump file")
    parser.add_argument("--services", nargs="*", help="Manual BLE service UUIDs to annotate")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON profile")
    args = parser.parse_args()

    devices: List[BleDevice] = []

    if args.input and os.path.isfile(args.input):
        devices.extend(parse_hcitool_le_scan(args.input))

    if args.services:
        svc_names = set(args.services)
        for dev in devices:
            devs_services = [u.lower() for u in dev.advertised_services]
            matched = svc_names & set(devs_services)
            if matched:
                dev.advertised_services = list(matched)
                pairing, encrypted, issues = classify_device(list(matched), dev.flags)
                dev.pairing_mode = pairing
                dev.encryption_required = encrypted
                dev.known_issues = issues

    if not devices:
        print("[!] No devices found in input (provide a scan dump or --services flag).", file=sys.stderr)
        return 2

    critical_count = sum(1 for d in devices if d.risk_score() >= 6)
    high_count = sum(1 for d in devices if 4 <= d.risk_score() < 6)

    print(f"\n  [*] Scanned {len(devices)} BLE device(s)")
    print(f"  [*] Risk breakdown: CRITICAL={critical_count}  HIGH={high_count}\n")
    for d in sorted(devices, key=lambda x: -x.risk_score()):
        risk_label = "CRITICAL" if d.risk_score() >= 6 else "HIGH" if d.risk_score() >= 4 else "MEDIUM" if d.risk_score() else "LOW"
        print(f"  [{risk_label:>8}] {d.address}  RSSI={d.rssi}dBm  Vendor={d.vendor or '?'}")
        if d.advertised_services:
            print(f"           Services : {', '.join(d.advertised_services[:5])}")
        if d.known_issues:
            for iss in d.known_issues[:3]:
                print(f"           * {iss}")

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "device_count": len(devices),
        "devices": [d.to_dict() for d in devices],
    }
    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    print(f"\n  [*] Recommended controls per BSIMCG IoT guidance:\n"
          f"      - Enforce LE Secure Connections (encryption) on all paired links\n"
          f"      - Disable pairing mode when not in use (bonding-not-required flag)\n"
          f"      - Inventory all BLE vendors and revoke access for unknown vendors\n"
          f"      - Validate service UUIDs against approved allowlist\n", file=sys.stderr)

    return 1 if critical_count else 0


if __name__ == "__main__":
    sys.exit(main())
