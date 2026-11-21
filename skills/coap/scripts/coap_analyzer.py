#!/usr/bin/env python3
"""
CoAP Protocol Security Analyzer — inspects raw CoAP request/response captures
(pcapng/text export or manual hex input) for protocol misuse, unencrypted
observe subscriptions, and option abuse. Does NOT send packets.
"""
from __future__ import annotations

import argparse
import binascii
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


# CoAP version/map constants (RFC 7252)
COAP_VERSIONS = {0: "v1.0", 1: "v1.1"}
COAP_METHODS = {1: "GET", 2: "POST", 3: "PUT", 4: "DELETE", 5: "FETCH", 6: "PATCH", 7: "INTERBIT"}
COAP_CODES = {
    0x01: "Created", 0x02: "Deleted", 0x03: "Valid", 0x04: "Changed",
    0x05: "Created2", 0x40: "Content", 0x41: "Continued",
    0x80: "Bad Request", 0x81: "Unauthorized", 0x82: "Bad Option",
    0x83: "Forbidden", 0x84: "Not Found", 0x85: "Method Not Allowed",
    0x86: "Not Acceptable", 0x87: "Conflict", 0x88: "Precondition Failed",
    0x89: "Request Entity Too Large", 0x8A: "Unsupported Media Type",
    0xBF: "Too Many Requests", 0xC0: "Request Entity Cached",
    0xC1: "Partial Content",
}


@dataclass
class CoAPOption:
    number: int
    length: int
    value_hex: str
    is_critical: bool = False
    delta: int = 0


@dataclass
class CoAPMessage:
    msg_id: int
    token: bytes
    code: Optional[int]
    method_name: str = ""
    options: List[CoAPOption] = field(default_factory=list)
    payload_start: int = 0
    payload_hex: str = ""
    source: str = ""
    dest: str = ""
    anomalies: List[str] = field(default_factory=list)

    def flag_anomaly(self, msg: str) -> None:
        if msg not in self.anomalies:
            self.anomalies.append(msg)

    def to_dict(self) -> dict:
        return {
            "msg_id": self.msg_id, "token": binascii.hexlify(self.token).decode(),
            "code": self.code, "method": self.method_name,
            "options_count": len(self.options),
            "payload_size_bytes": len(self.payload_hex) // 2,
            "anomalies": self.anomalies, "source": self.source, "dest": self.dest,
        }


def parse_coap_header(raw: bytes, offset: int = 0) -> tuple:
    """Return (version, type, token_len, flags_reserved, msg_id) from header."""
    if offset + 4 > len(raw):
        return None
    b0, b1, b2, b3 = raw[offset:offset+4]
    version = (b0 >> 6) & 0x03
    tcnr = b0 & 0x03
    msg_type = (b1 >> 6) & 0x03
    token_len = b1 & 0x0F
    flags = (b2 >> 4) & 0x0F
    msg_id = ((b2 & 0x0F) << 8) | b3
    return version, msg_type, token_len, flags, msg_id


def decode_option_delta(option_byte: int) -> tuple:
    """Returns (delta_inc, delta_extra_length, incl_byte, extra_length)."""
    inc = option_byte >> 4
    length = option_byte & 0x0F
    if inc < 13:
        return inc, length, None, None
    if inc == 13:
        extra = bytearray()
        extra.append(option_byte)
        return 13, length, extra, 1
    if inc == 14:
        extra = bytearray()
        extra.append(option_byte)
        return 14, length, extra, 2
    # inc == 15 => end of options
    return 15, length, None, None


def parse_coap_packet(raw: bytes, src: str = "", dst: str = "") -> Optional[CoAPMessage]:
    """Parse a single CoAP packet from raw bytes."""
    header = parse_coap_header(raw)
    if header is None:
        return None
    version, msg_type, token_len, _flags, msg_id = header
    if version != 1:
        return None  # only v1.1 handled here

    idx = 4
    token = raw[idx:idx+token_len]
    idx += token_len

    code = None
    if idx < len(raw):
        code = raw[idx]
        idx += 1

    method_name = ""
    if code is not None and code <= 31:
        method_name = COAP_METHODS.get(code, f"UNKNOWN-{code}")

    opts: List[CoAPOption] = []
    while idx < len(raw):
        b = raw[idx]
        idx += 1
        inc, length, ext_byte, ext_len = decode_option_delta(b)
        if inc == 15:
            break
        opt_delta = inc
        opt_len = length
        if inc == 13:
            if idx >= len(raw):
                break
            opt_delta = (raw[idx] << 8) | raw[idx+1]
            idx += 2
        elif inc == 14:
            if idx + 1 >= len(raw):
                break
            opt_delta = (raw[idx] << 8) | raw[idx+1]
            idx += 2
        if opt_len == 0:
            pass
        elif opt_len == 1:
            if idx >= len(raw):
                break
            opt_len = raw[idx]
            idx += 1
        elif opt_len == 2:
            if idx + 1 >= len(raw):
                break
            opt_len = (raw[idx] << 8) | raw[idx+1]
            idx += 2
        val_start = idx
        idx += opt_len
        val_bytes = raw[val_start:val_start+opt_len]
        opts.append(CoAPOption(number=opt_delta, length=opt_len, value_hex=val_bytes.hex()))

    payload = b""
    if idx < len(raw) and raw[idx] == 0xFF:
        idx += 1
    if idx < len(raw):
        payload = raw[idx:]

    msg = CoAPMessage(msg_id=msg_id, token=token, code=code, method_name=method_name,
                      options=opts, payload_hex=payload.hex(), source=src, dest=dst)

    # Anomaly checks
    observe_opt = next((o for o in opts if o.number == 6), None)
    if observe_opt and not any(o.number == 5 for o in opts):  # no block2?
        msg.flag_anomaly("Observe subscription without Block2 — potential DoS vector")
    if any(o.number in (15, 16, 17, 18, 19) for o in opts):  # Uri-Path, Uri-Query, Proxy-Uri, Uri-Host, ETag
        # Check for path traversal hints
        for o in opts:
            if b".." in o.value_hex.encode():
                msg.flag_anomaly(f"Suspicious option {o.number}: possible path traversal in URI component")
    if len(msg.token) == 0 and code is not None and code >= 0x80:
        msg.flag_anomaly("Error response without token — may indicate malformed/probe packet")
    if payload and len(payload) > 1024:
        msg.flag_anomaly(f"Large payload ({len(payload)} bytes) on {'request' if method_name else 'response'}")
    return msg


def load_packets_from_text(path: str) -> List[tuple]:
    """Load space-separated hex byte pairs from a text file (one packet per line)."""
    packets: List[tuple] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Could be pure hex or colons or spaces; normalize
                cleaned = re.sub(r"[ :\t]", "", line)
                if re.match(r"^([0-9a-fA-F]{2})+$", cleaned) and len(cleaned) % 4 == 0:
                    try:
                        raw = binascii.unhexlify(cleaned)
                        packets.append((raw,))
                    except ValueError:
                        pass
    except OSError:
        pass
    return packets


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG CoAP Protocol Security Analyzer (Passive)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input", help="Path to hex-dump file (one CoAP packet per line)")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"[!] Input not found: {args.input}", file=sys.stderr)
        return 2

    packets = load_packets_from_text(args.input)
    messages: List[CoAPMessage] = []
    for pkt_tuple in packets:
        msg = parse_coap_packet(pkt_tuple[0])
        if msg:
            messages.append(msg)

    anomaly_counts: Dict[str, int] = {}
    for msg in messages:
        for a in msg.anomalies:
            anomaly_counts[a] = anomaly_counts.get(a, 0) + 1

    print(f"\n  [*] Parsed {len(messages)} valid CoAP message(s) from {args.input}")
    print(f"  [*] Methods observed: {', '.join(dict.fromkeys(m.method_name for m in messages if m.method_name)) or 'N/A'}")
    print(f"  [*] Error responses : {sum(1 for m in messages if m.code and m.code >= 0x80)}")
    print(f"  [*] Messages with anomalies: {sum(1 for m in messages if m.anomalies)}\n")
    for msg in messages[:20]:
        sig = f"{msg.method_name or '?':>8} id={msg.msg_id} token={binascii.hexlify(msg.token).decode()[:12]}"
        if msg.anomalies:
            sig += f"  [!{len(msg.anomalies)}]"
        print(f"  {sig}")
        for a in msg.anomalies[:2]:
            print(f"       ~ {a}")

    if anomaly_counts:
        print(f"\n  [*] Anomaly summary:")
        for k, v in sorted(anomaly_counts.items(), key=lambda x: -x[1]):
            print(f"      [{v:>3d}] {k}")

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_messages": len(messages),
        "messages": [m.to_dict() for m in messages],
        "anomaly_summary": anomaly_counts,
    }
    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    return 1 if any(m.anomalies for m in messages) else 0


if __name__ == "__main__":
    sys.exit(main())
