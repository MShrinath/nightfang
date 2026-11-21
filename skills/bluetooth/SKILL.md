# BLE (Bluetooth Low Energy) Security Testing Skill

**Category**: Wireless / Bluetooth Security  
**Associated Agents**: `protocol-pentester`, `wireless-pentester`, `iot-pentester`  
**Payload Integration**: BLE pairing attacks map to CWE-287 (Improper Authentication). Use `resolver.get_by_cwe("CWE-287")` for safe enumeration payloads.  

---

## 1. Scope

BLE security assessment covering device discovery, pairing vulnerability testing, GATT service enumeration, characteristic manipulation, and protocol-level downgrade attacks on Bluetooth 4.0–5.4 implementations.

---

## 2. Reconnaissance Phase

### 2.1 Device Discovery & Profiling
```bash
# List all BLE peripherals in range
btmgmt find
# Or use hcitool for older stacks
hcitool lescan --dual --le
# Identify vendor by OUI prefix
gatttool -b <MAC> -I <<EOF
connect <MAC>
characteristics
exit
EOF
```

### 2.2 GATT Service Enumeration
Extract all services, characteristics, and descriptors to map attack surface:
```python
from bleak import BleakClient
async def enumerate_gatt(mac: str):
    async with BleakClient(mac) as client:
        services = await client.get_services()
        for svc in services:
            print(f"Service: {svc.uuid}")
            for ch in svc.characteristics:
                print(f"  Char: {ch.uuid} props={ch.properties} desc={ch.descriptors}")
```

### 2.3 Pairing Mode Analysis
Detect insecure pairing configurations:
| Configuration | Risk | Indicator |
|--------------|------|-----------|
| Just Works | CRITICAL | No MITM protection, PIN=000000 |
| Passkey Entry | HIGH | PIN transmitted without encryption |
| Out of Band | LOW | Secure if NFC key exchange verified |
| numeric comparison | MEDIUM | Requires user confirmation on both sides |

---

## 3. Attack Vectors

| Vector | Technique | CWE | Safe? |
|--------|-----------|-----|-------|
| Man-in-the-Middle | MitM between two BLE devices | CWE-287 | HITL |
| Connection Parameter Abuse | Force high-latency/low-energy params | CWE-20 | YES |
| Bond Key Extraction | Extract stored bond keys from memory | CWE-798 | HITL |
| GATT Write Flood | Rapid writes causing stack exhaustion | CWE-400 | HITL |
| Descriptor Override | Modify CCCD to enable notify without auth | CWE-284 | YES |

---

## 4. Detection Rule Generation

### Sigma Rule
```yaml
title: Unusual BLE Bonding Request Volume
logsource:
    category: bluetooth_adapter
detection:
    selection_ble:
        event: 'bond_request'
    timeframe: 300
    condition: count(event) > 5 within timeframe
level: medium
```

---

## 5. Tools Reference

- `bluelog` — BLE scanner and analyzer
- `lightbrutus` — Automatic BLE exploitation framework
- `bluez tools` — hcitool, gatttool, btmgmt
- `bleah` — Python BLE penetration testing library

---

## 6. References

- Bluetooth Core Specification v5.4 — Sections on Security & Pairing
- CWE-287 Improper Authentication / CWE-284 Access Control Bypass
- OWASP Bluetooth Security Testing Guide
