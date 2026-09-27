---
name: ot-ics
description: Operational Technology (OT) and Industrial Control Systems (ICS) security assessment covering SCADA, PLC, DCS, industrial protocols (Modbus, DNP3, S7comm, EtherNet/IP, OPC-UA), and IEC 62443 compliance under strict safety controls.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot, ics, scada, plc, modbus, dnp3, s7comm, opc-ua, iec62443, purdue-model]
mitre_attack: [T0800, T0814, T0836, T0843, T0846, T0855, T0886]
d3fend_techniques: [D3-ICS, D3-NTA, D3-PRP]
version: "1.0"
---

# Operational Technology (OT) & ICS Security Skill

Passive, safety-first methodology for evaluating industrial networks, programmable logic controllers (PLCs), human-machine interfaces (HMIs), and supervisory control architectures.

> **SAFETY MANDATE (Zero Process Interruption)**: Industrial control networks cannot tolerate high-rate traffic, aggressive port scans, or malformed protocol packets. All OT testing is **passive-first** (pcap analysis, span port listening) and strictly requires manual operator confirmation before any active protocol query.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `wireshark` / `tshark` | Deep industrial packet inspection | `tshark -r capture.pcap -Y "modbus || s7comm || dnp3"` | Python `scapy` |
| `s7scan` | Siemens S7 PLC read-only enumeration | `s7scan <PLC_IP>` | PLC status web interface |
| `modbus-cli` | Read-only Modbus register inspection | `modbus read <PLC_IP> holding 1 10` | Python `pymodbus` |
| `nmap` (ICS NSE) | Low-rate, non-intrusive industrial probes | `nmap --script modbus-discover,s7-info -p 502,102 <PLC>` (T2 rate) | Passive traffic analysis |

## Methodology

### 1. Purdue Model Mapping & Network Segmentation
- **Architecture Validation**: Verify strict perimeter segmentation between Enterprise IT (Levels 4-5) and Industrial Control Network (Levels 0-3).
- **Industrial DMZ (IDMZ, Level 3.5)**: Audit jump boxes, data historians, and dual-homed systems for direct routing or bridge bypasses.
- **Rogue Wireless / Cellular Gateways**: Identify maintenance cellular modems or unapproved access points bridging field networks directly to the Internet.

### 2. Industrial Protocol Analysis (Level 1–2)
- **Modbus TCP (Port 502)**:
  - Inspect for absence of authentication and encryption.
  - Read diagnostic information (Function Code 43 / Device Identification).
  - Verify if holding registers or coils can be read anonymously.
- **Siemens S7comm / S7comm-plus (Port 102)**:
  - Query PLC type, firmware version, and module state via read-only SZL requests.
  - Audit CPU protection level (Protection Level 1/2/3).
- **DNP3 (Port 20000) & EtherNet/IP (Port 44818)**:
  - Inspect for unencrypted control communication and absence of cryptographic integrity verification.
- **OPC-UA (Port 4840)**:
  - Enumerate endpoints; verify security policy enforcement (`Basic256Sha256`, `SignAndEncrypt`) vs insecure `None`.

### 3. HMI & Engineering Workstation Auditing (Level 2)
- Audit HMI operating systems for unpatched legacy vulnerabilities (Windows 7/XP, missing SMB signing).
- Inspect HMI application project files for hardcoded passwords, cleartext database connections, and default administrative credentials.

### 4. Safety Instrumented Systems (SIS) Isolation
- Verify physical and logical isolation of Safety Instrumented Systems (e.g. Triconex, HIMA) from standard basic process control systems (BPCS).

## Output
- OT/ICS risk assessment conforming to IEC 62443-3-3 and ATT&CK for ICS.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
