---
name: wireless
description: Wireless and radio frequency (RF) security assessment covering IEEE 802.11 (WPA2/WPA3-Personal, WPA-Enterprise), rogue APs, Bluetooth Low Energy (BLE), Zigbee, and sub-GHz IoT communication.
domain: cybersecurity
subdomain: wireless-security
tags: [wireless, wifi, wpa2, wpa3, ble, bluetooth, zigbee, rogue-ap, 802.11]
mitre_attack: [T1040, T1200, T1407, T1412]
d3fend_techniques: [D3-WSE, D3-CTA]
version: "1.0"
---

# Wireless & RF Security Skill

Methodology for assessing wireless local area networks, Bluetooth peripherals, and Internet-of-Things (IoT) radio frequency communication protocols.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `aircrack-ng` suite | 802.11 packet capture & frame analysis | `airodump-ng <IFACE>` | Kismet / Wireshark |
| `bettercap` | Wireless & BLE reconnaissance framework | `bettercap -iface <IFACE>` | `hcxdumptool` / `tshark` |
| `eaphammer` | Targeted WPA-Enterprise evil twin & credential harvest | `eaphammer --creds --interface <IFACE>` | hostapd-wpe |
| `gattacker` / `bleah` | Bluetooth Low Energy (BLE) GATT auditing | `bleah -t 20` | `gatttool` / `bluetoothctl` |

## Methodology

### 1. 802.11 Network Discovery & Mapping
- Passive spectrum scanning to identify active BSSIDs, ESSIDs, channel distribution, and encryption standards (WEP, WPA-TKIP, WPA2-CCMP, WPA3-SAE).
- Detect hidden SSIDs through client probe request correlation.
- Identify client association status and monitor signal strength to map rogue access points.

### 2. WPA/WPA2/WPA3 Authentication Auditing
- **WPA2-PSK (Pre-Shared Key)**: Passive capture of the 4-way EAPOL handshake via legitimate client reconnection. Offline dictionary analysis using authorized wordlists.
- **WPA3-SAE (Simultaneous Authentication of Equals)**: Evaluate target AP for downgrade attack vulnerabilities (Transition Mode allowing WPA2 fallback).
- **WPA-Enterprise (802.1X)**: Audit EAP method configuration (PEAP-MSCHAPv2, EAP-TLS, EAP-TTLS). Test for missing server certificate validation on corporate endpoints.

### 3. Rogue Access Points & Evil Twin Analysis
- Set up controlled rogue AP to identify client devices with misconfigured auto-connect profiles.
- Test for client certificate validation enforcement when presented with synthetic RADIUS server certificates.

### 4. Bluetooth Low Energy (BLE) & IoT RF Auditing
- Enumerate BLE advertising packets, UUIDs, and exposed GATT services and characteristics.
- Test GATT characteristics for missing read/write authorization and unencrypted communications.
- Assess pairing modes (Just Works vs Passkey Entry vs Numeric Comparison) for eavesdropping or MITM vulnerabilities.

## Output
- Wireless infrastructure inventory, rogue AP detection summary, and RF exposure findings.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
