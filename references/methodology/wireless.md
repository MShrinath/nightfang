# Methodology: wireless

Source: [PentestingEverything/Wi-Fi Pentesting](https://github.com/m14r41/PentestingEverything/tree/main/Wi-Fi%20Pentesting)

---


# Wireless Pentesting Checklist

## Core Concepts

Wi-Fi pentesting evaluates the security of wireless networks and their clients to determine whether an attacker within radio range can gain unauthorized access, intercept traffic, or pivot into the internal network. The goal is to validate encryption, authentication, segmentation, and physical signal exposure.

**Phases**
- Recon and discovery: enumerate SSIDs, BSSIDs, channels, encryption types, and WPS status.
- Access attempt: attack the relevant auth model (WEP/WPA2 handshake capture and cracking, or enterprise 802.1X).
- Rogue/Evil Twin testing: assess client trust and credential capture via spoofed access points (in scope only).
- Post-access assessment: once on the network, probe segmentation, internal services, and outbound controls.
- Reporting: document exposure, weak controls, and remediation.

**Key concepts**
- Encryption matters: Open and WEP are trivially broken; WPA2-PSK is offline-crackable from a captured handshake; WPA3 and 802.1X raise the bar.
- WPS PINs and weak pre-shared keys are common fast paths to access.
- Enterprise (802.1X) security hinges on certificate validation and the EAP method; misconfig enables credential theft.
- Signal leakage beyond the physical perimeter expands the attack surface.
- Flat networks (no VLAN/segmentation) turn Wi-Fi access into full internal access.

> How to perform real world Wifi Pentesting:

## Unauthenticated

* Collect details using `airodump-ng / Kismet / WiFi Analyzer`: SSID, BSSID, channel, encryption type, WPS status
* If WPS is enabled → assess WPS exposure; if not → proceed with other authentication methods
* Identify encryption type: Open / WEP / WPA2 / WPA3 (note handshake + authentication type)
* Check WiFi signal leakage beyond intended physical boundary (office perimeter)
* Use `airodump-ng` to monitor target AP and clients; identify active stations
* Check for captive portal:

  * Observe authentication flow
  * Validate client binding/session behavior
* Validate MAC filtering / access restrictions (if present)
* Test network reachability (if any partial access exists): DNS / HTTP / ICMP behavior
* Observe traffic patterns for exposed services or misconfigurations

---

## If Enterprise Setup (802.1X)

* Identify WPA2/WPA3-Enterprise deployment
* Determine EAP method (PEAP / EAP-TLS / TTLS / others)
* Validate certificate authentication behavior (trusted / untrusted / pinned)
* Identify RADIUS dependency and authentication flow
* A

---

