---
name: network
description: Network service probing, CVE discovery, SSL/TLS cryptographic evaluation, SMB/SNMP auditing, and infrastructure testing.
version: "2.0"
domain: cybersecurity
subdomain: network-security
tags: [network, ports, services, cve, smb, snmp, ssl-tls, cryptography]
mitre_attack: [T1021, T1110, T1558, T1040, T1573, T1557]
d3fend_techniques: [D3-NA, D3-BA, D3-CTA, D3-CH]
---

# Network Security Skill

Methodologies for infrastructure and network-level vulnerability assessment and cryptographic configuration auditing.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `nmap` | Port scan & NSE scripting | `nmap -sV -sC -p <PORTS> <TARGET>` | `rustscan` |
| `masscan` | High-rate subnet port scanning | `masscan -p1-65535 <SUBNET> --rate=1000` | `nmap -sS -T4` |
| `enum4linux` | Windows/Samba enumeration | `enum4linux -a <TARGET>` | `crackmapexec smb` |
| `testssl.sh` | TLS cipher & protocol audit | `testssl.sh --quiet --color 0 <TARGET>:443` | `sslscan` / `sslyze` |

## Focus Areas

### 1. Service Enumeration & Fingerprinting
- Scan all discovered TCP ports and high-value UDP ports (53, 123, 161, 500, 1194).
- Extract service banners without triggering defensive lockouts.
- Map service versions against public NVD / CVE records for known exploitable vulnerabilities.

### 2. Network Protocol & Authentication Audits
- **SMB / RPC (Ports 139, 445)**:
  - Check for null session access, guest login acceptance, and open file shares.
  - Audit for SMB signing status (required vs. disabled).
- **SNMP (UDP 161)**:
  - Test for default community strings (`public`, `private`, `community`).
  - Enumerate network interfaces, routing tables, and system processes if SNMP is exposed.
- **Remote Access (SSH, RDP, VNC, Telnet)**:
  - Identify cleartext communication protocols (Telnet, FTP, HTTP, rlogin).
  - Verify SSH configuration for weak key exchange algorithms or password authentication on public bastions.

### 3. SSL/TLS Cryptographic Evaluation
- **Protocol Versions**: Detect deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1).
- **Cipher Suites**: Flag insecure ciphers (RC4, DES, 3DES, EXPORT, NULL, CBC mode ciphers susceptible to Lucky13).
- **Certificate Verification**:
  - Check certificate expiration, self-signed certificates, and hostname mismatches.
  - Verify certificate revocation mechanisms (CRL, OCSP stapling).
- **Known Flaws**: Test for Heartbleed, ROBOT, POODLE, DROWN, and secure renegotiation support.

## Output
- Network service inventory with identified versions.
- SSL/TLS cryptographic posture scorecard.
- Standardized findings recorded per [`schemas/finding.md`](../../schemas/finding.md).
