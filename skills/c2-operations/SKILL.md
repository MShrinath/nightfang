---
name: c2-operations
description: Command and Control (C2) resilience and adversary infrastructure assessment covering multi-tier redirector architectures, malleable traffic profile analysis, covert protocol egress auditing (DNS/HTTPS/ICMP tunneling), and network beacon detection telemetry.
version: "2.0"
domain: cybersecurity
subdomain: red-team-operations
tags: [c2, command-and-control, redirectors, domain-fronting, malleable-c2, egress-testing, dns-tunneling, covert-channels]
mitre_attack: [T1071, T1090, T1095, T1572, T1573, T1041]
d3fend_techniques: [D3-NTF, D3-NTA, D3-DNSA, D3-PA]
---

# Command & Control (C2) Resilience Skill

Methodology for assessing network perimeter detection capabilities, evaluating covert communication channel resilience, analyzing proxy egress controls, and measuring detection telemetry for adversary infrastructure.

> **SAFETY & HITL GOVERNANCE**: Active deployment of network listener beacons, tunneling mechanisms, or simulated C2 traffic across production networks strictly requires explicit Human-in-the-Loop authorization per [SOP-04](../../references/sops.md#sop-04-human-in-the-loop-hitl-exploitation-gate). Only benign canary traffic with verifiable non-destructive payloads may be transmitted per [SOP-05](../../references/sops.md#sop-05-proof-of-concept-safety--artifact-cleanup).

---

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `CALDERA` | Automated adversary emulation & C2 scenario execution | CALDERA web interface / agent deployment | Atomic Red Team / manual scripts |
| `Atomic Red Team` | Atomic C2 communication testing primitives | `Invoke-AtomicTest T1071.001 -ShowDetails` | Manual curl / Invoke-WebRequest |
| `Zeek / Suricata` | Network traffic monitoring & protocol inspection | `zeek -C -r <PCAP_FILE>` | Wireshark / TShark analysis |
| `dnscat2 / iodine` | DNS tunneling detection & egress auditing | Query inspection mode (canary queries) | `dig` / `nslookup` automated loops |
| `egress-assess` | Protocol egress and egress firewall validation | `egress-assess --client <SERVER_IP>` | PowerShell TCP connection tests |

---

## Methodology

### 1. Multi-Tiered Infrastructure & Redirector Architecture
Evaluate security monitoring visibility against multi-tier C2 delivery architectures:
- **Functional Tier Segregation**:
  - *Short-haul interactive tier*: High-frequency, short-dwell listeners for interactive operations.
  - *Long-haul staging tier*: Low-frequency, high-jitter beacons for long-term operational resilience.
- **Reverse Proxy Redirectors**: Apache `mod_rewrite` / Nginx reverse proxies filtering incoming HTTP requests based on user-agent, headers, or query parameters, routing non-matching traffic to benign decoy websites.
- **Domain Fronting & Cloud Relays**: Assessing detection capabilities when traffic routes through shared CDNs or cloud frontends (Cloudflare, AWS CloudFront, Azure Edge).

### 2. Malleable C2 Traffic Profiles & Protocol Blending (T1071)
Assess deep packet inspection (DPI) and proxy visibility against custom-shaped network traffic:
- **HTTP/HTTPS Header Camouflage**: Simulating C2 beaconing using legitimate browser headers, cookies, and standard API JSON payloads.
- **Jitter & Sleep Calibration**: Measuring beacon detection thresholds by introducing random time intervals (jitter: 20%–50%) to disrupt periodic frequency analysis.
- **WebSockets & Asynchronous Streams**: Testing protocol state tracking by evaluating continuous bi-directional WebSocket connections.
- **Legitimate SaaS Relays**: Simulating C2 channels that transit legitimate cloud platforms (Slack Webhooks, Microsoft Teams APIs, Google Drive API).

### 3. Covert Egress & Protocol Tunneling (T1572, T1095)
Evaluate outbound perimeter firewall enforcement and deep inspection controls:
- **DNS Tunneling (T1071.004)**:
  - Inject benign synthetic subdomain queries (`<canary-token>.test.c2.domain.com`) to evaluate DNS query log analytics, entropy thresholds, and TXT record payload detection.
- **ICMP Tunneling (T1095)**:
  - Transmit benign echo requests with arbitrary data payloads to determine if stateful firewalls inspect ICMP packet body contents.
- **Proxy Authentication & SSL Inspection Bypass**:
  - Evaluate egress proxy inspection when traffic uses non-standard ports over SSL or uses pinned certificates.

### 4. Detection Telemetry & Beacon Heuristics (T1041)
- **JA3 / JA4 Fingerprinting**: Analyze TLS Client Hello parameters (ciphers, extensions, elliptic curves) to identify anomalous custom beacon binaries.
- **NetFlow / IPFIX Analysis**: Calculate connection periodicity, bytes sent vs. bytes received ratios, and duration metrics.
- **Mean Time to Detect (MTTD)**: Measure the time elapsed from beacon initiation until automated SOC alert generation.

---

## Defensive Pairing & Detection Engineering

| Attack Technique | MITRE D3FEND Countermeasure | Detection Logic Specification |
| :--- | :--- | :--- |
| **T1071.001** (Web C2) | `D3-NTF` (Network Traffic Filtering) | Sigma: HTTP requests with unusual User-Agent strings or periodic beacon intervals matching Jaro-Winkler regularity > 0.85 |
| **T1071.004** (DNS Tunneling) | `D3-DNSA` (DNS Analysis) | Zeek / Sentinel: Alert on DNS domains with high Shannon entropy in subdomains or request rate > 50 queries/min |
| **T1095** (Non-Application Tunnel) | `D3-PA` (Protocol Analysis) | Suricata: Detect ICMP echo requests where payload length exceeds standard operating system defaults (> 64 bytes) |

---

## Output Contract

- C2 Resilience & Egress Gap Analysis Report detailing perimeter filtering efficacy and MTTD.
- Standardized finding records formatted per [`schemas/finding.md`](../../schemas/finding.md).
