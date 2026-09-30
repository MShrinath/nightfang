---
name: hunting
description: Advanced threat hunting, business logic flaws, race conditions, parameter pollution, and novel vulnerability chaining.
version: "2.0"
domain: cybersecurity
subdomain: threat-hunting
tags: [hunting, logic-flaws, race-conditions, toctou, parameter-pollution, request-smuggling]
mitre_attack: [T1203, T1059, T1562]
d3fend_techniques: [D3-THA, D3-MCI]
---

# Threat Hunting & Logic Flaw Discovery

Manual, creative vulnerability hunting that goes beyond automated scanner templates to discover business logic flaws, race conditions, and complex attack paths.

## Hunting Methodologies

### 1. Business Logic & Workflow Bypasses
- **Multi-Step Process Tampering**: Skip mandatory verification steps (e.g., jump directly from Step 1 [Cart] to Step 4 [Order Confirmation], skipping Step 3 [Payment]).
- **Negative & Decimal Values**: Inject negative quantities, oversized numbers, or extreme decimal precisions in financial, credit, or checkout parameters.
- **State Confusion**: Reuse checkout tokens across accounts or swap user sessions mid-flow.

### 2. Concurrency & Race Conditions (TOCTOU)
- **Time-of-Check to Time-of-Use (TOCTOU)**:
  - Test discount coupons, balance transfers, or single-use gift cards by firing 20–50 parallel requests simultaneously.
  - Script parallel requests using `curl` background jobs:
    ```bash
    for i in {1..20}; do curl -s -X POST https://target/api/redeem -H "Auth: Bearer $TOKEN" -d '{"code":"PROMO"}' & done; wait
    ```
  - Verify whether credit or state was applied multiple times.

### 3. Advanced Web Protocol Attacks
- **Parameter Pollution (HPP)**: Submit identical parameter names multiple times (`?id=1&id=2`) to observe whether backend parsers accept first, last, or concatenate values to bypass WAFs.
- **HTTP Request Smuggling**: Test front-end proxy vs. back-end server parsing discrepancies using `CL.TE` and `TE.CL` transfer-encoding and content-length headers.
- **Web Cache Poisoning**: Inject unkeyed headers (`X-Forwarded-Host`, `X-Original-URL`) to poison CDN/cache responses with malicious redirections or scripts.
- **Prototype Pollution**: Send objects with `__proto__`, `constructor.prototype` keys into JSON parsers to modify base JavaScript prototypes.

### 4. Authentication & Token Deep Dives
- **JWT Tampering**:
  - Test acceptance of `alg: none`.
  - Check signature verification failure bypass.
  - Test public-key-to-HMAC algorithm confusion (RS256 to HS256).
- **OAuth Hunting**:
  - Manipulate `redirect_uri` to external domains.
  - Test for missing or unvalidated `state` parameters allowing CSRF on OAuth connections.

### 5. Behavioral Threat Hunting & Evasion Artifacts
- Cross-link with [`skills/defense-evasion`](../defense-evasion/SKILL.md):
  - **Process Lineage Anomalies**: Hunt for unusual parent-child process trees (e.g., `winword.exe`, `excel.exe`, or `w3wp.exe` spawning `cmd.exe` or `powershell.exe`).
  - **Memory Inspection**: Hunt for processes containing unbacked executable memory regions (`PAGE_EXECUTE_READWRITE`) using tools like `Moneta` and `PE-sieve`.
  - **Living off the Land Abuse**: Detect command line invocations of LOLBAS binaries executing non-standard arguments (`mshta http://`, `certutil -urlcache`).

### 6. Network Beaconing & C2 Heuristic Hunting
- Cross-link with [`skills/c2-operations`](../c2-operations/SKILL.md):
  - **Traffic Periodicity Analysis**: Hunt NetFlow and proxy logs for repetitive HTTP/HTTPS outbound requests exhibiting regular time intervals (beaconing) with low delta variance.
  - **TLS JA3/JA4 Fingerprinting**: Identify anomalous TLS Client Hello fingerprints not associated with standard enterprise operating systems or browsers.
  - **DNS Entropy & Query Volume**: Identify high-entropy subdomain lookups indicating DNS tunneling or covert egress channels.

### 7. Credential Access Telemetry Hunting
- Cross-link with [`skills/credential-access`](../credential-access/SKILL.md):
  - **LSASS Access Monitoring**: Query Sysmon Event ID 10 for processes requesting `PROCESS_VM_READ` on `lsass.exe` outside authorized antimalware and system binaries.
  - **SAM & DPAPI Access**: Monitor Windows Security Event ID 4656/4663 for unauthorized handle requests targeting `%SystemRoot%\System32\config\SAM` or user DPAPI master key folders.

## Output
- Detailed logic flaw reproduction walkthroughs and behavioral hunt hypotheses.
- Findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
