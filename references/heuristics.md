# NIGHTFANG Decision Heuristics & Triage Logic

Internal decision-making heuristics used by NIGHTFANG agents to prioritize attack vectors, score findings, deconflict swarm operations, guide tool fallback, hunt variants, and evaluate feasibility.

---

## 1. Finding Severity & Priority Calibration

NIGHTFANG scores severity from **1 (Informational)** to **10 (Critical)** using the impact decision matrix:

```
IF unauthenticated RCE OR full database compromise OR full cloud admin takeover OR ICS Safety Instrumented System trip:
  --> Severity = 9 - 10 (Critical)

ELSE IF authenticated RCE OR high-privilege BOLA/IDOR OR mass credential leakage OR direct SQLi OR AD Domain Admin path:
  --> Severity = 7 - 8 (High)

ELSE IF stored XSS OR standard IDOR (limited PII) OR CSRF on state-changing actions OR SSRF (internal only) OR K8s namespace breakout:
  --> Severity = 5 - 6 (Medium)

ELSE IF reflected XSS OR missing rate-limiting OR verbose stack trace with path disclosure OR TLS 1.0/1.1 OR weak cipher:
  --> Severity = 3 - 4 (Low)

ELSE (Missing security headers, banner disclosure, informational items):
  --> Severity = 1 - 2 (Informational)
```

### Multi-Metric Priority Triage (EPSS + CISA KEV + CVSS)
Severity reflects potential damage; operational **Priority (P0–P3)** dictates remediation urgency:
- **P0 (Emergency - Fix SLA 24h)**: Any finding listed on **CISA KEV** or having **EPSS $\ge 0.36$** with Nightfang Severity $\ge 7$.
- **P1 (High - Fix SLA 7d)**: Unauthenticated vulnerabilities with Nightfang Severity $\ge 7$ or CVSS v4.0 $\ge 8.0$.
- **P2 (Medium - Fix SLA 30d)**: Authenticated vulnerabilities or high-complexity attack paths (Severity 5–6).
- **P3 (Low - Fix SLA 90d)**: Informational / hardening deviations (Severity 1–4).

> **Scoring Separation Rule**: Nightfang Severity (1–10 qualitative), Nightfang Confidence (1–10 certainty), CVSS v3.1/v4.0 (formula metric), and EPSS (empirical probability 0.0–1.0) are completely distinct and recorded independently in [`schemas/finding.md`](../schemas/finding.md).

---

## 2. Action Classification & HITL Gate Heuristic

Severity drives **urgency/priority** in alerts. The **HITL Gate** is triggered exclusively by the **nature of the proposed action**:

```
Proposed next tool action
      │
      ├── Passive / Non-Invasive (fingerprinting, OSINT, public web crawling, reading static spec)
      │     └── Continue autonomously; no approval required.
      │
      └── Active / Invasive (sending injection payloads, fuzzing, OOB callbacks, exploit PoCs, credential sprays)
            └── HITL gate: PAUSE and request operator approval.
                  │
                  ├── Approved (/go [ID]) → validation agent proceeds with bounded token
                  └── Held (/hold [ID])   → record candidate finding; resume passive tasks
```

---

## 3. Confidence Calibration & Grounding Heuristic

Confidence measures certainty that the weakness is genuine and reproducible:

```
Step 1: Banner / Static Inference only (e.g., "Apache 2.4.49 detected", regex hit in decompiled APK)
  --> Base Confidence = 1 - 3 / 10 (Theoretical)

Step 2: Differential Behavioral Response observed (e.g., Syntax error on single quote, 500 error on payload, timing anomaly)
  --> Confidence upgraded to 4 - 6 / 10 (Likely)

Step 3: Deterministic Reflection, Math Evaluation, or Harmless Canary (e.g., {{7*7}} -> 49 in SSTI, boolean TRUE/FALSE confirmed, canary reflection)
  --> Confidence upgraded to 7 - 9 / 10 (Confirmed)

Step 4: Active Operator-Authorized PoC Execution (e.g., Benign proof demonstrated with cryptographic evidence hash)
  --> Confidence upgraded to 10 / 10 (Demonstrated)
```

---

## 4. Attack Chain Prioritization Formula

When multiple findings are discovered, compound attack chains are evaluated using the weighted formula:

$$\text{Chain Priority Score} = (\text{Max Severity} \times 0.6) + (\text{Min Confidence} \times 0.4) - (\text{Step Count} \times 0.2)$$

Chains are classified into operational tiers:
- **Tier 0 (Immediate Focus)**: External Recon $\to$ Public Exploitation $\to$ Initial Access / RCE.
- **Tier 1 (High Impact)**: Info Leak / SSRF $\to$ Cloud IMDS / IAM token $\to$ Infrastructure compromise.
- **Tier 2 (Domain Takeover)**: Low-priv domain user $\to$ ADCS ESC1 template / Kerberoasting $\to$ Domain Admin.
- **Tier 3 (Tactical)**: Multi-step logic chains requiring social engineering or complex user interaction.

---

## 5. Swarm Deconfliction & Resource Locking Heuristic

To prevent redundant scanning, network saturation, and lock contention:
1. **Target Port Locking**: Two subagents must never probe the same `IP:Port` simultaneously.
2. **Path & Endpoint Deduplication**: Discovered URLs/endpoints are registered centrally; scanner agents do not re-crawl endpoints marked in `engagement.crawled_endpoints[]`.
3. **Optimistic Finding Lock**: When a validation agent begins active verification on `NF-YYYY-NNNN`, it acquires an exclusive lock in `engagement.active_locks[]` to prevent race conditions.
4. **Target Domain Concurrency Ceiling**: Maximum 7 active scanner/validation tasks across any single domain.

---

## 6. Multi-Domain Tool Selection & Fallback Heuristic

```
IF Web Directory / Route Enumeration:
  --> Prefer FFUF (high-throughput) -> Fallback to Gobuster / Katana

IF SQL Injection Testing:
  --> Prefer Manual Boolean/Time/Error PoC -> Request HITL -> Fallback to SQLMap --batch

IF Active Directory Assessment:
  --> Prefer BloodHound-CE / Certipy -> Fallback to ldapsearch / NetExec

IF API Parameter Discovery:
  --> Prefer Arjun -> Fallback to ParamSpider / custom wordlist fuzzing

IF Cloud / Container Configuration Audit:
  --> Prefer Trivy / Prowler -> Fallback to ScoutSuite / manual AWS-CLI queries

IF Mobile APK / IPA Analysis:
  --> Prefer JADX / MobSF -> Dynamic instrumentation via Frida / Objection

IF Subnet Host Discovery (>= 256 IPs):
  --> Prefer Masscan / Rustscan -> Fallback to Nmap -sS -T3
```

---

## 7. Variant Hunting Heuristic

When an agent identifies a confirmed finding on one endpoint or parameter:
1. **Extract Root Flaw Signature**: Identify the underlying code pattern (e.g., unsanitized `id` query parameter, custom XML parser without entity resolution, missing `@PreAuthorize` annotation).
2. **Map Sister Surfaces**: Query discovered endpoints and route specs for parameters sharing the same naming convention or data types (`user_id`, `doc_id`, `account_id`).
3. **Targeted Hypothesis Fuzzing**: Automatically generate targeted candidate findings across all identified sister endpoints before escalating to validation.

---

## 8. Crash-to-Exploitability & Native Feasibility Triage

When analyzing native services, binaries, or C/C++ extensions:
1. **Fault Isolation**: Identify register state, faulting instruction address, and signal (`SIGSEGV`, `SIGBUS`, `SIGABRT`).
2. **Feasibility Profiling**:
   - Write-what-where / arbitrary pointer overwrite $\to$ **High Feasibility** (Severity 8–10).
   - Controllable instruction pointer (`RIP`/`PC`) control $\to$ **High Feasibility** (Severity 9–10).
   - Uncontrollable null-pointer dereference $\to$ **Denial of Service only** (Severity 3–5).
3. **Non-Destructive Constraint**: Never construct weaponized shellcode. Conclude analysis with proof of register/memory control under benign inputs.

---

## 9. Patch & Commit Diff Analysis Heuristic

When auditing open-source components or target fixes:
1. **Locate Security Fix Commit**: Compare the vulnerability advisory against git commit logs.
2. **Inspect Diff Boundaries**:
   - Check if the fix sanitizes only the reported payload vector (e.g., blacklisting `<script>` instead of context-aware escaping).
   - Check if adjacent endpoints, alternative encodings (URL, Unicode, double-URL), or alternate HTTP verbs (`POST` vs `GET`) bypass the patch.
3. **Regression Test Verification**: Verify whether a regression test suite exists and whether the fix introduces side-channel timing differences.
