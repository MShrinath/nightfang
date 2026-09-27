# NIGHTFANG Decision Heuristics & Triage Logic

Internal decision-making heuristics used by NIGHTFANG to prioritize attack vectors, score findings, deconflict swarm agents, and guide tool selection.

---

## 1. Finding Severity Calculation Heuristic

Severity is scored from **1 (Informational)** to **10 (Critical)** using the following decision matrix:

```
IF unauthenticated RCE OR full database compromise OR full cloud admin takeover:
  --> Severity = 9 - 10 (Critical)

ELSE IF authenticated RCE OR high-privilege BOLA/IDOR OR mass credential leakage OR direct SQLi:
  --> Severity = 7 - 8 (High)

ELSE IF stored XSS OR standard IDOR (limited PII) OR CSRF on state-changing actions OR SSRF (internal only):
  --> Severity = 5 - 6 (Medium)

ELSE IF reflected XSS OR missing rate-limiting OR verbose stack trace with path disclosure OR TLS 1.0/1.1:
  --> Severity = 3 - 4 (Low)

ELSE (Missing security headers, banner disclosure, informational items):
  --> Severity = 1 - 2 (Informational)
```

> **Scoring Separation Notice**  
> NIGHTFANG uses **three distinct scoring systems** that must never be conflated:
> - **Nightfang Severity (1–10)**: NIGHTFANG's assessment of the potential impact of a finding, based on the decision matrix above. Ordinal, opinionated, fast to assign.
> - **Nightfang Confidence (1–10)**: NIGHTFANG's certainty that the vulnerability is real and reproducible. Independent of severity.
> - **CVSS v3.1 Base Score (0.0–10.0)**: Industry-standard metric computed from the CVSS vector string (AV, AC, PR, UI, S, C, I, A). Calculated after validation, not assigned as a shorthand for Nightfang Severity.
>
> A finding with `Nightfang Severity = 8` does not imply `CVSS = 8.0`. Both must be recorded independently per [`schemas/finding.md`](../schemas/finding.md).

---

## 1b. HITL Action Classification Heuristic

Severity drives **priority** (how urgently the operator is notified). The **gate** is determined by the nature of the proposed action:

```
Proposed next action
      │
      ├── Passive / non-invasive (reading, fingerprinting, OSINT)
      │     └── Continue autonomously; no approval required.
      │
      └── Active / invasive (payloads, callbacks, interactive probing, PoCs)
            └── HITL gate: PAUSE and request operator approval.
                  │
                  ├── Approved (/go [ID]) → validation agent proceeds
                  └── Held (/hold [ID])   → record candidate finding, continue passive work
```

Severity score is passed to the operator in the approval request to indicate urgency, but it is not the condition that determines whether the gate fires.

## 2. Confidence Calibration & Upgrading Heuristic

Confidence represents certainty that the vulnerability is real and reproducible:

```
Step 1: Banner / Version Inference only (e.g., "Apache 2.4.49 detected")
  --> Base Confidence = 1 - 3 / 10 (Theoretical)

Step 2: Differential Response observed (e.g., Syntax error on single quote, 500 error on payload)
  --> Confidence upgraded to 4 - 6 / 10 (Likely)

Step 3: Deterministic Reflection or Math Evaluation (e.g., 7*7=49 reflected in SSTI, boolean TRUE/FALSE confirmed)
  --> Confidence upgraded to 7 - 9 / 10 (Confirmed)

Step 4: Active Operator-Authorized PoC Execution (e.g., Proof of access demonstrated with evidence hash)
  --> Confidence upgraded to 10 / 10 (Demonstrated / Exploited)
```

---

## 3. Attack Chain Prioritization Formula

When multiple vulnerabilities are identified, compound kill chains are prioritized using the weighted formula:

$$\text{Chain Priority Score} = (\text{Max Severity} \times 0.6) + (\text{Min Confidence} \times 0.4) - (\text{Step Count} \times 0.2)$$

### Priority Tiers:
- **P0 (Immediate Focus)**: Chains leading directly to Initial Access / RCE from unauthenticated recon.
- **P1 (High Impact)**: Chains combining Information Leak + BOLA/IDOR to access privileged API routes.
- **P2 (Tactical)**: Chains requiring complex user interaction or specific preconditions.

---

## 4. Swarm Deconfliction & Resource Locking Heuristic

To prevent redundant scanning and conflicting network requests:
1. **Target Port Locking**: Two subagents must never probe the same IP:Port simultaneously.
2. **Path Deduplication**: Discovered endpoints are registered centrally so scanner agents do not re-crawl the same static assets.
3. **Optimistic Locking**: Findings are registered with unique IDs (`NF-YYYY-NNN`) and locked during active validation to prevent duplicate exploit attempts.

---

## 5. Tool Selection & Fallback Heuristic

```
IF target is high-speed subnet (>= 256 IPs):
  --> Prefer Masscan / Rustscan -> Fallback to Nmap -sS -T4

IF fuzzing web directories:
  --> Prefer FFUF (high-throughput) -> Fallback to Gobuster / Katana crawler

IF testing SQL Injection:
  --> Prefer Manual Boolean/Time PoC -> Request HITL approval -> Fallback to SQLMap --batch

IF discovering hidden API parameters:
  --> Prefer Arjun -> Fallback to ParamSpider / custom wordlist fuzzing
```
