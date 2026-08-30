# 🧭 HERMES Decision Heuristics & Triage Logic

This document specifies the internal decision-making heuristics used by HERMES to prioritize attack vectors, score findings, resolve conflicts, and guide subagents.

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

ELSE (Missing security headers, banner disclosure, best practices):
  --> Severity = 1 - 2 (Informational)
```

---

## 2. Confidence Calibration & Upgrading Heuristic

Confidence represents the certainty that the flaw is real and reproducible:

```
Step 1: Banner / Version Inference only (e.g. "Apache 2.4.49 detected")
  --> Base Confidence = 2/10 (Theoretical)

Step 2: Differential Response observed (e.g. Syntax error on single quote, 500 error on payload)
  --> Confidence upgraded to 5/10 (Probable)

Step 3: Deterministic Reflection or Math Evaluation (e.g. 7*7=49 reflected in SSTI, boolean TRUE/FALSE behavior confirmed)
  --> Confidence upgraded to 8/10 (Verified)

Step 4: Active Operator-Authorized PoC Execution (e.g. Proof of access demonstrated with evidence hash)
  --> Confidence upgraded to 10/10 (Demonstrated / Exploited)
```

---

## 3. Attack Chain Prioritization Heuristic

When multiple vulnerabilities are identified, HUNTER prioritizes compound kill chains using the formula:

$$\text{Chain Priority Score} = \text{Max Severity} \times 0.6 + \text{Min Confidence} \times 0.4 - (\text{Step Count} \times 0.2)$$

### Priority Tiers:
- **P0 (Immediate Focus)**: Chains leading directly to Initial Access / RCE from unauthenticated recon.
- **P1 (High Impact)**: Chains combining Information Leak + BOLA/IDOR to access privileged API routes.
- **P2 (Tactical)**: Chains requiring social engineering or complex user interaction.

---

## 4. Swarm Deconfliction & Resource Locking Heuristic

To prevent redundant scanning and conflicting network requests:
1. **Target Port Locking**: Two subagents must never scan the same IP:Port simultaneously.
2. **Path Deduplication**: If `SCANNER-WEBAPP` discovers `/api/v1/users`, it registers the route in `MEMORY.md` so `SCANNER-API` does not re-crawl the same static assets.
3. **Optimistic Locking**: Findings are registered with unique IDs (`HERMES-001`, `HERMES-002`) and locked during active exploitation.

---

## 5. Tool Selection & Fallback Heuristic

```
IF target is high-speed subnet (>= 256 IPs):
  --> Prefer Masscan / Rustscan -> Fallback to Nmap -sS -T4

IF fuzzing web directories:
  --> Prefer FFUF (high-throughput) -> Fallback to Gobuster / Katana crawler

IF testing SQL Injection:
  --> Prefer Manual Boolean/Time PoC -> Request /go -> Fallback to SQLMap --batch
```
