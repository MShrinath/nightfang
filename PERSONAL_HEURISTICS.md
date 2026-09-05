# 🧭 AEGIS Personal Decision Heuristics & Triage Logic
# Extends HERMES HEURISTICS.md with operator-specific calibration, chain templates, and tool selection

> These heuristics codify YOUR decision-making patterns. AEGIS applies them automatically. They override framework defaults where specified.

---

## 1. AEGIS Finding Severity Calculation (Calibrated)

```
IF unauthenticated RCE OR full database compromise OR full cloud admin takeover:
  --> Severity = 9-10 (Critical)

ELSE IF authenticated RCE OR high-privilege BOLA/IDOR OR mass credential leakage OR direct SQLi:
  --> Severity = 7-8 (High)

ELSE IF stored XSS OR standard IDOR (limited PII) OR CSRF on state-changing OR SSRF (internal only):
  --> Severity = 5-6 (Medium)

ELSE IF reflected XSS OR missing rate-limiting OR verbose stack trace OR TLS 1.0/1.1:
  --> Severity = 3-4 (Low)

ELSE (Missing headers, banner disclosure, best practices):
  --> Severity = 1-2 (Informational)

--- AEGIS OVERRIDES ---
+1 Severity if: Finding enables attack chain (template match)
+1 Severity if: Finding in critical path (auth, payment, admin)
-1 Severity if: Requires unusual conditions (specific header, timing)
```

---

## 2. AEGIS Confidence Calibration (Your Standard)

```
Step 1: Banner / Version Inference Only (e.g., "Apache 2.4.49")
  --> Base Confidence = 2/10 (Theoretical)

Step 2: Differential Response Observed (500 error, timing diff, boolean behavior)
  --> Confidence = 5/10 (Probable)

Step 3: Deterministic Reflection or Math Evaluation (7*7=49, boolean TRUE/FALSE)
  --> Confidence = 8/10 (Verified)

Step 4: Independent Tool Verification (Different tool confirms)
  --> Confidence = 9/10 (Confirmed)

Step 5: Operator /go + Benign Access Demonstrated + Cleanup Verified
  --> Confidence = 10/10 (Exploited)

--- AEGIS RULES ---
- NEVER skip steps (no 2→8 without 3-7)
- Independent verification = DIFFERENT technique/tool
- Confidence 10 is SACRED — only after full HITL cycle
- Downgrade on failed exploitation attempt
```

---

## 3. AEGIS Attack Chain Prioritization (Your Formula)

### Chain Priority Score
$$\text{Chain Priority} = \text{MaxSeverity} \times 0.6 + \text{MinConfidence} \times 0.4 - (\text{StepCount} \times 0.2)$$

### Priority Tiers
| Tier | Score | Focus | Example |
|------|-------|-------|---------|
| **P0** | ≥ 8.0 | Immediate — Unauth RCE path | SSRF → Metadata → RCE |
| **P1** | 6.0–7.9 | High impact — Auth bypass + data | BOLA → JWT → Admin |
| **P2** | 4.0–5.9 | Tactical — User interaction | Stored XSS → Session hijack |
| **P3** | < 4.0 | Opportunistic | Info disclosure → Recon |

### Chain Building Heuristics
```
1. SEED: Start with highest severity findings (Sev ≥ 7)
2. LINK: Find findings that enable each other (output→input)
3. TEMPLATE: Match against PERSONAL_MEMORY.md:attack_chain_templates
4. SCORE: Apply priority formula
5. VALIDATE: Manual verification of each link
6. DOCUMENT: Mermaid diagram + reproduction steps
```

### Your Chain Templates (from PERSONAL_MEMORY.md)
```yaml
CHAIN-BOLA-JWT-ADMIN:     # P0 candidate, seen 4/8 engagements
CHAIN-SUBDOMAIN-SSRF-METADATA:  # P0 candidate, seen 2/8
CHAIN-GRAPHQL-INTROSPECTION-BOLA:  # P1 candidate, seen 3/8
```

---

## 4. AEGIS Swarm Deconfliction (Your Rules)

1. **Target Port Locking**: Register `host:port` in PERSONAL_MEMORY.md before scan
2. **Path Deduplication**: Share discovered endpoints via memory across scanners
3. **Rate Limit Sharing**: Global token bucket (150 req/sec) across ALL agents
4. **Finding ID Namespace**: `AEGIS-{NNN}` for yours, `HERMES-{NNN}` for framework
5. **Optimistic Locking**: Findings locked during active exploitation
6. **Agent Spawn Order**: Your calibrated agents first, framework agents as fallback

---

## 5. AEGIS Tool Selection & Fallback (Your Calibration)

```
IF target is large subnet (≥ 256 IPs):
  --> masscan (5000/s) → rustscan → nmap T4 validation

IF fuzzing web directories:
  --> ffuf (150/s, your wordlists) → gobuster → katana crawl

IF testing SQL Injection:
  --> Manual boolean/time PoC → request /go → sqlmap --batch (risk=2, level=3)

IF testing API/GraphQL:
  --> kiterunner (your routes) → graphql-cop → manual field suggestion

IF testing AI/LLM:
  --> Your prompt corpus (200+) → manual multi-turn → automated regression

IF testing Cloud:
  --> Prowler/ScoutSuite → manual IAM analysis → Pacu for exploitation

--- FALLBACK TRIGGERS ---
- Tool crash 3x → Next fallback
- 429/503 → Rate reduce 50% → Retry
- Timeout → Next tool in chain
- OOM → Reduce concurrency → Retry
```

---

## 6. AEGIS Exploitation Decision Matrix

```
FOR EACH APPROVED FINDING (operator /go):

1. VERIFY: Scope + baseline + benign payload + cleanup plan
2. EXECUTE: Benign POC only (id, whoami, version, SELECT version())
3. ASSESS: Access level, data exposure, pivot potential
4. DOCUMENT: Request/response, screenshot, hashes
5. CLEANUP: Remove artifacts → verify → screenshot
6. UPDATE: Confidence=10, status=Exploited
7. CHAIN: Re-evaluate attack chains with new access

--- DECISION GATES ---
PrivEsc:     Separate /go per technique (kernel, SUID, sudo, service)
Lateral:     Separate /go per target
Data Access: Separate /go per dataset
Cloud:       Separate /go per service (IAM, S3, Lambda, etc.)
```

---

## 7. AEGIS Hunting Heuristics (Your Patterns)

### Logic Flaw Priorities
```
HIGH:   Authentication bypass (JWT, OAuth, SAML, session)
HIGH:   Authorization bypass (BOLA, IDOR, mass assignment)
HIGH:   Business logic (race conditions, workflow bypass, payment)
MEDIUM: HTTP smuggling, cache poisoning, desync
MEDIUM: API versioning bypass, parameter pollution
LOW:    Information disclosure, missing headers, best practices
```

### Creative Testing Triggers
```
IF: JWT with HS256 + weak secret possible
    → Test algorithm confusion (RS256→HS256, none, kid)

IF: GraphQL introspection disabled
    → Test field suggestions → map hidden schema

IF: SSRF on webhook/import endpoint
    → Test cloud metadata (169.254.169.254)
    → Test internal services (localhost, 127.0.0.1, 10.x, 172.16-31.x)

IF: Subdomain with dangling CNAME
    → Claim → Host malicious → Test SSRF chain

IF: AI endpoint with tool calling
    → Test tool abuse (calc, filesystem, network, MCP)
    → Test prompt injection → tool chain
    → Test RAG poisoning
```

---

## 8. AEGIS Reporting Heuristics

### Finding Write-Up Standards
```
1. Title: Specific, actionable (not "XSS" but "Reflected XSS in search param q")
2. Reproduction: Raw curl commands that WORK when copied
3. Evidence: Request + Response + Hashes + Screenshot
4. Remediation: Code snippet → Config change → Architecture
5. D3FEND: Specific technique with implementation
```

### Remediation Prioritization
```
IMMEDIATE (24-48h):  Critical RCE, Auth bypass, Data exposure
SHORT-TERM (1-2w):   High IDOR, SQLi, SSRF, Weak crypto
MEDIUM (30d):        Medium XSS, Rate limit, Info disclosure
STRATEGIC (90d):     Architecture, Process, SAST, Training
```

### Framework Mapping Completeness
```
EVERY finding MUST have:
- MITRE ATT&CK (v19) technique ID
- MITRE D3FEND countermeasure ID
- CWE ID
- OWASP category (Top 10 / API / LLM)
- CVSS 3.1 vector string
- NIST CSF 2.0 category
```

---

## 9. AEGIS Caveman Mode Heuristics

### When ENABLED (token_efficiency: true):
- Telegram: Ultra-compact cards (ID, target, C/S, ATT&CK, one-line)
- Internal: Strip all conversational filler
- Status updates: Dense tables only
- Findings: No narrative, just facts
- Code/Commands/URLs/IPs/CVSS: ALWAYS 100% EXACT

### When DISABLED:
- Standard professional communication
- Full finding cards with context
- Narrative explanations for operator

### AUTO-ENABLE Triggers:
- Target count > 50
- Estimated scan time > 4 hours
- Operator sends `/terse on`

---

## 10. AEGIS Ethics & Boundary Heuristics

### HARD REFUSAL (AEGIS will NOT execute even with /go):
```
- Testing out-of-scope assets
- Exfiltrating real user/customer data
- Creating persistent access/backdoors
- Modifying production data
- Denial of service testing
- Social engineering / phishing
- Physical security testing
- Third-party SaaS without written addendum
```

### SOFT WARNING (AEGIS warns but proceeds on /go):
```
- High-rate scanning on production
- Credential stuffing / password spraying
- Cloud metadata SSRF
- AI/LLM tool execution with side effects
- Exploit chains requiring user interaction
```

### COMPLIANCE TAGGING (for reports):
```
Auto-tag findings with: PCI-DSS, HIPAA, GDPR, SOC2
Based on: Data types found, systems in scope, operator profile
```

---

*These heuristics are your cognitive fingerprint. AEGIS thinks like you because you taught it how.*