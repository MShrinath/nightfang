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

---

## 10. PriorityDAG Lead Queue & Autonomous Task Dispatch Heuristic

The autonomous engine organizes pending tasks using a Directed Acyclic Graph (DAG) with priority min-heap semantics:
1. **Priority Hierarchy**:
   - `CRITICAL (Priority 0)`: Verified candidate exploit PoCs, out-of-band callback handling, immediate RCE / SQLi verification.
   - `HIGH (Priority 1)`: Newly uncovered subdomains, exposed admin consoles, active route and port discovery.
   - `MEDIUM (Priority 2)`: Parameter fuzzing, variant analysis hypothesis testing, API schema traversal.
   - `LOW (Priority 3)`: Comprehensive directory brute-forcing, passive OSINT aggregation, WHOIS enrichment.
   - `INFORMATIONAL (Priority 4)`: Background documentation generation, header baseline checks.
2. **Dependency & Cycle Invariants**:
   - A downstream verification task cannot execute until its prerequisite fingerprinting task completes successfully (`depends_on: [task_id]`).
   - If a prerequisite fails, downstream dependent tasks are automatically cancelled with rationale recorded in engagement memory.
3. **State Machine Transitions**:
   - `PENDING` $\to$ `RUNNING` $\to$ `COMPLETED` | `FAILED` | `PAUSED_FOR_APPROVAL`
   - Paused tasks do not block the min-heap pop of independent sibling tasks.

---

## 11. Recursive Lead Generation & Attack Surface Expansion Heuristic

Autonomous security assessment requires continuous surface discovery without manual intervention:
1. **Domain & Subdomain Ingestion**: Every stdout/stderr stream from recon and scanning tools is regex-analyzed for newly disclosed hostnames. Discovered hostnames matching `engagement.scope.domains` are automatically enqueued for service and port discovery.
2. **Endpoint & Route Ingestion**: Discovered HTTP URLs, API routes (REST/GraphQL/gRPC endpoints), and form action targets are immediately extracted, deduplicated against `engagement.crawled_endpoints[]`, and enqueued for parameter fuzzing (`variant_hunt.py`).
3. **Technology-Triggered Specialization**:
   - Web server exposes WordPress / Drupal $\to$ dynamically enqueues CMS plugin vulnerability check.
   - Endpoint returns GraphQL schema $\to$ dynamically enqueues introspective field traversal.
   - Host exposes SMB port 445 / RPC $\to$ dynamically enqueues `ad-attacker` Kerberos / null session check.
   - Cloud metadata reflection observed (IMDS `169.254.169.254`) $\to$ dynamically enqueues `cloud-security` token extraction task.

---

## 12. Self-Healing Reflection & Rate Backoff Heuristic

When active tools encounter infrastructure defense triggers, the engine adapts dynamically rather than failing:
1. **Status Code Reflection**:
   - HTTP `429 Too Many Requests` or `503 Service Unavailable` triggers SOP-02 backoff: pauses target operations for 30s, halves target rate ceiling, and re-enqueues failed tasks with exponential backoff (up to 2 retries).
   - HTTP `403 Forbidden` / Cloudflare WAF challenge on a specific path triggers OPSEC noise downgrade (`LOUD` $\to$ `MODERATE` or `QUIET`), injects header variations (e.g. `X-Forwarded-For: 127.0.0.1`), and schedules variant route probing.
2. **Socket Timeout & Connection Reset**:
   - 3 consecutive connection timeouts on a port triggers temporary port deactivation and marks the target service as latency-sensitive, reducing concurrency to 1.

---

## 13. Native Operational Skill Lenses & Autonomous Decision Procedures

NIGHTFANG incorporates a 15-capability cognitive skill matrix categorized into 5 native operational modes. These are not merely secondary fallbacks; they are native operational lenses embedded into the swarm's cognitive execution loop:

### Lens 1: Frontline Sensory & Web Perception
1. **Agent-Reach (Zero-Fee Multi-Platform OSINT)**:
   - *Trigger*: Passive reconnaissance, threat actor attribution, developer leak discovery, or recent CVE exploit chatter.
   - *Autonomous Action*: Execute zero-fee queries across X, Reddit, GitHub, and YouTube transcripts before querying paid threat intelligence APIs. Cross-reference uncovered developer usernames with commit logs.
2. **defuddle (Token-Efficient DOM Extractor)**:
   - *Trigger*: Target web endpoints return HTML responses $> 4\text{ KB}$ during crawling, scraping, or documentation inspection.
   - *Autonomous Action*: Pipe raw HTML through `defuddle` to extract clean, semantic Markdown. Strips boilerplate scripts, style tags, and navigation headers, reducing LLM context window consumption by up to 80%.
3. **youtube-skills (Video Intel & Transcript Mining)**:
   - *Trigger*: Recon uncovers conference talks, engineering demos, or recorded webinars related to target organization systems.
   - *Autonomous Action*: Ingest video transcripts, index chapters, and query spoken technical terms for architectural disclosures, internal hostnames, or unreleased API endpoints.
4. **browser-harness (Live Authenticated Browser Automation)**:
   - *Trigger*: Modern Single-Page Applications (React, Vue, Angular) requiring complex DOM hydration, canvas interactions, or multi-step SSO/MFA flows where headless HTTP tools (`curl`, `ffuf`) fail to parse state.
   - *Autonomous Action*: Spawn live instrumented Chrome session via `browser-harness` to interact with dynamic JavaScript components, capture DOM mutations, and evaluate client-side token storage.

### Lens 2: Engineering Rigor & Codebase Knowledge
1. **addyosmani agent-skills (Production Engineering Lifecycle)**:
   - *Trigger*: Initiating new security assessments, developing custom exploits, or crafting hardening guidance.
   - *Autonomous Action*: Enforce structured lifecycle progression: `/spec` (scope & threat boundaries) $\to$ `/plan` (subtask DAG) $\to$ `/build` (probe implementation) $\to$ `/test` (canary verification) $\to$ `/review` (7-question adversarial gate) $\to$ `/ship` (report generation).
2. **mattpocock skills (Verification & Engineering Discipline)**:
   - *Trigger*: Custom exploit PoC authoring, validation script synthesis, or defensive patch verification.
   - *Autonomous Action*: Enforce `/grill-with-docs` (verify against target protocol RFCs), `/tdd` (write automated canary assertions before exploit execution), and `/implement` (clean, non-destructive execution).
3. **codebase-memory-mcp (Persistent AST Semantic Knowledge Graph)**:
   - *Trigger*: Static Application Security Testing (SAST), white-box source code audits, or complex git diff reviews.
   - *Autonomous Action*: Build and query a persistent Abstract Syntax Tree (AST) graph of the target codebase. Trace cross-file data flows from untrusted inputs (`sources`) to sensitive sinks (`sinks`), replacing fragile flat regex scanning.

### Lens 3: Orchestration, Supervision & System Evolution
1. **minions (Mission Control Visual HUD & Supervision)**:
   - *Trigger*: Active multi-agent pentest engagements requiring continuous operational oversight.
   - *Autonomous Action*: Maintain real-time HUD telemetry: stream active agent states, DAG task completion, rate limits, and pending HITL approval items to the operator's mission control dashboard.
2. **oh-my-hermes (Multi-Agent Coworker Lanes & Model Routing)**:
   - *Trigger*: Parallel subtask execution requiring specialized model characteristics.
   - *Autonomous Action*: Route analytical reasoning tasks (taint analysis, exploit math) to high-reasoning models; route high-throughput tasks (log filtering, regex matching) to low-latency models across isolated coworker lanes.
3. **loopy (Stateful Exploration & Feedback Loops)**:
   - *Trigger*: Multi-step stateful business logic testing (e.g. e-commerce checkout, privilege grant flows, state machine bypasses).
   - *Autonomous Action*: Execute recursive exploration loops with stateful feedback memory, adjusting payload permutations dynamically based on previous step HTTP response changes without resetting session cookies.
4. **SkillClaw (Continuous Post-Session Skill Evolution)**:
   - *Trigger*: Successful vulnerability validation, unexpected WAF bypass, or novel defense circumvention.
   - *Autonomous Action*: Analyze the successful execution trajectory, extract reusable procedural heuristics, and persist evolved sub-playbooks for future swarm engagements.

### Lens 4: Presentation Craft & Workspace Integration
1. **humanizer (De-AI Tone & Authenticity Filter)**:
   - *Trigger*: Compiling executive summaries, technical walkthroughs, or operator chat notifications.
   - *Autonomous Action*: Strip robotic markers, passive voice, sycophancy, and boilerplate corporate buzzwords. Ensure communication is terse, objective, authoritative, and direct.
2. **make-interfaces-feel-better (Visual Ergonomics & Optical Alignment)**:
   - *Trigger*: Markdown table generation, terminal dashboard output, and finding card formatting.
   - *Autonomous Action*: Align columns optically, apply clean typographic hierarchy, and format status indicators (`[+]`, `[-]`, `[!]`) for frictionless operator scanning.
3. **OpenMontage (Agentic Video PoC Studio)**:
   - *Trigger*: Critical or High vulnerability demonstrations requiring visual executive deliverable.
   - *Autonomous Action*: Synthesize a concise, visual PoC video artifact combining screen capture timelines, attack graph transitions, and technical callouts.

### Lens 5: Low-Level & Specialized Execution Playbooks
1. **Low-Level & Specialized Playbooks**:
   - *Trigger*: Encountering low-level hardware, firmware, TPM 2.0, post-quantum crypto, or critical infrastructure systems.
   - *Autonomous Action*: Dynamically reference [`references/low_level_playbooks.md`](low_level_playbooks.md) to retrieve specialized execution commands and verification methodologies.
