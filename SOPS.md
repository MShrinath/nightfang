# 📜 OPENCLAW / HERMES — Standard Operating Procedures (SOPs)

This document specifies the operational runbooks and standard operating procedures that all swarm agents and operators must adhere to during engagements.

---

## SOP-01: Scope Verification & Boundary Enforcement
**Objective:** Guarantee zero out-of-scope traffic.
1. **Intake Validation**: Parse incoming IP subnets, domains, and wildcard records through `scripts/scope_validator.py`.
2. **DNS Resolution Check**: For wildcard domains (`*.example.com`), verify that resolved IP addresses belong to authorized ASNs or IP blocks.
3. **Third-Party CDN / SaaS Guardrail**: If an endpoint resolves to a multi-tenant cloud provider (e.g. AWS S3, Cloudflare, Azure Front Door), verify that testing only targets the specific customer bucket/tenant, never the shared underlying infrastructure.
4. **Violation Response**: If any tool attempts to query an out-of-scope host, immediately abort the command, log to `engagements/scope_violations.log`, and alert the operator.

---

## SOP-02: Rate Limiting & Stealth Management
**Objective:** Prevent denial of service or unintended service degradation.
1. **Baseline Speed**: Default active scanning rate is capped at `100 req/sec` unless specified otherwise in `engagement_template.yaml`.
2. **429 / 503 Detection**: If target responds with HTTP `429 Too Many Requests` or `503 Service Unavailable`:
   - Immediately pause requests from all agents for 30 seconds.
   - Reduce request rate by 50% (e.g., from 100 to 50 req/sec).
   - Log the rate-limiting signature to `MEMORY.md`.
3. **Concurrency Controls**: Maximum concurrent active scanner agents running simultaneously is capped at 7.

---

## SOP-03: False Positive Elimination & Dual Scoring
**Objective:** Deliver 100% verified, actionable findings.
1. **Rule of Dual Verification**: A vulnerability banner inference (Confidence 1–3) cannot be escalated to Confirmed (Confidence 7+) without active payload or timing verification.
2. **Re-Test Requirement**: Every injection finding (SQLi, XSS, SSRF) must be re-tested across 2 separate HTTP request attempts with varying parameter variations to eliminate dynamic false alarms.
3. **Confidence Scoring Breakdown**:
   - `1-3`: Theoretical / Version banner only.
   - `4-6`: Probable anomaly (e.g., timing difference, non-standard error response).
   - `7-9`: Verified vulnerability (e.g., PoC payload returns expected reflection, schema info, or math evaluation).
   - `10`: Fully exploited with demonstrated access under operator `/go`.

---

## SOP-04: Human-in-the-Loop (HITL) Exploitation Gate
**Objective:** Ensure complete operator governance prior to active exploitation.
1. **Identification**: Scanner agent flags candidate vulnerability with Severity >= 5.
2. **Telegram Alert Dispatch**: HERMES sends structured alert with finding ID, target, proposed action, risk level, and `/go` or `/hold` prompt.
3. **Execution Block**: The `EXPLOITER` subagent remains in a paused state until operator replies `/go [ID]`.
4. **Timeout Handling**: If operator does not respond within 60 minutes, the action is queued, and the swarm continues other non-intrusive scanning tasks.

---

## SOP-05: Proof-of-Concept Safety & Artifact Cleanup
**Objective:** Leave zero permanent changes on target systems.
1. **Benign PoC Execution**:
   - For RCE: Execute non-destructive commands (e.g., `id`, `whoami`, `hostname`).
   - For SQLi: Retrieve schema version (e.g., `SELECT version()`) rather than dumping user tables.
   - For File Upload: Upload inert files containing a timestamp identifier.
2. **Mandatory Cleanup**:
   - Immediately delete any dropped test files or webshells.
   - Re-request the upload path to verify HTTP 404.
   - Log cleanup verification timestamp in `MEMORY.md`.

---

## SOP-06: Evidence Hashing & Chain of Custody
**Objective:** Cryptographic integrity for all pentest evidence.
1. **Capture Raw Streams**: All command outputs and HTTP request/response pairs must be captured raw without manual edits.
2. **Cryptographic Hashing**: Compute SHA-256 hash for all captured evidence files and screenshots.
3. **Storage Location**: Save raw evidence into `engagements/<ENGAGEMENT_ID>/evidence/`.

---

## SOP-07: Emergency Stop Protocol (`/stop`)
**Objective:** Immediate shutdown of all active testing in case of critical incidents.
1. **Trigger**: Operator sends `/stop` via Telegram or CLI.
2. **Swarm Action**:
   - HERMES broadcasts immediate kill signal to all active subagents (`RECON-ACTIVE`, `SCANNER-WEBAPP`, `EXPLOITER`, etc.).
   - All background subprocesses (`nmap`, `ffuf`, `sqlmap`) are terminated.
   - Current session state is persisted to `MEMORY.md`.
   - HERMES confirms shutdown to operator on Telegram.
