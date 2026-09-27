# NIGHTFANG Standard Operating Procedures (SOPs)

Operational runbooks and standards governing all NIGHTFANG agents, workflows, and operators during engagements.

---

## SOP-01: Scope Verification & Boundary Enforcement
**Objective:** Guarantee zero out-of-scope network traffic.
1. **Intake Validation**: Parse incoming IP subnets, CIDRs, domains, and wildcard records. Validate against scope boundaries before any network request.
2. **DNS Resolution Check**: For wildcard domains (`*.example.com`), verify that resolved IP addresses belong to authorized ASNs or IP blocks.
3. **Third-Party CDN / Multi-Tenant Cloud Guardrail**: If an endpoint resolves to a shared cloud provider (e.g., AWS S3, Cloudflare, Azure Front Door), verify that testing only probes the customer-owned resource/tenant, never the underlying shared cloud infrastructure.
4. **Violation Response**: If any tool attempts to target an out-of-scope host, immediately abort the command, record the incident in the engagement log, and notify the operator.

---

## SOP-02: Rate Limiting & Stealth Management
**Objective:** Prevent denial of service or unintended service degradation.
1. **Rate Hierarchy**:
   - **Operator-defined rate** (from engagement configuration): takes precedence always.
   - **Safe default** (if no operator rate is specified): `20 req/sec` for unknown targets; `100 req/sec` is a permissible ceiling, not a universal starting point.
   - **Target-specific adjustment**: lower rate if target exhibits latency sensitivity, WAF presence, or behavioral rate-limiting signals before hitting 429/503.
   - **Automatic backoff**: if target returns HTTP `429 Too Many Requests` or `503 Service Unavailable`, immediately pause all agents for 30 seconds, then halve the current rate. Log the event to the engagement memory log.
2. **Concurrency Controls**: Maximum concurrent active scanner agents running simultaneously against a single target domain is capped at 7.

---

## SOP-03: False Positive Elimination & Dual Scoring
**Objective:** Deliver 100% verified, actionable findings.
1. **Rule of Dual Verification**: A vulnerability banner inference (Confidence 1–3) cannot be escalated to Confirmed (Confidence 7+) without active payload or timing verification.
2. **Re-Test Requirement**: Every injection candidate (SQLi, XSS, SSRF, SSTI) must be tested across 2 separate HTTP request attempts with parameter variations to eliminate dynamic false alarms.
3. **Confidence Scoring Breakdown**:
   - `1–3`: Theoretical / Version banner only.
   - `4–6`: Probable anomaly (timing difference, non-standard error response, reflection).
   - `7–9`: Verified vulnerability (PoC payload returns expected reflection, schema info, or math evaluation).
   - `10`: Fully exploited with demonstrated access under operator approval.

---

## SOP-04: Human-in-the-Loop (HITL) Exploitation Gate
**Objective:** Complete operator governance prior to any active, invasive action.
1. **Gate Trigger**: The HITL gate is triggered by the **nature of the proposed next action**, not by severity score alone.
   - **Passive / non-invasive work** (fingerprinting, OSINT, reading public data): may continue autonomously.
   - **Active validation** (sending payloads, executing PoCs, triggering out-of-band callbacks, interacting with internal infrastructure): **requires explicit operator approval** before proceeding.
   - Severity score influences **priority and urgency** of the approval request, but does not itself authorize or block execution.
2. **Approval Request**: Nightfang raises a structured request via the operator interface specifying: finding ID, target, proposed action, technique, potential impact, and whether the action is reversible.
3. **Approval Token Scope**: A `/go [ID]` approval is a bounded authorization, not a generic pass. It is scoped to all five dimensions simultaneously:
   - **Engagement ID**: Valid only within the active engagement session
   - **Operator identity**: Only the operator who initiated the engagement may approve
   - **Finding ID**: Authorizes the validation action for that specific finding only
   - **Proposed action**: The exact technique and target endpoint stated in the HITL request. A different technique or endpoint requires a new HITL request
   - **Expiration**: Approval expires if not acted upon within the operator-configured timeout. An expired approval must be re-requested; it cannot be reused
4. **Execution Block**: The `validation` agent remains in a paused state until a valid, unexpired `/go [ID]` is received.
5. **Timeout Handling**: If operator does not respond within the defined window, the action is queued and the swarm continues non-intrusive scanning tasks only.

---

## SOP-05: Proof-of-Concept Safety & Artifact Cleanup
**Objective:** Leave zero permanent state changes or damage on target systems.
1. **Benign PoC Execution**:
   - **RCE**: Execute non-destructive commands (e.g., `id`, `whoami`, `hostname`).
   - **SQLi**: Retrieve database version or user (e.g., `SELECT version()`) rather than dumping tables.
   - **File Upload**: Upload inert files containing a timestamped canary identifier.
   - **Strict Prohibitions**: Zero tolerance for DoS, table drops, ransomware, or persistent backdoor installation.
2. **Mandatory Cleanup**:
   - Immediately delete any dropped test files or uploaded canaries.
   - Re-request the upload path to verify HTTP 404 response.
   - Record cleanup verification timestamp in the engagement log.

---

## SOP-06: Evidence Hashing & Chain of Custody
**Objective:** Cryptographic integrity for all security findings.
1. **Raw Stream Capture**: All command outputs and HTTP request/response pairs must be captured raw without sanitization or truncation.
2. **Cryptographic Hashing**: Compute SHA-256 hashes for all captured evidence files, payloads, and screenshots.
3. **Storage Standard**: Store evidence organized by finding ID in the engagement evidence directory.

---

## SOP-07: Emergency Stop Protocol (`/stop`)
**Objective:** Immediate shutdown of all active testing in case of critical operational incidents.
1. **Trigger**: Operator sends `/stop` or `HALT` via the operator interface.
2. **Swarm Action**:
   - Broadcast immediate kill signal to all active agents.
   - Terminate all running subagent processes and background network tasks.
   - Persist current session state to the engagement log.
   - Confirm shutdown status to operator.
