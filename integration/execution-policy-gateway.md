# NIGHTFANG Execution Policy Gateway — Implementation Specification

Version: `1.0.0`  
This document is the executable specification for the **Execution Policy Gateway**. While the **Capability Router** handles dispatch (*which capability runs*), the Execution Policy Gateway handles runtime enforcement (*what network traffic and tool commands are permitted to run*). A host agent runtime (Hermes) implementing NIGHTFANG support must implement the gateway logic in this file exactly.

---

## 1. Overview & Architecture

The Execution Policy Gateway is the mandatory, fail-closed enforcement layer positioned directly between skill procedures and external tool execution (network I/O, binary execution, shell commands, and API requests).

No skill or agent may directly spawn network traffic or execute external binaries. Every tool execution request must pass through the 6-stage validation pipeline:

```
Skill / Agent Tool Invocation Request
               │
               ▼
┌──────────────────────────────────────────────┐
│       EXECUTION POLICY GATEWAY PIPELINE      │
│                                              │
│  [Stage 1] Scope & Boundary Enforcement     │  ← SOP-01 (CIDR, DNS, Cloud Tenant)
│                     │                        │
│  [Stage 2] Emergency Stop & Deconfliction   │  ← SOP-07, Heuristics §4 (Locking, Concurrency)
│                     │                        │
│  [Stage 3] Rate Limiting & Backoff Throttle  │  ← SOP-02 (Rate Hierarchy, 429/503 Auto-Backoff)
│                     │                        │
│  [Stage 4] Action Classification & HITL Gate │  ← SOP-04, Heuristics §1b (5-D Approval Token)
│                     │                        │
│  [Stage 5] Non-Destructive PoC Safety Filter │  ← SOP-05 (Benign Payloads, Canary Tracking)
│                     │                        │
│  [Stage 6] Evidence Hashing & Stream Wrapper │  ← SOP-06 (Raw Capture, SHA-256 Hashing)
└──────────────────────┬───────────────────────┘
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
[Approved / Passive]         [Active / Invasive]
         │                           │
         ▼                           ▼
 Tool Execution              Has Valid Token?
 (Rate Throttled)              /          \
                              /            \
                           YES              NO
                            │                │
                            ▼                ▼
                     Execute PoC       PAUSE Execution
                     & Track Canary    Emit HITL_REQUEST
                                       Await /go [ID]
```

---

## 2. Tool Invocation Request Contract

When an agent or skill requires external execution, it emits a `TOOL_INVOCATION_REQUEST` to the Gateway:

```yaml
tool_request:
  request_id: string          # Unique invocation UUID (e.g., "req-98f2b1a0")
  engagement_id: string       # Active engagement session ID
  agent_id: string            # Requesting agent: "recon" | "scanner" | "ai-security" | "validation" | "reporter"
  skill_id: string            # Source skill path (e.g., "skills/web/injection.md")
  tool_name: string           # Executable or library: "curl" | "nmap" | "ffuf" | "sqlmap" | "arjun" | etc.
  target:
    raw_target: string        # e.g., "https://target-app.internal/api/v1/user"
    hostname: string          # e.g., "target-app.internal"
    ip: string                # Resolved IPv4/IPv6 address (if resolved)
    port: integer             # Destination port (e.g., 443)
    scheme: string            # "http" | "https" | "tcp" | "udp"
  command_template: string    # Proposed CLI string or HTTP request specification
  action_type: string         # "PASSIVE_READ" | "ACTIVE_PROBE" | "EXPLOIT_POC"
  technique: string           # Technique identifier (e.g., "error-based-sqli-test", "banner-grab")
  payload: string             # Test payload or query argument (if applicable)
  canaries:                   # Canary identifiers requiring tracking (if file write/upload)
    - string
  finding_id: string          # Associated finding ID if validating a candidate (e.g., "NF-2026-0042")
  severity_hint: integer      # Finding severity (1-10) for prioritization / urgency context
```

---

## 3. The 6-Stage Gateway Pipeline

The Gateway evaluates the `tool_request` strictly sequentially. If any stage fails, evaluation halts immediately and the corresponding disposition is returned.

### Stage 1: Scope & Target Boundary Enforcement (SOP-01)

**Objective**: Guarantee zero out-of-scope network traffic.

1. **Target Parsing**: Extract destination IP, domain, and hostname from `target`.
2. **In-Scope Boundary Validation**:
   - Verify `target.hostname` against `engagement.scope.domains` (including authorized wildcards).
   - If `target.hostname` is a domain, perform DNS resolution:
     - Verify resolved IP address falls strictly inside authorized CIDR blocks (`engagement.scope.cidrs`).
     - If resolved IP does not belong to authorized subnets $\to$ **DENY**.
3. **Multi-Tenant Cloud Guardrail**:
   - If target resolves to shared cloud/CDN IP ranges (e.g., AWS S3, Cloudflare, Azure Front Door, Fastly):
     - Inspect request headers and destination path.
     - Prohibit probing shared management endpoints or tenant-adjacent resources.
     - Prohibit raw IP scans against shared edge clusters.
4. **Failure Outcome**:
   - If out-of-scope:
     ```
     GATEWAY_DISPOSITION: REJECTED
     CODE: SCOPE_VIOLATION
     REASON: Target <target> is outside engagement authorized scope.
     ```
   - Log incident immediately to `engagement.audit_log` per SOP-01. Network execution is blocked.

---

### Stage 2: Emergency Stop & Concurrency Locking (SOP-07, Heuristics §4)

**Objective**: Ensure instant kill-switch response and prevent swarm conflicts.

1. **Emergency Stop Check (SOP-07)**:
   - Check `engagement.state`. If state is `EMERGENCY_STOP` or `/stop` has been issued:
     ```
     GATEWAY_DISPOSITION: REJECTED
     CODE: EMERGENCY_STOP_ACTIVE
     REASON: Engagement is halted under SOP-07. No tools may be spawned.
     ```
2. **Concurrency Cap (SOP-02)**:
   - Count active running scanner/validation tool instances targeting `target.hostname`.
   - If active count $\ge 7$:
     - Tool request is queued (`QUEUE_CONCURRENCY_WAIT`).
     - Gateway blocks invocation until an active slot frees up.
3. **Swarm Resource Deconfliction (Heuristics §4)**:
   - **Port Lock**: Check `engagement.active_port_locks[]`. If another subagent is actively probing `target.ip:target.port`, hold invocation until the port is unlocked.
   - **Endpoint Deduplication**: If `action_type == PASSIVE_READ` and `target.raw_target` has already been crawled and recorded in `engagement.crawled_endpoints[]`, bypass tool execution and return cached output.
   - **Optimistic Finding Lock**: If `finding_id` is supplied, ensure no other validation agent currently holds an active lock on that finding.

---

### Stage 3: Rate Limiting & Backoff Throttle (SOP-02)

**Objective**: Enforce the rate hierarchy and protect target availability.

1. **Rate Hierarchy Evaluation**:
   - Level 1: `operator_defined_rate` from `engagement.config.rate_limit` (if set, this takes absolute precedence).
   - Level 2: `safe_default_rate` = `20 req/sec` (default for unknown/unprofiled targets).
   - Level 3: `permissible_ceiling` = `100 req/sec` (hard ceiling under all conditions).
2. **Target Backoff State Check**:
   - Inspect `engagement.rate_state[target.hostname]`:
     - If `backoff_until > current_timestamp`:
       - The target is currently in the **30-second pause window** triggered by a previous HTTP 429/503.
       - Delay execution until `backoff_until` expires.
     - Active rate for target = `current_rate` (which was halved during the last backoff event).
3. **Parameter Injection / Rate Throttling**:
   - The Gateway injects rate-limiting parameters directly into the tool command before execution:
     - **FFUF**: Append `-rate <active_rate>`
     - **Nmap**: Append `--max-rate <active_rate>`
     - **Custom HTTP/Scripts**: Gateway wraps the call in a token-bucket rate limiter enforcing interval $\Delta t = \frac{1}{\text{active\_rate}}$ seconds between requests.

---

### Stage 4: Action Classification & HITL Gate Evaluation (SOP-04, Heuristics §1b)

**Objective**: Absolute human governance before active probing or exploit execution.

```
Is action_type == PASSIVE_READ?
      │
      ├── YES ──► Pass Stage 4 autonomously (No operator prompt required)
      │
      └── NO (ACTIVE_PROBE or EXPLOIT_POC)
            │
            ▼
      Does a valid Approval Token exist in engagement.hitl_tokens[]?
            │
            ├── YES (all 5 dimensions match & unexpired) ──► Pass Stage 4 (Approved)
            │
            └── NO (Missing, mismatched, or expired token)
                  │
                  ▼
            SUSPEND EXECUTION ──► Emit HITL_REQUEST to Hermes
```

#### 5-Dimensional Token Verification
If an approval token exists, the Gateway verifies all five dimensions simultaneously:

| Dimension | Rule | Failure Action |
| :--- | :--- | :--- |
| **1. Engagement ID** | `token.engagement_id == tool_request.engagement_id` | Deny token mismatch |
| **2. Operator Identity** | `token.operator_id == engagement.authorized_operator` | Deny unauthorized operator |
| **3. Finding / Asset ID** | `token.finding_id == tool_request.finding_id` | Deny finding scope mismatch |
| **4. Proposed Action** | `token.technique == tool_request.technique` AND `token.tool_name == tool_request.tool_name` | Deny technique drift |
| **5. Expiration** | `token.expires_at > current_timestamp` | Expired token; reject reuse |

#### HITL Request Emission
If no valid token exists, the Gateway pauses the calling agent and emits a structured request:

```yaml
HITL_REQUEST:
  event_type: "OPERATOR_APPROVAL_REQUIRED"
  finding_id: tool_request.finding_id
  target: tool_request.target.raw_target
  proposed_action: tool_request.technique
  tool_name: tool_request.tool_name
  command_preview: tool_request.command_template
  severity_score: tool_request.severity_hint  # Urgency context only; does not alter gate
  reversible: (tool_request.canaries.length > 0)
  timestamp: ISO-8601
```

Hermes delivers this prompt to the active operator interface. The Gateway pauses execution:
- **Operator replies `/go [ID]`**: Hermes issues an unforgeable, 5-dimensional token. The Gateway validates the token and resumes to Stage 5.
- **Operator replies `/hold [ID]`**: The Gateway aborts the tool request with `GATEWAY_DISPOSITION: HELD`, records the candidate finding at its current unverified confidence, and returns execution control to the workflow.
- **Operator timeout**: Action remains queued; swarm continues passive work only.

---

### Stage 5: Non-Destructive PoC Safety & Canary Tracking (SOP-05)

**Objective**: Guarantee zero system damage, zero persistent backdoors, and 100% artifact tracking.

1. **Destructive Command Denylist Filter**:
   - The Gateway parses the final command string and payload against the dangerous pattern filter:
     ```regex
     \b(rm\s+-[rf]{1,2}|dd\s+if=|mkfs|:\(\)\{.*\}|DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+|DELETE\s+FROM|UPDATE\s+.*SET|shutdown|reboot|netcat\s+-e|nc\s+-e|useradd|adduser)\b
     ```
   - If any prohibited pattern matches $\to$ **DENY IMMEDIATELY**:
     ```
     GATEWAY_DISPOSITION: REJECTED
     CODE: DESTRUCTIVE_PAYLOAD_DETECTED
     REASON: Command matches prohibited destructive payload pattern under SOP-05.
     ```
2. **Benign Proof Verification**:
   - Approved validation techniques must adhere to benign observation primitives:
     - Remote Code Execution: `id`, `whoami`, `hostname`, `uname -a`
     - SQL Injection: `SELECT version()`, `@@version`, `sqlite_version()`
     - SSTI: Math evaluation verification (`{{7*7}}` $\to$ `49`)
     - SSRF: Out-of-band DNS callback or loopback `/etc/issue` read
3. **Artifact Canary Registration**:
   - If `tool_request.canaries` contains entries (e.g., temporary uploaded file name `nf_canary_20260927.txt`):
     - The Gateway registers each canary into `engagement.cleanup_inventory[]`.
     - Flags finding with `cleanup_pending: true`.
     - Phase 9 cannot close until HTTP 404 / deletion of each canary is verified.

---

### Stage 6: Evidence Capture & Cryptographic Hashing Wrapper (SOP-06)

**Objective**: Cryptographic integrity and chain of custody for all test outputs.

1. **Isolated Execution Hook**:
   - The Gateway executes the approved binary in an isolated subprocess.
   - Standard output (`stdout`), standard error (`stderr`), and raw network request/response streams are captured verbatim into memory buffers.
   - Truncation or stream filtering is strictly prohibited.
2. **Evidence Hashing**:
   - The Gateway computes cryptographic digests across all outputs:
     - `stdout_sha256`: SHA-256 of raw stdout
     - `stderr_sha256`: SHA-256 of raw stderr
     - `payload_sha256`: SHA-256 of the exact payload transmitted
3. **Audit Packaging**:
   - Wraps output into a standardized `TOOL_EXECUTION_RESULT`:
     ```yaml
     tool_result:
       request_id: tool_request.request_id
       status: "SUCCESS" | "FAILED" | "TIMEOUT"
       exit_code: integer
       raw_stdout: string
       raw_stderr: string
       stdout_sha256: string
       stderr_sha256: string
       execution_duration_ms: integer
       timestamp: ISO-8601
     ```

---

## 4. Backoff & Reactive Error Interception

The Gateway does not just inspect outgoing commands — it inspects returned HTTP responses from tools:

```
Tool Execution Completes
           │
           ▼
HTTP Response Status Code?
           │
           ├── 429 Too Many Requests OR 503 Service Unavailable
           │         │
           │         ▼
           │   [Trigger SOP-02 Auto-Backoff]
           │   1. Pause all active agents for target: backoff_until = now + 30s
           │   2. Current rate = max(1, current_rate / 2)
           │   3. Emit RATE_BACKOFF_EVENT to Hermes
           │   4. Log event in engagement memory
           │
           └── 200 / 300 / 400 / 500
                     │
                     ▼
               Deliver tool_result to calling skill
```

---

## 5. Gateway Contract Guarantees

An implementation of the Execution Policy Gateway must uphold the following invariant guarantees:

1. **Fail-Closed Default**: If an incoming request cannot be classified, if target DNS fails to resolve, or if token validity is ambiguous, the Gateway **denies** execution.
2. **Zero Bypasses**: No skill, subagent, or custom script may initiate network traffic without routing through the Gateway.
3. **Non-Transferable Approvals**: An approval token generated for finding `NF-2026-0001` cannot be reused for `NF-2026-0002` or on a different endpoint.
4. **Deterministic Rate Enforcement**: The Gateway modifies tool execution flags directly to guarantee network transmission conforms to active rate limits.
5. **Immutable Chain of Custody**: Every executed tool invocation generates a cryptographically hashed evidence bundle per SOP-06 before returning control to the agent.
