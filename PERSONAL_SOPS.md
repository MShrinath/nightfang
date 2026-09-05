# 📜 AEGIS Personal Standard Operating Procedures (SOPs)
# Extends HERMES SOPS.md with operator-specific safety, quality, and operational standards

> These SOPs are YOUR operational contract. AEGIS follows them absolutely. They override framework defaults where specified.

---

## SOP-A1: Personal Scope Verification & Boundary Enforcement
**Objective**: Guarantee zero out-of-scope traffic with operator's learned boundaries.

1. **Multi-Layer Validation**:
   - Layer 1: HERMES scope validator (CIDR, domain, URL, port)
   - Layer 2: AEGIS personal validator (learned exclusions, third-party detection)
   - Layer 3: Real-time DNS resolution check against known third-party ASNs
   
2. **Third-Party Infrastructure Guardrail**:
   - If target resolves to Cloudflare/AWS/Azure/GCP/Akamai/Fastly:
     - Verify testing only targets YOUR tenant/bucket
     - Block any request to shared infrastructure endpoints
     - Log third-party detection to PERSONAL_MEMORY.md
   
3. **Learned Exclusion Enforcement**:
   - Apply operator's personal exclusions from PERSONAL_MEMORY.md
   - Block sensitive paths (/admin/purge, /payment, /billing) automatically
   - Alert operator on any boundary probe attempt
   
4. **Violation Response**:
   - IMMEDIATE block (do not log then block — block first)
   - Log to `engagements/scope_violations.log` with full context
   - Telegram alert to operator within 5 seconds
   - Continue testing within scope

---

## SOP-A2: Personal Rate Limiting & Stealth Management
**Objective**: Prevent DoS with operator's calibrated limits and learned evasion.

1. **Calibrated Baselines** (from PERSONAL_MEMORY.md:tool_effectiveness):
   - Global: 150 req/sec (operator preference)
   - Per-tool: nmap T4, ffuf 150/s, nuclei 25 concurrent
   - Adaptive: Reduce by 50% on any 429/503
   
2. **Learned WAF Evasion** (from PERSONAL_MEMORY.md:target_signatures):
   - Cloudflare: 25 req/sec, HTTP/2, rotated UAs
   - Akamai: 15 req/sec, chunked encoding, header padding
   - AWS WAF: 50 req/sec, double-encode payloads
   - Unknown: Exponential backoff starting at 30s
   
3. **Concurrency Controls**:
   - Max 7 concurrent agents (operator config)
   - Shared token bucket across all agents
   - Per-target rate limiting with learned profiles
   
4. **429/503 Response Protocol**:
   - IMMEDIATE pause all agents for 30s
   - Reduce global rate by 50%
   - Update target signature in PERSONAL_MEMORY.md
   - Resume with new limits
   - Alert operator if same target triggers 3x

---

## SOP-A3: Personal False Positive Elimination & Dual Scoring
**Objective**: Deliver 100% verified findings with AEGIS confidence calibration.

1. **AEGIS Confidence Calibration** (from PERSONAL_MEMORY.md):
   - 1-2: Theoretical (banner only) — NEVER report alone
   - 3-4: Probable (differential response) — Flag for verification
   - 5-6: Likely (timing anomaly, error leakage) — Manual PoC required
   - 7-8: Verified (deterministic reflection, math eval) — Ready for /go
   - 9: Confirmed (independent tool verification)
   - 10: Exploited (operator /go + benign access demonstrated)

2. **Mandatory Re-Test Rules**:
   - Every injection finding: 2+ independent verification attempts
   - Different payloads, different parameters, different tools
   - SQLi: Manual boolean + time-based + sqlmap batch
   - XSS: Dalfox + manual payload + browser verification
   - SSRF: Internal metadata + internal service + loopback
   
3. **Confidence Escalation Protocol**:
   - Only upgrade on INDEPENDENT verification (different technique/tool)
   - Never escalate based on same tool re-run
   - Confidence 10 ONLY after: operator /go + benign access + cleanup verified
   
4. **AEGIS Finding Status Lifecycle**:
   ```
   Suspected (3-6) → Confirmed (7-9) → Exploited (10) → False Positive (0)
   ```

---

## SOP-A4: Personal HITL Exploitation Gate
**Objective**: Absolute operator governance with AEGIS safety rules.

1. **Pre-Exploitation Checklist** (AUTOMATIC, cannot bypass):
   - [ ] Scope validated (personal + framework)
   - [ ] Finding confidence ≥ 7
   - [ ] Operator /go received for THIS finding ID
   - [ ] Benign payload selected (id/whoami/version only)
   - [ ] Target baseline snapshot captured
   - [ ] Cleanup plan documented
   
2. **Benign POC Only — Non-Negotiable**:
   ```
   ALLOWED:    id, whoami, hostname, uname -a, pwd, ls -la /tmp
   ALLOWED:    SELECT version(), SELECT current_user(), SELECT database()
   ALLOWED:    http://169.254.169.254/latest/meta-data/
   ALLOWED:    {{7*7}}, {{config}}, {{request.environ}}
   FORBIDDEN:  --os-shell, --dump, --sql-shell, data exfiltration
   FORBIDDEN:  Persistence, backdoors, scheduled tasks, SSH keys
   FORBIDDEN:  Any command not in ALLOWED list
   ```

3. **Per-Finding Approval**:
   - Telegram alert with: finding ID, target, vuln type, Conf/Sev, benign POC plan
   - Operator replies: `/go AEGIS-XXX` or `/hold AEGIS-XXX`
   - 60-minute timeout → queue action, continue other scanning
   - `/stop` → IMMEDIATE kill all exploitation

4. **Post-Exploitation**:
   - Privilege escalation: SEPARATE /go per technique
   - Lateral movement: SEPARATE /go per target
   - Data access demo: SEPARATE /go per dataset

---

## SOP-A5: Personal POC Safety & Artifact Cleanup
**Objective**: Zero persistent changes with screenshot-verified cleanup.

1. **Benign POC Execution**:
   - Web RCE: `id` → capture output → verify UID
   - SQLi: `SELECT version()` → capture output → verify version string
   - SSRF: Metadata endpoint → capture IAM role → verify role ARN
   - JWT: Forge token → access admin → verify admin data → STOP
   
2. **Mandatory Cleanup Verification**:
   - Web shells: DELETE → HTTP 404 verification → SCREENSHOT
   - Test files: `rm -f` → `ls -la` verification → SCREENSHOT
   - Test accounts: `userdel` → `id user` verification → SCREENSHOT
   - Database entries: `DELETE` → `SELECT` verification → SCREENSHOT
   - Cloud resources: API DELETE → API LIST verification → SCREENSHOT
   
3. **Cleanup Evidence Package**:
   - Before screenshot (artifact exists)
   - Cleanup command + output
   - After screenshot (artifact gone)
   - All SHA-256 hashed
   - Stored in `evidence/cleanup/`

4. **Cleanup Failure Protocol**:
   - If cleanup fails: IMMEDIATE operator alert
   - Document exact failure
   - Provide manual cleanup instructions
   - Track until resolved

---

## SOP-A6: Personal Evidence Hashing & Chain of Custody
**Objective**: Cryptographic integrity for all evidence with AEGIS standards.

1. **Capture Standards**:
   - Raw HTTP request/response (no truncation)
   - Full command output (stdout + stderr)
   - Screenshots: PNG, 1920x1080 minimum
   - Tool outputs: Native format (JSON, XML) + text
   
2. **Hashing Protocol**:
   - Algorithm: SHA-256 (operator config)
   - Hash at capture time
   - Store hash in finding metadata
   - Manifest file: `evidence/manifest.json` with all hashes
   
3. **Storage Structure**:
   ```
   engagements/{ENG_ID}/evidence/
   ├── AEGIS-001_request.http
   ├── AEGIS-001_response.http
   ├── AEGIS-001_screenshot.png
   ├── AEGIS-001_cleanup_before.png
   ├── AEGIS-001_cleanup_after.png
   ├── manifest.json
   └── hashes.sha256
   ```

4. **Chain of Custody Log**:
   - Every access logged with timestamp, actor, purpose
   - Read-only after engagement complete
   - Archive with engagement

---

## SOP-A7: Personal Emergency Stop Protocol
**Objective**: Instant shutdown with state preservation.

1. **Trigger**: Operator sends `/stop` on Telegram or CLI
2. **AEGIS Actions** (parallel, < 5 seconds):
   - Broadcast SIGTERM to all subagents
   - Kill all subprocesses (nmap, ffuf, sqlmap, etc.)
   - Save current state to BOTH memories (HERMES + AEGIS)
   - Capture cleanup screenshots for any active exploits
   - Confirm shutdown to operator on Telegram
3. **Resume Capability**:
   - `AEGIS, resume ENG-XXXX` restores from checkpoint
   - No data loss, no duplicate work

---

## SOP-A8: Personal Reporting Standards
**Objective**: Every deliverable is executive-ready with AEGIS voice.

1. **Finding Format** (templates/personal_finding_template.md):
   - Dual scores with justification
   - Raw curl reproduction commands
   - Evidence hashes
   - Code-level remediation
   - D3FEND implementation guide
   
2. **Report Structure** (templates/personal_report_template.md):
   - Executive summary (< 1 page)
   - Attack chain visualizations (Mermaid)
   - Master findings table
   - Detailed walkthroughs
   - Prioritized remediation roadmap (24h/1w/30d/90d)
   - Full framework mappings
   
3. **Quality Gates**:
   - All findings reproducible by operator
   - Zero placeholder text
   - Evidence hashes verified
   - Framework mappings complete
   - Operator review before delivery

---

## SOP-A9: Personal Memory Management
**Objective**: Maintain high-fidelity personal knowledge base.

1. **Update Triggers** (automatic after each engagement):
   - New WAF signatures → target_signatures
   - Tool effectiveness → tool_effectiveness (rolling average)
   - Attack chains → attack_chain_templates
   - Engagement outcomes → engagement_history
   
2. **Sanitization Rules**:
   - NO raw tokens, passwords, PII, credit cards
   - References only: `${ENV_VAR}` or `vault://path`
   - Redact IPs unless explicitly in-scope
   
3. **Audit Trail**:
   - Every update: timestamp, agent, reason
   - Version control via git (optional)
   - Immutable sections: SOUL.md, OPERATOR_PROFILE.md (operator only)

---

*These SOPs are your operational DNA. AEGIS obeys them without exception.*