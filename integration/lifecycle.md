# NIGHTFANG Engagement Lifecycle

This document defines the complete request-to-response lifecycle for a NIGHTFANG engagement, from initial Hermes request through to final operator delivery. It is the authoritative lifecycle contract between the Hermes runtime and the NIGHTFANG capability pack.

---

## 1. Lifecycle Overview

```
Hermes Request
      │
      ▼
 1. Intake & Scope Verification      ← SOP-01
      │
      ▼
 2. Target Classification & Routing  ← manifest.yaml capabilities[]
      │
      ▼
 3. Workflow Activation              ← workflows/*.md
      │
      ▼
 4. Agent Delegation                 ← agents/*.md
      │
      ▼
 5. Skill Invocation                 ← skills/*/SKILL.md → sub-modules
      │
      ▼
 6. Finding Formulation              ← schemas/finding.md
      │
      ▼
 7. HITL Gate (if active action)     ← SOP-04
      │
      ├── Approved → 8. Validation
      │                    │
      │                    ▼
      │              9. Artifact Cleanup   ← SOP-05
      │                    │
      └── Held/Passive ─── ┤
                           ▼
                    10. Finding Store Update
                           │
                           ▼
                    11. Reporter Agent
                           │
                           ▼
                    12. Hermes Delivery
```

---

## 2. Phase-by-Phase Definition

### Phase 1 — Intake & Scope Verification

**Trigger:** Hermes receives an operator request and invokes NIGHTFANG.

**Steps:**
1. NIGHTFANG reads scope document from `engagement.scope` (Hermes memory)
2. Extract all targets mentioned in the request
3. Verify every target against the scope boundary:
   - In-scope → proceed
   - Out-of-scope → immediately halt; emit scope violation notice; do not proceed
   - Ambiguous → ask operator to confirm before any active action
4. Load engagement configuration (`engagement.config.rate_limit`, engagement ID, etc.)

**Outputs:**
- Confirmed target list
- Active scope boundary for this engagement turn

**References:** [SOP-01](../references/sops.md#sop-01-scope-verification--boundary-enforcement)

---

### Phase 2 — Capability Router

**Trigger:** Scope-verified target list available.

**Steps:**
1. Classify each target by type (see `integration/routing.md §4`)
2. Match target types against `manifest.yaml capabilities[]` entries
3. Select matched entry → read `workflow`, `agent`, `skills[]`
4. If ambiguous match (multiple entries with overlapping `target_types`), present both `id` values to the operator and ask them to confirm routing before proceeding

**Outputs:**
- Selected capability `id`
- Workflow file path
- Agent name
- Primary skill list

**References:** [`integration/routing.md`](routing.md), [`manifest.yaml`](../manifest.yaml)

---

### Phase 3 — Workflow Activation

**Trigger:** Capability Router has resolved to a workflow.

**Steps:**
1. Load the selected workflow file (`workflows/*.md`)
2. Identify the current phase within the workflow (first run = Phase 1; resume = last recorded phase from engagement memory)
3. Pass target list, scope, and engagement config to the workflow

**Outputs:**
- Active workflow phase
- Phase-specific objectives and constraints

**References:** Relevant workflow in `workflows/`

---

### Phase 4 — Agent Delegation

**Trigger:** Active workflow phase loaded.

**Steps:**
1. Load agent definition (`agents/*.md`) for the responsible agent
2. Agent reads its WHO/WHAT/WHEN definition to confirm it should activate
3. Agent accepts the target list, scope, and engagement config as inputs

**Outputs:**
- Agent context initialized
- Input parameters bound

---

### Phase 5 — Skill Invocation → Execution Policy Gateway

**Trigger:** Agent active.

**Steps:**
1. Load `SKILL.md` index for the primary skill
2. Identify which sub-modules are relevant to the current test objectives
3. Load only the required sub-modules (do not load all sub-modules by default)
4. Before invoking any tool, the **Execution Policy Gateway** evaluates:
   - **Rate limit**: apply operator-defined rate → safe default (20 req/sec) → target-adjusted → auto-backoff if 429/503
   - **HITL trigger**: is this tool invocation active/invasive? If yes → pause and emit HITL request before the tool runs
   - **PoC safety**: enforce benign-only constraint; reject any tool invocation that would cause DoS, data write, or persistent change
5. If gateway approves → tool executes; if gateway triggers HITL → flow jumps to Phase 7

**Outputs:**
- Raw evidence (HTTP requests/responses, command output, timing data)
- Initial finding candidates

**References:** [SOP-02](../references/sops.md#sop-02-rate-limiting--stealth-management), [SOP-04](../references/sops.md#sop-04-human-in-the-loop-hitl-exploitation-gate), [`integration/execution-policy-gateway.md`](execution-policy-gateway.md), [`integration/routing.md §5`](routing.md#5-skill-loading)

---

### Phase 6 — Finding Formulation

**Trigger:** Raw evidence collected.

**Steps:**
1. For each identified vulnerability or weakness, create a new finding record
2. Populate all required fields per `schemas/finding.md`:
   - `id`, `title`, `target`, `category`, `timestamp`
   - `confidence.score` + `rationale`
   - `severity.score` + `level` + `rationale`
   - `evidence[]`
   - `impact.technical` + `impact.business`
   - `classifications.mitre_attack[]`, `classifications.cwe[]`, `classifications.owasp[]`
3. `classifications.cvss_v31` is left blank at this stage (requires validation data)
4. Persist finding to `engagement.findings[]` in Hermes memory

**Outputs:**
- Structured finding record(s) per `schemas/finding.md`

**Important:** Nightfang Severity (1–10) ≠ CVSS Base Score. Do not pre-populate CVSS from severity. See `schemas/finding.md §3` disambiguation note.

---

### Phase 7 — HITL Gate

**Trigger:** Agent proposes a next action.

**Decision:**
```
Is the proposed next action active / invasive?
(payload delivery, PoC execution, out-of-band callback, interactive probing)
      │
      ├── YES → HITL gate fires
      │           │
      │           ├── Emit HITL_REQUEST to Hermes
      │           ├── Hermes delivers to operator via configured channel
      │           ├── Pause; await /go [ID] or /hold [ID]
      │           │
      │           ├── /go [ID] → proceed to Phase 8 (Validation)
      │           └── /hold [ID] → proceed to Phase 10 (Finding Store, no PoC)
      │
      └── NO (passive/non-invasive) → continue in Phase 5/6 autonomously
```

Severity is included in the HITL_REQUEST for operator urgency context but does not determine whether the gate fires.

**References:** [SOP-04](../references/sops.md#sop-04-human-in-the-loop-hitl-exploitation-gate), [`integration/hermes.md §2.4`](hermes.md#24-hitl-approval-requests)

---

### Phase 8 — Validation (Benign PoC)

**Trigger:** Operator has approved HITL request.

**Steps:**
1. Load `agents/validation.md` and `skills/attack-chain/SKILL.md`
2. Execute benign proof-of-concept only:
   - Allowed: `id`, `whoami`, `SELECT version()`, DNS callback, canary string reflection, `sleep` timing
   - Prohibited: DoS, file write, credential exfiltration, persistent changes
3. Capture outcome as evidence
4. Update finding: raise `confidence.score` to confirmed (7–9) or demonstrated (10)
5. Populate `classifications.cvss_v31` vector string and base score
6. Update `severity.score` if validation reveals higher or lower impact than initially assessed

**References:** [SOP-05](../references/sops.md#sop-05-proof-of-concept-safety--artifact-cleanup)

---

### Phase 9 — Artifact Cleanup

**Trigger:** Validation complete.

**Steps:**
1. Remove all test canaries, temporary files, and test accounts created during PoC
2. Verify target baseline returns to clean state (expected HTTP 404, pre-test state)
3. Log cleanup confirmation to engagement memory

**References:** [SOP-05](../references/sops.md#sop-05-proof-of-concept-safety--artifact-cleanup)

---

### Phase 10 — Finding Store Update

**Trigger:** Either (a) validation + cleanup complete, or (b) HITL held (no PoC executed).

**Steps:**
1. Finalize finding record with all available data
2. Persist to `engagement.findings[]` in Hermes memory
3. Tag finding status: `validated` (PoC complete) or `candidate` (awaiting/held)

---

### Phase 11 — Reporter Agent

**Trigger:** All planned workflow phases complete, or operator explicitly requests a report.

**Steps:**
1. Load `agents/reporter.md` and `skills/reporting/SKILL.md`
2. Read all findings from `engagement.findings[]`
3. Deduplicate findings (same vulnerability, multiple endpoints = one root finding with affected endpoints list)
4. Apply remediation roadmap from `skills/remediation/SKILL.md`
5. Render report using `templates/full_report_template.md`
6. Render individual finding walkthroughs using `templates/finding_template.md`

---

### Phase 12 — Hermes Delivery

**Trigger:** Report or finding alert ready.

**Steps:**
1. NIGHTFANG emits structured output per `AGENTS.md §7` communication protocol
2. Hermes delivers via configured channel (Telegram, Discord, CLI, Web)
3. Engagement turn complete; NIGHTFANG returns to idle / awaiting next operator instruction

---

## 3. Lifecycle State Machine

```
IDLE
  │
  │  Hermes invokes NIGHTFANG with request
  ▼
INTAKE                    ← scope check; halt if out-of-scope
  │
  ▼
ROUTING                   ← capability match; clarify if ambiguous
  │
  ▼
SCANNING (PASSIVE)        ← skills running; autonomous; no HITL needed
  │
  ├── finding ready, action is passive → FINDING_STORE → REPORTING
  │
  └── finding ready, action is active
        │
        ▼
      HITL_PENDING         ← paused; operator notification sent
        │
        ├── /go → VALIDATING → CLEANUP → FINDING_STORE → REPORTING
        └── /hold → FINDING_STORE (candidate) → REPORTING
```

---

## 4. Lifecycle Invariants

These conditions must hold at all times during an engagement:

1. **Scope never expands mid-engagement** without operator confirmation
2. **HITL queue is never auto-cleared** — only operator commands clear it
3. **No finding is deleted** — only status is updated (candidate → validated, or candidate → dismissed with reason)
4. **Rate limits are always active** — no skill may bypass the rate hierarchy in SOP-02
5. **Cleanup is always attempted** after any PoC execution, even if validation failed
