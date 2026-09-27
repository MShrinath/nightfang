# NIGHTFANG ↔ Hermes Integration Contract

Version: `0.1.0`  
This document describes what Hermes must provide to load and operate NIGHTFANG as a capability pack, and what NIGHTFANG contracts to provide in return.

---

## 1. What Hermes Must Do

### 1.1 Pack Discovery & Loading

Hermes loads NIGHTFANG by locating `manifest.yaml` in the pack root. The loader must read the following manifest fields at startup:

| Field | Type | Required | Purpose |
| :--- | :--- | :--- | :--- |
| `pack.name` | string | ✅ | Pack identity |
| `pack.version` | string | ✅ | Version for compatibility checks |
| `runtime.name` | string | ✅ | Verify this is a Hermes-compatible pack |
| `runtime.min_version` | string | ✅ | Reject if Hermes version is below this |
| `runtime.entrypoint.agent` | string | ✅ | Path to the main agent file (`AGENTS.md`) |
| `runtime.capabilities.*` | boolean map | ✅ | Which capability types this pack uses |
| `capabilities[]` | list | ✅ | **Capability Router** table: maps target types to workflow + agent + skills |

**Loading order:**
1. Parse `manifest.yaml`
2. Verify `runtime.name == "hermes"` and `runtime.min_version` compatibility
3. Load entrypoint agent at `runtime.entrypoint.agent` (`AGENTS.md`) into the active context
4. Register all entries from `capabilities[]` in the Hermes **Capability Router** index
5. Initialize the **Execution Policy Gateway** ([`integration/execution-policy-gateway.md`](execution-policy-gateway.md)) across all external tool and network execution handlers

### 1.2 Operator Interface (Channel Abstraction)

NIGHTFANG is channel-agnostic. Hermes owns and manages all operator-facing channels. NIGHTFANG emits structured messages; Hermes is responsible for delivery.

**What Hermes must expose to NIGHTFANG at runtime:**
- `send_operator_message(content: str)` — deliver a NIGHTFANG alert or status message to the operator via whatever channel is active
- `receive_operator_command() -> str` — receive operator replies (`/go [ID]`, `/hold [ID]`, `/stop`, `PROCEED`, etc.)

NIGHTFANG never calls Telegram, Discord, CLI, or Web APIs directly.

**Hermes must relay NIGHTFANG operator messages as-is**, preserving the structured format defined in `AGENTS.md §7`. Hermes may apply transport-appropriate formatting (e.g., Markdown for Telegram, plain text for CLI).

### 1.3 Persistent Memory

NIGHTFANG agents are stateless within a single turn. Hermes provides memory continuity across turns.

**Hermes must persist:**
- Active scope document (target list, in/out-of-scope boundaries)
- Findings store: all findings recorded by agents in this engagement
- Engagement configuration: operator-defined rate limit, engagement ID, authorized tester identity
- HITL queue: findings awaiting operator approval

**NIGHTFANG will reference memory via scoped keys:**
```
engagement.scope
engagement.findings[]
engagement.config.rate_limit
engagement.hitl_queue[]
```

Hermes maps these keys to its internal memory backend (file, database, vector store, etc.).

### 1.4 Scheduling

Hermes manages all scheduling. NIGHTFANG may request deferred execution (e.g., "retry this scan in 30 minutes") by emitting a schedule intent:

```
SCHEDULE_INTENT: retry scan of <target> in <duration>
REASON: rate-limited, backoff applied
```

Hermes intercepts this, creates the scheduled job, and reinvokes the relevant capability when the timer fires.

---

## 2. What NIGHTFANG Provides to Hermes

### 2.1 Entrypoint Agent

`AGENTS.md` is the single entrypoint. It contains NIGHTFANG's constitution: identity, safety rules, delegation model, and Capability Router dispatch logic. Hermes loads this as the primary instruction context.

### 2.2 Capability Router Table

`manifest.yaml` contains a `capabilities[]` list. Each entry defines:
- `id`: unique capability identifier (e.g., `web-application-security`)
- `target_types[]`: what kinds of input trigger this capability
- `workflow`: which workflow file to execute
- `agent`: which agent is responsible
- `skills[]`: which skill modules the agent invokes

Hermes uses this table to dispatch incoming requests to the correct Nightfang capability without parsing `AGENTS.md`.

### 2.3 Structured Findings

All findings produced by NIGHTFANG agents conform to `schemas/finding.md`. Hermes can ingest these findings for:
- Operator alert delivery
- Persistent storage in the findings store
- Generating engagement reports on demand

### 2.4 HITL Approval Requests

When NIGHTFANG reaches an action-based HITL gate (active validation required), it emits a structured approval request:

```
HITL_REQUEST:
  finding_id: NF-YYYY-NNNN
  target: <endpoint>
  proposed_action: <technique description>
  technique: <specific payload/tool>
  reversible: false
  potential_impact: <brief description>
  severity: <N>/10
```

### 2.5 Execution Policy Gateway Contract

Hermes must never execute external tools, network scans, or arbitrary commands requested by skills directly. All tool execution must be proxied through the **Execution Policy Gateway** ([`integration/execution-policy-gateway.md`](execution-policy-gateway.md)):
- Evaluates scope boundaries (SOP-01), emergency stop state (SOP-07), and resource locks (Heuristics §4)
- Enforces the rate hierarchy and auto-backoff delays (SOP-02)
- Enforces the 5-dimensional approval token check on active actions (SOP-04)
- Blocks prohibited destructive payloads and registers canaries for cleanup (SOP-05)
- Captures raw execution streams and computes SHA-256 evidence digests (SOP-06)

---

## 3. Hermes Version Compatibility

| NIGHTFANG Pack Version | Min Hermes Version | Notes |
| :--- | :--- | :--- |
| `0.1.x` | `0.1.0` | Initial integration contract |

If Hermes does not meet `min_version`, it must refuse to load the pack and surface an error to the operator.

---

## 4. What Hermes Must NOT Do

- Must not modify or inject content into NIGHTFANG agent prompts beyond the registered entrypoint
- Must not bypass the HITL gate by auto-approving HITL requests
- Must not execute external tools or network requests without routing them through the Execution Policy Gateway
- Must not expose out-of-scope targets to NIGHTFANG agents; scope enforcement is shared but Hermes must not route requests that clearly violate scope
- Must not strip or truncate finding schemas before persisting them

---

## 5. Integration Verification Checklist

Before declaring NIGHTFANG operational on a Hermes instance, verify:

- [ ] `manifest.yaml` parsed successfully
- [ ] `runtime.min_version` check passed
- [ ] `AGENTS.md` loaded as entrypoint
- [ ] All 8 capabilities registered in routing index
- [ ] Execution Policy Gateway intercepting all tool invocations and network requests
- [ ] `send_operator_message()` wired to active channel
- [ ] `receive_operator_command()` polling active
- [ ] Engagement memory scoped and initialized
- [ ] HITL queue initialized and operator-facing
- [ ] End-to-end smoke test: send a test finding through the full pipeline and verify operator receives alert
