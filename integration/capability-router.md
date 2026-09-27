# NIGHTFANG Capability Router — Implementation Specification

Version: `1.0.0`  
This document is the executable specification for the Capability Router. A Hermes loader implementing NIGHTFANG support must implement the logic in this file exactly. It complements [`routing.md`](routing.md) (which describes the concept) with a precise algorithm a runtime can follow step by step.

---

## Overview

The Capability Router accepts an operator request, classifies its target(s), and dispatches to the correct capability entry from `manifest.yaml capabilities[]`. It runs **after** the Authorization / Scope Gate and **before** any workflow, agent, or skill is activated.

```
Operator Request
      │
      ▼
[1] Parse & Extract Targets
      │
      ▼
[2] Classify Each Target → target_type token
      │
      ▼
[3] Match target_type against capabilities[].target_types[]
      │
      ├── 0 matches → ROUTING_FAILURE: clarify
      ├── 1 match   → dispatch
      └── N matches → apply specificity rules → 1 winner or ask operator
            │
            ▼
[4] Load entry.workflow, entry.agent, entry.skills[]
      │
      ▼
[5] Emit DISPATCH_EVENT → Hermes executes workflow
```

---

## Step 1 — Parse & Extract Targets

From the operator request, extract:
- All hostnames, IPs, CIDRs, URLs, finding IDs, or engagement IDs mentioned
- Any explicit `workflow=` override (operator may force a specific workflow)
- Any explicit `capability=` override (operator may force a specific capability `id`)

If an explicit `capability=` override is provided and the `id` exists in `manifest.yaml capabilities[]`, skip steps 2–3 and proceed directly to step 4 with that entry.

---

## Step 2 — Classify Each Target

Apply the classification table from [`routing.md §4`](routing.md#4-target-type-classification) to assign each extracted target a `target_type` token.

Classification priority (first matching rule wins):

```
1. Explicit operator hint (e.g., "this is a GraphQL API") → use declared type
2. URL path contains /graphql                             → graphql
3. URL path contains /api/ or /v[0-9]/                   → rest_api
4. Filename ends in .yaml or .json and resembles OpenAPI → openapi
5. Bare IP address                                        → ip_range
6. CIDR notation                                          → cidr
7. Known cloud prefix (arn:, /subscriptions/, etc.)       → aws / azure / gcp
8. HTTPS/HTTP URL, no API indicators                      → url
9. Bare domain, no scheme                                 → domain
10. MCP descriptor keyword                               → mcp_server
11. LLM provider URL or "llm" keyword                    → llm
12. Finding ID format (NF-YYYY-NNNN)                     → candidate_finding
13. "report" or "findings" keyword                       → engagement_findings
```

If no rule matches → `UNCLASSIFIED`. Treat as ROUTING_FAILURE (step 6).

---

## Step 3 — Match Against capabilities[]

For each classified target, scan `manifest.yaml capabilities[]` in order and collect all entries where `target_type ∈ entry.target_types[]`.

**Specificity tiebreaker** (when multiple entries match):

| Condition | Winner |
| :--- | :--- |
| One entry has a more specific token match | That entry wins (e.g., `rest_api` beats `url`) |
| Entries differ by workflow specificity | More specific workflow wins (e.g., `api-assessment` beats `standard-pentest`) |
| Still tied after both rules | Present tied `id` values to operator; await explicit selection |

**Multi-target requests**: If a request contains targets that classify into different capabilities (e.g., a domain + an API URL), dispatch **both** capabilities and run them as parallel tracks under the same engagement ID.

---

## Step 4 — Load Entry

From the matched `capabilities[]` entry, read:

```yaml
id:       → capability identifier (used in HITL requests, logs, and operator messages)
workflow: → load workflows/<value>.md
agent:    → load agents/<value>.md
skills[]: → register skill list; agent loads SKILL.md for each on demand
```

Pass to the workflow:
- `capability_id`: the matched `id`
- `target`: the classified target
- `target_type`: the assigned token
- `scope`: from `engagement.scope` in Hermes memory
- `config`: from `engagement.config` in Hermes memory

---

## Step 5 — Emit DISPATCH_EVENT

Emit a structured dispatch event to Hermes so it can log and resume:

```
DISPATCH_EVENT:
  engagement_id: <id>
  capability_id: <matched capability id>
  target:        <target>
  target_type:   <token>
  workflow:      <path>
  agent:         <agent id>
  skills:        [<skill paths>]
  timestamp:     <ISO-8601>
```

Hermes must persist this event to engagement memory. If the engagement resumes after a timeout or restart, Hermes replays the last DISPATCH_EVENT to restore router state.

---

## Step 6 — Routing Failure Modes

| Failure Condition | Router Behaviour |
| :--- | :--- |
| Target classifies as `UNCLASSIFIED` | Emit `ROUTING_FAILURE: unclassified_target`. Ask operator: "What type of target is this?" |
| No `capabilities[]` entry matches the token | Emit `ROUTING_FAILURE: no_matching_capability`. List known `target_types[]` for operator guidance |
| Multiple entries tied after specificity rules | Emit `ROUTING_AMBIGUOUS`. Present tied `id` values. Block until operator selects one |
| Matched entry references a missing `workflow` file | Emit `ROUTING_FAILURE: workflow_not_found`. Surface error; do not fabricate methodology |
| Matched entry references a missing `agent` file | Emit `ROUTING_FAILURE: agent_not_found`. Surface error; halt |
| Operator-forced `capability=` id not in manifest | Emit `ROUTING_FAILURE: unknown_capability_id`. List valid ids from manifest |
| Scope Gate previously rejected this target | Do not re-route. Scope violations are terminal for the current engagement turn |

---

## Step 7 — Router Contract Guarantees

The Capability Router guarantees the following invariants after a successful dispatch:

1. **Single source of truth**: The dispatched `capability_id`, `workflow`, `agent`, and `skills[]` are always derived from `manifest.yaml capabilities[]`. No hardcoded paths exist in the router.
2. **Scope is pre-verified**: The Authorization / Scope Gate has already accepted the target before the router runs. The router does not re-verify scope — that is the Gate's exclusive responsibility.
3. **No tool invocation**: The router dispatches to a workflow and agent. It does not invoke any tool, make any network request, or read any target system.
4. **Resumable**: Every dispatch produces a `DISPATCH_EVENT` that Hermes can replay to restore state after interruption.
5. **Audit trail**: Every routing decision (match, tiebreak, failure, operator override) is logged with timestamp and engagement ID before dispatch executes.
