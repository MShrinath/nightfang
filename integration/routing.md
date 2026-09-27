# NIGHTFANG Capability Router

This document defines exactly how the **Capability Router** maps an incoming operator request to a specific NIGHTFANG workflow, agent, and skill set. The Capability Router is distinct from the **Execution Policy Gateway** — it handles dispatch, not enforcement.

> For the step-by-step executable specification a Hermes loader implements, see [`integration/capability-router.md`](capability-router.md).

---

## 1. Routing Source of Truth

The Capability Router table lives in [`manifest.yaml`](../manifest.yaml) under the `capabilities[]` key. Each entry has an `id` field (e.g., `web-application-security`), `target_types[]`, `workflow`, `agent`, and `skills[]`.

**Do not hard-code routing logic.** Always derive dispatch from the manifest `capabilities[]` list.

---

## 2. Routing Algorithm

```
Incoming operator request (target + scope + task description)
            │
            ▼
    ┌────────────────────────────┐
    │  1. Extract target types   │
    │  (classify input)          │
    └────────────────┬───────────┘
                     │
                     ▼
    ┌────────────────────────────┐
    │  2. Match against          │
    │  manifest capabilities[]   │
    │  → find entry where        │
    │    target_types[] intersect│
    └────────────────┬───────────┘
                     │
                     ▼
    ┌────────────────────────────┐
    │  3. Select workflow        │
    │  entry.workflow            │
    └────────────────┬───────────┘
                     │
                     ▼
    ┌────────────────────────────┐
    │  4. Delegate to agent      │
    │  entry.agent               │
    └────────────────┬───────────┘
                     │
                     ▼
    ┌────────────────────────────┐
    │  5. Invoke skills (HOW)    │
    │  entry.skills[]            │
    └────────────────────────────┘
```

If a request matches **more than one** capability entry, apply the specificity rule:
- More specific `target_types` wins over more general (e.g., `url` beats `domain`)
- If still ambiguous, present both `id` values to the operator and ask them to confirm

---

## 3. Capability → Agent → Skill Mapping

The entries below are derived directly from `manifest.yaml capabilities[]`. The `id` column is the authoritative identifier — use it when referencing a capability in logs, approval requests, and operator messages.

| `id` | `target_types[]` | `workflow` | `agent` | `skills[]` |
| :--- | :--- | :--- | :--- | :--- |
| `attack-surface-mapping` | `domain`, `cidr`, `ip_range`, `hostname`, `asset_inventory` | `standard-pentest` | `recon` | `skills/recon` |
| `web-application-security` | `web_app`, `url`, `http`, `https`, `spa`, `cms` | `web-assessment` | `scanner` | `skills/web`, `skills/hunting` |
| `api-security` | `rest_api`, `graphql`, `grpc`, `openapi`, `swagger`, `json_api` | `api-assessment` | `scanner` | `skills/api`, `skills/hunting` |
| `network-infrastructure-security` | `network_host`, `subnet`, `port_service`, `tls_endpoint` | `standard-pentest` | `scanner` | `skills/network` |
| `cloud-security` | `aws`, `azure`, `gcp`, `s3_bucket`, `imds`, `cloud_tenant` | `standard-pentest` | `scanner` | `skills/cloud` |
| `ai-llm-security` | `llm`, `agent`, `mcp_server`, `prompt_interface`, `rag` | `ai-security-assessment` | `ai-security` | `skills/ai-security` |
| `exploit-validation` | `candidate_finding`, `unverified_exploit` | `standard-pentest` | `validation` | `skills/attack-chain`, `skills/remediation` |
| `security-reporting` | `engagement_findings`, `audit_deliverable` | `standard-pentest` | `reporter` | `skills/reporting`, `skills/remediation` |

---

## 4. Target Type Classification

Hermes or NIGHTFANG must classify the operator's input before routing. The `Classified As` values below are the exact tokens matched against `target_types[]` in `manifest.yaml capabilities[]`.

| Input Pattern | Classified As |
| :--- | :--- |
| IPv4/IPv6 address (e.g., `192.168.1.1`) | `ip_range` |
| CIDR block (e.g., `10.0.0.0/24`) | `cidr` |
| Bare hostname or domain (e.g., `example.com`) | `domain` |
| Hostname with implicit asset context | `hostname` |
| Org-level asset list or IP inventory | `asset_inventory` |
| HTTP/HTTPS URL without API path | `url`, `http`, or `https` |
| URL with CMS signature (WordPress, Drupal, etc.) | `cms` |
| Single-page application explicitly identified | `spa` |
| Web application (general) | `web_app` |
| URL referencing an API path (e.g., `/api/v1/`, `/graphql`) | `rest_api` or `graphql` |
| gRPC service descriptor | `grpc` |
| OpenAPI/Swagger spec file or URL | `openapi` or `swagger` |
| JSON API endpoint | `json_api` |
| Network host (port scan target) | `network_host` |
| Subnet for host enumeration | `subnet` |
| Specific service on a port | `port_service` |
| TLS/HTTPS endpoint for cipher audit | `tls_endpoint` |
| AWS resource (ARN, S3 bucket, EC2) | `aws` |
| Azure resource (subscription, resource group) | `azure` |
| GCP resource (project, service account) | `gcp` |
| Cloud storage bucket | `s3_bucket` |
| IMDS endpoint or SSRF to metadata service | `imds` |
| Cloud identity tenant | `cloud_tenant` |
| LLM endpoint or model-serving URL | `llm` |
| Agentic system or tool-use pipeline | `agent` |
| MCP server descriptor | `mcp_server` |
| Prompt input interface | `prompt_interface` |
| RAG pipeline or retrieval backend | `rag` |
| Reference to a prior candidate finding | `candidate_finding` |
| Unverified exploit or attack hypothesis | `unverified_exploit` |
| Engagement ID (report generation request) | `engagement_findings` |
| Audit deliverable request | `audit_deliverable` |

If classification is ambiguous, NIGHTFANG asks the operator to clarify before routing.

---

## 5. Skill Loading

Each skill directory contains a `SKILL.md` index/router file. **Load only `SKILL.md` first.** Sub-modules are loaded on demand based on what the specific test requires, to minimize context window consumption.

```
skills/web/SKILL.md          ← load first (index)
    ├── injection.md         ← load when: SQLi, SSTI, Command Injection tests
    ├── auth.md              ← load when: session, cookie, CSRF tests
    ├── access-control.md    ← load when: IDOR, path traversal tests
    └── ssrf.md              ← load when: SSRF tests
```

The agent's `SKILL.md` specifies when to load each sub-module. Agents must follow this directive; they do not load all sub-modules by default.

---

## 6. Routing Failure Modes

| Condition | Action |
| :--- | :--- |
| No matching capability in manifest | Ask operator to clarify target type before proceeding |
| Capability matched but agent file missing | Surface error; do not fabricate methodology |
| Skill file missing | Use available skill index; log gap to operator |
| Target classified as out-of-scope | Immediately halt; emit scope violation notice per SOP-01 |
| HITL queue full (operator unreachable) | Pause all active validation; continue passive scanning only |
