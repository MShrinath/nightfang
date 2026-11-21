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

If a request matches **more than one** capability entry (e.g., `tls_endpoint` matching both `network-infrastructure-security` and `cryptographic-security`), the Capability Router applies a deterministic 5-step hierarchy:
1. **Explicit Directive**: Operator `--capability=<id>` overrides all matching logic.
2. **Token Specificity**: More specific `target_types` wins over general (e.g., `rest_api` beats `url`).
3. **Contextual Intent Lexicon**: Request text is scanned for domain keywords (e.g., "cipher", "certificate", "jwt" $\to$ `cryptographic-security`; "ports", "service", "firewall" $\to$ `network-infrastructure-security`).
4. **Workflow Specialization**: Domain-specific workflows win over generic ones (`api-assessment` beats `standard-pentest`).
5. **Ambiguity Emission (`ROUTING_AMBIGUOUS`)**: If target is bare and intent is unstated, halt and request operator clarification with candidate capability IDs.

See [`integration/capability-router.md §Step 3`](capability-router.md#step-3-match-against-capabilities) for the complete executable algorithm.

---

## 3. Capability → Agent → Skill Mapping

The entries below are derived directly from `manifest.yaml capabilities[]`. The `id` column is the authoritative identifier — use it when referencing a capability in logs, approval requests, and operator messages.

| `id` | `target_types[]` | `workflow` | `agent` | `skills[]` |
| :--- | :--- | :--- | :--- | :--- |
| `autonomous-supervision` | `engagement_scope`, `target_specification`, `autonomous_engagement`, `swarm_supervision` | `dynamic-supervision` | `supervisor` | `skills/utility`, `skills/hunting`, `skills/reporting` |
| `attack-surface-mapping` | `domain`, `cidr`, `ip_range`, `hostname`, `asset_inventory` | `standard-pentest` | `recon` | `skills/recon` |
| `web-application-security` | `web_app`, `url`, `http`, `https`, `spa`, `cms` | `web-assessment` | `scanner` | `skills/web`, `skills/hunting` |
| `api-security` | `rest_api`, `graphql`, `grpc`, `openapi`, `swagger`, `json_api` | `api-assessment` | `scanner` | `skills/api`, `skills/hunting` |
| `network-infrastructure-security` | `network_host`, `subnet`, `port_service`, `tls_endpoint` | `standard-pentest` | `scanner` | `skills/network` |
| `cloud-security` | `aws`, `azure`, `gcp`, `s3_bucket`, `imds`, `cloud_tenant` | `cloud-assessment` | `cloud-security` | `skills/cloud`, `skills/container` |
| `container-kubernetes-security` | `docker_host`, `k8s_cluster`, `container_registry`, `helm_chart`, `k8s_manifest` | `cloud-assessment` | `container-breakout` | `skills/container`, `skills/privilege-escalation` |
| `cicd-pipeline-security` | `github_actions`, `gitlab_ci`, `jenkins`, `azure_devops`, `circleci` | `cicd-assessment` | `cicd-redteam` | `skills/cicd`, `skills/supply-chain` |
| `active-directory-security` | `ad_domain`, `ad_forest`, `domain_controller`, `ldap`, `kerberos`, `adcs` | `ad-assessment` | `ad-attacker` | `skills/active-directory`, `skills/privilege-escalation` |
| `wireless-security` | `wifi_ap`, `wifi_client`, `ble_device`, `zigbee_mesh`, `z_wave`, `lorawan` | `wireless-assessment` | `wireless-pentester` | `skills/wireless`, `skills/iot` |
| `mobile-security` | `android_app`, `ios_app`, `apk`, `ipa`, `mobile_backend` | `mobile-assessment` | `mobile-pentester` | `skills/mobile`, `skills/api`, `skills/crypto` |
| `iot-embedded-security` | `iot_device`, `firmware`, `hardware_interface`, `mqtt_broker`, `coap_endpoint` | `iot-ics-assessment` | `iot-pentester` | `skills/iot`, `skills/wireless` |
| `ot-ics-security` | `plc`, `rtu`, `historian`, `hmi`, `scada_server`, `industrial_network`, `safety_system` | `iot-ics-assessment` | `scada-attacker` | `skills/ot-ics`, `skills/network` |
| `cryptographic-security` | `tls_endpoint`, `certificate`, `jwt_token`, `crypto_implementation`, `pqc_migration` | `standard-pentest` | `crypto-analyzer` | `skills/crypto`, `skills/api` |
| `privilege-escalation` | `linux_host`, `windows_host`, `container`, `endpoint_shell` | `standard-pentest` | `privesc-advisor` | `skills/privilege-escalation` |
| `post-exploitation` | `compromised_host`, `internal_subnet`, `pivot_point` | `standard-pentest` | `lateral-movement` | `skills/post-exploitation`, `skills/network` |
| `forensics-incident-response` | `memory_dump`, `disk_image`, `log_archive`, `malware_sample`, `pcap` | `standard-pentest` | `forensics-analyst` | `skills/forensics` |
| `supply-chain-security` | `git_repo`, `package_lockfile`, `sbom`, `container_image`, `ci_cd_pipeline` | `supply-chain-assessment` | `supply-chain-auditor` | `skills/supply-chain`, `skills/cicd` |
| `grc-compliance` | `organization`, `control_set`, `audit_scope`, `policy_repo` | `standard-pentest` | `compliance-mapper` | `skills/grc`, `skills/reporting` |
| `threat-intelligence` | `threat_report`, `ioc_feed`, `malware_sample`, `actor_profile`, `campaign` | `standard-pentest` | `cti-analyst` | `skills/cti`, `skills/reporting` |
| `purple-team-adversary-emulation` | `detection_rules`, `sim_environment`, `attck_technique`, `atomic_test` | `purple-team` | `purple-team-operator` | `skills/purple-team`, `skills/remediation`, `skills/cti` |
| `ai-llm-security` | `llm`, `agent`, `mcp_server`, `prompt_interface`, `rag` | `ai-security-assessment` | `ai-security` | `skills/ai-security` |
| `exploit-validation` | `candidate_finding`, `unverified_exploit` | `standard-pentest` | `validation` | `skills/attack-chain`, `skills/remediation` |
| `security-reporting` | `engagement_findings`, `audit_deliverable` | `standard-pentest` | `reporter` | `skills/reporting`, `skills/remediation` |
| `utility-operations` | `engagement_request`, `scope_document`, `target_inventory` | `standard-pentest` | `engagement-planner` | `skills/utility`, `skills/recon` |
| `defense-evasion-assessment` | `endpoint_host`, `edr_policy`, `workstation_image`, `process_telemetry`, `lolbas_candidate` | `purple-team` | `evasion-specialist` | `skills/defense-evasion`, `skills/privilege-escalation` |
| `command-and-control-resilience` | `c2_infrastructure`, `egress_boundary`, `network_perimeter`, `covert_channel`, `proxy_gateway` | `purple-team` | `c2-operator` | `skills/c2-operations`, `skills/post-exploitation` |
| `initial-access-assessment` | `vpn_gateway`, `remote_access`, `perimeter_portal`, `payload_delivery`, `motw_container` | `standard-pentest` | `recon` | `skills/initial-access`, `skills/recon` |
| `credential-access-security` | `lsass_memory`, `credential_vault`, `sam_database`, `dpapi_store`, `session_token` | `standard-pentest` | `privesc-advisor` | `skills/credential-access`, `skills/privilege-escalation` |
| `reverse-engineering` | `binary_file`, `firmware_image`, `compiled_app`, `malware_executable`, `uefi_rom` | `reverse-engineering` | `reverse-engineer` | `skills/reverse-engineering`, `skills/iot`, `skills/mobile` |
| `database-security` | `database_server`, `sql_endpoint`, `db_credential`, `nosql_store` | `standard-pentest` | `database-attacker` | `skills/web`, `skills/network`, `skills/privilege-escalation` |
| `social-engineering` | `social_target`, `phishing_campaign`, `pretext_scenario`, `employee_profile` | `social-engineering` | `social-engineer` | `skills/initial-access`, `skills/recon`, `skills/utility` |
| `red-team-operations` | `redteam_scope`, `adversary_profile`, `crown_jewels`, `assumed_breach` | `red-team` | `c2-operator` | `skills/c2-operations`, `skills/post-exploitation`, `skills/defense-evasion` |
| `extended-osint-reach` | `social_profile`, `x_account`, `reddit_thread`, `youtube_channel`, `code_repo`, `developer_handle` | `standard-pentest` | `recon` | `skills/recon`, `skills/utility` |
| `repo-graph-memory` | `source_code`, `git_repo`, `ast_graph`, `code_workspace`, `repo_graph_memory` | `supply-chain-assessment` | `code-auditor` | `skills/web`, `skills/api`, `skills/crypto` |

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
| Social handle, X post, Reddit thread, YouTube video URL | `social_profile`, `x_account`, `reddit_thread`, `youtube_channel`, or `developer_handle` |
| Source code repository, AST knowledge graph, repo directory | `source_code`, `git_repo`, `ast_graph`, `code_workspace`, or `repo_graph_memory` |
| Binary executable, ELF/PE/Mach-O file, firmware image | `binary_file`, `firmware_image`, `compiled_app`, `malware_executable`, or `uefi_rom` |
| Database server, SQL query endpoint, database credentials | `database_server`, `sql_endpoint`, `db_credential`, or `nosql_store` |
| Social engineering target, pretexting plan, phishing vector | `social_target`, `phishing_campaign`, `pretext_scenario`, or `employee_profile` |
| Red team scenario scope, adversary emulation plan | `redteam_scope`, `adversary_profile`, `crown_jewels`, or `assumed_breach` |

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
