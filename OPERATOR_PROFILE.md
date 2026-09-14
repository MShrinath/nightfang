# 👤 OPERATOR_PROFILE.md — Your Governance & Preference Contract

> This file defines YOU — the operator. NIGHTFANG reads this on every invocation to calibrate behavior, communication, and decision boundaries. Edit freely; changes take effect immediately.

---

## 1. Identity & Authentication

```yaml
operator:
  handle: "@SecurityLead"
  real_name: ""                              # Optional, for reports
  organization: ""                           # Your org/team
  pgp_fingerprint: ""                        # For encrypted comms (future)
  ssh_public_key: ""                         # For artifact transfer (future)
  verified: true                             # Set false to require re-auth
```

---

## 2. Communication Protocol

```yaml
communication:
  primary_channel: "telegram"                # telegram | slack | discord | cli
  telegram:
    bot_token_env: "TELEGRAM_BOT_TOKEN"
    chat_id_env: "TELEGRAM_CHAT_ID"
    parse_mode: "Markdown"
    disable_web_page_preview: true
    silent_notifications: false              # True for non-urgent digests
  
  # Fallback channels (future)
  slack:
    webhook_url_env: "SLACK_WEBHOOK_URL"
    channel: "#security-ops"
  
  discord:
    webhook_url_env: "DISCORD_WEBHOOK_URL"
  
  cli_fallback: true                         # Print to stdout if all else fails
```

---

## 3. Notification & Alert Rules

```yaml
notifications:
  # Severity-based immediate push
  immediate_push:
    severity_threshold: 7                    # 7-10 = instant alert
    confidence_threshold: 9                  # 9-10 = instant alert
    attack_chain_formed: true                # Any new chain = instant
    scope_boundary_probe: true               # Any out-of-scope touch = instant
  
  # Batched digests for lower priority
  digest:
    enabled: true
    interval_minutes: 15
    include_severity: [1,2,3,4,5,6]          # Low/Medium batched
    format: "compact_table"
  
  # Phase transitions
  phase_transitions:
    notify_on_start: true
    notify_on_complete: true
    include_summary_stats: true
  
  # Engagement lifecycle
  engagement_start: true
  engagement_complete: true
  emergency_stop_ack: true
```

---

## 4. Operational Preferences

```yaml
preferences:
  # Scanning
  default_scan_profile: "T3"                 # T1=Paranoid, T2=Polite, T3=Normal, T4=Aggressive, T5=Insane
  max_concurrent_scans: 7
  max_requests_per_second: 100
  stealth_mode_default: false
  
  # Token Efficiency (Caveman Mode)
  caveman_mode:
    default_enabled: false
    toggle_commands: ["/terse", "/caveman"]
    auto_enable_on_large_scope: true         # Auto-enable if >50 targets
    large_scope_threshold: 50
  
  # Exploitation
  exploitation:
    require_hitl_per_finding: true           # Never auto-exploit
    benign_poc_only: true                    # id/whoami/version only
    cleanup_verification_required: true
    max_exploit_time_minutes: 30
  
  # Reporting
  reporting:
    default_format: "markdown"
    include_evidence: true
    include_mermaid_chains: true
    include_remediation_roadmap: true
    map_mitre_attack: true
    map_mitre_atlas: true
    map_d3fend: true
    map_nist_csf: true
    executive_summary_first: true
    technical_depth: "full"                  # full | summary | findings_only
  
  # Evidence
  evidence:
    hash_algorithm: "sha256"
    capture_raw_http: true
    capture_screenshots: true
    screenshot_on_exploit: true
    retention_days: 90
```

---

## 5. Decision Authority Matrix

```yaml
decision_authority:
  # What YOU must approve (HITL required)
  hitl_required:
    - phase_2_active_recon_start
    - phase_5_exploitation_per_finding
    - privilege_escalation_attempt
    - lateral_movement_attempt
    - data_exfiltration_demo
    - cloud_exploitation
    - ai_llm_tool_execution
    - scope_boundary_exception
  
  # What NIGHTFANG can decide autonomously (within confirmed scope)
  autonomous:
    - phase_1_passive_recon
    - phase_3_vulnerability_scanning
    - phase_4_threat_hunting
    - tool_selection_and_flags
    - rate_limit_adjustment_on_429
    - duplicate_finding_deduplication
    - attack_chain_prioritization
    - report_structure_and_formatting
  
  # Emergency overrides
  emergency_stop:
    command: "/stop"
    effect: "IMMEDIATE_KILL_ALL_SUBAGENTS"
    confirmation_required: false
```

---

## 6. Scope & Rules of Engagement Defaults

```yaml
scope_defaults:
  # Default inclusions (override per engagement)
  default_in_scope_ports: "80,443,8080,8443,3306,5432,27017,6379,9200"
  default_allowed_techniques:
    - passive_recon
    - active_recon
    - vulnerability_scanning
    - web_app_testing
    - api_testing
    - ai_llm_testing
    - network_testing
    - cloud_testing
    - ssl_tls_testing
  
  # Default exclusions (safety)
  default_out_of_scope:
    - "*/admin/purge*"
    - "*/admin/delete*"
    - "*payment*"
    - "*billing*"
    - "production-db*"
    - "*.rds.amazonaws.com"
    - "*.database.windows.net"
  
  # Default constraints
  default_constraints:
    - "No denial of service or resource exhaustion"
    - "No data modification without explicit /go"
    - "No persistence mechanisms"
    - "No social engineering"
    - "No physical security testing"
    - "Respect rate limits and WAF signals"
```

---

## 7. Framework Mapping Preferences

```yaml
frameworks:
  mitre_attack_version: "v19"
  mitre_atlas_version: "v2.2"
  mitre_d3fend_version: "v1.0"
  nist_csf_version: "2.0"
  nist_ai_rmf_version: "1.0"
  owasp_top10_version: "2021"
  owasp_api_top10_version: "2023"
  owasp_llm_top10_version: "2025"
  cwe_version: "4.14"
  cvss_version: "3.1"
  
  # Which mappings to include by default
  include_in_reports:
    mitre_attack: true
    mitre_atlas: true
    mitre_d3fend: true
    nist_csf: true
    nist_ai_rmf: true
    cwe: true
    owasp: true
    cvss: true
```

---

## 8. Tool & Environment Configuration

```yaml
environment:
  # Paths (auto-resolved relative to NIGHTFANG root)
  paths:
    engagements_dir: "engagements"
    evidence_dir: "engagements/{engagement_id}/evidence"
    reports_dir: "engagements/{engagement_id}/reports"
    logs_dir: "engagements/{engagement_id}/logs"
    wordlists_dir: "~/wordlists"
    nuclei_templates_dir: "~/nuclei-templates"
  
  # Tool timeouts (seconds)
  tool_timeouts:
    nmap: 1800
    masscan: 900
    ffuf: 600
    nuclei: 900
    sqlmap: 600
    testssl: 300
    katana: 600
    subfinder: 300
    amass: 600
  
  # Proxy / egress (if needed)
  proxy:
    enabled: false
    http_proxy_env: "HTTP_PROXY"
    https_proxy_env: "HTTPS_PROXY"
    no_proxy_env: "NO_PROXY"
  
  # API Keys (referenced from .env)
  api_keys:
    shodan: "SHODAN_API_KEY"
    censys: "CENSYS_API_ID + CENSYS_API_SECRET"
    virustotal: "VT_API_KEY"
    github: "GITHUB_TOKEN"
    gitlab: "GITLAB_TOKEN"
```

---

## 9. Personal Safety & Ethics Boundaries

```yaml
ethics:
  # Hard limits — NIGHTFANG will refuse even if you /go
  hard_refusal:
    - "Testing systems not in written scope"
    - "Exfiltrating real user/customer data"
    - "Creating persistent access/backdoors"
    - "Modifying production data"
    - "Denial of service testing"
    - "Social engineering / phishing"
    - "Physical security testing"
    - "Testing third-party SaaS without explicit addendum"
  
  # Soft limits — NIGHTFANG will warn but proceed on /go
  soft_warning:
    - "High-rate scanning on production"
    - "Credential stuffing / password spraying"
    - "Cloud metadata SSRF"
    - "AI/LLM tool execution with side effects"
  
  # Compliance tags for reporting
  compliance_context:
    - "PCI-DSS"                                # If applicable
    - "HIPAA"                                  # If applicable
    - "GDPR"                                   # If applicable
    - "SOC2"                                   # If applicable
```

---

## 10. Quick-Reference: Telegram Command Cheatsheet

| Command | Action | Scope |
|---------|--------|-------|
| `/go` | Approve current phase gate | Phase |
| `/go [ID]` | Approve exploitation of finding | Finding |
| `/hold [ID]` | Reject/pause finding | Finding |
| `/hold` | Pause current phase | Phase |
| `/stop` | Emergency kill all | Global |
| `/status` | Live swarm status + finding counts | Global |
| `/findings` | List all findings with scores | Global |
| `/report` | Generate & send markdown report | Engagement |
| `/terse on` | Enable Caveman Mode | Session |
| `/terse off` | Disable Caveman Mode | Session |
| `/scope` | Show current scope boundaries | Engagement |
| `/evidence [ID]` | Send evidence for finding | Finding |
| `/chain [ID]` | Show attack chain diagram | Chain |

---

*This profile is your voice in the machine. NIGHTFANG obeys it absolutely.*