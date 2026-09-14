# 🧠 PERSONAL_MEMORY.md — NIGHTFANG Long-Term Memory & Knowledge Base

> This is YOUR personal agent's persistent memory store. Distinct from NIGHTFANG's shared MEMORY.md — this holds *your* patterns, *your* preferences, *your* learned evasions, and *your* engagement history. NIGHTFANG reads/writes this automatically across all sessions.

---

## 1. Operator Profile & Governance (Synced from OPERATOR_PROFILE.md)

```yaml
operator_profile:
  handle: "@SecurityLead"
  identity_verified: true
  default_hitl_channel: "telegram"
  preferred_scan_speed: "T3"
  auto_terse_mode: false
  alert_severity_threshold: 7
  notification_digest_interval: 15
  timezone: "UTC"
  language: "en"
  report_audience: ["technical", "executive"]
  evidence_standard: "raw_curl_http_hash"
  cleanup_verification: "mandatory_screenshot"
```

---

## 2. Learned Target Signatures & Evasion Patterns (Personal)

*Your private threat intel — WAF behaviors, rate limits, quirks observed across YOUR engagements.*

```yaml
target_signatures:
  cloudflare:
    detected_headers: ["cf-ray", "__cf_bm", "cf-cache-status"]
    safe_request_rate: 25
    evasion_notes: "Rotated UAs + HTTP/2. Challenges on raw SQL in UA header."
    last_seen: "2026-08-15"
    engagement_ref: "ENG-2026-007"

  akamai:
    detected_headers: ["akamai-origin-hop", "true-client-ip"]
    safe_request_rate: 15
    evasion_notes: "Aggressive on POST body inspection. Use chunked encoding + header padding."
    last_seen: "2026-07-22"
    engagement_ref: "ENG-2026-005"

  aws_alb_waf:
    detected_headers: ["x-amzn-trace-id", "awselb"]
    safe_request_rate: 50
    evasion_notes: "Header inspection triggers on raw SQL keywords in User-Agent. Encode payloads."
    last_seen: "2026-06-30"
    engagement_ref: "ENG-2026-003"

  nginx_rate_limit:
    detected_status: 429
    backoff_strategy: "exponential_backoff_initial_30s"
    signature: "X-RateLimit-Limit header present"
    last_seen: "2026-08-01"

  f5_bigip_asm:
    detected_cookies: ["TS*", "BIGipServer*"]
    safe_request_rate: 10
    evasion_notes: "Deep packet inspection. Requires full request mimicry including TLS fingerprint."
    last_seen: "2026-05-18"

  custom_waf_unknown:
    detected_pattern: "403 on single quote in param, 200 on double-encoded"
    evasion_notes: "Double URL encode + case variation bypasses. Test per parameter."
    last_seen: "2026-08-28"
```

---

## 3. Credential Vault References (Sanitized)

*Validated testing credentials — NEVER stores raw secrets. References .env or vault IDs only.*

```yaml
credentials_registry:
  - host: "api.targetcorp.com"
    service: "api_bearer"
    role: "standard_user"
    username: "test_user_qa"
    token_ref: "${TARGETCORP_QA_TOKEN}"
    validated: "2026-08-20T14:30:00Z"
    scope: "read:users, read:orders"

  - host: "ssh.internal.targetcorp.com"
    service: "ssh_key"
    role: "admin"
    username: "pentest_admin"
    key_ref: "${TARGETCORP_SSH_KEY_PATH}"
    validated: "2026-08-18T09:15:00Z"

  - host: "graphql.targetcorp.com"
    service: "graphql_token"
    role: "premium_user"
    username: "premium_tester"
    token_ref: "${TARGETCORP_GRAPHQL_TOKEN}"
    validated: "2026-08-25T11:00:00Z"
```

---

## 4. Engagement History & Patterns

```yaml
engagement_history:
  - engagement_id: "ENG-2026-008"
    client: "FinTech Corp"
    type: "greybox"
    duration_days: 5
    phases_completed: [0,1,2,3,4,5,6]
    findings_total: 23
    critical: 2
    high: 5
    exploited: 3
    attack_chains: 4
    notable_pattern: "BOLA chain -> JWT weak secret -> Admin panel takeover"
    lessons_learned:
      - "GraphQL introspection disabled but field suggestion enabled"
      - "Rate limit on /auth/login but not /auth/register"
    caveman_mode_used: true
    token_savings_pct: 52

  - engagement_id: "ENG-2026-007"
    client: "SaaS Platform"
    type: "blackbox"
    duration_days: 3
    phases_completed: [0,1,2,3,4]
    findings_total: 17
    critical: 1
    high: 3
    exploited: 1
    attack_chains: 2
    notable_pattern: "Subdomain takeover -> SSRF -> Cloud metadata"
    lessons_learned:
      - "crt.sh revealed 200+ forgotten subdomains"
      - "WAF bypass via HTTP/2 request smuggling"
    caveman_mode_used: true
    token_savings_pct: 48

  - engagement_id: "ENG-2026-006"
    client: "Healthcare API"
    type: "whitebox"
    duration_days: 7
    phases_completed: [0,1,2,3,4,5,6]
    findings_total: 31
    critical: 3
    high: 8
    exploited: 5
    attack_chains: 6
    notable_pattern: "FHIR API BOLA + IDOR chain -> Full PHI access"
    lessons_learned:
      - "Swagger spec exposed internal debug endpoints"
      - "JWT algorithm confusion (RS256 -> HS256)"
    caveman_mode_used: false
```

---

## 5. Tool Effectiveness Matrix (Personal Calibration)

```yaml
tool_effectiveness:
  nmap:
    success_rate: 0.94
    preferred_flags: "-sS -T4 -p- --min-rate 2000 --max-retries 1"
    fallback: "masscan -p1-65535 --rate=5000"
  
  ffuf:
    success_rate: 0.89
    wordlist_preference: "raft-medium-directories.txt + custom_api.txt"
    fallback: "gobuster dir -w"
  
  nuclei:
    success_rate: 0.76
    template_sets: ["cves", "misconfig", "exposures", "tech"]
    custom_templates_path: "~/nuclei-templates-custom"
  
  sqlmap:
    success_rate: 0.82
    safety_rules: "--batch --risk=1 --level=2 --no-cast --answers='follow=N'"
    hitl_required_for: ["--os-shell", "--dump", "--sql-shell"]
  
  nuclei_ai:
    success_rate: 0.68
    note: "AI templates hit-or-miss. Manual prompt crafting > templates."

  katana:
    success_rate: 0.91
    note: "Best for SPA crawling. Use -d 3 -jc -kf all."

  testssl:
    success_rate: 0.97
    note: "Gold standard. Always run on 443 + alt ports."
```

---

## 6. Attack Chain Templates (Reusable Patterns)

```yaml
attack_chain_templates:
  - id: "CHAIN-BOLA-JWT-ADMIN"
    name: "BOLA → Weak JWT → Admin Panel"
    frequency: "High (seen in 4/8 engagements)"
    steps:
      - "Find BOLA on /api/v1/users/{id}/profile (Confirmed)"
      - "Extract admin user JWT via BOLA (ID=1)"
      - "Analyze JWT: alg=HS256, weak secret"
      - "Forge admin JWT with HS256 + 'admin':true"
      - "Access /admin panel with forged token"
    mitre_path: ["T1190", "T1552.004", "T1078"]
    d3fend_counters: ["D3-PSA", "D3-KDU", "D3-AA"]

  - id: "CHAIN-SUBDOMAIN-SSRF-METADATA"
    name: "Subdomain Takeover → SSRF → Cloud Metadata"
    frequency: "Medium (seen in 2/8 engagements)"
    steps:
      - "Passive subdomain enum finds dangling CNAME"
      - "Claim subdomain -> Host malicious endpoint"
      - "Find SSRF in /api/v1/webhook or /import"
      - "SSRF to http://169.254.169.254/latest/meta-data/"
      - "Extract IAM credentials / instance profile"
    mitre_path: ["T1590.005", "T1190", "T1552.005"]
    d3fend_counters: ["D3-DNST", "D3-SFI", "D3-CSM"]

  - id: "CHAIN-GRAPHQL-INTROSPECTION-BOLA"
    name: "GraphQL Introspection → Field Suggestion → BOLA"
    frequency: "Medium (seen in 3/8 engagements)"
    steps:
      - "GraphQL introspection disabled but __schema hints leak"
      - "Use field suggestion (typeahead) to map hidden fields"
      - "Find 'internalUserId' or 'adminToken' fields"
      - "BOLA on mutation updateUser(input: {id, internalUserId})"
    mitre_path: ["T1592", "T1190", "T1068"]
    d3fend_counters: ["D3-PSA", "D3-AA", "D3-MCI"]
```

---

## 7. Active Engagement State (Current Session)

```yaml
active_engagement:
  engagement_id: ""
  status: "idle"
  active_phase: "phase_0"
  target_assets: {}
  findings_discovered: []
  attack_chains_built: []
  operator_decisions: []
  token_efficiency_active: false
  last_checkpoint: ""
```

---

## 8. Memory Update Protocol (NIGHTFANG Personal)

> Rules for how NIGHTFANG updates this file across engagements.

```yaml
update_rules:
  deduplication_key: "host+port+service"         # Merge assets by unique key
  confidence_escalation:
    - "Only upgrade on independent verification (different tool/technique)"
    - "Confidence 10 ONLY after operator /go + demonstrated access"
  audit_trail_required: true
  sanitization_rules:
    - "No raw tokens, passwords, PII, credit cards"
    - "References only: ${ENV_VAR} or vault://path"
    - "Redact IPs in memory unless explicitly in-scope"
  retention:
    target_signatures: "indefinite"
    credentials_registry: "per_engagement + 30 days"
    engagement_history: "indefinite"
    tool_effectiveness: "indefinite (rolling avg)"
    attack_chain_templates: "indefinite"
```

---

## 9. Cross-Reference Index

| Memory Type | Location | Sync Direction |
|-------------|----------|----------------|
| NIGHTFANG Shared Assets | `MEMORY.md` → `assets` | READ-only (NIGHTFANG consumes) |
| NIGHTFANG Findings | `MEMORY.md` → `findings` | READ-only |
| NIGHTFANG Decisions | `MEMORY.md` → `decisions` | READ-only |
| Personal Signatures | `PERSONAL_MEMORY.md` → `target_signatures` | WRITE (NIGHTFANG owns) |
| Personal Chains | `PERSONAL_MEMORY.md` → `attack_chain_templates` | WRITE (NIGHTFANG owns) |
| Personal Tool Calibration | `PERSONAL_MEMORY.md` → `tool_effectiveness` | WRITE (NIGHTFANG owns) |

---

*This memory grows with every engagement. It is your institutional knowledge — portable, versioned, and yours alone.*