# 🧠 NIGHTFANG Long-Term Agent Memory & Knowledge Base

This file serves as the **persistent long-term memory store** for NIGHTFANG across engagements and sessions. NIGHTFANG automatically updates and references this file to retain operator preferences, target architecture patterns, learned evasion behaviors, and historical findings.

---

## 1. Operator Preferences & Governance Profile

```yaml
operator_profile:
  handle: ""                       # e.g. "@SecurityLead"
  default_hitl_channel: "telegram" # telegram | slack | discord | cli
  preferred_scan_speed: "T3"       # T1 (paranoid) to T4 (aggressive)
  auto_terse_mode: false           # default caveman mode on/off
  alert_severity_threshold: 7      # minimum severity score to trigger urgent push alert
  notification_digest_interval: 15 # minutes for batching low/medium findings
```

---

## 2. Learned Target Patterns & Evasion Signatures

NIGHTFANG records observed WAF behaviors, rate limits, and defenses across engagements:

```yaml
target_signatures:
  cloudflare:
    detected_headers: ["cf-ray", "__cf_bm", "cf-cache-status"]
    safe_request_rate: 25 # req/sec max to prevent IP challenge
    evasion_notes: "Use rotated User-Agents and HTTP/2 requests."
  
  aws_waf:
    detected_headers: ["x-amzn-requestid", "awselb"]
    safe_request_rate: 50 # req/sec
    evasion_notes: "Header inspection triggers on raw SQL keywords in User-Agent."

  nginx_rate_limiting:
    detected_status: 429
    backoff_strategy: "exponential_backoff_initial_30s"
```

---

## 3. Discovered Credential Vault (Active Session Memory)

Stores validated testing credentials provided or harvested during testing (sanitized/salted):

```yaml
credentials_registry:
  - host: ""
    service: "" # e.g. "ssh", "api_bearer", "basic_auth", "smb"
    role: ""    # e.g. "guest", "standard_user", "admin"
    username: ""
    token_or_secret_ref: "" # Reference to environment variable or vault ID
    validated_timestamp: ""
```

---

## 4. Active Engagement State Snapshot

```yaml
active_engagement:
  engagement_id: "ENG-2026-001"
  status: "idle" # idle | in_progress | paused | completed
  active_phase: "phase_0"
  total_assets_discovered: 0
  total_findings_count: 0
  highest_severity_observed: 0
  last_checkpoint_timestamp: ""
```

---

## 5. Memory Update Protocol for Subagents

When updating this memory store, swarm agents must follow these rules:
1. **Deduplication**: Never create duplicate asset or finding entries; update existing records by host/IP key.
2. **Confidence Escalation**: Only upgrade finding Confidence when verified by a separate scan technique or exploit demonstration.
3. **Audit Trail**: Every modification must record the subagent name and UTC timestamp.
4. **Sanitization**: Never store raw unencrypted credit cards, personal identifiable information (PII), or live root passwords in plain markdown files.
