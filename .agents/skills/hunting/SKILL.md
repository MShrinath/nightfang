---
name: hunting
description: >-
  Use this skill for threat hunting and advanced vulnerability discovery.
  Goes beyond automated scanning to find logic flaws, chained
  vulnerabilities, zero-day patterns, and complex attack paths that
  automated tools miss. Uses creative thinking, manual testing, and
  attack chain building. Activate when automated scans complete and
  deeper analysis is needed.
---

# Threat Hunting & Advanced Vulnerability Discovery

Manual, creative vulnerability hunting beyond automated tools.

## Hunting Methodology

### 1. Attack Surface Analysis
- Map all entry points (forms, APIs, file uploads, websockets)
- Identify trust boundaries
- Find data flow paths
- Locate third-party integrations

### 2. Logic Flaw Hunting
- [ ] Race conditions (TOCTOU)
  ```bash
  # Parallel request testing
  for i in {1..50}; do curl -s TARGET & done; wait
  ```
- [ ] Business logic bypass
  - Skip steps in multi-step processes
  - Negative values in quantity/price fields
  - Currency/unit manipulation
- [ ] State management issues
  - Session fixation
  - State confusion between users
  - Replay attacks

### 3. Chained Vulnerability Discovery
- Build attack chains from individual findings:
  ```
  Info Disclosure → Credential Leak → Auth Bypass → RCE
  SSRF → Internal Access → Database Dump
  XSS → Session Hijack → Admin Access → File Upload → Shell
  ```
- Document each chain with Confidence/Severity for the full chain

### 4. Pattern-Based Hunting
- [ ] Search for common vulnerability patterns:
  - `eval()`, `exec()`, `system()` in source code (if available)
  - Deserialization endpoints
  - File inclusion patterns
  - Template injection indicators
  - GraphQL introspection enabled
  - Debug endpoints left in production

### 5. Authentication & Session Deep Dive
- [ ] JWT analysis:
  - `none` algorithm acceptance
  - Key confusion (RS256 → HS256)
  - Weak signing keys
  - Token lifetime analysis
- [ ] OAuth hunting:
  - Redirect URI manipulation
  - State parameter absence
  - Token leakage via referrer
  - Scope escalation

### 6. Infrastructure Hunting
- [ ] Cloud misconfigurations:
  - S3 bucket enumeration
  - Azure blob access
  - GCP storage permissions
  - Metadata endpoint access from SSRF
- [ ] CI/CD exposure:
  - `.git` directory exposure
  - `.env` file disclosure
  - Source map files
  - Backup files (.bak, .old, ~)

## Creative Testing Techniques

1. **Parameter Pollution**: Send same parameter multiple times
2. **HTTP Method Override**: X-HTTP-Method-Override, X-Method-Override
3. **Content-Type Switching**: Change between JSON/XML/form-data
4. **Unicode Normalization**: Use Unicode equivalents to bypass filters
5. **Null Byte Injection**: %00 in file paths and parameters
6. **HTTP Request Smuggling**: CL.TE / TE.CL confusion
7. **Cache Poisoning**: Host header injection, X-Forwarded-Host
8. **Prototype Pollution**: `__proto__`, `constructor.prototype`

## Output
- Hunting log with all techniques attempted
- Discovered vulnerability chains with full attack narrative
- Confidence/Severity scores for each finding and chain
- Novel findings not caught by automated scanning

## ⚠️ HITL: All exploitation of discovered chains requires operator approval

## NIGHTFANG Agent Integration
The **HUNTER** agent automates this skill's procedures within the NIGHTFANG swarm:
- Runs as Phase 4 after all scanning phases complete
- Consumes all findings from previous phases (recon, webapp, API, network, SSL, cloud, AI)
- Builds attack chains using templates: BOLA→JWT→Admin, Subdomain→SSRF→Metadata, GraphQL→Field→BOLA
- Generates Mermaid diagrams for each chain with color-coded roles
- Prioritizes exploitation targets (P0-P3) based on chain score and complexity
- Outputs attack chains with MITRE ATT&CK paths and D3FEND countermeasures
- Requires HITL via Telegram `/go` before any chain exploitation attempt
- Configure via `technique_config.hunting` in engagement YAML
