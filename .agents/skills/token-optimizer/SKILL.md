---
name: token-optimizer
description: >-
  Use this skill for token-efficient agent operation and context compression (Caveman Mode).
  Reduces token consumption by 40-60% across swarm agents by stripping conversational filler,
  redundant pleasantries, and verbose formatting during internal reasoning and live scans,
  while keeping commands, payloads, CVSS scores, and code blocks 100% exact.
domain: cybersecurity
subdomain: orchestration
tags: [token-optimization, caveman-mode, context-compression, efficiency, cost-saving]
version: "1.0"
---

# Token Optimizer (Caveman Mode) for HERMES Swarms

High-efficiency communication and context compression protocol for autonomous agent swarms.

## When to Use
- `token_efficiency: true` is set in `config/engagement_template.yaml`.
- Operator issues `/terse on` or `/caveman on` via Telegram or CLI.
- Large-scale engagements with extensive port scanning, fuzzing, or thousands of API endpoints where context window preservation is critical.

## Core Rules

### 1. The Golden Principle: "Why use many token when few token do trick"
- Strip all conversational pleasantries ("I would be happy to help with that", "As you requested", "Let me think about this step-by-step").
- Deliver direct, high-density factual updates.
- Keep sentences short, punchy, and telegraphic.

### 2. What Must NEVER Be Compressed (100% Precision Mandatory)
- **Target URLs, IP addresses, and Port numbers**
- **Exact command lines and parameters** (`nmap`, `sqlmap`, `curl`, `ffuf`)
- **Code snippets, payloads, and syntax**
- **Dual scores (Confidence X/10, Severity Y/10)**
- **CVSS v3.1 vectors, CWE IDs, and MITRE ATT&CK / D3FEND tags**
- **Error logs and raw HTTP response headers**

### 3. Phase-Aware Output Behavior

| Mode / Phase | Behavior in Terse Mode (`/terse on`) | Behavior in Normal Mode (`/terse off`) |
| :--- | :--- | :--- |
| **Phase 0 (Intake)** | `Scope loaded. 4 targets. Validated. Ready. /go?` | Detailed scope breakdown with conversational confirmation. |
| **Phase 1-4 (Recon/Scan)** | `Nmap done. 80,443 open. Nginx 1.24. Found BOLA /api/v1/user. Conf: 8/10, Sev: 8/10.` | Multi-paragraph explanation of scanning methods and findings. |
| **Phase 5 (HITL Request)** | Compact Telegram alert with direct `/go` or `/hold` prompt. | Standard structured card. |
| **Phase 6 (Final Report)** | **FULL FORMAL REPORT** (Executive markdown, comprehensive walkthroughs). | **FULL FORMAL REPORT**. |

> [!NOTE]
> Phase 6 Final Reports are **exempt** from caveman mode. Client deliverables and audit reports are ALWAYS formatted with complete professional language.

## Examples

### Scan Update
- **Verbose (Standard):**
  > "I have finished running the active reconnaissance scan against the target host 198.51.100.10. During the scan, I identified that port 80 and port 443 are open running Nginx 1.24. Additionally, port 8080 is open hosting an Express Node.js API service."
- **Terse (Caveman Mode):**
  > `Host 198.51.100.10 scanned. Open: 80, 443 (Nginx 1.24), 8080 (Node.js Express). Passing to SCANNER-WEBAPP.`

### Vulnerability Flag
- **Verbose (Standard):**
  > "We have detected a potential Broken Object Level Authorization vulnerability on the endpoint /api/v1/users/profile. When changing user ID from 1 to 2, sensitive data is returned without proper authorization checks. Severity is 8/10 and Confidence is 8/10."
- **Terse (Caveman Mode):**
  > `Finding HERMES-002: BOLA on /api/v1/users/profile. Param 'id' lacks auth check. Conf: 8/10. Sev: 8/10. Exploit test? /go HERMES-002 or /hold HERMES-002`

## Toggle Control
- Enable: `/terse on` or `/caveman on`
- Disable: `/terse off` or `/caveman off`
- Status: `/terse`
