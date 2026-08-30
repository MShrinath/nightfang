# 🎓 OPENCLAW / HERMES — Complete Operator Tutorial & Runbook

Welcome to **OPENCLAW / HERMES**. This guide provides an end-to-end walkthrough on how to configure, operate, and master the autonomous penetration testing swarm framework with Human-in-the-Loop (HITL) Telegram controls, toggleable token optimization, and multi-framework industry mapping.

---

## Table of Contents
1. [System Overview & Architecture](#1-system-overview--architecture)
2. [Prerequisites & Environment Setup](#2-prerequisites--environment-setup)
3. [Telegram Bot Integration Setup](#3-telegram-bot-integration-setup)
4. [Configuring Your Engagement](#4-configuring-your-engagement)
5. [The Dual-Scoring Ranking Matrix](#5-the-dual-scoring-ranking-matrix)
6. [Human-in-the-Loop (HITL) Protocol & Commands](#6-human-in-the-loop-hitl-protocol--commands)
7. [Toggleable Token Optimizer (Caveman Mode)](#7-toggleable-token-optimizer-caveman-mode)
8. [Swarm Agents & Skill Delegation](#8-swarm-agents--skill-delegation)
9. [End-to-End Engagement Walkthrough (Realistic Simulation)](#9-end-to-end-engagement-walkthrough-realistic-simulation)
10. [Report Generation & Reproduction Verification](#10-report-generation--reproduction-verification)
11. [Troubleshooting, Safety, & Best Practices](#11-troubleshooting-safety--best-practices)

---

## 1. System Overview & Architecture

HERMES acts as the **Central Master Orchestrator**, managing a swarm of specialized subagents across 6 engagement phases.

```
                                  ┌───────────────────────┐
                                  │   OPERATOR / LEAD     │
                                  │   (Telegram Mobile)   │
                                  └───────────┬───────────┘
                                              │ Telegram /go, /hold, /stop, /terse
                                  ┌───────────▼───────────┐
                                  │  HERMES Orchestrator  │
                                  │ (Scope, Memory, HITL) │
                                  └───────────┬───────────┘
               ┌──────────────────────────────┼──────────────────────────────┐
               │                              │                              │
     ┌─────────▼─────────┐          ┌─────────▼─────────┐          ┌─────────▼─────────┐
     │    RECON SWARM    │          │   SCANNER SWARM   │          │  EXPLOITER SWARM  │
     ├───────────────────┤          ├───────────────────┤          ├───────────────────┤
     │ • RECON-PASSIVE   │          │ • SCANNER-WEBAPP  │          │ • EXPLOITER       │
     │ • RECON-ACTIVE    │          │ • SCANNER-API     │          │ • HUNTER (Chains) │
     │                   │          │ • SCANNER-AI (LLM)│          │ • PRIVESC-AGENT   │
     │                   │          │ • SCANNER-NETWORK │          │                   │
     │                   │          │ • SCANNER-SSL     │          │                   │
     │                   │          │ • SCANNER-VULN    │          │                   │
     │                   │          │ • SCANNER-CLOUD   │          │                   │
     └─────────┬─────────┘          └─────────┬─────────┘          └─────────┬─────────┘
               │                              │                              │
               └──────────────────────────────┼──────────────────────────────┘
                                              │
                                    ┌─────────▼─────────┐
                                    │  REPORTING SWARM  │
                                    ├───────────────────┤
                                    │ • REPORTER        │
                                    │ • REMEDIATION     │
                                    │ • EVIDENCE-VAULT  │
                                    └───────────────────┘
```

---

## 2. Prerequisites & Environment Setup

### Required Tools (Installed on Target System / Host)
- **Recon & Discovery**: `nmap`, `masscan`, `whois`, `dig`, `subfinder`, `amass`, `whatweb`, `wafw00f`
- **Web & API Testing**: `nikto`, `gobuster`, `ffuf`, `nuclei`, `sqlmap`, `dalfox`, `commix`, `jwt_tool`, `katana`, `arjun`
- **Network & Exploitation**: `metasploit-framework`, `hydra`, `crackmapexec` / `netexec`, `impacket`, `testssl.sh`
- **Python Runtime**: Python 3.10+ with `requests`, `pyyaml`

---

## 3. Telegram Bot Integration Setup

HERMES communicates live updates and requests exploitation permissions via Telegram.

### Step 1: Create your Telegram Bot
1. Open Telegram and search for `@BotFather`.
2. Send `/newbot` and follow prompts (e.g., Name: `Hermes Pentest Bot`, Username: `hermes_sec_bot`).
3. Save the **HTTP API Token** (e.g., `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`).

### Step 2: Obtain your Telegram Chat ID
1. Message `@userinfobot` or `@GetIDsBot` on Telegram.
2. Note your numerical **Chat ID** (e.g., `987654321`).

### Step 3: Populate Config
Insert your token and chat ID into `config/engagement_template.yaml`:
```yaml
telegram:
  bot_token: "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
  chat_id: "987654321"
```

---

## 4. Configuring Your Engagement

Copy `config/engagement_template.yaml` to `engagements/target_engagement.yaml` and specify your scope:

```yaml
engagement:
  name: "Acme Corp Web & API Pentest"
  client: "Acme Corporation"
  type: "greybox"
  start_date: "2026-09-01"
  end_date: "2026-09-05"
  operator: "@SecurityLead"

scope:
  in_scope:
    domains:
      - "acme.example.com"
      - "*.api.acme.example.com"
    ips:
      - "198.51.100.10"
      - "198.51.100.11"
    urls:
      - "https://acme.example.com/*"
      - "https://api.acme.example.com/v1/*"
    ports:
      - "80,443,8080,8443"

  out_of_scope:
    domains:
      - "payments.acme.example.com"
    ips:
      - "198.51.100.1"
    urls:
      - "https://acme.example.com/admin/purge_database"
    notes:
      - "Strictly no DoS / Stress testing."
      - "Do not alter financial records."

rules:
  token_efficiency: false # Toggle Caveman mode on/off
```

---

## 5. The Dual-Scoring Ranking Matrix

Every finding reported by HERMES is rated on two independent 1-to-10 scales:

```
                  ┌─────────────────────────────────────────────────────────────┐
                  │                 SEVERITY SCORE (1-10)                       │
                  │ (1-2 Info | 3-4 Low | 5-6 Med | 7-8 High | 9-10 Critical)   │
┌─────────────────┼───────────────────┬───────────────────┬─────────────────────┤
│ CONFIDENCE (1-10)│ 1 - 4 (Low Impact)│ 5 - 7 (Med Impact)│ 8 - 10 (Crit Impact)│
├─────────────────┼───────────────────┼───────────────────┼─────────────────────┤
│ 1 - 3 (Inferred)│ Version banner info│ Theoretical CVE   │ Potential blind RCE │
│                 │ (e.g. Apache 2.4) │ (untested banner) │ (requires verify)   │
├─────────────────┼───────────────────┼───────────────────┼─────────────────────┤
│ 4 - 6 (Probable)│ Missing Sec Header│ Timing anomaly on │ Error-based SQLi    │
│                 │ confirmed         │ IDOR endpoint     │ stack trace seen    │
├─────────────────┼───────────────────┼───────────────────┼─────────────────────┤
│ 7 - 9 (Verified)│ Cleartext cookie  │ BOLA verified via │ SQLi / Auth Bypass  │
│                 │ extracted         │ 2nd account test  │ PoC query proven    │
├─────────────────┼───────────────────┼───────────────────┼─────────────────────┤
│ 10 (Exploited)  │ Best practice PoC │ Data modified /   │ Full RCE / Admin    │
│                 │ executed          │ records accessed  │ Shell Achieved      │
└─────────────────┴───────────────────┴───────────────────┴─────────────────────┘
```

---

## 6. Human-in-the-Loop (HITL) Protocol & Commands

HERMES will **NEVER** run intrusive exploitation commands without explicit operator authorization.

### Telegram Commands
| Command | Action |
|---------|--------|
| `/go [ID]` | Approve exploitation of a specific finding (e.g. `/go HERMES-003`) |
| `/go` | Approve current phase gate to proceed |
| `/hold [ID]` | Reject or pause testing on that vector |
| `/terse on` | **Enable Caveman Mode** (40-60% token savings, punchy telegram updates) |
| `/terse off` | **Disable Caveman Mode** (standard conversational updates) |
| `/status` | Get current progress, active swarm agents, and finding counts |
| `/findings` | List all discovered findings with dual scores & ATT&CK IDs |
| `/report` | Generate and export real-time report markdown |
| `/stop` | Immediate emergency shutdown of all active subagents |

---

## 7. Toggleable Token Optimizer (Caveman Mode)

HERMES includes an integrated **Caveman / Terse Mode** that reduces token usage by 40-60% during scans:

### How to Toggle:
1. **In Config**: Set `token_efficiency: true` in `config/engagement_template.yaml`.
2. **On Telegram / Chat**: Send `/terse on` or `/terse off` at any time.

### How it Behaves:
- **During Recon & Scans**: Strips conversational filler, producing compact, high-density telemetry.
- **On Telegram**: Formats compact alert cards for faster mobile triage.
- **Code & Commands**: Every `curl`, `nmap`, and payload remains **100% exact**.
- **Phase 6 Final Deliverables**: Automatically rendered in **formal executive English** for clients and auditors.

---

## 8. Swarm Agents & Skill Delegation

HERMES orchestrates 21 specialized skills across dedicated agents:

| Swarm Agent | Primary Skills Used | Phase | Objective |
|-------------|---------------------|-------|-----------|
| **RECON-PASSIVE** | `recon-passive`, `scope-management` | Phase 1 | Subdomain enum, WHOIS, DNS, cert logs without packet contact |
| **RECON-ACTIVE** | `recon-active`, `scope-management` | Phase 2 | Nmap scans, service detection, port validation within scope |
| **SCANNER-WEBAPP** | `webapp-testing`, `evidence-collection` | Phase 3 | OWASP Top 10 web testing (XSS, SQLi, SSRF, IDOR) |
| **SCANNER-API** | `api-testing`, `evidence-collection` | Phase 3 | REST/GraphQL BOLA, mass assignment, token analysis |
| **SCANNER-AI** | `llm-ai-security`, `evidence-collection`| Phase 3 | OWASP Top 10 for LLMs, prompt injection, MCP tool abuse |
| **SCANNER-NETWORK**| `network-testing`, `evidence-collection`| Phase 3 | SMB, SSH, RDP, Kerberos, service misconfiguration |
| **SCANNER-SSL** | `ssl-tls-testing` | Phase 3 | Cipher strength, Heartbleed/POODLE, cert expiration |
| **SCANNER-VULN** | `vulnerability-scanning` | Phase 3 | Automated Nuclei template matching & CVE correlation |
| **SCANNER-CLOUD** | `cloud-testing` | Phase 3 | AWS/Azure/GCP bucket permissions, IAM & metadata checks |
| **HUNTER** | `hunting`, `attack-chain-analysis` | Phase 4 | Logic flaws, race conditions, compound multi-step kill chains |
| **EXPLOITER** | `payload-crafting`, `privilege-escalation`| Phase 5 | Targeted exploit execution on `/go` approval |
| **REPORTER** | `reporting`, `remediation-advisor`, `incident-integrations` | Phase 6 | Structured reports, reproduction guides, Jira/Slack exports |

---

## 9. End-to-End Engagement Walkthrough (Realistic Simulation)

### Step 1: Launch Engagement
Operator prompts HERMES:
```
HERMES, initialize engagement with config: engagements/target_engagement.yaml
```

### Step 2: Phase 1 — Passive Reconnaissance
- **RECON-PASSIVE** runs `subfinder`, `crt.sh`, `dig`.
- Telegram notification sent to operator with asset count.

### Step 3: Phase 2 — Active Reconnaissance (HITL Gate)
- HERMES asks via Telegram: *"Ready to run nmap port scans on 2 live hosts. Proceed?"*
- Operator replies: `/go`
- **RECON-ACTIVE** identifies open ports and versions.

### Step 4: Phase 3 — Parallel Scanning & AI Probing
- **SCANNER-WEBAPP**, **SCANNER-API**, and **SCANNER-AI** engage simultaneously.
- **Finding #1**: BOLA on `/api/v1/users/{id}/profile` (Severity 8/10, Confidence 8/10, ATT&CK T1190).
- **Finding #2**: Prompt Injection & Guardrail Bypass on `/api/v1/ai/assistant` (Severity 7/10, Confidence 9/10, ATLAS AML.T0051).

### Step 5: Phase 4 — Threat Hunting & Attack Chaining
- **HUNTER** connects BOLA data leak to billing service access token.
- Constructs Attack Chain with Mermaid visual mapping.

### Step 6: Phase 5 — Exploitation with HITL
- Operator sends: `/go HERMES-001`
- **EXPLOITER** executes benign verification query and proves access. Confidence updated to **10/10**.

### Step 7: Phase 6 — Final Deliverable & Jira Ticketing
- **REPORTER** compiles `engagements/acme_engagement_report.md`.
- Automatically opens Jira security ticket and dispatches Telegram summary.

---

## 10. Report Generation & Reproduction Verification

Every report generated by OPENCLAW guarantees 100% reproduction accuracy:

```markdown
### Steps to Reproduce Finding #HERMES-001:

1. Authenticate as low-privileged test user:
   curl -s -X POST https://api.acme.example.com/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"test_qa_user","password":"Password123!_Secure"}'
   
   Response returns JWT token: eyJhbGci...

2. Execute BOLA request attempting to view Admin User (ID 1):
   curl -s -X GET https://api.acme.example.com/v1/users/1/profile \
     -H "Authorization: Bearer eyJhbGci..."

3. Verification:
   Observe HTTP 200 OK with full PII and internal API tokens for user ID 1.
```

---

## 11. Troubleshooting, Safety, & Best Practices

1. **Scope Boundary Safety**: HERMES automatically matches every target host against CIDR/domain regex. Any third-party host is automatically blocked unless explicitly listed in `in_scope`.
2. **Emergency Stop**: Send `/stop` at any time on Telegram to immediately kill all running subagents and network processes.
3. **Caveman Mode Efficiency**: Use `/terse on` for large scans to cut token costs by up to 60%.
4. **Artifact Cleanup**: After any exploit test, HERMES verifies that temporary files or test payloads created on target systems are cleaned up.
5. **Rate Limit Control**: Adjust `max_scan_rate: 50` in your YAML config if testing environments with aggressive WAFs or load constraints.

---
*OPENCLAW / HERMES Swarm Framework — Engineered for precision, speed, and safety.* 🦅
