# 🦅 OPENCLAW / HERMES

**Autonomous Penetration Testing Swarm Agent Framework**

> An AI-powered pentesting orchestrator that coordinates specialized security agents to perform comprehensive, methodical penetration testing with human-in-the-loop controls and multi-framework industry mapping.

---

## 🏗️ Architecture

```
                    ┌────────────────────────┐
                    │        OPERATOR        │
                    │ (Telegram / Slack / UI)│
                    └───────────┬────────────┘
                                │ HITL Controls (/go, /hold, /stop)
                    ┌───────────▼────────────┐
                    │         HERMES         │
                    │   Master Orchestrator  │
                    │  (Scope & Governance)  │
                    └───────────┬────────────┘
         ┌──────────────────────┼──────────────────────┐
    ┌────▼────┐            ┌────▼────┐            ┌────▼────┐
    │  RECON  │            │ SCANNER │            │EXPLOITER│
    │  Swarm  │            │  Swarm  │            │  Swarm  │
    └────┬────┘            └────┬────┘            └────┬────┘
         │                      │                      │
    ┌────▼────┐            ┌────▼────┐            ┌────▼────┐
    │REPORTER │            │ MEMORY  │            │EVIDENCE │
    │ & Comms │            │ Manager │            │ & Vault │
    └─────────┘            └─────────┘            └─────────┘
```

## ✨ Key Capabilities

- **🐝 Swarm Architecture**: 9 specialized subagents coordinated across 6 operational phases.
- **🤖 Telegram & Multi-Channel HITL**: Human-in-the-loop controls via Telegram, Slack, Discord, and Jira.
- **📊 Dual-Scoring System**: Independent Confidence (1–10) + Severity (1–10) ranking on every finding.
- **🛡️ 6-Framework Cross-Mapping**: Every finding and skill is mapped to **MITRE ATT&CK v19**, **NIST CSF 2.0**, **MITRE D3FEND**, **MITRE ATLAS**, **NIST AI RMF**, and **OWASP**.
- **🔌 Model Context Protocol (MCP)**: Native MCP integration for Playwright browser engines, threat intel feeds, and ticketing pipelines.
- **📋 Auto-Reporting & Walkthroughs**: 100% reproducible step-by-step walkthroughs with evidence artifacts and remediation roadmaps.
- **🎯 Strict Scope Enforcement**: Automated CIDR, IP, regex domain, and URL matching to guarantee zero out-of-scope traffic.

## 🛠️ Specialized Skills (20 Total)

| Skill | Category | Description | Framework Mappings |
| :--- | :--- | :--- | :--- |
| **`recon-passive`** | Recon | OSINT, DNS, subdomains, cert logs | ATT&CK T1593, D3-DNST |
| **`recon-active`** | Recon | Port scanning, version detection (Nmap) | ATT&CK T1046, D3-NTA |
| **`webapp-testing`** | Web | OWASP Top 10 (SQLi, XSS, SSRF, IDOR) | ATT&CK T1190, D3-WAF |
| **`api-testing`** | API | REST, GraphQL, gRPC (BOLA, BFLA) | ATT&CK T1190, D3-ARA |
| **`llm-ai-security`** | AI / LLM | Prompt injection, MCP & agent security | MITRE ATLAS, NIST AI RMF |
| **`network-testing`** | Infra | SMB, RPC, SSH, Kerberos, AD paths | ATT&CK T1021, D3-NA |
| **`ssl-tls-testing`** | Crypto | TLS versions, weak ciphers, cert analysis | ATT&CK T1573, D3-CTA |
| **`vulnerability-scanning`**| Vuln | Automated Nuclei templates & CVE matching | ATT&CK T1595, D3-VDA |
| **`cloud-testing`** | Cloud | AWS, Azure, GCP storage & IAM misconfigs | ATT&CK T1580, D3-CSM |
| **`hunting`** | Advanced | Logic flaws, race conditions, kill chains | ATT&CK T1203, D3-THA |
| **`privilege-escalation`** | Post-Exploit | Linux/Windows privilege escalation | ATT&CK T1548, D3-PEA |
| **`payload-crafting`** | Exploit | Precision benign payloads & WAF bypass | ATT&CK T1059, D3-EAA |
| **`attack-chain-analysis`**| Strategy | Visual Mermaid kill chain synthesis | Unified Kill Chain, D3-TCA |
| **`scope-management`** | Governance | Boundary parsing, validation & enforcement | NIST CSF GV.SC-01 |
| **`memory-management`** | State | Multi-agent state & timeline persistence | NIST CSF ID.AM-05 |
| **`evidence-collection`** | Audit | Evidence capture & cryptographic hashing | ATT&CK T1005, D3-FAA |
| **`incident-integrations`** | Operations | Jira, GitHub, Slack, Discord & PagerDuty | NIST CSF RS.CO, D3-IRN |
| **`telegram-hitl`** | Comms | Telegram bot commands & approval loops | NIST CSF GV.PO-02 |
| **`reporting`** | Deliverables | Executive summary & reproduction manuals | NIST CSF RS.CO-03 |
| **`remediation-advisor`** | Defense | Prioritized remediation & D3FEND defenses | D3FEND Countermeasures |

## 🚀 Quick Start Guide

### 1. Configure Scope & Notifications
Edit `config/engagement_template.yaml` with your target scope, Telegram Bot token, and optional Slack/Jira webhooks:
```yaml
scope:
  in_scope:
    domains: ["*.example.com"]
    ips: ["198.51.100.0/24"]
    ports: ["80,443,8080,8443"]
```

### 2. Launch HERMES
Initiate HERMES with your engagement file:
```
HERMES, initialize engagement with config/engagement_template.yaml
```

### 3. Monitor & Control via Telegram
- Receive live phase updates and preliminary vulnerability alerts.
- Reply `/go [ID]` to authorize targeted proof-of-concept demonstration.
- Reply `/hold [ID]` to skip or pause an attack vector.
- Type `/status` for live swarm progress and `/report` for immediate markdown compilation.

---

## 📁 Repository Structure

```
OPENCLAW/
├── AGENTS.md                                # Master Orchestrator identity & HITL rules
├── GEMINI.md                                # Project-wide safety guidelines
├── README.md                                # This documentation
├── TUTORIAL.md                              # Complete operator runbook & simulation
├── config/
│   ├── engagement_template.yaml             # Engagement scope & credentials config
│   ├── subagents.yaml                       # Swarm agent registry & dependencies
│   ├── workflows.yaml                       # 6-phase execution lifecycle & deconfliction
│   └── mcp_servers.yaml                     # Model Context Protocol external tool servers
├── docs/
│   └── framework_mappings.md                # ATT&CK, NIST, D3FEND, ATLAS cross-mappings
├── templates/
│   ├── finding_template.md                  # Individual finding deliverable template
│   ├── full_report_template.md              # Executive penetration test report template
│   └── telegram_templates.md                # Standardized Telegram notification formats
├── scripts/
│   ├── scope_validator.py                   # CIDR, IP, and domain scope validator
│   ├── telegram_bridge.py                   # Telegram bot HITL bridge
│   ├── multi_channel_notifier.py            # Slack, Discord & webhook alert bridge
│   └── report_compiler.py                   # Automated markdown report generator
├── .agents/
│   ├── skills/                              # 20 standardized agentskills.io skills
│   └── subagents/                           # 9 dedicated subagent operational prompts
└── engagements/                             # Sandboxed engagement logs and reports
```

## ⚖️ Ethics & Authorization

> [!CAUTION]
> OPENCLAW / HERMES is strictly designed for **authorized security testing and educational research**. Explicit written authorization is mandatory prior to assessing any computer system or network.
