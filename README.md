# 🦅 OPENCLAW / HERMES

**Autonomous Penetration Testing Swarm Agent Framework**

> An AI-powered pentesting orchestrator that coordinates specialized security agents to perform comprehensive, methodical penetration testing with human-in-the-loop controls, persistent state memory, and multi-framework industry mapping.

---

## 🏗️ Architecture

```
                    ┌────────────────────────┐
                    │        OPERATOR        │
                    │ (Telegram / Slack / UI)│
                    └───────────┬────────────┘
                                │ HITL Controls (/go, /hold, /stop, /terse)
                    ┌───────────▼────────────┐
                    │         HERMES         │
                    │   Master Orchestrator  │
                    │ (MEMORY, SOPS & Scope) │
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
- **🧠 Persistent Memory & State**: Long-term memory store (`MEMORY.md`), decision heuristics (`HEURISTICS.md`), and SOP runbooks (`SOPS.md`).
- **🤖 Telegram & Multi-Channel HITL**: Human-in-the-loop controls via Telegram, Slack, Discord, and Jira.
- **🪨 Toggleable Caveman Mode**: Optional 40–60% token reduction via `/terse on|off` or config flag.
- **📊 Dual-Scoring System**: Independent Confidence (1–10) + Severity (1–10) ranking on every finding.
- **🛡️ 6-Framework Cross-Mapping**: Mapped to **MITRE ATT&CK v19**, **NIST CSF 2.0**, **MITRE D3FEND**, **MITRE ATLAS**, **NIST AI RMF**, and **OWASP**.
- **🔌 Model Context Protocol (MCP)**: Native MCP integration for Playwright browser engines, threat intel feeds, and ticketing pipelines.
- **📋 Auto-Reporting & Walkthroughs**: 100% reproducible step-by-step walkthroughs with evidence artifacts and remediation roadmaps.
- **🎯 Strict Scope Enforcement**: Automated CIDR, IP, regex domain, and URL matching to guarantee zero out-of-scope traffic.

---

## 📁 Repository Structure

```
OPENCLAW/
├── AGENTS.md                                # Master Orchestrator identity & HITL rules
├── GEMINI.md                                # Project-wide safety guidelines
├── MEMORY.md                                # Persistent agent memory & learned target patterns
├── SOPS.md                                  # Standard Operating Procedures (safety, rate limits, cleanup)
├── HEURISTICS.md                            # Triage heuristics & attack chain prioritization logic
├── TOOLS.md                                 # Complete tool inventory, timeouts & fallback matrix
├── README.md                                # This documentation
├── TUTORIAL.md                              # Complete operator runbook & simulation
├── .env.example                             # Environment variables template
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
│   ├── state_manager.py                     # Real-time state & memory manager
│   ├── telegram_bridge.py                   # Telegram bot HITL bridge
│   ├── multi_channel_notifier.py            # Slack, Discord & webhook alert bridge
│   └── report_compiler.py                   # Automated markdown report generator
├── .agents/
│   ├── skills/                              # 21 standardized agentskills.io skills
│   └── subagents/                           # 9 dedicated subagent operational prompts
└── engagements/                             # Sandboxed engagement logs and reports
```

## 🚀 Quick Start Guide

1. Copy `.env.example` to `.env` and fill in your `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.
2. Edit `config/engagement_template.yaml` with your target scope and rules of engagement.
3. Start the assessment with HERMES:
   ```
   HERMES, initialize engagement with config/engagement_template.yaml
   ```
4. Control testing live via Telegram with `/go [ID]`, `/hold [ID]`, `/terse on|off`, `/status`, and `/report`.

---

## ⚖️ Ethics & Authorization

> [!CAUTION]
> OPENCLAW / HERMES is strictly designed for **authorized security testing and educational research**. Explicit written authorization is mandatory prior to assessing any computer system or network.
