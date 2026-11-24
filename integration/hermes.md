# NIGHTFANG ↔ Hermes Integration Contract

This document describes how Hermes hosts, operates, and becomes **NIGHTFANG** as an autonomous security intelligence layer, detailing what Hermes provides, what NIGHTFANG delivers, and how remote channels (Telegram, Discord, Web, CLI) interact with the autonomous hunting engine.

---

## 1. Architectural Philosophy: Hermes IS Nightfang

NIGHTFANG is not an isolated command-line script — it is the **security brain and capability pack for Hermes**. When an operator installs NIGHTFANG via `install.sh` (Linux/macOS) or `install.ps1` (Windows):

1. NIGHTFANG's persona, constitution, and operating procedures are installed as the default Hermes system prompt (`~/.hermes/nightfang/system.md`).
2. All 42 domain skills are symlinked/copied into Hermes's skill store (`~/.hermes/skills/nightfang`).
3. Hermes's runtime config (`~/.hermes/nightfang/config.yaml`) is overlaid with NIGHTFANG's 35 capabilities, execution policy gateway, and tiered autonomy settings.
4. When Hermes connects to any transport channel (Telegram bot, Discord bot, Web UI, or local CLI terminal), **the operator is talking directly to NIGHTFANG**.

```
┌────────────────────────────────────────────────────────────────────────┐
│                         Host Runtime (Hermes)                          │
│     Model Selection • Token Efficiency / Terse Mode • Scheduling       │
│                 Long-Term Memory • Channel Adaptors                    │
├───────────────────┬───────────────────┬───────────────────┬────────────┤
│     Telegram      │      Discord      │        CLI        │    Web     │
└───────────────────┴───────────────────┴───────────────────┴────────────┘
                                   │ Loads via manifest.yaml
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        NIGHTFANG Capability Pack                       │
│                       Security Orchestration Layer                     │
├───────────────────┬───────────────────┬────────────────────────────────┤
│      Agents       │      Skills       │           Workflows            │
│    (46 Agents)    │    (42 Skills)    │         (26 Workflows)         │
├───────────────────┴───────────────────┴────────────────────────────────┤
│                   Autonomous Hunter Engine Daemon                      │
│            PriorityDAG Task Queue • Recursive Lead Expansion           │
│             Execution Policy Gateway (6-Stage Verification)            │
│               Container / Subprocess Sandbox Isolation                 │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Findings conforming to
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          Shared Finding Schema                         │
│                         (schemas/finding.md)                           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. What Hermes Must Provide

### 2.1 Pack Discovery & Loading

Hermes loads NIGHTFANG by locating `manifest.yaml` in the pack root. The loader reads:
- `runtime.name == "hermes"` and `runtime.min_version >= "0.2.0"`.
- `runtime.entrypoint.agent`: Path to `AGENTS.md`.
- `capabilities[]`: The 35-capability routing table mapping target classifications to workflows, agents, and skills.

### 2.2 Channel Adaptors (Telegram, Discord, Web, CLI)

NIGHTFANG is completely channel-agnostic. Hermes owns and manages all operator-facing transports. 

**Runtime API exposed to NIGHTFANG:**
- `send_operator_message(content: str)` — Deliver structured findings, progress updates, or approval cards.
- `receive_operator_command() -> str` — Ingest operator replies (`approve <ID>`, `deny <ID>`, `/hunt`, `/queue`, `/stop`).

#### Remote Telegram & Discord Experience:
1. **Autonomous Launch**: The operator sends `/hunt target.corp` or "Nightfang, scan target.corp" on Telegram.
2. **Continuous Background Execution**: Hermes delegates the target to NIGHTFANG's Autonomous Hunter. The engine does **not** stop after each turn. It maintains a background PriorityDAG queue, auto-running passive recon and active scanning.
3. **Non-Blocking Approval Cards**: When an invasive exploit PoC is identified, NIGHTFANG formats an approval card and sends it to Telegram:
   ```text
   ⚠️ [HITL APPROVAL GATE]
   Target: api.target.corp
   Tool: sqlmap (Noise: LOUD)
   Technique: SQL Injection Verification
   Command: sqlmap -u "https://api.target.corp/v1/user?id=1" --batch
   Action: [ APPROVE ] or [ DENY ]
   Reply: approve REQ-9a3b8c
          deny REQ-9a3b8c
   ```
4. **Uninterrupted Parallel Hunting**: While waiting for the operator to tap or text `approve REQ-9a3b8c`, NIGHTFANG **continues scanning other subdomains, ports, and endpoints in parallel**. The assessment never stalls.

### 2.3 Persistent Memory & State Store

Hermes persists engagement state across turns and restarts:
- `engagement.scope`: Authorized domains, CIDRs, and exclusions.
- `engagement.findings[]`: Verified and candidate findings conforming to `schemas/finding.md`.
- `engagement.hitl_queue[]`: Pending approval cards awaiting operator response (`hitl_queue.json`).
- `engagement.crawled_endpoints[]`: Deduplicated routes and assets discovered during execution.
- `engagement.config`: Active autonomy tier, rate limits, and operator identity.

---

## 3. Tiered Autonomy ("Traffic Light" Model)

Hermes and the Execution Policy Gateway enforce 3 configurable autonomy tiers:

| Tier | Behavior | Best Used For |
| :--- | :--- | :--- |
| **`REACTIVE`** | Halts on every active probe (`MODERATE` or `LOUD`) for explicit manual approval. | Sensitive production environments, manual walkthroughs, initial scoping. |
| **`SEMI_AUTONOMOUS` *(Default)*** | Auto-executes GREEN (passive) and YELLOW (moderate scanning) within safe rate limits. Queues RED (exploit PoCs) asynchronously without blocking the swarm. | Autonomous continuous bug hunting via Telegram/Discord. Maximizes finding yield without risking service outages. |
| **`FULL_AUTONOMOUS`** | Auto-executes GREEN, YELLOW, and safe non-destructive RED PoCs within scope boundaries. Protected by SOP-05 destructive command filtering (`rm`, `DROP`, `mkfs`, etc.). | Isolated test environments, capture-the-flag competitions, authorized staging labs. |

---

## 4. Operator Commands in Hermes

When chatting with Hermes (on Telegram, Discord, CLI, or Web), the following commands are registered:

| Command | Syntax | Description |
| :--- | :--- | :--- |
| `/hunt` | `/hunt <target> [--tier TIER]` | Seeds target into PriorityDAG and starts continuous autonomous hunting. |
| `/queue` | `/queue` | Displays current pending tasks, completed jobs, and paused HITL approvals. |
| `/autonomy` | `/autonomy [REACTIVE\|SEMI_AUTONOMOUS\|FULL_AUTONOMOUS]` | Displays or switches the active autonomy tier. |
| `approve` | `approve <REQ_ID>` (or `/go <REQ_ID>`) | Approves a queued exploit action, mints a 5-D token, and resumes execution. |
| `deny` | `deny <REQ_ID>` (or `/hold <REQ_ID>`) | Denies an exploit action, records finding as candidate, and cancels tool invocation. |
| `/scope` | `/scope [view\|set <target>]` | Views or updates authorized engagement boundaries and CIDRs. |
| `/findings` | `/findings` | Summarizes all discovered vulnerabilities with severity and confidence scores. |
| `/report` | `/report [full\|executive]` | Compiles formal executive and technical deliverable markdown reports. |
| `/clean` | `/clean` | Verifies target baseline and deletes all temporary test files/canaries. |
| `/stop` | `/stop` (or `/halt`) | Immediate emergency stop; kills all running processes and subagents. |

---

## 5. Execution Policy Gateway Enforcement

Hermes must never execute security tools or network traffic directly. All tool invocations are proxied through the **Execution Policy Gateway** ([`integration/execution-policy-gateway.md`](execution-policy-gateway.md)):
1. **Stage 1 (Scope & OPSEC)**: Re-validates target against `engagement.scope` before every request.
2. **Stage 2 (Emergency Stop & Deconfliction)**: Checks emergency halt flag and host/port locks.
3. **Stage 3 (Rate Limiting & Backoff)**: Auto-injects rate flags (`-rate 20`, `--max-rate 20`) and executes backoff on 429/503.
4. **Stage 4 (Action Classification & HITL Gate)**: Applies the Autonomy Tier and checks 5-D approval tokens.
5. **Stage 5 (Non-Destructive Safety Filter)**: Blocks destructive commands and tracks artifact canaries.
6. **Stage 6 (Evidence Hashing)**: Captures raw execution streams and computes cryptographic SHA-256 digests (`[EVD-XXXXXX]`).

---

## 6. Model Context Protocol (MCP) Integration & Knowledge Graph Architecture

NIGHTFANG integrates a verified suite of 8 Model Context Protocol (MCP) servers into Hermes, bridging external testing engines, memory systems, threat intelligence feeds, and browser automation directly into the agent runtime:

### 6.1 Verified MCP Servers
1. **Testing & QA Runners**:
   - `mk-qa-master`: Multi-framework QA test runner (`pytest`, `Jest`, `Cypress`, `Go`, `Schemathesis`) with built-in DOM analyzer and QA advisor loop. Invoked via `uvx mk-qa-master`.
   - `security-scanner-mcp`: AST-level static security scanner detecting OWASP Top 10 vulnerabilities, secrets, SQLi, and XSS across AI-generated code and target projects. Invoked via `npx -y security-scanner-mcp`.
2. **Memory & Knowledge Graph**:
   - `codebase-memory-mcp`: AST code intelligence and persistent semantic index for cross-file taint analysis. Invoked via `npx -y codebase-memory-mcp`.
   - `@modelcontextprotocol/server-memory`: Persistent entity-relation knowledge graph memory server. Configured with `MEMORY_FILE_PATH: ~/.hermes/nightfang/memory/knowledge_graph.jsonl` for tracking entities, relations, and observations across multi-turn engagements.
   - `th-memory-mcp`: Adaptive SQLite-backed persistent memory engine with hybrid FTS5 full-text search and vector retrieval. Invoked via `npx -y th-memory-mcp`.
3. **Threat Intelligence & Browser Automation**:
   - `cve-mcp`: Real-time vulnerability intelligence engine with 41 tools across NVD, EPSS, CISA KEV, GHSA, Metasploit, and MITRE ATT&CK. Invoked via `npx -y cve-mcp`.
   - `osint-mcp-server`: Comprehensive OSINT reconnaissance aggregator querying Shodan, Censys, VirusTotal, SecurityTrails, WHOIS, DNS, and crt.sh. Invoked via `npx -y osint-mcp-server`.
   - `playwright` (`@playwright/mcp`): Headless browser automation for dynamic SPA crawling, DOM probing, network event inspection, and failure screenshot capture. Invoked via `npx -y @playwright/mcp@latest --headless`.

### 6.2 Knowledge Graph Persistence
The knowledge graph memory store is initialized at `~/.hermes/nightfang/memory/knowledge_graph.jsonl`. Both `install.sh` and `install.ps1` configure the exact absolute path in `~/.hermes/mcp.json` and ensure parent directory isolation and atomic write safety.
