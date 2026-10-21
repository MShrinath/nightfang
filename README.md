# NIGHTFANG

NIGHTFANG is a modular, autonomous security capability pack that transforms the **Hermes** host runtime into an advanced, continuous penetration testing and vulnerability hunting engine.

When installed into Hermes, NIGHTFANG infuses Hermes with its security persona, 37 specialized agents, 33 registered capabilities, 17 workflows, 31 skills, the 6-stage Execution Policy Gateway, and the background Autonomous Hunter Daemon. Whether interacting via **Telegram, Discord, Web UI, or CLI**, the operator communicates directly with NIGHTFANG.

---

## Architecture & Integration Flow

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
│    (37 Agents)    │    (31 Skills)    │         (17 Workflows)         │
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

**Authorization / Scope Gate** and **Execution Policy Gateway** are enforced at runtime — they are not conceptual labels. No capability may be routed and no tool may be invoked if either gate is not satisfied.

---

## Autonomous Execution Core

NIGHTFANG eliminates stuttering, turn-by-turn halts through four foundational subsystems:

1. **PriorityDAG Lead Queue**: Pending tasks are managed in a Directed Acyclic Graph with priority min-heap semantics (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFORMATIONAL`). Prerequisite scans automatically unblock downstream validation.
2. **Recursive Lead Generator**: Reconnaissance and scanning outputs are continuously parsed for newly uncovered subdomains, exposed HTTP endpoints, API schemas, and open ports, dynamically feeding downstream specialized agents without manual prompting.
3. **Self-Healing Reflection**: Catches HTTP `429 Too Many Requests`, `503 Service Unavailable`, and WAF triggers in real-time, pauses target traffic for 30s, halves target rate ceilings, and re-queues failed tasks with exponential backoff.
4. **Non-Blocking Asynchronous HITL Queue**: Exploit PoCs requiring operator authorization are suspended into `hitl_queue.json` while the background hunter **continues scanning other targets and endpoints in parallel**.

### The 3 Autonomy Tiers ("Traffic Light" Model)

Configured in `adapters/hermes/config.yaml` or dynamically toggled via `/autonomy`:

- **`REACTIVE`**: Halts on every active probe (`MODERATE` or `LOUD`) for explicit manual operator confirmation.
- **`SEMI_AUTONOMOUS` *(Default)***: Automatically approves and executes all GREEN (passive OSINT) and YELLOW (moderate scanning/crawling) tasks under safe rate limits. Emits non-blocking approval cards only for RED (exploit PoCs or invasive tests).
- **`FULL_AUTONOMOUS`**: Automatically runs GREEN, YELLOW, and safe non-destructive RED PoCs within scope boundaries, guarded by the SOP-05 destructive payload filter.

---

## Operator Interface & "Approve / Deny" Protocol

When an invasive action requires approval, NIGHTFANG emits a structured card formatted for the active channel (Telegram, Discord, Web, CLI):

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

- **Approve**: Operator replies `approve REQ-9a3b8c` (or `/go REQ-9a3b8c`). The Gateway mints an unforgeable 5-dimensional token and immediately dispatches the task.
- **Deny**: Operator replies `deny REQ-9a3b8c` (or `/hold REQ-9a3b8c`). The action is aborted and recorded as an unvalidated candidate.
- **Non-blocking**: The hunter continues discovering other assets in the background while awaiting your response.

---

## Operator Command Quick Reference

| Command | Usage | Description |
| :--- | :--- | :--- |
| `/hunt` | `/hunt <target> [--tier TIER]` | Seeds target and launches autonomous continuous hunting loop |
| `/queue` | `/queue` | Displays pending tasks, completed jobs, and paused HITL approvals |
| `/autonomy` | `/autonomy [TIER]` | Checks or switches active autonomy tier |
| `approve` | `approve <REQ_ID>` | Approves queued exploit task (alias: `/go <REQ_ID>`) |
| `deny` | `deny <REQ_ID>` | Cancels queued exploit task (alias: `/hold <REQ_ID>`) |
| `/scope` | `/scope [view\|set <target>]` | Inspects or configures authorized targets and CIDRs |
| `/findings` | `/findings` | Displays table of discovered vulnerabilities with confidence & severity |
| `/report` | `/report [full\|executive]` | Generates comprehensive markdown report deliverable |
| `/clean` | `/clean` | Triggers artifact and test canary verification & cleanup |
| `/stop` | `/stop` | Immediate emergency halt for all active scans and subagents |

---

## Fast Installation into Hermes

To install NIGHTFANG directly into Hermes so Hermes operates as NIGHTFANG:

### Linux / macOS
```bash
git clone https://github.com/your-org/nightfang.git
cd nightfang
./install/install.sh
```

### Windows (PowerShell)
```powershell
git clone https://github.com/your-org/nightfang.git
cd nightfang
powershell -ExecutionPolicy Bypass -File install\install.ps1
```

### Verify Status
```powershell
powershell -ExecutionPolicy Bypass -File install\status.ps1
# Status: NIGHTFANG IS FULLY OPERATIONAL IN HERMES
```

---

## 37 Specialized Agents (Taxonomy)

NIGHTFANG deploys **37 specialized agents** across two operational tiers:

### 1. Direct Entrypoint Agents (28 Agents)
Cover all 33 registered capabilities from `manifest.yaml`:
- **`supervisor`**: Dynamic orchestration, recursive decomposition, task replanning, and loop prevention.
- **`recon`**: Domain enumeration, WHOIS/DNS OSINT, attack surface mapping, and initial access delivery staging.
- **`scanner`**: Web vulnerability analysis, API discovery, and network port/service scanning.
- **`validation`**: Benign exploit PoC verification, 5-D HITL token enforcement, and canary cleanup.
- **`reporter`**: Executive deliverable compilation and risk communication.
- **`cloud-security`**: Multi-cloud IAM, storage permissions, and IMDS SSRF audits (AWS/Azure/GCP).
- **`container-breakout`**: Container escape checks, Kubernetes RBAC audits, and namespace isolation.
- **`cicd-redteam`**: CI/CD pipeline poisoning, runner isolation, and secrets exposure testing.
- **`ad-attacker`**: Active Directory enumeration, Kerberoasting, and ADCS certificate template abuse.
- **`wireless-pentester`**: 802.11 WiFi, BLE GATT, and RF protocol analysis.
- **`mobile-pentester`**: Android and iOS mobile application static/dynamic assessment (OWASP MASVS).
- **`iot-pentester`**: Embedded firmware extraction, hardware bus debugging (UART/JTAG/SPI).
- **`scada-attacker`**: ICS/SCADA and operational technology testing (Modbus, S7comm, IEC 62443).
- **`crypto-analyzer`**: Cryptographic protocol auditing, TLS verification, and JWT manipulation.
- **`privesc-advisor`**: Host privilege escalation (Linux SUID/capabilities & Windows LSASS/DPAPI).
- **`lateral-movement`**: Internal pivoting, pass-the-hash, WMI/WinRM lateral movement, and data exfiltration testing.
- **`forensics-analyst`**: Volatility3 memory triage, artifact timeline construction, and incident forensics.
- **`supply-chain-auditor`**: Software supply chain auditing, CycloneDX/SPDX SBOM generation, and dependency confusion.
- **`compliance-mapper`**: Regulatory crosswalks (NIST CSF 2.0, ISO 27001, SOC 2, PCI-DSS, CIS Controls).
- **`cti-analyst`**: Cyber threat intelligence synthesis, Diamond Model attribution, and STIX 2.1 IOC extraction.
- **`purple-team-operator`**: Adversary emulation, MITRE ATT&CK matrix validation, and defensive tuning loops.
- **`ai-security`**: Adversarial LLM testing, prompt injection, MCP server security, and tool-use auditing.
- **`engagement-planner`**: Scope boundary definition, ROE validation, and schedule planning.
- **`evasion-specialist`**: Defense evasion, AMSI/ETW bypass analysis, and EDR resilience evaluation.
- **`c2-operator`**: Covert command-and-control simulation, malleable profiles, and egress analysis.
- **`reverse-engineer`**: Binary disassembly, decompilation, and proprietary protocol dissection.
- **`database-attacker`**: Relational and NoSQL database security, privilege escalation, and injection auditing.
- **`social-engineer`**: Authorized phishing template design, credential harvest simulation, and awareness testing.

### 2. Delegated Specialist Agents (9 Agents)
Invoked downstream by workflows or primary agents for specialized lifecycle sub-tasks:
- **`detection-engineer`**: Authors machine-readable Sigma rules, Sentinel KQL queries, and Splunk SPL logic.
- **`threat-modeler`**: STRIDE/PASTA architectural threat modeling prior to active testing.
- **`code-auditor`**: Static application security testing (SAST) and sink-to-source taint tracking.
- **`risk-scorer`**: Formulaic CVSS v3.1/v4.0 vector computation and EPSS feed queries.
- **`fix-verifier`**: Post-remediation regression testing and patch efficacy validation.
- **`malware-analyst`**: Suspicious binary triage, behavioral dissection, and YARA rule generation.
- **`payload-crafter`**: Synthesizes benign, non-destructive proof-of-concept verification payloads.
- **`traffic-analyzer`**: PCAP network traffic dissection and covert beaconing detection.
- **`opsec-anonymizer`**: Egress proxy validation, multi-hop routing, and network deconfliction.

---

## 31 Security Skills

Located in `skills/`, loaded on-demand:
`recon`, `web`, `api`, `network`, `cloud`, `container`, `cicd`, `active-directory`, `wireless`, `mobile`, `iot`, `ot-ics`, `crypto`, `forensics`, `supply-chain`, `grc`, `cti`, `purple-team`, `privilege-escalation`, `post-exploitation`, `ai-security`, `hunting`, `attack-chain`, `remediation`, `reporting`, `utility`, `defense-evasion`, `c2-operations`, `initial-access`, `credential-access`, `reverse-engineering`.

---

## 17 Execution Workflows

Located in `workflows/`:
1. `dynamic-supervision.md`: Autonomous dynamic 4-step loop (Decompose $\to$ Dispatch $\to$ Execute $\to$ Reflect).
2. `standard-pentest.md`: Full 10-phase enterprise penetration test.
3. `web-assessment.md`: Dedicated web application assessment.
4. `api-assessment.md`: REST, GraphQL, and gRPC security audit.
5. `cloud-assessment.md`: Multi-cloud, container, and Kubernetes audit.
6. `ad-assessment.md`: Active Directory, Kerberos, and ADCS audit.
7. `ai-security-assessment.md`: LLM, agentic tool-use, and MCP server evaluation.
8. `purple-team.md`: Adversary emulation and detection engineering cycle.
9. `cicd-assessment.md`: CI/CD pipeline and supply chain build security.
10. `mobile-assessment.md`: Android and iOS mobile app assessment (MASVS).
11. `wireless-assessment.md`: 802.11 WiFi, BLE, and RF auditing.
12. `iot-ics-assessment.md`: Safety-first IoT and ICS/SCADA operational technology testing.
13. `supply-chain-assessment.md`: Software supply chain, SBOM, and dependency audit.
14. `bug-bounty.md`: Fast-paced vulnerability hunting on web and API targets.
15. `red-team.md`: Full-scope multi-stage adversary simulation and covert egress testing.
16. `reverse-engineering.md`: Binary analysis, protocol reverse engineering, and disassembly.
17. `social-engineering.md`: Authorized phishing, payload delivery simulation, and awareness assessment.

---

## Automated Verification Suite

NIGHTFANG includes built-in automated test suites across all core subsystems:

```powershell
# Run the complete test suite
.\nightfang.cmd --test
```

- **Execution Policy Gateway** (`tools/gateway.py`): 9 self-tests validating scope checks, OPSEC enforcement, emergency stop, rate injection, 5-D HITL token validation, destructive payload filtering, and rate ceilings.
- **Autonomous Hunter Daemon** (`tools/daemon.py`): 5 self-tests validating priority queue ordering, semi-autonomous execution, non-blocking HITL queueing, token resumption, and self-healing rate backoff.
- **Finding Schema Validator** (`schemas/validator.py`): 2 self-tests validating complete findings and catching 24 schema violations on malformed records.
- **Sandbox Runner** (`tools/sandbox.py`): 2 self-tests validating subprocess fallback, process containment, and timeout termination.
