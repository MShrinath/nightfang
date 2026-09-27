# NIGHTFANG

NIGHTFANG is a modular, host-agnostic security capability pack designed to run on top of an agent host runtime (Hermes).

---

## Architecture

```
                   Hermes
                      │
                      ▼
             ┌─────────────────┐
             │ Nightfang Intake│
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │ Authorization / │
             │  Scope Gate     │   ← SOP-01: target verified before anything runs
             └────────┬────────┘
                      │
                      ▼
             ┌─────────────────┐
             │  Capability     │
             │  Router         │   ← manifest.yaml capabilities[] → workflow/agent/skill
             └────────┬────────┘
                      │
               Workflow / Agent
                      │
                      ▼
                    Skill
                      │
                      ▼
             ┌─────────────────┐
             │  Execution      │
             │  Policy Gateway │   ← rate limits, HITL trigger, PoC safety
             └────────┬────────┘
                      │
                  Active?
                 /       \
               no         yes
               │            │
               ▼          /go
             Tool            │
               │          Validation Agent
               └─────┬──────┘
                     ▼
                  Result
                     │
                     ▼
                  Finding        ← schemas/finding.md
                     │
                     ▼
                 Reporter
                     │
                     ▼
                  Hermes         ← configured channel (CLI, Telegram, Discord, Web)
```

**Authorization / Scope Gate** and **Execution Policy Gateway** are enforced at runtime — they are not conceptual labels. No capability may be routed and no tool may be invoked if either gate is not satisfied.

---

## Capability Router vs. Execution Policy Gateway

These are two distinct security enforcement points. Do not conflate them.

| | Capability Router | Execution Policy Gateway |
| :--- | :--- | :--- |
| **Triggered by** | Incoming operator request (target + task) | A skill requesting tool invocation |
| **Input** | Target type classification | Proposed tool action |
| **Governs** | Which workflow, agent, and skills handle the request | Whether the tool may run, at what rate, and if HITL approval is required |
| **Source of truth** | `manifest.yaml` → `capabilities[]`, [`integration/capability-router.md`](integration/capability-router.md) | `references/sops.md`, [`integration/execution-policy-gateway.md`](integration/execution-policy-gateway.md) |
| **Output** | Dispatched workflow + agent + skill list | Approved tool execution or HITL pause |

---

## Terminology

These terms have precise meanings in this codebase. Do not treat them as interchangeable.

| Term | Definition |
| :--- | :--- |
| **Agent** | A decision-making role with defined responsibility, trigger conditions, and input/output contract. Agents decide *what* to do and *when* to do it. |
| **Skill** | A reusable security procedure. Skills define *how* to test for a class of vulnerability. They are loaded on-demand by agents. |
| **Workflow** | An execution state machine. Workflows define *in what order* phases and agents are activated across an engagement lifecycle. |
| **Tool** | An external executable or API invoked by a skill (e.g., nmap, sqlmap, ffuf, curl). Tools represent the actual execution boundary where network traffic is generated. |
| **Schema** | A structured data contract. All findings produced by any agent must conform to `schemas/finding.md`. |
| **Reference** | A policy or knowledge document (SOPs, heuristics, framework mappings). References govern what agents are *allowed* to do and how they should classify what they find. |
| **Template** | A presentation format. Templates define how findings and reports are rendered into operator-facing deliverables. |

---

## Execution Pipeline

```text
User Request (target + scope)
         ↓
Hermes invokes NIGHTFANG
         ↓
Authorization / Scope Gate
   └── Target in-scope? → proceed
   └── Out-of-scope?    → halt immediately
         ↓
Capability Router reads manifest.yaml capabilities[]
   └── Classifies target type
   └── Selects matching capability (id, workflow, agent, skills[])
   └── Ambiguous match? → ask operator to confirm before routing
         ↓
Agent delegated (WHO: Recon / Scanner / AI-Security / Validation / Reporter)
         ↓
Skill invoked on-demand (HOW: web, api, network, cloud, ai-security, …)
         ↓
Execution Policy Gateway evaluates each tool invocation:
   └── Rate limit: operator-defined → 20 req/sec default → target-adjusted → auto-backoff
   └── HITL trigger: passive action → continue; active action → pause for /go
   └── PoC safety: benign only; DoS/backdoor/data-alter strictly prohibited
         ↓
Tool executed (external executable or API)
         ↓
Finding formulated per schemas/finding.md:
   Confidence 1–10      (certainty the vuln is real)
   Severity   1–10      (potential impact if exploited)
   Grounding  0.55–0.95 (evidentiary reproducibility bucket)
   CVSS v3.1 / v4.0     (computed from vector after validation; not derived from Severity)
         ↓
Benign PoC executed (if HITL approved) → artifact cleanup verified
         ↓
Validation Gate evaluated (Q1-Q7 adversarial criteria → PASS / KILL / DOWNGRADE)
         ↓
Reporter compiles executive + technical deliverables
         ↓
Hermes delivers to configured channel
```

---

## Dual Ranking & Scoring Dimensions

Every finding carries five independent, non-interchangeable evaluation metrics:

**1. Confidence (1–10)** — How certain is NIGHTFANG that this vulnerability is real and reproducible?

| Range | Level | Meaning |
| :--- | :--- | :--- |
| 1–3 | Theoretical | Inferred from version banner or OSINT; no behavioral verification |
| 4–6 | Likely | Anomalous behavior or reflection observed; payload not yet proven |
| 7–9 | Confirmed | Verified via benign non-destructive PoC |
| 10 | Demonstrated | Fully exploited with demonstrated access under HITL approval |

**2. Severity (1–10)** — How bad would it be if this vulnerability were exploited?

| Range | Level | Meaning |
| :--- | :--- | :--- |
| 1–2 | Informational | No direct exploit path; best-practice deviation |
| 3–4 | Low | Minimal impact; requires high interaction or constrained prerequisites |
| 5–6 | Medium | Realistic attack path; moderate impact |
| 7–8 | High | Significant compromise; privilege escalation or sensitive data access |
| 9–10 | Critical | Full system takeover, unauthenticated RCE, or mass data exfiltration |

**3. Evidence Grounding Index (0.55–0.95)** — Mathematical evidentiary grounding bucket:
- `0.95 CERTAIN`: Complete raw request/response proof with SHA-256 hash.
- `0.85 STRONG`: High-fidelity execution log or tool artifact confirming sink interaction.
- `0.75 PROBABLE`: Consistent behavioral anomaly, timing differential, or reflection.
- `0.65 TENTATIVE`: Indirect indication, blind time-based anomaly with network jitter.
- `0.55 WEAK`: Theoretical or inferred from version banner or passive OSINT.

**4. CVSS v3.1 / v4.0 Base Score (0.0–10.0)** is computed separately after validation from the vector string (AV/AC/PR/UI/S/C/I/A). It is not derived from the Nightfang Severity score and must not be treated as equivalent.

**5. EPSS (0.000–1.000)** provides empirical exploit probability from the EPSS model feed.

---

## HITL Approval Token Security

The `/go [ID]` and `/hold [ID]` commands are not generic tokens. Each approval is scoped to a specific, bounded action:

| Dimension | What it binds |
| :--- | :--- |
| **Engagement ID** | Approval is valid only within the current engagement session |
| **Operator identity** | Only the operator who initiated the engagement may approve |
| **Finding ID** | Approval authorizes one specific finding's validation action |
| **Proposed action** | The exact technique and target endpoint stated in the HITL request |
| **Expiration** | Approval expires if not acted upon within the operator-defined timeout window |

An approval of finding `NF-2026-0042` does not authorize any other action. If the validation agent needs to attempt a different technique or target a different endpoint, a new HITL request must be raised.

---

## Repository Structure

```
nightfang/
├── AGENTS.md                  # Constitution: identity, safety rules, routing & delegation
├── manifest.yaml              # Hermes integration contract & Capability Router (24 capabilities)
│
├── agents/                    # WHO (Decision-making roles)
│   ├── recon.md               # Asset discovery & reconnaissance
│   ├── scanner.md             # Vulnerability enumeration & weakness discovery
│   ├── ai-security.md         # AI, LLM & MCP security testing
│   ├── validation.md          # Exploit PoC & impact verification (HITL-gated)
│   ├── reporter.md            # Findings synthesis & deliverable compilation
│   ├── ad-attacker.md         # Active Directory & Kerberos/ADCS security
│   ├── cloud-security.md      # Multi-cloud infrastructure security (AWS/Azure/GCP)
│   ├── container-breakout.md  # Container runtime & Kubernetes cluster security
│   ├── cicd-redteam.md        # CI/CD workflow & pipeline security
│   ├── mobile-pentester.md    # Android & iOS mobile app assessment (MASVS)
│   ├── wireless-pentester.md  # 802.11 WiFi, BLE, and RF security
│   ├── iot-pentester.md       # Embedded firmware, hardware, and IoT protocols
│   ├── scada-attacker.md      # ICS/SCADA and operational technology (Purdue model)
│   ├── crypto-analyzer.md     # Cryptographic protocols, ciphers, and PQC readiness
│   ├── forensics-analyst.md   # Digital forensics, memory analysis, and YARA rules
│   ├── supply-chain-auditor.md# Software supply chain, SBOM, and SLSA provenance
│   ├── compliance-mapper.md   # Regulatory compliance mapping (NIST/ISO/SOC2/CIS/PCI)
│   ├── cti-analyst.md         # Threat intelligence, STIX 2.1, and attribution
│   ├── purple-team-operator.md# Purple team emulation & detect-tune-validate loop
│   ├── detection-engineer.md  # Defensive detection engineering (Sigma/KQL/SPL)
│   ├── threat-modeler.md      # Architecture review & threat modeling (STRIDE/PASTA)
│   ├── privesc-advisor.md     # Host privilege escalation analysis (Linux/Windows)
│   ├── lateral-movement.md    # Internal network pivoting & lateral movement
│   ├── code-auditor.md        # Static application security testing (SAST)
│   ├── risk-scorer.md         # Multi-metric risk scoring (CVSS/EPSS/KEV)
│   ├── fix-verifier.md        # Remediation verification & regression testing
│   └── engagement-planner.md  # Scope governance & engagement orchestration
│
├── skills/                    # HOW (Security procedures, loaded on-demand)
│   ├── recon/                 # OSINT, DNS & network discovery
│   ├── web/                   # Web application testing & injection checklists
│   ├── api/                   # API security testing (REST, GraphQL, gRPC)
│   ├── network/               # Network service auditing, SMB, SNMP, SSL/TLS
│   ├── cloud/                 # Cloud storage, IMDS SSRF, and IAM policies
│   ├── container/             # Container escape & Kubernetes RBAC audits
│   ├── cicd/                  # Workflow poisoning, runner isolation, secrets
│   ├── active-directory/      # Kerberos (Roasting), ADCS templates, BloodHound
│   ├── wireless/              # 802.11 WPA2/WPA3, Enterprise, BLE GATT
│   ├── mobile/                # Android/iOS static/dynamic (Frida), MASVS v2.0
│   ├── iot/                   # Firmware extraction, hardware buses (UART/JTAG/SPI)
│   ├── ot-ics/                # Purdue model, Modbus, S7comm, IEC 62443
│   ├── crypto/                # TLS auditing, JWT tampering, padding oracles
│   ├── forensics/             # Volatility3 memory, Plaso timeline, disk artifacts
│   ├── supply-chain/          # Syft SBOM (SPDX/CycloneDX), dependency confusion
│   ├── grc/                   # Multi-framework compliance crosswalks & ALE scoring
│   ├── cti/                   # Intelligence cycle, STIX 2.1, Diamond Model, TLP
│   ├── purple-team/           # Atomic Red Team emulation, DeTT&CT, MTTD
│   ├── privilege-escalation/  # Linux (SUID/caps/sudo) & Windows (tokens/services)
│   ├── post-exploitation/     # Lateral movement (PtH/WMI), pivoting, egress/DLP
│   ├── ai-security/           # Adversarial LLM, prompt injection, MCP audits
│   ├── hunting/               # Logic flaws, race conditions (TOCTOU), HPP
│   ├── attack-chain/          # Kill chain correlation & priority scoring
│   ├── remediation/           # Tri-tier remediation, Sigma rules, SLAs
│   ├── reporting/             # Finding deduplication & deliverable compilation
│   └── utility/               # Rapid triage checklists & engagement memory
│
├── workflows/                 # IN WHAT ORDER (Execution state machines)
│   ├── standard-pentest.md    # 10-phase standard penetration test
│   ├── web-assessment.md      # Targeted web application assessment
│   ├── api-assessment.md      # Dedicated API security audit
│   ├── ai-security-assessment.md # LLM, tool-use & MCP security test
│   ├── ad-assessment.md       # Active Directory & Kerberos/ADCS audit
│   ├── cloud-assessment.md    # Multi-cloud, container, and Kubernetes audit
│   ├── mobile-assessment.md   # Mobile application security assessment (MASVS)
│   ├── wireless-assessment.md # Wireless & RF security assessment
│   ├── cicd-assessment.md     # CI/CD pipeline and build security audit
│   ├── purple-team.md         # Adversary emulation & detection engineering loop
│   ├── iot-ics-assessment.md  # Safety-first IoT & SCADA/OT assessment
│   ├── supply-chain-assessment.md # Software supply chain & SBOM audit
│   └── bug-bounty.md          # Targeted web/API vulnerability hunting
│
├── schemas/                   # WHAT DATA (Structured data contracts)
│   └── finding.md             # Unified finding schema (with blue, CVE, CTI, ICS)
│
├── references/                # UNDER WHAT RULES (Policy & knowledge)
│   ├── sops.md                # Standard Operating Procedures (SOP-01 to SOP-07)
│   ├── heuristics.md          # Multi-metric scoring, triage, variant hunting, fallbacks
│   ├── tools.md               # External tool inventory & fallback matrix
│   └── framework_mappings.md  # ATT&CK, NIST CSF 2.0, D3FEND, ATLAS, OWASP, IEC 62443
│
├── integration/               # Hermes integration contract
│   ├── hermes.md              # What Hermes must provide & what Nightfang contracts to deliver
│   ├── routing.md             # Capability Router: how capabilities[] is applied at runtime
│   ├── capability-router.md   # Capability Router: executable dispatch specification
│   ├── execution-policy-gateway.md # Execution Policy Gateway: 6-stage runtime enforcement spec
│   └── lifecycle.md           # Full 12-phase engagement lifecycle & state machine
│
└── templates/                 # HOW TO PRESENT (Deliverable formats)
    ├── full_report_template.md # Master executive & technical report (with compliance/purple)
    └── finding_template.md     # Individual technical finding walkthrough (with Sigma/KQL)
```

---

## Loading with Hermes

1. Place `nightfang/` in Hermes's capability pack directory.
2. Hermes reads `manifest.yaml`, validates the runtime contract, and registers the **Capability Router** from `capabilities[]`.
3. Hermes initializes engagement memory (`engagement.scope`, `engagement.findings[]`, `engagement.config`).
4. Initiate an engagement via any configured Hermes channel:
   ```
   /engage target=https://target-app.internal scope=10.0.0.0/24 workflow=standard-pentest
   ```
5. During active validation phases, respond to HITL approval requests:
   ```
   /go [ID]    — approve the specific bounded action for finding [ID]
   /hold [ID]  — record as candidate; do not proceed with active validation
   /stop       — halt all active agents immediately
   ```

See [`integration/hermes.md`](integration/hermes.md) for the full Hermes loader contract.
