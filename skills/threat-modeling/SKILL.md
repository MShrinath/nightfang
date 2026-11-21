---
name: threat-modeling
description: STRIDE, PASTA, and LINDDUN threat modeling methodologies for architecture-level security analysis.
version: "2.0"
domain: cybersecurity
subdomain: threat-modeling
tags: [threat-modeling, stride, pasta, linddun, architecture]
mitre_attack: [TA0043]
d3fend_techniques: [D3-AMCA, D3-UEM, D3-NTA]
---

# Threat Modeling

Architecture-level security analysis using STRIDE, PASTA, and LINDDUN methodologies to identify and prioritize threats before implementation begins.

## Methodology

### 1. STRIDE (Microsoft)
Per-threat-type classification for data flow diagrams:

| Category | Description | Mitigation |
| :--- | :--- | :--- |
| **S**poofing | Impersonating a user or system | Authentication, digital signatures |
| **T**ampering | Modifying data in transit or at rest | Integrity checks, encryption, checksums |
| **R**epudiation | Denying actions performed | Audit logs, non-repudiation receipts |
| **I**nformation Disclosure | Exposing sensitive data | Encryption, access controls, data masking |
| **D**enial of Service | Overloading resources | Rate limits, redundancy, CDN |
| **E**levation of Privilege | Gaining higher privileges | Least privilege, RBAC, input validation |

### 2. PASTA (Risk-Based)
Process for threat modeling and risk analysis:

1. **Define Business Objectives** — What needs to be protected?
2. **Define Technical Scope** — Systems, interfaces, data flows.
3. **Decompose & Application Mapping** — DFDs, trust boundaries, data flows.
4. **Threat Analysis** — Enumerate threats per component using STRIDE.
5. **Vulnerability & Weakness Analysis** — Map threats to specific vulnerabilities.
6. **Attack Modeling & Simulation** — Create attack trees for high-risk threats.
7. **Risk Analysis & Prioritization** — Score and rank threats by likelihood × impact.
8. **Residual Risk Assessment** — Evaluate remaining risk after mitigations.

### 3. LINDDUN (Privacy-Focused)
Privacy-specific threat categories:

| Category | Description |
| :--- | :--- |
| **L**inkability | Cross-referencing data across systems |
| **I**dentifiability | Re-identifying anonymous data |
| **N**on-repudiation | Denying actions involving personal data |
| **D**etectability | Detecting the presence of personal data |
| **D**isclosure of Information | Exposing personal data |
| **U**nawareness | Users unaware of data processing |
| **N**on-compliance | Violating privacy regulations |

## Tools

| Tool | Purpose | Command |
| :--- | :--- | :--- |
| `threat-model-cli` | Automated STRIDE analysis | `threat-model --input <DFD> --method STRIDE` |
| `owasp-threat-dragon` | Visual threat modeling | `owasp-threat-dragon --diagram <file>` |
| `Microsoft Threat Modeling Tool` | GUI-based analysis | GUI application |
| `pytm` | Python-based threat modeling | `python pytm.py --target <TARGET>` |

## Output
- Threat model document with DFD, threat catalog, risk matrix, and mitigation plan.
- Prioritized risk register for implementation team.