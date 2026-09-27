---
name: grc
description: Governance, Risk, and Compliance (GRC) skill covering multi-framework crosswalks (NIST CSF 2.0, ISO 27001:2022, SOC 2, CIS Controls v8, PCI-DSS v4.0), risk scoring, gap analysis, and audit evidence compilation.
domain: cybersecurity
subdomain: grc-compliance
tags: [grc, compliance, nist-csf, iso27001, soc2, cis-controls, pci-dss, audit]
mitre_attack: []
d3fend_techniques: [D3-GAC, D3-PAC]
version: "1.0"
---

# Governance, Risk, & Compliance (GRC) Skill

Methodology for mapping technical penetration testing findings, configuration gaps, and architectural weaknesses into regulatory compliance frameworks and executive risk registers.

## Master Framework Crosswalk

| Category | NIST CSF 2.0 | ISO 27001:2022 | SOC 2 Type II | CIS Controls v8 | PCI-DSS v4.0 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Asset Management** | `ID.AM` | `A.5.9`, `A.8.1` | CC6.1 | Control 1, Control 2 | Req 2.4, Req 9.1 |
| **Identity & Access** | `PR.AA`, `PR.AC` | `A.5.15`, `A.9.2` | CC6.2, CC6.3 | Control 5, Control 6 | Req 7.1, Req 8.2 |
| **Data Protection** | `PR.DS` | `A.8.20`, `A.8.24` | CC6.7 | Control 3 | Req 3.1, Req 4.1 |
| **Vulnerability Mgt** | `DE.CM`, `RS.MI` | `A.8.8` | CC7.1 | Control 7 | Req 6.3, Req 11.3 |
| **Network Security** | `PR.IR` | `A.8.20`, `A.8.22` | CC6.6 | Control 12 | Req 1.1, Req 2.1 |
| **Incident Response** | `RS.MA`, `RS.AN` | `A.5.24` → `A.5.28`| CC7.3, CC7.4 | Control 17 | Req 12.10 |

## Methodology

### 1. Finding-to-Compliance Mapping
- For every technical finding generated during testing, extract affected asset category.
- Map finding directly to the corresponding clause and requirement across all active organizational frameworks.
- Determine compliance status: `COMPLIANT`, `PARTIALLY_COMPLIANT`, or `NON_COMPLIANT`.

### 2. Quantitative & Qualitative Risk Scoring
- **Qualitative Risk**: Evaluate Threat Event Frequency (TEF) and Vulnerability Severity (Loss Event Frequency vs Loss Magnitude) using the FAIR framework.
- **Annualized Loss Expectancy (ALE)**:
  $$\text{ALE} = \text{Single Loss Expectancy (SLE)} \times \text{Annualized Rate of Occurrence (ARO)}$$
- Highlight non-compliant controls that jeopardize certification (e.g. failing PCI-DSS Requirement 6.2 for Critical CVEs).

### 3. Gap Analysis & Remediation Plan of Action and Milestones (POA&M)
- Formulate concrete POA&M milestones with assigned ownership, target closure dates, and resource requirements.
- Distinguish between compensating controls, policy updates, and direct technical fixes.

## Output
- Cross-framework compliance matrix and executive risk register.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
