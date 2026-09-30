---
name: cti
description: Cyber Threat Intelligence (CTI) skill covering the intelligence cycle, IOC normalization and defanging, STIX 2.1/MISP exports, threat actor attribution, TLP markings, and Diamond Model analysis.
version: "2.0"
domain: cybersecurity
subdomain: threat-intelligence
tags: [cti, threat-intel, stix, misp, ioc, attribution, diamond-model, tlp]
mitre_attack: [TA0043, TA0042]
d3fend_techniques: [D3-IOC, D3-TIP]
---

# Cyber Threat Intelligence (CTI) Skill

Methodology for collecting, normalizing, analyzing, and disseminating actionable threat intelligence.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `misp-cli` | Query MISP instances for threat events and attributes | Python `pymisp` query | MISP REST API |
| `stix2` | Python library for serializing STIX 2.1 objects | Python script | Manual JSON formatting |
| `ioc-extractor` | Automated extraction and defanging of IOCs | Regex / Python | CyberChef recipe |

## Methodology

### 1. The Intelligence Cycle & Priority Intelligence Requirements (PIRs)
- **Planning & Direction**: Establish PIRs aligned with engagement scope (e.g. "What threat actors actively target this cloud infrastructure or financial sector?").
- **Collection**: Ingest feeds, OSINT feeds, AlienVault OTX, CISA KEV, and telemetry.
- **Processing**: Defang IOCs (`hxxp://`, `192[.]168[.]1[.]1`), remove duplicates, and calculate cryptographic hashes.

### 2. Analytical Frameworks
- **The Diamond Model of Intrusion Analysis**:
  - Core nodes: Adversary $\leftrightarrow$ Infrastructure $\leftrightarrow$ Capability $\leftrightarrow$ Victim.
  - Establish meta-features: Phase, Result, Direction, Methodology, Resources.
- **MITRE ATT&CK Mapping**: Map observed adversary behaviors directly to ATT&CK technique IDs and sub-techniques.
- **Admiralty Scale (Source Reliability & Information Credibility)**:
  - Reliability: A (Completely reliable) to F (Cannot be judged).
  - Credibility: 1 (Confirmed by other sources) to 6 (Truth cannot be judged).

### 3. Traffic Light Protocol (TLP 2.0) Handling
- Enforce strict TLP handling across all intelligence outputs:
  - **TLP:RED**: Restricted only to the individual recipient.
  - **TLP:AMBER+STRICT**: Restricted to the customer organization only.
  - **TLP:AMBER**: Restricted to the organization and trusted partners on need-to-know basis.
  - **TLP:GREEN**: Shareable within the relevant sector/community.
  - **TLP:CLEAR**: Publicly shareable.

### 4. STIX 2.1 Serialization
- Format all discovered threat data into standard STIX 2.1 objects: `indicator`, `attack-pattern`, `threat-actor`, `malware`, `relationship`.

## Output
- CTI threat brief, normalized IOC package, and STIX 2.1 JSON bundle.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
