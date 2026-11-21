---
name: attack-chain
description: Multi-step attack chain formulation, kill chain mapping, compound risk scoring, and attack path visualization.
version: "2.0"
domain: cybersecurity
subdomain: attack-chain-analysis
tags: [attack-chain, kill-chain, correlation, risk-prioritization, exploitation-planning]
mitre_attack: [TA0001, TA0002, TA0003, TA0004, TA0005, TA0006, TA0007, TA0008, TA0009, TA0010, TA0040, TA0043]
d3fend_techniques: [D3-TCA, D3-RCA]
---

# Attack Chain Analysis Skill

Correlates individual vulnerabilities discovered across different agents and phases into coherent, compound attack narratives.

## Core Capabilities

### 1. Cyber Kill Chain Mapping
Map isolated findings into end-to-end compromise paths:

```
[Reconnaissance] ➔ [Weaponization] ➔ [Delivery] ➔ [Exploitation] ➔ [Privilege Escalation] ➔ [Lateral Movement] ➔ [Objectives]
```

| Phase | Common Discovered Findings |
| :--- | :--- |
| **Reconnaissance** | Exposed `.git`, WHOIS disclosures, subdomains, open ports |
| **Initial Access** | Web/API injection (SQLi, SSTI), public default credentials, unauthenticated upload |
| **Execution** | Command injection, deserialization RCE, agent tool abuse |
| **Privilege Escalation**| Sudo misconfiguration, weak token generation, BOLA to admin API |
| **Lateral Movement** | Internal SSRF to metadata service, extracted database credentials |
| **Objectives** | Production database exfiltration, host takeover |

### 2. Connection Analysis Process
1. **Inventory**: Collect all findings recorded adhering to `schemas/finding.md`.
2. **Link Formulation**: Identify prerequisite-to-enabler relationships:
   - *Finding A (Information Leak)* exposes internal API tokens.
   - *Finding B (SSRF)* enables reaching the internal API endpoint.
   - *Finding C (Admin Endpoint)* accepts the leaked tokens to grant administrative privileges.
3. **Chain Prioritization Formula**:
   Prioritize candidate chains using the weighted score:
   $$\text{Priority Score} = (\text{Max Severity} \times 0.6) + (\text{Min Confidence} \times 0.4) - (\text{Step Count} \times 0.2)$$

### 3. Visualization Standard
Construct Mermaid diagrams illustrating the full kill chain sequence:

```mermaid
graph LR
    A["Step 1: SSRF via Webhook (NF-001)"] -->|Accesses Internal IMDS| B["Step 2: Temporary IAM Credentials (NF-002)"]
    B -->|Grants S3 Admin| C["Step 3: Exfiltration of Production Data (NF-003)"]
```

## Output
- Compound attack chain objects.
- Visual Mermaid diagrams ready for final reporting.

## Payload Integration (scripts/agent_payloads.py)
Attack-chain agents SHOULD use `AgentPayloadResolver` to enrich chain steps with validated payloads:
```python
from scripts.agent_payloads import AgentPayloadResolver
resolver = AgentPayloadResolver()

# For each finding in a chain, map CWE/OWASP to available payloads
# Example: Chain step shows CWE-89 (SQLi) -> pull actual payloads for verification
sql_payloads = resolver.get_by_cwe("CWE-89")

# For destructive steps requiring HITL approval, fetch full payload catalog
rce_payloads = resolver.get_destructive_payloads("Command Injection")
deserial_payloads = resolver.get_destructive_payloads("Insecure Deserialization")

# Safe validation payloads for non-destructive proof
ssti_payloads = resolver.get_safe_payloads("Server Side Template Injection")
```
CLI for operator review:
```bash
python scripts/payload_lookup.py --cwe CWE-89           # All SQLi payloads (destructive)
python scripts/payload_lookup.py --cwe CWE-94 --safe-only  # Safe SSTI only
python scripts/payload_lookup.py --owasp A03:2021       # All injection-class payloads
```
