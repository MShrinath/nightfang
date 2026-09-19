---
name: attack-chain-analysis
description: >-
  Use this skill for building and analyzing multi-step attack chains.
  Correlates individual findings into complete attack narratives,
  maps kill chains, assesses cumulative risk, and identifies the
  most impactful attack paths. Activate after multiple findings have
  been discovered to identify compound risks.
---

# Attack Chain Analysis

Correlate individual findings into complete attack narratives.

## Kill Chain Mapping

Map findings to the Cyber Kill Chain:

```
1. RECONNAISSANCE → Asset discovery, OSINT findings
2. WEAPONIZATION → Payload crafting based on vulns found
3. DELIVERY → Attack vector identification
4. EXPLOITATION → Vulnerability exploitation
5. INSTALLATION → Persistence mechanisms
6. COMMAND & CONTROL → Communication channels
7. ACTIONS ON OBJECTIVES → Impact demonstration
```

## Chain Building Process

### Step 1: Finding Inventory
Collect all individual findings with their scores:
```
F1: Information Disclosure (Conf: 9, Sev: 3)
F2: SSRF (Conf: 7, Sev: 6)
F3: AWS Metadata Access via SSRF (Conf: 6, Sev: 8)
F4: IAM Key Extraction (Conf: 5, Sev: 9)
```

### Step 2: Connection Analysis
Identify how findings connect:
```
F1 → reveals internal architecture
  → enables F2 (know internal endpoints)
    → enables F3 (access metadata service)
      → enables F4 (extract credentials)
```

### Step 3: Chain Scoring
For the complete chain:
- **Chain Confidence**: Lowest individual confidence in the chain
  - `min(9, 7, 6, 5) = 5/10`
- **Chain Severity**: Highest severity (final impact)
  - `max(3, 6, 8, 9) = 9/10`
- **Chain Complexity**: Number of steps
  - `4 steps = Medium complexity`

### Step 4: Narrative Construction
```markdown
## Attack Chain: Info Disclosure → Cloud Compromise

**Chain Confidence:** 5/10 | **Chain Severity:** 9/10
**Steps:** 4 | **Complexity:** Medium

### Narrative
An attacker could leverage the information disclosure in the
error messages (F1) to discover internal service endpoints.
Using this knowledge, they could exploit the SSRF vulnerability
(F2) to access the cloud metadata service (F3), extracting
temporary IAM credentials (F4) that grant administrative
access to the AWS account.

### Impact
Complete compromise of the cloud infrastructure, including
access to all S3 buckets, databases, and the ability to
launch new resources.
```

## Chain Visualization

Generate mermaid diagrams for attack chains:
```mermaid
graph LR
    A[Info Disclosure] -->|reveals endpoints| B[SSRF]
    B -->|access internal| C[Metadata Access]
    C -->|extract creds| D[Cloud Compromise]
    
    style A fill:#ff9
    style B fill:#f96
    style C fill:#f66
    style D fill:#f00,color:#fff
```

## Prioritization Matrix

| Priority | Criteria |
|----------|----------|
| P0 - Critical | Chain leads to RCE/full compromise, high confidence |
| P1 - High | Chain leads to significant data access, medium+ confidence |
| P2 - Medium | Chain leads to limited access, or low confidence |
| P3 - Low | Theoretical chain, not yet validated |

## Output
- Visual attack chain diagrams
- Narrative for each chain
- Cumulative risk assessment
- Prioritized chain list
- Recommendations to break each chain
