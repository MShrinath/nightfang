---
name: remediation
description: Structured remediation advisory, tri-tier fix strategies (quick, proper, strategic), remediation SLA matrix, and D3FEND mappings.
version: "2.0"
domain: cybersecurity
subdomain: defensive-remediation
tags: [remediation, d3fend, mitigation, sla, security-architecture]
d3fend_techniques: [D3-HSA, D3-PMA, D3-PSA, D3-UVI, D3-ARA]
---

# Remediation Advisory Skill

Provides specific, actionable, defense-in-depth remediation guidance and prioritized fix roadmaps.

## Tri-Tier Remediation Architecture

Every finding must be paired with a three-tier remediation strategy:

```markdown
### Remediation: [Finding Title]

#### 1. Quick Fix (Immediate — Within 24-48 Hours)
Targeted configuration update or localized patch to halt active exploitation.
*Example: Apply a WAF rule blocking `/....//` or disable the vulnerable endpoint in Nginx.*

#### 2. Proper Fix (Short-Term — Within 1-2 Weeks)
Code-level or framework-level fix addressing the root vulnerability.
*Example: Migrate raw string concatenation to parameterized queries / ORM prepared statements.*

#### 3. Strategic Fix (Long-Term / Architectural)
Systemic design change or process improvement preventing the flaw class across the organization.
*Example: Adopt an API gateway with centralized RBAC, CI/CD automated SAST/DAST gating, and input validation libraries.*

#### 4. Verification Step
Step-by-step instructions for engineering teams to verify that the fix resolves the vulnerability without regression.
```

---

## Remediation SLA Matrix

Remediation urgency is tied directly to the Dual Ranking Severity score:

| Severity Level | Score Range | Remediation SLA | Escalation Target |
| :--- | :--- | :--- | :--- |
| **Critical** | `9 – 10` | Within **24–48 Hours** | CISO / Incident Response Lead |
| **High** | `7 – 8` | Within **1 Week** | Security Engineering & App Owner |
| **Medium** | `5 – 6` | Within **30 Days** | Development Sprint Backlog |
| **Low** | `3 – 4` | Within **90 Days (Quarterly)** | Maintenance Cycle |
| **Informational** | `1 – 2` | Next Major Release / Best Practice | Architecture Review |

---

## D3FEND Countermeasure Mapping Standard
Every remediation must include the appropriate **MITRE D3FEND** technique identifier:
- Input handling: `D3-UVI` (User Input Validation), `D3-PSA` (Parameter Sanitization)
- Authentication/Authorization: `D3-ARA` (Application Role Authorization), `D3-BA` (Biometric/MFA)
- Network/Transport: `D3-NA` (Network Access Control), `D3-CTA` (Certificate Trust Analysis)
- System Execution: `D3-EAA` (Execution Access Authorization), `D3-MCI` (Model Context Isolation)
