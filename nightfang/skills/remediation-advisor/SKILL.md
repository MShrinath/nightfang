---
name: remediation-advisor
description: >-
  Use this skill for generating specific, actionable remediation
  recommendations. Provides code-level fixes, configuration changes,
  architecture improvements, and prioritized remediation roadmaps.
  Activate when generating reports or when the operator asks for
  fix recommendations.
---

# Remediation Advisory

Provide specific, actionable fix recommendations.

## Remediation Template

For each finding:

```markdown
## Remediation: [Finding Title]

### Quick Fix (Immediate)
[Specific code change or configuration update]

### Proper Fix (Short-term)
[Architecture-level fix with implementation guidance]

### Strategic Fix (Long-term)
[Process/design changes to prevent recurrence]

### Verification
[How to verify the fix works]
```

## Common Remediations

### SQL Injection
- **Quick**: Parameterized queries / prepared statements
- **Proper**: ORM usage + input validation
- **Strategic**: Security code review process + SAST integration

### XSS
- **Quick**: Output encoding (context-aware)
- **Proper**: Content Security Policy + templating engine auto-escape
- **Strategic**: Security headers + regular security testing

### Authentication Issues
- **Quick**: Enforce strong passwords + account lockout
- **Proper**: MFA implementation + session management review
- **Strategic**: Zero-trust architecture adoption

### Access Control
- **Quick**: Add authorization checks to affected endpoints
- **Proper**: Implement RBAC/ABAC framework
- **Strategic**: Centralized authorization service

### SSRF
- **Quick**: URL allowlisting
- **Proper**: Network segmentation + metadata endpoint blocking
- **Strategic**: Service mesh with strict egress controls

### Insecure Deserialization
- **Quick**: Input validation + type checking on deserialized data
- **Proper**: Use safe serialization formats (JSON over native serialization)
- **Strategic**: Integrity checks + sandboxed deserialization environments

### Broken Authentication
- **Quick**: Rate limiting + account lockout policies
- **Proper**: MFA + secure session token generation
- **Strategic**: Passwordless authentication + SSO adoption

### Security Misconfiguration
- **Quick**: Disable debug modes + remove default credentials
- **Proper**: Infrastructure as Code with security baselines
- **Strategic**: Automated configuration compliance scanning (CIS benchmarks)

## Prioritization Framework

| Severity | SLA | Category |
|----------|-----|----------|
| 9-10 | Fix within 24-48 hours | Critical |
| 7-8 | Fix within 1 week | High |
| 5-6 | Fix within 1 month | Medium |
| 3-4 | Fix within 1 quarter | Low |
| 1-2 | Track and address in next cycle | Informational |

## Cost-Benefit Analysis

For each remediation, assess:
- **Effort**: Hours/days to implement
- **Risk Reduction**: How much does it reduce overall risk?
- **Dependencies**: Does it require other changes first?
- **Quick Win?**: High impact + low effort = do it first

## Report Integration
- Pair every finding with its remediation
- Group related remediations to avoid duplication
- Estimate effort for each fix (hours/days)
- Identify quick wins (high impact, low effort)
- Map fixes to compliance requirements where applicable (PCI-DSS, HIPAA, SOC 2)
