---
name: reporting
description: >-
  Use this skill for generating penetration testing reports. Creates
  structured, professional reports with executive summaries, detailed
  findings, reproduction walkthroughs, evidence documentation, remediation
  recommendations, and risk scoring. Formats reports for Telegram delivery
  and full markdown documents. Activate at the end of each testing phase
  or when the operator requests a status report.
---

# Penetration Testing Report Generation

Create comprehensive, actionable security reports.

## Report Structure

### 1. Executive Summary
- Engagement overview (scope, dates, methodology)
- Key findings count by severity
- Overall risk assessment
- Top 3 critical findings highlighted

### 2. Scope & Methodology
- Targets tested (IPs, domains, URLs)
- Testing methodology used
- Tools employed
- Limitations and exclusions

### 3. Findings Summary Table

```markdown
| # | Finding | Confidence | Severity | Status |
|---|---------|-----------|----------|--------|
| 1 | SQL Injection in /api/users | 9/10 | 9/10 | Exploited |
| 2 | Missing HSTS Header | 10/10 | 3/10 | Confirmed |
| 3 | Default Admin Credentials | 8/10 | 8/10 | Confirmed |
```

### 4. Detailed Findings

For each finding:

```markdown
## Finding #[N]: [Title]

**Confidence:** [X]/10 | **Severity:** [Y]/10
**CVSS Score:** [if applicable]
**CWE:** [CWE-XXX]
**OWASP Category:** [A0X]
**Status:** Confirmed / Exploited / Suspected

### Description
[What the vulnerability is and why it matters]

### Evidence
[Commands run, responses received, screenshots]

### Steps to Reproduce
1. [Step-by-step walkthrough]
2. [Exact commands with parameters]
3. [Expected vs actual output]

### Impact
[What an attacker could achieve]

### Remediation
[Specific fix recommendations with code examples where possible]

### References
- [CVE link]
- [OWASP reference]
- [Vendor advisory]
```

### 5. Remediation Roadmap
- Prioritized fix list (Critical → Low)
- Quick wins vs long-term fixes
- Estimated effort per fix

### 6. Appendices
- Full tool output logs
- Scope document
- Engagement timeline

## Telegram Report Format

For quick Telegram updates:

```
📋 HERMES Engagement Report
━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Target: [scope summary]
📅 Date: [date]

🔴 Critical: [count]
🟠 High: [count]
🟡 Medium: [count]
🟢 Low: [count]
ℹ️ Info: [count]

🏆 Top Findings:
1. [Finding] — Sev: X/10, Conf: Y/10
2. [Finding] — Sev: X/10, Conf: Y/10
3. [Finding] — Sev: X/10, Conf: Y/10

📄 Full report attached.
```

## Report Quality Checklist
- [ ] Every finding has both Confidence and Severity scores
- [ ] Reproduction steps are complete and tested
- [ ] Evidence is included (not just claims)
- [ ] Remediation is specific (not generic advice)
- [ ] No false positives included without flagging
- [ ] CVSS/CWE/OWASP mapped where applicable
- [ ] Professional language, no jargon without explanation
