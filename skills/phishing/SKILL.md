---
name: phishing
description: Authorized phishing simulation, credential harvest testing, and security awareness assessment.
version: "2.0"
domain: cybersecurity
subdomain: social-engineering
tags: [phishing, social-engineering, credential-harvest, awareness]
mitre_attack: [TA0001, T1059, T1136, T1557, T1589]
d3fend_techniques: [D3-AMCA, D3-UEM]
---

# Phishing & Social Engineering

Authorized phishing simulation and credential harvest testing within defined engagement scopes. All activities require explicit written authorization and operate under strict SOP-04/SOP-05 controls.

## Tools & Execution Matrix

| Tool | Purpose | Standard Command | Fallback |
| :--- | :--- | :--- | :--- |
| `goPhish` | Full phishing platform | `gopherfish --config config.json` | Custom Flask app |
| `evilginx` | Adversary-in-the-middle | `evilginx2 -config config.json` | Custom proxy |
| `setoolkit` | Social engineering toolkit | `setoolkit` | Manual HTML/CSS |
| `SendGrid` / `Mailgun` | Email delivery | API-based SMTP relay | `smtplib` |
| `Twilio` | SMS phishing | API-based SMS relay | `curl` API |

## Methodology

### 1. Campaign Planning
- Define target audience (specific department, role, or employee list).
- Select phishing vector: email, SMS (smishing), voice (vishing), or USB drops.
- Craft lures based on current events, internal terminology, and target interests.
- Configure landing pages to mirror legitimate authentication portals.

### 2. Email Delivery
- Use organization-approved mail servers or external providers with SPF/DKIM alignment.
- Implement tracking pixels and link redirects to measure opens and clicks.
- Stagger delivery to avoid triggering spam filters and rate limits.

### 3. Credential Harvest & Capture
- Mimic legitimate login portals (Office 365, Okta, VPN, internal SSO).
- Capture submitted credentials and session tokens.
- For Adversary-in-the-Middle: proxy authentication sessions to harvest MFA tokens.

### 4. Post-Campaign Analysis
- Calculate open rate, click rate, and credential submission rate.
- Identify high-risk individuals and departments for targeted training.
- Report findings with actionable recommendations for email filtering, MFA enforcement, and user training.

## Scope Boundary Validation
- All phishing campaigns require explicit written authorization from organizational leadership.
- No real user credentials are stored or reused — captured credentials are immediately notified to the target organization.
- Campaigns are time-boxed and must be concluded within the agreed engagement window.
- No financial fraud, data exfiltration, or malware delivery is conducted.

## Output
- Campaign report: targets, delivery metrics, credential submissions, and risk assessment.
- Recommendations for email security controls, MFA deployment, and user training programs.