---
name: incident-integrations
description: >-
  Use this skill for integrating penetration testing findings with external incident management,
  issue tracking, and multi-channel alerting platforms (Jira, GitHub Issues, Slack, Discord,
  PagerDuty, Notion, and Email). Automates vulnerability ticket creation, triage tagging,
  and stakeholder notifications upon confirmed findings.
domain: cybersecurity
subdomain: incident-response
tags: [incident-management, jira, github-issues, slack, pagerduty, multi-channel, mcp-integration]
mitre_attack: [T1078]
nist_csf: [RS.CO-01, RS.CO-02, RS.CO-03, RC.CO-01]
d3fend_techniques: [D3-IRN, D3-ITM]
version: "1.0"
---

# Incident & Multi-Channel Integrations

Automated dispatching of validated security findings to enterprise issue trackers and alerting channels.

## When to Use
- A High or Critical vulnerability is confirmed and needs immediate ticketing in Jira or GitHub Issues.
- Operator wants automated notifications dispatched to Slack, Discord, or Microsoft Teams alongside Telegram.
- Critical findings require PagerDuty / OpsGenie escalation.
- Exporting findings database to Notion or internal Wiki for engineering remediation tracking.

## Prerequisites
- Webhook URLs or API credentials for target services (e.g. Jira API Token, Slack Webhook URL, Discord Webhook).
- Configured MCP servers or Python requests bridge in `config/mcp_servers.yaml`.

## Supported Platforms & Workflows

### 1. Jira Security Issue Creation
Automate Jira ticket creation with formatted vulnerability details:
- **Project**: Security / Vulnerability Backlog
- **Issue Type**: Bug / Security Vulnerability
- **Priority**:
  - Severity 9-10 -> `Highest` (P0)
  - Severity 7-8  -> `High` (P1)
  - Severity 5-6  -> `Medium` (P2)
  - Severity 1-4  -> `Low` (P3)
- **Labels**: `hermes-pentest`, `owasp-top10`, `cve-cwe`, `sla-tracked`

### 2. GitHub Security Advisory & Issue Tracking
- Create private vulnerability reports or labeled issues (`security`, `vulnerability`, `needs-triage`).
- Auto-attach step-by-step reproduction walkthroughs and remediation code snippets.

### 3. Slack & Discord Real-time Alerting
Dispatch rich-text cards to SOC/Engineering channels:
- Finding title, target URL, Severity, and Confidence bars.
- Direct link to the engagement report artifact.

### 4. PagerDuty Urgent Escalation
- Trigger PagerDuty incidents for Severity 10 / Remote Code Execution / Unauthenticated Admin Takeover findings discovered during testing windows.

## Workflow

### Step 1: Filter Finding by Severity Threshold
Only dispatch tickets for validated findings exceeding configured threshold (default: Severity >= 7).

### Step 2: Format Payload by Target Platform
```json
{
  "finding_id": "HERMES-004",
  "title": "SQL Injection in /api/v1/orders",
  "severity": 9,
  "confidence": 10,
  "target": "https://api.example.com/v1/orders",
  "mitre_attack": "T1190",
  "d3fend": "D3-PSA",
  "reproduction": "curl -X POST ...",
  "remediation": "Use parameterized prepared statements."
}
```

### Step 3: Dispatch via MCP / Python Script
```bash
python scripts/multi_channel_notifier.py --config config/engagement_template.yaml --finding-file engagements/latest_finding.json
```

### Step 4: Verification & Audit Logging
- Record external Ticket ID (e.g. `SEC-1042`) back into HERMES engagement memory.
- Log dispatch timestamp and webhook response status code.

## Safety & Governance Guardrails
> [!IMPORTANT]
> Never post cleartext sensitive credentials (e.g. real API keys or extracted database hashes) to unencrypted public channels. Findings dispatched to public/team channels must sanitize confidential customer data.
