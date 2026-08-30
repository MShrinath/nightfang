---
name: telegram-hitl
description: >-
  Use this skill for Telegram bot integration and human-in-the-loop
  communication. Handles all operator communication including finding
  reports, permission requests, status updates, mode toggles, and engagement controls.
  This skill defines message formats, command handling, and the approval
  workflow. Activate whenever communicating with the operator.
domain: cybersecurity
subdomain: orchestration
tags: [telegram, hitl, human-in-the-loop, bot-commands, operator-governance]
nist_csf: [GV.PO-02, RS.CO-01]
version: "1.1"
---

# Telegram Human-in-the-Loop (HITL) Integration

Manage operator communication through Telegram bot.

## Bot Commands

| Command | Description |
|---------|------------|
| `/start` | Initialize engagement session |
| `/scope` | Display current scope |
| `/status` | Show engagement progress and active swarms |
| `/findings` | List all findings with Confidence & Severity scores |
| `/go [finding_id]` | Approve exploitation of specific finding |
| `/hold [finding_id]` | Pause/deny exploitation on that finding |
| `/terse on` or `/caveman on` | **Enable Caveman Mode** (40-60% token reduction, terse updates) |
| `/terse off` or `/caveman off` | **Disable Caveman Mode** (standard conversational updates) |
| `/stop` | Emergency halt all active testing |
| `/resume` | Resume paused testing |
| `/report` | Generate and send current markdown report |
| `/set_scope` | Update engagement scope |
| `/config` | Show/update agent configuration |

## Message Templates

### Finding Report
```
🔍 HERMES Finding #[ID]
━━━━━━━━━━━━━━━━━━━━━━
📎 Target: [endpoint/host]
🎯 Type: [vulnerability type]
📊 Confidence: [X]/10 [confidence_bar]
🔴 Severity: [Y]/10 [severity_bar]
🛡️ ATT&CK / D3FEND: [TXXXX / D3-XXX]
📝 Summary: [brief description]
💡 Details: [technical details]

🔧 Proposed Action: [what HERMES wants to do]
⚠️ Risk: [potential impact of the action]

Reply: /go [ID] or /hold [ID]
```

### Terse Mode Finding Alert (When Caveman Mode is ON)
```
🔍 #{ID}: [vulnerability type]
Target: [endpoint] | Conf: [X]/10 | Sev: [Y]/10
Action: [brief exploit plan]
Reply: /go [ID] or /hold [ID]
```

### Progress Update
```
📊 HERMES Status Update
━━━━━━━━━━━━━━━━━━━━━━
🕐 Phase: [current phase]
⏱️ Duration: [time elapsed]
🎯 Targets Tested: [X/Y]
🔍 Findings: [count by severity]
⏳ Queue: [pending actions]

Next: [what's planned next]
```

## Approval Workflow

```
HERMES discovers potential vulnerability
         ↓
Formats finding with Confidence/Severity scores & ATT&CK ID
         ↓
Sends to operator via Telegram
         ↓
    ┌────┴────┐
    ↓         ↓
  /go       /hold
    ↓         ↓
Proceed    Log decision
with       and skip
exploit    this vector
    ↓         ↓
Report     Continue
results    other tests
```

## Rate Limiting & Safety
- Maximum 1 message per 5 seconds to avoid flooding.
- High/Critical findings sent immediately.
- Low-severity findings batched into digest updates.
- All decisions logged to `engagements/decision_audit.log`.
