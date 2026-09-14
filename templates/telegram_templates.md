# 📱 NIGHTFANG Telegram Message Templates & Protocols

Standardized message formats sent to the operator via Telegram.

---

## 1. Engagement Initialization
```
🦅 NIGHTFANG Orchestrator Online
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Engagement: {engagement_name}
🏢 Target: {client_name}
📋 Scope: {target_count} targets loaded
⏰ Window: {testing_window}
🛡️ Mode: Human-in-the-Loop Active

Ready to start Phase 1: Passive Reconnaissance.
Reply: /go to initiate swarm or /hold to adjust scope.
```

---

## 2. Phase Transition Update
```
📊 NIGHTFANG Phase Update [{phase_name}]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🕐 Current Phase: {current_phase} (Phase {phase_num}/6)
⏱️ Elapsed: {elapsed_time}
🌐 Assets Identified: {asset_count}
🔍 Findings Queued: {finding_count}

{phase_summary_details}

Next Step: {next_action}
Reply: /go to proceed or /status for full breakdown.
```

---

## 3. High/Critical Finding Alert & Exploitation Request (HITL Gate)
```
🔍 NIGHTFANG Finding #{finding_id}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📎 Target: {target_endpoint}
🎯 Type: {vulnerability_title}
📊 Confidence: {confidence_score}/10 [{confidence_bar}]
🔴 Severity: {severity_score}/10   [{severity_bar}]
📝 Summary: {brief_summary}

💡 Technical Details:
{technical_proof_summary}

🔧 Proposed Action: {exploit_plan}
⚠️ Risk Level: {risk_level}

⚠️ Awaiting permission to proceed with exploitation.
Reply: /go {finding_id} or /hold {finding_id}
```

---

## 4. Exploitation Outcome Notification
```
✅ NIGHTFANG Exploitation Result
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Finding: #{finding_id} — {vulnerability_title}
📊 Updated Confidence: 10/10 (Demonstrated)
💥 Access Level Achieved: {access_level}
📝 Evidence ID: {evidence_id}

Artifact Cleanup Status: Completed & Verified Clean.
Continuing engagement queue...
```

---

## 5. Live Status Response (`/status`)
```
📊 NIGHTFANG Live Engagement Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Engagement: {engagement_name}
🕐 Active Phase: {active_phase}
⏱️ Runtime: {runtime}

🐝 Swarm Agent Status:
• RECON-PASSIVE:    {status_1}
• RECON-ACTIVE:     {status_2}
• SCANNER-WEBAPP:   {status_3}
• SCANNER-API:      {status_4}
• SCANNER-NETWORK:  {status_5}
• HUNTER:           {status_6}
• EXPLOITER:        {status_7}

📊 Current Findings:
🔴 Critical (9-10): {crit_count}
🟠 High (7-8):     {high_count}
🟡 Medium (5-6):   {med_count}
🟢 Low (3-4):      {low_count}
ℹ️ Info (1-2):     {info_count}

Reply: /findings for list or /report for markdown export.
```

---

## 6. Final Engagement Summary
```
📋 NIGHTFANG Pentest Complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Target: {client_name}
⏱️ Total Duration: {total_duration}

📊 Deliverable Summary:
• Total Findings: {total_findings}
• Exploited Vectors: {exploited_count}
• Attack Chains Formed: {chain_count}

📄 Full Markdown Report generated at:
`engagements/{engagement_slug}_report.md`

Type /report to receive document stream.
Thank you for operating with NIGHTFANG. 🦅
```
