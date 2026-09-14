# 🛡️ NIGHTFANG — Security Framework Cross-Mapping

This document defines the comprehensive cross-framework mapping for all 20 NIGHTFANG skills across **MITRE ATT&CK v19**, **NIST CSF 2.0**, **MITRE D3FEND v1.4**, **MITRE ATLAS**, and **OWASP Standards**.

---

## Master Skill-to-Framework Matrix

| Skill Name | Primary Domain | MITRE ATT&CK v19 | NIST CSF 2.0 | MITRE D3FEND | MITRE ATLAS | OWASP / CWE |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`recon-passive`** | OSINT / Intel | T1593, T1594, T1596 | ID.AM-01, ID.RA-01 | D3-DNST, D3-WHIA | — | CWE-200 |
| **`recon-active`** | Network Discovery | T1046, T1595, T1018 | ID.AM-02, DE.CM-01 | D3-NTA, D3-SDA | — | CWE-200 |
| **`webapp-testing`** | Web Application | T1190, T1059.007, T1505 | PR.DS-01, DE.CM-01 | D3-PSA, D3-WAF | — | OWASP A01-A10 |
| **`api-testing`** | API Security | T1190, T1078, T1552 | PR.AC-01, PR.DS-02 | D3-ARA, D3-PSA | — | OWASP API1-API10 |
| **`llm-ai-security`** | AI / LLM Security | T1190, T1059 | PR.DS-01, DE.CM-01 | D3-PSA, D3-MCI | AML.T0051, AML.T0043 | OWASP LLM01-LLM10 |
| **`network-testing`** | Network / Infra | T1021, T1110, T1558 | PR.AC-05, PR.PT-01 | D3-NA, D3-BA | — | CWE-287, CWE-306 |
| **`ssl-tls-testing`** | Cryptography | T1040, T1573, T1557 | PR.DS-02, PR.DS-05 | D3-CTA, D3-CH | — | CWE-326, CWE-327 |
| **`vulnerability-scanning`**| Vuln Assessment | T1595.002, T1190 | DE.CM-08, ID.RA-02 | D3-VDA, D3-SPM | — | CVE / CWE Core |
| **`privilege-escalation`** | Post-Exploitation | T1548, T1068, T1053 | PR.AC-04, DE.AE-02 | D3-PEA, D3-PAC | — | CWE-250, CWE-269 |
| **`cloud-testing`** | Cloud Security | T1580, T1530, T1078.004| PR.AC-06, PR.DS-01 | D3-CSM, D3-IAM | — | CSA Top Threats |
| **`hunting`** | Threat Hunting | T1203, T1059, T1562 | DE.AE-01, RS.AN-03 | D3-THA, D3-MCI | — | Business Logic Flaws|
| **`payload-crafting`** | Weaponization | T1059, T1027, T1547 | PR.PT-02, DE.CM-01 | D3-EAA, D3-SCA | — | CWE-94, CWE-78 |
| **`attack-chain-analysis`**| Kill Chain Mapping| TA0001 → TA0040 | ID.RA-03, RS.AN-01 | D3-TCA, D3-RCA | — | Unified Kill Chain |
| **`scope-management`** | Governance | — | GV.SC-01, PR.IP-01 | — | — | Rules of Engagement |
| **`memory-management`** | Orchestration | — | ID.AM-05, RS.CO-02 | — | — | State Continuity |
| **`evidence-collection`**| Forensics / Audit | T1005, T1074 | DE.AE-04, RS.AN-03 | D3-FAA, D3-FCA | — | Chain of Custody |
| **`token-optimizer`** | Performance | — | — | — | — | Caveman Token Saver |
| **`telegram-hitl`** | Operator Comms | — | GV.PO-02, RS.CO-01 | — | — | Telegram Bot Governance |
| **`reporting`** | Technical Comms | — | RS.CO-03, RC.CO-01 | — | — | Executive Standards |
| **`remediation-advisor`** | Defensive Advice | — | RS.MI-01, RC.RP-01 | D3-HSA, D3-PMA | — | Fix Roadmaps / SLAs |

---

## Detailed MITRE ATT&CK v19 Tactic Alignment

```
┌─────────────────┬───────────────────────────────────────────┬───────────────────────────┐
│ TACTIC          │ NIGHTFANG PHASE & SKILLS                   │ ATT&CK TECHNIQUES COVERED │
├─────────────────┼───────────────────────────────────────────┼───────────────────────────┤
│ TA0043 Recon    │ Phase 1 & 2 (recon-passive, recon-active) │ T1595, T1593, T1594, T1596│
│ TA0001 Initial  │ Phase 3 (webapp-testing, api-testing, ai) │ T1190, T1133, T1078       │
│ TA0002 Execution│ Phase 3 & 4 (webapp-testing, payload)     │ T1059, T1203, T1053       │
│ TA0004 PrivEsc  │ Phase 5 (privilege-escalation)            │ T1548, T1068, T1134       │
│ TA0006 Creds    │ Phase 3 & 4 (network-testing, hunting)    │ T1110, T1558, T1003       │
│ TA0007 Discovery│ Phase 2 & 3 (recon-active, cloud-testing) │ T1046, T1018, T1580, T1530│
│ TA0008 Lateral  │ Phase 4 & 5 (network-testing)             │ T1021, T1570, T1550       │
└─────────────────┴───────────────────────────────────────────┴───────────────────────────┘
```

---

## MITRE D3FEND Defensive Mapping
Every finding reported by NIGHTFANG via Telegram automatically proposes the corresponding **D3FEND Defensive Countermeasure ID**:
- **Injection Flaws (SQLi/XSS/Command):** `D3-PSA` (Parameter Sanitization Analysis) & `D3-WAF` (Web Application Filtering)
- **Broken Authentication / BOLA:** `D3-ARA` (Application Role Authorization) & `D3-BA` (Biometric/MFA Authentication)
- **Weak TLS Configuration:** `D3-CTA` (Certificate Trust Analysis) & `D3-CH` (Cryptographic Hash Hardening)
- **Unauthenticated Network Services:** `D3-NA` (Network Access Control) & `D3-SDA` (Service Disable / Access Restriction)
- **LLM Prompt Injection:** `D3-MCI` (Model Context Isolation) & `D3-PSA` (Input Boundary Validation)
