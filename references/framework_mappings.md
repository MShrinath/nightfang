# NIGHTFANG Security Framework Cross-Mapping

Defines the cross-framework mapping for NIGHTFANG skills and finding types across **MITRE ATT&CK v19**, **NIST CSF 2.0**, **MITRE D3FEND v1.4**, **MITRE ATLAS**, and **OWASP Standards**.

---

## 1. Master Skill-to-Framework Matrix

| Skill / Domain | MITRE ATT&CK v19 | NIST CSF 2.0 | MITRE D3FEND | MITRE ATLAS | OWASP / CWE |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`recon`** | T1593, T1594, T1596, T1046, T1595 | ID.AM-01, DE.CM-01 | D3-DNST, D3-WHIA, D3-NTA | — | CWE-200 |
| **`web`** | T1190, T1059.007, T1505 | PR.DS-01, DE.CM-01 | D3-PSA, D3-WAF, D3-UVI | — | OWASP A01–A10 |
| **`api`** | T1190, T1078, T1552 | PR.AC-01, PR.DS-02 | D3-ARA, D3-PSA | — | OWASP API1–API10 |
| **`ai-security`** | T1190, T1059 | PR.DS-01, DE.CM-01 | D3-PSA, D3-MCI | AML.T0051, AML.T0054 | OWASP LLM01–LLM10 |
| **`network`** | T1021, T1110, T1558, T1040 | PR.AC-05, PR.PT-01 | D3-NA, D3-BA, D3-CTA | — | CWE-287, CWE-306 |
| **`cloud`** | T1580, T1530, T1078.004 | PR.AC-06, PR.DS-01 | D3-CSM, D3-IAM | — | CSA Top Threats |
| **`hunting`** | T1203, T1059, T1562 | DE.AE-01, RS.AN-03 | D3-THA, D3-MCI | — | Business Logic Flaws |
| **`attack-chain`**| TA0001 → TA0040 (Kill Chain) | ID.RA-03, RS.AN-01 | D3-TCA, D3-RCA | — | Unified Kill Chain |
| **`remediation`** | — | RS.MI-01, RC.RP-01 | D3-HSA, D3-PMA | — | Fix Roadmaps / SLAs |
| **`reporting`** | — | RS.CO-03, RC.CO-01 | — | — | Executive Deliverables |

---

## 2. MITRE ATT&CK Tactic Alignment

```
┌───────────────────┬───────────────────────────────────────────┬───────────────────────────┐
│ TACTIC            │ NIGHTFANG PHASE & SKILLS                  │ ATT&CK TECHNIQUES COVERED │
├───────────────────┼───────────────────────────────────────────┼───────────────────────────┤
│ TA0043 Recon      │ Phase 2 (recon)                           │ T1595, T1593, T1594, T1596│
│ TA0001 Initial    │ Phase 3 (web, api, ai-security)           │ T1190, T1133, T1078       │
│ TA0002 Execution  │ Phase 3 & 4 (web, hunting)                │ T1059, T1203, T1053       │
│ TA0004 PrivEsc    │ Phase 7 & 8 (validation)                  │ T1548, T1068, T1134       │
│ TA0006 Creds      │ Phase 3 & 4 (network, hunting)            │ T1110, T1558, T1003       │
│ TA0007 Discovery  │ Phase 2 & 3 (recon, cloud)                │ T1046, T1018, T1580, T1530│
│ TA0008 Lateral    │ Phase 7 & 8 (validation)                  │ T1021, T1570, T1550       │
└───────────────────┴───────────────────────────────────────────┴───────────────────────────┘
```

---

## 3. MITRE D3FEND Defensive Mapping

Every finding recorded by NIGHTFANG must include corresponding **D3FEND Defensive Countermeasure IDs**:
- **Injection Flaws (SQLi / XSS / Command / Template)**:
  - `D3-UVI` (User Input Validation)
  - `D3-PSA` (Parameter Sanitization Analysis)
  - `D3-WAF` (Web Application Filtering)
- **Broken Authentication / BOLA / IDOR**:
  - `D3-ARA` (Application Role Authorization)
  - `D3-BA` (Biometric / Multi-Factor Authentication)
  - `D3-SFI` (Session Fixation Invalidation)
- **Weak TLS Configuration & Cryptographic Flaws**:
  - `D3-CTA` (Certificate Trust Analysis)
  - `D3-CH` (Cryptographic Hash Hardening)
- **Unauthenticated / Exposed Network Services**:
  - `D3-NA` (Network Access Control)
  - `D3-SDA` (Service Disable / Access Restriction)
- **LLM Prompt Injection & Agent Tool Exploitation**:
  - `D3-MCI` (Model Context Isolation)
  - `D3-PSA` (Input Boundary Validation)
  - `D3-EAA` (Execution Access Authorization)
