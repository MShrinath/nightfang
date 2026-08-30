<!-- Template for an Individual Vulnerability Finding with Framework Mappings -->
# Finding #[FINDING_ID]: [Vulnerability Title]

**Target:** `[ENDPOINT_OR_HOST]`
**Vulnerability Type:** [VULNERABILITY_TYPE]
**Date Discovered:** [YYYY-MM-DD HH:MM:SS UTC]
**Discovered By Subagent:** [AGENT_NAME]

---

## 📊 Dual Scoring Assessment

| Metric | Score | Justification |
| :--- | :--- | :--- |
| **Confidence Score** | **[1-10]/10** | [Explain why: e.g., Confirmed via active HTTP reproduction / Banner inference / Full PoC] |
| **Severity Score** | **[1-10]/10** | [Explain impact: e.g., Direct administrative data compromise / Denial of service / Info leak] |
| **Status** | `[Suspected | Confirmed | Exploited | False Positive]` | Current engagement lifecycle status |

### 🛡️ Industry Framework Classifications
- **MITRE ATT&CK v19:** `[e.g., T1190 - Exploit Public-Facing Application]`
- **MITRE D3FEND Countermeasure:** `[e.g., D3-PSA: Parameter Sanitization Analysis / D3-WAF: Web Application Filtering]`
- **MITRE ATLAS (if AI/LLM):** `[e.g., AML.T0051 - LLM Prompt Injection]`
- **NIST CSF 2.0:** `[e.g., PR.DS-01, DE.CM-01]`
- **CWE:** [CWE-XXX: Name]
- **OWASP Category:** [A0X:2021 / API-0X:2023 / LLM-0X:2025]
- **CVSS v3.1 Score:** `[e.g., 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)]`

---

## 📝 Vulnerability Description
[Detailed explanation of the flaw, the underlying root cause, and how it manifests in the target environment.]

---

## 🔍 Technical Evidence & Proof of Concept

### Request Details
```http
POST /api/v1/resource/update HTTP/1.1
Host: [TARGET_HOST]
Authorization: Bearer [TOKEN]
Content-Type: application/json

{
  "parameter": "PAYLOAD_HERE"
}
```

### Response Details
```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: [LEN]

{
  "status": "success",
  "data": "EXPOSED_SENSITIVE_DATA"
}
```

---

## 👣 Step-by-Step Walkthrough to Reproduce

1. **Step 1: Preparation**
   [Command or setup step]
   ```bash
   [Exact reproduction command]
   ```

2. **Step 2: Execution**
   [Execution command]
   ```bash
   [Exact reproduction command]
   ```

3. **Step 3: Verification**
   [Observed vs expected outcome]

---

## 💥 Impact Assessment
- **Confidentiality:** [High / Medium / Low / None] — [Details]
- **Integrity:** [High / Medium / Low / None] — [Details]
- **Availability:** [High / Medium / Low / None] — [Details]
- **Business Risk:** [Real-world business consequences if exploited by malicious actor]

---

## 🛡️ Remediation & D3FEND Countermeasures

### ⚡ Quick Fix (Immediate Action)
```python
# Code snippet or configuration line fix
```

### 🏗️ Strategic / Architectural Fix (Long-term)
[Comprehensive architectural improvement]

### 🛡️ D3FEND Recommended Defense: `[D3-XXX]`
[Specific defense technique implementation guide]

---

## 🔗 References
- [Official CVE / Advisory Link]
- [OWASP Testing Guide Reference]
- [MITRE ATT&CK Technique Link]
