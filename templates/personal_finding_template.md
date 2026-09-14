<!-- NIGHTFANG Personal Finding Template - Operator's Format, Voice & Standards -->
# Finding #[FINDING_ID]: [Vulnerability Title]

**Target:** `[ENDPOINT_OR_HOST]`
**Vulnerability Type:** [VULNERABILITY_TYPE]
**Date Discovered:** [YYYY-MM-DD HH:MM:SS UTC]
**Discovered By:** NIGHTFANG-[AGENT_NAME]
**Engagement:** [ENGAGEMENT_ID]

---

## 📊 Dual Scoring Assessment (NIGHTFANG Calibrated)

| Metric | Score | Justification |
| :--- | :--- | :--- |
| **Confidence Score** | **[1-10]/10** | [NIGHTFANG Standard: Banner=2, Differential=5, Deterministic=8, Exploited=10] |
| **Severity Score** | **[1-10]/10** | [NIGHTFANG Standard: RCE/Data=9-10, Auth Bypass/BOLA=7-8, IDOR/XSS/SSRF=5-6, Info=1-4] |
| **Status** | `[Suspected \| Confirmed \| Exploited \| False Positive]` | Current lifecycle status |
| **Chain Priority** | `[P0 \| P1 \| P2 \| —]` | From NIGHTFANG chain priority formula |

### 🛡️ Industry Framework Classifications
- **MITRE ATT&CK v19:** `[e.g., T1190 - Exploit Public-Facing Application]`
- **MITRE ATLAS (if AI/LLM):** `[e.g., AML.T0051 - LLM Prompt Injection]`
- **MITRE D3FEND:** `[e.g., D3-PSA: Parameter Sanitization Analysis]`
- **NIST CSF 2.0:** `[e.g., PR.DS-01, DE.CM-01]`
- **NIST AI RMF (if AI):** `[e.g., MAP-1.5, MEASURE-2.6]`
- **CWE:** [CWE-XXX: Name]
- **OWASP Category:** [A0X:2021 / API-0X:2023 / LLM-0X:2025]
- **CVSS v3.1:** `[e.g., 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)]`

---

## 📝 Vulnerability Description
[Detailed explanation of the flaw, root cause, and manifestation in target environment. Technical, precise, no fluff.]

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

### Evidence Hashes (SHA-256)
- Request: `sha256:abc123...`
- Response: `sha256:def456...`
- Screenshot: `sha256:ghi789...`

---

## 👣 Step-by-Step Walkthrough to Reproduce (NIGHTFANG Standard: 100% Reproducible)

### 1. Prerequisites
```bash
# Environment setup
export TARGET="https://api.target.com"
export TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### 2. Reproduction Commands
```bash
# Exact command to reproduce
curl -s -X GET "$TARGET/api/v1/users/1/profile" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

### 3. Expected vs Observed
| Step | Command | Expected | Observed |
|------|---------|----------|----------|
| 1 | [cmd] | 403 Forbidden | 200 OK + PII |

### 4. Verification
```bash
# Verification command
curl -s -X GET "$TARGET/api/v1/users/1/profile" \
  -H "Authorization: Bearer $TOKEN" | jq '.data.email'
# Returns: admin@target.com (confirms BOLA)
```

---

## 💥 Impact Assessment

| Dimension | Rating | Details |
|-----------|--------|---------|
| **Confidentiality** | [High/Medium/Low/None] | [Specific data exposed] |
| **Integrity** | [High/Medium/Low/None] | [Data modification possible?] |
| **Availability** | [High/Medium/Low/None] | [DoS potential?] |
| **Business Risk** | [Critical/High/Medium/Low] | [Real-world consequence] |

---

## 🔗 Attack Chain Context (NIGHTFANG)

### This Finding Enables:
- [ ] **CHAIN-BOLA-JWT-ADMIN** — BOLA → Weak JWT → Admin Panel
- [ ] **CHAIN-SUBDOMAIN-SSRF-METADATA** — Subdomain → SSRF → Cloud Metadata
- [ ] **CHAIN-GRAPHQL-INTROSPECTION-BOLA** — GraphQL → Field Suggestion → BOLA
- [ ] Custom chain: [DESCRIPTION]

### This Finding Requires:
- [ ] Prior finding: [FINDING_ID]
- [ ] Credential: [ROLE/TOKEN]
- [ ] Network position: [INTERNAL/EXTERNAL]

---

## 🛡️ Remediation & D3FEND Countermeasures (NIGHTFANG Style: Code → Config → Architecture)

### ⚡ Immediate Fix (Code/Config)
```python
# Exact code fix
@app.route("/api/v1/users/<int:user_id>/profile")
@require_auth
def get_profile(user_id):
    # FIX: Add authorization check
    if not current_user.can_access(user_id):
        return {"error": "Forbidden"}, 403
    return get_user_profile(user_id)
```

### 🏗️ Strategic Fix (Architecture)
[Comprehensive architectural improvement — e.g., "Implement centralized authorization service with ABAC model"]

### 🛡️ D3FEND Implementation: `[D3-XXX]`
[Specific defense technique implementation guide with code/config examples]

---

## 📎 Evidence Artifacts
- `evidence/NIGHTFANG-042_request.http` — Raw request
- `evidence/NIGHTFANG-042_response.http` — Raw response
- `evidence/NIGHTFANG-042_screenshot.png` — Browser/terminal proof
- `evidence/NIGHTFANG-042_curl.sh` — Reproduction script

---

## 🔗 References
- [Official CVE / Advisory Link]
- [OWASP Testing Guide Reference]
- [MITRE ATT&CK Technique Link]
- [NIGHTFANG Chain Template: CHAIN-XXX]