# NIGHTFANG Finding Walkthrough Template

> **Schema Contract:** [`schemas/finding.md`](../schemas/finding.md)  
> **Role:** Atomic presentation unit for individual technical findings within NIGHTFANG assessments.
> 
> *Instructions for Reporting Agent*: Render this template directly from the structured finding object in the findings store. Preserve all raw evidence verbatim without summarization or truncation. Maintain the exact evidence SHA-256 digests and validation gate outputs.

---

### Finding [FINDING_ID]: [FINDING_TITLE]

| Parameter | Value |
| :--- | :--- |
| **Finding ID** | `[NF-YYYY-NNNN]` |
| **Target Asset** | `[Host / URL / Endpoint / IP:Port / ARN / Cloud Resource]` |
| **Category** | `[web / api / network / active_directory / cloud / container / mobile / ai_llm / ics / supply_chain]` |
| **Discovery Tool** | `[nuclei / nmap / ffuf / Certipy / BloodHound / custom_script]` |
| **CVE Identifier** | `[CVE-YYYY-NNNNN or N/A]` |
| **CWE ID** | `[CWE-XXX: Weakness Title]` |
| **First Discovered** | `[ISO-8601 Timestamp]` |

---

#### 1. Finding Lifecycle State

```text
  [1] DISCOVERED ──► [2] CANDIDATE ──► [3] DUAL-VERIFIED ──► [4] HITL APPROVED
                                                                     │
  [8] RETESTED   ◄── [7] REMEDIATED ◄── [6] REPORTED    ◄── [5] VALIDATED
```

- **Current State:** `[DISCOVERED | CANDIDATE | DUAL-VERIFIED | HITL APPROVED | VALIDATED | REPORTED | REMEDIATED | RETESTED]`
- **State Transition Notes:** `[e.g., Operator granted HITL token /go req-98f2b1a0 on 2026-09-27T22:30:00Z; non-destructive validation confirmed.]`

---

#### 2. Multi-Metric Risk Calibration

NIGHTFANG evaluates vulnerabilities across five independent, non-interchangeable scoring axes:

| Metric | Score / Level | Specification / Vector |
| :--- | :--- | :--- |
| **Nightfang Confidence** | **`[X]/10`** ([Theoretical / Likely / Confirmed / Demonstrated]) | Justification: *[Rationale for confidence score]* |
| **Nightfang Severity** | **`[Y]/10`** ([Informational / Low / Medium / High / Critical]) | Justification: *[Rationale for severity impact]* |
| **Evidence Grounding** | **`[0.XX]`** (`[CERTAIN / STRONG / PROBABLE / TENTATIVE / WEAK]`) | Provenance: *[Reproducibility level and artifact integrity]* |
| **CVSS v3.1** | **`[Base Score]`** (`[Severity Level]`) | Vector: `[CVSS:3.1/AV:.../A:H]` |
| **CVSS v4.0** | **`[Base Score]`** (`[Severity Level]`) | Vector: `[CVSS:4.0/AV:.../SA:H]` |
| **EPSS Score** | **`[0.XXXXX]`** (Percentile: `[XX.X]%`) | Model probability of real-world exploitation in next 30 days |
| **CISA KEV** | **`[YES / NO]`** | Listed on CISA Known Exploited Vulnerabilities Catalog |

---

#### 3. Adversarial Validation Gate

Evaluated by the [`validation`](../agents/validation.md) agent prior to confirmation to guarantee finding validity and prevent hallucinations:

```text
Validation Gate Evaluation
────────────────────────────────────────────────────────────────────────────
Q1 In Scope?          [PASS / KILL]      Notes: [Verified against engagement scope CIDR/domain]
Q2 Grounded?          [PASS / KILL]      Notes: [Raw artifact backed by SHA-256 hash]
Q3 Reachable?         [PASS / KILL]      Notes: [Payload reached backend sink without WAF intercept]
Q4 Controllable?      [PASS / KILL]      Notes: [Input directly manipulates control flow/memory state]
Q5 Impactful?         [PASS / DOWNGRADE] Notes: [Meets class impact threshold for security rating]
Q6 Default/Custom?    [DEFAULT / CUSTOM] Notes: [Present in standard baseline configuration]
Q7 Severity Honest?   [PASS / DOWNGRADE] Notes: [CVSS reflects demonstrated reality, not worst-case]

Verdict: [PASS | KILL | DOWNGRADE | CHAIN_REQUIRED]
Failed Gate: [null | Q1 | Q2 | Q3 | Q4 | Q5 | Q6 | Q7]
Verdict Rationale: [Detailed justification for verdict, especially for KILL, DOWNGRADE, or CHAIN_REQUIRED]
Evidence References: [EVD-001, EVD-002]
Provenance Hash: [SHA-256 of test artifact at validation time]
Evaluator: agents/validation.md
Evaluation Timestamp: [ISO-8601 Timestamp]
```

---

#### 4. Executive Summary

- **What was discovered:** [Concise plain-English explanation of the vulnerability and where it is located.]
- **Business & Operational Impact:** [Clear description of potential business fallout: customer data exposure, unauthorized fund transfer, regulatory fines, operational downtime, or reputational damage.]
- **Action Required:** [High-level action needed from management: allocate engineering sprint, apply emergency hotfix, or restrict network access.]

---

#### 5. Technical Description & Root Cause

**Vulnerability Mechanism:**  
[In-depth technical breakdown of the underlying vulnerability. Detail the vulnerable parameter, source code sink, protocol flaw, or missing access control routine.]

**Root Cause Analysis:**  
[Why does this vulnerability exist? e.g., Insufficient user input sanitization prior to database querying, reliance on client-side state validation, insecure default credentials in OEM firmware, or missing authorization check on object reference ID.]

---

#### 6. Step-by-Step Reproduction Procedure

Deterministic reproduction steps executable by engineering or audit personnel:

1. **Step 1: Target Preparation & Baseline Inspection**
   ```bash
   [Exact curl command, CLI invocation, or network query]
   ```

2. **Step 2: Payload Injection / Vector Execution**
   ```bash
   [Exact non-destructive validation payload command]
   ```

3. **Step 3: Verification Observation**
   - Expected Result: `[Detailed description of vulnerable response, HTTP status, or canary leak]`

---

#### 7. Immutable Evidence Manifest

> **Evidence Integrity Notice**: Captured verbatim by the Execution Policy Gateway during execution. Content is cryptographically hashed and unedited.

```text
Evidence [EVD-XXX]
────────────────────────────────────────────────────────────────────────────
Type:      [HTTP_REQUEST_RESPONSE | COMMAND_OUTPUT | MEMORY_DUMP | LOG_SNIPPET]
Source:    [Agent ID / Tool Name, e.g., scanner / curl]
Timestamp: [ISO-8601 Timestamp]
SHA-256:   [64-character SHA-256 hash]
Integrity: VERIFIED MATCH

Request / Input Command:
────────────────────────
[RAW_REQUEST_STRING_OR_COMMAND_LINE_EXACTLY_AS_SENT]

Response / Standard Output:
───────────────────────────
[RAW_RESPONSE_STRING_OR_OUTPUT_EXACTLY_AS_RECEIVED]
```

*(Repeat Evidence block for each attached proof artifact `[EVD-XXX]`)*

---

#### 8. Impact Assessment

- **Technical Impact:**
  - **Confidentiality:** [High / Medium / Low / None] — *[Specific data disclosed, e.g., database credentials, PII]*
  - **Integrity:** [High / Medium / Low / None] — *[Specific modifications possible, e.g., database records, configuration files]*
  - **Availability:** [High / Medium / Low / None] — *[Disruption potential, e.g., service crash, deadlock, resource exhaustion]*
- **Business Impact:**
  - [Direct regulatory impact (GDPR, HIPAA, PCI-DSS), financial exposure, and operational friction.]

---

#### 9. Framework Mappings

- **MITRE ATT&CK:**
  - `[TXXXX.XXX]`: `[Technique Name]` — *[Sub-technique context]*
- **MITRE ATLAS (AI/LLM findings):**
  - `[AML.TXXXX]`: `[ATLAS Technique Name]`
- **Common Weakness Enumeration (CWE):**
  - `[CWE-XXX]`: `[Weakness Title]`
- **OWASP Classification:**
  - `[OWASP Top 10 / API Security Top 10 / LLM Top 10 classification]`
- **Regulatory Controls:**
  - NIST CSF 2.0: `[PR.AC-XX, PR.DS-XX]` | ISO 27001:2022: `[A.8.XX]` | CIS Controls v8: `[Control XX]`

---

#### 10. Defensive Engineering & Detection Rules

Every validated finding must include defensive countermeasures and detection logic authored by the [`detection-engineer`](../agents/detection-engineer.md):

- **Verified by Blue Skill:** `[skills/remediation/detection-engineering.md]`
- **DeTT&CT Detection Level:** `[none | telemetry | detection | prevention]`

##### Vendor-Neutral Sigma Rule
```yaml
title: Detect [Vulnerability Name] Exploitation Attempt
id: [SIGMA-UUID-OR-NAME]
status: experimental
description: Identifies exploitation attempts targeting [Vulnerability Name] on [Target Asset]
references:
  - [URL or Advisory Reference]
author: NIGHTFANG Detection Engineering Agent
date: [YYYY-MM-DD]
logsource:
  category: [webserver | process_creation | network_traffic]
  product: [windows | linux | web]
detection:
  selection:
    [field|modifier]: '[pattern_string]'
  condition: selection
falsepositives:
  - Legitimate administrative actions matching test syntax
level: high
tags:
  - attack.t[xxxx]
```

##### Platform Detection Queries
- **Microsoft Sentinel (KQL):**
  ```kql
  W3CIISLog
  | where csMethod in ("GET", "POST")
  | where csUriStem contains "[endpoint_path]" and csUriQuery contains "[pattern]"
  | project TimeGenerated, cIP, csMethod, csUriStem, csUriQuery, scStatus
  ```
- **Splunk (SPL):**
  ```spl
  index=web sourcetype=access_combined uri_path="*[endpoint_path]*" uri_query="*[pattern]*"
  | stats count by src_ip, uri_path, uri_query, status
  ```
- **Elastic (EQL):**
  ```eql
  process where event.category == "process" and process.name in ("sh", "bash", "cmd.exe") and process.args contains "[pattern]"
  ```

---

#### 11. Remediation Guidance

##### Tri-Tier Remediation Plan
1. **Tactical Quick Fix (Immediate — Apply within 24–48 Hours):**
   - `[Immediate configuration change, WAF virtual patch rule, or input filter allowlist to prevent exploitation.]`
2. **Strategic Proper Fix (Definitive — Apply within Current Sprint):**
   - `[Architectural fix, parameterized queries, canonical path resolution, or secure library implementation.]`
3. **Architectural Hardening (Systemic — Long-Term):**
   - `[Zero Trust principle, least-privilege service account permissions, network segmentation, or egress filtering.]`

##### MITRE D3FEND Countermeasures
- `[D3-XXX]`: `[Defensive Technique Name]` — *[Specific implementation guidance for target environment]*
- `[D3-YYY]`: `[Defensive Technique Name]` — *[Specific implementation guidance for target environment]*

##### References & External Advisories
- `[https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-YYYY-NNNNN]`
- `[https://owasp.org/www-project-top-ten/]`
- `[Vendor Security Advisory Link]`

---

#### 12. Retest & Artifact Cleanup Verification

- **Testing Canary Identifiers:** `[e.g., nf_canary_20260927_0042.txt]`
- **Canary Cleanup Verification:**
  - Baseline Target Cleanup: Verified HTTP 404 / File Absent on `[Target Asset / Canary Path]`
  - Verified by: `[agents/validation.md]` per SOP-05
- **Post-Remediation Retest Status:**
  - Status: `[PENDING_RETEST | RESOLVED | REOPENED]`
  - Retest Agent: `[agents/fix-verifier.md]`
  - Retest Date: `[YYYY-MM-DD / Unverified]`
  - Retest Notes: `[Outcome of patch validation re-test]`

---

*(Optional Domain Extensions: Attach if finding pertains to Supply Chain, OT/ICS, Active Directory, or AI/LLM)*

<!-- Domain Extension: Software Supply Chain -->
<!--
#### Supply Chain Metadata
- Affected Package: [package_name]@[version] (Ecosystem: [npm | PyPI | Maven | Go | Cargo])
- Dependency Confusion Vector: [Internal namespace unclaimed on public registry]
- SLSA Provenance Tier: [SLSA Level 0 / 1 / 2 / 3]
-->

<!-- Domain Extension: Operational Technology / ICS -->
<!--
#### OT/ICS Metadata
- Industrial Protocol: [Modbus TCP | DNP3 | S7comm | EtherNet/IP | OPC-UA]
- Purdue Model Level: [Level 0 Process | Level 1 Basic Control | Level 2 Supervisory]
- Safety System Impact: [none | process-degradation | safety-instrumented-function-trip]
-->
