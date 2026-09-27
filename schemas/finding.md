# NIGHTFANG Finding Schema

Version: `1.0.0`  
Standardized finding schema for all NIGHTFANG agents (Recon, Scanner, AI Security, Validation, Reporter).

---

## 1. Overview

All NIGHTFANG agents must record vulnerabilities, security weaknesses, and validated findings adhering to this shared schema. Standardizing findings decouples discovery from presentation:
- **Scanner & AI Security Agents** populate discovery, evidence, and initial confidence/severity.
- **Validation Agents** update confidence to verified levels (7-10), attach proof-of-concept evidence, and refine impact.
- **Reporter Agents** ingest findings across the swarm to compile final executive deliverables and remediation matrices.
- **Host Runtime (Hermes)** consumes finding summaries for operator alerts across any configured UI (Telegram, Discord, CLI, Web).

---

## 2. Schema Definition

```yaml
finding:
  id: string              # Unique finding identifier (e.g., "NF-2026-001")
  title: string           # Clear, descriptive title of the vulnerability
  target: string          # Target host, domain, URL, IP:port, or asset identifier
  category: string        # Finding category (e.g., web, api, network, ai_prompt_injection, mcp_audit, auth, rce)
  timestamp: string       # ISO-8601 timestamp when finding was recorded

  confidence:
    score: integer        # Dual Ranking Confidence Score (1-10)
    rationale: string     # Justification for the confidence score

  severity:
    score: integer        # Dual Ranking Severity Score (1-10)
    level: string         # Categorical rating: informational | low | medium | high | critical
    rationale: string     # Justification for the severity score

  evidence:
    - type: string        # http_request, http_response, command_output, screenshot, log, prompt_transcript
      description: string # Context for this evidence item
      data: string        # Raw request/response, shell command + stdout, payload used

  reproduction:
    - step: integer       # Sequential step number
      action: string      # Specific action to reproduce
      command: string     # Optional exact command or payload

  impact:
    technical: string     # Technical impact (e.g., unauthenticated arbitrary file read, admin session hijack)
    business: string      # Business impact (e.g., customer PII exposure, service outage, compliance violation)

  remediation:
    guidance: string      # Step-by-step instructions to remediate the vulnerability
    mitre_d3fend:         # Applicable MITRE D3FEND defensive techniques
      - id: string        # e.g., "D3-UVI"
        name: string      # e.g., "User Input Validation"
    references:           # Relevant advisories, RFCs, or documentation links
      - string

  classifications:
    cvss_v31:
      vector: string      # CVSS:3.1/AV:... vector string
      base_score: number  # 0.0 - 10.0
    mitre_attack:         # Applicable MITRE ATT&CK technique IDs
      - id: string        # e.g., "T1190"
        name: string      # e.g., "Exploit Public-Facing Application"
    mitre_atlas:          # Applicable MITRE ATLAS technique IDs (for AI/LLM findings)
      - id: string        # e.g., "AML.T0054"
        name: string      # e.g., "LLM Prompt Injection"
    cwe:                  # Common Weakness Enumeration IDs
      - id: string        # e.g., "CWE-89"
        name: string      # e.g., "Improper Neutralization of Special Elements used in an SQL Command"
    owasp:                # OWASP Top 10 or OWASP LLM Top 10 classification
      - id: string        # e.g., "A03:2021" or "LLM01:2025"
        name: string      # e.g., "Injection" or "Prompt Injection"
```

---

## 3. Dual Ranking System Definitions

Every finding must be graded using NIGHTFANG's dual 1–10 scoring model:

### Confidence Score (1–10)
Measures certainty that the vulnerability is genuine and exploitable on the target.

| Score Range | Level | Description | Criteria |
| :--- | :--- | :--- | :--- |
| **1 – 3** | **Theoretical** | Inferred from passive data, version banners, or OSINT | No behavioral verification. Software version is historically vulnerable, but configuration or patch status is unverified. |
| **4 – 6** | **Likely** | Behavioral indicator observed | Error messages, anomaly responses, timing differences, or reflection observed, but payload execution is not yet proven. |
| **7 – 9** | **Confirmed** | Verified via active non-destructive testing | Harmless canary payload executed (e.g., DNS exfiltration, `sleep` verification, math evaluation, benign canary string reflection). |
| **10** | **Demonstrated** | Fully exploited and weaponized | Exploit fully demonstrated under authorized HITL approval with tangible access, data extraction, or code execution confirmed. |

### Severity Score (1–10)
Measures potential technical and operational impact if exploited.

| Score Range | Severity Level | Description & Impact Scope |
| :--- | :--- | :--- |
| **1 – 2** | **Informational** | Best practice deviation, informational disclosure (e.g., verbose server banners, missing non-critical security headers). No direct exploit path. |
| **3 – 4** | **Low** | Minimal impact. Requires high user interaction, highly restrictive prerequisites, or discloses non-sensitive internal metadata. |
| **5 – 6** | **Medium** | Notable impact with realistic attack path. Direct CSRF on non-critical actions, reflected XSS without session fixation, rate-limit absence, or localized Denial of Service. |
| **7 – 8** | **High** | Significant compromise. Stored XSS affecting privileged users, unauthenticated access to sensitive data, SQL injection without system command execution, privilege escalation. |
| **9 – 10** | **Critical** | Complete system takeover, unauthenticated Remote Code Execution (RCE), host filesystem compromise, mass database exfiltration, or complete LLM guardrail bypass granting tool execution. |

> **Scoring System Disambiguation**
>
> NIGHTFANG operates three **independent, non-interchangeable** scoring systems. Agents must never use one as a proxy for another:
>
> | System | Range | Purpose | When Assigned |
> | :--- | :--- | :--- | :--- |
> | **Nightfang Confidence** | 1 – 10 | How certain we are the vulnerability is real and exploitable | At discovery; upgraded at each validation stage |
> | **Nightfang Severity** | 1 – 10 | NIGHTFANG's opinionated estimate of potential impact | At discovery; may be revised after exploitation data |
> | **CVSS v3.1 Base Score** | 0.0 – 10.0 | Industry-standard formula-based score derived from the CVSS vector string | After validation; requires complete AV/AC/PR/UI/S/C/I/A values |
>
> **`Nightfang Severity = 8` does not mean `CVSS Base Score = 8.0`.** CVSS is computed from a vector string — not assigned from the severity matrix above. A finding may have Nightfang Severity 9 and CVSS 6.8, or vice versa, depending on attack complexity, prerequisites, and scope. Record all three independently in `classifications.cvss_v31` and `confidence.score` / `severity.score`.

---

## 4. Concrete Example

```yaml
finding:
  id: "NF-2026-0042"
  title: "Unauthenticated Remote Code Execution via Path Traversal in File Export Endpoint"
  target: "https://target-app.internal/api/v1/export"
  category: "web_api_rce"
  timestamp: "2026-09-22T21:40:00Z"

  confidence:
    score: 8
    rationale: "Arbitrary file read confirmed non-destructively via canary /etc/issue retrieval and out-of-band DNS callback."

  severity:
    score: 10
    level: "critical"
    rationale: "Allows unauthenticated attackers to write arbitrary templates and trigger server-side code execution under the web service account."

  evidence:
    - type: "http_request"
      description: "Triggering traversal via filename parameter"
      data: |
        POST /api/v1/export HTTP/1.1
        Host: target-app.internal
        Content-Type: application/json

        {"filename": "....//....//etc/issue", "format": "pdf"}
    - type: "http_response"
      description: "Server response containing /etc/issue contents"
      data: |
        HTTP/1.1 200 OK
        Content-Type: application/json

        {"status": "success", "content": "Debian GNU/Linux 12 \\n \\l"}

  reproduction:
    - step: 1
      action: "Send JSON payload targeting /api/v1/export with traversal sequence in filename"
      command: "curl -s -X POST https://target-app.internal/api/v1/export -H 'Content-Type: application/json' -d '{\"filename\": \"....//....//etc/issue\", \"format\": \"pdf\"}'"
    - step: 2
      action: "Observe reflection of system file contents in the returned JSON object"

  impact:
    technical: "Arbitrary filesystem read and downstream template write resulting in Remote Code Execution (RCE)."
    business: "Complete compromise of backend processing tier and exfiltration of production secrets."

  remediation:
    guidance: "Enforce strict basename validation against an allowlist of permitted export templates. Prohibit path separators and resolve all paths to a canonical restricted directory before reading."
    mitre_d3fend:
      - id: "D3-UVI"
        name: "User Input Validation"
      - id: "D3-FP"
        name: "File Path Restriction"
    references:
      - "https://owasp.org/www-community/attacks/Path_Traversal"

  classifications:
    cvss_v31:
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
      base_score: 10.0
    mitre_attack:
      - id: "T1190"
        name: "Exploit Public-Facing Application"
      - id: "T1059"
        name: "Command and Scripting Interpreter"
    cwe:
      - id: "CWE-22"
        name: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
    owasp:
      - id: "A01:2021"
        name: "Broken Access Control"
```
