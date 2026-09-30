# NIGHTFANG Finding Schema

Standardized finding schema for all NIGHTFANG agents across offensive, defensive, audit, and purple-team domains.

---

## 1. Overview

All NIGHTFANG agents must record vulnerabilities, security weaknesses, and validated findings adhering to this shared schema. Standardizing findings decouples discovery from presentation:
- **Scanner, Cloud, Mobile, AD, & AI Security Agents** populate discovery, evidence, tools used, and initial confidence/severity.
- **Validation Agents** update confidence to verified levels (7-10), attach proof-of-concept evidence, and refine impact.
- **Blue & Detection Engineering Agents** attach defensive detection rules (Sigma, KQL, SPL, EQL) and verification status.
- **Reporter Agents** ingest findings across the swarm to compile final executive deliverables and remediation matrices.
- **Host Runtime (Hermes)** consumes finding summaries for operator alerts across any configured UI (Telegram, Discord, CLI, Web).

---

## 2. Schema Definition

```yaml
finding:
  id: string              # Unique finding identifier (e.g., "NF-2026-001")
  title: string           # Clear, descriptive title of the vulnerability
  target: string          # Target host, domain, URL, IP:port, or asset identifier
  category: string        # Finding category (e.g., web, api, network, active_directory, cloud, container, mobile, ai_llm, ics)
  timestamp: string       # ISO-8601 timestamp when finding was recorded

  tool_used: string       # Tool/utility used for discovery (e.g., "nuclei", "nmap", "ffuf", "Certipy", "BloodHound")
  cve: string             # CVE identifier if applicable (e.g., "CVE-2024-21626")

  confidence:
    score: integer        # Dual Ranking Confidence Score (1-10)
    rationale: string     # Justification for the confidence score

  severity:
    score: integer        # Dual Ranking Severity Score (1-10)
    level: string         # Categorical rating: informational | low | medium | high | critical
    rationale: string     # Justification for the severity score

  evidence_grounding:
    score: number         # Evidentiary Grounding Index (0.55 - 0.95)
    bucket: string        # CERTAIN (0.95) | STRONG (0.85) | PROBABLE (0.75) | TENTATIVE (0.65) | WEAK (0.55)
    rationale: string     # Justification for grounding bucket based on artifact reproducibility

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

  # Blue Team & Detection Engineering
  validated_by_blue_skill: string  # Paired blue skill that verified (e.g., "web-sqli-detection")
  detection_status: string         # none | telemetry | detection | prevention (per DeTT&CT ladder)
  detection_rule:
    sigma_id: string               # Sigma rule ID or rule definition
    splunk_spl: string             # Splunk SPL query
    sentinel_kql: string           # Microsoft Sentinel KQL query
    elastic_eql: string            # Elastic EQL query

  # Validation Metadata & Adversarial Gate (Verification provenance)
  validation_gate:
    status: string                 # PASS | KILL | DOWNGRADE | CHAIN_REQUIRED
    evaluator: string              # Agent or operator who evaluated (e.g., "agents/validation.md")
    timestamp: string              # ISO-8601 evaluation timestamp
    provenance_hash: string        # SHA-256 of test artifact at validation time
    q1_in_scope:
      result: boolean              # True if target is within authorized scope
      notes: string                # Target scope verification details
    q2_grounded:
      result: boolean              # True if backed by unedited raw artifact
      evidence_ref: string         # Artifact identifier (e.g., "EVD-042")
      notes: string                # Raw evidence provenance notes
    q3_reachable:
      result: boolean              # True if payload reached vulnerable sink
      notes: string                # WAF/filter bypass confirmation
    q4_controllable:
      result: boolean              # True if input influences program execution flow/state
      notes: string                # Control flow confirmation
    q5_impactful:
      result: boolean              # True if demonstrated impact meets class threshold
      notes: string                # Observed impact notes
    q6_default_vs_custom:
      result: string               # DEFAULT | CUSTOM | NON_STANDARD_DEP
      notes: string                # Configuration prerequisites
    q7_severity_honest:
      result: boolean              # True if CVSS/severity reflects reality vs worst-case
      notes: string                # Severity grounding justification
    verdict:
      status: string               # PASS | KILL | DOWNGRADE | CHAIN_REQUIRED
      failed_gate: string          # Failed gate identifier ("Q1".."Q7") or null if passed
      reason: string               # Mandatory explanation (required for KILL, DOWNGRADE, CHAIN_REQUIRED)
      evidence_refs:               # Artifact IDs supporting the verdict
        - string

  # Purple Team & Adversary Emulation
  emulation:
    atomic_test_id: string         # Atomic Red Team test ID (e.g., "T1190.1")
    caldera_ability_id: string     # CALDERA ability ID if applicable
    coverage_tier: string          # none | telemetry | detection | prevention
    mttd_seconds: integer          # Mean time to detect (if measured)

  # Supply Chain & Software Bill of Materials (SBOM)
  supply_chain:
    package_name: string           # Affected dependency or library
    package_version: string        # Vulnerable version string
    ecosystem: string              # npm | PyPI | Maven | NuGet | Go | Cargo | OCI
    confusion_type: string         # dependency-confusion | typosquatting | malicious-maintainer | known-cve

  # Cyber Threat Intelligence (CTI) & Attribution
  threat_intel:
    actor: string                  # Associated threat actor/group (e.g., "APT29", "FIN7")
    campaign: string               # Campaign name or tracker
    confidence: string             # high | medium | low (estimative language)
    tlp: string                    # TLP:RED | TLP:AMBER | TLP:GREEN | TLP:CLEAR

  # Operational Technology / ICS Specifics
  ics:
    protocol: string               # Modbus | DNP3 | S7comm | EtherNet/IP | OPC-UA
    purdue_level: integer          # 0 to 5
    safety_impact: string          # none | process-degradation | safety-instrumented-function-trip | physical-damage

  classifications:
    cvss_v31:
      vector: string      # CVSS:3.1/AV:... vector string
      base_score: number  # 0.0 - 10.0
    cvss_v40:
      vector: string      # CVSS:4.0/AV:... vector string
      base_score: number  # 0.0 - 10.0
    epss:
      score: number       # EPSS probability score (0.00000 - 1.00000)
      percentile: number  # EPSS percentile (0.0 - 100.0)
    cisa_kev: boolean     # True if listed on CISA Known Exploited Vulnerabilities catalog
    mitre_attack:         # Applicable MITRE ATT&CK technique IDs
      - id: string        # e.g., "T1190"
        name: string      # e.g., "Exploit Public-Facing Application"
    mitre_atlas:          # Applicable MITRE ATLAS technique IDs (for AI/LLM findings)
      - id: string        # e.g., "AML.T0054"
        name: string      # e.g., "LLM Prompt Injection"
    cwe:                  # Common Weakness Enumeration IDs
      - id: string        # e.g., "CWE-89"
        name: string      # e.g., "Improper Neutralization of Special Elements used in an SQL Command"
    owasp:                # OWASP Top 10, API Top 10, or LLM Top 10 classification
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

### Evidence Grounding Index (0.55–0.95)
Measures the mathematical evidentiary grounding and reproducibility of the attached proof artifacts. Independent of confidence or severity.

| Grounding Score | Bucket | Description & Evidentiary Standard |
| :--- | :--- | :--- |
| **0.95** | **CERTAIN** | Fully reproduced with unedited raw request/response proof, SHA-256 digest verification, and deterministic benign canary output. |
| **0.85** | **STRONG** | High-fidelity execution log or tool artifact confirming sink interaction; minor environmental variables unverified. |
| **0.75** | **PROBABLE** | Consistent behavioral anomaly, timing differential, or partial reflection; payload execution likely but not completely verified. |
| **0.65** | **TENTATIVE** | Indirect indication, blind time-based anomaly with network jitter, or non-deterministic response variation. |
| **0.55** | **WEAK** | Theoretical or inferred from version banner, passive OSINT, or unconfirmed error string reflection. |

> **Scoring System Disambiguation**
>
> NIGHTFANG operates five **independent, non-interchangeable** metrics. Agents must never use one as a proxy for another:
>
> | System | Range | Purpose | When Assigned |
> | :--- | :--- | :--- | :--- |
> | **Nightfang Confidence** | 1 – 10 | Certainty that vulnerability is real and exploitable | At discovery; upgraded during validation |
> | **Nightfang Severity** | 1 – 10 | Opinionated operational & business impact score | At discovery; refined after exploitation |
> | **Evidence Grounding** | 0.55 – 0.95 | Evidentiary quality and artifact reproducibility bucket | At evidence capture; verified by Validation Agent |
> | **CVSS v3.1 / v4.0** | 0.0 – 10.0 | Industry-standard formulaic score from vector string | Post-validation; derived strictly from vector |
> | **EPSS** | 0.000 – 1.000 | Empirical likelihood of in-the-wild exploitation | At triage; queried from EPSS model feed |
>
> **`Nightfang Severity = 8` does not mean `CVSS Base Score = 8.0`.** CVSS is computed from a vector string — not assigned from the severity matrix above. A finding may have Nightfang Severity 9 and CVSS 6.8, or vice versa, depending on attack complexity, prerequisites, and scope. Record all metrics independently.

---

## 4. Concrete Example

```yaml
finding:
  id: "NF-2026-0042"
  title: "Unauthenticated Remote Code Execution via Path Traversal in File Export Endpoint"
  target: "https://target-app.internal/api/v1/export"
  category: "web_api_rce"
  timestamp: "2026-09-22T21:40:00Z"
  tool_used: "curl"
  cve: "CVE-2026-11928"

  confidence:
    score: 8
    rationale: "Arbitrary file read confirmed non-destructively via canary /etc/issue retrieval and out-of-band DNS callback."

  severity:
    score: 10
    level: "critical"
    rationale: "Allows unauthenticated attackers to write arbitrary templates and trigger server-side code execution under the web service account."

  evidence_grounding:
    score: 0.95
    bucket: "CERTAIN"
    rationale: "Complete raw HTTP request and response captured verbatim with SHA-256 hash verifying /etc/issue retrieval."

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

  validated_by_blue_skill: "skills/remediation/detection-engineering.md"
  detection_status: "detection"
  detection_rule:
    sigma_id: "proc_creation_win_webshell_traversal"
    splunk_spl: 'index=web status=200 uri_path="/api/v1/export" | where match(post_body, "\.\./\.\.")'
    sentinel_kql: 'W3CIISLog | where csUriStem == "/api/v1/export" and csMethod == "POST"'
    elastic_eql: 'process where event.category == "process" and process.name == "sh"'

  validation_gate:
    status: "PASS"
    evaluator: "agents/validation.md"
    timestamp: "2026-09-22T21:45:00Z"
    provenance_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    q1_in_scope:
      result: true
      notes: "Target https://target-app.internal verified in engagement authorized scope"
    q2_grounded:
      result: true
      evidence_ref: "EVD-0042"
      notes: "Raw HTTP request and response verified with SHA-256 match"
    q3_reachable:
      result: true
      notes: "Payload reached file resolution routine directly; no WAF blocking"
    q4_controllable:
      result: true
      notes: "Filename argument controls absolute path string passed to open()"
    q5_impactful:
      result: true
      notes: "Discloses arbitrary OS configuration and system release metadata"
    q6_default_vs_custom:
      result: "DEFAULT"
      notes: "Endpoint is active in standard production deployment"
    q7_severity_honest:
      result: true
      notes: "CVSS 10.0 reflects direct unauthenticated remote exploit path"
    verdict:
      status: "PASS"
      failed_gate: null
      reason: "All 7 adversarial gates satisfied with reproducible benign evidence artifact"
      evidence_refs:
        - "EVD-0042"

  classifications:
    cvss_v31:
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
      base_score: 10.0
    cvss_v40:
      vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
      base_score: 10.0
    epss:
      score: 0.94231
      percentile: 98.4
    cisa_kev: true
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
