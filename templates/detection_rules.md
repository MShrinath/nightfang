# NIGHTFANG Detection Engineering Templates

**ID**: `templates/detection_rules.md`  
**Governing Agent**: [`agents/detection-engineer.md`](../agents/detection-engineer.md)  
**Schema Compliance**: [`schemas/finding.md`](../schemas/finding.md)  
**Purpose**: Standardized, machine-readable detection engineering templates (Sigma rules, Microsoft Sentinel KQL, Splunk SPL, Elastic EQL) paired with offensive findings discovered during NIGHTFANG engagements.

---

## 1. Overview & Red ↔ Blue Pairing Architecture

In accordance with NIGHTFANG's **Red ↔ Blue Pairing Principle**, every verified offensive finding (`schemas/finding.md`) must be translated into actionable detection engineering artifacts. Offensive exploitation without corresponding defensive telemetry leaves client defenders vulnerable to identical techniques from adversaries.

```
┌──────────────────────────────────────────────┐
│           NIGHTFANG Offensive Finding        │
│             (schemas/finding.md)             │
│   • Target Endpoint & Parameter              │
│   • Benign PoC Artifact [EVD-XXX]            │
│   • MITRE ATT&CK ID (e.g., T1190)            │
└──────────────────────┬───────────────────────┘
                       │
                       ▼ Handed to detection-engineer agent
┌──────────────────────────────────────────────┐
│     Detection Engineering Translation Gate   │
│                                              │
│  [Tier 1] Universal Sigma Rule Specification │  ← Vendor-neutral rule definition
│  [Tier 2] Microsoft Sentinel KQL Query       │  ← Azure / M365 cloud SIEM
│  [Tier 3] Splunk SPL Query                   │  ← Enterprise on-prem / cloud SIEM
│  [Tier 4] Elastic EQL Rule                   │  ← Elastic Security / Kibana
│  [Tier 5] MITRE D3FEND Countermeasures       │  ← Active defensive architecture
└──────────────────────────────────────────────┘
```

### Detection Engineering Maturity Ladder (DeTT&CT)
Every finding must classify its defensive coverage tier:
- **`none`**: No logging or telemetry exists for this attack surface.
- **`telemetry`**: Raw events are collected in SIEM/data lakes, but no alert rule is defined.
- **`detection`**: Automated alert triggers when exploitation patterns are observed.
- **`prevention`**: Inline control (WAF, EDR, AppLocker, IPS) blocks the attempt outright.

---

## 2. Universal Sigma Rule Templates

Sigma is the open, vendor-agnostic signature format for SIEM/EDR log repositories.

### Template 2.1: Web Application Exploit Detection (Path Traversal / SQLi / SSRF)

```yaml
title: Potential Path Traversal Exploitation Attempt via File Export Endpoint
id: {{SIGMA_UUID}}
status: test
description: |
  Detects directory traversal sequences and attempts to access sensitive system files
  via HTTP export parameters, matching activity observed in NIGHTFANG finding {{FINDING_ID}}.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://owasp.org/www-community/attacks/Path_Traversal
author: NIGHTFANG Detection Engineer
date: {{CURRENT_DATE}}
modified: {{CURRENT_DATE}}
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.cwe_22
logsource:
  category: webserver
  product: null
detection:
  selection_endpoint:
    cs-method: 'POST'
    cs-uri-stem|contains:
      - '/api/v1/export'
      - '/export'
  selection_traversal_patterns:
    cs-uri-query|contains:
      - '../'
      - '..\'
      - '%2e%2e%2f'
      - '%2e%2e/'
      - '..%2f'
      - '%2e%2e%5c'
    # For body-inspection enabled reverse proxies (WAF/Envoy/ModSecurity):
    post_body|contains:
      - '../'
      - 'etc/issue'
      - 'etc/passwd'
      - 'windows/win.ini'
  filter_internal_scanner:
    c-ip:
      - '127.0.0.1'
      - '::1'
  condition: selection_endpoint and selection_traversal_patterns and not filter_internal_scanner
falsepositives:
  - Legitimate export parameters containing relative paths if poorly designed
  - Internal automated vulnerability assessment runs
level: high
```

### Template 2.2: Process Execution & Web Shell Spawning

```yaml
title: Web Server Spawning Interactive Command Interpreter
id: {{SIGMA_UUID}}
status: stable
description: |
  Detects a web server engine (IIS, Apache, Nginx, Tomcat, NodeJS) spawning an interactive
  shell or script engine, indicative of webshell execution or Remote Code Execution (RCE).
references:
  - https://attack.mitre.org/techniques/T1059/004/
  - https://attack.mitre.org/techniques/T1505/003/
author: NIGHTFANG Detection Engineer
date: {{CURRENT_DATE}}
tags:
  - attack.execution
  - attack.persistence
  - attack.t1059.004
  - attack.t1505.003
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\w3wp.exe'
      - '\httpd.exe'
      - '\nginx.exe'
      - '\tomcat.exe'
      - '\node.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\whoami.exe'
      - '\net.exe'
      - '\nltest.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Custom administrative tools configured to trigger scripts via web interfaces (must be investigated)
level: critical
```

---

## 3. Microsoft Sentinel (KQL) Templates

Kusto Query Language templates optimized for Microsoft Sentinel, Microsoft Defender for Cloud, and Azure Monitor logs.

### Template 3.1: W3C / Application Gateway Web Attack Detection

```kql
// Title: Web Attack Pattern Detection on Protected Endpoints
// Finding Ref: {{FINDING_ID}}
// MITRE ATT&CK: T1190
let TargetEndpoint = "{{ENDPOINT_PATH}}"; // e.g. "/api/v1/export"
let LookbackPeriod = 24h;
W3CIISLog
| where TimeGenerated >= ago(LookbackPeriod)
| where csUriStem has TargetEndpoint
| where csMethod in ("GET", "POST", "PUT")
| extend DecodedQuery = url_decode(csUriQuery)
| where DecodedQuery has_any ("../", "..\\", "etc/passwd", "etc/issue", "cmd.exe", "whoami", "SELECT ", "UNION ", "SLEEP(")
| project TimeGenerated, 
          ClientIP = cIP, 
          Method = csMethod, 
          UriStem = csUriStem, 
          Query = DecodedQuery, 
          HttpStatus = scStatus, 
          BytesSent = scBytes, 
          UserAgent = csUserAgent
| summarize AttemptCount = count(), 
            TargetEndpoints = make_set(UriStem), 
            StatusSet = make_set(HttpStatus) 
            by ClientIP, bin(TimeGenerated, 15m)
| where AttemptCount >= 1
| sort by AttemptCount desc
```

### Template 3.2: Azure AD / Entra ID Anomaly Detection

```kql
// Title: Suspicious High-Privilege Role Assignment or Service Principal Abuse
// Finding Ref: {{FINDING_ID}}
// MITRE ATT&CK: T1098
let LookbackPeriod = 48h;
AuditLogs
| where TimeGenerated >= ago(LookbackPeriod)
| where OperationName in ("Add member to role", "Add app role assignment to service principal", "Add service principal credentials")
| extend TargetRole = tostring(TargetResources[0].modifiedProperties[1].newValue)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend InitiatingActor = tostring(InitiatedBy.user.userPrincipalName)
| where TargetRole has_any ("Global Administrator", "Privileged Role Administrator", "Security Administrator", "Owner")
| project TimeGenerated, OperationName, InitiatingActor, TargetUser, TargetRole, Result
```

---

## 4. Splunk (SPL) Templates

Search Processing Language templates for Splunk Enterprise, Splunk Cloud, and Splunk Enterprise Security (ES).

### Template 4.1: Web Exploitation & Behavioral Anomaly

```spl
`comment("Title: High-Frequency or Suspicious Web Injection Sequences")`
`comment("Finding Ref: {{FINDING_ID}} | MITRE: T1190")`
index=web sourcetype=access_combined OR sourcetype=iis
| eval endpoint="{{ENDPOINT_PATH}}"
| search uri_path="*{{ENDPOINT_PATH}}*"
| eval decoded_uri=urldecode(uri_query)
| eval match_injection=if(match(decoded_uri, "(?i)(\.\./|union\s+select|sleep\(\d+\)|version\(\)|/etc/passwd)"), 1, 0)
| where match_injection=1
| stats count as injection_attempts, 
        values(status) as statuses, 
        values(decoded_uri) as sample_payloads, 
        earliest(_time) as first_seen, 
        latest(_time) as last_seen 
        by src_ip, uri_path
| where injection_attempts > 0
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort - injection_attempts
```

### Template 4.2: Linux Auditd / Endpoint Execution Telemetry

```spl
`comment("Title: Web Server User Spawning Unexpected Shell Commands")`
`comment("Finding Ref: {{FINDING_ID}} | MITRE: T1059.004")`
index=os sourcetype=auditd type=EXECVE
| eval target_users=mvfilter(match(euid, "^(33|48|1000|1001|www-data|apache|nginx)$"))
| where isnotnull(target_users)
| search (a0="/bin/sh" OR a0="/bin/bash" OR a0="curl" OR a0="wget" OR a0="python*" OR a0="id" OR a0="whoami")
| table _time host euid auid a0 a1 a2 a3
```

---

## 5. Elastic (EQL) Templates

Event Query Language templates designed for Elastic Security, Kibana Alerting, and Fleet integrations.

### Template 5.1: Process Creation EQL Rule

```eql
process where event.category == "process" 
  and event.type == "start"
  and process.parent.name in ("w3wp.exe", "httpd.exe", "nginx.exe", "apache2", "node")
  and (
    process.name in ("sh", "bash", "dash", "cmd.exe", "powershell.exe", "pwsh.exe") 
    or process.args in ("whoami", "id", "hostname", "cat /etc/issue", "cat /etc/passwd")
  )
```

### Template 5.2: Network Outbound Callback on Non-Standard Port

```eql
network where event.category == "network" 
  and event.type == "connection"
  and network.direction == "egress"
  and process.name in ("w3wp.exe", "java", "node", "python3")
  and not destination.port in (80, 443, 53)
```

---

## 6. Pairing Checklist for Detection Engineers

When generating detection rules for a finding:
1. **Specificity vs. Brittleness**:
   - Do NOT key detection solely on the exact benign test payload used by NIGHTFANG (e.g. `{{7*7}}`).
   - Detect the underlying syntax, pattern, sink interaction, or behavioral anomaly.
2. **Telemetry Source Identification**:
   - Explicitly identify the required data source: Web access logs, WAF telemetry, Sysmon Event ID 1 (Process Creation), Linux Auditd, or CloudTrail/AuditLogs.
3. **MITRE ATT&CK & D3FEND Mapping**:
   - Ensure ATT&CK Technique ID matches finding `classifications.mitre_attack`.
   - Ensure defensive countermeasures match finding `remediation.mitre_d3fend`.
4. **False Positive Suppression**:
   - Enumerate known legitimate administrative systems, scheduled tasks, and internal API clients in the exclusion block.
