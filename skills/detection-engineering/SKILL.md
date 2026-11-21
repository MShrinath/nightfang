---
name: detection-engineering
description: Detection engineering skill covering Sigma rule generation, KQL/EQL query authoring, detection logic testing, and detection coverage gap analysis.
version: "2.0"
domain: cybersecurity
subdomain: defensive-detection
tags: [detection-engineering, sigma, kql, eql, splunk, sentinel, spl, dett&ct, mitre-attack]
mitre_attack: [T1059, T1003, T1558, T1021, T1078, T1105]
d3fend_techniques: [D3-DTE, D3-TVE, D3-ATA, D3-NTA]
---

# Detection Engineering Skill

Provides production-ready detection rule authoring across SIEM platforms, detection logic validation, and coverage gap analysis.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `sigmac` | Generic Sigma rule compiler | `sigma convert -t splunk detection.yml` | Manual query translation |
| `sigma-cli` | Sigma rule validation & metadata extraction | `sigma check detection.yml` | Manual YAML linting |
| `KQL` | Kusto Query Language for Azure Sentinel/MDE | `let dt = datetime(...)` | Manual query review |
| `EQL` | Event Query Language for Elastic/Splunk | `process where name == "cmd.exe"` | Manual logic review |
| `SPL` | Splunk Search Processing Language | `index=win eventcode=4688` | Manual review |

## Methodology

### 1. Sigma Rule Generation
For every validated finding, generate a Sigma rule following the standard schema:

```yaml
title: [Finding Title]
id: [uuid]
status: test
description: [One-line detection logic]
references:
  - https://attack.mitre.org/techniques/[Txxxx]
tags:
  - attack.t1059
  - detection.threat_hunting
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    NewProcessName: "*cmd.exe*"
  condition: selection
falsepositives:
  - Administrative activity
level: medium
```

### 2. KQL Query Authoring (Azure Sentinel / MDE)
Translate Sigma rules to KQL for Microsoft environments:

```kusto
let timeframe = 1h;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4688
| where NewProcessName has "cmd.exe"
| project TimeGenerated, Computer, Account, NewProcessName
```

### 3. EQL Query Authoring (Elastic / Wazuh)
For Elastic Stack deployments:

```eql
process where process.name == "cmd.exe" and process.parent.name == "svchost.exe"
```

### 4. Detection Logic Testing
- Validate rules against known-good baseline data (no false positives)
- Test against known-bad data from reference corpora
- Measure detection latency (time from event to alert)
- Tune thresholds to balance sensitivity vs. noise

### 5. Coverage Gap Analysis
For each finding:
- Map to MITRE ATT&CK technique
- Identify which log sources can detect it
- Flag findings with zero detection coverage
- Recommend additional telemetry collection

## Integration with Blue Team Agent

This skill is consumed by `agents/blue-team-agent.md` for:
- Sigma rule generation from validated findings
- KQL/EQL query authoring for SIEM deployment
- Detection logic testing against simulated TTPs
- Coverage gap identification and remediation recommendations

## Payload Integration

```python
from scripts.agent_payloads import AgentPayloadResolver
resolver = AgentPayloadResolver()
safe_payloads = resolver.get_safe_payloads("Command Injection")
```