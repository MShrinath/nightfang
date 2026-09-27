---
name: purple-team
description: Purple team adversary emulation and detection engineering skill covering threat-informed execution (Atomic Red Team, CALDERA), the detect-tune-validate loop, MTTD measurement, and detection gap visualization.
domain: cybersecurity
subdomain: purple-team-adversary-emulation
tags: [purple-team, emulation, atomic-red-team, caldera, detection-engineering, mttd, dett&ct]
mitre_attack: [T1190, T1059, T1558, T1003, T1021]
d3fend_techniques: [D3-DTE, D3-TVE]
version: "1.0"
---

# Purple Team Adversary Emulation Skill

Collaborative methodology bridging offensive TTP emulation with defensive detection validation to measure Mean Time to Detect (MTTD), eliminate blind spots, and tune security telemetry.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `invoke-atomicredteam` | Scripted atomic test execution against local/remote hosts | `Invoke-AtomicTest T1003.001 -ShowDetails` | Manual CLI emulation |
| `caldera` | Automated adversary emulation platform | API trigger via CALDERA server | Standalone atomic scripts |
| `sigma` / `sigmac` | Generic detection signature compiler | `sigma convert -t splunk rule.yml` | Manual query translation |

## Methodology

### 1. The Detect-Tune-Validate Loop
The purple team cycle executes in 4 continuous steps for each technique:

```
[1. Emulate] ──► [2. Inspect Telemetry] ──► [3. Tune Rule] ──► [4. Re-Verify]
   Offensive         SIEM / EDR / Logs         Engineers            Confirm
  Benign PoC         Alert Generated?         Write Sigma         Detection
```

1. **Emulate**: Execute benign, single-purpose atomic unit test (Atomic Red Team) matching a specific ATT&CK technique ID.
2. **Inspect Telemetry**: Verify whether raw telemetry was ingested into the SIEM/EDR:
   - Level 0: None (No logs generated).
   - Level 1: Telemetry (Event logged, but no detection rule triggered).
   - Level 2: Detection (Alert fired in SIEM/EDR).
   - Level 3: Prevention (Action proactively blocked by host/network control).
3. **Tune Rule**: If detection failed, draft or update detection rules (Sigma, Sentinel KQL, Splunk SPL, Elastic EQL).
4. **Re-Verify**: Re-execute atomic test to prove that the new rule fires reliably without false positives.

### 2. Detection Metrics & Coverage Measurement
- **Mean Time to Detect (MTTD)**: Measure duration in seconds from atomic execution timestamp to alert ingestion timestamp in SIEM.
- **DeTT&CT / ATT&CK Navigator Layer**: Compile JSON heatmap visualizing organization's defensive coverage across all ATT&CK tactics.

## Output
- Purple team matrix with baseline vs tuned detection statuses and MTTD metrics.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
