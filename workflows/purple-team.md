# Purple Team Adversary Emulation Workflow

**Workflow ID**: `purple-team`  
**Description**: Collaborative adversary emulation and detection engineering workflow connecting offensive execution with defensive telemetry validation.  
**Required Agents**: `purple-team-operator`, `detection-engineer`, `cti-analyst`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Exercise Planning & Threat Selection (`cti-analyst`)**:
   - Establish Priority Intelligence Requirements and select specific threat actor TTPs or ATT&CK techniques for emulation.
2. **Pre-Emulation Telemetry Baseline (`purple-team-operator`)**:
   - Verify health and ingestion state of host EDR, network sensors, and centralized SIEM.
3. **Controlled Atomic Emulation (`purple-team-operator`)**:
   - Execute benign atomic unit tests (Atomic Red Team) under operator supervision.
   - Record exact execution timestamp and host telemetry identifiers.
4. **Defensive Telemetry Inspection (`detection-engineer`)**:
   - Query SIEM/EDR to verify if telemetry was captured and if existing alert rules fired.
   - Determine baseline status on the DeTT&CT ladder (None, Telemetry, Detection, Prevention) and measure MTTD.
5. **Detection Tuning & Engineering (`detection-engineer`)**:
   - If detection was absent or delayed, draft tuned Sigma rules and native queries (KQL, SPL, EQL).
6. **Re-Test Verification (`purple-team-operator`)**:
   - Re-run atomic emulation test to prove the new detection fires cleanly without false alarms.
7. **Coverage Reporting & ATT&CK Layer (`reporter`)**:
   - Export ATT&CK Navigator layer JSON and compile the final purple team assessment deliverable.
