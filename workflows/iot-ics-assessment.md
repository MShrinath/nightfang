# IoT & Industrial Control Systems (OT/ICS) Assessment Workflow

**Workflow ID**: `iot-ics-assessment`  
**Description**: Safety-first, passive-priority security assessment of embedded IoT devices, programmable logic controllers (PLCs), and SCADA architectures conforming to IEC 62443.  
**Required Agents**: `scada-attacker`, `iot-pentester`, `validation`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Intake & Industrial Safety Gate**:
   - Verify plant operational state and define zero-disruption constraints with industrial plant operators per SOP-01.
   - Restrict testing to passive network monitoring and offline device/firmware analysis.
2. **Purdue Model Architecture Review (`scada-attacker`)**:
   - Map network segmentation between IT (Levels 4-5) and Industrial Control (Levels 0-3).
   - Audit the Industrial DMZ (IDMZ, Level 3.5) for routing bypasses or multi-homed jump host vulnerabilities.
3. **Passive Network & Protocol Analysis (`scada-attacker`)**:
   - Analyze network traffic captures (PCAPs) from span ports for unencrypted industrial protocols (Modbus, S7comm, DNP3, EtherNet/IP, OPC-UA).
   - Enumerate active PLCs, HMIs, and engineering workstations without active probing.
4. **Firmware & Embedded Hardware Evaluation (`iot-pentester`)**:
   - Unpack firmware images and inspect filesystems for hardcoded credentials, debug binaries, and vulnerabilities.
   - Audit physical device debug ports (UART, JTAG) in offline lab environments.
5. **Operator Approval Gate (HITL)**: Any active query to live PLC or controller hardware strictly requires explicit confirmation from the designated OT operator per SOP-04.
6. **Read-Only Non-Destructive Validation (`validation`)**: Verify protocol accessibility using read-only diagnostic function codes.
7. **IEC 62443 Compliance & Hardening Deliverables (`reporter`)**: Generate industrial cybersecurity assessment report conforming to IEC 62443-3-3.
