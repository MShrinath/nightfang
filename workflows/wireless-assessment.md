# Wireless & RF Security Assessment Workflow

**Workflow ID**: `wireless-assessment`  
**Description**: On-site and perimeter wireless security assessment covering 802.11 WiFi, WPA-Enterprise, rogue AP detection, and Bluetooth Low Energy (BLE).  
**Required Agents**: `wireless-pentester`, `validation`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Intake & Scope Governance**: Verify authorized corporate ESSIDs, BSSIDs, facility boundaries, and regulatory radio frequency constraints per SOP-01.
2. **Spectrum Reconnaissance (`wireless-pentester`)**:
   - Passive spectrum sweep across 2.4 GHz, 5 GHz, and 6 GHz bands.
   - Map active access points, channel allocation, signal strengths, and client association states.
   - Detect rogue access points and unauthorized ad-hoc or cellular tethering devices.
3. **Protocol & Authentication Auditing (`wireless-pentester`)**:
   - Audit WPA2/WPA3 configuration and evaluate WPA3 downgrade transition risks.
   - Inspect WPA-Enterprise 802.1X certificate validation enforcement across client devices.
4. **Bluetooth & IoT RF Probing (`wireless-pentester`)**:
   - Enumerate BLE peripherals, advertised services, and unauthenticated GATT characteristics.
5. **Operator Approval Gate (HITL)**: Request operator approval before transmitting active evil twin beacons or client deauth frames per SOP-04.
6. **Controlled Validation (`validation`)**: Capture evidence transcripts and confirm encryption weaknesses without user disruption.
7. **Final Deliverable Compilation (`reporter`)**: Compile wireless security posture report and rogue access point inventory.
