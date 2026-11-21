# Methodology: iot

Source: [PentestingEverything/IoT Pentesting](https://github.com/m14r41/PentestingEverything/tree/main/IoT%20Pentesting)

---

# iOT Pentesting

IoT and Embedded Device Security involves assessing the security of connected devices, embedded systems, firmware, and hardware components to identify vulnerabilities that could lead to unauthorized access, data exposure, or device compromise. The assessment includes firmware extraction and analysis, reverse engineering, secure boot validation, hardware interface testing (UART, JTAG, SWD), flash memory analysis, and the identification of hardcoded credentials, insecure configurations, and exposed debug interfaces.

The security review also covers device communication protocols and embedded system controls, including MQTT, BLE, Zigbee, CoAP, and other network services. Key activities include evaluating authentication and authorization mechanisms, encryption implementations, secure storage practices, firmware update processes, and device-to-device or device-to-cloud communications. The objective is to strengthen the security posture of IoT and embedded environments by identifying risks and providing remediation recommendations aligned with industry security best practices

## Baiscs Concept of iOT

<details>
<summary><span style="font-size:20px;"><strong>IoT Core Concepts Cheat Sheet</strong></span></summary>

| Area | Core Concept | What You Should Understand |
|------|-------------|----------------------------|
| IoT Basics | Definition | Physical devices connected to internet for data exchange and control |
| Architecture | Device → Cloud → App | IoT systems are layered: device, communication, cloud, application |
| Device Layer | Embedded System | Hardware (MCU/SoC) running firmware controlling sensors/actuators |
| Firmware | Embedded Software | Low-level code stored in flash memory controlling device behavior |
| OS in IoT | RTOS / Embedded Linux | Lightweight operating systems used in devices |
| Sensors | Data Input | Components that collect real-world data (temperature, motion, light, etc.) |
| Actuators | Physical Output | Components that perform actions (motor, lock, relay, etc.) |
| Communication | Data Transfer | How device talks to cloud/app using protocols |
| Protocols | MQTT / HTTP / CoAP | Lightweight communication protocols used in IoT systems |
| Wireless Tech | Wi-Fi / BLE / Zigbee | Common connectivity methods in IoT devices |
| Cloud Layer | Backend System | Stores data, manages devices, provides APIs |
| APIs | Device Control | Interfaces used by apps/cloud to control IoT devices |
| Mobile App | User Interface | App

---

