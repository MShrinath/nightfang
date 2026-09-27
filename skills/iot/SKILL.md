---
name: iot
description: IoT and embedded device security assessment covering firmware extraction and static analysis, hardware interfaces (UART, JTAG, SPI, I2C), IoT network protocols (MQTT, CoAP), and RTOS security.
domain: cybersecurity
subdomain: iot-embedded-security
tags: [iot, embedded, firmware, hardware, uart, jtag, mqtt, coap, rtos]
mitre_attack: [T0846, T0855, T1200, T1429]
d3fend_techniques: [D3-FWE, D3-HSA, D3-DCS]
version: "1.0"
---

# IoT & Embedded Systems Security Skill

Methodology for assessing embedded hardware, IoT devices, microcontrollers, and embedded Linux/RTOS platforms.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `binwalk` | Firmware analysis & extraction tool | `binwalk -eM firmware.bin` | `7z` / `dd` / manual carver |
| `ghidra` | SRE decompiler & disassembler for embedded architectures | Interactive GUI / headless script | IDA Pro / Radare2 |
| `mosquitto_sub` | MQTT protocol inspector & subscriber | `mosquitto_sub -h <HOST> -t "#" -v` | Python `paho-mqtt` |
| `flashrom` | EEPROM/Flash chip extraction over SPI/I2C | `flashrom -p ft2232_spi -r dump.bin` | Minipro / CH341A programmer |

## Methodology

### 1. Firmware Analysis & Extraction
- **Unpacking**: Identify filesystem types (SquashFS, CramFS, JFFS2, UBIFS) using `binwalk`.
- **Credential & Secret Discovery**: Scan extracted filesystems for hardcoded SSH private keys, factory root passwords (`/etc/shadow`), hardcoded API endpoints, and encryption keys.
- **Service Configuration**: Inspect init scripts (`/etc/init.d/`, `/etc/systemd/`) for unauthenticated telnet/HTTP services running with root privileges.

### 2. Hardware Debug & Bus Interfacing
- **UART (Universal Asynchronous Receiver-Transmitter)**: Locate pin headers via multimeter. Connect serial adapter (3.3V/5V) to inspect bootloader output (U-Boot) and check for unauthenticated root shells.
- **JTAG / SWD**: Pinout identification using logic analyzer or JTAGulator; verify boundary scan registers and firmware flash read-out protection (RDP).
- **SPI / I2C Bus Sniffing**: Inspect communications between microcontroller and external flash memory during boot to capture decryption keys or configuration data.

### 3. IoT Communication Protocols (MQTT & CoAP)
- **MQTT Broker Auditing**: Test broker for anonymous access, wildcards (`#` and `+`), and sensitive sensor telemetry or control commands.
- **CoAP (Constrained Application Protocol)**: Enumerate resources via `/.well-known/core`; test for unauthenticated resource modification (`PUT`/`POST`).

### 4. Over-The-Air (OTA) Update Security
- Intercept and inspect firmware update traffic:
  - Verify whether firmware download URL uses TLS.
  - Verify cryptographic signature verification before flashing (checking if tampered images are accepted).

## Output
- Embedded hardware vulnerability profile and firmware security audit.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
