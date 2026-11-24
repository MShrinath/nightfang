# Low-Level & Specialized Attack Playbooks (817 Execution Standards)

Authoritative reference catalog of **817 specialized execution playbooks** across exotic hardware, firmware/UEFI, post-quantum cryptography, industrial SCADA safety systems, and deep-forensics incident response. Used dynamically by NIGHTFANG agents (e.g. `forensics-analyst`, `firmware-analyst`, `scada-attacker`, `crypto-analyzer`, `protocol-pentester`) under Lens 5 of the Native Cognitive Skill Matrix.

---

## Catalog Overview & Distribution

| Domain Code | Operational Domain | Playbook Count | Primary Agents | Risk / Impact Profile |
| :--- | :--- | :--- | :--- | :--- |
| **HW-UEFI** | Firmware, UEFI/BIOS & Hardware Implants | 184 Playbooks | `firmware-analyst`, `forensics-analyst` | P0 - Critical / Low-Level Persistence |
| **TPM-HSM** | TPM 2.0, Secure Boot & Key Attestation | 126 Playbooks | `crypto-analyzer`, `forensics-analyst` | P1 - High / Cryptographic Bypass |
| **PQC-CRY** | Post-Quantum Cryptography & Quantum Resistance | 142 Playbooks | `crypto-analyzer`, `code-auditor` | P2 - Medium / Long-Term Forward Secrecy |
| **ICS-SCA** | Industrial Control Systems & SCADA Safety (SIS) | 215 Playbooks | `scada-attacker`, `protocol-pentester` | P0 - Critical / Kinetic & Physical Safety |
| **KRN-DFIR**| Kernel Rootkits, Hypervisors & Deep Forensics | 150 Playbooks | `forensics-analyst`, `malware-analyst` | P0 - Critical / Root Compromise |
| **TOTAL** | **Comprehensive Exotic Domain Coverage** | **817 Playbooks** | Swarm Specialists | Dynamic Dispatch |

---

## 1. HW-UEFI: Firmware, UEFI/BIOS & Hardware Implants (184 Playbooks)

Focuses on low-level pre-boot execution environments, SPI flash integrity, Option ROM backdoors, and SMI/SMM vulnerability auditing.

### Representative Playbook Index
- **`HW-UEFI-001..035`**: SPI Flash Extraction & Firmware Deserialization (Binwalk, UEFIExtractor, Chipsec SPI lock audits).
- **`HW-UEFI-036..075`**: System Management Mode (SMM) Cache Poisoning & SMI handler vulnerability discovery.
- **`HW-UEFI-076..120`**: Option ROM & PCI Expansion ROM signature enforcement and DMA attack surfaces.
- **`HW-UEFI-121..160`**: DXE Driver Taint Analysis: tracing untrusted NVRAM variable inputs to memory execution sinks.
- **`HW-UEFI-161..184`**: Intel Boot Guard / AMD Hardware Validated Boot (HVB) fuse verification and anchor validation.

### Execution Standard
```bash
# Non-destructive SPI flash audit via Chipsec module
python3 -m chipsec.main -m common.bios_wp
python3 -m chipsec.main -m common.smm
```

---

## 2. TPM-HSM: TPM 2.0, Secure Boot & Key Attestation (126 Playbooks)

Focuses on Platform Configuration Register (PCR) measurement validation, sealed storage extraction, remote attestation spoofing, and bus interposition.

### Representative Playbook Index
- **`TPM-HSM-001..028`**: PCR Measurement Drift & Event Log reconstruction (TCG event log parsing against PCR 0-7).
- **`TPM-HSM-029..060`**: LPC/SPI Bus Interposition attack simulation (sniffing TPM unencrypted transit keys during boot).
- **`TPM-HSM-061..095`**: PKCS#11 HSM session hijacking and token authorization boundary auditing.
- **`TPM-HSM-096..126`**: Secure Boot db/dbx revocation list synchronization and shim vulnerability checks (Boothole / Baton Drop).

### Verification Procedure
```bash
# Inspect TPM 2.0 capabilities and active PCR banks (read-only)
tpm2_pcrread sha256:0,1,2,3,4,5,6,7
tpm2_getcap properties-fixed
```

---

## 3. PQC-CRY: Post-Quantum Cryptography & Agility (142 Playbooks)

Focuses on transitioning legacy public-key cryptosystems to NIST post-quantum standards, evaluating hybrid key exchange, and detecting weak lattice parameterizations.

### Representative Playbook Index
- **`PQC-CRY-001..040`**: ML-KEM (Kyber-512/768/1024) decapsulation timing leakage and side-channel analysis.
- **`PQC-CRY-041..075`**: ML-DSA (Dilithium) and SLH-DSA (SPHINCS+) signature verification fuzzing and stateful hash misuse.
- **`PQC-CRY-076..110`**: Hybrid TLS 1.3 Key Exchange Auditing (`X25519MLKEM768` renegotiation downgrade attacks).
- **`PQC-CRY-111..142`**: Cryptographic Agility Inventory: automated AST detection of hardcoded classical asymmetric primitives (RSA-2048, ECDSA-P256).

### Verification Procedure
```bash
# Verify TLS 1.3 hybrid post-quantum cipher suite negotiation
openssl s_client -connect target.tld:443 -curves X25519MLKEM768 -tls1_3
```

---

## 4. ICS-SCA: Industrial Control Systems & SCADA Safety (215 Playbooks)

Focuses on OT protocols, fieldbus networks, Programmable Logic Controllers (PLCs), and Safety Instrumented Systems (SIS) without causing physical disruption.

### Safety Constraint (MANDATORY)
Per NIGHTFANG SOP-01 and SOP-05: **Never issue destructive write commands or reset coils on live production PLCs.** All OT probing defaults to read-only passive inspection and protocol banner discovery.

### Representative Playbook Index
- **`ICS-SCA-001..050`**: Modbus/TCP passive device identification and function code capability mapping (FC 01-04 read audits).
- **`ICS-SCA-051..095`**: DNP3 Outstation discovery, internal indication flags (IIN) extraction, and unsolicited response checks.
- **`ICS-SCA-096..145`**: Rockwell Ethernet/IP & CIP (Common Industrial Protocol) identity attribute read and rack/slot enumeration.
- **`ICS-SCA-146..185`**: Siemens S7comm / S7comm-plus SZL read queries for CPU model, firmware version, and memory allocation.
- **`ICS-SCA-186..215`**: Triconex / Yokogawa Safety Instrumented System (SIS) network isolation and safety zone boundary validation.

### Execution Standard
```bash
# Read-only Modbus device identification (Unit ID 1, Read Device ID)
python3 -c "from pymodbus.client import ModbusTcpClient; c = ModbusTcpClient('target.plc'); c.connect(); print(c.read_device_information())"
```

---

## 5. KRN-DFIR: Kernel Rootkits, Hypervisors & Deep Forensics (150 Playbooks)

Focuses on detecting advanced persistent threats (APTs), hypervisor-level rootkits, DKOM (Direct Kernel Object Manipulation), and conducting live volatile memory extraction.

### Representative Playbook Index
- **`KRN-DFIR-001..035`**: Volatility3 memory carving for unlinked EPROCESS structures and hidden kernel threads.
- **`KRN-DFIR-036..070`**: Linux eBPF rootkit detection and kprobe/uprobe verification (`bpftool prog list`).
- **`KRN-DFIR-071..110`**: Windows SSDT, IDT, and IRP hook discovery via raw physical memory analysis.
- **`KRN-DFIR-111..135`**: Hypervisor introspection: detecting nested virtualization artifacts and VM-exit timing anomalies.
- **`KRN-DFIR-136..150`**: Hardware-assisted memory acquisition (PCIe DMA via Screamer/PCILeech) with cryptographic hashing (SOP-06).

### Verification Procedure
```bash
# Volatile memory forensic triage (read-only)
python3 vol.py -f memory.dmp windows.psscan
python3 vol.py -f memory.dmp windows.malfind
```

---

## Integration with Capability Router & System Prompt

- Referenced by **Lens 5** of the Native Cognitive Skill Matrix in `adapters/hermes/system.md`.
- Invoked automatically by `forensics-analyst`, `firmware-analyst`, and `scada-attacker` when low-level or exotic targets are encountered.
- Enforces strict compliance with `schemas/finding.md` and `references/sops.md`.
