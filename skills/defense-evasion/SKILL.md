---
name: defense-evasion
description: Defense evasion and endpoint security assessment covering AMSI/ETW telemetry auditing, userland API unhooking analysis, process injection detection, Living off the Land (LOLBAS/GTFOBins) auditing, and in-memory execution resilience.
version: "2.0"
domain: cybersecurity
subdomain: defense-evasion
tags: [defense-evasion, amsi, etw, edr-evasion, process-injection, lolbas, gtfobins, syscalls, unhooking]
mitre_attack: [T1562, T1055, T1218, T1140, T1036, T1112]
d3fend_techniques: [D3-EDR, D3-PSA, D3-EAA, D3-SFA]
---

# Defense Evasion & EDR Resilience Skill

Methodology for assessing endpoint visibility, evaluating EDR telemetry gaps, testing security control bypass resistance, and hardening environments against evasion tradecraft.

> **SAFETY & HITL GOVERNANCE**: Active testing of process injection, telemetry modification, or security software evasion strictly requires explicit Human-in-the-Loop authorization per [SOP-04](../../references/sops.md#sop-04-human-in-the-loop-hitl-exploitation-gate). All validation proofs must be non-destructive (e.g. benign API telemetry verification, clean process termination) per [SOP-05](../../references/sops.md#sop-05-proof-of-concept-safety--artifact-cleanup).

---

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `Sysmon` | Host telemetry & process creation event auditing | Log review via Event Viewer (Event ID 1, 7, 8, 10) | Windows Security Event Log (Audit Process Creation) |
| `PE-sieve` | Scans running processes for inline hooks, shellcode, and hollowed modules | `pe-sieve.exe /pid <PID> /quiet` | `hollows_hunter.exe` |
| `Moneta` | Memory analysis tool identifying unbacked executable code and modified memory | `moneta.exe -p <PID>` | Process Hacker / Process Explorer |
| `Atomic Red Team` | Standardized atomic tests for defense evasion validation | `Invoke-AtomicTest T1562.001 -ShowDetails` | Manual benign API verification |
| `LOLBAS / GTFOBins` | Living-off-the-land binaries reference catalogs | Catalog inspection & policy review | Sysinternals `autoruns` / WDAC policies |

---

## Methodology

### 1. Userland API Hooking & Direct Syscall Resilience
- **Hook Detection**: Inspect `ntdll.dll` function exports in target userland processes using `PE-sieve` to determine which system calls are hooked by active endpoint agents (e.g., `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`).
- **Syscall Handling Assessment**: Evaluate whether EDR kernel sensors (via kernel callbacks, ObRegisterCallbacks) detect execution flow that bypasses userland hooks via direct or indirect syscalls (`SysWhispers`, `Hell's Gate` models).
- **NTDLL Reloading / Unhooking**: Assess detection coverage when an application reads a fresh copy of `ntdll.dll` from disk to restore hooked function prologues.

### 2. Scripting & Telemetry Blinding Auditing (T1562)
- **AMSI (Antimalware Scan Interface, T1562.001)**:
  - Audit whether PowerShell and WSH script buffer scanning is active.
  - Test telemetry generation using benign standard canary strings (e.g., standard AMSI test string).
  - Inspect process memory for unauthorized modifications to `amsi.dll!AmsiScanBuffer`.
- **ETW (Event Tracing for Windows, T1562.006)**:
  - Audit ETW Microsoft-Windows-Threat-Intelligence provider status.
  - Evaluate endpoint alerts when functions like `ntdll!EtwEventWrite` or `EtwNotificationRegister` are patched in memory.

### 3. Process Injection Pattern Analysis (T1055)
Evaluate endpoint detection and prevention controls against standard process injection architectures:
- **Asynchronous Procedure Call (APC) Injection (T1055.004)**: Early Bird APC injection into suspended child processes.
- **Process Hollowing (T1055.012)**: Unmapping target process memory and replacing the section.
- **Module Overloading / DLL Injection (T1055.001)**: Loading payloads into legitimate signed DLL memory spaces.
- **Unbacked Memory Scanning**: Test EDR memory scanners against executable pages (`PAGE_EXECUTE_READWRITE`) lacking disk backing.

### 4. Living off the Land (LOLBAS & GTFOBins, T1218)
- Audit execution boundaries and application allowlisting (AppLocker, Windows Defender Application Control - WDAC):
  - **Script Interpreters**: `mshta.exe`, `cscript.exe`, `wscript.exe`, `powershell.exe -ep bypass`.
  - **Signed Utilities**: `certutil.exe -urlcache`, `rundll32.exe`, `regsvr32.exe /s /u /i`, `bitsadmin.exe`.
  - **Compiler Execution**: `csc.exe`, `vbc.exe`, `msbuild.exe` used for in-line compilation.

---

## Defensive Pairing & Detection Engineering

| Attack Technique | MITRE D3FEND Countermeasure | Detection Logic Specification |
| :--- | :--- | :--- |
| **T1562.001** (AMSI Tampering) | `D3-SFA` (Script File Analysis) | Sentinel KQL / Sysmon: Event ID 10 (ProcessAccess to powershell.exe with `PAGE_EXECUTE_READWRITE`) |
| **T1055** (Process Injection) | `D3-PSA` (Process Spawn Analysis) | Sigma Rule: Cross-process thread creation to remote processes without legitimate handle context |
| **T1218** (Signed Binary Proxy) | `D3-EAA` (Execution Access Audit) | Sysmon Event ID 1: Command line execution of `certutil` with network download flags (`-urlcache`, `-split`) |

---

## Output Contract

- Defense Evasion Assessment Report identifying endpoint detection blindspots and telemetry gaps.
- Standardized finding records formatted per [`schemas/finding.md`](../../schemas/finding.md) with CVSS, MITRE ATT&CK, D3FEND, and Sigma detection rules.
