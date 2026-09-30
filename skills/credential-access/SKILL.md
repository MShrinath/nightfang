---
name: credential-access
description: Credential access assessment covering LSASS memory protection auditing (RunAsPPL, Credential Guard), local credential store evaluation (SAM, LSA secrets, DPAPI), browser/vault secret extraction analysis, and token/PRT session hijacking resistance.
domain: cybersecurity
subdomain: credential-access
tags: [credential-access, lsass, mimikatz, dpapi, sam, prt, token-theft, credential-dumping, kerberos-tickets]
mitre_attack: [T1003, T1555, T1552, T1110, T1558, T1134.001]
d3fend_techniques: [D3-CAD, D3-EAA, D3-PSA, D3-CAA]
version: "1.0"
---

# Credential Access Resilience Skill

Methodology for assessing identity store security, auditing local host credential protection mechanisms, evaluating EDR alerting on memory inspection, and testing token theft resistance.

> **SAFETY & HITL GOVERNANCE**: Active extraction of memory dumps, accessing local credential vaults, or reading sensitive process tokens strictly requires explicit Human-in-the-Loop authorization per [SOP-04](../../references/sops.md#sop-04-human-in-the-loop-hitl-exploitation-gate). Zero production credentials may be altered, cracked, or exfiltrated per [SOP-05](../../references/sops.md#sop-05-proof-of-concept-safety--artifact-cleanup).

---

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `nanodump` | Obfuscated LSASS minidump with handle duplication & PSS | `nanodump.exe --write <PATH>` | ProcDump / Task Manager |
| `SharpDPAPI` | C# implementation of DPAPI backup key & master key audit | `SharpDPAPI.exe triage` | Native PowerShell DPAPI inspection |
| `Rubeus` | Kerberos interaction & ticket inspection (audit mode) | `Rubeus.exe triage` | `klist` / `klist.exe purge` |
| `Atomic Red Team` | Atomic validation of credential access primitives | `Invoke-AtomicTest T1003.001 -ShowDetails` | Manual read of dummy test secrets |
| `Sysmon` | Process access monitoring for LSASS handle requests | Log review (Event ID 10: ProcessAccess) | Windows Audit Object Access (Event 4656/4663) |

---

## Methodology

### 1. LSASS Memory Protection & Dumping Resistance (T1003.001)
Evaluate endpoint controls protecting the Local Security Authority Subsystem Service (`lsass.exe`):
- **LSA Protection (RunAsPPL)**:
  - Inspect registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`.
  - Verify whether `lsass.exe` executes as a Protected Process Light (PPL), blocking non-kernel process handle acquisition (`PROCESS_VM_READ`).
- **Windows Defender Credential Guard (Virtualization-Based Security - VBS)**:
  - Check whether NTLM and Kerberos secret keys are isolated in the `LsaIso.exe` virtualized container.
- **Process Access Telemetry**:
  - Test EDR / Sysmon alerting when a process opens a handle to `lsass.exe` with access mask `0x1010` (`PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`) or `0x1F0FFF` (`PROCESS_ALL_ACCESS`).

### 2. Local Host Secret Store Auditing (T1003.002, T1003.004)
Inspect host configuration for exposed offline credential databases:
- **SAM & SYSTEM Registry Hives**:
  - Verify file permissions on `%SystemRoot%\System32\config\SAM` and `%SystemRoot%\System32\config\SYSTEM`.
  - Audit volume shadow copy service (VSS) permissions to ensure unprivileged users cannot read shadow copy snapshots of registry hives.
- **LSA Secrets & Service Accounts**:
  - Audit registry keys under `HKLM\SECURITY\Policy\Secrets` for plaintext passwords assigned to services or scheduled tasks.
- **Data Protection API (DPAPI, T1555)**:
  - Audit storage of DPAPI Master Keys in `%APPDATA%\Microsoft\Protect\<SID>`.
  - Evaluate backup key access permissions on domain controllers.

### 3. Browser & Application Credential Vaults (T1555.003)
Assess protection of stored credentials across client software:
- **Chromium & Firefox Vaults**:
  - Inspect SQLite database permissions (`Login Data`, `Cookies`, `Web Data`) in user application profiles.
  - Verify DPAPI decryption requirements (`Local State` encrypted key).
- **Password Manager & KeePass Storage**:
  - Audit file permissions on `.kdbx` files and evaluate whether application memory leaks master passwords during unlock events.

### 4. Token & Session Credential Harvesting (T1134.001, T1528)
Assess identity token isolation and theft resistance:
- **Primary Refresh Token (PRT) Extraction**:
  - On Microsoft Entra ID (Azure AD) joined endpoints, inspect TPM (Trusted Platform Module) binding of the Primary Refresh Token.
  - Audit CloudAP plugin token broker permissions.
- **Kerberos Ticket Cache (T1558)**:
  - Inspect local user LSA ticket cache for reusable Ticket-Granting Tickets (TGTs).
- **Token Impersonation & Delegation**:
  - Evaluate whether services running under service accounts can duplicate tokens of logged-in administrative users (`SeImpersonatePrivilege`).

---

## Defensive Pairing & Detection Engineering

| Attack Technique | MITRE D3FEND Countermeasure | Detection Logic Specification |
| :--- | :--- | :--- |
| **T1003.001** (LSASS Memory) | `D3-CAD` (Credential Access Detection) | Sysmon Event ID 10: SourceImage != legitimate system binary (e.g. not `csrss.exe`) requesting `PROCESS_VM_READ` on `TargetImage: lsass.exe` |
| **T1003.002** (SAM Hive Read) | `D3-EAA` (Execution Access Audit) | Windows Security Event ID 4656: Handle request to `\Device\HarddiskVolume*\Windows\System32\config\SAM` |
| **T1555.003** (Browser Credential) | `D3-PSA` (Process Spawn Analysis) | Sigma: Non-browser process reading files under `%AppData%\Local\Google\Chrome\User Data\*\Login Data` |

---

## Output Contract

- Credential Access Exposure Report detailing memory protection posture, LSA protection status, and vault security.
- Standardized finding records formatted per [`schemas/finding.md`](../../schemas/finding.md).
