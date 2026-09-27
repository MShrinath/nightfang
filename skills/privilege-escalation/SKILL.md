---
name: privilege-escalation
description: Linux and Windows local privilege escalation methodology covering SUID binaries, Linux capabilities, sudo misconfigurations, cron jobs, Windows services, token manipulation, UAC bypasses, and unquoted service paths.
domain: cybersecurity
subdomain: privilege-escalation
tags: [privesc, linux-privesc, windows-privesc, suid, sudo, uac, tokens, services]
mitre_attack: [T1548, T1068, T1134, T1574]
d3fend_techniques: [D3-ARA, D3-PSA, D3-EAA]
version: "1.0"
---

# Local Privilege Escalation Skill

Methodology for identifying local configuration flaws, kernel weaknesses, and permission misconfigurations allowing elevation from unprivileged user to root or SYSTEM.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `linpeas` | Automated Linux privilege escalation enumerator | `linpeas.sh -a` | Manual `/bin/find` & `/proc` check |
| `winpeas` | Automated Windows privilege escalation enumerator | `winpeas.exe quiet cmd` | PowerShell `Get-Service` scripts |
| `gtfobins` | Reference catalog of Unix binaries with escape functions | Web/CLI lookup | Manual man page review |
| `lolbas` | Living Off The Land Binaries and Scripts (Windows) | Web/CLI lookup | Sysinternals inspection |

## Methodology

### 1. Linux Local Privilege Escalation
- **SUID/SGID Binaries**: Enumerate executables with setuid bit enabled (`find / -perm -4000 2>/dev/null`); cross-reference with GTFOBins for shell escape or arbitrary file read capabilities.
- **Sudo Misconfigurations**: Inspect `sudo -l` for commands executable with `NOPASSWD`; check for wildcard path abuse or environment variable preservation (`env_keep+=LD_PRELOAD`).
- **Capabilities**: Enumerate elevated POSIX capabilities via `getcap -r / 2>/dev/null` (e.g. `cap_setuid+ep`, `cap_dac_read_search+ep`).
- **Scheduled Tasks & Cron**: Audit `/etc/crontab`, `/etc/cron.*`, and systemd timers for writable scripts executed by root.
- **NFS Root Squashing**: Check `/etc/exports` for `no_root_squash` configurations allowing remote root file creation.

### 2. Windows Local Privilege Escalation
- **Service Permissions & Unquoted Paths**: Enumerate services with unquoted paths containing spaces in non-system directories; inspect services with weak DACLs (`SERVICE_CHANGE_CONFIG`).
- **Token Manipulation**: Check `whoami /priv` for dangerous privileges:
  - `SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege`: Evaluate local token impersonation.
  - `SeBackupPrivilege` / `SeRestorePrivilege`: Read/write access to arbitrary files including SAM and SYSTEM hives.
  - `SeDebugPrivilege`: Process memory inspection and injection.
- **AlwaysInstallElevated**: Check registry keys `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`.
- **Credential Storage**: Check Credential Manager, Registry Autologon (`DefaultPassword`), DPAPI vaults, and unattend files (`sysprep.xml`, `unattend.xml`).

## Output
- Local privilege escalation vector inventory and proof of configuration flaw.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
