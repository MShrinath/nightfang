---
name: privilege-escalation
description: >-
  Use this skill for post-exploitation privilege escalation. Covers both
  Linux and Windows escalation techniques including SUID abuse, kernel
  exploits, misconfigured services, credential harvesting, and AD-based
  escalation. Activate after initial access has been gained with operator
  approval.
---

# Privilege Escalation

Escalate privileges after gaining initial access.

## ⚠️ PREREQUISITE: Operator approval required before using this skill.

## Linux Privilege Escalation

### Enumeration Tools
| Tool | Command |
|------|--------|
| `linpeas` | `./linpeas.sh` |
| `linux-exploit-suggester` | `./les.sh` |
| `pspy` | `./pspy64` (process snooping) |

### Common Vectors
- [ ] SUID/SGID binaries → `find / -perm -4000 2>/dev/null`
- [ ] Writable `/etc/passwd` or `/etc/shadow`
- [ ] Sudo misconfigurations → `sudo -l`
- [ ] Cron jobs running as root
- [ ] Kernel exploits (match with `uname -a`)
- [ ] Capabilities → `getcap -r / 2>/dev/null`
- [ ] Docker group membership
- [ ] NFS no_root_squash
- [ ] Writable PATH directories
- [ ] Sensitive files: SSH keys, config files, history files
- [ ] GTFOBins for sudo/SUID binaries

## Windows Privilege Escalation

### Enumeration Tools
| Tool | Command |
|------|--------|
| `winpeas` | `.\winPEASx64.exe` |
| `PowerUp` | `Invoke-AllChecks` |
| `Seatbelt` | `.\Seatbelt.exe -group=all` |
| `SharpUp` | `.\SharpUp.exe` |

### Common Vectors
- [ ] Unquoted service paths
- [ ] Weak service permissions
- [ ] AlwaysInstallElevated
- [ ] Stored credentials → `cmdkey /list`
- [ ] Token impersonation (Potato attacks)
- [ ] DLL hijacking
- [ ] Registry autoruns
- [ ] Scheduled tasks
- [ ] Kerberoasting (domain joined)
- [ ] SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege

## Procedure

1. **Enumerate**: Run automated enumeration tools
2. **Analyze**: Review output for escalation vectors
3. **Prioritize**: Rank vectors by likelihood and impact
4. **Report**: Send findings to operator via Telegram (⚠️ HITL)
5. **Exploit**: Attempt approved escalation vectors
6. **Verify**: Confirm elevated privileges
7. **Document**: Record exact steps for reproduction

## Output
- Current privilege level
- Discovered escalation vectors with Confidence/Severity
- Exploitation steps (if approved)
- Post-escalation access level achieved
