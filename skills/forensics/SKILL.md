---
name: forensics
description: Digital forensics and incident response (DFIR) skill covering memory analysis (Volatility), disk imaging, timeline reconstruction, YARA rule generation, artifact hunting, and malware static/dynamic triage.
domain: cybersecurity
subdomain: forensics-incident-response
tags: [forensics, dfir, memory, volatility, yara, timeline, incident-response, malware-triage]
mitre_attack: [T1070, T1562, T1005, T1113]
d3fend_techniques: [D3-MDA, D3-FHA, D3-TMA]
version: "1.0"
---

# Digital Forensics & Incident Response Skill

Methodology for preserving evidence, analyzing compromised host artifacts, reconstructing incident timelines, and triaging suspicious artifacts.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `volatility3` | Memory image analysis & process extraction | `python3 vol.py -f mem.raw windows.pslist` | Rekall / memory strings |
| `yara` | Pattern matching & malware signature detection | `yara -r rules.yar <DIRECTORY>` | grep / strings |
| `log2timeline` | Plaso-based super-timeline generation | `log2timeline.py timeline.plaso <IMAGE>` | `mactime` / Autopsy |
| `capa` | Automated capability detection in executable files | `capa sample.exe` | Manual static disassembly |

## Methodology

### 1. Evidence Preservation & Chain of Custody (SOP-06)
- **Live Memory Acquisition**: Dump volatile memory prior to system shutdown (using LiME on Linux or WinPmem on Windows).
- **Cryptographic Verification**: Compute SHA-256 digests immediately upon acquisition; store evidence in read-only write-blocked storage.
- **Order of Volatility**: Memory $\to$ Network state/connections $\to$ Process table $\to$ Disk storage $\to$ Remote logging.

### 2. Memory Forensics (Volatility3)
- **Process Enumeration**: Identify unlinked or hidden processes (`windows.psscan` vs `windows.pslist`).
- **Code Injection Detection**: Scan for unbacked executable memory regions, reflective DLL injection, or hollowed processes (`windows.malfind`).
- **Network Sockets**: Reconstruct active and terminated network sockets at time of acquisition (`windows.netscan`).
- **Command Line & Environment**: Extract process arguments, parent-child relationships, and injected environment variables.

### 3. Disk & Artifact Analysis
- **Windows Artifacts**:
  - Prefetch files (`.pf`): Execution timestamps and run counts.
  - Shimcache & Amcache: Application execution history and SHA-1 hashes.
  - UserAssist & Shellbags: User GUI execution and folder navigation history.
  - USN Journal / $MFT: Deleted file recovery and timestamp manipulation (timestomping) detection.
- **Linux Artifacts**:
  - `/var/log/auth.log` / `secure`: SSH logins, sudo escalations, failed attempts.
  - Cron & Systemd timers: Persistence mechanisms (`/etc/cron*`, `/etc/systemd/system/`).
  - Command History: `.bash_history`, auditd logs (`ausearch`).

### 4. YARA Signature Creation & IOC Extraction
- Extract static indicators of compromise: domain names, IPv4 addresses, registry keys, and unique string patterns.
- Construct optimized YARA rules with condition logic balancing precision and avoidance of false positives.

## Output
- Incident timeline, memory artifact extraction report, and YARA detection signatures.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
