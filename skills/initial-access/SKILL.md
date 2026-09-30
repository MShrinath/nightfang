---
name: initial-access
description: Initial access vector assessment covering external perimeter gateway auditing (VPNs, Citrix/RDS, SSO), delivery staging inspection (ISO/VHD containers, MOTW handling, HTML smuggling), and DLL sideloading vulnerability analysis.
version: "2.0"
domain: cybersecurity
subdomain: initial-access
tags: [initial-access, delivery-staging, motw, html-smuggling, dll-sideloading, remote-services, perimeter-gateway]
mitre_attack: [T1190, T1566, T1189, T1133, T1574.002, T1078]
d3fend_techniques: [D3-MTA, D3-EAA, D3-FCI, D3-EI]
---

# Initial Access Resilience Skill

Methodology for assessing external perimeter resilience, evaluating payload delivery filter efficacy, analyzing client-side execution boundaries, and auditing application search order hijacking vectors.

> **SAFETY & HITL GOVERNANCE**: Active testing against external gateways or staging simulated payload delivery mechanisms strictly requires explicit Human-in-the-Loop authorization per [SOP-04](../../references/sops.md#sop-04-human-in-the-loop-hitl-exploitation-gate). Zero unauthorized credential stuffing or destructive execution permitted per [SOP-05](../../references/sops.md#sop-05-proof-of-concept-safety--artifact-cleanup).

---

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `checkdmarc` | Validates SPF, DKIM, and DMARC email authentication records | `checkdmarc <DOMAIN>` | Manual DNS TXT record review |
| `o365spray` | Validates Microsoft 365 / Entra ID tenant lockout and spray defense | `o365spray --validate --domain <DOMAIN>` | Manual login form timing analysis |
| `ProcMon` | Process Monitor for DLL search order and missing DLL detection | Filter: `Process Name is <APP.EXE>` and `Result is NAME NOT FOUND` | Windows SDK `depends.exe` |
| `Atomic Red Team` | Atomic validation of delivery mechanisms and MOTW behavior | `Invoke-AtomicTest T1566.001 -ShowDetails` | Manual benign file staging |
| `Semgrep` | Static analysis of web download scripts for HTML smuggling patterns | `semgrep --config p/security-audit` | Regex pattern matching |

---

## Methodology

### 1. External Remote Services & Gateway Auditing (T1133)
Evaluate security boundaries protecting external enterprise entrypoints:
- **VPN Concentrators & Portals**: Audit public SSL VPN endpoints (Pulse Secure, Fortinet, GlobalProtect) for known version vulnerabilities, missing security patches, and MFA bypass anomalies.
- **Remote Desktop & Citrix Gateways**: Inspect exposed RDP / Citrix StoreFront portals for password spray lockout protections and network level authentication (NLA) enforcement.
- **Single Sign-On (SSO) Gateways**: Evaluate Microsoft Entra ID / Okta portals for conditional access policy gaps (e.g. non-enforced MFA on legacy authentication protocols like ActiveSync or IMAP).

### 2. Container & Mark-of-the-Web (MOTW) Handling (T1566)
Evaluate email gateway, proxy, and endpoint defenses against container-based payload delivery:
- **Mark-of-the-Web (Zone.Identifier) Propagation**:
  - Test whether archive and container formats (ISO, VHD, IMG, 7z) propagate the MOTW security zone (`ZoneId=3`) to nested contents upon mounting or extraction.
- **LNK Shortcut Lure Architecture**:
  - Inspect system policy against `.lnk` files referencing embedded relative PowerShell or LOLBAS command strings.
- **Compiled Formats**:
  - Audit filtering policies for `.chm` (Compiled HTML Help), `.hta`, and `.msi` application installers received from external sources.

### 3. HTML Smuggling & Client-Side Staging (T1027.006)
Assess browser and web gateway inspection against client-side file reconstruction:
- **JavaScript Blob Assembly**:
  - Evaluate web filtering detection when files are dynamically constructed in the browser DOM via JavaScript (`Blob`, `window.URL.createObjectURL`, `msSaveOrOpenBlob`) from base64-encoded strings.
- **Encrypted Archives**:
  - Test perimeter sandbox inspection against password-protected archives where passwords are provided in the web page text.

### 4. DLL Sideloading & Search Order Hijacking (T1574.002)
Evaluate local host software deployments for unsafe library resolution:
- **Standard Search Order Inspection**:
  - Identify third-party signed executables that resolve dynamic link libraries without specifying fully qualified paths.
- **Missing DLL Identification**:
  - Run `ProcMon` with filter `Result is NAME NOT FOUND` on `.dll` paths to discover DLLs searched for in writable directories (e.g., user `AppData`, standard install directories with weak DACLs).
- **Safe DLL Search Mode**:
  - Verify registry setting `HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode`.

---

## Defensive Pairing & Detection Engineering

| Attack Technique | MITRE D3FEND Countermeasure | Detection Logic Specification |
| :--- | :--- | :--- |
| **T1566** (Phishing Attachment) | `D3-MTA` (Message Transfer Agent) | Mail Gateway: Block or quarantine email attachments containing container formats (`.iso`, `.vhd`, `.img`) from external senders |
| **T1574.002** (DLL Sideloading) | `D3-FCI` (File Content Inversion) | Sysmon Event ID 7: ImageLoaded event where a signed system process loads an unsigned DLL from a non-standard directory |
| **T1133** (External Remote Services) | `D3-EAA` (Execution Access Audit) | Sentinel KQL: Alert on multiple failed logins across multiple accounts followed by a single successful login from the same IP (Password Spray) |

---

## Output Contract

- Initial Access Vulnerability Assessment Report detailing perimeter exposure and delivery filtering efficacy.
- Standardized finding records formatted per [`schemas/finding.md`](../../schemas/finding.md).
