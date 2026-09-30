---
name: active-directory
description: Active Directory domain security assessment covering Kerberos attacks (Kerberoasting, ASREProasting), ADCS certificate template abuse (ESC1-ESC15), ACL misconfigurations, and BloodHound attack path mapping.
domain: cybersecurity
subdomain: active-directory-security
tags: [active-directory, kerberos, kerberoast, asreproast, adcs, bloodhound, certipy, ldap, acl]
mitre_attack: [T1558, T1003, T1484, T1078, T1069]
d3fend_techniques: [D3-ARA, D3-KDC, D3-CAA]
version: "1.0"
---

# Active Directory Security Skill

Comprehensive assessment of on-premises and hybrid Active Directory infrastructure, focusing on identity architecture, credential hygiene, and privilege escalation paths.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `BloodHound-CE` | Graph-based attack path analysis | Ingestion via `bloodhound-python` | Manual LDAP query / `ldapsearch` |
| `Certipy` | Active Directory Certificate Services (ADCS) enumeration & audit | `certipy find -vulnerable -u <USER> -p <PASS> -dc-ip <DC_IP>` | Manual PKI template review |
| `NetExec` | Network credential spray & share enumeration | `netexec smb <SUBNET> -u <USER> -p <PASS> --shares` | `crackmapexec` / Impacket |
| `Impacket` | Protocol manipulation (Kerberos, SMB, WMI, DCE/RPC) | `GetNPUsers.py`, `GetUserSPNs.py` | Native PowerShell cmdlets |

## Methodology

### 1. Domain Reconnaissance & Enumeration
- **Domain Controllers & Global Catalogs**: Locate PDC, Kerberos KDC, and LDAP endpoints via SRV records (`_ldap._tcp.dc._msdcs.<DOMAIN>`).
- **Domain Trust Mapping**: Enumerate internal, external, and forest trusts; check for SID filtering status.
- **Account Policy Auditing**: Inspect lockout thresholds, password complexity, and fine-grained password policies (FGPP).

### 2. Kerberos Protocol Auditing
- **ASREProasting (T1558.004)**: Query users with `DONT_REQ_PREAUTH` attribute enabled; capture offline crackable ticket without password.
- **Kerberoasting (T1558.003)**: Request service tickets (TGS) for accounts with registered Service Principal Names (SPNs); extract ticket hashes for weak service account auditing.
- **Unconstrained & Constrained Delegation (T1558)**: Identify accounts configured for `TRUSTED_FOR_DELEGATION` or Resource-Based Constrained Delegation (RBCD).

### 3. Active Directory Certificate Services (ADCS) Auditing
- Enumerate published certificate templates across enterprise CAs.
- Audit for vulnerable certificate configurations:
  - **ESC1 / ESC2**: Template permits client authentication, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, and low-privilege enrollment permissions.
  - **ESC3**: Template specifies Certificate Request Agent EKU without manager approval.
  - **ESC4**: Template ACL misconfigurations granting `GenericAll` or `WriteDacl` to unprivileged users.
  - **ESC8**: NTLM relaying to ADCS HTTP enrollment endpoints (`certsrv`).

### 4. ACL & Object Permission Abuse
- Graph analysis via BloodHound to identify shortest paths to Tier 0 assets (Domain Admins, Enterprise Admins).
- Detect dangerous DACLs: `GenericAll`, `WriteOwner`, `WriteDacl`, and `ForceChangePassword` on privileged groups or accounts.

### 5. Domain Secret Extraction & DCSync Auditing (T1003.006)
- Cross-link with [`skills/credential-access`](../credential-access/SKILL.md):
  - Audit accounts configured with directory replication rights (`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`) on the root domain NC.
  - Assess network and SIEM detection telemetry for MS-DRSR replication requests initiated from non-DC workstations (Windows Event ID 4662 with access mask `0x100`).

### 6. Kerberos Ticket Forgery & Persistence Resistance (T1558.001 / T1558.002)
- **krbtgt Key Rotation**: Inspect domain `krbtgt` password last set timestamp; verify dual-rotation hygiene to invalidate forged Ticket Granting Tickets (Golden Tickets).
- **PAC Validation & Kerberos Armoring (FAST)**: Verify enforcement of RFC 6113 Flexible Authentication Secure Tunneling (FAST) to mitigate offline ticket tampering.
- **Service Ticket Forgery (Silver Tickets)**: Identify high-privilege service accounts using static weak passwords allowing service ticket forgery without KDC interaction.

### 7. Hybrid Identity & Azure AD Connect Security
- Audit Azure AD Connect staging servers and MSOL service accounts for elevated on-premises replication permissions.
- Evaluate Seamless Single Sign-On (`AZUREADSSOACC` computer account) Kerberos key age and rotation procedures.

## Output
- Active Directory attack path graph and risk inventory.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
