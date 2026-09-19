---
name: recon-active
description: >-
  Use this skill for active reconnaissance. Performs port scanning, service
  enumeration, version detection, and OS fingerprinting using tools like
  nmap. This DOES send traffic to the target. Activate after passive recon
  and only against in-scope targets with operator approval.
---

# Active Reconnaissance

Perform direct scanning and enumeration against authorized targets.

## Tools & Techniques

| Tool | Purpose | Command Example |
|------|---------|----------------|
| `nmap` | Port scan / service detection | See below |
| `masscan` | High-speed port scanning | `masscan -p1-65535 TARGET --rate=1000` |
| `rustscan` | Fast port scanner | `rustscan -a TARGET --ulimit 5000` |
| `enum4linux` | SMB/NetBIOS enumeration | `enum4linux -a TARGET` |
| `snmpwalk` | SNMP enumeration | `snmpwalk -v2c -c public TARGET` |
| `ldapsearch` | LDAP enumeration | `ldapsearch -x -H ldap://TARGET -b '' -s base` |
| `nbtscan` | NetBIOS scanner | `nbtscan TARGET/24` |

## Nmap Scan Phases

### Phase 1: Quick Discovery
```bash
nmap -sn TARGET_RANGE          # Host discovery (ping sweep)
nmap -sS -T4 -p- TARGET        # Full TCP SYN scan
nmap -sU --top-ports 100 TARGET # Top UDP ports
```

### Phase 2: Service Enumeration
```bash
nmap -sV -sC -p PORTS TARGET   # Version detection + default scripts
nmap -O TARGET                  # OS fingerprinting
```

### Phase 3: Targeted NSE Scripts
```bash
nmap --script=vuln TARGET              # Vulnerability scripts
nmap --script=http-enum TARGET         # HTTP enumeration
nmap --script=ssl-enum-ciphers TARGET  # SSL/TLS analysis
nmap --script=smb-os-discovery TARGET  # SMB info
```

## Procedure

1. **Host Discovery**: Identify live hosts in the target range
2. **Port Scanning**: Full TCP scan + top UDP ports
3. **Service Detection**: Identify services and versions on open ports
4. **OS Fingerprinting**: Determine operating system
5. **Script Scanning**: Run relevant NSE scripts based on discovered services
6. **Protocol-Specific Enum**: SMB, SNMP, LDAP, etc. as applicable
7. **Consolidate**: Merge results into attack surface map

## Output Format

- Host/IP inventory with status
- Open ports with service/version info
- OS detection results
- NSE script output highlights
- Identified potential entry points
- Confidence assessment for each finding

## Rate Limiting & Stealth
- Use `-T3` or lower for stealth engagements
- Use `--scan-delay` to avoid triggering IDS/IPS
- Fragment packets with `-f` if needed
- Always check operator preferences for scan aggressiveness
