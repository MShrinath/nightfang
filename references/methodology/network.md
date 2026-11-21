# Methodology: network

Source: [PentestingEverything/Network Pentesting](https://github.com/m14r41/PentestingEverything/tree/main/Network%20Pentesting)

---


<details>
<summary><strong> Network Pentesting - Core Concepts</strong></summary>

# Basics of Network Pentesting.

| Domain                   | Description                                                                       | Common Tools                   |
| ------------------------ | --------------------------------------------------------------------------------- | ------------------------------ |
| Scoping & Planning       | Define objectives, scope, targets, testing constraints, and rules of engagement.  | Documentation, Asset Inventory |
| Network Fundamentals     | Understand TCP/IP, OSI, IP addressing, subnetting, routing, and common protocols. | Wireshark, tcpdump             |
| Reconnaissance           | Gather information about the target network and identify potential assets.        | Whois, dig, Amass              |
| Host Discovery           | Identify live hosts and network assets.                                           | Nmap, Masscan, fping           |
| Port Scanning            | Discover exposed ports and accessible services.                                   | Nmap, RustScan, Masscan        |
| Service Enumeration      | Identify services, versions, configurations, and accessible resources.            | Nmap NSE, Netcat, smbclient    |
| Protocol Enumeration     | Assess network protocols such as SMB, DNS, SNMP, FTP, SSH, SMTP, and NFS.         | Nmap NSE, enum4linux, snmpwalk |
| Vulnerability Assessment | Identify vulnerabilities, insecure configurations, and outdated software.         | Nessus, OpenVAS, Nuclei        |
| Exploitation             | Validate identified vulnerabilities through controlled testing.                   | Metasploit, Impacket           |
| Privilege Escalation     | Determine whether elevated privileges can be obtained after initial access.       | WinPEAS, LinPEAS               |
| Post-Exploitation        | Assess the impact of compromise and identify accessible resources.                | Native OS Tools, Impacket      |
| Reporting                | Document findings, evidence, impact, and remediation recommendations.             | Dradis, PlexTrac               |



</details>

---

## Sample Report

See the full **[Metasploitable Pentest Report](/network-pentesting/metasploitable-pentest-report)**: a complete network penetration test of Metasploitable 2, covering the executive summary, methodology, 13 critical findings with working PoCs, a remediation roadmap, and a CVSS appendix.


---

