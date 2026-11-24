---
name: recon
description: Comprehensive reconnaissance methodologies, passive OSINT, DNS brute-forcing, active port scanning, and tech fingerprinting.
version: "2.0"
domain: cybersecurity
subdomain: reconnaissance
tags: [recon, osint, dns, port-scanning, fingerprinting, attack-surface]
mitre_attack: [TA0043, T1593, T1594, T1596, T1046, T1595, T1018]
d3fend_techniques: [D3-DNST, D3-WHIA, D3-NTA]
---

# Reconnaissance & Attack Surface Mapping

Comprehensive discovery methodologies covering passive intelligence gathering and active network/service enumeration within authorized scopes.

## Tools & Execution Matrix

| Tool | Purpose | Standard Command | Fallback |
| :--- | :--- | :--- | :--- |
| `subfinder` | Passive subdomain enum | `subfinder -d <DOMAIN> -silent` | `amass enum -passive` |
| `amass` | OSINT network mapping | `amass enum -passive -d <DOMAIN>` | `crt.sh API curl` |
| `dig` / `nslookup`| DNS record discovery | `dig <DOMAIN> ANY +noall +answer` | Python `dnspython` |
| `whatweb` | Tech stack identification | `whatweb -a 1 <TARGET>` | `wappalyzer-cli` / curl headers |
| `wafw00f` | WAF presence detection | `wafw00f <TARGET>` | Header heuristics |
| `nmap` | Port & service scan | `nmap -sS -T4 -p- --min-rate 1000 <TARGET>` | `masscan` / `rustscan` |

## Methodology

### 1. Passive Intelligence Gathering (No Traffic to Target)
- **Certificate Transparency Logs**: Query `https://crt.sh/?q=%.<DOMAIN>&output=json` to uncover wildcard and historic subdomains.
- **DNS Enumeration**: Query A, AAAA, CNAME, MX, TXT, SPF, and DMARC records. Inspect TXT records for SaaS verification tokens (Google, MS, Sendgrid).
- **Public OSINT**: Check public GitHub repositories, Pastebin, and Wayback Machine for exposed endpoints and credentials.

### 2. Active Enumeration (Authorized Direct Probing)
- **Subdomain Resolution**: Resolve discovered subdomains to IP addresses. Filter out wildcard DNS catch-alls.
- **Port Discovery**:
  - Scan top 1,000 TCP ports first, followed by full 65,535 scan if authorized.
  - Probe high-risk UDP ports: 53 (DNS), 123 (NTP), 161 (SNMP), 500 (IKE), 1194 (OpenVPN).
- **Service Version Fingerprinting**: Run version detection (`nmap -sV`) to identify software names and build numbers.
- **Web Application Profiling**:
  - Identify web frameworks, application servers, and CMS engines.
  - Test for WAF presence before launching high-throughput tests.
  - Probe standard discovery paths: `robots.txt`, `sitemap.xml`, `security.txt`, `.well-known/`.

### 3. Scope Boundary Validation
- Verify all resolved IPs against operator-approved CIDR ranges and ASNs.
- Flag any asset hosted on third-party CDNs (Cloudflare, Fastly, AWS CloudFront) to prevent scanning shared edge infrastructure.

## Output
- Normalized target inventory (IPs, hostnames, open ports, detected technologies).
- Immediate findings for exposed low-hanging files (`.git`, `.env`, backup archives) per `schemas/finding.md`.
