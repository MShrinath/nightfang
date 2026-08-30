---
name: recon-passive
description: >-
  Use this skill for passive reconnaissance. Gathers OSINT, DNS records,
  WHOIS data, subdomain enumeration, certificate transparency logs, and
  technology fingerprinting WITHOUT sending any traffic to the target.
  Activate when the operator provides a domain or organization name for
  initial intelligence gathering.
---

# Passive Reconnaissance

Perform non-intrusive information gathering that does not alert the target.

## Tools & Techniques

| Tool | Purpose | Command Example |
|------|---------|----------------|
| `whois` | Domain registration data | `whois example.com` |
| `dig` | DNS record enumeration | `dig example.com ANY +noall +answer` |
| `nslookup` | DNS resolution | `nslookup -type=any example.com` |
| `subfinder` | Subdomain discovery | `subfinder -d example.com -silent` |
| `amass` | OSINT subdomain enum | `amass enum -passive -d example.com` |
| `theHarvester` | Email/name/subdomain OSINT | `theHarvester -d example.com -b all` |
| `shodan` | Internet-connected device search | `shodan search hostname:example.com` |
| `censys` | Certificate & host search | Via API |
| `crt.sh` | Certificate Transparency | `curl -s 'https://crt.sh/?q=%25.example.com&output=json'` |
| `whatweb` | Technology fingerprinting | `whatweb -a 1 example.com` |
| `wafw00f` | WAF detection | `wafw00f example.com` |
| `dnsrecon` | DNS enumeration | `dnsrecon -d example.com` |

## Procedure

1. **WHOIS Lookup**: Gather registrant info, creation/expiry dates, name servers
2. **DNS Enumeration**: Query A, AAAA, MX, NS, TXT, SOA, CNAME records
3. **Subdomain Discovery**: Run subfinder + amass in passive mode
4. **Certificate Transparency**: Query crt.sh for all issued certificates
5. **Technology Stack**: Identify web technologies, frameworks, CMS
6. **WAF Detection**: Check for Web Application Firewalls
7. **Shodan/Censys**: Search for exposed services and banners
8. **OSINT Correlation**: Cross-reference findings from all sources

## Output Format

Generate a structured recon report with:
- Target overview (domain, IPs, ASN)
- Subdomain list with resolution status
- Technology stack summary
- DNS configuration analysis
- Potential attack surface identified
- Interesting findings flagged for further investigation

## Validation
- Verify all discovered subdomains are within scope
- Cross-reference DNS results from multiple sources
- Confirm technology fingerprints with at least 2 detection methods
