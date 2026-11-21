---
name: osint
description: Open-source intelligence gathering, social media reconnaissance, people search, and digital footprint analysis.
version: "2.0"
domain: cybersecurity
subdomain: osint
tags: [osint, reconnaissance, social-engineering, people-search, footprint]
mitre_attack: [TA0043, T1593, T1594, T1596]
d3fend_techniques: [D3-DNST, D3-WHIA, D3-NTA]
---

# Open-Source Intelligence (OSINT)

Passive intelligence gathering from public sources to build a comprehensive digital footprint of targets without touching their infrastructure.

## Tools & Execution Matrix

| Tool | Purpose | Standard Command | Fallback |
| :--- | :--- | :--- | :--- |
| `theHarvester` | Email/domain OSINT | `theHarvester -d <DOMAIN> -b all` | `hunter.io` API |
| `maltego` | Graph-based OSINT | `maltego -d <DOMAIN>` | Custom graph scripts |
| `sherlock` | Username enumeration | `sherlock <USERNAME>` | Manual site search |
| `phoneinfoga` | Phone number recon | `phoneinfoga scan <PHONE>` | `numlookup` API |
| `emailrep` | Email breach check | `emailrep <EMAIL>` | HaveIBeenPwned API |
| `dnstwist` | Domain typo-squatting | `dnstwist -f l --gsl <DOMAIN>` | `dnstool` |

## Methodology

### 1. Domain & Subdomain Harvesting
- Query Certificate Transparency logs via `crt.sh` for wildcard and historic subdomains.
- Enumerate DNS records (A, AAAA, CNAME, MX, TXT, SPF, DMARC, DKIM, DMARC).
- Check for exposed Git repositories (`.git/`, `.svn/`, `.hg/`).
- Search for exposed configuration files (`.env`, `.npmrc`, `.pypirc`, `netrc`).

### 2. People & Contact Discovery
- Extract email addresses from public sources (LinkedIn, GitHub, corporate sites, conference talks).
- Cross-reference with breach databases (Have I Been Pwned, Dehashed).
- Map organizational relationships via LinkedIn and GitHub network analysis.
- Identify key personnel (CISO, CTO, DevOps, developers) for targeted social engineering.

### 3. Social Media Reconnaissance
- Scrape public profiles for bio data, posting patterns, and technology mentions.
- Monitor for employee oversharing (conference badges, office photos, code snippets).
- Track bug bounty program registrations and disclosure timelines.

### 4. Technology Stack Fingerprinting
- Identify cloud providers, CDN, WAF, analytics, and SaaS integrations.
- Map third-party JavaScript libraries and their versions.
- Detect CI/CD and build tooling from exposed endpoints.

## Scope Boundary Validation
- All OSINT queries are passive — no traffic is sent to target infrastructure.
- Verify discovered data against authorized scope boundaries before downstream action.
- Flag any data that appears to be PII or sensitive personal information.

## Output
- Normalized OSINT dossier: domains, subdomains, IPs, email addresses, phone numbers, social profiles, technology stack, and key personnel.