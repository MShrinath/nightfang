# OSINT Collection Workflow

## Scope

Open-Source Intelligence (OSINT) gathers publicly available information about targets through passive, non-interactive collection techniques. This workflow covers domain intelligence, infrastructure discovery, personnel profiling, technical artifact analysis, and threat landscape mapping. No authentication, scanning, or interaction with live target systems occurs during OSINT execution.

## Prerequisites

- Target identifiers clearly defined: domain names, IP ranges, corporate entities, personnel names, technology stack indicators.
- Operator confirmation that collected information will be used solely within authorized engagement scope.
- Awareness of jurisdictional constraints regarding personal data collection and privacy regulations (GDPR, CCPA where applicable).
- Documentation of data source provenance for chain-of-custody compliance per `references/sops.md#sop-06-evidence-hashing-chain-of-custody`.

**Skill Reference**: `AGENTS.md` § Advisory Mode, `manifest.yaml` capability `attack-surface-mapping`

## Phase 1 — Domain & Infrastructure Enumeration

Build the complete external facing infrastructure profile through passive DNS and certificate data collection.

1. Perform subdomain enumeration using certificate transparency log searches (crt.sh, Google CT Search), DNS history databases (SecurityTrails, ViewDNS), and wildcard resolution testing.
2. Query public DNS records for MX, TXT (SPF/DKIM/DMARC), CNAME chains, NS records, and Dnssec status across all discovered subdomains.
3. Extract TLS certificates from discovered endpoints; analyze Subject Alternative Names for additional infrastructure reveals and expired certificate usage patterns.
4. Search historical WHOIS records for ownership transfers, naming pattern changes, and registrar reputation signals.
5. Map IP address allocations to autonomous system numbers and geolocate infrastructure using BGP routing table queries and IP intelligence feeds.

**Tools**: Sublist3r, sublist3r-enhanced, amass passivedns mode, crtsh Python library, whois-cli, bgp.he.net API queries, PassiveTotal (free tier).

**Skill Reference**: `skills/recon/scripts/subdomain_enum.py`, `skills/recon/scripts/dns_recon.py`, `schemas/finding.md`

## Phase 2 — Technology Stack Fingerprinting

Identify software components, versions, and third-party integrations exposed through public-facing assets.

1. Extract HTTP response headers, server banners, and meta tags from web application entry points to identify web server, framework, CMS platform, and frontend library versions.
2. Analyze JavaScript bundle content for internal API endpoint patterns, third-party service references, SDK keys, and client-side configuration secrets accidentally committed to public repositories.
3. Review RSS feeds, sitemap.xml files, and pagination parameters for hidden or deprecated URL paths not linked from primary navigation.
4. Search public GitHub repositories, GitLab instances, and code hosting platforms for organization-owned source code containing API keys, hardcoded credentials, internal architecture documentation, and debug endpoints.
5. Identify CDN providers, WAF vendors, and DDoS mitigation services from response header signatures and observed infrastructure behavior.

**Tools**: wappalyzer signatures, whatweb, nuclei passive templates, theHarvester, GitHub Advanced Security search (operator-provided tokens only), GitRob (read-only reconnaissance mode).

**Skill Reference**: `skills/recon/scripts/tech_fingerprint.py`, `workflows/web-assessment.md`

## Phase 3 — Personnel & Organizational Intelligence

Construct organizational structure profiles from publicly available professional and social data.

1. Aggregate employee name lists from LinkedIn corporation pages, company "About Us" sections, press releases, and conference speaker listings matching the target organization.
2. Identify key technical roles: CISO, security team members, DevOps engineers, application developers, infrastructure administrators — including their published technical blog posts and conference presentations revealing architectural details.
3. Search for leaked credential datasets (HaveIBeenPwned API queries for organizational email domains) to assess credential reuse risk among personnel.
4. Map organizational reporting structures and geographic presence from public filings, business registries, and venture capital funding announcements.
5. Identify third-party vendors and technology partners whose compromise could provide lateral access to the target organization's environment.

**HITL Gate Not Applicable**: This phase involves only public record collection; no authentication or targeted interaction is required. Always respect rate limits on public APIs and comply with terms of service.

**Skills Reference**: `skills/cti`, `skills/recon`, `references/sops.md#sop-02-rate-limiting-stealth-management`

## Phase 4 — Data Breach & Leak Analysis

Assess whether target infrastructure or credentials have appeared in publicly disclosed breach material.

1. Query HaveIBeenPwned aggregated breach databases for organizational email domains and known username patterns.
2. Search pastebin archives, leak forums, and cryptocurrency ransom notes for target-related data disclosures referencing internal infrastructure names, VPN credentials, or proprietary code.
3. Correlate discovered breach data with active employment status to prioritize credential reset urgency for current versus former employees.
4. Document exposure vector, date of breach disclosure, approximate data volume, and classification of compromised information for each identified incident.
5. Cross-reference breach timestamps against operational milestone dates to correlate potential insider threat opportunities or contracted penetration test aftermath exposure.

**Tools**: Hibp-api-python, DeHashed (authorized use only), custom paste aggregation crawlers operating within rate limits, Shodan/Censys historical data queries.

**Skill Reference**: `skills/hunting/scripts/ioc_extractor.py`, `schemas/finding.md`

## Phase 5 — Threat Landscape & IOCs Aggregation

Compile adversary-relevant intelligence from public threat feeds and incident databases.

1. Collect Known Indicators of Compromise (IOCs) from MITRE ATT&CK navigator layers, AlienVault OTX pulses, Mandiant threat reports, and government CISA advisory bulletins related to target industry vertical.
2. Monitor pastebin-style data dumps and HackerOne/Bugcrowd public program disclosures for previously reported vulnerabilities affecting target technology stack components.
3. Track malware sample hashes and command-and-control infrastructure associated with threat actor campaigns targeting similar organizations.
4. Compile domain and IP reputation scores from VirusTotal, AbuseIPDB, and emerging threat intel provider free tiers.
5. Produce an OSINT evidence package with SHA-256 hashes for all downloaded artifacts and URLs visited, stored per `schemas/finding.md` provenance requirements.

**Skill Reference**: `skills/reporting/scripts/report_assembler.py`, `templates/master_report.md`, `references/framework_mappings.md`
