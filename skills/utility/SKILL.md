---
name: utility
description: Utility operations covering fast triage checklists, engagement session memory, pattern recall, cross-engagement deduplication, and quality assurance gates.
version: "2.0"
domain: cybersecurity
subdomain: utility-operations
tags: [utility, triage, engagement-memory, quality-assurance, checklists]
mitre_attack: []
d3fend_techniques: []
---

# Utility Operations Skill

Support procedures and helper checklists that ensure engagement consistency, deduplication, rapid triage, and quality assurance across the NIGHTFANG swarm.

## Methodology

### 1. Rapid Triage Checklist
When presented with a newly discovered asset or URL, execute the rapid 60-second triage checklist:
1. **HTTP Status & Headers**: Check status code (`200`, `301`, `401`, `403`, `500`), server banner (`Server:`, `X-Powered-By:`), and security headers (`HSTS`, `CSP`, `X-Frame-Options`).
2. **TLS Certificate**: Check issuer, validity window, and Subject Alternative Names (SANs) for adjacent internal hostnames.
3. **Endpoint Fingerprint**: Identify technology stack (WordPress, Next.js, Django, Spring Boot, Laravel) via favicon hash, HTML generator tags, or cookie names (`PHPSESSID`, `JSESSIONID`, `csrftoken`).
4. **API Route Exposure**: Probe for common documentation routes (`/swagger-ui.html`, `/api-docs`, `/openapi.json`, `/graphql`).
5. **Administrative Portals**: Probe for administrative surfaces (`/admin`, `/login`, `/dashboard`).

### 2. Engagement Memory & Pattern Learning
- Query `engagement.findings[]` before executing duplicate probes against identical parameter names or static assets.
- Record successful payload patterns (e.g. specific WAF evasion encodings or injection prefixes) in `engagement.learned_patterns` to accelerate subsequent testing on the same target.

### 3. Finding Quality Assurance & Pre-Reporting Filter
Before a candidate finding is escalated to the reporter agent:
- Verify that finding conforms to [`schemas/finding.md`](../../schemas/finding.md).
- Verify that evidence includes raw HTTP request/response or command output with corresponding SHA-256 hash (SOP-06).
- Confirm that confidence and severity scores are calibrated independently per [`references/heuristics.md`](../../references/heuristics.md).
- Confirm that required D3FEND and MITRE ATT&CK mappings are populated.

## Output
- Fast triage summaries, engagement memory logs, and verified findings packages.
