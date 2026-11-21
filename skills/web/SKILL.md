---
name: web
description: Web application penetration testing covering OWASP Top 10, injection, authentication, access control, and SSRF.
version: "2.0"
domain: cybersecurity
subdomain: web-application
tags: [web, owasp, xss, sqli, ssrf, ssti, idor, auth-bypass]
mitre_attack: [T1190, T1059.007, T1505]
d3fend_techniques: [D3-PSA, D3-WAF, D3-UVI, D3-SFI]
---

# Web Application Security Skill (Index & Router)

This skill provides modular testing procedures for web applications. Load specific modules as needed to conserve context:

## Sub-Modules
- **Injection Flaws**: [`injection.md`](injection.md) — SQLi, SSTI, and Command Injection methodologies.
- **Authentication & Sessions**: [`auth.md`](auth.md) — Cookie flags, session fixation, CSRF, and reset flaws.
- **Access Control & Traversal**: [`access-control.md`](access-control.md) — IDOR, BOLA, and directory traversal.
- **Server-Side Request Forgery**: [`ssrf.md`](ssrf.md) — Internal loopback and cloud metadata extraction.

## Recommended Tooling
- `nuclei`: Vulnerability template scanning (`nuclei -u <TARGET> -tags cve,misconfig`)
- `ffuf`: High-speed directory and parameter fuzzing
- `katana`: Crawler for dynamic single-page applications (SPAs)
- `dalfox`: Automated XSS verification with benign reflection checks

## Finding Generation
All vulnerabilities discovered across web modules must be recorded adhering to [`schemas/finding.md`](../../schemas/finding.md).

## Payload Integration (scripts/agent_payloads.py)
Web agents MUST use `AgentPayloadResolver` to retrieve safe payloads before attempting any injection:
```python
from scripts.agent_payloads import AgentPayloadResolver
resolver = AgentPayloadResolver()
# Safe discovery payloads for initial probing
xss_discovery = resolver.get_safe_payloads("XSS Injection")
sqli_safe = resolver.get_safe_payloads("SQL Injection")   # empty — all SQLi are HITL
ssrf_safe = resolver.get_safe_payloads("Server Side Request Forgery")
# Destructive payloads require explicit HITL approval
sqli_full = resolver.get_by_class("SQL Injection")       # full catalog (HITL only)
rsti_safe = resolver.get_safe_payloads("Server Side Template Injection")
```
CLI equivalent:
```bash
python scripts/payload_lookup.py --class "XSS Injection" --safe-only
python scripts/payload_lookup.py --cwe CWE-89 2>&1 || echo "Requires HITL"
python scripts/payload_lookup.py --owasp A05:2021    # Broken Access Control
python scripts/payload_lookup.py --cwe CWE-918        # Server-Side Request Forgery
```
