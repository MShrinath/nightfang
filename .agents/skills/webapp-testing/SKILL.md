---
name: webapp-testing
description: >-
  Use this skill for web application penetration testing. Covers OWASP Top 10
  testing including SQLi, XSS, CSRF, IDOR, SSRF, authentication bypass,
  directory traversal, and more. Uses tools like Burp Suite, SQLMap, Nikto,
  Gobuster, ffuf, and custom scripts. Activate when testing web endpoints,
  APIs, or web-based services.
---

# Web Application Testing

Comprehensive web application security assessment following OWASP methodology.

## Tools & Techniques

| Tool | Purpose | Command Example |
|------|---------|----------------|
| `nikto` | Web server scanner | `nikto -h TARGET` |
| `gobuster` | Directory/file brute-force | `gobuster dir -u TARGET -w WORDLIST` |
| `ffuf` | Web fuzzer | `ffuf -u TARGET/FUZZ -w WORDLIST` |
| `sqlmap` | SQL injection | `sqlmap -u 'TARGET?param=1' --batch` |
| `wpscan` | WordPress scanner | `wpscan --url TARGET` |
| `nuclei` | Template-based scanner | `nuclei -u TARGET -t cves/` |
| `dalfox` | XSS scanner | `dalfox url TARGET` |
| `commix` | Command injection | `commix --url TARGET` |
| `jwt_tool` | JWT analysis | `jwt_tool TOKEN` |
| `arjun` | Parameter discovery | `arjun -u TARGET` |
| `paramspider` | Parameter mining | `paramspider -d TARGET` |
| `katana` | Web crawler | `katana -u TARGET -d 3` |

## OWASP Top 10 Testing Checklist

### A01 — Broken Access Control
- [ ] Test IDOR on all resource endpoints (change IDs, UUIDs)
- [ ] Check horizontal/vertical privilege escalation
- [ ] Test forced browsing to admin panels
- [ ] Verify CORS configuration
- [ ] Check directory listing

### A02 — Cryptographic Failures
- [ ] Check for sensitive data in transit (HTTP vs HTTPS)
- [ ] Analyze TLS configuration (`testssl.sh TARGET`)
- [ ] Look for hardcoded secrets/API keys in responses
- [ ] Check for sensitive data in URL parameters

### A03 — Injection
- [ ] SQL Injection (error-based, blind, time-based)
- [ ] NoSQL Injection
- [ ] Command Injection
- [ ] LDAP Injection
- [ ] Template Injection (SSTI)
- [ ] XPath Injection

### A04 — Insecure Design
- [ ] Business logic flaws
- [ ] Race conditions
- [ ] Missing rate limiting
- [ ] Insecure direct object references in workflows

### A05 — Security Misconfiguration
- [ ] Default credentials
- [ ] Unnecessary features enabled
- [ ] Error handling exposing stack traces
- [ ] Missing security headers
- [ ] Open cloud storage buckets

### A06 — Vulnerable Components
- [ ] Identify frameworks and library versions
- [ ] Cross-reference with CVE databases
- [ ] Check for known exploits (Exploit-DB, NVD)

### A07 — Authentication Failures
- [ ] Brute force protection
- [ ] Password policy enforcement
- [ ] Session management flaws
- [ ] JWT vulnerabilities (none algorithm, key confusion)
- [ ] OAuth/OIDC misconfigurations

### A08 — Software & Data Integrity
- [ ] Insecure deserialization
- [ ] Missing integrity checks on updates
- [ ] CI/CD pipeline vulnerabilities

### A09 — Logging & Monitoring Failures
- [ ] Check if sensitive actions are logged
- [ ] Look for log injection possibilities

### A10 — SSRF
- [ ] Test URL parameters for SSRF
- [ ] Check internal service access
- [ ] Cloud metadata endpoint access (169.254.169.254)

## Procedure

1. **Crawl & Map**: Spider the application, build sitemap
2. **Technology ID**: Identify stack, frameworks, CMS
3. **Directory Brute-force**: Discover hidden endpoints
4. **Parameter Discovery**: Find hidden parameters
5. **Authentication Testing**: Test login flows and session management
6. **Injection Testing**: Test all input points for injection flaws
7. **Access Control Testing**: Test authorization on every endpoint
8. **Business Logic**: Test application-specific logic flaws
9. **API Testing**: Test REST/GraphQL endpoints separately

## ⚠️ HITL Checkpoint
Before running any exploitation commands (sqlmap with --os-shell, commix exploitation, etc.), **STOP and request operator permission via Telegram**.
