---
name: ssl-tls-testing
description: >-
  Use this skill for SSL/TLS security assessment. Analyzes certificate
  validity, cipher suites, protocol versions, known vulnerabilities
  (Heartbleed, POODLE, BEAST, CRIME, ROBOT), and configuration issues.
  Activate when assessing HTTPS services or any TLS-wrapped protocols.
---

# SSL/TLS Security Testing

Comprehensive TLS configuration and certificate analysis.

## Tools

| Tool | Purpose | Command |
|------|---------|--------|
| `testssl.sh` | Full TLS analysis | `testssl.sh TARGET:443` |
| `sslscan` | SSL cipher enumeration | `sslscan TARGET` |
| `sslyze` | Python SSL scanner | `sslyze TARGET` |
| `nmap` | SSL NSE scripts | `nmap --script ssl-* -p 443 TARGET` |
| `openssl` | Manual TLS testing | See below |

## Checks

- [ ] Certificate validity (expiry, chain, SAN)
- [ ] Self-signed certificates
- [ ] Weak signature algorithms (SHA1, MD5)
- [ ] Protocol versions (SSLv2, SSLv3, TLS 1.0/1.1 should be disabled)
- [ ] Weak cipher suites (RC4, DES, NULL, EXPORT)
- [ ] Forward secrecy support
- [ ] HSTS header presence and configuration
- [ ] Certificate transparency
- [ ] Key size (RSA < 2048, ECC < 256 are weak)
- [ ] Known vulnerabilities: Heartbleed, POODLE, BEAST, CRIME, BREACH, ROBOT, DROWN
- [ ] OCSP stapling
- [ ] Mixed content issues

## Quick Commands

```bash
# Full analysis
testssl.sh --full TARGET:443

# Manual checks
openssl s_client -connect TARGET:443 -tls1
openssl s_client -connect TARGET:443 -tls1_1
openssl s_client -connect TARGET:443 -tls1_2
openssl s_client -connect TARGET:443 -tls1_3

# Certificate details
openssl s_client -connect TARGET:443 | openssl x509 -noout -text
```

## Output
- TLS configuration grade (A+ to F)
- Protocol support matrix
- Cipher suite analysis
- Vulnerability findings with Confidence/Severity scores

## NIGHTFANG Agent Integration
The **SCANNER-SSL** agent automates this skill's procedures within the NIGHTFANG swarm:
- Runs as Phase 3 parallel scanner alongside webapp, API, network, cloud, and AI scanners
- Uses `testssl.sh`, `sslscan`, `sslyze`, `nmap` SSL scripts, `openssl` for comprehensive TLS analysis
- Tests certificate validity, cipher suites, protocol versions, known vulnerabilities (Heartbleed, POODLE, BEAST, CRIME, ROBOT, DROWN)
- Outputs TLS grade (A+ to F) with MITRE ATT&CK mappings (T1557, T1040)
- Requires no HITL for scanning (passive), but findings feed into HUNTER for chain building
- Configure via `technique_config.ssl_tls_testing` in engagement YAML
