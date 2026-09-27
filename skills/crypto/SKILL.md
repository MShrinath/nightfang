---
name: crypto
description: Cryptographic security assessment covering SSL/TLS ciphers, weak algorithms (MD5, SHA1, DES, RC4), JWT/JWE implementation flaws, padding oracles, key length validation, and Post-Quantum Cryptography (PQC) readiness.
domain: cybersecurity
subdomain: cryptographic-security
tags: [crypto, tls, ciphers, jwt, padding-oracle, rsa, ecc, pqc]
mitre_attack: [T1552, T1584, T1040]
d3fend_techniques: [D3-CTA, D3-CH]
version: "1.0"
---

# Cryptographic Security Skill

Technical methodology for evaluating cryptographic implementations, protocol negotiation, and key management practices.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `testssl.sh` | Deep TLS/SSL cipher suite & vulnerability audit | `testssl.sh --fast <TARGET>` | `sslscan` / `openssl s_client` |
| `jwt_tool` | JSON Web Token (JWT) tampering & vulnerability scanner | `python3 jwt_tool.py <TOKEN> -M at` | Manual base64 decode & Python script |
| `openssl` | Direct cryptographic verification & certificate parsing | `openssl s_client -connect <HOST>:443 -tls1_2` | Python `ssl` library |
| `padbuster` | Automated padding oracle detector | `padbuster <URL> <SAMPLE> <BLOCKSIZE>` | Custom timing/error test |

## Methodology

### 1. Transport Layer Security (TLS) Auditing
- **Protocol Version Support**: Test for deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1). Verify TLS 1.2 and TLS 1.3 support.
- **Cipher Suite Analysis**: Detect weak, export, or insecure ciphers:
  - CBC mode ciphers (Lucky13 risk)
  - RC4, 3DES, NULL ciphers
  - Export ciphers (FREAK / Logjam)
  - Ciphers without Forward Secrecy (non-ECDHE / non-DHE)
- **Certificate Validation**: Verify CA trust chain, expiration dates, validity of SAN/CN matching hostname, and revocation checking (OCSP / CRL).
- **TLS Extensions**: Inspect for HSTS (`Strict-Transport-Security`), OCSP Stapling, and ALPN negotiation.

### 2. JSON Web Token (JWT) Security
- **Algorithm Confusion**: Test switching `alg` from `RS256` (asymmetric) to `HS256` (symmetric using public key as HMAC secret).
- **None Algorithm**: Test if signature verification is bypassed when `alg: "none"` is supplied.
- **Key Injection (JKU / JWK Abuse)**: Test if the token header accepts attacker-controlled JWK sets or remote `jku` URLs without domain allowlisting.
- **Weak HMAC Secrets**: Offline dictionary attacks against weak HS256 secrets using authorized wordlists.

### 3. Symmetric & Asymmetric Implementation Flaws
- **Block Cipher Modes**: Detect ECB mode (Electronic Codebook) usage resulting in deterministic ciphertext patterns.
- **IV Reuse**: Detect static initialization vectors (IVs) used with CBC or GCM modes leading to keystream recovery.
- **Padding Oracle Detection**: Inspect differential server errors (e.g. `200 OK` vs `500 Internal Error` vs distinct padding error messages) when modifying ciphertext byte blocks.
- **RSA Key Lengths**: Flag RSA keys shorter than 2048 bits or weak exponent parameters ($e=3$).

### 4. Post-Quantum Cryptography (PQC) Readiness
- Evaluate organizational cipher migration timelines and detect legacy algorithms with long-term data sensitivity (Harvest Now, Decrypt Later risks).

## Output
- Cryptographic configuration report and vulnerability findings.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
