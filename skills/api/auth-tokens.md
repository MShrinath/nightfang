# API Security Methodology: Authentication & Token Security

Methodologies for testing API authentication tokens, JWT integrity, and lifecycle management.

---

## 1. JWT Security Testing
- **Algorithm Confusion**:
  - Test `alg: none`: Strip signature and send modified payload.
  - Test RS256 $\to$ HS256: Sign token using target's public RSA certificate as the HMAC secret key.
- **Claim Manipulation**:
  - Modify `role`, `is_admin`, or `sub` claims and verify if signature is strictly checked.
- **Weak Signing Keys**:
  - Crack weak HMAC secrets using dictionary attacks with `jwt_tool`.

---

## 2. API Key & Token Lifecycle
- **Revocation & Expiry**:
  - Test if expired tokens are accepted due to lax backend validation or redis cache TTL bugs.
- **Token Leakage**:
  - Inspect URL parameters (`?token=`), referer headers, client-side logs, and error responses for exposed credentials.
