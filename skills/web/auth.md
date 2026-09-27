# Web Vulnerability Methodology: Authentication & Session Security

Methodologies for testing login workflows, session state management, cookie security, and CSRF.

---

## 1. Cookie & Token Security
- **Security Flags**: Inspect all session cookies for `Secure`, `HttpOnly`, and `SameSite=Lax|Strict`.
- **Session Fixation**:
  - Record cookie/session ID before authentication.
  - Authenticate with valid credentials.
  - Verify if the session ID was reissued upon privilege change. If identical, flag session fixation.

---

## 2. Cross-Site Request Forgery (CSRF)
- **State-Changing Actions**: Identify POST/PUT/DELETE endpoints (password change, email update, funds transfer).
- **Anti-CSRF Tokens**:
  - Test omitting the CSRF token.
  - Test submitting an empty token (`csrf_token=`).
  - Test submitting a token from a different user session.
  - Test changing request `Content-Type` to `application/json` or `text/plain`.

---

## 3. Password Reset & Account Recovery
- **Token Predictability**: Analyze entropy and timestamp correlation of password reset tokens.
- **Host Header Injection**: Modify `Host: attacker.com` during password reset request to observe if the reset link URL incorporates the poisoned host.
