# Web Vulnerability Methodology: Access Control & IDOR

Methodologies for testing Insecure Direct Object References (IDOR), broken access control, and directory traversal.

---

## 1. Insecure Direct Object References (IDOR)
- **Identification**: Locate numeric or predictable identifiers in requests:
  - `GET /api/documents?id=1024`
  - `GET /invoices/2026-0089.pdf`
- **Cross-Account Probing**:
  - Authenticate User A and capture a sensitive resource ID.
  - Authenticate User B and request User A's resource ID using User B's session token.
  - Check for full unauthorized read, update, or deletion access.

---

## 2. Directory & Path Traversal
- **Sequences**:
  - `....//....//etc/issue`
  - `..%2f..%2f..%2fetc%2fpasswd`
  - `..\..\..\windows\win.ini`
- **Indicators**: Observe reflection of OS banner strings, configuration directives, or system users.
- **Safety**: Restrict read targets to public OS release files (`/etc/issue`, `/etc/os-release`) rather than password hashes (`/etc/shadow`).
