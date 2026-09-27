# API Security Methodology: BOLA & BFLA Testing

Methodologies for testing Broken Object Level Authorization (API1) and Broken Function Level Authorization (API5).

---

## 1. Broken Object Level Authorization (BOLA / IDOR)
- **Vectors**: Resource endpoints accepting IDs in paths, queries, or bodies:
  - `GET /api/v1/users/{userId}/profile`
  - `POST /api/v1/accounts/{accountId}/transfer`
  - `DELETE /api/v1/documents/{docUuid}`
- **Testing Procedure**:
  1. Capture authenticated requests as standard user `User_A`.
  2. Substitute target resource identifiers with resource IDs belonging to `User_B`.
  3. Replay request using `User_A` session tokens.
  4. Verify if data is disclosed or modified across tenant boundaries.

---

## 2. Broken Function Level Authorization (BFLA)
- **Vectors**: Administrative or privileged API routes:
  - `/api/v1/admin/users`
  - `/api/v1/system/config`
  - `/api/v1/audit/logs`
- **Testing Procedure**:
  1. Identify administrative endpoints from Swagger docs, JavaScript bundles, or path guessing.
  2. Send requests to administrative endpoints using a low-privileged regular user token.
  3. Test HTTP method tampering: convert `GET /api/v1/users` to `DELETE /api/v1/users/42` without admin privileges.
