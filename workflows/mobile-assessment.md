# Mobile Application Security Assessment Workflow

**Workflow ID**: `mobile-assessment`  
**Description**: Comprehensive security assessment of Android (APK) and iOS (IPA) applications adhering to OWASP MASVS v2.0.  
**Required Agents**: `mobile-pentester`, `scanner`, `validation`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Intake & Scope**: Ingest application package files (APK/IPA), authorized backend API base URLs, and test user accounts.
2. **Static Code & Binary Analysis (`mobile-pentester`)**:
   - Decompile application package and inspect manifest for exported components and dangerous permissions.
   - Scan bytecode for hardcoded cryptographic keys, API tokens, and insecure endpoint references.
3. **Dynamic & Runtime Assessment (`mobile-pentester`)**:
   - Instrument runtime environment using Frida and Objection.
   - Evaluate SSL/TLS certificate pinning enforcement and test dynamic bypasses.
   - Inspect local data storage (SQLite, SharedPreferences, Keychain) and verify encryption.
4. **Backend API Assessment (`scanner`)**:
   - Intercept mobile API traffic and test backend endpoints for BOLA, BFLA, and injection flaws.
5. **Operator Approval Gate (HITL)**: Request operator approval before active validation against backend services per SOP-04.
6. **PoC Validation (`validation`)**: Capture evidence transcripts and cryptographic hashes per SOP-06.
7. **Reporting & MASVS Matrix (`reporter`)**: Compile technical findings and complete OWASP MASVS v2.0 compliance report.
