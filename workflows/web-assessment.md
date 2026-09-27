# Web Application Assessment Workflow

**Workflow ID**: `web-assessment`  
**Description**: Targeted vulnerability assessment and penetration testing for web applications, web frameworks, single-page apps (SPAs), and content management systems.  
**Required Agents**: `recon`, `scanner`, `validation`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Intake & Scope**: Parse base URLs, user roles/credentials, and exclusion patterns (e.g., logout links, billing endpoints).
2. **Web Discovery (`recon`)**:
   - Technology fingerprinting (`whatweb`), WAF identification (`wafw00f`).
   - Deep crawling (`katana`) and directory/parameter fuzzing (`ffuf`, `arjun`).
3. **OWASP Top 10 Assessment (`scanner`)**:
   - Injection testing (SQLi, SSTI, XSS, Command Injection).
   - Authentication, CSRF, and session fixation verification.
   - Access control & IDOR parameter swapping across credentialed user tiers.
4. **Logic Flaw Hunting**: Concurrency testing on state-changing endpoints, parameter pollution, and cache poisoning.
5. **Operator Approval Gate (HITL)**: Request approval via operator interface for any candidate finding with Severity ≥ 5.
6. **PoC Validation (`validation`)**: Execute benign verification payloads; capture raw evidence and SHA-256 hashes.
7. **Cleanup & Final Reporting (`reporter`)**: Purge test canaries and compile the final web application security assessment report.
