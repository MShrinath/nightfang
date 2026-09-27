# Bug Bounty & Targeted Web/API Hunting Workflow

**Workflow ID**: `bug-bounty`  
**Description**: Targeted vulnerability hunting workflow optimized for web applications, APIs, and microservices within defined program scope rules.  
**Required Agents**: `recon`, `scanner`, `validation`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Scope & Policy Ingestion (`engagement-planner`)**:
   - Ingest program scope rules (in-scope domains, excluded subnets, forbidden techniques).
   - Set stealth and rate limit hierarchy (defaulting to safe conservative rates per SOP-02).
2. **Reconnaissance & Asset Discovery (`recon`)**:
   - Subdomain enumeration (passive sources, Certificate Transparency).
   - Live endpoint probing and technology fingerprinting.
3. **Targeted Weakness Hunting (`scanner`)**:
   - High-impact vulnerability testing: SSRF, IDOR/BOLA, authentication bypasses, GraphQL introspection, race conditions.
   - Business logic flaw analysis across multi-step checkout/registration flows.
4. **Operator Approval Gate (HITL)**: Request operator approval before sending active non-destructive PoC verification payloads per SOP-04.
5. **Controlled PoC Verification (`validation`)**:
   - Execute minimal, non-destructive proof-of-concept payloads (`id`, `whoami`, `SELECT version()`).
   - Capture clean, unadulterated HTTP requests, responses, and SHA-256 evidence hashes.
6. **Artifact Cleanup Verification**: Ensure all canary parameters and test accounts are cleaned up per SOP-05.
7. **Deliverable Synthesis (`reporter`)**: Generate clear, reproducible bug bounty report with CVSS calculation and remediation advice.
