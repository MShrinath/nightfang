# API Security Assessment Workflow

**Workflow ID**: `api-assessment`  
**Description**: Dedicated penetration testing workflow targeting REST, GraphQL, and gRPC endpoints, evaluating OWASP API Security Top 10 risks.  
**Required Agents**: `scanner`, `validation`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Intake & Specification Ingestion**:
   - Ingest OpenAPI / Swagger schemas, Postman collections, or GraphQL endpoints.
   - Parse authentication tokens (Bearer JWTs, API keys, OAuth clients).
2. **Endpoint Mapping & Fuzzing (`scanner`)**:
   - Discover undocumented / shadow endpoints (`kiterunner`, `ffuf`).
   - Run GraphQL introspection (`graphql-cop`) and hidden parameter mining (`arjun`).
3. **Authorization & Logic Testing (`scanner`)**:
   - BOLA / IDOR parameter substitution across tenant accounts.
   - BFLA testing on administrative routes (`/admin/*`) with standard user tokens.
   - Mass assignment fuzzing on `POST`/`PUT` endpoints.
   - Rate limiting and resource exhaustion benchmarks.
4. **HITL Validation Gate**: Operator approval requested for high-impact BOLA, auth bypass, or SSRF findings.
5. **Impact Verification (`validation`)**: Verify unauthorized data access scope without modifying customer records.
6. **Remediation & Report Compilation (`reporter`)**: Generate API findings deliverable with D3FEND fixes (`D3-ARA`, `D3-PSA`).
