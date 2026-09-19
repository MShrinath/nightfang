---
name: api-testing
description: >-
  Use this skill for API security testing. Covers REST, GraphQL, gRPC, and
  SOAP APIs. Tests for broken authentication, BOLA/IDOR, mass assignment,
  rate limiting bypass, injection, and API-specific vulnerabilities.
  Activate when the target exposes API endpoints.
---

# API Security Testing

Specialized testing for API endpoints and services.

## Tools & Techniques

| Tool | Purpose |
|------|--------|
| `curl` / `httpie` | Manual API testing |
| `Postman` / `Insomnia` | API request collections |
| `ffuf` | API endpoint fuzzing |
| `arjun` | Hidden parameter discovery |
| `kiterunner` | API endpoint discovery |
| `graphql-cop` | GraphQL security testing |
| `InQL` | GraphQL introspection |
| `jwt_tool` | JWT token analysis |
| `mitmproxy` | API traffic interception |
| `nuclei` | API-specific templates |

## OWASP API Top 10 Checklist

### API1 — Broken Object Level Authorization (BOLA)
- [ ] Enumerate object IDs and test access across users
- [ ] Test sequential/predictable ID patterns
- [ ] Check UUID guessability

### API2 — Broken Authentication
- [ ] Test token generation and validation
- [ ] Check for token leakage in responses/logs
- [ ] Test API key rotation and revocation
- [ ] OAuth flow testing

### API3 — Broken Object Property Level Authorization
- [ ] Mass assignment testing (send extra fields)
- [ ] Check response filtering (excessive data exposure)
- [ ] Test field-level access control

### API4 — Unrestricted Resource Consumption
- [ ] Rate limiting bypass
- [ ] Resource exhaustion (large payloads, deep nesting)
- [ ] Pagination abuse

### API5 — Broken Function Level Authorization
- [ ] Test admin endpoints with regular user tokens
- [ ] HTTP method tampering (GET→PUT→DELETE)
- [ ] Check for hidden admin APIs

### API6 — Unrestricted Access to Sensitive Business Flows
- [ ] Automated abuse of business workflows
- [ ] Lack of anti-automation controls

### API7 — Server Side Request Forgery
- [ ] URL parameters pointing to internal resources
- [ ] Webhook URL manipulation
- [ ] File import from URL features

### API8 — Security Misconfiguration
- [ ] CORS misconfiguration
- [ ] Verbose error messages
- [ ] Default configurations
- [ ] Unnecessary HTTP methods enabled

### API9 — Improper Inventory Management
- [ ] Shadow/zombie API discovery
- [ ] Version comparison (v1 vs v2 for missing controls)
- [ ] Documentation vs reality gaps

### API10 — Unsafe Consumption of APIs
- [ ] Third-party API trust boundaries
- [ ] Redirect following behavior
- [ ] Response validation

## Procedure

1. **Discovery**: Map all API endpoints (OpenAPI/Swagger, crawling, fuzzing)
2. **Authentication Analysis**: Understand auth mechanism (JWT, OAuth, API key)
3. **Schema Analysis**: Review request/response schemas for data leaks
4. **Authorization Testing**: BOLA, BFLA testing across all endpoints
5. **Input Validation**: Injection testing on all parameters
6. **Rate Limiting**: Test abuse controls
7. **Business Logic**: Application-specific API abuse scenarios

## Output
- Endpoint inventory with methods and auth requirements
- Per-endpoint vulnerability findings with Confidence/Severity scores
- Proof-of-concept requests (curl commands) for reproduction

## NIGHTFANG Agent Integration
The **SCANNER-API** agent automates this skill's procedures within the NIGHTFANG swarm:
- Runs as Phase 3 parallel scanner alongside webapp, network, SSL, cloud, and AI scanners
- Uses `curl`, `kiterunner`, `arjun`, `graphql-cop`, `jwt_tool`, `nuclei` for comprehensive API testing
- Tests OWASP API Top 10: BOLA, Broken Auth, Mass Assignment, Rate Limiting, BFLA, SSRF, Misconfiguration, Inventory, Unsafe Consumption
- GraphQL introspection testing with full schema query
- JWT algorithm confusion and weak secret analysis
- Requires HITL via Telegram `/go` before BOLA exploitation or mass assignment testing
- Outputs findings with MITRE ATT&CK mappings (T1190, T1078, T1552)
- Configure via `technique_config.api_testing` in engagement YAML
