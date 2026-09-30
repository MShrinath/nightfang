---
name: api
description: Comprehensive API security testing covering REST, GraphQL, and gRPC endpoints, OWASP API Top 10, auth bypasses, and BOLA.
version: "2.0"
domain: cybersecurity
subdomain: api-security
tags: [api, rest, graphql, grpc, bola, bfla, owasp-api, jwt]
mitre_attack: [T1190, T1078, T1552]
d3fend_techniques: [D3-ARA, D3-PSA, D3-UVI]
---

# API Security Testing Skill (Index & Router)

This skill provides modular testing procedures for REST, GraphQL, and gRPC APIs. Load specific sub-modules as needed:

## Sub-Modules
- **Authorization & Access**: [`bola-bfla.md`](bola-bfla.md) — Object & Function Level Authorization testing.
- **Authentication & Tokens**: [`auth-tokens.md`](auth-tokens.md) — JWT tampering, API key lifecycle, and algorithm confusion.
- **Specifications & Fuzzing**: [`spec-fuzzing.md`](spec-fuzzing.md) — OpenAPI/Swagger parsing, mass assignment, and GraphQL auditing.

## Recommended Tooling
- `curl` / `httpie`: Manual API request replay and payload verification.
- `arjun`: Hidden parameter discovery.
- `graphql-cop`: GraphQL introspection and security audit.
- `jwt_tool`: Cryptographic JWT analysis and tampering.

## Finding Generation
All API vulnerabilities must be emitted conforming to [`schemas/finding.md`](../../schemas/finding.md).
