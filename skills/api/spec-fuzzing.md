# API Security Methodology: Specification Analysis & Parameter Fuzzing

Methodologies for OpenAPI/Swagger discovery, GraphQL testing, and parameter fuzzing.

---

## 1. Specification Analysis & Shadow APIs
- **Discovery**: Probe standard specification paths:
  - `/swagger.json`, `/swagger/v1/swagger.json`
  - `/v3/api-docs`, `/openapi.json`, `/openapi.yaml`
- **Shadow API Identification**: Compare endpoints found in documentation against routes discovered in client JS bundles to detect unversioned or forgotten endpoints.

---

## 2. Mass Assignment (Broken Property Level Authorization)
- Inspect response schemas for internal fields (`role`, `is_verified`, `tenant_id`, `balance`).
- Inject candidate property fields into `POST` and `PATCH` requests:
  ```json
  {"email": "user@test.local", "role": "admin", "is_super_admin": true}
  ```
- Verify if backend ORM automatically maps parameters into persistent database entities.

---

## 3. GraphQL Security Testing
- **Introspection**: Send query `{ __schema { types { name } } }` using `graphql-cop`.
- **Query Depth & Resource Exhaustion**: Test deeply nested circular queries (`user { posts { author { posts } } }`) to evaluate rate limiting and denial-of-service controls.
