# Methodology: api

Source: [PentestingEverything/API Pentesting](https://github.com/m14r41/PentestingEverything/tree/main/API%20Pentesting)

---

# What is API Testing?
API penetration testing is the process of identifying security weaknesses in an API by simulating attacks. The goal is to check for common vulnerabilities such as authentication problems, payment bypass, authorization flaws, data leaks, or misconfigurations, so developers can fix them and keep data safe.
> Stay updated with the latest official OWASP API Security guidance here: [https://owasp.org/www-project-api-security/](https://owasp.org/www-project-api-security/)

## Core Concepts

API pentesting evaluates the endpoints that power web, mobile, and machine-to-machine clients, where the business logic and data live with little of the UI that normally constrains a user. Because APIs expose objects and actions directly, the highest-impact bugs are usually authorization and logic flaws rather than classic injection.

**Methodology / Phases:**
- Map the API: collect endpoints, methods, and parameters from docs, Swagger/OpenAPI specs, JS files, and proxied traffic.
- Understand auth: identify the scheme (API key, JWT, OAuth 2.0, session) and how tokens are issued and scoped.
- Test authorization: swap IDs and tokens between roles and users to probe object and function level access.
- Fuzz inputs and logic: parameters, mass assignment, rate limits, and chained calls that bypass intended flow.
- Triage and report: confirm impact, capture reproducible requests, and rate severity.

**Key Concepts / What to look for:**
- Broken Object Level Authorization (BOLA/IDOR): accessing other users' objects by changing an ID.
- Broken Function Level Authorization: reaching admin or privileged actions as a low-privileged user.
- Broken authentication: weak, replayable, or improperly validated tokens (JWT alg, expiry, signature).
- Mass assignment and excessive data exposure: writing or reading fields the client should not control or see.
- Missing rate limiting and resource controls: enabling brute force, enumeration, and abuse.

## REST API vs SOAP API 

| **Aspect**         | **REST API**                                                                 | **SOAP**                                                                       |
|--------------------|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **Protocol**       | REST uses HTTP/HTTPS, focusing on simple, stateless communication.          | SOAP works over multiple protocols like H

---

## Sub-Topics

- GraphQL
- Rest API

