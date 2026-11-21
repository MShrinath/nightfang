# Threat Modeling Workflow

## Scope

Threat modeling provides a structured methodology for identifying and prioritizing security risks in application architecture before implementation begins. This workflow covers STRIDE, PASTA, and attack-tree analysis techniques applied to new feature design, architecture reviews, and existing system reassessment. No active network interaction occurs during threat modeling.

## Prerequisites

- Architecture documentation or system design diagrams are available for review.
- Stakeholder interviews scheduled or historical context documents accessible.
- Clear understanding of data sensitivity classification (public, internal, confidential, restricted).
- Defined trust boundaries between components and external entities.

**Skill Reference**: `AGENTS.md` § Advisory Mode, `references/sops.md#sop-01-scope-verification-boundary-enforcement`

## Phase 1 — Architecture Decomposition

Break down the target system into executable components and data flow relationships.

1. Enumerate all application components: web servers, API gateways, microservices, databases, message queues, third-party integrations, client applications.
2. Identify data stores and classify data at rest sensitivity levels per component.
3. Map inter-component communication channels: synchronous (HTTP/RPC/gRPC), asynchronous (message brokers, event streams), and batch processing pipelines.
4. Define trust boundaries between each data flow crossing administrative or security domains.
5. Catalog identity sources, authentication mechanisms, and authorization data stores used across component interactions.

**Tools**: System architecture diagrams (provided), component inventory spreadsheets, DFD generation tools (Microsoft Threat Tool, draw.io templates).

**Skill Reference**: `skills/threat-modeling`, `schemas/finding.md`

## Phase 2 — STRIDE Threat Enumeration

Apply the STRIDE framework systematically across every element identified in Phase 1.

For each component and data flow, evaluate:

- **Spoofing**: Can an actor impersonate another identity at this boundary? Consider token forgery, certificate spoofing, session hijacking vectors.
- **Tampering**: Can data be modified in transit or at rest without detection? Evaluate integrity controls, checksums, digital signatures, WORM storage.
- **Repudiation**: Can an actor deny performing an action? Assess logging completeness, audit trail integrity, non-repudiation mechanisms.
- **Information Disclosure**: Can sensitive data be accessed beyond authorized scope? Review encryption at rest and in transit, access control granularity, error message content.
- **Denial of Service**: Can the component be rendered unavailable to legitimate users? Examine rate limiting, resource exhaustion vectors, dependency single points of failure.
- **Elevation of Privilege**: Can a lower-privileged actor gain elevated permissions? Trace permission inheritance, role transition logic, access control bypass opportunities.

Record every identified threat with component reference, threat type, and preliminary likelihood assessment.

**Tools**: Structured threat listing templates, Microsoft Threat Modeling Tool, OWASP Threat Dragon.

**Skill Reference**: `skills/threat-modeling`, `skills/hunting`

## Phase 3 — Attack Tree Construction

Build hierarchical attack trees for highest-priority threats identified in Phase 2.

1. Select top 5 threats ranked by combined likelihood and business impact score.
2. For each selected threat, construct an attack tree rooting at the attacker goal with branching conditions representing prerequisite capabilities.
3. Label each leaf node with the specific vulnerability or misconfiguration enabling that attack path.
4. Identify common sub-goals across multiple attack trees to prioritize unified remediation efforts.
5. Score each path using DREAD or custom likelihood/impact scoring aligned with organizational risk appetite.

**Tools**: Visual attack tree diagrams (draw.io, Gliffy), automated attack tree analysis tools (Drakmap, ATaaS API if available).

**Skill Reference**: `skills/hunting/scripts/ioc_extractor.py`, `references/framework_mappings.md`

## Phase 4 — Mitigation Prioritization & Countermeasure Mapping

Translate threats into actionable defense recommendations.

1. Rank all identified threats by risk score combining likelihood (1–5) and impact (1–5) with organizational context weighting.
2. For each high-priority threat, prescribe primary countermeasures mapped to MITRE D3FEND technique IDs.
3. Identify secondary compensating controls where primary mitigations introduce unacceptable performance or operational cost.
4. Produce architecture change recommendations that eliminate entire threat categories rather than applying point fixes.
5. Generate a threat register suitable for ongoing review cycles and architectural decision record (ADR) integration.

**Tools**: Risk scoring matrices, ADR template (`templates/adr_template.md`), MITRE D3FEND knowledge base cross-reference.

**Skill Reference**: `skills/reporting`, `skills/remediation`, `integrations/execution-policy-gateway.md`
