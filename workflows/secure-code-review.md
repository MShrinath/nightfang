# Secure Code Review Workflow

## Scope

This workflow performs manual and assisted source-code security reviews for repositories where source code is available. It covers OWASP Top 10, CWE Top 25, and language-specific vulnerability patterns. Applicable to Web, API, Thick Client, and CLI application sources across all supported languages (Python, Go, Rust, Java, C#, JavaScript/TypeScript, C/C++).

## Prerequisites

Confirm the following before starting:
- Source repository URL and read-only access verified.
- Build system and dependency manifest present (requirements.txt, go.mod, Cargo.toml, package.json, pom.xml, etc.).
- Repository size is within context-retrievable limits; large monorepos require scoped analysis of specific packages or services.
- Operator approval obtained for any automated tooling that performs checkout operations.

**Skill Reference**: `AGENTS.md` § SOP-01, `references/framework_mappings.md`

## Phase 1 — Scope Definition & Language Detection

Identify the technology stack and define review boundaries.

1. Scan repository root for language indicators: `.py`, `.go`, `.rs`, `.java`, `.cs`, `.js`, `.ts`, `.c`, `.cpp`, `.h`.
2. Parse dependency manifests to catalog all third-party libraries and their versions.
3. Map application architecture: identify entry points, middleware, service boundaries, and data flow paths.
4. Classify trust boundaries between internal components and external inputs.
5. Define priority ranking based on exposure (public internet-facing, internal, admin-only) and sensitivity (PII, credentials, financial data).

**Tools**: `scripts/sca_scan.py`, `tools/scanner.py`, Snyk CLI, Trivy (artifact scanning only).

**Skill Reference**: `skills/secure-code-review`, `skills/web`, `skills/api`

## Phase 2 — Automated Static Analysis (SAST)

Run language-appropriate static analyzers configured to the project's security baseline.

1. Execute taint-analysis scanners targeting injection sinks (SQL, OS commands, LDAP, XXE, template injection, header injection).
2. Configure rule sets to suppress known false positives and reduce noise from benign patterns (e.g., debug-only logging, test harness code).
3. Cross-reference scanner output with dependency vulnerability feeds (NVD, OSV, GHSA) for transitive risk.
4. Review each flagged result against the source context — scanner output alone does not constitute a finding.
5. Document confirmed findings with exact file path, line number, affected function signature, and CWE classification.

**Tools**: Semgrep, Bandit, ESLint with security plugins, golangci-lint, SonarQube, CodeQL queries.

**Skill Reference**: `skills/web/scripts/jwt_forge.py`, `skills/api/scripts/api_security_tester.py`

## Phase 3 — Manual Security Architecture Review

Conduct structured walkthrough of high-risk components identified in Phase 2 and architectural hotspots.

1. **Authentication & Session Management**: Review login flows, token issuance/rotation, session fixation resistance, MFA enforcement, and password reset logic. Verify tokens are opaque, time-bound, and bound to client identity.
2. **Authorization & Access Control**: Trace permission checks at every data-access boundary. Identify horizontal privilege escalation vectors (insecure direct object references) and vertical escalation paths (role transition logic flaws).
3. **Input Validation**: Audit sanitization at trust boundaries. Confirm allowlist validation rather than blocklist approaches. Check for encoding bypasses in multibyte character sets where applicable.
4. **Cryptography Usage**: Verify algorithm selection, key management practices, IV reuse prevention, and correct implementation of authenticated encryption. Flag custom cryptography in favor of established libraries.
5. **Error Handling & Logging**: Inspect stack trace exposure, error message information leakage, and sensitive data inclusion in log outputs.

**Tools**: Manual review via agent reasoning, supplemented by `skills/code-auditor` agent delegation.

**Skill Reference**: `skills/crypto`, `skills/credential-access`, `schemas/finding.md`

## Phase 4 — Dependency & Supply Chain Audit

Evaluate external package risk independent of source code.

1. Generate Software Bill of Materials (SBOM) from dependency manifests.
2. Query vulnerability databases for published CVEs affecting listed packages.
3. Assess package health metrics: maintenance recency, contributor diversity, download frequency anomalies, and known malicious package history (npm audit, pip audit, cargo audit).
4. Review build scripts for post-install hooks, bootstrap scripts, and pre-build transforms that could introduce supply chain risk.
5. Verify lockfile integrity and pinning strategy to prevent uncontrolled dependency resolution.

**Tools**: `skills/supply-chain-registry/scripts/supply_chain_audit.py`, npm audit, pip-audit, dependabot, SCA tools.

**Skill Reference**: `skills/supply-chain`, `workflows/supply-chain-assessment.md`

## Phase 5 — Findings Correlation & Reporting

Consolidate all findings into unified deliverables with prioritized remediation guidance.

1. Deduplicate findings across automated and manual sources; merge related observations into single findings where appropriate.
2. Assign dual ranking (Confidence 1–10, Severity 1–10) per `schemas/finding.md`.
3. Compute CVSS v3.1 and v4.0 vectors grounded in demonstrated behavior, not theoretical worst case.
4. Map every finding to MITRE ATT&CK techniques and assign MITRE D3FEND countermeasures.
5. Produce language-specific secure coding recommendations with before/after code examples.
6. Attach machine-readable detection signatures (Sigma rules for log-based detection, IDE plugin rules for future prevention).

**Tools**: `skills/reporting/scripts/report_assembler.py`, `schemas/finding.md`, `templates/master_report.md`.

**Skill Reference**: `skills/reporting`, `skills/remediation`, `workflows/supply-chain-assessment.md`
