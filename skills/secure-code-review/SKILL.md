---
name: secure-code-review
description: Static Application Security Testing (SAST), sink-to-source taint tracking, and manual code review procedures.
version: "2.0"
domain: cybersecurity
subdomain: sast
tags: [sast, code-review, taint-tracking, static-analysis]
mitre_attack: [TA0001]
d3fend_techniques: [D3-AST, D3-SCA]
---

# Secure Code Review & SAST

Static Application Security Testing and manual code review procedures for identifying vulnerabilities in source code before deployment.

## Tools & Execution Matrix

| Tool | Purpose | Standard Command | Fallback |
| :--- | :--- | :--- | :--- |
| `semgrep` | Multi-language SAST | `semgrep --config=auto <DIR>` | `bandit` (Python) |
| `bandit` | Python SAST | `bandit -r <DIR> -f json` | Manual review |
| `gitleaks` | Secret scanning | `gitleaks detect --source=<DIR>` | `trufflehog` |
| `trufflehog` | Secret scanning | `trufflehog filesystem <DIR>` | `git-secrets` |
| `gosec` | Go SAST | `gosec ./...` | `go vet` |
| `eslint` | JavaScript SAST | `eslint --ext .js,.ts <DIR>` | Manual review |

## Methodology

### 1. Source Code Scanning
- Run language-appropriate SAST tool across the entire codebase.
- Configure custom rules for project-specific patterns (internal APIs, data models).
- Filter results by severity and relevance to the application's threat model.

### 2. Sink-to-Source Taint Tracking
- Identify dangerous sinks: `exec()`, `eval()`, `system()`, `SQL queries`, `file I/O`, `HTTP requests`.
- Trace data flow from untrusted sources: user input, HTTP params, headers, cookies, files.
- Flag any path where untrusted data reaches a dangerous sink without sanitization.

### 3. Manual Code Review
- Focus on authentication, authorization, session management, and cryptography.
- Review data access layers for SQL injection, ORM bypass, and privilege escalation.
- Check for hardcoded secrets, credentials, and configuration errors.
- Verify input validation, output encoding, and error handling.

### 4. Dependency Scanning
- Scan dependency manifests (`package.json`, `Cargo.toml`, `pom.xml`, `go.mod`) for known CVEs.
- Check for transitive dependency vulnerabilities.
- Identify deprecated or unmaintained packages.

### 5. Secret Detection
- Scan entire repository for exposed credentials, API keys, and tokens.
- Check git history for secrets that were committed and later removed.
- Verify `.gitignore` excludes sensitive files.

## Output
- SAST report with findings ranked by severity and exploitability.
- Taint tracking map showing untrusted data flows to dangerous sinks.
- Dependency vulnerability report with remediation guidance.
- Secret exposure report with rotation recommendations.