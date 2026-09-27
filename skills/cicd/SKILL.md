---
name: cicd
description: CI/CD pipeline and software delivery security assessment covering workflow poisoning (Poisoned Pipeline Execution), runner token extraction, dependency confusion, OIDC identity abuse, and secrets hygiene.
domain: cybersecurity
subdomain: cicd-pipeline-security
tags: [cicd, github-actions, gitlab-ci, jenkins, pipeline-poisoning, oidc, runner-abuse, secrets]
mitre_attack: [T1195.002, T1587.001, T1552.004]
d3fend_techniques: [D3-PA, D3-SCA, D3-BCV]
version: "1.0"
---

# CI/CD Pipeline Security Skill

Security assessment of automated continuous integration and continuous deployment pipelines (GitHub Actions, GitLab CI/CD, Jenkins, Azure DevOps).

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `gato-cli` | GitHub Actions audit & exploitation toolkit | `gato audit --repo <ORG/REPO>` | GitHub REST API inspection |
| `trufflehog` | Automated git secret and key scanner | `trufflehog git <REPO_URL>` | Gitleaks / regex grep |
| `step-security` | Harden-runner workflow auditor | Workflow static analysis | Manual YAML review |
| `pip-audit` / `npm audit` | Pipeline dependency vulnerability audit | `pip-audit` / `npm audit` | Trivy / Snyk |

## Methodology

### 1. Poisoned Pipeline Execution (PPE) Analysis
- **Trigger Auditing**: Identify untrusted pull request triggers (`pull_request_target`, `workflow_run`) that checkout untrusted code or execute build scripts with elevated repository write tokens.
- **Script Injection in Workflow Runners**: Inspect workflow expressions (`${{ github.event.issue.title }}`, `${{ github.head_ref }}`) concatenated directly into `run:` shell steps without intermediate environment variables.

### 2. Runner Isolation & Secrets Hygiene
- **Self-Hosted Runner Security**: Determine whether public pull requests execute on persistent self-hosted runners without ephemeral container teardown.
- **Build Secret Exposure**: Audit step outputs, log redaction effectiveness, and runner filesystem temporary directories (`/tmp`, `/home/runner`) for leaked access tokens or SSH deployment keys.

### 3. OIDC & Cloud Provider Federation Abuse
- Inspect OpenID Connect (OIDC) trust configurations between CI/CD platforms and cloud providers (AWS IAM, GCP Workload Identity, Azure Federated Credentials).
- Verify audience (`aud`) and subject (`sub`) claims validation to prevent cross-repository token substitution.

### 4. Artifact & Build Provenance Verification
- Check for artifact tampering between build, test, and release stages.
- Validate cryptographic signatures and SLSA provenance generated during pipeline execution.

## Output
- Pipeline security audit report with vulnerable workflow triggers and secret leakage risks.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
