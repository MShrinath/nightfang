# DevSecOps Pipeline Security Workflow

## Scope

This workflow evaluates CI/CD pipeline security across all stages — source control, build, test, artifact storage, deployment, and runtime monitoring. Applicable to GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, Bitbucket Pipelines, and custom automation frameworks.

## Prerequisites

- Read access to pipeline configuration files (`.github/workflows/*.yml`, `Jenkinsfile`, `.gitlab-ci.yml`, etc.).
- Read access to environment variable secrets list (never consume actual secret values).
- Read access to artifact repository listings and deployment target configurations.
- Operator authorization to inspect runner infrastructure and container registries.

**Skill Reference**: `AGENTS.md` § SOP-01, `manifest.yaml` capabilities `cicd-pipeline-security`

## Phase 1 — Pipeline Topology Mapping

Document the complete execution flow without modifying any artifacts or triggering builds.

1. Enumerate all workflow definition files across every branch and repository in scope.
2. Map pipeline stages: checkout → dependencies → build → unit test → SAST/DAST → artifact publish → deploy → smoke test.
3. Identify all external actions, reusable workflows, composite actions, and marketplace plugins referenced.
4. Catalog authentication mechanisms: OIDC tokens, SSH keys, PATs, runner registration tokens, AWS IAM roles.
5. Document deployment targets: cloud accounts, container registries, Kubernetes clusters, edge nodes, CDN endpoints.

**Tools**: `gh actions view`, `git ls-files`, YAML linters, custom traversal scripts.

**Skill Reference**: `skills/cicd`, `workflows/supply-chain-assessment.md`

## Phase 2 — Secret Management Audit

Review how secrets are stored, injected, and rotated throughout the pipeline lifecycle.

1. Inventory all declared secrets (repository-level, organization-level, environment-level, vault references).
2. Verify no secrets are logged, echoed, or passed as command-line arguments visible in job logs.
3. Check for secret leakage via artifact downloads, debug dumps, or cache entries containing sensitive data.
4. Assess rotation cadence policies and credential lifetime restrictions per secret category.
5. Evaluate runner isolation: shared runners expose secrets to subsequent jobs on the same host; self-hosted runners must be reviewed for cross-job contamination.

**HITL Gate Required Before**: Accessing live secret values, downloading production artifacts for inspection, or testing credential validity against live services.

**Tools**: Detect-secrets, gitleaks audit mode (read-only), git-secrets, custom secret pattern matching.

**Skill Reference**: `skills/crypto/scripts/credential_scanner.py`, `schemas/finding.md`

## Phase 3 — Dependency & Supply Chain Hardening

Assess the integrity and freshness guarantees of all upstream inputs.

1. Review dependency resolution strategy: locked versions vs. floating ranges vs. `latest` tags.
2. Verify provenance attestation requirements (Sigstore cosign, SLSA provenance, in-toto attestations).
3. Audit software bill of materials generation and vulnerability scanning integration at each pipeline stage.
4. Check for dependency confusion risk: private package names exposed to public registries due to misconfigured scopes.
5. Evaluate post-commit hooks and pre-merge checks that enforce security gate criteria before code enters main branches.

**Tools**: Syft, Grype, Trivy image scanner (artifact evaluation only), Dependabot/Snyk/GitHub Advisory Database.

**Skill Reference**: `skills/supply-chain`, `skills/fuzzing-engine`, `workflows/supply-chain-assessment.md`

## Phase 4 — Runner & Environment Security

Evaluate the execution environment that processes pipeline workloads.

1. Inspect runner operating system version, patch level, and available kernel hardening features.
2. Verify network egress restrictions: can runners reach arbitrary external hosts or only approved APIs?
3. Assess ephemeral workspace cleanup: verify no state persists between jobs on shared infrastructure.
4. Check container base image composition for known vulnerabilities and overly permissive configurations.
5. Review privilege separation: does any job run as root, have Docker socket access, or possess host filesystem write permissions outside its workspace?

**Tools**: Container image analysis (read-only layers), CIS benchmark checklists for runner OS, policy-as-code validation (Conftest, OPA).

**Skill Reference**: `skills/container`, `skills/cloud`, `workflows/cloud-assessment.md`

## Phase 5 — Deployment Integrity & Runtime Guardrails

Validate that deployed artifacts match audited build outputs and runtime defenses are adequate.

1. Compare deployed binary hashes against artifact repository records to confirm immutability.
2. Verify image signing enforcement at registry admission controller level.
3. Assess deployment secret injection patterns: mounted volumes vs. environment variables vs. runtime secret managers.
4. Review runtime monitoring coverage: are pipeline-generated artifacts instrumented with telemetry, structured logging, and anomaly detection?
5. Evaluate rollback capability: can compromised deployments be reverted within defined RTO thresholds?

**HITL Gate Required Before**: Triggering destructive pipeline operations, modifying production deployment configurations, or executing workload containers in live environments.

**Skill Reference**: `skills/reporting`, `skills/remediation`, `integration/execution-policy-gateway.md`
