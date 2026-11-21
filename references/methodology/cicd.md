# Methodology: cicd

Source: [PentestingEverything/CI-CD Pentesting](https://github.com/m14r41/PentestingEverything/tree/main/CI-CD%20Pentesting)

---

## CI CD Pentesting

**A continuous penetration testing solution consists of several key components. Vulnerability Scanner that automatically scans your code for vulnerabilities. Continuous monitoring system for tracking new assets and environmental changes. Integration with CI/CD tooling to start a new scan whenever there is a code update**

---

## Core Concepts

CI/CD pentesting assesses the pipelines and tooling that build, test, and ship software. The goal is to protect the path from source code to production, since a single compromised step can poison every downstream artifact and reach production with trusted credentials.

**Methodology / Phases:**
- Map the pipeline: source repos, CI/CD platform, runners, build steps, artifact stores, and deploy targets.
- Review pipeline definitions: workflow/YAML files, triggers, and where untrusted input (PRs, forks) can run code.
- Hunt for secrets: tokens and keys in repo history, variables, logs, and build environments.
- Test trust and permissions: runner privileges, token scope, branch protections, and who can alter the pipeline.
- Trace the supply chain: dependencies, base images, and artifact integrity from build to deploy.

**Key Concepts / What to look for:**
- Secret leakage: credentials exposed in code, variables, or build logs.
- Poisoned pipeline execution: attacker-controlled input that runs in the pipeline (e.g. malicious PR workflows).
- Over-privileged runners and tokens: build jobs with more access than they need.
- Supply chain weaknesses: unpinned dependencies, mutable image tags, and unsigned artifacts.
- Weak access control: unprotected branches, missing reviews, and tamperable pipeline configuration.

---

<details>
<summary><strong>Overview</strong></summary>

A CI/CD pipeline is an automation system used for continuous integration and continuous delivery of software.

CI/CD security testing focuses on identifying vulnerabilities that can impact:

* Code integrity
* Build and deployment security
* Secret management
* Supply chain security

The objective is to ensure secure software delivery across all stages of the pipeline.

</details>

---

<details>
<summary><strong>CI/CD Security Architecture</strong></summary>

| Layer                  | Description                                                |
| ---------------------- | ---------------------------------------------------------- |
| Source Code Repository | Stores application source code and version history         |
| CI/CD Pipel

---

