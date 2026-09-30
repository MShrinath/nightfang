---
name: supply-chain
description: Software supply chain security assessment covering Software Bill of Materials (SBOM) generation and analysis, dependency confusion, typosquatting detection, malicious maintainer takeover, and SLSA provenance.
version: "2.0"
domain: cybersecurity
subdomain: supply-chain-security
tags: [supply-chain, sbom, dependency-confusion, typosquatting, slsa, provenance, npm, pypi]
mitre_attack: [T1195.001, T1195.002]
d3fend_techniques: [D3-SCA, D3-SLSA, D3-SIG]
---

# Software Supply Chain Security Skill

Methodology for assessing software dependencies, package registries, build provenance, and third-party software components.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `syft` | CLI tool for generating SBOM from container images and filesystems | `syft <TARGET> -o spdx-json=sbom.json` | `cyclonedx-cli` |
| `grype` | Vulnerability scanner for container images and filesystems | `grype sbom:sbom.json` | `trivy` |
| `osv-scanner` | Open Source Vulnerability scanner powered by Google OSV | `osv-scanner -r .` | `pip-audit` / `npm audit` |
| `slsa-verifier` | Verifies SLSA provenance on build artifacts | `slsa-verifier verify-artifact <ARTIFACT> ...` | Cosign / Sigstore manual check |

## Methodology

### 1. Software Bill of Materials (SBOM) Generation & Analysis
- Generate standardized SBOMs in **SPDX 2.3** or **CycloneDX 1.5** formats from source trees, lockfiles, and container images.
- Enumerate complete dependency graphs, distinguishing direct vs transitive dependencies.
- Match all components against the OSV, NVD, and GitHub Advisory databases for known CVEs.

### 2. Dependency Confusion & Namespace Hijacking
- **Internal vs Public Registry Resolution**: Identify internal corporate package names (e.g. `@corp/auth-lib`) referenced in `package.json`, `requirements.txt`, `pom.xml`, or `go.mod`.
- **Public Availability Check**: Query public registries (npm, PyPI, Maven Central, RubyGems) to verify if internal package namespaces are unclaimed.
- Flag any unclaimed internal package names as critical dependency confusion risks.

### 3. Typosquatting & Malicious Package Hunting
- Check package names against known open-source libraries for common typosquatting patterns (Levenshtein distance $\le 2$, missing hyphens, swapped characters).
- Inspect package install scripts (`preinstall`, `postinstall`, `setup.py`) for suspicious outbound network connections or obfuscated shell execution.

### 4. Build Integrity & SLSA Provenance Verification
- Verify Supply-chain Levels for Software Artifacts (SLSA Levels 1–4) compliance:
  - Source integrity (version-controlled, review-enforced).
  - Build service isolation (ephemeral, hermetic, isolated environments).
  - Provenance generation (cryptographically signed metadata linking artifact to source commit).

## Output
- Complete SBOM artifact and dependency vulnerability report.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
