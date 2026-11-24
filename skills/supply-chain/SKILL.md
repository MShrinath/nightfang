---
name: supply-chain
description: Software supply chain security assessment covering Software Bill of Materials (SBOM) generation and analysis, dependency confusion, typosquatting detection, malicious maintainer takeover, registry auditing, and SLSA provenance.
version: "2.0"
domain: cybersecurity
subdomain: supply-chain-security
tags: [supply-chain, sbom, dependency-confusion, typosquatting, slsa, provenance, npm, pypi, registry-audit]
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
| `supply_chain_audit.py` | Native dependency inventory & typosquat scanner | `python skills/supply-chain/scripts/supply_chain_audit.py --root .` | `dependency_checker.py` |

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
- Check installed packages against known open-source libraries for common typosquatting patterns:
  | Pattern | Example | Severity |
  |---------|---------|----------|
  | Visual confusable chars | `reqeusts` vs `requests` | CRITICAL |
  | Added numeric suffix | `axiosv2`, `express_1` | HIGH |
  | Swapped letters | `flaskk`, `django-d` | HIGH |
  | Added hyphen/underscore prefix | `_python-dotenv`, `-webpack` | MEDIUM |
  | Homoglyph substitution | `facebоok` (Cyrillic о) | CRITICAL |
- **Malicious Package Signature Scan**:
  - Scan package metadata and install scripts (`preinstall`, `postinstall`, `setup.py`) for suspicious keywords (`eval`, `exec`, `base64_decode`, `child_process`).
  - Flag newly registered packages with low download counts mimicking popular libraries.

### 4. Build Integrity & SLSA Provenance Verification
- Verify Supply-chain Levels for Software Artifacts (SLSA Levels 1–4) compliance:
  - Source integrity (version-controlled, review-enforced).
  - Build service isolation (ephemeral, hermetic, isolated environments).
  - Provenance generation (cryptographically signed metadata linking artifact to source commit).

## Detection Rules

### Sigma Rule — Suspicious Package Installation from Untrusted Source
```yaml
title: Suspicious Package Installation from Untrusted Source
logsource:
    category: build_pipeline
detection:
    selection_registry_change:
        event: 'package_install'
        registry: 'unapproved'
    condition: selection_registry_change
level: high
```

## Output
- Complete SBOM artifact and dependency vulnerability report.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
