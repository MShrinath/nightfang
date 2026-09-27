# Software Supply Chain Assessment Workflow

**Workflow ID**: `supply-chain-assessment`  
**Description**: Comprehensive security evaluation of software dependencies, package repositories, build integrity, and Software Bill of Materials (SBOM) provenance.  
**Required Agents**: `supply-chain-auditor`, `code-auditor`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Intake & Scope**: Identify target software repositories, package registries, release artifacts, and build systems.
2. **SBOM Generation & Dependency Analysis (`supply-chain-auditor`)**:
   - Generate standardized SBOM in SPDX and CycloneDX formats using Syft.
   - Scan full dependency tree (direct and transitive) for known CVEs using Grype and OSV-Scanner.
3. **Dependency Confusion & Namespace Audit (`supply-chain-auditor`)**:
   - Identify private internal package dependencies in manifest and lockfiles.
   - Query public package registries (npm, PyPI, Maven, Go, Cargo) to detect unclaimed namespace exposure.
4. **Source Code & Third-Party Library Review (`code-auditor`)**:
   - Audit vendored dependencies and package install scripts for typosquatting signals or malicious lifecycle hooks.
5. **SLSA Provenance Verification (`supply-chain-auditor`)**:
   - Verify build provenance, isolated builder environments, and cryptographic artifact signatures.
6. **Remediation & Final Report (`reporter`)**:
   - Compile comprehensive software supply chain security report, dependency vulnerability catalog, and SLSA hardening roadmap.
