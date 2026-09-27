# CI/CD Pipeline & Supply Chain Assessment Workflow

**Workflow ID**: `cicd-assessment`  
**Description**: Dedicated security audit of automated continuous integration pipelines, build runner environments, and software supply chain components.  
**Required Agents**: `cicd-redteam`, `supply-chain-auditor`, `validation`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Intake & Pipeline Scope**: Identify repositories, CI/CD platforms (GitHub Actions, GitLab, Jenkins), and deployment targets per SOP-01.
2. **Workflow Configuration Analysis (`cicd-redteam`)**:
   - Audit pipeline trigger events (`pull_request_target`, `workflow_run`) for untrusted execution.
   - Inspect workflow definition files for script injection vulnerabilities in shell execution steps.
   - Audit runner isolation and environment secret masking.
3. **Software Supply Chain & Dependency Audit (`supply-chain-auditor`)**:
   - Generate and inspect Software Bill of Materials (SBOM) for direct and transitive dependencies.
   - Audit for dependency confusion vulnerabilities by verifying private package namespace claims on public registries.
   - Audit SLSA build provenance and artifact signing.
4. **Cloud OIDC Integration Review (`cicd-redteam`)**:
   - Evaluate OpenID Connect (OIDC) trust policies between CI/CD runners and cloud environments.
5. **Operator Approval Gate (HITL)**: Request operator approval before attempting any active test PR creation or build triggering per SOP-04.
6. **PoC Validation (`validation`)**: Verify workflow vulnerabilities with benign canary environment outputs.
7. **Reporting & Hardening Blueprint (`reporter`)**: Compile CI/CD security assessment report with pipeline hardening recommendations.
