# Cloud & Container Security Assessment Workflow

**Workflow ID**: `cloud-assessment`  
**Description**: Security evaluation of multi-cloud infrastructure (AWS, Azure, GCP), container workloads, and Kubernetes clusters.  
**Required Agents**: `cloud-security`, `container-breakout`, `validation`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Intake & Cloud Scope**: Verify cloud tenant boundaries, account IDs, and IAM audit credentials per SOP-01.
2. **Cloud Posture & Asset Discovery (`cloud-security`)**:
   - Enumerate public storage containers/buckets (S3, Azure Blobs, GCS).
   - Audit IAM roles, policies, and cross-account trust boundaries for privilege escalation vectors.
   - Test instance metadata services (IMDSv1 vs IMDSv2) via discovered web/SSRF vectors.
3. **Container & Kubernetes Auditing (`container-breakout`)**:
   - Assess container isolation, Linux capabilities, and exposed runtime sockets (`docker.sock`).
   - Audit Kubernetes API servers, Kubelet endpoints, and cluster-wide RBAC permissions.
   - Evaluate Pod Security Standards (PSS) and admission controller enforcement.
4. **Operator Approval Gate (HITL)**: Request operator approval before any active privilege escalation or container escape probing per SOP-04.
5. **Controlled PoC Validation (`validation`)**: Verify privilege boundary leaps using benign observation commands (`id`, `whoami`, `aws sts get-caller-identity`).
6. **Cleanup & Deliverable Compilation (`reporter`)**: Purge all testing artifacts and compile multi-cloud security assessment report.
