---
name: container
description: Container and Kubernetes security assessment covering container breakout vectors, insecure runtime privileges, Kubernetes RBAC audits, admission controller bypasses, and Kubelet API auditing.
version: "2.0"
domain: cybersecurity
subdomain: container-kubernetes-security
tags: [container, docker, kubernetes, k8s, escape, rbac, admission-controller, kubelet]
mitre_attack: [T1611, T1612, T1613, T1610]
d3fend_techniques: [D3-CIE, D3-CHM, D3-PSA]
---

# Container & Kubernetes Security Skill

Offensive assessment and security posture evaluation of container runtimes (Docker, containerd, CRI-O) and container orchestration platforms (Kubernetes, OpenShift, EKS, GKE, AKS).

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `kube-bench` | CIS Kubernetes Benchmark compliance | `kube-bench run --targets master,node` | Manual manifest inspection |
| `trivy` | Container image vulnerability & secret scanner | `trivy image <IMAGE>` | Grype / Clair |
| `kubectl` | Kubernetes API interaction | `kubectl auth can-i --list` | Direct curl to K8s API |
| `cdk-go` | Container penetration testing toolkit | Automated container escape check | Manual sysfs/procfs inspection |

## Methodology

### 1. Container Runtime Isolation & Breakout (T1611)
- **Privileged Mode Detection**: Check `/proc/self/status` for `CapEff` (`0000003fffffffff` = privileged). Test disk device mounting via `fdisk -l` or `/dev/sd*`.
- **Dangerous Linux Capabilities**: Test for `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_OVERRIDE`, `CAP_NET_ADMIN`.
- **Exposed Host Sockets**: Check for mounted Docker socket (`/var/run/docker.sock`) or containerd socket (`/run/containerd/containerd.sock`).
- **Dangerous Mounts**: Inspect `/proc/` and `/sys/` mounts (e.g. `/proc/sys/kernel/core_pattern` or `release_agent` cgroup escapes).

### 2. Kubernetes Node & Kubelet Auditing (T1613)
- **Unauthenticated Kubelet API**: Probe port `10250` (HTTPS) and `10255` (read-only HTTP) for anonymous access (`/pods`, `/run/`).
- **Node IAM Metadata**: From pod context, probe cloud instance metadata endpoint (`169.254.169.254`) to identify node instance profile or service account tokens.

### 3. Kubernetes RBAC & Service Account Abuse
- Extract mounted service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`.
- Enumerate permitted verbs and resources (`kubectl auth can-i --list`).
- Audit for high-risk RBAC permissions:
  - `pods/exec` (arbitrary command execution in workloads)
  - `secrets/get`, `secrets/list` (cluster-wide credential harvest)
  - `roles/bind`, `clusterroles/bind` (privilege escalation to cluster-admin)

### 4. Admission Control & Pod Security Standards (PSS)
- Test for enforcement of Pod Security Standards (Privileged, Baseline, Restricted).
- Audit admission webhook configurations for fail-open policies (`failurePolicy: Ignore`).

## Output
- Container breakout attack paths and Kubernetes cluster risk analysis.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
