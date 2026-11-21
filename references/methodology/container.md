# Methodology: container

Source: [PentestingEverything/Container & Kubernetes  Assessment](https://github.com/m14r41/PentestingEverything/tree/main/Container%20&%20Kubernetes%20%20Assessment)

---

# Docker Overview and Security Resources

Docker is a platform that uses container technology to automate application deployment, ensuring consistent performance across different environments. It enhances portability, efficiency, version control, and orchestration for scalable and isolated application deployment. However, Docker can have security issues such as vulnerabilities in container images, misconfigurations, and risks associated with shared kernel resources.

## Core Concepts

Container and Kubernetes assessment evaluates how images, containers, and the orchestrator are built and configured. Containers share the host kernel rather than fully virtualizing it, so the central question is whether an attacker can break out of a container or move laterally across the cluster.

**Methodology / Phases:**
- Scan images: check base images and layers for vulnerabilities, embedded secrets, and excessive contents.
- Review runtime config: privileged containers, mounted host paths, capabilities, and exposed sockets (e.g. the Docker socket).
- Test container escape: kernel exploits, misconfigurations, and dangerous mounts that reach the host.
- Assess the cluster: Kubernetes RBAC, service accounts, network policies, secrets handling, and the API server exposure.
- Map lateral movement: from a pod to other pods, nodes, the control plane, and cloud metadata/credentials.

**Key Concepts / What to look for:**
- Privileged and over-capable containers: `--privileged`, added capabilities, and host namespace sharing.
- Dangerous mounts: the Docker socket, host filesystem, or `/proc` exposed inside a container.
- Image hygiene: vulnerable packages, hardcoded secrets, and outdated or unpinned base images.
- Kubernetes RBAC and secrets: overly broad roles, default tokens, and plaintext or readable secrets.
- Weak isolation: missing network policies, exposed dashboards/kubelet, and reachable cloud metadata.

| Credit          | Details                                   |
|-----------------|-------------------------------------------|
| CSbyGB         | [CSbyGB](https://github.com/CSbyGB)       |
|    Madhurendra Kumar             |  [m14r41](https://github.com/m14r41/PentestingEverything/edit/main/DockerContainer%20Pentesting/README.md)                   |

## What is Docker?
- [Docker Overview on Docker Docs](https://lnkd.in/eRkNTVNu)
- [What is Docker and How it Works on Simplilearn](https://lnkd.in/ep8T7yUM)
- [Linux Containers - Basic Concepts by Lucian Carata](https://l

---

