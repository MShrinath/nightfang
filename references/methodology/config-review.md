# Methodology: config-review

Source: [PentestingEverything/Configuration Review](https://github.com/m14r41/PentestingEverything/tree/main/Configuration%20Review)

---



# Configuration Review in Penetration Testing

## What is Configuration Review?

A **configuration review** is a methodical process in penetration testing where the tester examines system, application, network, and infrastructure settings to identify **security misconfigurations** that could lead to vulnerabilities. It is one of the most overlooked but **critical components** in any security assessment.

This phase often involves **manual inspection** and the use of automated tools to validate if systems follow **security best practices** and  **organization-specific hardening guidelines** .

---

## Objectives of a Configuration Review

* Identify insecure default settings.
* Discover unnecessary services or ports.
* Ensure secure access controls and permissions.
* Validate encryption settings (e.g., SSL/TLS).
* Check for outdated software or missing patches.
* Confirm logging, monitoring, and auditing configurations.
* Evaluate adherence to regulatory or compliance standards (e.g., PCI DSS, ISO 27001, NIST).

---

## What to Review (Key Areas)

### 1. **Operating System (OS) Configuration**

* Are unnecessary services or daemons running?
* Are default credentials still in place?
* Are firewalls (e.g., iptables, Windows Firewall) configured properly?
* Are secure boot and kernel hardening enabled?

### 2. **Web Servers (e.g., Apache, Nginx, IIS)**

* Are directory listings disabled?
* Are error messages exposing server info?
* Is `X-Frame-Options` or `Content-Security-Policy` set?
* Is SSL enforced, and are weak ciphers disabled?

### 3. **Database Servers**

* Are databases exposed on public IPs?
* Are strong authentication mechanisms in place?
* Is logging enabled for queries and login attempts?
* Are permissions overly permissive (e.g., `GRANT ALL`)?

### 4. **Network Devices (Routers, Firewalls, Switches)**

* Is Telnet disabled in favor of SSH?
* Are management interfaces accessible from the internet?
* Are default SNMP community strings changed?
* Are ACLs (Access Control Lists) correctly implemented?

### 5. **Cloud Infrastructure (AWS, Azure, GCP)**

* Are public S3 buckets properly secured?
* Are IAM roles overly permissive?
* Are access keys exposed in source code?
* Is multi-factor authentication (MFA) enabled?

### 6. **Containers and Orchestration (Docker, Kubernetes)**

* Are containers running as root?
* Are images pulled from untrusted sources?
* Is the Kubernetes dashboard open to the internet?
* Are secrets stored securely (e.g., not i

---

