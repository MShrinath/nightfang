---
name: cloud
description: Cloud security assessment covering AWS, Azure, and GCP, public storage bucket audits, IAM privilege escalation, and IMDS SSRF exploitation.
version: "2.0"
domain: cybersecurity
subdomain: cloud-security
tags: [cloud, aws, azure, gcp, imds, s3, iam, metadata-ssrf]
mitre_attack: [T1580, T1530, T1078.004]
d3fend_techniques: [D3-CSM, D3-IAM]
---

# Cloud Security Skill

Offensive assessment and security posture evaluation across public cloud platforms (AWS, Azure, Google Cloud).

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `ScoutSuite` | Multi-cloud configuration auditor | `scout aws --no-browser` | Manual AWS CLI review |
| `Prowler` | AWS CIS benchmark security audit | `prowler aws` | Cloud custodian / CLI scripts |
| `aws-cli` | AWS service interaction | `aws s3 ls s3://<BUCKET> --no-sign-request` | `curl` / `s3cmd` |
| `az-cli` | Azure tenant & resource inspection | `az storage blob list --account-name <ACC>` | REST API curl |

## Methodology

### 1. Cloud Storage & Asset Exposure
- **AWS S3**: Test buckets for public read, write, and ACL permissions (`s3://<BUCKET>` via anonymous requests).
- **Azure Blob Storage**: Test container public access levels (Private, Blob, Container) for unauthenticated listing and download.
- **GCP Cloud Storage**: Test bucket permissions with `allUsers` and `allAuthenticatedUsers`.

### 2. Instance Metadata Service (IMDS) Exploitation via SSRF
- **AWS IMDSv1**: Query `http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>` via discovered SSRF vulnerabilities to extract temporary IAM credentials (AccessKeyId, SecretAccessKey, Token).
- **AWS IMDSv2**: Test if `X-aws-ec2-metadata-token` is required, and assess if token generation can be triggered via headers.
- **Azure Metadata**: Query `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with header `Metadata: true`.
- **GCP Metadata**: Query `http://metadata.google.internal/computeMetadata/v1/` with header `Metadata-Flavor: Google`.

### 3. IAM & Privilege Escalation Analysis
- Enumerate attached IAM policies for excessive permissions (`*` wildcard actions).
- Check for dangerous IAM permissions that allow privilege escalation (e.g., `iam:CreateAccessKey`, `iam:AttachUserPolicy`, `iam:PassRole`, `sts:AssumeRole`).

### 4. Serverless & Container Exposure
- Audit unauthenticated API Gateway endpoints and AWS Lambda function URLs.
- Identify exposed Kubernetes API servers (port 6443 / 8080) and unprotected Docker daemon sockets (port 2375).

## Output
- Cloud resource inventory and public exposure matrix.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
