---
name: cloud-testing
description: >-
  Use this skill for cloud infrastructure security testing. Covers AWS,
  Azure, and GCP misconfigurations, storage bucket enumeration, IAM
  analysis, serverless function testing, and cloud-specific attack
  vectors. Activate when cloud infrastructure is in scope.
---

# Cloud Infrastructure Security Testing

Test cloud service configurations and security.

## AWS Testing

### S3 Bucket Enumeration
```bash
# Check bucket existence and permissions
aws s3 ls s3://BUCKET --no-sign-request
aws s3 cp test.txt s3://BUCKET --no-sign-request

# Common bucket naming patterns
[company]-backup, [company]-dev, [company]-staging
[company]-assets, [company]-uploads, [company]-logs
```

### IAM Analysis
```bash
# If credentials available
aws sts get-caller-identity
aws iam list-users
aws iam list-roles
aws iam get-policy --policy-arn ARN
```

### Metadata Service (via SSRF)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
```

### Lambda & Serverless
```bash
aws lambda list-functions
aws lambda get-function --function-name NAME
```

## Azure Testing

### Blob Storage
```bash
# Anonymous access check
curl https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list
```

### Azure AD
```bash
# Enumerate Azure AD
az ad user list
az ad group list
az role assignment list
```

## GCP Testing

### Storage Buckets
```bash
gsutil ls gs://BUCKET
curl https://storage.googleapis.com/BUCKET
```

### Metadata
```
http://metadata.google.internal/computeMetadata/v1/
```

## Common Cloud Misconfigurations

- [ ] Public storage buckets
- [ ] Overprivileged IAM roles
- [ ] Exposed metadata endpoints
- [ ] Unencrypted data at rest
- [ ] Missing MFA on admin accounts
- [ ] Security groups too permissive
- [ ] Logging not enabled
- [ ] Default VPC configurations
- [ ] Exposed database services
- [ ] Serverless function injection

## Tools
| Tool | Purpose |
|------|--------|
| `ScoutSuite` | Multi-cloud security audit |
| `Prowler` | AWS security assessment |
| `CloudSploit` | Cloud security scanning |
| `Pacu` | AWS exploitation framework |
| `enumerate-iam` | IAM permission enumeration |
| `S3Scanner` | S3 bucket scanner |

## ⚠️ HITL: All cloud exploitation requires operator approval

## NIGHTFANG Agent Integration
The **SCANNER-CLOUD** agent automates this skill's procedures within the NIGHTFANG swarm:
- Runs as Phase 3 parallel scanner alongside webapp, API, network, SSL, and AI scanners
- Uses `awscli`, `az`, `gcloud`, `prowler`, `scoutsuite`, `pacu`, `s3scanner` tools
- Tests AWS (S3, IAM, EC2, Lambda, RDS), Azure (Storage, AD), GCP (Buckets, Metadata)
- SSRF-based cloud metadata access testing without credentials
- Outputs findings with MITRE ATT&CK mappings (T1530, T1078.004, T1580, T1552.005)
- Requires HITL via Telegram `/go` before any cloud exploitation
- Configure via `technique_config.cloud_testing` in engagement YAML (regions, subscriptions, projects)
