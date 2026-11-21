# Configuration Review Workflow

## Scope

Configuration review evaluates system, application, cloud service, and infrastructure settings against industry-hardened baselines (CIS Benchmarks, DISA STIGs, NIST SP 800-53, vendor security guides). This workflow identifies misconfigurations that expand attack surface, weaken access controls, or violate compliance requirements — without executing exploits or modifying configurations.

## Prerequisites

- Read-only API credentials or SSH/console access to target systems for configuration inspection.
- Established configuration baseline documents or CIS benchmark levels (Level 1 / Level 2) applicable to engagement scope.
- Operator authorization covering specific host types (Windows Server, RHEL, Ubuntu), cloud accounts (AWS, Azure, GCP), and database instances.
- Understanding of any approved deviation from baseline configurations already documented in change management records.

**Skill Reference**: `AGENTS.md` § SOP-01, `references/sops.md#sop-01-scope-verification-boundary-enforcement`

## Phase 1 — Target Classification & Baseline Selection

Determine applicable configuration standards based on target type and operating environment.

1. Inventory all target categories within scope: compute instances, container runtimes, database servers, storage services, network appliances, identity providers, managed Kubernetes clusters.
2. Select the appropriate benchmark baseline per target category (e.g., CIS Microsoft Windows Server Benchmark, CIS Amazon Web Services Foundations Benchmark, CIS Docker Benchmark).
3. Identify any organization-specific hardening standards that supersede or extend vendor benchmarks.
4. Catalog known approved exceptions with corresponding change request references; exclude these from violation reporting.
5. Define the reporting granularity level: individual setting violations, categorized control failures, or risk-weighted composite scores.

**Tools**: CIS-CAT Pro assessment mode, OpenSCAP scanner (read-only profiles), goss validation framework, custom baseline parsers.

**Skill Reference**: `skills/grc`, `workflows/standard-pentest.md`

## Phase 2 — Cloud Service Configuration Audit

Review cloud resource configurations across IAM, networking, storage, and managed services.

1. **Identity & Access Management**: Enumerate overly permissive IAM policies (AdministratorAccess, iam:PassRole without conditions), unused permissions boundaries, missing MFA on root accounts, expired certificate pairs.
2. **Network Security**: Verify VPC flow log enablement, security group egress rules, NAT gateway placement, WAF rule associations, DDoS protection status, private link configurations.
3. **Data Protection**: Check encryption-at-rest for all storage services (EBS volumes, S3 buckets, RDS instances, KMS key rotation schedules), transport-layer encryption enforcement, bucket policy public access blockers.
4. **Logging & Monitoring**: Confirm CloudTrail logging completeness (management events, data events, global services), CloudWatch log retention periods, GuardDuty detector status, Config rule evaluation coverage.
5. **Secret Management**: Audit Secrets Manager / AWS Systems Manager Parameter Store usage, verify automatic rotation configuration, identify plaintext credential storage in environment variables or launch templates.

**HITL Gate Required Before**: Running destructive configuration changes, attaching policies to production roles, or accessing secrets store contents beyond metadata enumeration.

**Tools**: Prowler, AWS Config queries, cf-nifti, checkov, Terrascan, cfn-nag.

**Skill Reference**: `skills/cloud/scripts/cloud_auditor.py`, `schemas/finding.md`

## Phase 3 — Operating System & Middleware Hardening Review

Assess host-level configuration against benchmark requirements.

1. **Authentication Configuration**: Review password complexity policies, account lockout thresholds, SSH daemon hardening (`PasswordAuthentication no`, `PermitRootLogin no`, `X11Forwarding no`), PAM module configuration, sudoers file audit.
2. **Audit & Logging**: Verify systemd-journald persistence settings, auditd rule completeness for privileged operations, syslog forwarding to centralized SIEM, log tamper detection mechanisms.
3. **Filesystem & Kernel Parameters**: Check mount options (nodev, nosuid, noexec on sensitive partitions), kernel parameter tuning (sysctl hardening), file integrity monitoring agent deployment and rule coverage.
4. **Service Exposure**: Inventory listening network services, verify unnecessary service disablement, confirm firewall rules restrict service exposure to authorized source CIDR ranges only.
5. **Patch Management**: Assess patch currency relative to vendor security advisories, evaluate automatic update configuration, identify unpatched critical vulnerabilities with available errata.

**Tools**: OpenSCAP remediation preview mode, Chef InSpec execute-only checks, Lynis audit report parsing, custom policy comparison scripts.

**Skill Reference**: `skills/network`, `skills/credential-access`, `integration/execution-policy-gateway.md`

## Phase 4 — Application & Database Configuration Assessment

Review middleware and data layer settings for security posture gaps.

1. **Web Servers**: Evaluate HTTP security headers (HSTS, X-Frame-Options, CSP, Referrer-Policy), TLS cipher suite restrictions, SSL/TLS version deprecation, error page information disclosure.
2. **Application Servers**: Inspect session management configuration (timeout values, secure cookie flags, SameSite attributes), JNDI injection prevention settings, hot-deployment disabling, debugging interface exposure.
3. **Database Engines**: Assess default account removal, remote administration port restrictions, transparent data encryption status, query result set row-limiting configurations, connection pooling authentication methods.
4. **Message Brokers**: Review MQTT/RabbitMQ/Kafka broker authentication, topic-level access control lists, TLS mutual authentication enforcement, retained message visibility, admin console exposure.
5. **Cache Layers**: Verify Redis/Memcached bind-address restriction to loopback or internal subnet, requirepass/authentication enforcement, CONFIG command accessibility restrictions.

**Tools**: Nessus configuration auditing plugins, OpenVAS NASL scripts in scan-only mode, dbaudit utilities, custom YAML/JSON configuration diff parsers.

**Skill Reference**: `skills/crypto`, `skills/reporting`, `workflows/standard-pentest.md`

## Phase 5 — Remediation Guidance & Compliance Mapping

Transform configuration findings into prioritized action items mapped to regulatory frameworks.

1. Score each finding by deviation severity: critical (directly exploitable misconfiguration), high (increases attack surface significantly), medium (defense-in-depth reduction), low (best-practice recommendation).
2. Map every finding to the originating benchmark section reference (e.g., "CIS AWS Level 1 — Section 2.1.1") and relevant compliance framework requirement (SOC 2 CC6.1, PCI DSS Req 2.x, HIPAA 164.312(a)(1)).
3. Provide executable remediation commands or IaC template corrections for each class of finding.
4. Produce a configuration drift summary showing movement toward or away from baseline over successive review cycles if historical data is available.
5. Deliver a compliance readiness scorecard suitable for auditor presentation with gap closure timelines.

**Skill Reference**: `skills/reporting/scripts/report_assembler.py`, `templates/master_report.md`, `references/framework_mappings.md`
