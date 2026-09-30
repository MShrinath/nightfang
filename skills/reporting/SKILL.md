---
name: reporting
description: Technical report synthesis, finding deduplication, executive summary formatting, and final deliverable generation.
version: "2.0"
domain: cybersecurity
subdomain: technical-reporting
tags: [reporting, executive-summary, findings-compilation, deliverables]
---

# Reporting & Deliverables Compilation Skill

Methodologies for ingesting swarm findings, deduplicating vulnerabilities, synthesizing attack narratives, and generating audit-ready penetration test deliverables.

## Core Capabilities

### 1. Ingestion & Deduplication
- Ingest finding objects produced per [`schemas/finding.md`](../../schemas/finding.md).
- Cluster related endpoints exhibiting identical root causes (e.g., missing CSRF token across 15 forms) into a single unified finding with multiple affected endpoints.

### 2. Dual-Tier Presentation
- **Executive Summary**: High-level risk score, business risk context, findings distribution table, and top 3 critical risks for leadership.
- **Engineering Walkthroughs**: Granular reproduction steps, exact `curl` / CLI commands, raw request/response captures, and cryptographic SHA-256 evidence hashes.

### 3. Report Generation Standard
- Follow [`templates/full_report_template.md`](../../templates/full_report_template.md) for master engagement deliverables.
- Use [`templates/finding_template.md`](../../templates/finding_template.md) for technical finding entries.
- Ensure every finding includes MITRE ATT&CK / ATLAS classifications, CVSS v3.1 vector strings, and MITRE D3FEND remediation guidance.
