# Firewall Penetration Testing Workflow

## Scope

This workflow tests perimeter and internal firewall rule configurations through authorized enumeration and policy verification. Scope includes hardware firewalls (Palo Alto, Fortinet, Cisco ASA/Firepower), software firewalls (iptables/nftables, Windows Defender Firewall, pfSense), WAF rulesets, and cloud security group / network ACL configurations. **No destructive rule modification is performed during this workflow.**

## Prerequisites

- Explicit written authorization covering specific firewall appliances or cloud VPCs.
- Network diagram confirming firewall placement within the attack topology.
- Understanding of expected allowed/denied traffic flows for baseline comparison.
- Operator confirmation that port probing and banner-grabbing is within scope boundaries.

**Skill Reference**: `AGENTS.md` § SOP-01, `references/sops.md#sop-01-scope-verification-boundary-enforcement`

## Phase 1 — Passive Rule Discovery

Enumerate firewall posture through non-invasive observation techniques only.

1. Collect publicly advertised firewall vendor information, firmware versions, and management interface exposure status.
2. Map permitted ingress/egress paths using traceroute, ping sweep, and TCP SYN probes against documented service ports.
3. Analyze TLS certificate chain presented by management interfaces to identify appliance model and firmware revision.
4. Survey DNS records, WHOIS data, and Shodan/Censys API queries for historically exposed management endpoints.
5. Document observed traffic patterns during a quiet-period observation window to identify active service ports.

**Tools**: Masscan, rustscan, Nmap (SYN scan `-sS` only, low rate), SSLscan, sublist3r, ciphersuite.info.

**Skill Reference**: `skills/network`, `skills/recon`, `workflows/standard-pentest.md`

## Phase 2 — Rule Logic Verification

Test whether observed filtering behavior matches documented or expected security policy.

1. Perform UDP and TCP state verification: send packets through seemingly closed ports to detect stateful inspection weaknesses or port knocking bypasses.
2. Test rule ordering flaws: send crafted packet sequences designed to exploit rule precedence conflicts (e.g., explicit allow preceding implicit deny).
3. Verify default-deny posture: confirm that undocumented ports return appropriate rejection codes rather than silent drops that could indicate misconfiguration.
4. Assess NAT/PORT forwarding rule transparency: identify forwarded internal addresses and services not documented in security baselines.
5. Evaluate IPv6 handling: confirm IPv6 firewall rules mirror IPv4 equivalents or confirm intentional exclusion with operator consent.

**Tools**: Scapy (custom packet crafting), Nmap script engine (`firewalk`, `ipidseq`, `netbios`), hping3 (authorized testing only).

**Skill Reference**: `skills/network/scripts/port_scan_enhanced.py`, `schemas/finding.md`

## Phase 3 — Management Interface Assessment

Test administrative access controls governing firewall configuration changes.

1. Scan for exposed management interfaces (HTTPS 443, HTTP 80, SSH 22, proprietary protocols like PAN-OS, FortiManager ports).
2. Attempt password spray only against admin interfaces explicitly authorized in scope; use minimum necessary attempts (3 per account) to respect rate limiting.
3. Verify multi-factor authentication enforcement on all management access paths including API endpoints and mobile administration apps.
4. Check for default or well-known credentials still active on unmodified factory-default installations discovered within scope.
5. Review HTTP response headers for information disclosure (X-Powered-By, Server banners revealing firmware version) on management interface responses.

**HITL Gate Required Before**: Any credential testing against admin interfaces, attempting authentication bypass techniques, or accessing backup/configuration export endpoints.

**Tools**: Burp Suite (proxy mode for management interface HTTPS), Hydra (rate-limited, scope-confirmed only), Nuclei templates for firewall CVEs.

**Skill Reference**: `skills/initial-access`, `skills/credential-access`, `references/sops.md#sop-04-human-in-the-loop-hitl-exploitation-gate-tiered-autonomy`

## Phase 4 — Cloud Security Group & ACL Review

For cloud-deployed firewalls and network segmentation controls.

1. Audit AWS Security Groups, Azure Network Security Groups, GCP Firewall Rules, and OCI Security Lists for over-permissive CIDR allowances.
2. Identify egress permitting unrestricted outbound internet access from restricted network segments (data exfiltration vector).
3. Review transit gateway and VPC peering routing tables for unintended cross-VPC reachability bypassing security group controls.
4. Check for deprecated or dangling security group rules referencing deleted instances that were never cleaned up.
5. Verify AWS Flow Logs, Azure Network Watcher, and GCP VPC flow logs are enabled and retention periods meet compliance requirements.

**Tools**: Cloudsploration, CloudGoat scenarios (read-only assessment mode), AWS CLI/Azure CLI/GCloud CLI (describe commands only).

**Skill Reference**: `skills/cloud`, `skills/container`, `workflows/cloud-assessment.md`

## Phase 5 — Reporting & Policy Gap Analysis

Produce findings that map observed behavior to security policy gaps.

1. Document every firewall rule discrepancy as a finding with evidence capture (packet captures, port scan results, configuration excerpts).
2. Assign severity based on attack surface expansion potential and ease of exploitation by adversaries with basic tooling.
3. Map findings to MITRE ATT&CK Tactic TA0001 (Initial Access) and TA0003 (Persistence) techniques enabled by misconfigured rules.
4. Provide rule-level remediation recommendations specifying exact policy statements to modify, add, or remove.
5. Deliver a consolidated firewall security posture report suitable for both technical remediation teams and executive briefing.

**Skill Reference**: `skills/reporting/scripts/report_assembler.py`, `templates/master_report.md`, `references/framework_mappings.md`
