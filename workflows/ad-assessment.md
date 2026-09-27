# Active Directory Security Assessment Workflow

**Workflow ID**: `ad-assessment`  
**Description**: Comprehensive security assessment of Active Directory forest architecture, Kerberos authentication, Certificate Services (ADCS), and domain privilege escalation paths.  
**Required Agents**: `ad-attacker`, `privesc-advisor`, `validation`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Intake & Scope Governance**: Parse domain FQDN, Domain Controller IPs, authorized testing credentials, and lockout threshold constraints per SOP-01.
2. **Domain Reconnaissance (`ad-attacker`)**:
   - Enumerate DC endpoints, domain trusts, organizational units, and user/group memberships.
   - Run BloodHound ingestion to map identity relationships and shortest paths to Domain Admin.
3. **Authentication & Protocol Auditing (`ad-attacker`)**:
   - Test for ASREProasting on accounts with pre-authentication disabled (`DONT_REQ_PREAUTH`).
   - Query Service Principal Names (SPNs) for Kerberoastable service accounts.
   - Audit unconstrained and resource-based constrained delegation (RBCD).
4. **Certificate Services (ADCS) Audit (`ad-attacker`)**:
   - Enumerate published certificate templates with Certipy.
   - Evaluate template misconfigurations (ESC1, ESC2, ESC3, ESC4, ESC8 NTLM relaying).
5. **Operator Approval Gate (HITL)**: Request operator approval before attempting any active ticket acquisition, certificate enrollment, or password hash testing per SOP-04.
6. **Controlled PoC Validation (`validation`)**: Verify privilege escalation hypotheses with non-destructive queries; capture evidence hashes per SOP-06.
7. **Remediation & Final Report (`reporter`)**: Generate Active Directory hardening roadmap, Tier 0 asset isolation guide, and executive deliverables.
