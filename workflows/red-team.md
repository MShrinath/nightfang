# Full-Scope Red Team Adversary Simulation Workflow

**Workflow ID**: `red-team`  
**Description**: Multi-phase goal-oriented adversary emulation simulating full cyber kill-chain operations against authorized enterprise targets.  
**Required Agents**: `opsec-anonymizer`, `recon`, `scanner`, `payload-crafter`, `c2-operator`, `evasion-specialist`, `lateral-movement`, `privesc-advisor`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Phase 1 — Operational Setup & OPSEC Verification (`opsec-anonymizer`)**:
   - Verify proxychains, VPNs, redirectors, and egress IP isolation.
   - Confirm target scope boundaries and operational rules of engagement (`SOP-01`).
2. **Phase 2 — External Reconnaissance & Attack Surface Mapping (`recon`)**:
   - Passive OSINT, DNS infrastructure mapping, credential leak correlation, and public asset discovery.
3. **Phase 3 — Vulnerability Discovery & Weakness Identification (`scanner`)**:
   - Non-destructive enumeration of exposed perimeter web, API, and network entrypoints.
4. **Phase 4 — Benign Proof-of-Concept & Delivery Staging (`payload-crafter`, `evasion-specialist`)**:
   - Synthesize benign validation payloads and verify defensive evasion posture under strict HITL approval.
5. **Phase 5 — C2 Infrastructure Coordination & Post-Access Pivot (`c2-operator`)**:
   - Establish resilient, covert egress communication channels using authorized redirector infrastructure.
6. **Phase 6 — Host Privilege Escalation & Domain Expansion (`privesc-advisor`, `lateral-movement`)**:
   - Enumerate local privilege elevation paths, audit Kerberos delegations, and map trust boundaries.
7. **Phase 7 — Objective Demonstration & Canary Verification (`validation`)**:
   - Demonstrate simulated objective completion (e.g. proof of access to target test canary file) without disrupting production data.
8. **Phase 8 — Artifact Cleanup & Baseline Verification (`SOP-05`)**:
   - Purge all temporary test canaries, accounts, and test staging files. Verify clean status.
9. **Phase 9 — Reporting & Defensive Engineering (`reporter`, `detection-engineer`)**:
   - Compile comprehensive executive summary, attack chain graphs, and paired Sigma/KQL detection rules.
