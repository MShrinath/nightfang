# Authorized Social Engineering Assessment Workflow

**Workflow ID**: `social-engineering`  
**Description**: Authorized human-factor resilience and security awareness testing workflow conducted under strict Rules of Engagement.  
**Required Agents**: `social-engineer`, `recon`, `opsec-anonymizer`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Phase 1 — Scope & ROE Boundary Verification (`SOP-01`)**:
   - Verify explicit written authorization and target employee exclusion lists (no executives, medical personnel, or safety-critical operators).
2. **Phase 2 — Open Source Intelligence & Persona Modeling (`recon`)**:
   - Collect authorized organizational structure information, communication formats, and public business profiles.
3. **Phase 3 — Pretext Design & Lure Formulation (`social-engineer`)**:
   - Develop context-specific, non-coercive awareness scenarios (e.g., IT self-service portal, benefits notification).
4. **Phase 4 — Human-in-the-Loop Operator Gate (`SOP-04`)**:
   - Present final simulation templates and dispatch schedules to engagement stakeholders.
   - Halt until explicit `/go` confirmation token is granted.
5. **Phase 5 — Controlled Simulation Dispatch (`social-engineer`, `opsec-anonymizer`)**:
   - Transmit authorized test messages via designated assessment infrastructure.
   - Track delivery telemetry, open rates, and click metrics.
6. **Phase 6 — Real-Time Telemetry & Metric Collection (`social-engineer`)**:
   - Record simulation engagement metrics (clicks, credential submissions, report-button clicks).
   - Immediately discard and zero-out any user passwords entered on test landing pages.
7. **Phase 7 — Debrief & Awareness Reporting (`reporter`)**:
   - Compile human-risk metric reports, identifying training opportunities and organizational resilience recommendations without punitive individual naming.
