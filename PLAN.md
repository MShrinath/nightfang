# NIGHTFANG — Development Plan

**Goal:** Evolve `nightfang` into the ultimate AI-automation soul for agent-driven cybersecurity VAPT
(penetration testing / vulnerability assessment / purple-teaming) on the Hermes runtime.

**Git discipline:** Every meaningful change is committed with a descriptive message.
Baseline = the cloned repo as-is (commit `b0dd317`). All work branches off `main`.

**Reference repos (cloned as siblings, NOT merged into nightfang yet):**
- `../refs/PentestingEverything` (m14r41) — structured pentest methodology library by domain
  (Web, API, AD, Cloud, Container, CI/CD, Mobile, IoT, OSINT, LLM, MCP, Threat Modeling, ...)
- `../refs/payloadsallthethings` (swisskyrepo) — 66 vulnerability-class payload catalogs
  (SQLi, SSTI, SSRF, XSS, XXE, Race, deserialization, GraphQL, JWT, ...)

---

## Phase 0 — Baseline (DONE)
- Cloned `nightfang` → project root
- Cloned both reference repos → sibling `refs/` directory
- Git identity set: `koush` <koushikreddybh@gmail.com>
- Initial commit marking the baseline.

## Phase 1 — Methodology Ingestion (PentestingEverything)
Pull domain cheat-sheets into nightfang as *procedural knowledge* so agents can execute
real-world methodology, not just tool names.
- Map each `refs/PentestingEverything/<Domain>/` into a corresponding nightfang skill:
  Web → `skills/web`, API → `skills/api`, AD → `skills/active-directory`,
  Cloud → `skills/cloud`, Container → `skills/container`, CI/CD → `skills/cicd`,
  Mobile → `skills/mobile`, IoT → `skills/iot`, OSINT → `skills/recon`,
  LLM → `skills/ai-security`, MCP → `skills/ai-security`,
  Threat Modeling → `agents/threat-modeler`, Secure Code Review → `agents/code-auditor`.
- Add a `references/methodology/` tree summarizing each domain's checklist.
- Commit per domain (e.g. `feat(web): ingest web-application methodology`).

## Phase 2 — Payload Library (payloadsallthethings)
Build a searchable, CWE/OWASP-indexed payload catalog that agents can draw from
at runtime (non-destructive PoC payloads only — SOP-05 enforced by gateway).
- Create `references/payloads/` with an index (`index.json`) mapping
  vuln-class → CWE → OWASP → payload file(s) → safe-by-default flag.
- Ingest the 66 vulnerability categories; prioritize web/api/infra classes first.
- Add a `skills/utility` script `payload_lookup.py` for agent-side retrieval.
- Commit: `feat(payloads): ingest payload catalog + index`.

## Phase 3 — Runtime Hardening (tools/)
Make the execution core genuinely usable and testable.
- `tools/gateway.py` — expand scope/OPSEC/rate/HITL/destructive-filter tests to a real
  pytest suite (`tests/test_gateway.py`), not just self-tests.
- `tools/daemon.py` — add a dry-run mode + persistent queue on disk (`memory/queue.json`).
- `tools/sandbox.py` — add command allowlist + timeout + output capture + artifact cleanup verification.
- `schemas/validator.py` — expand the 24-violation malformed-record corpus.
- Commit per component.

## Phase 4 — Capability Gaps
Add agents/skills the reference repos show are missing:
- `skills/osint` (already partly in recon — expand)
- `skills/phishing` / `agents/social-engineer` enhancements
- `skills/threat-modeling` procedures
- `skills/secure-code-review` (SAST) procedures
- Detection-engineering output templates (Sigma/SPL/KQL) per finding.

## Phase 5 — Reporting & SBOM
- `templates/` reporting engine: executive + full + per-finding walkthroughs,
  attack-chain visualization, D3FEND remediation roadmap.
- Supply-chain / SBOM agent enhancements (SPDX + CycloneDX).

## Phase 6 — Verification
- `nightfang.cmd --test` / `nightfang.sh test` should run the full pytest suite
  and report PASS/FAIL per subsystem.
- Final verification commit.

---

## Conventions
- Commits: `feat|fix|docs|test|refactor(<area>): <one-line summary>`
- Never commit the `refs/` sibling repos into nightfang; reference them by path in docs.
- All exploit payloads remain non-destructive by default; destructive variants gated behind
  the HITL approval token (SOP-04/SOP-05).