#!/usr/bin/env python3
"""
NIGHTFANG Finding Schema Validator (Executable Implementation)
Reference Specification: schemas/finding.md

Validates security findings against NIGHTFANG's standardized schema:
1. Top-Level Mandatory Fields (id, title, target, category, timestamp, etc.)
2. Dual Ranking System (Confidence 1-10, Severity 1-10 with matching level string)
3. Evidence Grounding Index (0.55-0.95 with matching bucket string)
4. The 7-Question Adversarial Validation Gate (Q1-Q7 + verdict)
5. CVSS v3.1 / v4.0 vector string regex parsing and base score ranges
6. MITRE ATT&CK (TXXXX[.XXX]) and MITRE ATLAS (AML.TXXXX) IDs
7. MITRE D3FEND (D3-XXX) defensive countermeasure IDs
8. Cryptographic provenance hashes (SHA-256 64-char lowercase hex)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None


# ============================================================================
# Regex Patterns
# ============================================================================

SHA256_REGEX = re.compile(r"^[a-f0-9]{64}$")
MITRE_ATTACK_REGEX = re.compile(r"^T\d{4}(?:\.\d{3})?$")
MITRE_ATLAS_REGEX = re.compile(r"^AML\.T\d{4}(?:\.\d{3})?$")
MITRE_D3FEND_REGEX = re.compile(r"^D3-[A-Z0-9]+$")
CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_REGEX = re.compile(r"^CWE-\d+$")

CVSS_V31_REGEX = re.compile(
    r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
    r"(?:/E:[XUPFH]|/RL:[XOTWU]|/RC:[XURC]|/CR:[XLMH]|/IR:[XLMH]|/AR:[XLMH]|/MAV:[XNALP]|/MAC:[XLH]|/MPR:[XNLH]|/MUI:[XNR]|/MS:[XUC]|/MC:[XNLH]|/MI:[XNLH]|/MA:[XNLH])*$"
)

CVSS_V40_REGEX = re.compile(
    r"^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[NLH]/VI:[NLH]/VA:[NLH]/SC:[NLH]/SI:[NLH]/SA:[NLH].*$"
)

VALID_SEVERITY_LEVELS = {
    (1, 2): "informational",
    (3, 4): "low",
    (5, 6): "medium",
    (7, 8): "high",
    (9, 10): "critical",
}

VALID_GROUNDING_BUCKETS = {
    0.95: "CERTAIN",
    0.85: "STRONG",
    0.75: "PROBABLE",
    0.65: "TENTATIVE",
    0.55: "WEAK",
}

VALID_GATE_STATUSES = {"PASS", "KILL", "DOWNGRADE", "CHAIN_REQUIRED"}
VALID_DEFAULT_VS_CUSTOM = {"DEFAULT", "CUSTOM", "NON_STANDARD_DEP"}
VALID_FAILED_GATES = {"Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7"}
VALID_EVIDENCE_TYPES = {
    "http_request",
    "http_response",
    "command_output",
    "screenshot",
    "log",
    "prompt_transcript",
}
VALID_DETECTION_STATUSES = {"none", "telemetry", "detection", "prevention"}


# ============================================================================
# Validation Report Data Model
# ============================================================================

@dataclass
class ValidationReport:
    finding_id: str
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def print_summary(self) -> None:
        prefix = "PASS" if self.is_valid else "FAIL"
        print(f"[{prefix}] Finding: {self.finding_id or 'UNKNOWN'}")
        for err in self.errors:
            print(f"    - ERROR: {err}")
        for warn in self.warnings:
            print(f"    - WARNING: {warn}")


# ============================================================================
# Validator Class
# ============================================================================

class FindingValidator:
    """Validates finding dictionaries against schemas/finding.md."""

    def validate(self, finding_data: Dict[str, Any]) -> ValidationReport:
        # Unwrap nested 'finding' root key if present
        if "finding" in finding_data and isinstance(finding_data["finding"], dict):
            finding = finding_data["finding"]
        else:
            finding = finding_data

        finding_id = str(finding.get("id", ""))
        report = ValidationReport(finding_id=finding_id, is_valid=True)

        self._validate_core_metadata(finding, report)
        self._validate_dual_ranking(finding, report)
        self._validate_evidence_grounding(finding, report)
        self._validate_evidence_and_reproduction(finding, report)
        self._validate_validation_gate(finding, report)
        self._validate_classifications(finding, report)
        self._validate_remediation(finding, report)
        self._validate_telemetry_and_detection(finding, report)

        return report

    def _validate_core_metadata(self, f: Dict[str, Any], r: ValidationReport) -> None:
        required_fields = ["id", "title", "target", "category", "timestamp", "tool_used"]
        for field_name in required_fields:
            val = f.get(field_name)
            if not val or not str(val).strip():
                r.add_error(f"Missing mandatory core metadata field: '{field_name}'")

        # Validate timestamp format (ISO-8601)
        ts = f.get("timestamp")
        if ts:
            try:
                # Basic check for ISO-8601 compatibility
                datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except ValueError:
                r.add_warning(f"Timestamp '{ts}' does not strictly parse as ISO-8601 format.")

        # Optional CVE format
        cve = f.get("cve")
        if cve and not CVE_REGEX.match(cve):
            r.add_warning(f"CVE '{cve}' does not match standard pattern CVE-YYYY-NNNN+")

    def _validate_dual_ranking(self, f: Dict[str, Any], r: ValidationReport) -> None:
        # 1. Confidence Score (1-10)
        conf = f.get("confidence")
        if not isinstance(conf, dict):
            r.add_error("Missing 'confidence' dictionary.")
        else:
            score = conf.get("score")
            if score is None or not isinstance(score, int) or score < 1 or score > 10:
                r.add_error(f"Confidence score must be an integer between 1 and 10, got: {score}")
            if not conf.get("rationale"):
                r.add_warning("Missing 'confidence.rationale'.")

        # 2. Severity Score (1-10) & Level
        sev = f.get("severity")
        if not isinstance(sev, dict):
            r.add_error("Missing 'severity' dictionary.")
        else:
            score = sev.get("score")
            level = str(sev.get("level", "")).lower()

            if score is None or not isinstance(score, int) or score < 1 or score > 10:
                r.add_error(f"Severity score must be an integer between 1 and 10, got: {score}")
            else:
                expected_level = None
                for (low, high), lvl in VALID_SEVERITY_LEVELS.items():
                    if low <= score <= high:
                        expected_level = lvl
                        break
                if level != expected_level:
                    r.add_error(
                        f"Severity level mismatch: score {score} requires level '{expected_level}', got '{level}'."
                    )

            if not sev.get("rationale"):
                r.add_warning("Missing 'severity.rationale'.")

    def _validate_evidence_grounding(self, f: Dict[str, Any], r: ValidationReport) -> None:
        eg = f.get("evidence_grounding")
        if not isinstance(eg, dict):
            r.add_error("Missing 'evidence_grounding' dictionary.")
            return

        score = eg.get("score")
        bucket = eg.get("bucket")

        if score is None or not isinstance(score, (int, float)):
            r.add_error("Missing numeric 'evidence_grounding.score'.")
        else:
            score_float = round(float(score), 2)
            if score_float not in VALID_GROUNDING_BUCKETS:
                r.add_error(
                    f"Evidence grounding score must be one of {list(VALID_GROUNDING_BUCKETS.keys())}, got: {score_float}"
                )
            else:
                expected_bucket = VALID_GROUNDING_BUCKETS[score_float]
                if bucket != expected_bucket:
                    r.add_error(
                        f"Evidence grounding bucket mismatch: score {score_float} requires bucket '{expected_bucket}', got '{bucket}'."
                    )

    def _validate_evidence_and_reproduction(self, f: Dict[str, Any], r: ValidationReport) -> None:
        evidence = f.get("evidence")
        if not evidence or not isinstance(evidence, list):
            r.add_error("Finding must include at least one item in 'evidence' list.")
        else:
            for i, ev in enumerate(evidence):
                if not isinstance(ev, dict):
                    r.add_error(f"Evidence item #{i+1} must be an object.")
                    continue
                ev_type = ev.get("type")
                if not ev_type:
                    r.add_error(f"Evidence item #{i+1} missing 'type'.")
                elif ev_type not in VALID_EVIDENCE_TYPES:
                    r.add_error(
                        f"Evidence item #{i+1} invalid type '{ev_type}'. Must be one of {sorted(list(VALID_EVIDENCE_TYPES))}."
                    )
                if not ev.get("data"):
                    r.add_error(f"Evidence item #{i+1} missing 'data'.")

        repro = f.get("reproduction")
        if not repro or not isinstance(repro, list):
            r.add_error("Finding must include reproduction steps in 'reproduction' list.")

    def _validate_validation_gate(self, f: Dict[str, Any], r: ValidationReport) -> None:
        gate = f.get("validation_gate")
        if not isinstance(gate, dict):
            r.add_error("Missing mandatory 'validation_gate' dictionary (SOP-04).")
            return

        status = gate.get("status")
        if status not in VALID_GATE_STATUSES:
            r.add_error(f"validation_gate.status must be one of {VALID_GATE_STATUSES}, got: '{status}'")

        if not gate.get("evaluator"):
            r.add_error("validation_gate missing 'evaluator'.")

        # Provenance hash check
        prov_hash = gate.get("provenance_hash")
        if not prov_hash or not SHA256_REGEX.match(str(prov_hash).lower()):
            r.add_error(f"validation_gate.provenance_hash must be a 64-char hex SHA-256 digest, got: '{prov_hash}'")

        # 7 Adversarial Questions
        for q_key in ["q1_in_scope", "q3_reachable", "q4_controllable", "q5_impactful", "q7_severity_honest"]:
            q_val = gate.get(q_key)
            if not isinstance(q_val, dict) or "result" not in q_val:
                r.add_error(f"validation_gate missing '{q_key}.result' boolean.")
            elif not isinstance(q_val["result"], bool):
                r.add_error(f"validation_gate.{q_key}.result must be a boolean.")

        # Q2 Grounded requires evidence_ref
        q2 = gate.get("q2_grounded")
        if not isinstance(q2, dict) or "result" not in q2:
            r.add_error("validation_gate missing 'q2_grounded.result'.")
        elif not isinstance(q2["result"], bool):
            r.add_error("validation_gate.q2_grounded.result must be a boolean.")
        elif not q2.get("evidence_ref"):
            r.add_error("validation_gate.q2_grounded missing 'evidence_ref' (e.g. 'EVD-042').")

        # Q6 Default vs Custom
        q6 = gate.get("q6_default_vs_custom")
        if not isinstance(q6, dict) or "result" not in q6:
            r.add_error("validation_gate missing 'q6_default_vs_custom.result'.")
        elif q6["result"] not in VALID_DEFAULT_VS_CUSTOM:
            r.add_error(f"validation_gate.q6_default_vs_custom.result must be one of {VALID_DEFAULT_VS_CUSTOM}, got: '{q6.get('result')}'")

        # Verdict
        verdict = gate.get("verdict")
        if not isinstance(verdict, dict):
            r.add_error("validation_gate missing 'verdict' object.")
        else:
            v_status = verdict.get("status")
            if v_status not in VALID_GATE_STATUSES:
                r.add_error(f"validation_gate.verdict.status must be one of {VALID_GATE_STATUSES}, got: '{v_status}'")
            if not verdict.get("reason"):
                r.add_error("validation_gate.verdict missing 'reason'.")

            failed_gate = verdict.get("failed_gate")
            if v_status == "PASS":
                if failed_gate is not None:
                    r.add_error(f"validation_gate.verdict.failed_gate must be null when status is PASS, got: '{failed_gate}'")
                # Cross-check 6 boolean gates: all must be True for PASS
                for q_k, q_label in [
                    ("q1_in_scope", "Q1"),
                    ("q2_grounded", "Q2"),
                    ("q3_reachable", "Q3"),
                    ("q4_controllable", "Q4"),
                    ("q5_impactful", "Q5"),
                    ("q7_severity_honest", "Q7"),
                ]:
                    q_data = gate.get(q_k)
                    if isinstance(q_data, dict) and q_data.get("result") is False:
                        r.add_error(f"validation_gate.verdict cannot be PASS when {q_label} ({q_k}) result is False.")
            elif v_status in {"KILL", "DOWNGRADE", "CHAIN_REQUIRED"}:
                if not failed_gate or failed_gate not in VALID_FAILED_GATES:
                    r.add_error(f"validation_gate.verdict.failed_gate must be one of {VALID_FAILED_GATES} when verdict is '{v_status}', got: '{failed_gate}'")

    def _validate_classifications(self, f: Dict[str, Any], r: ValidationReport) -> None:
        cls = f.get("classifications")
        if not isinstance(cls, dict):
            r.add_error("Missing 'classifications' dictionary.")
            return

        # CVSS v3.1
        if "cvss_v31" in cls and isinstance(cls["cvss_v31"], dict):
            v31 = cls["cvss_v31"]
            vec = v31.get("vector")
            if not vec or not CVSS_V31_REGEX.match(vec):
                r.add_error(f"Invalid CVSS v3.1 vector string: '{vec}'")
            score = v31.get("base_score")
            if score is None or not (0.0 <= float(score) <= 10.0):
                r.add_error(f"CVSS v3.1 base_score must be between 0.0 and 10.0, got: {score}")

        # CVSS v4.0
        if "cvss_v40" in cls and isinstance(cls["cvss_v40"], dict):
            v40 = cls["cvss_v40"]
            vec = v40.get("vector")
            if not vec or not CVSS_V40_REGEX.match(vec):
                r.add_error(f"Invalid CVSS v4.0 vector string: '{vec}'")
            score = v40.get("base_score")
            if score is None or not (0.0 <= float(score) <= 10.0):
                r.add_error(f"CVSS v4.0 base_score must be between 0.0 and 10.0, got: {score}")

        # EPSS
        if "epss" in cls and isinstance(cls["epss"], dict):
            epss = cls["epss"]
            epss_score = epss.get("score")
            if epss_score is None or not (0.0 <= float(epss_score) <= 1.0):
                r.add_error(f"EPSS score must be a probability between 0.0 and 1.0, got: {epss_score}")
            epss_pct = epss.get("percentile")
            if epss_pct is None or not (0.0 <= float(epss_pct) <= 100.0):
                r.add_error(f"EPSS percentile must be a percentage between 0.0 and 100.0, got: {epss_pct}")

        # CISA KEV
        if "cisa_kev" in cls:
            if not isinstance(cls["cisa_kev"], bool):
                r.add_error(f"cisa_kev must be a boolean, got: {cls['cisa_kev']}")

        # MITRE ATT&CK
        if "mitre_attack" in cls and isinstance(cls["mitre_attack"], list):
            for i, tech in enumerate(cls["mitre_attack"]):
                t_id = tech.get("id") if isinstance(tech, dict) else str(tech)
                if not t_id or not MITRE_ATTACK_REGEX.match(t_id):
                    r.add_error(f"Invalid MITRE ATT&CK technique ID #{i+1}: '{t_id}' (expected TXXXX or TXXXX.XXX)")

        # MITRE ATLAS
        if "mitre_atlas" in cls and isinstance(cls["mitre_atlas"], list):
            for i, tech in enumerate(cls["mitre_atlas"]):
                t_id = tech.get("id") if isinstance(tech, dict) else str(tech)
                if not t_id or not MITRE_ATLAS_REGEX.match(t_id):
                    r.add_error(f"Invalid MITRE ATLAS technique ID #{i+1}: '{t_id}' (expected AML.TXXXX)")

        # CWE
        if "cwe" in cls and isinstance(cls["cwe"], list):
            for i, cwe_item in enumerate(cls["cwe"]):
                c_id = cwe_item.get("id") if isinstance(cwe_item, dict) else str(cwe_item)
                if not c_id or not CWE_REGEX.match(c_id):
                    r.add_warning(f"CWE ID #{i+1} '{c_id}' does not match CWE-NNN format.")

        # OWASP
        if "owasp" in cls and isinstance(cls["owasp"], list):
            for i, owasp_item in enumerate(cls["owasp"]):
                if isinstance(owasp_item, dict):
                    o_id = owasp_item.get("id")
                    if not o_id or not str(o_id).strip():
                        r.add_error(f"OWASP classification #{i+1} missing 'id'.")
                elif not str(owasp_item).strip():
                    r.add_error(f"OWASP classification #{i+1} empty.")

    def _validate_remediation(self, f: Dict[str, Any], r: ValidationReport) -> None:
        rem = f.get("remediation")
        if not isinstance(rem, dict):
            r.add_error("Missing 'remediation' dictionary.")
            return

        if not rem.get("guidance"):
            r.add_error("Remediation must contain actionable 'guidance'.")

        # MITRE D3FEND
        d3fend = rem.get("mitre_d3fend")
        if d3fend and isinstance(d3fend, list):
            for i, d in enumerate(d3fend):
                d_id = d.get("id") if isinstance(d, dict) else str(d)
                if not d_id or not MITRE_D3FEND_REGEX.match(d_id):
                    r.add_error(f"Invalid MITRE D3FEND ID #{i+1}: '{d_id}' (expected D3-XXX)")

    def _validate_telemetry_and_detection(self, f: Dict[str, Any], r: ValidationReport) -> None:
        det_status = f.get("detection_status")
        if det_status and det_status not in VALID_DETECTION_STATUSES:
            r.add_error(f"detection_status must be one of {VALID_DETECTION_STATUSES}, got: '{det_status}'")


# ============================================================================
# CLI and Test Runner
# ============================================================================

def load_finding_file(filepath: str) -> Dict[str, Any]:
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Try JSON
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Try YAML
    if yaml is not None:
        return yaml.safe_load(content)

    raise ValueError(f"Could not parse file {filepath} (PyYAML is required for YAML parsing).")


def run_self_tests() -> bool:
    """Run validator against reference example from schemas/finding.md."""
    print("Running NIGHTFANG Finding Validator Self-Tests...")

    valid_example = {
        "finding": {
            "id": "NF-2026-0042",
            "title": "Unauthenticated Remote Code Execution via Path Traversal",
            "target": "https://target-app.internal/api/v1/export",
            "category": "web_api_rce",
            "timestamp": "2026-09-22T21:40:00Z",
            "tool_used": "curl",
            "confidence": {
                "score": 8,
                "rationale": "Arbitrary file read confirmed non-destructively."
            },
            "severity": {
                "score": 10,
                "level": "critical",
                "rationale": "Allows unauthenticated attackers to execute commands."
            },
            "evidence_grounding": {
                "score": 0.95,
                "bucket": "CERTAIN",
                "rationale": "Complete raw HTTP request and response captured."
            },
            "evidence": [
                {
                    "type": "http_request",
                    "description": "Trigger traversal",
                    "data": "POST /api/v1/export"
                }
            ],
            "reproduction": [
                {
                    "step": 1,
                    "action": "Send payload",
                    "command": "curl -s -X POST https://target-app.internal/api/v1/export"
                }
            ],
            "impact": {
                "technical": "Remote Code Execution",
                "business": "Complete server compromise"
            },
            "remediation": {
                "guidance": "Enforce strict basename validation against allowlist.",
                "mitre_d3fend": [
                    {"id": "D3-UVI", "name": "User Input Validation"}
                ]
            },
            "validation_gate": {
                "status": "PASS",
                "evaluator": "agents/validation.md",
                "timestamp": "2026-09-22T21:45:00Z",
                "provenance_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "q1_in_scope": {"result": True, "notes": "In scope"},
                "q2_grounded": {"result": True, "evidence_ref": "EVD-0042", "notes": "Verified"},
                "q3_reachable": {"result": True, "notes": "Reached sink"},
                "q4_controllable": {"result": True, "notes": "Direct control"},
                "q5_impactful": {"result": True, "notes": "Critical impact"},
                "q6_default_vs_custom": {"result": "DEFAULT", "notes": "Default deploy"},
                "q7_severity_honest": {"result": True, "notes": "Realistic CVSS"},
                "verdict": {
                    "status": "PASS",
                    "failed_gate": None,
                    "reason": "All 7 gates satisfied"
                }
            },
            "detection_status": "detection",
            "validated_by_blue_skill": "skills/remediation/detection-engineering.md",
            "classifications": {
                "cvss_v31": {
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "base_score": 10.0
                },
                "cvss_v40": {
                    "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                    "base_score": 10.0
                },
                "epss": {
                    "score": 0.94231,
                    "percentile": 98.4
                },
                "cisa_kev": True,
                "mitre_attack": [
                    {"id": "T1190", "name": "Exploit Public-Facing Application"}
                ],
                "owasp": [
                    {"id": "A01:2021", "name": "Broken Access Control"}
                ]
            }
        }
    }

    validator = FindingValidator()
    report = validator.validate(valid_example)
    assert report.is_valid, f"Expected valid finding, got errors: {report.errors}"
    print("  [PASS] Test 1: Full valid reference finding passed validation.")

    # Test 2: Injected validation errors
    invalid_example = {
        "finding": {
            "id": "NF-2026-INVALID",
            "title": "Broken finding",
            "target": "target.internal",
            "category": "web",
            "timestamp": "2026-09-22T00:00:00Z",
            "tool_used": "nmap",
            "detection_status": "INVALID_DET_STATUS",
            "confidence": {"score": 15},  # Invalid: score > 10
            "severity": {"score": 10, "level": "medium"},  # Invalid: 10 must be 'critical'
            "evidence_grounding": {"score": 0.95, "bucket": "WEAK"},  # Invalid: 0.95 must be CERTAIN
            "evidence": [
                {"type": "INVALID_TYPE", "data": "bad type"}
            ],
            "reproduction": [],
            "impact": {},
            "remediation": {},
            "validation_gate": {
                "status": "INVALID_STATUS",
                "provenance_hash": "not_a_sha256",
                "q1_in_scope": {"result": False},
                "verdict": {
                    "status": "PASS",
                    "reason": "impossible pass"
                }
            },
            "classifications": {
                "cvss_v31": {"vector": "INVALID_CVSS", "base_score": 15.0},
                "epss": {"score": 9.9, "percentile": 200.0},
                "cisa_kev": "maybe",
                "mitre_attack": [{"id": "INVALID_ATTACK_ID"}],
                "owasp": [{"name": "Missing ID"}],
            }
        }
    }
    report_bad = validator.validate(invalid_example)
    assert not report_bad.is_valid
    assert len(report_bad.errors) >= 12, f"Expected at least 12 errors, got {len(report_bad.errors)}: {report_bad.errors}"
    print(f"  [PASS] Test 2: Successfully caught {len(report_bad.errors)} schema violations in malformed finding.")

    print("\nAll Validator self-tests PASSED successfully!")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="NIGHTFANG Finding Schema Validator")
    parser.add_argument("file", nargs="?", help="Path to finding YAML or JSON file")
    parser.add_argument("--test", action="store_true", help="Run self-tests")
    args = parser.parse_args()

    if args.test or not args.file:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    validator = FindingValidator()
    try:
        data = load_finding_file(args.file)
        report = validator.validate(data)
        report.print_summary()
        sys.exit(0 if report.is_valid else 1)
    except Exception as e:
        print(f"Fatal validation error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
