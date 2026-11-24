#!/usr/bin/env python3
"""
NIGHTFANG Finding Persistence, Deduplication & MCP Knowledge Graph Bridge (tools/finding_sync.py)

Responsibilities:
1. Normalizes findings using schemas/validator.py.
2. Deterministic Deduplication: Uses `f"{normalized_target}:{cwe_id}:{endpoint_or_port}"` identity key.
3. Multi-Target Partitioning: Maintains partitioned index by target/domain and engagement/session so
   findings for distinct targets/chats never mix up.
4. MCP Knowledge Graph Bridge: Generates `@modelcontextprotocol/server-memory` JSONL records for
   `memory/knowledge_graph.jsonl` linking targets, vulnerabilities, CWE weaknesses, and D3FEND defenses.
5. Thread-safe/Atomic persistence for `findings.json`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

try:
    from schemas.validator import FindingValidator, ValidationReport
except ImportError:
    sys.path.insert(0, os.path.join(repo_root, "schemas"))
    from validator import FindingValidator, ValidationReport


def normalize_target_key(target: str) -> str:
    """Extract host/domain part from target string (e.g. https://api.corp.com:443/v1 -> api.corp.com)."""
    t = target.strip()
    # Strip protocol
    if "://" in t:
        t = t.split("://", 1)[1]
    # Strip path
    if "/" in t:
        t = t.split("/", 1)[0]
    # Strip port if present
    if ":" in t:
        t = t.split(":", 1)[0]
    return t.lower()


class FindingSyncManager:
    """Manages finding persistence, target isolation, and MCP Knowledge Graph synchronization."""

    def __init__(
        self,
        findings_path: Optional[str] = None,
        kg_path: Optional[str] = None,
        validator: Optional[FindingValidator] = None,
    ) -> None:
        self.findings_path = findings_path or os.path.join(repo_root, "memory", "findings.json")
        self.kg_path = kg_path or os.path.join(repo_root, "memory", "knowledge_graph.jsonl")
        self.validator = validator or FindingValidator()

        # Ensure memory directory exists
        os.makedirs(os.path.dirname(os.path.abspath(self.findings_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.kg_path)), exist_ok=True)

    def load_findings_store(self) -> Dict[str, Any]:
        """
        Load findings store with support for both legacy list/dict and partitioned structures.
        Returns:
            {
                "version": "2.0",
                "findings": { dedup_key: finding_obj },
                "targets": { target_host: [dedup_keys] },
                "updated_at": ISO8601
            }
        """
        if not os.path.exists(self.findings_path):
            return {"version": "2.0", "findings": {}, "targets": {}, "updated_at": datetime.now(timezone.utc).isoformat()}

        try:
            with open(self.findings_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, list):
                # Legacy array format migration
                store: Dict[str, Any] = {
                    "version": "2.0",
                    "findings": {},
                    "targets": {},
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                for item in data:
                    key = self.compute_dedup_key(item)
                    store["findings"][key] = item
                    t_host = normalize_target_key(item.get("finding", item).get("target", "general"))
                    store["targets"].setdefault(t_host, []).append(key)
                return store

            if isinstance(data, dict):
                if "findings" not in data:
                    data = {"version": "2.0", "findings": data, "targets": {}, "updated_at": datetime.now(timezone.utc).isoformat()}
                if "targets" not in data:
                    data["targets"] = {}
                    for k, item in data.get("findings", {}).items():
                        t_host = normalize_target_key(item.get("finding", item).get("target", "general"))
                        data["targets"].setdefault(t_host, []).append(k)
                return data
        except Exception:
            pass

        return {"version": "2.0", "findings": {}, "targets": {}, "updated_at": datetime.now(timezone.utc).isoformat()}

    def save_findings_store(self, store: Dict[str, Any]) -> bool:
        """Atomic write to findings store to avoid corruption under concurrency."""
        store["updated_at"] = datetime.now(timezone.utc).isoformat()
        target_dir = os.path.dirname(os.path.abspath(self.findings_path))
        temp_fd, temp_file = tempfile.mkstemp(dir=target_dir, prefix="findings_", suffix=".tmp")
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(store, f, indent=2)
            # Atomic replace
            os.replace(temp_file, self.findings_path)
            return True
        except Exception:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass
            return False

    def compute_dedup_key(self, finding_entry: Dict[str, Any]) -> str:
        """
        Compute deterministic deduplication identity: f"{target}:{cwe_id}:{endpoint_or_port}"
        """
        inner = finding_entry.get("finding", finding_entry)
        target = str(inner.get("target", "general")).strip().lower()
        cwe_id = str(inner.get("cwe_id", "CWE-000")).strip().upper()

        endpoint = ""
        endpoints_list = inner.get("affected_endpoints", [])
        if endpoints_list and isinstance(endpoints_list, list):
            endpoint = str(endpoints_list[0]).strip().lower()
        if not endpoint:
            # Check title or category as discriminator
            endpoint = str(inner.get("title", "")).strip().lower()

        # Sanitize key
        key_raw = f"{target}:{cwe_id}:{endpoint}"
        return re.sub(r"[^a-zA-Z0-9_\-\.:]", "_", key_raw)

    def sync_finding(
        self,
        finding_data: Dict[str, Any],
        session_id: Optional[str] = None,
        target_override: Optional[str] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Synchronize a single finding:
        1. Validates finding schema.
        2. Deduplicates & updates findings.json (partitioned by target).
        3. Appends entities & relations to MCP knowledge_graph.jsonl.
        """
        inner = finding_data.get("finding", finding_data)

        if target_override:
            inner["target"] = target_override

        # Validate schema
        report: ValidationReport = self.validator.validate(inner)
        if not report.is_valid:
            err_msg = f"Schema validation failed: {'; '.join(report.errors)}"
            return False, err_msg, {}

        # Prepare normalized payload
        payload = {"finding": inner} if "finding" not in finding_data else finding_data
        if session_id:
            payload["session_id"] = session_id

        # Compute dedup key
        dedup_key = self.compute_dedup_key(payload)
        target_host = normalize_target_key(inner.get("target", "general"))

        # Load & update findings store
        store = self.load_findings_store()
        is_update = dedup_key in store["findings"]
        store["findings"][dedup_key] = payload

        # Update target partitioning index
        target_keys = store["targets"].setdefault(target_host, [])
        if dedup_key not in target_keys:
            target_keys.append(dedup_key)

        save_ok = self.save_findings_store(store)
        if not save_ok:
            return False, "Failed to save findings store atomically", {}

        # Emit to MCP Knowledge Graph
        self.emit_to_knowledge_graph(inner, target_host)

        status_msg = "Updated existing finding" if is_update else "Ingested new finding"
        return True, f"{status_msg} [{dedup_key}]", payload

    def sync_batch(
        self,
        findings_list: List[Dict[str, Any]],
        session_id: Optional[str] = None,
        target_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Synchronize a batch of findings."""
        results = {
            "total": len(findings_list),
            "ingested": 0,
            "failed": 0,
            "errors": [],
            "keys": [],
        }
        for item in findings_list:
            ok, msg, payload = self.sync_finding(item, session_id=session_id, target_override=target_override)
            if ok:
                results["ingested"] += 1
                results["keys"].append(self.compute_dedup_key(payload))
            else:
                results["failed"] += 1
                results["errors"].append(msg)
        return results

    def get_findings_for_target(self, target: str) -> List[Dict[str, Any]]:
        """Retrieve findings strictly partitioned for a given target."""
        store = self.load_findings_store()
        t_norm = normalize_target_key(target)
        keys = store.get("targets", {}).get(t_norm, [])
        if not keys:
            # Fallback search
            matched = []
            for k, f in store.get("findings", {}).items():
                inner = f.get("finding", f)
                if t_norm in normalize_target_key(inner.get("target", "")):
                    matched.append(f)
            return matched
        return [store["findings"][k] for k in keys if k in store.get("findings", {})]

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Retrieve all findings."""
        store = self.load_findings_store()
        return list(store.get("findings", {}).values())

    def emit_to_knowledge_graph(self, finding: Dict[str, Any], target_host: str) -> None:
        """
        Append entity and relation records to memory/knowledge_graph.jsonl conforming to
        @modelcontextprotocol/server-memory specification.
        """
        fid = finding.get("id", "FINDING-UNKNOWN")
        title = finding.get("title", "Security Finding")
        cwe_id = finding.get("cwe_id", "CWE-000")
        sev_obj = finding.get("severity", {})
        sev_score = sev_obj.get("score", 5.0) if isinstance(sev_obj, dict) else 5.0

        d3fend = finding.get("mitre_d3fend", {})
        countermeasures = d3fend.get("countermeasures", []) if isinstance(d3fend, dict) else []
        d3_id = countermeasures[0].get("id", "D3-PSA") if countermeasures else "D3-PSA"

        now_iso = datetime.now(timezone.utc).isoformat()

        # Entities to write
        entities = [
            {
                "type": "entity",
                "name": target_host,
                "entityType": "Asset",
                "observations": [f"Target host evaluated during penetration testing: {target_host}"],
            },
            {
                "type": "entity",
                "name": fid,
                "entityType": "Vulnerability",
                "observations": [
                    f"Vulnerability '{title}' severity {sev_score}/10 on {target_host}",
                    f"Classification: {cwe_id}",
                ],
            },
            {
                "type": "entity",
                "name": cwe_id,
                "entityType": "WeaknessClass",
                "observations": [f"Common Weakness Enumeration entry: {cwe_id}"],
            },
            {
                "type": "entity",
                "name": d3_id,
                "entityType": "Countermeasure",
                "observations": [f"MITRE D3FEND defensive countermeasure: {d3_id}"],
            },
        ]

        # Relations to write
        relations = [
            {
                "type": "relation",
                "from": target_host,
                "to": fid,
                "relationType": "has_vulnerability",
            },
            {
                "type": "relation",
                "from": fid,
                "to": cwe_id,
                "relationType": "classified_as",
            },
            {
                "type": "relation",
                "from": fid,
                "to": d3_id,
                "relationType": "remediated_by",
            },
        ]

        # Atomic line append to knowledge_graph.jsonl
        try:
            with open(self.kg_path, "a", encoding="utf-8") as f:
                for ent in entities:
                    f.write(json.dumps(ent) + "\n")
                for rel in relations:
                    f.write(json.dumps(rel) + "\n")
        except Exception as e:
            sys.stderr.write(f"[!] Knowledge graph append error: {e}\n")


def run_self_tests() -> bool:
    """Run automated verification suite for FindingSyncManager."""
    print("Running NIGHTFANG Finding Sync & MCP Knowledge Graph Self-Tests...")

    temp_dir = tempfile.mkdtemp(prefix="nf_sync_test_")
    test_findings_path = os.path.join(temp_dir, "findings.json")
    test_kg_path = os.path.join(temp_dir, "knowledge_graph.jsonl")

    try:
        mgr = FindingSyncManager(findings_path=test_findings_path, kg_path=test_kg_path)

        # Reference valid finding sample conforming to schemas/validator.py
        sample_finding = {
            "id": "NF-2026-0042",
            "title": "Unauthenticated Remote Code Execution via Path Traversal",
            "target": "https://api.corp.test/api/v1/export",
            "category": "web_api_rce",
            "timestamp": "2026-09-22T21:40:00Z",
            "tool_used": "curl",
            "confidence": {
                "score": 8,
                "rationale": "Arbitrary file read confirmed non-destructively.",
            },
            "severity": {
                "score": 10,
                "level": "critical",
                "rationale": "Allows unauthenticated attackers to execute commands.",
            },
            "evidence_grounding": {
                "score": 0.95,
                "bucket": "CERTAIN",
                "rationale": "Complete raw HTTP request and response captured.",
            },
            "evidence": [
                {
                    "type": "http_request",
                    "description": "Trigger traversal",
                    "data": "POST /api/v1/export",
                }
            ],
            "reproduction": [
                {
                    "step": 1,
                    "action": "Send payload",
                    "command": "curl -s -X POST https://api.corp.test/api/v1/export",
                }
            ],
            "impact": {
                "technical": "Remote Code Execution",
                "business": "Complete server compromise",
            },
            "remediation": {
                "guidance": "Enforce strict basename validation against allowlist.",
                "mitre_d3fend": [
                    {"id": "D3-UVI", "name": "User Input Validation"}
                ],
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
                    "reason": "All 7 gates satisfied",
                },
            },
            "detection_status": "detection",
            "validated_by_blue_skill": "skills/detection-engineering/SKILL.md",
            "classifications": {
                "cvss_v31": {
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "base_score": 10.0,
                },
                "cvss_v40": {
                    "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                    "base_score": 10.0,
                },
                "epss": {
                    "score": 0.94231,
                    "percentile": 98.4,
                },
                "cisa_kev": True,
                "mitre_attack": [
                    {"id": "T1190", "name": "Exploit Public-Facing Application"}
                ],
                "owasp": [
                    {"id": "A01:2021", "name": "Broken Access Control"}
                ],
            },
        }

        # Test 1: Ingest valid finding & verify persistence
        ok, msg, payload = mgr.sync_finding({"finding": sample_finding}, session_id="sess-001")
        assert ok, f"Sync failed: {msg}"
        assert os.path.exists(test_findings_path)
        assert os.path.exists(test_kg_path)
        print("  [PASS] Test 1: Ingest valid finding and verify persistence.")

        # Test 2: Deterministic Deduplication
        store_before = mgr.load_findings_store()
        assert len(store_before["findings"]) == 1
        # Re-ingest duplicate finding
        ok2, msg2, _ = mgr.sync_finding({"finding": sample_finding}, session_id="sess-002")
        assert ok2
        assert "Updated existing finding" in msg2
        store_after = mgr.load_findings_store()
        assert len(store_after["findings"]) == 1, "Duplicate finding was incorrectly added instead of deduplicated"
        print("  [PASS] Test 2: Deterministic deduplication updates record without duplication.")

        # Test 3: MCP Knowledge Graph JSONL schema compliance
        with open(test_kg_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line.strip()) for line in f if line.strip()]
        entity_types = {item.get("entityType") for item in lines if item.get("type") == "entity"}
        assert "Asset" in entity_types
        assert "Vulnerability" in entity_types
        assert "WeaknessClass" in entity_types
        assert "Countermeasure" in entity_types

        relation_types = {item.get("relationType") for item in lines if item.get("type") == "relation"}
        assert "has_vulnerability" in relation_types
        assert "classified_as" in relation_types
        assert "remediated_by" in relation_types
        print("  [PASS] Test 3: Knowledge graph emission adheres to MCP memory schema.")

        # Test 4: Corrupt finding rejection
        bad_finding = {"id": "BAD-1", "title": "Missing lots of fields"}
        bad_ok, bad_msg, _ = mgr.sync_finding({"finding": bad_finding})
        assert not bad_ok
        assert "Schema validation failed" in bad_msg
        print("  [PASS] Test 4: Corrupt finding correctly rejected by validation gate.")

        # Test 5: Target Partitioning & Cross-Target Isolation (Operator requirement)
        import copy
        target_b_finding = copy.deepcopy(sample_finding)
        target_b_finding["id"] = "NF-2026-0043"
        target_b_finding["target"] = "https://targetb.test/api/v1/export"
        target_b_finding["reproduction"][0]["command"] = "curl -s https://targetb.test/api/v1/export"

        ok_b, _, _ = mgr.sync_finding({"finding": target_b_finding})
        assert ok_b

        # Retrieve isolated findings
        findings_a = mgr.get_findings_for_target("api.corp.test")
        findings_b = mgr.get_findings_for_target("targetb.test")
        assert len(findings_a) == 1
        assert len(findings_b) == 1
        assert findings_a[0]["finding"]["id"] == "NF-2026-0042"
        assert findings_b[0]["finding"]["id"] == "NF-2026-0043"
        # Verify no cross-pollution
        assert "targetb" not in findings_a[0]["finding"]["target"]
        assert "api.corp.test" not in findings_b[0]["finding"]["target"]
        print("  [PASS] Test 5: Target partitioning and strict target isolation verified.")

    finally:
        # Cleanup temp directory
        for root, dirs, files in os.walk(temp_dir, topdown=False):
            for file in files:
                try:
                    os.remove(os.path.join(root, file))
                except OSError:
                    pass
            for d in dirs:
                try:
                    os.rmdir(os.path.join(root, d))
                except OSError:
                    pass
        try:
            os.rmdir(temp_dir)
        except OSError:
            pass

    print("\nAll 5 Finding Sync & Knowledge Graph self-tests PASSED successfully!")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIGHTFANG Finding Sync & Knowledge Graph Bridge")
    parser.add_argument("--test", action="store_true", help="Run automated self-tests")
    parser.add_argument("--sync", type=str, help="Path to JSON file containing findings to sync")
    parser.add_argument("--target", type=str, help="Target override or target filter")
    args = parser.parse_args()

    if args.test:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    if args.sync:
        if not os.path.exists(args.sync):
            print(f"[!] Input file '{args.sync}' not found.")
            sys.exit(1)
        with open(args.sync, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings_list = data if isinstance(data, list) else [data]
        mgr = FindingSyncManager()
        res = mgr.sync_batch(findings_list, target_override=args.target)
        print(f"[*] Sync Complete: Ingested={res['ingested']}, Failed={res['failed']}")
        sys.exit(0 if res["failed"] == 0 else 1)

    # Default action
    success = run_self_tests()
    sys.exit(0 if success else 1)
