#!/usr/bin/env python3
"""Shared payload lookup helper for nightfang agents.

Usage:
    from scripts.agent_payloads import AgentPayloadResolver
    resolver = AgentPayloadResolver()
    payloads = resolver.get_by_cwe("CWE-89")
    sql_files = resolver.get_by_class("SQL Injection")
"""
import json
import os
from typing import List, Dict, Any, Optional

INDEX_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "references", "payloads", "index.json"
)
# Reference payload repo path (relative to repository root; override via env)
REF_PATH = os.environ.get(
    "NIGHTFANG_PAYLOADS_REF",
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "..", "refs", "payloadsallthethings"
    )
)


class AgentPayloadResolver:
    """Agent-facing payload resolver using the ingested PayloadsAllTheThings catalog."""

    def __init__(self):
        self._catalog = None

    def _load(self) -> Dict[str, Any]:
        if self._catalog is None:
            with open(INDEX_PATH, encoding="utf-8") as f:
                self._catalog = json.load(f)
        return self._catalog

    def list_classes(self) -> List[Dict[str, Any]]:
        """Return all vulnerability classes with metadata."""
        cat = self._load()
        return [
            {
                "class": name,
                "cwe": meta["cwe"],
                "owasp": meta["owasp"],
                "safe_default": meta["safe_default"],
                "payload_count": len(meta["payload_files"]),
            }
            for name, meta in sorted(cat.items())
        ]

    def get_by_class(self, vuln_class: str) -> Optional[Dict[str, Any]]:
        """Get payload info by exact vulnerability class name."""
        cat = self._load()
        for name, meta in cat.items():
            if name.lower() == vuln_class.lower():
                return {
                    "class": name,
                    "cwe": meta["cwe"],
                    "owasp": meta["owasp"],
                    "safe_default": meta["safe_default"],
                    "payload_files": [f"{REF_PATH}/{f}" for f in meta["payload_files"]],
                }
        return None

    def get_by_cwe(self, cwe: str) -> List[Dict[str, Any]]:
        """Get all classes matching a CWE identifier."""
        cat = self._load()
        matches = []
        for name, meta in cat.items():
            if meta["cwe"].lower() == cwe.lower():
                matches.append({
                    "class": name,
                    "cwe": meta["cwe"],
                    "owasp": meta["owasp"],
                    "safe_default": meta["safe_default"],
                    "payload_files": [f"{REF_PATH}/{f}" for f in meta["payload_files"]],
                })
        return matches

    def get_by_owasp(self, owasp: str) -> List[Dict[str, Any]]:
        """Get all classes matching an OWASP category."""
        cat = self._load()
        matches = []
        for name, meta in cat.items():
            if meta["owasp"].lower() == owasp.lower():
                matches.append({
                    "class": name,
                    "cwe": meta["cwe"],
                    "owasp": meta["owasp"],
                    "safe_default": meta["safe_default"],
                    "payload_files": [f"{REF_PATH}/{f}" for f in meta["payload_files"]],
                })
        return matches

    def get_safe_payloads(self, vuln_class: str) -> List[str]:
        """Return only safe/non-destructive payload file paths for a class."""
        info = self.get_by_class(vuln_class)
        if not info or not info["safe_default"]:
            return []
        return info["payload_files"]

    def get_destructive_payloads(self, vuln_class: str) -> List[str]:
        """Return destructive payload file paths for a class (requires HITL approval)."""
        info = self.get_by_class(vuln_class)
        if not info or info["safe_default"]:
            return []
        return info["payload_files"]


if __name__ == "__main__":
    # Quick smoke test
    r = AgentPayloadResolver()
    print("Classes:", len(r.list_classes()))
    print("CWE-943 (injection-related):", r.get_by_cwe("CWE-943"))
    print("A03:2021:", r.get_by_owasp("A03:2021"))
    print("JWT Manipulation:", r.get_by_class("JWT Manipulation"))