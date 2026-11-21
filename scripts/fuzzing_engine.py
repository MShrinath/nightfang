#!/usr/bin/env python3
"""
NIGHTFANG Fuzzing Engine — Structured mutation fuzzer for protocols, web inputs, and binaries.
Supports stateful session fuzzing with crash triage and coverage feedback.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional, Any
import hashlib
import json


class MutationType(str, Enum):
    NULL_BYTE = "null_byte"
    OVERFLOW = "overflow"
    TYPE_COERCION = "type_coercion"
    ENCODING_BYPASS = "encoding_bypass"
    EMPTY_VALUE = "empty_value"
    BOOLEAN_FLIP = "boolean_flip"
    LENGTH_EXTEND = "length_extend"
    MAGIC_NUMBER = "magic_number"
    WHITESPACE_VARIATION = "whitespace_variation"
    DELIMITER_SWAPP = "delimiter_swap"


@dataclass
class FuzzTestCase:
    """Single fuzz test case."""
    input_data: str
    mutation_type: str
    expected_behavior: str
    actual_response: Optional[str] = None
    crash_detected: bool = False
    timing_delta: float = 0.0
    hash_signature: str = ""

    def __post_init__(self):
        if not self.hash_signature:
            self.hash_signature = hashlib.sha256(self.input_data.encode()).hexdigest()[:16]


class CoverageTracker:
    """Track input coverage for guided fuzzing."""
    def __init__(self):
        self.covered_inputs: set = set()
        self.total_mutations: int = 0
        self.crashes: List[Dict] = []

    def record_hit(self, input_hash: str) -> bool:
        new = input_hash not in self.covered_inputs
        self.covered_inputs.add(input_hash)
        return new

    def record_crash(self, case: FuzzTestCase, response_text: str):
        self.crashes.append({
            "hash": case.hash_signature,
            "input_preview": case.input_data[:200],
            "mutation_type": case.mutation_type,
            "response_excerpt": response_text[:500],
        })

    def stats(self) -> Dict:
        return {
            "coverage_pct": round(len(self.covered_inputs) / max(1, self.total_mutations) * 100, 1),
            "total_mutations": self.total_mutations,
            "new_coverage": len([h for h in self.covered_inputs]),
            "crashes_found": len(self.crashes),
        }


class FuzzingEngine:
    """Protocol-aware structured fuzzer with coverage tracking."""

    DEFAULT_MUTATIONS = [
        {"type": MutationType.NULL_BYTE, "data": "\x00"},
        {"type": MutationType.OVERFLOW, "data": "A" * 10000},
        {"type": MutationType.ENCODING_BYPASS, "data": "%25%25"},
        {"type": MutationType.EMPTY_VALUE, "data": ""},
        {"type": MutationType.WHITESPACE_VARIATION, "data": " \t\n\r"},
        {"type": MutationType.MAGIC_NUMBER, "data": "-1"},
        {"type": MutationType.TYPE_COERCION, "data": "true"},
        {"type": MutationType.LENGTH_EXTEND, "data": "X" * 500},
    ]

    PROTOCOL_PATTERNS = {
        "http_header": ["Host", "X-Forwarded-For", "Authorization", "Cookie"],
        "url_path": ["../", "/..%2f", "/.%2e", "//", "//../"],
        "json_body": ["{", "{null", '{"key":null}', '""'],
        "sql_input": ["'", "' OR '1'='1", "1; DROP TABLE", "admin'--"],
        "xml_input": ["<", "<![CDATA[", "<?xml", "</tag>"],
    }

    def __init__(self, target: str, fuzz_type: str = "generic"):
        self.target = target
        self.fuzz_type = fuzz_type
        self.tracker = CoverageTracker()
        self.test_cases: List[FuzzTestCase] = []

    def generate_test_cases(self, base_input: str, count: int = 20) -> List[FuzzTestCase]:
        """Generate mutation test cases from a base input value."""
        cases = []
        mutations = self.DEFAULT_MUTATIONS[:]
        # Add protocol-specific mutations
        if self.fuzz_type in self.PROTOCOL_PATTERNS:
            mutations.extend([
                {"type": MutationType.ENCODING_BYPASS, "data": p}
                for p in self.PROTOCOL_PATTERNS[self.fuzz_type][:4]
            ])
        for i in range(min(count, len(mutations))):
            m = mutations[i % len(mutations)]
            case = FuzzTestCase(
                input_data=f"{base_input}{m['data']}" if m['data'] else base_input,
                mutation_type=m["type"],
                expected_behavior="no_change" if m["type"] == MutationType.EMPTY_VALUE else "same_status",
            )
            cases.append(case)
            self.tracker.total_mutations += 1
        return cases

    def run_and_evaluate(self, cases: List[FuzzTestCase], evaluator) -> List[FuzzTestCase]:
        """Run test cases through evaluator function and collect results."""
        results = []
        for case in cases:
            try:
                result = evaluator(case.input_data)
                case.actual_response = result.get("body", "")[:500]
                case.timing_delta = result.get("duration_ms", 0)
                case.crash_detected = result.get("crash", False) or result.get("status") in (0, None)
                new_cover = self.tracker.record_hit(case.hash_signature)
                if case.crash_detected:
                    self.tracker.record_crash(case, case.actual_response or "")
            except Exception as e:
                case.crash_detected = True
                case.actual_response = str(e)[:500]
            results.append(case)
        return results

    def report(self) -> Dict:
        """Generate fuzzing report."""
        crashes = self.tracker.crashes
        return {
            "target": self.target,
            "fuzz_type": self.fuzz_type,
            "stats": self.tracker.stats(),
            "crashes": crashes,
            "coverage_report": "PASS" if len(crashes) == 0 else "CRASHES_FOUND",
        }


if __name__ == "__main__":
    engine = FuzzingEngine("https://target.corp/api/v1/search", fuzz_type="url_path")
    cases = engine.generate_test_cases(base_input="q=test", count=8)
    for c in cases:
        print(f"  [{c.mutation_type}] hash={c.hash_signature} input={c.input_data[:60]}...")
    print(f"\nCoverage: {json.dumps(engine.tracker.stats(), indent=2)}")
