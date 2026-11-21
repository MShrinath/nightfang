#!/usr/bin/env python3
"""
NIGHTFANG Finding Validator Corpus Test Suite

Tests the validator against a collection of malformed finding records
stored in schemas/corpus/. Each corpus file represents a specific type
of schema violation or edge case.
"""

import json
import os
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from schemas.validator import FindingValidator, ValidationReport


CORPUS_DIR = Path(__file__).parent.parent / "schemas" / "corpus"


def load_corpus_file(filepath: Path) -> Dict[str, Any]:
    """Load a JSON corpus file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def get_corpus_filename(corpus_data: Dict[str, Any]) -> str:
    """Extract filename from corpus data (used for reporting)."""
    # Return the key name or 'unknown'
    if isinstance(corpus_data.get("id"), str):
        return corpus_data["id"]
    return "unknown"


def run_corpus_tests() -> Tuple[int, int, List[str]]:
    """
    Run all corpus tests.
    
    Returns:
        (passed, total, errors) - number of passed tests, total tests, list of error messages
    """
    validator = FindingValidator()
    corpus_files = sorted(CORPUS_DIR.glob("*.json"))
    
    if not corpus_files:
        print(f"[WARN] No corpus files found in {CORPUS_DIR}")
        return 0, 0, ["No corpus files found"]
    
    passed = 0
    failed = 0
    errors = []
    
    for corpus_file in corpus_files:
        try:
            corpus_data = load_corpus_file(corpus_file)
            report = validator.validate(corpus_data)
            
            expected_errors = len(corpus_data.get("expected_errors", []))
            
            # If expected_errors is specified, check count
            if expected_errors > 0:
                if len(report.errors) >= expected_errors:
                    passed += 1
                    print(f"  [PASS] {corpus_file.name}: Caught {len(report.errors)} errors (expected >= {expected_errors})")
                else:
                    failed += 1
                    errors.append(f"{corpus_file.name}: Expected >= {expected_errors} errors, got {len(report.errors)}")
                    print(f"  [FAIL] {corpus_file.name}: Expected >= {expected_errors} errors, got {len(report.errors)}")
            else:
                # Default: expect at least some errors (malformed record)
                if not report.is_valid:
                    passed += 1
                    print(f"  [PASS] {corpus_file.name}: Validated as invalid ({len(report.errors)} errors)")
                else:
                    failed += 1
                    errors.append(f"{corpus_file.name}: Expected invalid but got valid")
                    print(f"  [FAIL] {corpus_file.name}: Expected invalid but got valid")
                    
        except Exception as e:
            failed += 1
            errors.append(f"{corpus_file.name}: Exception during validation: {e}")
            print(f"  [ERROR] {corpus_file.name}: {e}")
    
    return passed, len(corpus_files), errors


def main() -> None:
    print("=" * 60)
    print("NIGHTFANG Validator Corpus Test Suite")
    print("=" * 60)
    print(f"Corpus directory: {CORPUS_DIR}")
    print(f"Corpus files: {len(list(CORPUS_DIR.glob('*.json')))}")
    print()
    
    passed, total, errors = run_corpus_tests()
    
    print()
    print("-" * 60)
    print(f"Results: {passed}/{total} passed")
    
    if errors:
        print(f"\nFailures ({len(errors)}):")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("\nAll corpus tests PASSED!")
        sys.exit(0)


class CorpusTestSuite(unittest.TestCase):
    """Unittest-compatible wrapper around run_corpus_tests()."""

    def test_all_corpus_files_rejected(self) -> None:
        passed, total, errors = run_corpus_tests()
        self.assertEqual(total, 12, f"Expected 12 corpus files, got {total}")
        self.assertEqual(passed, total, f"{len(errors)} failures: {errors}")


if __name__ == "__main__":
    unittest.main(module=None)
