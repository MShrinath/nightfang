#!/usr/bin/env python3
"""
NIGHTFANG Agent Self-Improvement Module

Agents can automatically update their knowledge by:
1. Checking for newer skill definitions from central registry
2. Validating corpus findings against updated schemas
3. Propagating learned patterns to peer agents

Usage:
    python tools/auto_update.py [--check] [--update] [--validate-corpus]
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# Registry locations (can be overridden via env or config)
SKILL_REGISTRY_PATH = Path(__file__).parent.parent / "manifest.yaml"
CORPUS_DIR = Path(__file__).parent.parent / "schemas" / "corpus"
AGENTS_DIR = Path(__file__).parent.parent / "agents"
VERSION_FILE = Path(__file__).parent.parent / ".nightfang_version"


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Could not load {path}: {e}")
        return None


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def compute_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def get_current_version() -> Optional[str]:
    if VERSION_FILE.exists():
        return load_json(VERSION_FILE) or {}
    return None


def set_version(version: str, changelog: str) -> None:
    VERSION_FILE.write_text(json.dumps({
        "version": version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "changelog": changelog,
    }, indent=2))


def check_skill_updates(remote_registry_url: str) -> List[Dict[str, Any]]:
    """Check for newer skill versions from remote registry."""
    # Stub: in production, fetch from URL and compare hashes
    print(f"[INFO] Checking skills against remote registry: {remote_registry_url}")
    print("[INFO] No updates available (registry sync stub)")
    return []


def validate_corpus_against_schema() -> Dict[str, Any]:
    """Validate all corpus files against the validator schema."""
    # Ensure we can import from project root
    _proj_root = Path(__file__).parent.parent
    if str(_proj_root) not in sys.path:
        sys.path.insert(0, str(_proj_root))
    
    from schemas.validator import FindingValidator
    
    validator = FindingValidator()
    results = {"total": 0, "valid_as_intended": 0, "invalidated": 0, "errors": []}
    
    if not CORPUS_DIR.exists():
        return results
    
    for f in sorted(CORPUS_DIR.glob("*.json")):
        results["total"] += 1
        data = load_json(f)
        if data is None:
            continue
        
        report = validator.validate(data)
        # Corpus files should all be invalid (they're malformed records)
        if not report.is_valid:
            results["valid_as_intended"] += 1
        else:
            results["invalidated"] += 1
            results["errors"].append(f"{f.name}: unexpectedly valid")
    
    return results


def propagate_learned_patterns(agent_id: str, pattern: Dict[str, Any]) -> bool:
    """Propagate a learned pattern to peer agents via shared manifest."""
    manifest_path = Path(__file__).parent.parent / "manifest.yaml"
    # In production, this would sync across agents or write to shared storage
    print(f"[INFO] Pattern propagation stub for agent={agent_id}: {pattern.get('id', 'unknown')}")
    return True


def sync_agent_knowledge(agent_path: Path) -> bool:
    """Check if an agent's SKILL.md needs updating based on latest patterns."""
    if not agent_path.exists():
        return False
    
    # Read current content
    content = agent_path.read_text(encoding="utf-8")
    current_hash = compute_hash(content)
    
    # Check for known improvements (stub - would query a central KB)
    improvements_needed = []
    
    if not improvements_needed:
        print(f"  [OK] {agent_path.name}: up to date (hash={current_hash})")
        return True
    
    # Apply updates
    new_content = content
    for imp in improvements_needed:
        # Pattern-based auto-fixes
        if imp.get("type") == "add_section":
            new_content += f"\n\n## {imp['title']}\n{imp['content']}\n"
    
    if new_content != content:
        agent_path.write_text(new_content, encoding="utf-8")
        new_hash = compute_hash(new_content)
        print(f"  [UPDATE] {agent_path.name}: applied {len(improvements_needed)} improvements ({current_hash}->{new_hash})")
        return True
    else:
        print(f"  [OK] {agent_path.name}: no changes needed")
        return True


def main() -> None:
    parser = argparse.ArgumentParser(description="NIGHTFANG Agent Self-Improvement Tool")
    parser.add_argument("--check", action="store_true", help="Check for updates without applying")
    parser.add_argument("--update", action="store_true", help="Apply available updates")
    parser.add_argument("--validate-corpus", action="store_true", help="Validate corpus against schema")
    parser.add_argument("--agent", type=str, help="Specific agent ID to update")
    args = parser.parse_args()
    
    print("=" * 60)
    print("NIGHTFANG Self-Improvement Engine")
    print("=" * 60)
    
    # Current version
    current = get_current_version()
    version = current.get("version", "0.0.0") if current else "0.0.0"
    print(f"Current version: {version}")
    print()
    
    # Validate corpus
    if args.validate_corpus or args.check or args.update:
        print("--- Corpus Validation ---")
        cv_results = validate_corpus_against_schema()
        print(f"  Total corpus files: {cv_results['total']}")
        print(f"  Correctly rejected: {cv_results['valid_as_intended']}")
        if cv_results["errors"]:
            print(f"  Unexpectedly validated: {len(cv_results['errors'])}")
            for err in cv_results["errors"]:
                print(f"    - {err}")
        print()
    
    # Check for skill updates
    if args.check or args.update:
        print("--- Skill Update Check ---")
        updates = check_skill_updates("https://registry.nightfang.local/skills")
        print(f"  Available updates: {len(updates)}")
        if updates:
            for u in updates:
                print(f"    - {u['skill_id']}: {u['current_version']} -> {u['new_version']}")
        print()
    
    # Sync agent knowledge
    if args.agent:
        agent_path = AGENTS_DIR / f"{args.agent}.md"
        if agent_path.exists():
            print(f"--- Agent Knowledge Sync ---")
            sync_agent_knowledge(agent_path)
            print()
    elif args.check or args.update:
        print("--- All Agents Knowledge Sync ---")
        for agent_md in sorted(AGENTS_DIR.glob("*.md")):
            sync_agent_knowledge(agent_md)
        print()
    
    # Bump version if updates applied
    if args.update and current:
        new_version = ".".join(str(int(x) + 1 if i == 2 else x) for i, x in enumerate(version.split(".")))
        set_version(new_version, "Self-improvement auto-update applied")
        print(f"Version bumped to {new_version}")
    
    print("\nDone.")


if __name__ == "__main__":
    main()
