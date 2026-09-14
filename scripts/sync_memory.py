#!/usr/bin/env python3
"""
NIGHTFANG — Memory Synchronization Utility
Syncs personal memory (PERSONAL_MEMORY.md) with NIGHTFANG shared memory (MEMORY.md)
and engagement session state.
"""

import sys
import json
import yaml
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent))
from env_loader import load_env

load_env()


def parse_personal_memory(filepath: Path) -> dict:
    """Parse YAML frontmatter sections from PERSONAL_MEMORY.md"""
    content = filepath.read_text(encoding="utf-8")
    sections = {}
    
    # Simple YAML block extraction (between ```yaml and ```)
    import re
    yaml_blocks = re.findall(r'```yaml\n(.*?)\n```', content, re.DOTALL)
    
    for block in yaml_blocks:
        try:
            data = yaml.safe_load(block)
            if data:
                # Merge top-level keys
                for k, v in data.items():
                    if k not in sections:
                        sections[k] = v
                    elif isinstance(v, dict) and isinstance(sections[k], dict):
                        sections[k].update(v)
                    elif isinstance(v, list):
                        sections[k].extend(v)
        except Exception:
            pass
    
    return sections


def load_nightfang_memory(filepath: Path) -> dict:
    """Load NIGHTFANG MEMORY.md"""
    return parse_personal_memory(filepath)  # Same format


def load_session_state(engagement_dir: Path) -> dict:
    """Load engagement session state"""
    state_file = engagement_dir / "session_state.json"
    if state_file.exists():
        with open(state_file) as f:
            return json.load(f)
    return {}


def sync_personal_to_engagement(personal_memory: dict, engagement_dir: Path):
    """Sync relevant personal patterns to engagement memory"""
    
    engagement_memory = {
        "learned_evasion_profiles": personal_memory.get("target_signatures", {}),
        "attack_chain_templates": personal_memory.get("attack_chain_templates", []),
        "tool_calibration": personal_memory.get("tool_effectiveness", {}),
        "operator_preferences": personal_memory.get("operator_profile", {}),
    }
    
    mem_file = engagement_dir / "nightfang_personal_memory.json"
    with open(mem_file, "w") as f:
        json.dump(engagement_memory, f, indent=2)
    
    print(f"[SYNC] Personal memory synced to {mem_file}")


def sync_engagement_to_personal(engagement_dir: Path, personal_memory: dict):
    """Update personal memory with engagement outcomes"""
    
    state = load_session_state(engagement_dir)
    if not state:
        print("[SYNC] No session state found")
        return
    
    # Update engagement history
    history = personal_memory.get("engagement_history", [])
    
    # Check if already recorded
    eng_id = engagement_dir.name
    if not any(h.get("engagement_id") == eng_id for h in history):
        engagement_record = {
            "engagement_id": eng_id,
            "client": state.get("client", "Unknown"),
            "type": state.get("type", "greybox"),
            "phases_completed": state.get("phases_completed", []),
            "findings_total": len(state.get("findings", [])),
            "critical": len([f for f in state.get("findings", []) if f.get("severity", 0) >= 9]),
            "high": len([f for f in state.get("findings", []) if 7 <= f.get("severity", 0) <= 8]),
            "exploited": len([f for f in state.get("findings", []) if f.get("confidence", 0) == 10]),
            "attack_chains": len(state.get("attack_chains", [])),
            "caveman_mode_used": state.get("terse_mode", False),
            "completed_at": datetime.now(timezone.utc).isoformat()
        }
        history.append(engagement_record)
        personal_memory["engagement_history"] = history
        print(f"[SYNC] Added engagement {eng_id} to personal history")
    
    # Update tool effectiveness (rolling average)
    tools = personal_memory.get("tool_effectiveness", {})
    # In practice, calculate from actual tool outputs
    print("[SYNC] Tool effectiveness updated (simulated)")
    
    # Update target signatures
    signatures = personal_memory.get("target_signatures", {})
    # In practice, extract from scanner outputs
    print("[SYNC] Target signatures updated (simulated)")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="NIGHTFANG Memory Sync")
    parser.add_argument("--sync-personal", action="store_true", help="Sync personal -> engagement")
    parser.add_argument("--sync-engagement", action="store_true", help="Sync engagement -> personal")
    parser.add_argument("--engagement-dir", default="engagements/current", help="Engagement directory")
    
    args = parser.parse_args()
    
    personal_file = Path("PERSONAL_MEMORY.md")
    engagement_dir = Path(args.engagement_dir)
    
    if not personal_file.exists():
        print(f"[SYNC] Personal memory not found: {personal_file}")
        return 1
    
    personal_memory = parse_personal_memory(personal_file)
    
    if args.sync_personal:
        if engagement_dir.exists():
            sync_personal_to_engagement(personal_memory, engagement_dir)
        else:
            print(f"[SYNC] Engagement dir not found: {engagement_dir}")
    
    if args.sync_engagement:
        if engagement_dir.exists():
            sync_engagement_to_personal(engagement_dir, personal_memory)
            # Note: Writing back to PERSONAL_MEMORY.md requires YAML frontmatter update
            print("[SYNC] Personal memory updated in memory (write to file manually)")
        else:
            print(f"[SYNC] Engagement dir not found: {engagement_dir}")
    
    if not args.sync_personal and not args.sync_engagement:
        parser.print_help()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())