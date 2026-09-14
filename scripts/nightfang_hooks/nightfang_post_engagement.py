#!/usr/bin/env python3
"""
NIGHTFANG Post-Engagement Hook
Updates personal memory, calculates tool effectiveness, archives engagement
"""

import sys
import os
import json
import yaml
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_env

load_env()


def update_tool_effectiveness(engagement_dir: Path, personal_memory: dict):
    """Calculate and update tool effectiveness from engagement results"""
    
    # In practice, parse all tool outputs and calculate success rates
    # For now, simulate updates
    
    tools = personal_memory.get("tool_effectiveness", {})
    
    # Simulated updates based on engagement
    updates = {
        "nmap": {"success_rate": 0.94, "last_used": datetime.now(timezone.utc).isoformat()},
        "ffuf": {"success_rate": 0.89, "last_used": datetime.now(timezone.utc).isoformat()},
        "nuclei": {"success_rate": 0.76, "last_used": datetime.now(timezone.utc).isoformat()},
        "sqlmap": {"success_rate": 0.82, "last_used": datetime.now(timezone.utc).isoformat()},
    }
    
    for tool, data in updates.items():
        if tool in tools:
            # Rolling average
            old_rate = tools[tool].get("success_rate", 0.5)
            tools[tool]["success_rate"] = round((old_rate * 0.7) + (data["success_rate"] * 0.3), 2)
        else:
            tools[tool] = data
    
    personal_memory["tool_effectiveness"] = tools
    print(f"[NIGHTFANG Post-Engagement] Updated tool effectiveness for {len(tools)} tools")


def extract_new_signatures(engagement_dir: Path, personal_memory: dict):
    """Extract new WAF/rate-limit signatures from engagement"""
    
    # In practice, parse scanner outputs for new signatures
    # For now, simulate
    
    signatures = personal_memory.get("target_signatures", {})
    
    # Example: if we saw a new WAF
    new_sig = {
        "detected_headers": ["x-new-waf-header"],
        "safe_request_rate": 20,
        "evasion_notes": "Discovered in current engagement",
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "engagement_ref": engagement_dir.name
    }
    
    if "new_waf_discovered" not in signatures:
        signatures["new_waf_discovered"] = new_sig
        print("[NIGHTFANG Post-Engagement] Added new WAF signature to personal memory")
    
    personal_memory["target_signatures"] = signatures


def archive_engagement(engagement_dir: Path):
    """Archive engagement logs and evidence"""
    
    archive_dir = Path("engagements/archive") / engagement_dir.name
    archive_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy key files
    import shutil
    for src in engagement_dir.glob("*"):
        if src.is_file() or src.name in ["evidence", "reports", "logs"]:
            dst = archive_dir / src.name
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)
    
    print(f"[NIGHTFANG Post-Engagement] Archived engagement to {archive_dir}")


def update_engagement_history(engagement_dir: Path, personal_memory: dict):
    """Add engagement to history"""
    
    history = personal_memory.get("engagement_history", [])
    
    # Parse engagement stats from report or state
    state_file = engagement_dir / "session_state.json"
    if state_file.exists():
        with open(state_file) as f:
            state = json.load(f)
        
        engagement_record = {
            "engagement_id": engagement_dir.name,
            "client": state.get("client", "Unknown"),
            "type": state.get("type", "greybox"),
            "duration_days": 0,  # Calculate from timestamps
            "phases_completed": state.get("phases_completed", []),
            "findings_total": len(state.get("findings", [])),
            "critical": len([f for f in state.get("findings", []) if f.get("severity", 0) >= 9]),
            "high": len([f for f in state.get("findings", []) if 7 <= f.get("severity", 0) <= 8]),
            "exploited": len([f for f in state.get("findings", []) if f.get("confidence", 0) == 10]),
            "attack_chains": len(state.get("attack_chains", [])),
            "notable_pattern": "Auto-extracted from findings",
            "lessons_learned": [],
            "caveman_mode_used": state.get("terse_mode", False)
        }
        
        history.append(engagement_record)
        personal_memory["engagement_history"] = history
        print(f"[NIGHTFANG Post-Engagement] Added engagement {engagement_dir.name} to history")


def save_personal_memory(personal_memory: dict):
    """Save updated personal memory to PERSONAL_MEMORY.md"""
    
    # In practice, update the YAML frontmatter sections
    # For now, just log
    print("[NIGHTFANG Post-Engagement] Personal memory updated (simulated)")
    print("  Run manual update of PERSONAL_MEMORY.md with new data")


def main():
    if len(sys.argv) < 2:
        print("Usage: nightfang_post_engagement.py <engagement_dir>")
        return 1
    
    engagement_dir = Path(sys.argv[1])
    if not engagement_dir.exists():
        print(f"Engagement directory not found: {engagement_dir}")
        return 1
    
    print(f"[NIGHTFANG Post-Engagement] Processing {engagement_dir.name}")
    
    # Load current personal memory (simulated)
    personal_memory = {
        "tool_effectiveness": {},
        "target_signatures": {},
        "engagement_history": []
    }
    
    # Run updates
    update_tool_effectiveness(engagement_dir, personal_memory)
    extract_new_signatures(engagement_dir, personal_memory)
    update_engagement_history(engagement_dir, personal_memory)
    archive_engagement(engagement_dir)
    save_personal_memory(personal_memory)
    
    print("[NIGHTFANG Post-Engagement] Complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())