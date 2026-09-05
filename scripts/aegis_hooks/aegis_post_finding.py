#!/usr/bin/env python3
"""
AEGIS Post-Finding Hook
Enriches findings with personal context, applies chain templates
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


def enrich_finding(finding: dict, personal_memory: dict) -> dict:
    """Enrich a finding with AEGIS personal context"""
    
    # Add personal metadata
    finding["aegis"] = {
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        "operator": personal_memory.get("operator_profile", {}).get("handle", "@SecurityLead"),
        "chain_templates_checked": [],
        "evasion_profile_applied": None,
        "tool_calibration_used": None
    }
    
    # Check for matching attack chain templates
    chain_templates = personal_memory.get("attack_chain_templates", [])
    vuln_type = finding.get("type", "").lower()
    
    for template in chain_templates:
        template_name = template.get("name", "").lower()
        if any(keyword in vuln_type for keyword in ["bola", "idor", "jwt", "ssrf", "graphql", "ai", "llm"]):
            if any(keyword in template_name for keyword in ["bola", "idor", "jwt", "ssrf", "graphql", "ai", "llm"]):
                finding["aegis"]["chain_templates_checked"].append(template.get("id"))
                finding["suggested_chain"] = template.get("id")
    
    # Apply evasion profile if target matches
    target = finding.get("target", "")
    signatures = personal_memory.get("target_signatures", {})
    
    for sig_name, sig_data in signatures.items():
        if sig_name in target or any(h in target for h in sig_data.get("detected_headers", [])):
            finding["aegis"]["evasion_profile_applied"] = sig_name
            finding["evasion_notes"] = sig_data.get("evasion_notes")
            break
    
    # Apply tool calibration
    tool_eff = personal_memory.get("tool_effectiveness", {})
    finding["aegis"]["tool_calibration_used"] = tool_eff
    
    return finding


def main():
    if len(sys.argv) < 2:
        print("Usage: aegis_post_finding.py <finding_json_file>")
        return 1
    
    finding_file = Path(sys.argv[1])
    if not finding_file.exists():
        print(f"Finding file not found: {finding_file}")
        return 1
    
    with open(finding_file, "r") as f:
        finding = json.load(f)
    
    # Load personal memory (simplified - in practice parse YAML frontmatter)
    personal_memory = {
        "operator_profile": {"handle": "@SecurityLead"},
        "target_signatures": {},
        "attack_chain_templates": [],
        "tool_effectiveness": {}
    }
    
    # Try to load from PERSONAL_MEMORY.md
    mem_file = Path("PERSONAL_MEMORY.md")
    if mem_file.exists():
        # In practice, parse the YAML sections
        pass
    
    # Enrich finding
    enriched = enrich_finding(finding, personal_memory)
    
    # Write back
    with open(finding_file, "w") as f:
        json.dump(enriched, f, indent=2)
    
    print(f"[AEGIS Post-Finding] Enriched finding {finding.get('id', 'unknown')}")
    if enriched["aegis"]["chain_templates_checked"]:
        print(f"  Chain templates: {enriched['aegis']['chain_templates_checked']}")
    if enriched["aegis"]["evasion_profile_applied"]:
        print(f"  Evasion profile: {enriched['aegis']['evasion_profile_applied']}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())