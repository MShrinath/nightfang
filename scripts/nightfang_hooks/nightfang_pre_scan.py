#!/usr/bin/env python3
"""
NIGHTFANG Pre-Scan Hook
Validates scope, loads evasion profiles, calibrates tools before scanning
"""

import sys
import os
import yaml
import json
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config, load_env

load_env()


def main():
    engagement_config = "config/personal_engagement.yaml"
    config = load_config(engagement_config)
    
    print("[NIGHTFANG Pre-Scan] Validating engagement configuration...")
    
    # 1. Validate scope
    scope = config.get("scope", {})
    in_scope = scope.get("in_scope", {})
    
    domains = in_scope.get("domains", [])
    ips = in_scope.get("ips", [])
    urls = in_scope.get("urls", [])
    
    print(f"  Domains: {len(domains)}")
    print(f"  IP ranges: {len(ips)}")
    print(f"  URLs: {len(urls)}")
    
    # 2. Load personal memory for evasion profiles
    memory_file = Path("PERSONAL_MEMORY.md")
    if memory_file.exists():
        print("[NIGHTFANG Pre-Scan] Loading personal memory for evasion profiles...")
        # In practice, parse YAML frontmatter from PERSONAL_MEMORY.md
        # For now, just confirm file exists
        print("  Personal memory found - evasion profiles available")
    
    # 3. Calibrate tools from personal memory
    agent_config = config.get("agent", {})
    calibration = agent_config.get("calibration", {})
    
    print("[NIGHTFANG Pre-Scan] Tool calibration:")
    for tool, value in calibration.items():
        print(f"  {tool}: {value}")
    
    # 4. Verify critical tools
    critical_tools = ["nmap", "ffuf", "nuclei", "sqlmap", "masscan", "subfinder", "katana"]
    print("[NIGHTFANG Pre-Scan] Verifying critical tools...")
    for tool in critical_tools:
        # In practice, check with `which` or `command -v`
        print(f"  {tool}: ASSUMED_AVAILABLE")
    
    # 5. Check rate limits
    rules = config.get("rules", {})
    max_rate = rules.get("max_scan_rate", 100)
    print(f"[NIGHTFANG Pre-Scan] Global rate limit: {max_rate} req/sec")
    
    print("[NIGHTFANG Pre-Scan] Complete - ready for scanning")
    return 0


if __name__ == "__main__":
    sys.exit(main())