#!/usr/bin/env python3
"""NIGHTFANG Command-Line Interface.

Provides a proper CLI interface wrapping the Autonomous Hunter Daemon
and Execution Policy Gateway for direct operator interaction.

Usage:
    nightfang-cli test                    Run all self-tests
    nightfang-cli target <DOMAIN>         Launch autonomous hunter
    nightfang-cli daemon [--target T]   Run daemon (background)
    nightfang-cli hunt <TARGET>           Launch continuous hunting
    nightfang-cli gateway                 Run just the gateway
    nightfang-cli status                  Show system status
    nightfang-cli agents                  List registered agents
    nightfang-cli skills                  List registered skills
    nightfang-cli payloads [CLASS]        Query payload catalog
    nightfang-cli help                    Show help
"""
import sys
import os
import json
import time
from datetime import datetime

# Handle both direct invocation and package imports
if __name__ == "__main__" and "tools" not in sys.modules:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def cmd_test(args):
    """Run self-tests for daemon and gateway."""
    print("=" * 60)
    print("NIGHTFANG CLI Self-Tests")
    print("=" * 60)
    
    from gateway import run_self_tests as gateway_tests
    
    print("\n[1] Testing Execution Policy Gateway...")
    try:
        gw_ok = gateway_tests()
        print("  Gateway tests: PASSED")
    except Exception as e:
        print(f"  Gateway tests: FAILED - {e}")
        gw_ok = False
    
    print("\n[2] Testing Daemon...")
    try:
        from daemon import run_self_tests as daemon_tests
        daemon_ok = daemon_tests()
        print("  Daemon tests: PASSED")
    except Exception as e:
        print(f"  Daemon tests: FAILED - {e}")
        daemon_ok = False
    
    print("\n" + "=" * 60)
    if gw_ok and daemon_ok:
        print("All self-tests PASSED")
        return 0
    else:
        print("Some tests FAILED")
        return 1

def cmd_target(args):
    """Launch autonomous hunter against target."""
    if not args.target:
        print("[!] No target specified")
        return 1
    
    from daemon import AutonomousHunterDaemon, EngagedEngagementConfig, AutonomyTier
    
    target = args.target
    tier = AutonomyTier[args.tier.upper()] if args.tier else AutonomyTier.SEMI_AUTONOMOUS
    
    print(f"[*] Launching autonomous hunter against: {target}")
    print(f"[*] Autonomy tier: {tier.name}")
    
    cfg = EngagedEngagementConfig(
        engagement_id=f"ENG-{int(time.time())}",
        authorized_operator="operator",
        authorized_domains=[target, f"*.{target}"],
        autonomy_tier=tier,
    )
    
    daemon = AutonomousHunterDaemon(cfg)
    daemon.seed_target(target)
    daemon.run_continuous(max_cycles=args.max_cycles or 50)

def cmd_daemon(args):
    """Run daemon in background mode."""
    from daemon import AutonomousHunterDaemon, EngagedEngagementConfig, AutonomyTier
    
    target = args.target
    tier = AutonomyTier[args.tier.upper()] if args.tier else AutonomyTier.SEMI_AUTONOMOUS
    
    if not target:
        print("[!] No target specified. Running daemon in passive mode...")
        target = None
    
    print("[*] Starting NIGHTFANG Autonomous Hunter Daemon...")
    
    if target:
        cfg = EngagedEngagementConfig(
            engagement_id=f"ENG-{int(time.time())}",
            authorized_operator="operator",
            authorized_domains=[target, f"*.{target}"],
            autonomy_tier=tier,
        )
    else:
        cfg = EngagedEngagementConfig(engagement_id=f"ENG-{int(time.time())}")
    
    daemon = AutonomousHunterDaemon(cfg)
    if target:
        daemon.seed_target(target)
    daemon.run_continuous(max_cycles=args.max_cycles or 50)

def cmd_hunt(args):
    """Launch continuous hunting against target."""
    if not args.target:
        print("[!] No target specified. Usage: nightfang-cli hunt <TARGET>")
        return 1
    
    from daemon import run_hunt  # Import the convenience function
    run_hunt(args.target)

def cmd_gateway(args):
    """Run just the gateway (without daemon)."""
    from gateway import ExecutionPolicyGateway, EngagementState, EngagementConfig
    from sandbox import SandboxRunner
    
    print("[*] Starting NIGHTFANG Execution Policy Gateway...")
    print("[*] Note: Gateway requires an active engagement context.")
    print("[*] Use 'nightfang-daemon' to start full autonomous operation.")
    
    if args.config:
        try:
            with open(args.config) as f:
                config = json.load(f)
            cfg = EngagementConfig(**config)
        except Exception as e:
            print(f"[!] Failed to load config: {e}")
            return 1
    else:
        cfg = EngagementConfig(
            engagement_id=f"ENG-{int(time.time())}",
            authorized_operator="operator",
        )
    
    state = EngagementState(cfg)
    gw = ExecutionPolicyGateway(state)
    print(f"[+] Gateway ready. Engagement: {cfg.engagement_id}")

def cmd_status(args):
    """Show system status."""
    print("=" * 60)
    print("NIGHTFANG System Status")
    print("=" * 60)
    
    # Check tools
    tools = [
        ("daemon.py", "Autonomous Hunter Engine"),
        ("gateway.py", "Execution Policy Gateway"),
        ("sandbox.py", "Sandbox Runner"),
        ("threat_emulator.py", "Threat Emulation Engine"),
    ]
    
    print("\nCore Tools:")
    for name, desc in tools:
        path = os.path.join(os.path.dirname(__file__), name)
        status = "OK" if os.path.exists(path) else "MISSING"
        print(f"  [{status}] {name} - {desc}")
    
    # Check skills
    skills_dir = os.path.join(os.path.dirname(__file__), "..", "skills")
    if os.path.exists(skills_dir):
        skills = [d for d in os.listdir(skills_dir) 
                  if os.path.isdir(os.path.join(skills_dir, d)) and not d.startswith("_")]
        print(f"\nSkills Directory: {len(skills)} skills registered")
    else:
        print("\nSkills Directory: NOT FOUND")
    
    # Check payload catalog
    catalog_path = os.path.join(os.path.dirname(__file__), "..", "references", "payloads", "index.json")
    if os.path.exists(catalog_path):
        with open(catalog_path) as f:
            catalog = json.load(f)
        safe_count = sum(1 for v in catalog.values() if v.get("safe_default"))
        print(f"Payload Catalog: {len(catalog)} categories, {safe_count} safe")
    else:
        print("Payload Catalog: NOT FOUND")
    
    print("\n" + "=" * 60)

def cmd_agents(args):
    """List registered agents."""
    manifest_path = os.path.join(os.path.dirname(__file__), "..", "manifest.yaml")
    
    import yaml
    with open(manifest_path) as f:
        manifest = yaml.safe_load(f)
    
    agents = manifest.get("agents", [])
    print(f"\nRegistered Agents ({len(agents)}):")
    print("-" * 40)
    
    for agent in agents:
        name = agent.get("name", "unknown")
        purpose = agent.get("purpose", "N/A")[:50]
        print(f"  {name}: {purpose}...")

def cmd_skills(args):
    """List registered skills."""
    skills_dir = os.path.join(os.path.dirname(__file__), "..", "skills")
    
    if not os.path.exists(skills_dir):
        print("Skills directory not found")
        return 1
    
    skills = []
    for d in sorted(os.listdir(skills_dir)):
        skill_path = os.path.join(skills_dir, d, "SKILL.md")
        if os.path.isdir(os.path.join(skills_dir, d)) and os.path.exists(skill_path):
            skills.append(d)
    
    print(f"\nRegistered Skills ({len(skills)}):")
    print("-" * 40)
    for skill in skills:
        print(f"  {skill}")

def cmd_payloads(args):
    """Query the payload catalog."""
    catalog_path = os.path.join(os.path.dirname(__file__), "..", "references", "payloads", "index.json")
    
    if not os.path.exists(catalog_path):
        print("Payload catalog not found")
        return 1
    
    with open(catalog_path) as f:
        catalog = json.load(f)
    
    if args.class_name:
        if args.class_name in catalog:
            info = catalog[args.class_name]
            print(f"\n{args.class_name}:")
            print(f"  CWE: {info.get('cwe', 'N/A')}")
            print(f"  OWASP: {info.get('owasp', 'N/A')}")
            print(f"  Safe: {info.get('safe_default', False)}")
            files = info.get('payload_files', [])
            if files:
                print(f"  Payload files: {len(files)}")
                for f in files[:5]:
                    print(f"    - {f}")
                if len(files) > 5:
                    print(f"    ... and {len(files) - 5} more")
            else:
                print("  Payload files: (none - recon/probe only)")
        else:
            print(f"Category '{args.class_name}' not found")
            print(f"Available: {len(catalog)} categories")
            if args.list:
                for k in sorted(catalog.keys()):
                    safe = "safe" if catalog[k].get("safe_default") else "destructive"
                    print(f"  {k} [{safe}]")
    else:
        safe = [k for k, v in catalog.items() if v.get("safe_default")]
        destructive = [k for k, v in catalog.items() if not v.get("safe_default")]
        
        print(f"\nPayload Catalog: {len(catalog)} categories")
        print(f"  Safe for testing: {len(safe)}")
        print(f"  Potentially destructive: {len(destructive)}")

def cmd_help(args):
    """Show help."""
    print(__doc__)
    print("\nSubcommands:")
    commands = [
        ("test", "Run self-tests for daemon and gateway"),
        ("target <DOMAIN>", "Launch autonomous hunter against target"),
        ("daemon", "Run daemon in background mode"),
        ("hunt <TARGET>", "Launch continuous hunting"),
        ("gateway", "Run just the gateway"),
        ("status", "Show system status"),
        ("agents", "List registered agents"),
        ("skills", "List registered skills"),
        ("payloads [CLASS]", "Query payload catalog"),
        ("help", "Show this help"),
    ]
    for cmd, desc in commands:
        print(f"  {cmd:20s} - {desc}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        prog="nightfang-cli",
        description="NIGHTFANG Command-Line Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Test command
    test_parser = subparsers.add_parser("test", help="Run self-tests for daemon and gateway")
    test_parser.set_defaults(func=cmd_test)
    
    # Target command
    target_parser = subparsers.add_parser("target", help="Launch autonomous hunter against target")
    target_parser.add_argument("target", nargs="?", help="Target domain or IP")
    target_parser.add_argument("--tier", choices=["REACTIVE", "SEMI_AUTONOMOUS", "FULL_AUTONOMOUS"], default="SEMI_AUTONOMOUS", help="Autonomy tier")
    target_parser.add_argument("--max-cycles", type=int, help="Maximum execution cycles")
    target_parser.set_defaults(func=cmd_target)
    
    # Daemon command
    daemon_parser = subparsers.add_parser("daemon", help="Run daemon in background mode")
    daemon_parser.add_argument("--target", help="Initial target")
    daemon_parser.add_argument("--tier", choices=["REACTIVE", "SEMI_AUTONOMOUS", "FULL_AUTONOMOUS"], default="SEMI_AUTONOMOUS")
    daemon_parser.add_argument("--max-cycles", type=int, default=50)
    daemon_parser.set_defaults(func=cmd_daemon)
    
        # Hunt command
    hunt_parser = subparsers.add_parser("hunt", help="Launch continuous hunting")
    hunt_parser.add_argument("target", nargs="?", help="Target domain or IP")
    hunt_parser.set_defaults(func=cmd_hunt)
    
        # Gateway command
    gateway_parser = subparsers.add_parser("gateway", help="Run just the gateway")
    gateway_parser.add_argument("--config", help="Path to config file")
    gateway_parser.set_defaults(func=cmd_gateway)
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Show system status")
    status_parser.set_defaults(func=cmd_status)
    
    # Agents command
    agents_parser = subparsers.add_parser("agents", help="List registered agents")
    agents_parser.set_defaults(func=cmd_agents)
    
    # Skills command
    skills_parser = subparsers.add_parser("skills", help="List registered skills")
    skills_parser.set_defaults(func=cmd_skills)
    
    # Payloads command
    payloads_parser = subparsers.add_parser("payloads", help="Query payload catalog")
    payloads_parser.add_argument("class_name", nargs="?", help="Category name to query")
    payloads_parser.add_argument("--list", action="store_true", help="List all categories")
    payloads_parser.set_defaults(func=cmd_payloads)
    
    # Help command
    help_parser = subparsers.add_parser("help", help="Show this help")
    help_parser.set_defaults(func=cmd_help)
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 0
    
    if not hasattr(args, 'func'):
        parser.print_help()
        return 0
    
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())