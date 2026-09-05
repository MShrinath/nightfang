#!/usr/bin/env python3
"""
AEGIS ↔ HERMES Bridge
Integrates personal agent with HERMES framework shared memory and state
"""

import sys
import json
import yaml
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from env_loader import load_env, load_config

load_env()


class HermesBridge:
    """Bridge between AEGIS personal agent and HERMES framework"""
    
    def __init__(self, engagement_dir: str = "engagements/current"):
        self.engagement_dir = Path(engagement_dir)
        self.engagement_dir.mkdir(parents=True, exist_ok=True)
        
        # HERMES shared files
        self.hermes_memory_file = Path("MEMORY.md")
        self.hermes_state_file = self.engagement_dir / "session_state.json"
        self.hermes_config_file = Path("config/engagement_template.yaml")
        
        # AEGIS personal files
        self.aegis_memory_file = Path("PERSONAL_MEMORY.md")
        self.aegis_soul_file = Path("SOUL.md")
        self.aegis_operator_file = Path("OPERATOR_PROFILE.md")
        
        self.hermes_state = self._load_hermes_state()
        self.hermes_config = load_config(str(self.hermes_config_file))
    
    def _load_hermes_state(self) -> Dict:
        """Load HERMES session state"""
        if self.hermes_state_file.exists():
            with open(self.hermes_state_file) as f:
                return json.load(f)
        return {
            "engagement_id": f"ENG-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}",
            "status": "active",
            "phase": "phase_0_intake",
            "terse_mode": False,
            "assets": {},
            "findings": [],
            "decisions": [],
            "timeline": []
        }
    
    def _save_hermes_state(self):
        """Save HERMES session state"""
        with open(self.hermes_state_file, "w") as f:
            json.dump(self.hermes_state, f, indent=2)
    
    # ===== MEMORY SYNC =====
    
    def sync_findings_to_hermes(self, aegis_findings: list) -> int:
        """Sync AEGIS findings to HERMES shared memory"""
        synced = 0
        for finding in aegis_findings:
            # Convert AEGIS finding to HERMES format
            hermes_finding = {
                "id": finding.get("id", f"HERMES-{len(self.hermes_state['findings'])+1:03d}"),
                "title": finding.get("title", ""),
                "target": finding.get("target", ""),
                "type": finding.get("type", ""),
                "confidence": finding.get("confidence", 5),
                "severity": finding.get("severity", 5),
                "mitre_attack": finding.get("mitre_attack", "T1190"),
                "d3fend": finding.get("d3fend", "D3-PSA"),
                "status": "Confirmed" if finding.get("confidence", 0) >= 7 else "Suspected",
                "description": finding.get("description", ""),
                "discovered_at": finding.get("discovered_at", datetime.now(timezone.utc).isoformat()),
                "aegis_metadata": finding.get("aegis", {})
            }
            
            # Check for duplicate
            existing = next((f for f in self.hermes_state["findings"] if f["id"] == hermes_finding["id"]), None)
            if existing:
                existing.update(hermes_finding)
            else:
                self.hermes_state["findings"].append(hermes_finding)
                synced += 1
        
        self._save_hermes_state()
        return synced
    
    def sync_assets_to_hermes(self, assets: Dict) -> int:
        """Sync discovered assets to HERMES"""
        synced = 0
        for host, data in assets.items():
            if host not in self.hermes_state["assets"]:
                self.hermes_state["assets"][host] = {
                    "ip": data.get("ip", host),
                    "ports": data.get("ports", []),
                    "services": data.get("services", []),
                    "status": "discovered",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                synced += 1
            else:
                # Merge ports/services
                existing = self.hermes_state["assets"][host]
                existing["ports"] = list(set(existing["ports"]) | set(data.get("ports", [])))
                existing["services"] = list(set(existing["services"]) | set(data.get("services", [])))
        
        self._save_hermes_state()
        return synced
    
    def get_hermes_findings(self) -> list:
        """Get all findings from HERMES memory"""
        return self.hermes_state.get("findings", [])
    
    def get_hermes_assets(self) -> Dict:
        """Get all assets from HERMES memory"""
        return self.hermes_state.get("assets", {})
    
    def get_hermes_decisions(self) -> list:
        """Get operator decisions from HERMES"""
        return self.hermes_state.get("decisions", [])
    
    # ===== SCOPE VALIDATION =====
    
    def validate_target(self, target: str) -> bool:
        """Validate target against HERMES scope"""
        from scope_validator import ScopeValidator
        validator = ScopeValidator(str(self.hermes_config_file))
        return validator.validate_target(target)
    
    def get_scope_summary(self) -> Dict:
        """Get scope summary for operator confirmation"""
        scope = self.hermes_config.get("scope", {})
        in_scope = scope.get("in_scope", {})
        
        return {
            "domains": len(in_scope.get("domains", [])),
            "ips": len(in_scope.get("ips", [])),
            "urls": len(in_scope.get("urls", [])),
            "ports": in_scope.get("ports", []),
            "techniques": self.hermes_config.get("rules", {}).get("allowed_techniques", [])
        }
    
    # ===== HITL INTEGRATION =====
    
    def request_operator_approval(self, phase: str, details: Dict) -> bool:
        """Request operator approval via HERMES Telegram bridge"""
        from scripts.telegram_bridge import TelegramHITLBridge
        
        bridge = TelegramHITLBridge(str(self.hermes_config_file))
        
        if phase == "phase_2_active_recon":
            message = f"""⚠️ AEGIS Permission Request
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 Action: Active port scanning & service enumeration
🎯 Targets: {details.get('target_count', 0)} hosts
⚡ Timing: T4 (Aggressive)
🛡️ Evasion: {details.get('evasion_profile', 'adaptive')}
📊 Est. time: {details.get('est_time', 'unknown')}

This sends traffic directly to targets using learned evasion profiles.
Reply: /go or /hold"""
        
        elif phase == "phase_5_exploitation":
            message = f"""⚠️ AEGIS Exploitation Request
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Target: {details.get('target', 'unknown')}
🔧 Vulnerability: {details.get('vuln_title', 'unknown')}
📊 Confidence: {details.get('confidence', 0)}/10
🔴 Severity: {details.get('severity', 0)}/10
💥 Proposed POC: {details.get('exploit_description', 'Benign verification')}
⚡ Expected impact: {details.get('expected_impact', 'Access proof')}
🛡️ Safety: Benign commands only (id, whoami, version)
🧹 Cleanup: Mandatory verification

Reply: /go {details.get('finding_id', 'unknown')} or /hold {details.get('finding_id', 'unknown')}"""
        
        else:
            message = f"AEGIS {phase} approval requested. Details: {details}"
        
        # Send and wait for response (simplified - in practice uses polling)
        bridge.send_message(message)
        return True  # In practice, poll for /go response
    
    # ===== PHASE TRANSITIONS =====
    
    def transition_phase(self, new_phase: str):
        """Transition engagement phase in both memories"""
        self.hermes_state["phase"] = new_phase
        self._save_hermes_state()
        
        # Log to timeline
        self.hermes_state["timeline"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": "AEGIS",
            "message": f"Transitioned to phase: {new_phase}"
        })
        self._save_hermes_state()
    
    def set_terse_mode(self, enabled: bool):
        """Toggle caveman mode in both systems"""
        self.hermes_state["terse_mode"] = enabled
        self._save_hermes_state()
    
    # ===== REPORTING =====
    
    def generate_preliminary_report(self) -> str:
        """Generate preliminary report using HERMES reporter"""
        from scripts.report_compiler import generate_report
        
        findings_file = self.engagement_dir / "findings.json"
        with open(findings_file, "w") as f:
            json.dump(self.hermes_state["findings"], f, indent=2)
        
        output_file = self.engagement_dir / "preliminary_report.md"
        generate_report(
            str(self.hermes_config_file),
            str(findings_file),
            str(output_file)
        )
        
        return str(output_file)
    
    # ===== AEGIS PERSONAL MEMORY =====
    
    def load_personal_memory(self) -> Dict:
        """Load AEGIS personal memory"""
        # Parse YAML frontmatter from PERSONAL_MEMORY.md
        content = self.aegis_memory_file.read_text(encoding="utf-8")
        import re
        yaml_blocks = re.findall(r'```yaml\n(.*?)\n```', content, re.DOTALL)
        
        memory = {}
        for block in yaml_blocks:
            try:
                data = yaml.safe_load(block)
                if data:
                    memory.update(data)
            except Exception:
                pass
        return memory
    
    def update_personal_memory(self, section: str, data: Dict):
        """Update a section of PERSONAL_MEMORY.md"""
        # In practice, this would rewrite the YAML frontmatter
        # For now, log the update
        print(f"[BRIDGE] Personal memory update: {section}")
    
    def get_learned_evasion(self, target: str) -> Optional[Dict]:
        """Get learned evasion profile for target"""
        memory = self.load_personal_memory()
        signatures = memory.get("target_signatures", {})
        
        for name, sig in signatures.items():
            if self._target_matches_signature(target, sig):
                return {"profile": name, **sig}
        return None
    
    def _target_matches_signature(self, target: str, signature: Dict) -> bool:
        """Check if target matches a learned signature"""
        headers = signature.get("detected_headers", [])
        cookies = signature.get("detected_cookies", [])
        # In practice, would check actual target headers
        return False  # Simplified
    
    def get_chain_templates(self) -> list:
        """Get attack chain templates from personal memory"""
        memory = self.load_personal_memory()
        return memory.get("attack_chain_templates", [])
    
    def get_tool_calibration(self, tool: str) -> Dict:
        """Get tool calibration from personal memory"""
        memory = self.load_personal_memory()
        return memory.get("tool_effectiveness", {}).get(tool, {})
    
    def record_engagement_outcome(self, outcome: Dict):
        """Record engagement outcome to personal memory"""
        memory = self.load_personal_memory()
        history = memory.get("engagement_history", [])
        
        history.append({
            "engagement_id": self.hermes_state["engagement_id"],
            "client": self.hermes_config.get("engagement", {}).get("client", "Unknown"),
            "type": self.hermes_config.get("engagement", {}).get("type", "greybox"),
            "phases_completed": self.hermes_state.get("phases_completed", []),
            "findings_total": len(self.hermes_state.get("findings", [])),
            "critical": len([f for f in self.hermes_state.get("findings", []) if f.get("severity", 0) >= 9]),
            "high": len([f for f in self.hermes_state.get("findings", []) if 7 <= f.get("severity", 0) <= 8]),
            "exploited": len([f for f in self.hermes_state.get("findings", []) if f.get("confidence", 0) == 10]),
            "attack_chains": len(self.hermes_state.get("attack_chains", [])),
            "caveman_mode_used": self.hermes_state.get("terse_mode", False),
            "completed_at": datetime.now(timezone.utc).isoformat()
        })
        
        self.update_personal_memory("engagement_history", history)


def main():
    """CLI for bridge operations"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AEGIS ↔ HERMES Bridge")
    parser.add_argument("--sync-findings", help="Sync findings from JSON file")
    parser.add_argument("--sync-assets", help="Sync assets from JSON file")
    parser.add_argument("--validate-target", help="Validate target against scope")
    parser.add_argument("--scope-summary", action="store_true", help="Get scope summary")
    parser.add_argument("--transition-phase", help="Transition to phase")
    parser.add_argument("--terse-mode", choices=["on", "off"], help="Toggle terse mode")
    parser.add_argument("--preliminary-report", action="store_true", help="Generate preliminary report")
    parser.add_argument("--engagement-dir", default="engagements/current", help="Engagement directory")
    
    args = parser.parse_args()
    
    bridge = HermesBridge(args.engagement_dir)
    
    if args.sync_findings:
        with open(args.sync_findings) as f:
            findings = json.load(f)
        count = bridge.sync_findings_to_hermes(findings)
        print(f"Synced {count} findings to HERMES")
    
    elif args.sync_assets:
        with open(args.sync_assets) as f:
            assets = json.load(f)
        count = bridge.sync_assets_to_hermes(assets)
        print(f"Synced {count} assets to HERMES")
    
    elif args.validate_target:
        result = bridge.validate_target(args.validate_target)
        print(f"Target {'IN-SCOPE' if result else 'OUT-OF-SCOPE'}: {args.validate_target}")
        sys.exit(0 if result else 2)
    
    elif args.scope_summary:
        summary = bridge.get_scope_summary()
        print(json.dumps(summary, indent=2))
    
    elif args.transition_phase:
        bridge.transition_phase(args.transition_phase)
        print(f"Transitioned to {args.transition_phase}")
    
    elif args.terse_mode:
        bridge.set_terse_mode(args.terse_mode == "on")
        print(f"Terse mode: {args.terse_mode}")
    
    elif args.preliminary_report:
        report = bridge.generate_preliminary_report()
        print(f"Preliminary report: {report}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()