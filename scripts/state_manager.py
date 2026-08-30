#!/usr/bin/env python3
"""
OPENCLAW / HERMES — State & Memory Manager
Handles real-time persistence, asset inventory, findings logging, operator decision audits, and engagement timelines.
"""

import sys
import json
import os
from datetime import datetime, timezone
from pathlib import Path

class EngagementStateManager:
    def __init__(self, engagement_dir: str = "engagements/current"):
        self.engagement_dir = Path(engagement_dir)
        self.engagement_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.engagement_dir / "session_state.json"
        self.state = self._load_state()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _load_state(self) -> dict:
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
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

    def save(self):
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=2)

    def set_phase(self, phase_name: str):
        self.state["phase"] = phase_name
        self.log_timeline("HERMES", f"Transitioned to phase: {phase_name}")
        self.save()

    def set_terse_mode(self, enabled: bool):
        self.state["terse_mode"] = enabled
        self.log_timeline("HERMES", f"Caveman/Terse mode set to: {enabled}")
        self.save()

    def register_asset(self, host: str, ip: str = None, ports: list = None, services: list = None):
        if host not in self.state["assets"]:
            self.state["assets"][host] = {
                "ip": ip or host,
                "ports": ports or [],
                "services": services or [],
                "status": "discovered",
                "timestamp": self._now()
            }
        else:
            if ports:
                existing = set(self.state["assets"][host]["ports"])
                self.state["assets"][host]["ports"] = list(existing.union(ports))
            if services:
                existing_svc = set(self.state["assets"][host]["services"])
                self.state["assets"][host]["services"] = list(existing_svc.union(services))
        self.save()

    def add_finding(self, title: str, target: str, vuln_type: str, confidence: int, severity: int,
                    description: str = "", attack_id: str = "T1190", d3fend_id: str = "D3-PSA") -> str:
        count = len(self.state["findings"]) + 1
        finding_id = f"HERMES-{count:03d}"
        finding = {
            "id": finding_id,
            "title": title,
            "target": target,
            "type": vuln_type,
            "confidence": confidence,
            "severity": severity,
            "mitre_attack": attack_id,
            "d3fend": d3fend_id,
            "status": "Confirmed" if confidence >= 7 else "Suspected",
            "description": description,
            "discovered_at": self._now()
        }
        self.state["findings"].append(finding)
        self.log_timeline("SCANNER", f"Discovered finding {finding_id}: {title} (Conf: {confidence}, Sev: {severity})")
        self.save()
        return finding_id

    def record_decision(self, finding_id: str, action: str, operator_decision: str, notes: str = ""):
        decision_entry = {
            "timestamp": self._now(),
            "finding_id": finding_id,
            "action": action,
            "decision": operator_decision,
            "notes": notes
        }
        self.state["decisions"].append(decision_entry)
        self.log_timeline("OPERATOR", f"Decision for {finding_id}: {operator_decision.upper()}")
        self.save()

    def log_timeline(self, actor: str, message: str):
        self.state["timeline"].append({
            "timestamp": self._now(),
            "actor": actor,
            "message": message
        })

if __name__ == "__main__":
    mgr = EngagementStateManager()
    print(f"[*] OPENCLAW State Manager Initialized: Engagement {mgr.state['engagement_id']}")
    print(f"[*] Current Phase: {mgr.state['phase']} | Assets: {len(mgr.state['assets'])} | Findings: {len(mgr.state['findings'])}")
