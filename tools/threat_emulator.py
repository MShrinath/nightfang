#!/usr/bin/env python3
"""
NIGHTFANG Threat Emulation Agent — MITRE ATT&CK Technique Runner & Campaign Planner
Specializes in automated adversarial behavior simulation mapped to MITRE ATT&CK
tactics, techniques, and sub-techniques.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional


class AttackTactic(str, Enum):
    INIT_ACCESS = "T1"         # Initial Access
    EXECUTION = "T2"            # Execution
    PERSISTENCE = "T3"          # Persistence
    PRIVESC = "T4"              # Privilege Escalation
    DEF_EVASION = "T5"          # Defense Evasion
    CREDENTIAL_ACCESS = "T6"   # Credential Access
    DISCOVERY = "T7"           # Discovery
    LATERAL = "T8"             # Lateral Movement
    COLLECTION = "T9"          # Collection
    COMMAND_CTRL = "T10"       # Command and Control
    EXFIL = "T11"              # Exfiltration
    IMPACT = "T12"             # Impact


@dataclass
class AttackerTechnique:
    """Single ATT&CK technique definition."""
    tactic: str
    technique_id: str
    name: str
    description: str
    detection_difficulty: int    # 1=easy detect, 10=hard detect
    mitigation_ease: int         # 1=hard to mitigate, 10=easy
    safe_poc_available: bool
    required_permissions: str


class ThreatEmulatorAgent:
    """Simulates adversary behaviors using non-destructive PoC techniques."""

    KNOWN_TECHNIQUES: Dict[str, AttackerTechnique] = {
        "T1083": AttackerTechnique(
            "discovery", "T1083", "File/Directory Discovery",
            "Enumerate files and directories on target", 10, 9, True, "low"
        ),
        "T1078": AttackerTechnique(
            "initial_access", "T1078", "Valid Accounts",
            "Use legitimate credentials for access", 8, 5, False, "medium"
        ),
        "T1059": AttackerTechnique(
            "execution", "T1059", "Command & Scripting Interpreter",
            "Run commands via shell or scripting host", 9, 4, True, "none"
        ),
        "T1566": AttackerTechnique(
            "initial_access", "T1566", "Phishing",
            "Deliver malicious payloads via phishing", 10, 7, False, "any"
        ),
        "T1071": AttackerTechnique(
            "command_ctrl", "T1071", "Application Layer Protocol",
            "C2 over HTTP/S/DNS, etc.", 7, 6, True, "network"
        ),
        "T1041": AttackerTechnique(
            "exfiltration", "T1041", "Exfiltration Over C2 Channel",
            "Data exfil over established C2 channel", 7, 6, False, "network"
        ),
        "T1562": AttackerTechnique(
            "defense_evasion", "T1562", "Impair Defenses",
            "Disable/disable logging or security tools", 9, 3, False, "admin"
        ),
        "T1082": AttackerTechnique(
            "discovery", "T1082", "System Information Discovery",
            "Gather OS, version, architecture info", 10, 9, True, "low"
        ),
        "T1069": AttackerTechnique(
            "discovery", "T1069", "Permission Groups Discovery",
            "Enumerate local/group permissions", 9, 8, True, "low"
        ),
        "T1553": AttackerTechnique(
            "defense_evasion", "T1553", "Subvert Trust Controls",
            "Bypass code signing, AMSI bypass attempts", 9, 4, False, "high"
        ),
        "T1003": AttackerTechnique(
            "credential_access", "T1003", "OS Credential Dumping",
            "lsass/memory dump techniques (read-only)", 10, 5, False, "admin"
        ),
        "T1021": AttackerTechnique(
            "lateral_movement", "T1021", "Remote Services",
            "SMB/RDP/WinRM lateral movement probes", 7, 5, True, "network"
        ),
    }

    def __init__(self, engagement_id: str, scope_domains: List[str]):
        self.engagement_id = engagement_id
        self.scope_domains = scope_domains
        self.executed_techniques: List[Dict] = []

    def get_technique(self, tech_id: str) -> Optional[AttackerTechnique]:
        return self.KNOWN_TECHNIQUES.get(tech_id)

    def generate_campaign(self, tactic: Optional[str] = None, max_techniques: int = 5) -> List[Dict]:
        """Generate a non-destructive attack campaign mapped to ATT&CK."""
        pool = list(self.KNOWN_TECHNIQUES.values())
        if tactic:
            pool = [t for t in pool if t.tactic == tactic]
        campaign = []
        for tech in sorted(pool, key=lambda x: (-x.detection_difficulty + x.mitigation_ease))[:max_techniques]:
            if tech.safe_poc_available:
                campaign.append({
                    "technique_id": tech.technique_id,
                    "name": tech.name,
                    "tactic": tech.tactic,
                    "description": tech.description,
                    "safe_poc": f"[SAFE_POC] Simulate {tech.name} via benign probe",
                    "detection_risk": tech.detection_difficulty,
                })
        return campaign

    def build_emulation_task(self, tech_id: str) -> Dict:
        """Build an emulation task for the Daemon queue."""
        tech = self.KNOWN_TECHNIQUES.get(tech_id)
        if not tech:
            raise ValueError(f"Unknown technique: {tech_id}")
        return {
            "task_type": "emulation",
            "technique_id": tech_id,
            "technique_name": tech.name,
            "campaign_id": self.engagement_id,
            "noise_level": "QUIET" if tech.safe_poc_available else "MODERATE",
            "required_approval": not tech.safe_poc_available,
            "expected_output": "attacker_behavior_report",
        }


if __name__ == "__main__":
    agent = ThreatEmulatorAgent("ENG-TEST", ["target.corp"])
    print("=== Available Techniques ===")
    for tid, tech in agent.KNOWN_TECHNIQUES.items():
        flag = "SAFE" if tech.safe_poc_available else "HITL"
        print(f"  {tid} [{flag}] {tech.name}")
    print("\n=== Sample Campaign (Discovery Tactic) ===")
    camp = agent.generate_campaign(tactic="discovery", max_techniques=5)
    for entry in camp:
        print(f"  {entry['technique_id']}: {entry['name']} (detection risk: {entry['detection_risk']}/10)")
