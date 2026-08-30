#!/usr/bin/env python3
"""
OPENCLAW / HERMES — Multi-Channel Notifier & Issue Tracker Bridge
Dispatches validated vulnerability findings to Slack, Discord, Microsoft Teams, Jira, and GitHub.
"""

import sys
import json
import logging
import urllib.request
import urllib.error
import yaml
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class MultiChannelNotifier:
    def __init__(self, config_path: str):
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)
            
        self.integrations = self.config.get("integrations", {})

    def send_slack_webhook(self, webhook_url: str, finding: dict) -> bool:
        sev_color = "#e01e5a" if finding.get("severity", 1) >= 7 else "#ecb22e"
        payload = {
            "attachments": [
                {
                    "color": sev_color,
                    "title": f"🦅 HERMES Alert: Finding #{finding.get('id', 'N/A')} - {finding.get('title')}",
                    "fields": [
                        {"title": "Target", "value": f"`{finding.get('target')}`", "short": True},
                        {"title": "Severity", "value": f"{finding.get('severity')}/10", "short": True},
                        {"title": "Confidence", "value": f"{finding.get('confidence')}/10", "short": True},
                        {"title": "MITRE ATT&CK", "value": f"`{finding.get('mitre_attack', 'N/A')}`", "short": True},
                        {"title": "D3FEND Defense", "value": f"`{finding.get('d3fend', 'N/A')}`", "short": True},
                        {"title": "Summary", "value": finding.get('description', 'N/A'), "short": False}
                    ],
                    "footer": "OPENCLAW / HERMES Autonomous Pentest Swarm"
                }
            ]
        }
        return self._post_json(webhook_url, payload)

    def send_discord_webhook(self, webhook_url: str, finding: dict) -> bool:
        sev_color = 0xEE220C if finding.get("severity", 1) >= 7 else 0xFEE75C
        payload = {
            "embeds": [
                {
                    "title": f"🦅 Finding #{finding.get('id')} — {finding.get('title')}",
                    "color": sev_color,
                    "fields": [
                        {"name": "Target", "value": f"`{finding.get('target')}`", "inline": True},
                        {"name": "Severity", "value": f"🔴 {finding.get('severity')}/10", "inline": True},
                        {"name": "Confidence", "value": f"📊 {finding.get('confidence')}/10", "inline": True},
                        {"name": "MITRE ATT&CK", "value": f"`{finding.get('mitre_attack', 'N/A')}`", "inline": True},
                        {"name": "D3FEND Countermeasure", "value": f"`{finding.get('d3fend', 'N/A')}`", "inline": True},
                        {"name": "Description", "value": finding.get('description', 'N/A'), "inline": False}
                    ],
                    "footer": {"text": "OPENCLAW / HERMES Pentest Framework"}
                }
            ]
        }
        return self._post_json(webhook_url, payload)

    def _post_json(self, url: str, data: dict) -> bool:
        try:
            req_data = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "OPENCLAW-HERMES/2.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as res:
                return res.status in (200, 204)
        except Exception as e:
            logging.error(f"Webhook dispatch failed: {e}")
            return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python multi_channel_notifier.py <config.yaml> <finding.json>")
        sys.exit(1)
        
    conf_file = sys.argv[1]
    finding_file = sys.argv[2]
    
    with open(finding_file, "r", encoding="utf-8") as f:
        finding_data = json.load(f)
        
    notifier = MultiChannelNotifier(conf_file)
    print(f"[*] Dispatching finding #{finding_data.get('id')} to configured channels...")
