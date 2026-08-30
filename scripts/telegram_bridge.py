#!/usr/bin/env python3
"""
OPENCLAW / HERMES — Telegram HITL Bridge Script
Provides a lightweight Telegram bot bridge for Human-in-the-Loop operator approvals and alerts.
"""

import sys
import json
import logging
import yaml
from pathlib import Path

try:
    import requests
except ImportError:
    print("[-] Please install requests: pip install requests")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class TelegramHITLBridge:
    def __init__(self, config_path: str):
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)
            
        tg_conf = self.config.get("telegram", {})
        self.token = tg_conf.get("bot_token")
        self.chat_id = tg_conf.get("chat_id")
        self.base_url = f"https://api.telegram.org/bot{self.token}"

    def send_message(self, text: str) -> bool:
        if not self.token or not self.chat_id:
            logging.warning("Telegram token or chat_id not configured in config YAML.")
            return False
            
        url = f"{self.base_url}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        try:
            res = requests.post(url, json=payload, timeout=10)
            return res.status_code == 200
        except Exception as e:
            logging.error(f"Failed to send Telegram message: {e}")
            return False

    def get_latest_command(self) -> str | None:
        """Polls for latest operator command (/go, /hold, /stop, /status)"""
        url = f"{self.base_url}/getUpdates"
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                updates = res.json().get("result", [])
                if updates:
                    latest = updates[-1]
                    return latest.get("message", {}).get("text")
        except Exception as e:
            logging.error(f"Failed to retrieve updates: {e}")
        return None

if __name__ == "__main__":
    print("[*] OPENCLAW / HERMES Telegram HITL Bridge Initialized.")
    if len(sys.argv) > 2 and sys.argv[1] == "--send":
        config_path = "config/engagement_template.yaml"
        bridge = TelegramHITLBridge(config_path)
        msg = sys.argv[2]
        bridge.send_message(msg)
        print("[+] Message dispatched.")
