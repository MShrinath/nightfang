#!/usr/bin/env python3
"""
OPENCLAW / HERMES — Telegram HITL Bridge Script
Provides a lightweight Telegram bot bridge for Human-in-the-Loop operator approvals and alerts.
Fully integrates with .env and environment variable interpolation.
"""

import os
import sys
import json
import logging
from pathlib import Path

# Auto-import env_loader
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from env_loader import load_config, load_env
except ImportError:
    def load_config(p): return {}
    def load_env(): pass

try:
    import requests
except ImportError:
    print("[-] Please install requests: pip install requests")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class TelegramHITLBridge:
    def __init__(self, config_path: str = "config/engagement_template.yaml"):
        load_env()
        self.config = load_config(config_path)
            
        tg_conf = self.config.get("telegram", {})
        # Prioritize config (interpolated with .env), fallback directly to os.environ
        self.token = tg_conf.get("bot_token") or os.environ.get("TELEGRAM_BOT_TOKEN")
        self.chat_id = tg_conf.get("chat_id") or os.environ.get("TELEGRAM_CHAT_ID")
        self.base_url = f"https://api.telegram.org/bot{self.token}"

    def send_message(self, text: str) -> bool:
        if not self.token or not self.chat_id:
            logging.warning("Telegram token or chat_id not configured in .env or config YAML.")
            return False
            
        url = f"{self.base_url}/sendMessage"
        payload = {
            "chat_id": str(self.chat_id),
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
        """Polls for latest operator command (/go, /hold, /stop, /status, /terse)"""
        if not self.token:
            return None
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
    bridge = TelegramHITLBridge()
    print("[*] OPENCLAW / HERMES Telegram HITL Bridge Initialized.")
    if bridge.token and bridge.chat_id:
        masked_token = bridge.token[:6] + "..." if len(bridge.token) > 6 else "(set)"
        print(f"[+] Loaded Telegram credentials from .env / config (Token: {masked_token}, Chat ID: {bridge.chat_id})")
    else:
        print("[!] Warning: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not found in .env or config.")
        
    if len(sys.argv) > 2 and sys.argv[1] == "--send":
        msg = sys.argv[2]
        bridge.send_message(msg)
        print("[+] Message dispatched.")
