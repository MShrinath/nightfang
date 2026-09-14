#!/usr/bin/env python3
"""
NIGHTFANG — Zero-Dependency Environment & Config Loader
Loads .env variables and dynamically resolves ${VAR_NAME} references in YAML/JSON configs.
Includes a built-in fallback parser if PyYAML is not installed.
"""

import os
import re
import json
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

def load_env(env_path: str = ".env"):
    """Parses .env file and loads keys into os.environ if not already present."""
    p = Path(env_path)
    if not p.exists():
        p = Path(__file__).resolve().parent.parent / ".env"
    if not p.exists():
        p = Path(__file__).resolve().parent.parent / ".env.example"
    
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k not in os.environ:
                    os.environ[k] = v

def _substitute_env_vars(obj):
    """Recursively replaces ${VAR_NAME} or ${VAR_NAME:default} with environment variables."""
    if isinstance(obj, str):
        pattern = re.compile(r"\$\{([A-Za-z0-9_]+)(?::([^}]*))?\}")
        def repl(match):
            var_name = match.group(1)
            default_val = match.group(2) if match.group(2) is not None else ""
            val = os.environ.get(var_name, default_val)
            if val.lower() == "true": return "true"
            if val.lower() == "false": return "false"
            return val
        return pattern.sub(repl, obj)
    elif isinstance(obj, dict):
        return {k: _substitute_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_substitute_env_vars(elem) for elem in obj]
    return obj

def _simple_yaml_parser(text: str) -> dict:
    """Lightweight fallback parser for basic YAML key-value hierarchies when PyYAML is unavailable."""
    result = {}
    stack = [result]
    indent_levels = [-1]
    
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        
        indent = len(line) - len(line.lstrip())
        while indent_levels and indent <= indent_levels[-1]:
            stack.pop()
            indent_levels.pop()
            
        current = stack[-1]
        
        if ":" in stripped:
            key, val = stripped.split(":", 1)
            key = key.strip().strip("- ")
            val = val.strip()
            
            if not val or val.startswith("#"):
                new_dict = {}
                if isinstance(current, dict):
                    current[key] = new_dict
                stack.append(new_dict)
                indent_levels.append(indent)
            else:
                clean_val = val.split("#")[0].strip().strip('"').strip("'")
                if isinstance(current, dict):
                    current[key] = clean_val
        elif stripped.startswith("- "):
            item = stripped[2:].strip().strip('"').strip("'")
            if isinstance(current, list):
                current.append(item)
            elif isinstance(current, dict) and current:
                last_key = list(current.keys())[-1]
                if not isinstance(current[last_key], list):
                    current[last_key] = []
                current[last_key].append(item)
                
    return result

def load_config(config_path: str) -> dict:
    """Loads a configuration file with full .env interpolation."""
    load_env()
    p = Path(config_path)
    if not p.exists():
        p = Path(__file__).resolve().parent.parent / config_path
    
    if not p.exists():
        return {}
        
    with open(p, "r", encoding="utf-8") as f:
        content = f.read()
        
    if HAS_YAML:
        raw = yaml.safe_load(content) or {}
    else:
        raw = _simple_yaml_parser(content)
        
    return _substitute_env_vars(raw)

if __name__ == "__main__":
    load_env()
    print("[+] NIGHTFANG Environment & Config Loader verified (Zero external dependencies).")
    cfg = load_config("config/engagement_template.yaml")
    print(f"[+] Loaded config test: telegram bot token -> {cfg.get('telegram', {}).get('bot_token', 'N/A')}")
    print(f"[+] Active keys detected:")
    for k in sorted(os.environ.keys()):
        if any(term in k for term in ["TELEGRAM", "SHODAN", "SLACK", "JIRA", "NIGHTFANG"]):
            val = os.environ[k][:4] + "..." if len(os.environ[k]) > 4 else "(set)"
            print(f"  • {k}: {val}")
