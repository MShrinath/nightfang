#!/usr/bin/env python3
"""Fix references/payloads/index.json: backslashes, space dirs, dangling refs."""
import json
from pathlib import Path

path = Path("references/payloads/index.json")
with open(path, encoding="utf-8") as f:
    data = json.load(f)


def fix_backslashes(obj):
    if isinstance(obj, str):
        return obj.replace("\\", "/")
    elif isinstance(obj, list):
        return [fix_backslashes(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: fix_backslashes(v) for k, v in obj.items()}
    return obj


data = fix_backslashes(data)

# Rename space-separated dirs to kebab-case
renames = {
    "AMSI Bypass": "amis-bypass",
    "Cron Audit Probe": "cron-audit-probe",
    "Exposed Service Probe": "exposed-service-probe",
    "IMDS SSRF Probe": "imds-ssrf-probe",
    "Outbound Egress Probe": "outbound-egress-probe",
    "Reverse Shell Probe": "reverse-shell-probe",
    "SMB Null Session Probe": "smb-null-session-probe",
    "Sudoers Audit Probe": "sudoers-audit-probe",
    "SUID Binary Audit": "suid-binary-audit",
}
for old, new in renames.items():
    if old in data:
        data[new] = data.pop(old)

# Remove entries whose source dir no longer exists on disk
refs_dir = path.parent
existing_dirs = {d.name for d in refs_dir.iterdir() if d.is_dir() and not d.name.startswith(".")}
orphaned = [k for k in data.keys() if k not in existing_dirs and not k.startswith(".") and k != "__deleted"]
for k in orphaned:
    print(f"  [REMOVED] {k} (source dir missing)")
    del data[k]

with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f"Fixed. {len(data)} categories remaining.")
