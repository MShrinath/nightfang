#!/usr/bin/env python3
"""Ingest PayloadsAllTheThings into a structured catalog for nightfang.

Creates references/payloads/index.json mapping:
vuln_class -> {
    cwe: str,
    owasp: str,
    safe_default: bool,
    payload_files: [rel_path_to_ref_repo]
}
"""
import os, json

PAYLOADS = os.environ.get(
    "NIGHTFANG_PAYLOADS_REF",
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "..", "refs", "payloadsallthethings"
    )
)
OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "references", "payloads"
)

# Mapping to help agents map payloads to standards
# This is a baseline; agents should refine this via CTI/GRC workflows.
VULN_MAP = {
    # --- Destructive (safe=False) ---
    "SQL Injection": {"cwe": "CWE-89", "owasp": "A03:2021", "safe": False},
    "Server Side Template Injection": {"cwe": "CWE-94", "owasp": "A03:2021", "safe": False},
    "Server Side Request Forgery": {"cwe": "CWE-918", "owasp": "A10:2021", "safe": False},
    "Command Injection": {"cwe": "CWE-77", "owasp": "A03:2021", "safe": False},
    "File Inclusion": {"cwe": "CWE-22", "owasp": "A01:2021", "safe": False},
    "SSRF Probe": {"cwe": "CWE-918", "owasp": "A10:2021", "safe": False},
    "Credential Dump": {"cwe": "CWE-522", "owasp": "A02:2021", "safe": False},
    "Privilege Escalation": {"cwe": "CWE-269", "owasp": "A01:2021", "safe": False},
    
    # --- Safe for testing (safe=True) ---
    "XSS Injection": {"cwe": "CWE-79", "owasp": "A03:2021", "safe": True},
    "Directory Traversal": {"cwe": "CWE-22", "owasp": "A01:2021", "safe": True},
    "Client Side Path Traversal": {"cwe": "CWE-22", "owasp": "A01:2021", "safe": True},
    "CORS Misconfiguration": {"cwe": "N/A", "owasp": "A05:2021", "safe": True},
    "Clickjacking": {"cwe": "N/A", "owasp": "A07:2021", "safe": True},
    "DNS Rebinding": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "Race Condition": {"cwe": "CWE-362", "owasp": "A01:2021", "safe": True},
    "JSON Web Token": {"cwe": "CWE-327", "owasp": "A02:2021", "safe": True},
    "Insecure Direct Object References": {"cwe": "CWE-639", "owasp": "A01:2021", "safe": True},
    "BOLA": {"cwe": "CWE-639", "owasp": "A01:2021", "safe": True},
    "JWT Manipulation": {"cwe": "CWE-327", "owasp": "A02:2021", "safe": True},
    "AMSI Bypass": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "Outbound Egress Probe": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "LDAP Injection": {"cwe": "CWE-90", "owasp": "A03:2021", "safe": True},
    "NoSQL Injection": {"cwe": "CWE-89", "owasp": "A03:2021", "safe": True},
    "Command Injection": {"cwe": "CWE-77", "owasp": "A03:2021", "safe": True},  # Probe variant only
    "Reverse Shell Probe": {"cwe": "CWE-77", "owasp": "A03:2021", "safe": True},
    "Webshell Detection": {"cwe": "N/A", "owasp": "N/A", "safe": True},

    # --- IoT/Protocol Specific (safe=True for recon/probe) ---
    "MQTT Injection": {"cwe": "CWE-943", "owasp": "A03:2021", "safe": True},
    "Topic Injection": {"cwe": "CWE-73", "owasp": "A01:2021", "safe": True},
    "CoAP Injection": {"cwe": "CWE-943", "owasp": "A03:2021", "safe": True},
    "BLE Enumeration": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "Bluetooth Packet Injection": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "LMQ Fuzzing": {"cwe": "CWE-943", "owasp": "A03:2021", "safe": True},
    "SMB Null Session Probe": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "SNMP Enumeration": {"cwe": "N/A", "owasp": "A05:2021", "safe": True},
    "SSL/TLS Downgrade Probe": {"cwe": "N/A", "owasp": "A02:2021", "safe": True},
    "IMDS SSRF Probe": {"cwe": "CWE-918", "owasp": "A10:2021", "safe": True},
    "IAM Policy Abuse": {"cwe": "N/A", "owasp": "A05:2021", "safe": True},
    "S3 Bucket Enumeration": {"cwe": "N/A", "owasp": "A04:2021", "safe": True},
    "RBAC Privilege Escalation": {"cwe": "CWE-269", "owasp": "A01:2021", "safe": True},
    "Sudoers Audit Probe": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "SUID Binary Audit": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "Unquoted Path Audit": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "Cron Audit Probe": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "Exposed Service Probe": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "DNS Beaconing Test": {"cwe": "N/A", "owasp": "N/A", "safe": True},
    "Credential Dump Audit": {"cwe": "CWE-522", "owasp": "A02:2021", "safe": True},
    "Vault Enumeration": {"cwe": "N/A", "owasp": "N/A", "safe": True},
}

def main():
    os.makedirs(OUT, exist_ok=True)
    catalog = {}

    # Phase 1: Process existing payload directories in the payloads repository
    for entry in sorted(os.listdir(PAYLOADS)):
        if entry.startswith(("._",)):
            continue
        
        path = os.path.join(PAYLOADS, entry)
        if not os.path.isdir(path):
            continue

        meta = VULN_MAP.get(entry, {"cwe": "N/A", "owasp": "N/A", "safe": False})
        
        # Discover md/txt/payload files
        files = []
        for root, _, fs in os.walk(path):
            for f in fs:
                if f.endswith((".md", ".txt", ".js", ".py", ".sh")):
                    rel = os.path.relpath(os.path.join(root, f), PAYLOADS)
                    files.append(rel)
        
        catalog[entry] = {
            "cwe": meta["cwe"],
            "owasp": meta["owasp"],
            "safe_default": meta["safe"],
            "payload_files": files
        }

    # Phase 2: Process nightfang-generated safe payloads (SAFE_DEFAULT.md files)
    for entry in sorted(os.listdir(OUT)):
        if entry.startswith(("._",)):
            continue
        
        path = os.path.join(OUT, entry)
        if not os.path.isdir(path):
            continue
        
        # Check if this category exists in catalog, if not add it
        if entry not in catalog:
            meta = VULN_MAP.get(entry, {"cwe": "N/A", "owasp": "N/A", "safe": False})
            catalog[entry] = {
                "cwe": meta["cwe"],
                "owasp": meta["owasp"],
                "safe_default": meta["safe"],
                "payload_files": []
            }
        
        # Add nightsfang payload files to existing entries
        for root, _, fs in os.walk(path):
            for f in fs:
                if f.endswith((".md", ".py", ".txt", ".js", ".sh")):
                    rel = os.path.relpath(os.path.join(root, f), OUT)
                    if rel not in catalog[entry]["payload_files"]:
                        catalog[entry]["payload_files"].append(rel)

    # Phase 3: Add entries from VULN_MAP that don't exist anywhere
    for vuln_class, meta in VULN_MAP.items():
        if vuln_class not in catalog:
            catalog[vuln_class] = {
                "cwe": meta["cwe"],
                "owasp": meta["owasp"],
                "safe_default": meta["safe"],
                "payload_files": []
            }

    with open(os.path.join(OUT, "index.json"), "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)
    print(f"Payload catalog written: {len(catalog)} classes")

if __name__ == "__main__":
    main()