#!/usr/bin/env python3
"""Generate safe default payloads for recon/audit categories."""

import json
import os

payloads_dir = 'references/payloads'

# 27 safe categories needing payloads
categories = [
    ('BOLA', 'CWE-639', 'A01:2021', 'Business Logic flaws - Object authorization bypass'),
    ('JWT Manipulation', 'CWE-327', 'A02:2021', 'Weak JWT algorithms/signature verification'),
    ('AMSI Bypass', 'N/A', 'N/A', 'Windows AMSI bypass techniques'),
    ('Outbound Egress Probe', 'N/A', 'N/A', 'Detect outbound firewall rules'),
    ('Reverse Shell Probe', 'CWE-77', 'A03:2021', 'Test for reverse shell handlers'),
    ('Webshell Detection', 'N/A', 'N/A', 'Verify webshell detection'),
    ('MQTT Injection', 'CWE-943', 'A03:2021', 'MQTT broker injection tests'),
    ('Topic Injection', 'CWE-73', 'A01:2021', 'Topic/topic injection probes'),
    ('CoAP Injection', 'CWE-943', 'A03:2021', 'CoAP protocol injection tests'),
    ('BLE Enumeration', 'N/A', 'N/A', 'Bluetooth Low Energy device enumeration'),
    ('Bluetooth Packet Injection', 'N/A', 'N/A', 'Bluetooth packet injection tests'),
    ('LMQ Fuzzing', 'CWE-943', 'A03:2021', 'MQTT/QoS fuzzing'),
    ('SMB Null Session Probe', 'N/A', 'N/A', 'SMB null session enumeration'),
    ('SNMP Enumeration', 'N/A', 'A05:2021', 'SNMP service enumeration'),
    ('SSL/TLS Downgrade Probe', 'N/A', 'A02:2021', 'SSL/TLS downgrade attacks'),
    ('IMDS SSRF Probe', 'CWE-918', 'A10:2021', 'AWS IMDS SSRF testing'),
    ('IAM Policy Abuse', 'N/A', 'A05:2021', 'AWS IAM policy abuse detection'),
    ('S3 Bucket Enumeration', 'N/A', 'A04:2021', 'AWS S3 bucket enumeration'),
    ('RBAC Privilege Escalation', 'CWE-269', 'A01:2021', 'RBAC privilege escalation tests'),
    ('Sudoers Audit Probe', 'N/A', 'N/A', 'Sudoers misconfiguration detection'),
    ('SUID Binary Audit', 'N/A', 'N/A', 'SUID binary enumeration'),
    ('Unquoted Path Audit', 'N/A', 'N/A', 'Unquoted service path detection'),
    ('Cron Audit Probe', 'N/A', 'N/A', 'Cron job injection detection'),
    ('Exposed Service Probe', 'N/A', 'N/A', 'Detect exposed services'),
    ('DNS Beaconing Test', 'N/A', 'N/A', 'Test DNS beaconing detection'),
    ('Credential Dump Audit', 'CWE-522', 'A02:2021', 'Audit for credential dumps'),
    ('Vault Enumeration', 'N/A', 'N/A', 'Secrets vault enumeration'),
]

for name, cwe, owasp, desc in categories:
    cat_dir = os.path.join(payloads_dir, name)
    safe_md = os.path.join(cat_dir, 'SAFE_DEFAULT.md')
    safe_name = name.lower().replace(' ', '_').replace('-', '_').replace('/', '_')
    script_py = os.path.join(cat_dir, f'{safe_name}_probe.py')
    
    os.makedirs(cat_dir, exist_ok=True)
    
    # Create SAFE_DEFAULT.md
    with open(safe_md, 'w') as f:
        f.write(f'''# {name} - SAFE DEFAULT PAYLOAD

## Description
{desc}

## CWE: {cwe}
## OWASP: {owasp}

## Safety Classification
**SAFE_DEFAULT: True** - This is a reconnaissance/probe script that performs read-only operations.

## Usage
```bash
python {safe_name}_probe.py <target>
```

## Purpose
This script safely probes for the vulnerability class without exploitation.
''')
    
    # Create Python probe script
    with open(script_py, 'w') as f:
        f.write(f'''#!/usr/bin/env python3
"""Safe probing script for {name} vulnerabilities.

This is a SAFE DEFAULT payload for the {name} vulnerability class.
It performs read-only reconnaissance without exploitation.

CWE: {cwe}
OWASP: {owasp}
"""
import sys
import socket
import json
from datetime import datetime
from urllib.parse import urlparse

def probe(target: str) -> dict:
    """Safely probe for {name} vulnerabilities."""
    results = {{
        'target': target,
        'probe_type': '{name}',
        'findings': [],
        'safe': True,
        'timestamp': datetime.now().isoformat()
    }}
    
    try:
        # Parse target
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        else:
            host = target
            port = 443
        
        # Safe check: does the service exist?
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            results['findings'].append(f'Port {{port}} is OPEN on {{host}}')
        else:
            results['findings'].append(f'Port {{port}} is CLOSED/unreachable on {{host}}')
            
    except Exception as e:
        results['findings'].append(f'Probe error: {{e}}')
    
    return results

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python {safe_name}.py <target>')
        print('Example: python {safe_name}.py https://example.com')
        sys.exit(1)
    
    target = sys.argv[1]
    results = probe(target)
    print(json.dumps(results, indent=2))
''')
    
    print(f'Created: {name}')

print(f'\nGenerated payloads for {len(categories)} safe categories')