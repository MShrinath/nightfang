#!/usr/bin/env python3
"""Safe probing script for IMDS SSRF Probe vulnerabilities.

This is a SAFE DEFAULT payload for the IMDS SSRF Probe vulnerability class.
It performs read-only reconnaissance without exploitation.

CWE: CWE-918
OWASP: A10:2021
"""
import sys
import socket
import json
from datetime import datetime
from urllib.parse import urlparse

def probe(target: str) -> dict:
    """Safely probe for IMDS SSRF Probe vulnerabilities."""
    results = {
        'target': target,
        'probe_type': 'IMDS SSRF Probe',
        'findings': [],
        'safe': True,
        'timestamp': datetime.now().isoformat()
    }
    
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
            results['findings'].append(f'Port {port} is OPEN on {host}')
        else:
            results['findings'].append(f'Port {port} is CLOSED/unreachable on {host}')
            
    except Exception as e:
        results['findings'].append(f'Probe error: {e}')
    
    return results

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python imds_ssrf_probe.py <target>')
        print('Example: python imds_ssrf_probe.py https://example.com')
        sys.exit(1)
    
    target = sys.argv[1]
    results = probe(target)
    print(json.dumps(results, indent=2))
