#!/usr/bin/env python3
"""Safe probing script for SSL/TLS Downgrade vulnerabilities.

This is a SAFE DEFAULT payload for the SSL/TLS Downgrade vulnerability class.
It performs read-only reconnaissance without exploitation.

CWE: N/A
OWASP: A02:2021
"""
import sys
import socket
import ssl
import json
from datetime import datetime

def probe(target: str) -> dict:
    """Safely probe for SSL/TLS downgrade vulnerabilities."""
    results = {
        "target": target,
        "probe_type": "SSL/TLS Downgrade Probe",
        "findings": [],
        "safe": True,
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        # Check if SSL/TLS protocols are supported
        protocols = [
            ("SSLv3", ssl.PROTOCOL_SSLv23),  # Deprecated
            ("TLSv1", ssl.PROTOCOL_TLSv1),
            ("TLSv1_1", ssl.PROTOCOL_TLSv1_1),
            ("TLSv1_2", ssl.PROTOCOL_TLSv1_2),
            ("TLSv1_3", ssl.PROTOCOL_TLS),
        ]
        
        for name, proto in protocols:
            try:
                ctx = ssl.create_default_context()
                if proto != ssl.PROTOCOL_TLS:
                    ctx.minimum_version = proto
                sock = socket.create_connection((target, 443), timeout=5)
                ssl_sock = ctx.wrap_socket(sock, server_hostname=target)
                ssl_sock.close()
                results["findings"].append(f"{name} is ACCEPTABLE on {target}")
            except Exception as e:
                results["findings"].append(f"{name} REJECTED or not supported")
                
    except Exception as e:
        results["findings"].append(f"Probe error: {e}")
    
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ssl_tls_downgrade_probe_probe.py <target>")
        print("Example: python ssl_tls_downgrade_probe_probe.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    results = probe(target)
    print(json.dumps(results, indent=2))
