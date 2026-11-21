# SSL/TLS Downgrade Probe - SAFE DEFAULT PAYLOAD

## Description
SSL/TLS downgrade attacks - testing for TLS 1.0/1.1 acceptance, SSLv2/v3 support

## CWE: N/A
## OWASP: A02:2021

## Safety Classification
**SAFE_DEFAULT: True** - This is a reconnaissance/probe script that performs read-only operations.

## Usage
```bash
python ssl_tls_downgrade_probe_probe.py <target>
```

## Purpose
This script safely probes for SSL/TLS downgrade vulnerabilities without exploitation.
