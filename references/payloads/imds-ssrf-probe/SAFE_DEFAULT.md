# IMDS SSRF Probe - SAFE DEFAULT PAYLOAD

## Description
AWS IMDS SSRF testing

## CWE: CWE-918
## OWASP: A10:2021

## Safety Classification
**SAFE_DEFAULT: True** - This is a reconnaissance/probe script that performs read-only operations.

## Usage
```bash
python imds_ssrf_probe_probe.py <target>
```

## Purpose
This script safely probes for the vulnerability class without exploitation.
