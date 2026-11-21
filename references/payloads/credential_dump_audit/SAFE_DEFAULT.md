# Credential Dump Audit - SAFE DEFAULT PAYLOAD

## Description
Audit for credential dumps

## CWE: CWE-522
## OWASP: A02:2021

## Safety Classification
**SAFE_DEFAULT: True** - This is a reconnaissance/probe script that performs read-only operations.

## Usage
```bash
python credential_dump_audit_probe.py <target>
```

## Purpose
This script safely probes for the vulnerability class without exploitation.
