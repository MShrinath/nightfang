# IAM Policy Abuse - SAFE DEFAULT PAYLOAD

## Description
AWS IAM policy abuse detection

## CWE: N/A
## OWASP: A05:2021

## Safety Classification
**SAFE_DEFAULT: True** - This is a reconnaissance/probe script that performs read-only operations.

## Usage
```bash
python iam_policy_abuse_probe.py <target>
```

## Purpose
This script safely probes for the vulnerability class without exploitation.
