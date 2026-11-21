# LMQ Fuzzing - SAFE DEFAULT PAYLOAD

## Description
MQTT/QoS fuzzing

## CWE: CWE-943
## OWASP: A03:2021

## Safety Classification
**SAFE_DEFAULT: True** - This is a reconnaissance/probe script that performs read-only operations.

## Usage
```bash
python lmq_fuzzing_probe.py <target>
```

## Purpose
This script safely probes for the vulnerability class without exploitation.
