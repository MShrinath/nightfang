# CoAP Security Testing Skill

**Category**: IoT / Lightweight Protocol Security  
**Associated Agents**: `protocol-pentester`, `iot-pentester`  
**Payload Integration**: Use `scripts/agent_payloads.py` — CoAP maps to CWE-943 (Improper Input Neutralization). Safe payloads via `resolver.get_safe_payloads("CoAP Injection")`.  

---

## 1. Scope

CoAP (Constrained Application Protocol, RFC 7252) is a RESTful protocol for constrained devices. This skill covers endpoint discovery, option manipulation, Observe pattern abuse, block-wise transfer attacks, and DTLS/TLS downgrade testing.

---

## 2. Reconnaissance Phase

### 2.1 CoAP Endpoint Discovery
```bash
# Standard port: 5683 (UDP), 5684 (DTLS)
coap-client -m get coap://<target>:5683/.well-known/core 2>/dev/null
coap-client -m get coap://<target>:5683/ -v d 2>/dev/null
```

### 2.2 Block-Wise Transfer Testing
Test oversized responses that may cause buffer overflows or DoS:
```python
from resources.coap import ClientResource
client = ClientResource("coap://target:5683/resource")
# Force block-wise with large block size
response = client.get(block_wise_size=1024, timeout=5)
```

### 2.3 Observer Pattern Abuse
Subscribe to resource changes and test notification flood capacity:
```
GET /.well-known/core → observe flag set
Monitor for rapid notification floods exceeding rate limits
```

---

## 3. Attack Vectors

| Vector | Technique | CWE | Safe? |
|--------|-----------|-----|-------|
| Option Manipulation | Malformed token/uri-path options | CWE-943 | YES (recon only) |
| Block-Wise DoS | Excessive block transfers flooding buffer | CWE-400 | HITL |
| DTLS Downgrade | Force TLS→plaintext transition | CWE-327 | HITL |
| Token Collision | Replay old tokens for response confusion | CWE-287 | YES |
| URI Encoding Bypass | Encode path separators in options | CWE-916 | YES (detection) |

---

## 4. Detection Rule Generation

### Sigma Rule
```yaml
title: Abnormal CoAP Block-Wise Transfer Volume
logsource:
    category: iot_gateway
detection:
    selection_coap:
        protocol: 'coap'
    condition: selection_coap and block_size > 512
level: low
```

---

## 5. References

- RFC 7252 — The Constrained Application Protocol (CoAP)
- RFC 7959 — Block-Wise Transfers in CoAP
- OWASP IoT Top 10
