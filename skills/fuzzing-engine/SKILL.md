# Fuzzing Engine Skill

**Category**: Automated Vulnerability Discovery  
**Associated Agents**: `api-fuzzer`, `protocol-pentester`, `web-shell-detector`, `scanner`  
**Payload Integration**: Each fuzzing target class has associated CWE/OWASP mappings. Access via `resolver.get_safe_payloads(class_name)` before destructive mutation sets.  

---

## 1. Scope

General-purpose structured fuzzing framework applicable to HTTP APIs, network protocols, file parsers, and input validation sinks. Integrates coverage feedback and crash triage.

---

## 2. Mutation Strategy Catalog

### String Mutations
| Strategy | Description | Typical Target | Safe? |
|----------|-------------|----------------|-------|
| Null Byte Injection | Append `\x00` at various positions | Path traversal, buffer truncation | YES |
| Length Extension | Pad to common overflow boundaries (256, 512, 1024, 4096, 65535) | Buffer overflow discovery | MODERATE |
| Type Coercion | Send integer where string expected and vice versa | Schema validation bypass | YES |
| Encoding Bypass | URL encode, double encode, HTML entity, UTF-7/UTF-16 | WAF/validator evasion | MODERATE |
| Whitespace Variation | Add tabs, newlines, null bytes within tokens | Token parsing edge cases | YES |
| Empty Value Test | Remove value entirely, send empty string | Null pointer dereference | YES |
| Boundary Values | `-1`, `0`, `1`, `MAX_INT`, `MIN_INT` | Integer overflow checks | YES |
| Magic Strings | `<script>`, `' OR 1=1`, `../etc/passwd`, `<?php ?>` | Injection sink identification | HITL |

### Protocol-Specific Mutations
| Protocol | Mutation Type | Effect |
|----------|--------------|--------|
| HTTP | Header injection, request smuggling sequences, method override | Desync, cache poisoning |
| JSON | Missing braces, unescaped quotes, duplicate keys, trailing commas | Parser divergence |
| XML | Unclosed tags, entity expansion, CDATA injection, DTD injection | XXE, billion-laughs DoS |
| SQL | Union stacking, comment injection, time-based blind payloads | Query manipulation |
| MQTT | Topic path traversal, QoS level abuse, retained message flooding | Broker confusion |

---

## 3. Stateful Session Fuzzing

Maintain authentication/session state across mutations to test context-dependent vulnerabilities:

```python
from scripts.fuzzing_engine import FuzzingEngine, CoverageTracker

engine = FuzzingEngine(target="https://target.corp/api/v1/users", fuzz_type="json_body")

def evaluate_request(case_input: str) -> dict:
    import requests
    resp = requests.post(
        "https://target.corp/api/v1/users",
        json={"username": case_input, "email": "test@example.com"},
        headers={"Authorization": f"Bearer {SESSION_TOKEN}"},
        timeout=10
    )
    return {
        "status": resp.status_code,
        "body": resp.text[:500],
        "duration_ms": resp.elapsed.total_seconds() * 1000,
        "crash": resp.status_code == 500,
    }

cases = engine.generate_test_cases(base_input="normaluser", count=15)
results = engine.run_and_evaluate(cases, evaluator=evaluate_request)
print(json.dumps(engine.report(), indent=2))
```

---

## 4. Crash Triage & Reporting

When a crash is detected (timeout, 5xx, connection reset), the engine produces:
1. **Crash signature** — hash of the triggering input
2. **Input preview** — first 200 characters of mutated value
3. **Mutation classification** — which strategy triggered the failure
4. **Response excerpt** — server error body for analysis
5. **Regression suggestion** — how to narrow down the exact trigger point

---

## 5. References

- AFL++ Documentation — Advanced mutation strategies
- OWASP Fuzzing Guide
- NIST SP 800-117 (Guide to SaaS Security)
