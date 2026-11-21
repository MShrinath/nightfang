# MQTT Security Testing Skill

**Category**: IoT / Protocol Security  
**Associated Agents**: `protocol-pentester`, `iot-pentester`  
**Payload Integration**: Use `scripts/agent_payloads.py` — MQ Telemetry Transport maps to CWE-943 ( improper Input Neutralization). Safe payloads available via `resolver.get_safe_payloads("MQTT Injection")`.  

---

## 1. Scope

MQTT (Message Queuing Telemetry Transport) is a lightweight publish-subscribe messaging protocol commonly used in IoT, IIoT, and m2m applications. This skill covers broker enumeration, topic injection, QoS manipulation, and credential bypass testing on MQTT deployments.

---

## 2. Reconnaissance Phase

### 2.1 Broker Discovery
```bash
# Default ports: 1883 (plaintext), 8883 (TLS), 9001 (WebSocket)
nmap -sV --script mqtt-subscribe,mqtt-topics -p 1883,8883,9001 <target>
mosquitto_sub -h <broker> -p 1883 -t '#' -C 1 2>/dev/null && echo "UNAUTH_ACCESSIBLE"
```

### 2.2 Anonymous Topic Enumeration
Subscribe to wildcard topics and collect all published messages without authentication:
```python
from paho.mqtt import client as mqtt_client
client = mqtt_client.Client()
client.connect("target", 1883, 60)
client.subscribe("#")
client.on_message = lambda c, u, m: print(f"[TOPIC] {u.decode()} => {m.payload.decode()}")
client.loop_forever(timeout=30)
```

### 2.3 QoS Level Analysis
Test each QoS level for message delivery guarantees and replay susceptibility:
| QoS | Behavior | Vulnerability Angle |
|-----|----------|---------------------|
| 0   | Fire & forget | Message loss during replay attacks |
| 1   | At least once | Duplicate processing, idempotency flaws |
| 2   | Exactly once | Session hijacking, packet replay window |

---

## 3. Attack Vectors

### 3.1 Unauthenticated Access
**Detection**: Subscribe to `$SYS/#` and standard topics without credentials.
```bash
mosquitto_sub -h <broker> -t '$SYS/broker/version' -C 1
mosquitto_sub -h <broker> -t 'telemetry/+/sensor/+/-/+/' -C 1
```
**Payload mapping**: `safe_default=True` for discovery, HITL required for write operations.

### 3.2 Topic Injection & Path Traversal
Inject directory traversal characters into topic names to access restricted channels:
```
test/malicious/../admin/command
telemetry/../../config/dump
$share/groupname/secret/topic
```
**CWE**: CWE-73 (External Control of File or Directory Name)  
**Safe payload check**: `resolver.get_safe_payloads("Topic Injection")`

### 3.3 Shared Subscription Abuse
MQTT 5.x shared subscriptions (`$share/<group>/<topic>`) can be exploited if not properly segmented:
```
$share/testgroup/production/sensitive/data
$share/admin/group/#
```

### 3.4 LMQ (Lightweight MQTT) Payload Fuzzing
Using the fuzzing engine for MQTT-specific mutations:
```python
from scripts.fuzzing_engine import FuzzingEngine
engine = FuzzingEngine(target="<broker>", fuzz_type="mqtt_topic")
cases = engine.generate_test_cases(base_input="sensor/temp/value", count=15)
```

---

## 4. Detection Rule Generation

### Sigma Rule Template
```yaml
title: Suspicious MQTT Topic Access Pattern
logsource:
    category: mqtt_broker
detection:
    selection_topic_traversal:
        topic_path: '*../*'
    selection_anomalous_qos:
        qos: '0'
        retained: true
    condition: selection_topic_traversal or selection_anomalous_qos
level: medium
```

### KQL (Azure Sentinel)
```kusto
MQTTEvents
| where Topic has ".." or Topic matches regex @"\$share/"
| summarize count() by ClientId, bin(TimeGenerated, 5m)
```

---

## 5. Output Schema Compliance

All findings must conform to [`schemas/finding.md`](../schemas/finding.md):
- Category: `iot` or `network`
- Tool used: `mosquitto_sub/pub`, `paho-mqtt`, custom fuzzer
- Evidence: raw MQTT packets captured (redacted)
- Detection rule: sigma/kql query attached per finding

---

## 6. References

- OWASP IoT Top 10: [IOT10-2025 MQTT Security](https://owasp.org/www-project-internet-of-things/)
- OASIS MQTT v5.0 Specification
- NIST IR 8228 (Cybersecurity for IoT)
