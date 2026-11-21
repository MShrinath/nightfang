#!/usr/bin/env python3
"""MQTT broker enumeration and topic scanning utility."""
import sys
import os
import json
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from paho.mqtt import client as mqtt_client
except ImportError:
    print("Installing paho-mqtt...")
    os.system(f"{sys.executable} -m pip install paho-mqtt --quiet")
    from paho.mqtt import client as mqtt_client


def connect(broker: str, port: int = 1883, timeout: int = 10):
    client = mqtt_client.Client()
    client.connect(broker, port, timeout)
    client.loop_start()
    return client


def enumerate_topics(client, broker: str, base_topic: str = "#", timeout: int = 5):
    topics = []

    def on_message(c, u, m):
        topics.append(m.topic.decode())

    client.on_message = on_message
    client.subscribe(base_topic, qos=1)
    client.publish("$SYS/broker/uptime", b"", qos=0)

    start = time.time()
    while len(topics) < 50 and (time.time() - start) < timeout:
        client.loop(0.1)

    client.unsubscribe(base_topic)
    client.loop_stop()
    return sorted(set(topics))


def check_anonymous_access(broker: str, port: int = 1883):
    """Test if broker allows unauthenticated access."""
    results = {"anonymous": False, "topics": [], "sys_info": {}}
    try:
        client = connect(broker, port, timeout=5)
        client.subscribe("#", qos=1)
        client.publish("$SYS/broker/version", b"probe", qos=0)
        topics = enumerate_topics(client, broker, timeout=4)
        results["anonymous"] = bool(topics)
        results["topics"] = topics[:20]
        client.disconnect()
    except Exception:
        pass
    return results


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--broker", default="localhost")
    ap.add_argument("--port", type=int, default=1883)
    args = ap.parse_args()
    print(f"[+] Checking anonymous access to {args.broker}:{args.port} ...")
    res = check_anonymous_access(args.broker, args.port)
    print(json.dumps(res, indent=2))
