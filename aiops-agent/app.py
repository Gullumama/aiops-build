import os
import threading
import requests
import json
import time
from datetime import datetime
from fastapi import FastAPI
from kubernetes import client, config, watch

# ================= CONFIG =================
OLLAMA_URL = os.getenv("OLLAMA_URL")
MODEL = os.getenv("OLLAMA_MODEL", "llama3:8b-instruct-q4_0")
LOKI_URL = "http://loki.monitoring.svc.cluster.local:3100"

STORE_FILE = "/tmp/incidents.json"

app = FastAPI()

incidents = []
incident_cache = set()
memory_db = []  # 🔥 incident memory

# ================= STORAGE =================
def load_incidents():
    global incidents, memory_db
    try:
        with open(STORE_FILE) as f:
            data = json.load(f)
            incidents = data.get("incidents", [])
            memory_db = data.get("memory", [])
    except:
        incidents, memory_db = [], []

def save_incidents():
    try:
        with open(STORE_FILE, "w") as f:
            json.dump({"incidents": incidents, "memory": memory_db}, f)
    except:
        pass

# ================= LOGS =================
def get_logs(v1, pod):
    try:
        return v1.read_namespaced_pod_log(
            name=pod.metadata.name,
            namespace=pod.metadata.namespace,
            tail_lines=100
        )[:800]
    except:
        return "No logs"

# ================= LOKI =================
def get_logs_from_loki(pod, namespace):
    try:
        query = f'{{namespace="{namespace}", pod="{pod}"}}'
        res = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params={"query": query, "limit": 200},
            timeout=5
        )
        data = res.json()

        logs = []
        for stream in data.get("data", {}).get("result", []):
            for val in stream.get("values", []):
                logs.append(val[1])

        return "\n".join(logs)[-1200:] if logs else "No logs"
    except:
        return "No logs"

# ================= EVENTS =================
def get_events(v1, pod):
    try:
        ev = v1.list_namespaced_event(pod.metadata.namespace)
        return "\n".join([
            f"{e.reason}: {e.message}"
            for e in ev.items if e.involved_object.name == pod.metadata.name
        ])[:500]
    except:
        return "No events"

# ================= RULE =================
def rule_engine(logs, events):
    text = (logs + events).lower()

    if "oom" in text:
        return "OOMKilled"
    if "connection refused" in text:
        return "Connection Refused"
    if "timeout" in text:
        return "Timeout"
    if "bad address" in text or "no such host" in text:
        return "DNS Failure"
    if "liveness probe failed" in text:
        return "Liveness Probe Failed"
    if "back-off" in text:
        return "CrashLoopBackOff"

    return "Unknown Failure"

# ================= MEMORY =================
def check_memory(rule, logs):
    for item in memory_db:
        if item["rule"] == rule and item["pattern"] in logs:
            return item["rca"]
    return None

def store_memory(rule, logs, rca):
    memory_db.append({
        "rule": rule,
        "pattern": logs[:100],
        "rca": rca
    })

# ================= CORRELATION =================
def correlate(ns, rule):
    related = [
        i for i in incidents
        if i["namespace"] == ns and i["rule"] == rule
    ]
    if len(related) > 3:
        return f"Cluster-wide issue detected affecting {len(related)} pods"
    return None

# ================= AI =================
def ai_rca(pod, ns, logs, events, rule):

    logs = logs[:1000]
    events = events[:400]

    prompt = f"""
You are a Kubernetes SRE.

Pod: {pod}
Namespace: {ns}
Issue: {rule}

Logs:
{logs}

Events:
{events}

Return ONLY:

Root Cause:
Fix:
Prevention:
"""

    for _ in range(3):
        try:
            res = requests.post(
                OLLAMA_URL,
                json={
                    "model": MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"num_predict": 250}
                },
                timeout=90
            )

            if res.status_code == 200:
                out = res.json().get("response", "").strip()
                if "Root Cause:" in out:
                    return out
        except:
            time.sleep(3)

    raise Exception("AI failed")

# ================= FALLBACK =================
def deterministic_rca(logs, events):

    text = (logs + events).lower()

    if "bad address" in text:
        return """Root Cause:
DNS resolution failure.

Fix:
kubectl get svc -A

Prevention:
Validate DNS"""

    if "liveness probe failed" in text:
        return """Root Cause:
Invalid liveness endpoint.

Fix:
Update probe path

Prevention:
Validate health endpoints"""

    return None

# ================= REMEDIATION =================
def remediate(v1, pod, rule):
    name = pod.metadata.name
    ns = pod.metadata.namespace

    try:
        if rule == "CrashLoopBackOff":
            v1.delete_namespaced_pod(name, ns)
            return "Pod restarted"

        if rule == "OOMKilled":
            return "Increase memory limits in deployment"

    except Exception as e:
        return str(e)

    return "No action"

# ================= PROCESS =================
def process_ai(incident, pod, v1, logs, events, rule):

    try:
        # MEMORY CHECK
        mem = check_memory(rule, logs)
        if mem:
            incident["ai_rca"] = mem
            return

        # AI CALL
        rca = ai_rca(pod.metadata.name, pod.metadata.namespace, logs, events, rule)
        incident["ai_rca"] = rca

        # STORE MEMORY
        store_memory(rule, logs, rca)

    except Exception as e:
        fallback = deterministic_rca(logs, events)
        incident["ai_rca"] = fallback if fallback else f"AI ERROR: {str(e)}"

    finally:
        save_incidents()

# ================= STORE =================
def store(pod, c, v1):
    ns = pod.metadata.namespace
    name = pod.metadata.name

    key = f"{ns}-{name}-{pod.metadata.uid}"
    if key in incident_cache:
        return

    incident_cache.add(key)

    logs = get_logs(v1, pod)
    if logs == "No logs":
        logs = get_logs_from_loki(name, ns)

    events = get_events(v1, pod)
    rule = rule_engine(logs, events)

    correlation = correlate(ns, rule)

    incident = {
        "pod": name,
        "namespace": ns,
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "rule": rule,
        "ai_rca": "⏳ AI analyzing...",
        "logs": logs,
        "events": events,
        "correlation": correlation,
        "remediation": remediate(v1, pod, rule)
    }

    incidents.append(incident)
    save_incidents()

    threading.Thread(
        target=process_ai,
        args=(incident, pod, v1, logs, events, rule),
        daemon=True
    ).start()

# ================= WATCHER =================
def watcher():
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    print("🚀 AIOps Agent Started")

    w = watch.Watch()

    while True:
        try:
            for e in w.stream(v1.list_pod_for_all_namespaces):
                pod = e['object']
                for c in pod.status.container_statuses or []:
                    if c.restart_count > 0:
                        store(pod, c, v1)
        except:
            time.sleep(5)

# ================= API =================
@app.get("/")
def root():
    return {"status": "Running", "incidents": len(incidents)}

@app.get("/incidents")
def get_all():
    return incidents

# ================= START =================
@app.on_event("startup")
def start():
    load_incidents()
    threading.Thread(target=watcher, daemon=True).start()