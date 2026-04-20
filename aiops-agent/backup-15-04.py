import os
import threading
import requests
import json
import time
from datetime import datetime
from fastapi import FastAPI
from kubernetes import client, config, watch

# ================= CONFIG =================
OLLAMA_URL = os.getenv("OLLAMA_URL", "")
K8SGPT_URL = os.getenv("K8SGPT_URL", "")

STORE_FILE = "/tmp/incidents.json"

app = FastAPI()

incidents = []
incident_cache = set()

# ================= STORAGE =================
def load_incidents():
    global incidents
    try:
        with open(STORE_FILE) as f:
            incidents = json.load(f)
    except:
        incidents = []

def save_incidents():
    try:
        with open(STORE_FILE, "w") as f:
            json.dump(incidents, f)
    except:
        pass

# ================= LOGS =================
def get_logs(v1, pod):
    try:
        return v1.read_namespaced_pod_log(
            name=pod.metadata.name,
            namespace=pod.metadata.namespace,
            tail_lines=30
        )[:500]
    except:
        return "No logs"

# ================= EVENTS =================
def get_events(v1, pod):
    try:
        ev = v1.list_namespaced_event(pod.metadata.namespace)
        msgs = [
            f"{e.reason}: {e.message}"
            for e in ev.items if e.involved_object.name == pod.metadata.name
        ]
        return "\n".join(msgs[-5:])[:500]
    except:
        return "No events"

# ================= K8SGPT =================
def get_k8sgpt_analysis():
    if not K8SGPT_URL:
        return "k8sgpt not configured"

    try:
        res = requests.get(f"{K8SGPT_URL}/analyze", timeout=5)
        return res.text[:500]
    except:
        return "k8sgpt unavailable"

# ================= RULE ENGINE =================
def rule_engine(logs, events):
    text = (logs + events).lower()

    if "oom" in text:
        return "OOMKilled"
    if "connection refused" in text:
        return "Connection Refused"
    if "timeout" in text:
        return "Timeout"
    if "no such host" in text:
        return "DNS Failure"
    if "back-off" in text:
        return "CrashLoopBackOff"

    return "Unknown Failure"

# ================= AI ENGINE =================
def ai_rca(pod, ns, logs, events, rule, k8sgpt_data):

    if not OLLAMA_URL:
        return f"{rule} detected. AI disabled (no Ollama)."

    prompt = f"""
Pod: {pod}
Namespace: {ns}

Issue: {rule}

Logs:
{logs}

Events:
{events}

Cluster:
{k8sgpt_data}

Give:
1. Root cause
2. Fix
"""

    prompt = prompt[:2000]

    try:
        res = requests.post(
            OLLAMA_URL,
            json={
                "model": "qwen:1.8b",
                "prompt": prompt,
                "stream": False
            },
            timeout=10
        )

        if res.status_code != 200:
            return f"{rule} detected. AI overloaded."

        return res.json().get("response", "AI failed")

    except:
        return f"{rule} detected. AI unavailable."

# ================= ASYNC AI =================
def process_ai(incident, name, ns, logs, events, rule):
    k8sgpt_data = get_k8sgpt_analysis()
    ai_output = ai_rca(name, ns, logs, events, rule, k8sgpt_data)

    incident["ai_rca"] = ai_output[:500]
    save_incidents()

# ================= STORE INCIDENT =================
def store(pod, c, v1):
    ns = pod.metadata.namespace
    name = pod.metadata.name

    key = f"{ns}-{name}-{pod.metadata.uid}-{c.restart_count}"
    if key in incident_cache:
        return

    incident_cache.add(key)

    logs = get_logs(v1, pod)
    events = get_events(v1, pod)
    rule = rule_engine(logs, events)

    incident = {
        "pod": name,
        "namespace": ns,
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "rule": rule,
        "ai_rca": "⏳ Processing...",
        "logs": logs,
        "events": events,
        "severity": "CRITICAL" if "oom" in rule.lower() else "HIGH",
        "remediation": "Manual check required"
    }

    incidents.append(incident)
    save_incidents()

    threading.Thread(
        target=process_ai,
        args=(incident, name, ns, logs, events, rule),
        daemon=True
    ).start()

    print(f"🚨 Incident stored: {name}")

# ================= WATCHER =================
def watcher():
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    print("🚀 AIOps Agent Started")

    pods = v1.list_pod_for_all_namespaces()

    for pod in pods.items:
        for c in pod.status.container_statuses or []:
            if c.restart_count > 0:
                store(pod, c, v1)

    w = watch.Watch()

    while True:
        try:
            for e in w.stream(v1.list_pod_for_all_namespaces):
                pod = e['object']

                for c in pod.status.container_statuses or []:
                    if c.restart_count > 0:
                        store(pod, c, v1)

        except Exception as e:
            print("Watcher crashed:", str(e))
            time.sleep(5)

# ================= API =================
@app.get("/")
def root():
    return {"status": "AIOps Agent Running", "incidents": len(incidents)}

@app.get("/incidents")
def get_all():
    return incidents

# ================= START =================
@app.on_event("startup")
def start():
    load_incidents()
    threading.Thread(target=watcher, daemon=True).start()