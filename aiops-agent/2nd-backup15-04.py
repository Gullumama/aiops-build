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
            tail_lines=100
        )[:500]
    except:
        return "No logs"

# ================= LOKI LOGS =================
def get_logs_from_loki(pod, namespace):
    try:
        query = f'{{namespace="{namespace}", pod="{pod}"}} |~ "(?i)error|exception|fail|panic|fatal"'

        res = requests.get(
            "http://loki.monitoring.svc.cluster.local:3100/loki/api/v1/query_range",
            params={
                "query": query,
                "limit": 50,
                "direction": "backward"
            },
            timeout=5
        )

        data = res.json()

        logs = []
        for stream in data.get("data", {}).get("result", []):
            for value in stream.get("values", []):
                logs.append(value[1])

        logs = "\n".join(logs)

        if not logs.strip():
            return "No error logs found"

        return logs[-1200:]

    except Exception as e:
        return f"Loki error: {str(e)}"
    
# ================= PATTERN DETECTION =================
def detect_pattern(logs):
    l = logs.lower()

    if "oom" in l:
        return "OOMKilled: Container ran out of memory. Increase memory limits."

    if "connection refused" in l:
        return "Dependency failure: Service connection refused."

    if "no such host" in l:
        return "DNS failure: Unable to resolve service."

    if "timeout" in l:
        return "Network timeout: Service not reachable."

    if "crashloopbackoff" in l:
        return "Application crash loop detected."

    if "exception" in l:
        return "Application exception detected in logs."

    return None

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



# ================= AI RCA =================
def ai_rca(pod, ns, logs, events, rule, k8sgpt_data):

    # ✅ fallback if AI not configured
    if not OLLAMA_URL:
        return f"{rule} detected. Check logs and events."

    prompt = f"""
You are a Kubernetes SRE expert.

Pod: {pod}
Namespace: {ns}
Issue: {rule}

Logs:
{logs}

Events:
{events}

Cluster:
{k8sgpt_data}

Respond strictly in this format:

Root Cause:
<one clear reason>

Fix:
<exact actionable steps>

Prevention:
<how to avoid in future>
"""

    retries = 2
    backoff = 2  # seconds

    for attempt in range(retries):
        try:
            res = requests.post(
                OLLAMA_URL,
                json={
                    "model": "qwen:1.8b",
                    "prompt": prompt,
                    "stream": False
                },
                timeout=20  # ✅ increased timeout
            )

            # ✅ check response validity
            if res.status_code == 200:
                output = res.json().get("response", "").strip()

                if output:
                    return output

            # retry if empty response
            time.sleep(backoff)

        except requests.exceptions.Timeout:
            print(f"⚠️ Ollama timeout (attempt {attempt+1})")
            time.sleep(backoff)

        except Exception as e:
            print(f"⚠️ Ollama error: {str(e)}")
            time.sleep(backoff)

    # ✅ FINAL FALLBACK (VERY IMPORTANT)
    return "AI unavailable. Using detected logs for RCA."
# ================= ASYNC AI =================
def process_ai(incident, name, ns, logs, events, rule):

    try:
        pattern = detect_pattern(logs)

        if pattern:
            ai_output = pattern
        else:
            k8sgpt_data = get_k8sgpt_analysis()
            ai_output = ai_rca(name, ns, logs, events, rule, k8sgpt_data)

        # ✅ fallback safety
        if not ai_output or "AI unavailable" in ai_output:
            ai_output = pattern if pattern else "Check logs for root cause."

        incident["ai_rca"] = ai_output[:800]

    except Exception as e:
        incident["ai_rca"] = f"Processing error: {str(e)}"

    save_incidents()
# # ================= STORE INCIDENT =================
def store(pod, c, v1):
    ns = pod.metadata.namespace
    name = pod.metadata.name

    # ✅ FIX 1: avoid duplicate incidents
    key = f"{ns}-{name}-{pod.metadata.uid}"
    if key in incident_cache:
        return

    incident_cache.add(key)

    # ✅ Step 1: get logs from K8s
    logs = get_logs(v1, pod)

    # ✅ Step 2: fallback to Loki if logs missing
    if logs == "No logs" or len(logs.strip()) < 20:
        logs = get_logs_from_loki(name, ns)

    # ✅ Step 3: get events
    events = get_events(v1, pod)

    # ✅ Step 4: fallback if still no logs
    if "No error logs" in logs or "Loki error" in logs:
        logs = events

    # ✅ Step 5: rule + pattern detection
    rule = rule_engine(logs, events)
    pattern = detect_pattern(logs)

    # ✅ Step 6: dynamic severity
    severity = "HIGH"
    l = logs.lower()

    if "oom" in l or "exception" in l:
        severity = "CRITICAL"
    elif "timeout" in l:
        severity = "MEDIUM"

    # ✅ Step 7: clean logs
    logs = logs.replace("\\n", "\n")

    # ✅ Step 8: confidence
    confidence = "HIGH" if pattern else "MEDIUM"

    # ✅ Step 9: create incident
    incident = {
        "pod": name,
        "namespace": ns,
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "rule": rule,
        "ai_rca": pattern if pattern else "⏳ AI analyzing...",
        "logs": logs[:1500],
        "events": events,
        "severity": severity,
        "confidence": confidence,
        "remediation": pattern if pattern else "AI analysis in progress"
    }

    incidents.append(incident)
    save_incidents()

    # ✅ Step 10: async AI (only if no pattern)
    if not pattern:
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