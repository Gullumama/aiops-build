# 🔥 AIOps RCA Platform

AI-powered Kubernetes Root Cause Analysis system.

## 🚀 Features
- Real-time issue detection
- AI-based RCA (Ollama - llama3:8b)
- K8sGPT integration
- Auto-remediation (planned)

## 🧩 Architecture
- aiops-agent → collects signals
- k8sgpt → analysis
- ollama → LLM reasoning
- UI → dashboard

## ⚙️ Deployment
```bash
kubectl apply -f rbac.yaml
