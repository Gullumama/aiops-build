import streamlit as st
import requests
import pandas as pd

st.set_page_config(layout="wide")
st.title("🚀 AIOps RCA Dashboard")

API_URL = "http://aiops-agent:8080/incidents"

# ================= FETCH DATA =================
try:
    response = requests.get(API_URL, timeout=5)
    data = response.json()
except:
    st.error("Backend not reachable")
    st.stop()

if not data:
    st.warning("No incidents detected")
    st.stop()

df = pd.DataFrame(data)

# ================= FILTER =================
namespaces = ["all"] + sorted(df["namespace"].unique().tolist())
ns = st.selectbox("Select Namespace", namespaces)

if ns != "all":
    df = df[df["namespace"] == ns]

# ================= METRICS =================
st.markdown("### 📊 Cluster Summary")

col1, col2 = st.columns(2)
col1.metric("Total Incidents", len(df))
col2.metric("Critical", len(df[df["severity"] == "CRITICAL"]))

st.markdown("---")

# ================= INCIDENT CARDS =================
for _, row in df.iterrows():

    severity_color = "red" if row["severity"] == "CRITICAL" else "orange"

    with st.container():
        st.markdown(
            f"<h3 style='color:{severity_color}'>🚨 {row['pod']}</h3>",
            unsafe_allow_html=True
        )

        col1, col2 = st.columns(2)

        with col1:
            st.write(f"📦 Namespace: {row['namespace']}")
            st.write(f"⏱ Time: {row['time']}")

        with col2:
            st.write(f"🚨 Severity: {row['severity']}")

        st.markdown("### 📌 Issue")
        st.error(row["rule"])

        with st.expander("🧠 AI RCA"):
            st.write(row["ai_rca"])

        with st.expander("📜 Logs"):
            st.code(row["logs"])

        with st.expander("📡 Events"):
            st.code(row["events"])

        with st.expander("⚙️ Remediation"):
            st.info(row["remediation"])

        st.markdown("---")