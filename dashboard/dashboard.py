import streamlit as st
import requests
import pandas as pd
import plotly.express as px
from datetime import datetime

API_URL = "http://localhost:8000/run"

st.set_page_config(
    page_title="SOC Automation Dashboard",
    layout="wide"
)

st.title("🛡 SOC Automation Platform")
st.caption("Detection Engineering | Risk Scoring | ML Anomaly Detection")

# ===== REFRESH BUTTON =====
col_refresh, col_time = st.columns([1, 4])

with col_refresh:
    if st.button("🔄 Refresh Alerts"):
        st.rerun()

with col_time:
    st.write(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

st.divider()

# ===== FETCH DATA FROM FASTAPI =====
try:
    response = requests.get(API_URL, timeout=60)
    response.raise_for_status()
    data = response.json()

    # 🔥 Correct key from backend
    alerts = data.get("alerts_generated", [])

except Exception as e:
    st.error(f"❌ API Error: {e}")
    st.stop()

if not alerts:
    st.warning("⚠ No alerts found.")
    st.stop()

df = pd.DataFrame(alerts)

# ===== METRICS PANEL =====
total_alerts = len(df)
high = len(df[df["severity"] == "High"])
medium = len(df[df["severity"] == "Medium"])
low = len(df[df["severity"] == "Low"])

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Alerts", total_alerts)
col2.metric("High", high)
col3.metric("Medium", medium)
col4.metric("Low", low)

st.divider()

# ===== SEVERITY PIE CHART =====
st.subheader("📊 Severity Distribution")

fig_pie = px.pie(
    df,
    names="severity",
    title="Alert Severity Breakdown"
)

st.plotly_chart(fig_pie, use_container_width=True)

# ===== TOP RISK IPs =====
st.subheader("🚨 Top Risky IPs")

top_ips = (
    df.groupby("ip")["score"]
    .max()
    .reset_index()
    .sort_values(by="score", ascending=False)
)

fig_bar = px.bar(
    top_ips,
    x="ip",
    y="score",
    title="Risk Score by IP"
)

st.plotly_chart(fig_bar, use_container_width=True)

# ===== ALERT TABLE =====
st.subheader("🗂 Alert Details")
st.dataframe(df, use_container_width=True)

# ===== ENGINE STATUS =====
st.subheader("⚙ Engine Status")
engine_status = data.get("engine_status", "unknown")
st.success(f"Engine Status: {engine_status}")

# ===== EXPORT CSV =====
csv = df.to_csv(index=False)

st.download_button(
    label="📥 Download Alerts as CSV",
    data=csv,
    file_name="soc_alerts.csv",
    mime="text/csv"
)
