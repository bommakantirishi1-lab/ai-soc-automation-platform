import streamlit as st
import pandas as pd
import plotly.express as px

from database import init_db, insert_alert, get_alerts
from engine import run_detection

st.set_page_config(
    page_title="SOC Automation Platform",
    layout="wide"
)

init_db()

st.title("🛡 SOC Automation & AI Response Platform")
st.caption("Built by Sai Rishi Kumar Bommakanti")

col1, col2 = st.columns([1, 5])

with col1:
    if st.button("🚀 Run Detection"):
        ip, score, severity, analyst = run_detection()
        insert_alert(ip, score, severity, analyst)
        st.success("Detection Executed")

alerts = get_alerts()

if not alerts:
    st.warning("No alerts yet.")
    st.stop()

df = pd.DataFrame(alerts)

# ===== METRICS =====
st.divider()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", len(df))
col2.metric("High", len(df[df["severity"] == "High"]))
col3.metric("Medium", len(df[df["severity"] == "Medium"]))
col4.metric("Low", len(df[df["severity"] == "Low"]))

st.divider()

# ===== SEVERITY PIE =====
st.subheader("Severity Distribution")
fig_pie = px.pie(df, names="severity")
st.plotly_chart(fig_pie, use_container_width=True)

# ===== RISK BAR =====
st.subheader("Risk Score by IP")
top_ips = df.groupby("source_ip")["score"].max().reset_index()
fig_bar = px.bar(top_ips, x="source_ip", y="score")
st.plotly_chart(fig_bar, use_container_width=True)

# ===== ALERT TABLE =====
st.subheader("Alert Queue")
st.dataframe(df, use_container_width=True)