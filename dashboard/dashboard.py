import streamlit as st
import requests
import pandas as pd
import plotly.express as px
from datetime import datetime

API_URL = "http://localhost:8000/run"

st.set_page_config(
    page_title="AI SOC Command Center",
    layout="wide"
)

st.title("🛡 AI SOC Command Center")
st.caption("Detection Engineering | Threat Intelligence | MITRE ATT&CK | Incident Response")

# ================================
# REFRESH PANEL
# ================================

col_refresh, col_time = st.columns([1,4])

with col_refresh:
    if st.button("🔄 Run Detection"):
        st.rerun()

with col_time:
    st.write("Last Updated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

st.divider()

# ================================
# FETCH DATA
# ================================

try:

    response = requests.get(API_URL, timeout=60)
    response.raise_for_status()
    data = response.json()

    alerts = data.get("alerts_generated", [])
    visitors = data.get("visitors", [])

except Exception as e:

    st.error(f"❌ Engine Error: {e}")
    st.stop()

if not alerts:
    st.warning("⚠ No alerts detected yet.")
    st.stop()

df = pd.DataFrame(alerts)

# ================================
# SOC METRICS
# ================================

total_alerts = len(df)
high = len(df[df["severity"] == "High"])
medium = len(df[df["severity"] == "Medium"])
low = len(df[df["severity"] == "Low"])

col1, col2, col3, col4 = st.columns(4)

col1.metric("🚨 Total Alerts", total_alerts)
col2.metric("🔴 High", high)
col3.metric("🟠 Medium", medium)
col4.metric("🟢 Low", low)

st.divider()

# ================================
# GLOBAL ATTACK MAP
# ================================

st.subheader("🌍 Global Attack Map")

if visitors:

    df_visitors = pd.DataFrame(visitors)

    if "lat" in df_visitors.columns:

        fig_map = px.scatter_geo(
            df_visitors,
            lat="lat",
            lon="lon",
            hover_name="ip",
            hover_data=["country","city","isp"],
            title="Detected Threat Activity"
        )

        st.plotly_chart(fig_map, use_container_width=True)

    else:
        st.info("Waiting for geo data...")

st.divider()

# ================================
# SEVERITY DISTRIBUTION
# ================================

col_left, col_right = st.columns(2)

with col_left:

    st.subheader("📊 Severity Distribution")

    fig_pie = px.pie(
        df,
        names="severity",
        title="Alert Severity Breakdown"
    )

    st.plotly_chart(fig_pie, use_container_width=True)

with col_right:

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

st.divider()

# ================================
# MITRE ATT&CK PANEL
# ================================

st.subheader("🎯 MITRE ATT&CK Techniques")

if "mitre_technique" in df.columns:

    techniques = df.explode("mitre_technique")

    technique_counts = techniques["mitre_technique"].value_counts().reset_index()
    technique_counts.columns = ["Technique","Count"]

    fig_mitre = px.bar(
        technique_counts,
        x="Technique",
        y="Count",
        title="Detected MITRE Techniques"
    )

    st.plotly_chart(fig_mitre, use_container_width=True)

st.divider()

# ================================
# ATTACK TIMELINE
# ================================

st.subheader("⏱ Attack Timeline")

timeline = []

for index, row in df.iterrows():

    for event in row["events"]:

        timeline.append({
            "IP": row["ip"],
            "Event": event,
            "Severity": row["severity"]
        })

timeline_df = pd.DataFrame(timeline)

st.dataframe(timeline_df, use_container_width=True)

st.divider()

# ================================
# ALERT TABLE
# ================================

st.subheader("🗂 SOC Incident Queue")

st.dataframe(df, use_container_width=True)

# ================================
# ENGINE STATUS
# ================================

st.subheader("⚙ Engine Status")

st.success(f"Engine Status: {data.get('engine_status','unknown')}")

st.write("Last Execution:", data.get("last_execution_time"))
st.write("Execution Duration:", data.get("execution_duration_seconds"), "seconds")

# ================================
# EXPORT ALERTS
# ================================

csv = df.to_csv(index=False)

st.download_button(
    label="📥 Download Alerts",
    data=csv,
    file_name="soc_alerts.csv",
    mime="text/csv"
)
# ================================
# ISO 27001 CONTROL MONITORING
# ================================

st.subheader("📋 ISO 27001 Security Control Monitoring")

iso_mapping = {
    "failed_login": "A.9 Access Control",
    "successful_login": "A.9 Access Control",
    "process_creation": "A.12 Operations Security",
    "outbound_connection": "A.13 Network Security"
}

iso_events = []

for index, row in df.iterrows():
    for event in row["events"]:
        control = iso_mapping.get(event)
        if control:
            iso_events.append(control)

if iso_events:

    iso_df = pd.DataFrame(iso_events, columns=["ISO Control"])

    iso_summary = iso_df.value_counts().reset_index()
    iso_summary.columns = ["ISO Control","Event Count"]

    fig_iso = px.bar(
        iso_summary,
        x="ISO Control",
        y="Event Count",
        title="Security Monitoring by ISO 27001 Control"
    )

    st.plotly_chart(fig_iso, use_container_width=True)

else:

    st.info("No ISO control events detected yet.")