import streamlit as st
import pandas as pd
import plotly.express as px
from engine import run_engine, alert_db, deduplicator, threat_feed_service
from datetime import datetime

st.set_page_config(
    page_title="SOC Automation Platform",
    layout="wide"
)

st.title("🛡 SOC Automation Platform")
st.caption("Detection Engineering | Risk Scoring | ML Detection | RAG-Based Deduplication")

# ===============================
# RUN DETECTION ENGINE
# ===============================
if st.button("▶ Run Detection Engine"):
    results = run_engine()
    st.success("Engine Executed Successfully")
else:
    st.info("Click the button above to run detection engine.")
    st.stop()

alerts = results.get("alerts_generated", [])

if not alerts:
    st.warning("No new alerts generated (may be suppressed by deduplication)")
else:
    st.success(f"✅ {len(alerts)} new alert(s) triggered")

# ===============================
# METRICS
# ===============================
st.divider()
st.subheader("📊 Detection Summary")

col1, col2, col3, col4, col5 = st.columns(5)

# Get all stored alerts (persistent)
all_stored_alerts = alert_db.get_all_alerts()
df_all = pd.DataFrame(all_stored_alerts) if all_stored_alerts else pd.DataFrame()

col1.metric("Total Stored Alerts", len(all_stored_alerts))
if not df_all.empty:
    col2.metric("High Severity", len(df_all[df_all["severity"] == "High"]))
    col3.metric("Medium Severity", len(df_all[df_all["severity"] == "Medium"]))
    col4.metric("Low Severity", len(df_all[df_all["severity"] == "Low"]))
else:
    col2.metric("High Severity", 0)
    col3.metric("Medium Severity", 0)
    col4.metric("Low Severity", 0)

# Deduplication stats
dedup_stats = results.get("dedup_stats", {})
col5.metric("Known Threat IPs", dedup_stats.get("known_ips", 0))

# ===============================
# LIVE THREAT FEED
# ===============================
st.divider()
st.subheader("🌍 Live Global Threat Landscape")

threat_data = threat_feed_service.get_live_threats_display()
threat_col1, threat_col2, threat_col3 = st.columns(3)

threat_col1.metric("🔴 Total Live Threats", threat_data['total_threats'])
threat_col2.metric("⚠️ High Severity Threats", threat_data['high_severity'])
threat_col3.metric("🕐 Last Updated", threat_data['last_updated'][:10] if threat_data['last_updated'] else "N/A")

if threat_data['threats']:
    st.dataframe(
        pd.DataFrame(threat_data['threats']),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No external threats in feed at the moment")

# ===============================
# SEVERITY DISTRIBUTION
# ===============================
st.divider()
st.subheader("📊 Severity Distribution (All Stored Alerts)")

if not df_all.empty:
    fig = px.pie(
        df_all,
        names="severity",
        title="Alert Distribution by Severity",
        color_discrete_map={"High": "#FF0000", "Medium": "#FFA500", "Low": "#00FF00"}
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No alerts stored yet")

# ===============================
# RISK SCORE BY IP
# ===============================
st.divider()
st.subheader("🚨 Risk Score by IP (Top Threats)")

if not df_all.empty:
    # Show top 10 IPs by risk score
    top_ips = df_all.nlargest(10, 'score')[['ip', 'score', 'severity']]
    fig2 = px.bar(
        top_ips,
        x="ip",
        y="score",
        color="severity",
        color_discrete_map={"High": "#FF0000", "Medium": "#FFA500", "Low": "#00FF00"},
        title="Top 10 IPs by Risk Score",
        labels={"score": "Risk Score", "ip": "Source IP"}
    )
    st.plotly_chart(fig2, use_container_width=True)
else:
    st.info("No IP risk data available yet")

# ===============================
# DETAILED ALERT TABLE
# ===============================
st.divider()
st.subheader("📋 All Stored Alerts (Persistent Database)")

if not df_all.empty:
    # Display all stored alerts
    display_cols = ['ip', 'score', 'severity', 'country', 'city', 'analyst', 'status']
    display_df = df_all[display_cols] if all(col in df_all.columns for col in display_cols) else df_all
    
    st.dataframe(
        display_df.sort_values('score', ascending=False),
        use_container_width=True,
        hide_index=True
    )
    
    st.caption(f"Total Persistent Records: {len(df_all)} | Database: {alert_db.db_path}")
else:
    st.info("No alerts in persistent storage yet. Run detection engine to generate alerts.")

# ===============================
# DEDUPLICATION STATS
# ===============================
st.divider()
st.subheader("🤖 ML Deduplication Intelligence")

col_dedup1, col_dedup2 = st.columns(2)
col_dedup1.metric("Known Threat Patterns", dedup_stats.get("known_ips", 0))
col_dedup2.metric("Patterns Learned", dedup_stats.get("patterns_learned", 0))

st.info("""
**How RAG Deduplication Works:**
- Learns from every triggered alert
- Same IP + Severity within 24h = SUPPRESSED (prevents duplicates)
- Similar patterns from multiple IPs = Detected and grouped
- Knowledge base grows intelligently over time
""")

# ===============================
# TIMESTAMPS
# ===============================
st.divider()
last_run = results.get("last_execution_time", "N/A")
execution_time = results.get("execution_duration_seconds", 0)
st.caption(f"Last Engine Run: {last_run} | Execution Time: {execution_time}s")
