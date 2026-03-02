import streamlit as st
import pandas as pd
import plotly.express as px
from engine import run_engine
from datetime import datetime

st.set_page_config(
    page_title="SOC Automation Platform",
    layout="wide"
)

st.title("🛡 SOC Automation Platform")
st.caption("Detection Engineering | Risk Scoring | ML Detection")

if st.button("▶ Run Detection Engine"):
    results = run_engine()
    st.success("Engine Executed Successfully")

else:
    st.info("Click the button above to run detection engine.")
    st.stop()

alerts = results.get("alerts_generated", [])

if not alerts:
    st.warning("No alerts generated.")
    st.stop()

df = pd.DataFrame(alerts)

st.divider()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Alerts", len(df))
col2.metric("High", len(df[df["severity"] == "High"]))
col3.metric("Medium", len(df[df["severity"] == "Medium"]))
col4.metric("Low", len(df[df["severity"] == "Low"]))

st.divider()

st.subheader("📊 Severity Distribution")
fig = px.pie(df, names="severity")
st.plotly_chart(fig, use_container_width=True)

st.subheader("🚨 Risk Score by IP")
fig2 = px.bar(df, x="ip", y="score")
st.plotly_chart(fig2, use_container_width=True)

st.subheader("📋 Alert Details")
st.dataframe(df, use_container_width=True)

st.caption(f"Last Run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")