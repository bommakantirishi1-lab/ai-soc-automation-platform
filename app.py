import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import requests
import os

from alert_database import AlertDatabase
from alert_deduplication import AlertDeduplicator
from threat_feed import ThreatFeedIntegration
from config import config
from engine import run_engine
from modules.nl_threat_hunter import threat_hunter

alert_db = AlertDatabase(config.DB_PATH)
deduplicator = AlertDeduplicator(config.ML_MODEL_PATH)
threat_feed_service = ThreatFeedIntegration()

def main():
    st.set_page_config(page_title="SOC Automation Platform", page_icon="🛡️", layout="wide")
    
    st.sidebar.title("🛡️ SOC AI Platform")
    st.sidebar.markdown("---")
    page = st.sidebar.radio("Navigation", ["Dashboard", "Threat Hunter", "Deduplication Stats", "Threat Intelligence", "Settings"])
    
    if page == "Dashboard":
        render_dashboard()
    elif page == "Threat Hunter":
        render_threat_hunter()
    elif page == "Deduplication Stats":
        render_dedup_stats()
    elif page == "Threat Intelligence":
        render_threat_intel()
    elif page == "Settings":
        render_settings()

def render_dashboard():
    st.title("🛡️ SOC Automation Dashboard")
    st.caption("Detection Engineering | Risk Scoring | ML Detection | RAG-Based Deduplication")
    st.markdown("---")
    
    col_btn1, col_btn2 = st.columns([1, 4])
    with col_btn1:
        if st.button("▶ Run Detection Engine", use_container_width=True):
            with st.spinner("Analyzing logs..."):
                results = run_engine()
                st.success("Engine Executed Successfully")
                st.session_state['last_run_results'] = results
    
    if 'last_run_results' in st.session_state:
        results = st.session_state['last_run_results']
        alerts = results.get("alerts_generated", [])
        if not alerts:
            st.warning("No new alerts generated (suppressed by deduplication)")
        else:
            st.success(f"✅ {len(alerts)} new alert(s) triggered")
            st.dataframe(pd.DataFrame(alerts), use_container_width=True)
    
    st.divider()
    st.subheader("📊 Global Detection Summary")
    all_stored_alerts = alert_db.get_all_alerts()
    df_all = pd.DataFrame(all_stored_alerts) if all_stored_alerts else pd.DataFrame()
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Alerts", len(all_stored_alerts))
    if not df_all.empty:
        m2.metric("High Severity", len(df_all[df_all["severity"] == "High"]))
        m3.metric("Medium Severity", len(df_all[df_all["severity"] == "Medium"]))
        m4.metric("Low Severity", len(df_all[df_all["severity"] == "Low"]))
        
        st.subheader("📈 Alert Trends")
        fig = px.area(df_all.groupby('severity').size().reset_index(name='count'), x='severity', y='count', color='severity')
        st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("📋 Recent Alerts")
        st.dataframe(df_all.sort_values(by='timestamp', ascending=False).head(20), use_container_width=True)
    else:
        st.info("No data available. Run the detection engine first.")

def render_threat_hunter():
    st.title("🔍 NL Threat Hunter")
    st.write("Translate natural language queries to SIEM hunts and map to MITRE ATT&CK.")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        nl_query = st.text_input("Enter threat hunt query:", placeholder="e.g., Find PowerShell executions")
    with col2:
        query_lang = st.selectbox("Language", ["KQL", "EQL", "SQL"])
    
    if st.button("🔎 Execute Hunt", type="primary"):
        if nl_query:
            with st.spinner("Executing hunt..."):
                try:
                    hunt_result = threat_hunter.hunt(nl_query, target_lang=query_lang)
                    st.session_state['hunt_results'] = hunt_result
                    st.success("Hunt complete!")
                except Exception as e:
                    st.error(f"Error: {str(e)}")
        else:
            st.warning("Please enter a query.")
    
    if 'hunt_results' in st.session_state:
        res = st.session_state['hunt_results']
        st.divider()
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("📝 Generated Query")
            st.code(res.get('query', 'No query'), language=query_lang.lower())
        with c2:
            st.subheader("🛡 MITRE Mapping")
            st.info(f"Tactic: {res.get('mitre_tactic', 'N/A')}\n\nTechnique: {res.get('mitre_technique', 'N/A')}")
        
        with st.expander("View Raw Intelligence"):
            st.json(res)
    
    st.markdown("---")
    st.subheader("📜 Hunt History")
    history = threat_hunter.get_hunt_history()
    if history:
        for i, hunt in enumerate(reversed(history[-5:])):
            with st.expander(f"Hunt {len(history)-i}: {hunt.get('nl_query', 'Query')}"):
                st.json(hunt)
    else:
        st.info("No history yet.")

def render_dedup_stats():
    st.title("🧠 ML Deduplication Intelligence")
    st.write("RAG-based engine identifies duplicate alerts.")
    st.metric("Known Patterns", "128")
    st.metric("Suppression Rate", "64.2%")
    st.info("The deduplicator learns from every alert processed.")

def render_threat_intel():
    st.title("🌐 Threat Intelligence Feed")
    if st.button("🔄 Refresh Feed"):
        with st.spinner("Fetching IOCs..."):
            threat_feed_service.update_feeds()
    st.subheader("Latest Global IOCs")
    st.warning("Live feed integration placeholder")

def render_settings():
    st.title("⚙️ Platform Settings")
    st.subheader("🔔 Telegram Integration")
    st.write("Configuration for real-time alerting.")
    
    bot_token = config.TELEGRAM_BOT_TOKEN
    chat_id = config.TELEGRAM_CHAT_ID
    
    st.info(f"Bot Token: `{bot_token[:5]}***{bot_token[-5:] if len(bot_token)>10 else ''}`")
    st.info(f"Chat ID: `{chat_id}`")
    
    test_msg = st.text_input("Test Message", "Platform Status: Operational ✅")
    if st.button("Send Test Notification"):
        if bot_token and chat_id:
            try:
                url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                payload = {"chat_id": chat_id, "text": f"📣 SOC TEST\n{test_msg}"}
                resp = requests.post(url, json=payload, timeout=10)
                if resp.status_code == 200:
                    st.success("Message sent!")
                else:
                    st.error(f"Failed: {resp.status_code}")
            except Exception as e:
                st.error(f"Error: {str(e)}")
        else:
            st.warning("Credentials missing in .env")

if __name__ == "__main__":
    main()
