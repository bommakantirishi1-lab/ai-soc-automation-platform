import streamlit as st
import pandas as pd
from datetime import datetime
import requests

from alert_database import AlertDatabase
from alert_deduplication import AlertDeduplicator
from threat_feed import ThreatFeedIntegration
from config import config
from engine import run_engine
from modules.nl_threat_hunter import threat_hunter

alert_db = AlertDatabase(config.DB_PATH)
deduplicator = AlertDeduplicator(config.ML_MODEL_PATH)
threat_feed_service = ThreatFeedIntegration()

st.set_page_config(page_title="SOC Platform", page_icon="🛡️", layout="wide")
st.sidebar.title("🛡️ SOC AI Platform")
st.sidebar.markdown("---")

page = st.sidebar.radio("Menu", ["Dashboard", "Threat Hunter", "Settings"])

if page == "Dashboard":
    st.title("🛡️ Dashboard")
    if st.button("▶ Run Detection"):
        results = run_engine()
        st.success("Done")
    all_alerts = alert_db.get_all_alerts()
    st.metric("Total Alerts", len(all_alerts))

elif page == "Threat Hunter":
    st.title("🔍 Threat Hunter")
    query = st.text_input("Enter query:")
    if st.button("🔎 Hunt"):
        if query:
            try:
                result = threat_hunter.hunt(query)
                st.success("Done")
                st.json(result)
            except Exception as e:
                st.error(str(e))

elif page == "Settings":
    st.title("⚙️ Settings")
    st.subheader("Telegram")
    token = config.TELEGRAM_BOT_TOKEN
    chat_id = config.TELEGRAM_CHAT_ID
    st.write(f"Token: {token[:5]}***")
    st.write(f"Chat: {chat_id}")
    msg = st.text_input("Test msg", "OK")
    if st.button("Send"):
        if token and chat_id:
            try:
                url = f"https://api.telegram.org/bot{token}/sendMessage"
                data = {"chat_id": chat_id, "text": msg}
                resp = requests.post(url, json=data, timeout=10)
                if resp.status_code == 200:
                    st.success("Sent")
                else:
                    st.error(f"Failed: {resp.status_code}")
            except Exception as e:
                st.error(str(e))
