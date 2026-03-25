import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

# ===============================
# IMPORT AND INITIALIZE FIRST
# ===============================
from alert_database import AlertDatabase
from alert_deduplication import AlertDeduplicator
from threat_feed import ThreatFeedIntegration
from config import config
from engine import run_engine
from modules.nl_threat_hunter import threat_hunter

# Initialize the modules
alert_db = AlertDatabase(config.DB_PATH)
deduplicator = AlertDeduplicator(config.ML_MODEL_PATH)
threat_feed_service = ThreatFeedIntegration()

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




# ===============================
# NATURAL LANGUAGE THREAT HUNTING (PRODUCTION-READY)
# ===============================
st.divider()
st.subheader("🔍 NL Threat Hunter - AI-Powered Threat Hunting")

# Initialize session state for hunt results
if 'hunt_results' not in st.session_state:
    st.session_state.hunt_results = []
if 'show_history' not in st.session_state:
    st.session_state.show_history = False

st.markdown("""
**Professional Threat Hunting Tool** - Translate natural language queries into SIEM queries, 
execute hunts, enrich IOCs with threat intelligence, and map to MITRE ATT&CK framework.

💡 **Example Queries**: 
- "Find PowerShell executions from suspicious IPs"
- "Search for lateral movement attempts"
- "Detect privilege escalation"
""")

# Threat Hunting Interface
col_hunt1, col_hunt2, col_hunt3 = st.columns([2, 1, 1])

with col_hunt1:
    nl_query = st.text_input(
        "🎯 Enter your threat hunt in plain English:",
        placeholder="e.g., 'Find PowerShell executions with network connections'",
        key="nl_query_input"
    )

with col_hunt2:
    query_lang = st.selectbox(
        "Query Language", 
        ["KQL", "EQL"], 
        key="hunt_lang",
        help="Choose target SIEM query language"
    )

with col_hunt3:
    hunt_button = st.button(
        "🔍 Execute Hunt", 
        key="hunt_btn",
        type="primary",
        use_container_width=True
    )

# Execute Hunt
if hunt_button:
    if nl_query and nl_query.strip():
        with st.spinner("⚡ Executing threat hunt..."):
            try:
                # Execute hunt using integrated threat hunter
                hunt_result = threat_hunter.hunt(nl_query, target_lang=query_lang)
                
                # Store result in session state
                st.session_state.hunt_results.insert(0, hunt_result)  # Add to beginning
                
                # Keep only last 10 hunts
                if len(st.session_state.hunt_results) > 10:
                    st.session_state.hunt_results = st.session_state.hunt_results[:10]
                
                # Display success
                st.success(f"✅ Hunt complete! Found {hunt_result.get('result_count', 0)} results")
                
                # Show results in expandable sections
                with st.expander("📊 Hunt Results", expanded=True):
                    col_r1, col_r2, col_r3 = st.columns(3)
                    col_r1.metric("Results Found", hunt_result.get('result_count', 0))
                    col_r2.metric("Query Language", hunt_result.get('query_language', 'N/A'))
                    col_r3.metric("Status", hunt_result.get('status', 'N/A').upper())
                    
                    st.code(hunt_result.get('generated_query', 'No query generated'), language='sql')
                    
                    # Display results
                    if hunt_result.get('results'):
                        st.dataframe(
                            pd.DataFrame(hunt_result['results']),
                            use_container_width=True,
                            hide_index=True
                        )
                    
                    # MITRE Mapping
                    mitre = hunt_result.get('mitre_mapping', {})
                    if mitre.get('techniques'):
                        st.info(f"🎯 MITRE ATT&CK: {', '.join(mitre.get('techniques', []))}")
                
            except Exception as e:
                st.error(f"❌ Hunt failed: {str(e)}")
    else:
        st.warning("⚠️ Please enter a threat hunting query.")

# Hunt History Toggle (FIXED - using session state)
st.divider()
col_hist1, col_hist2 = st.columns([3, 1])

with col_hist1:
    st.markdown("### 📜 Hunt History")

with col_hist2:
    if st.button("Toggle History" if not st.session_state.show_history else "Hide History"):
        st.session_state.show_history = not st.session_state.show_history

if st.session_state.show_history:
    if st.session_state.hunt_results:
        st.success(f"Showing {len(st.session_state.hunt_results)} recent hunts")
        for idx, hunt in enumerate(st.session_state.hunt_results):
            with st.expander(
                f"🔎 Hunt #{idx + 1}: {hunt.get('nl_query', 'Unknown')[:50]}... - {hunt.get('timestamp', '')[:19]}",
                expanded=False
            ):
                col_h1, col_h2, col_h3 = st.columns(3)
                col_h1.metric("Results", hunt.get('result_count', 0))
                col_h2.metric("Language", hunt.get('query_language', 'N/A'))
                col_h3.metric("Status", hunt.get('status', 'N/A').upper())
                
                st.code(hunt.get('generated_query', 'No query'), language='sql')
                
                if hunt.get('mitre_mapping', {}).get('techniques'):
                    st.caption(f"MITRE: {', '.join(hunt['mitre_mapping']['techniques'])}")
    else:
        st.info("🔍 No hunts executed yet. Start your first threat hunt above!")

# TELEGRAM NOTIFICATION TEST (FIXED)
st.divider()
with st.expander("🔔 Test Telegram Notifications", expanded=False):
    st.markdown("""
    **Configure Telegram Bot**:
    1. Get Bot Token from @BotFather
    2. Get Chat ID from @userinfobot
    3. Add to .env file
    """)
    
    test_message = st.text_input("Test Message", value="Test from SOC Automation Platform", key="test_telegram")
    
    if st.button("📤 Send Test Notification", key="send_test_telegram"):
        try:
            if config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID:
                url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
                response = requests.post(url, data={
                    "chat_id": config.TELEGRAM_CHAT_ID,
                    "text": f"🔔 TEST NOTIFICATION\n\n{test_message}\n\n✅ Telegram integration working!"
                }, timeout=10)
                
                if response.status_code == 200:
                    st.success("✅ Telegram notification sent successfully!")
                    st.json(response.json())
                else:
                    st.error(f"❌ Failed to send: HTTP {response.status_code}")
                    st.json(response.json())
            else:
                st.error("❌ Telegram credentials not configured in .env file")
                st.code("""
# Add to .env file:
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
                """, language="bash")
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    main()
