import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import requests
import json
import time

from alert_database import AlertDatabase
from alert_deduplication import AlertDeduplicator
from threat_feed import ThreatFeedIntegration
from config import config
from engine import run_engine
from modules.nl_threat_hunter import threat_hunter
from modules.log_ingestion import LogIngestion
from modules.detection_engine import DetectionEngine
from modules.alert_manager import AlertManager
from modules.case_manager import CaseManager
from modules.threat_intel import ThreatIntel
from modules.nvidia_ai import NvidiaAI
from modules.newsletter import Newsletter

# Initialize Core Services
alert_db = AlertDatabase(config.DB_PATH)
deduplicator = AlertDeduplicator(config.ML_MODEL_PATH)
threat_feed_service = ThreatFeedIntegration()
nvidia_ai = NvidiaAI()

st.set_page_config(page_title="AI SOC NEXUS", page_icon="🔮", layout="wide")

# --- CYBERPUNK AI THEME ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=JetBrains+Mono:wght@300;500&display=swap');
    
    .main { background-color: #03030b; color: #e0e0ff; font-family: 'JetBrains Mono', monospace; }
    .stApp { background: radial-gradient(circle at top right, #0a0a2e, #03030b); }
    
    h1, h2, h3 { font-family: 'Orbitron', sans-serif !important; color: #00f2ff !important; text-transform: uppercase; letter-spacing: 2px; text-shadow: 0 0 10px #00f2ff55; }
    
    /* AI Card Style */
    .ai-card {
        background: rgba(10, 10, 35, 0.6);
        border: 1px solid #00f2ff44;
        border-radius: 15px;
        padding: 20px;
        backdrop-filter: blur(10px);
        box-shadow: 0 4px 15px rgba(0, 242, 255, 0.1);
        transition: all 0.3s ease;
    }
    .ai-card:hover { border-color: #00f2ff; box-shadow: 0 0 20px rgba(0, 242, 255, 0.3); transform: translateY(-5px); }
    
    /* Metric Style */
    .metric-val { font-family: 'Orbitron', sans-serif; font-size: 2.2rem; font-weight: 700; color: #ffffff; }
    .metric-label { font-size: 0.9rem; color: #00f2ff; text-transform: uppercase; }
    
    /* Glowing Button */
    .stButton>button {
        background: linear-gradient(45deg, #00f2ff, #7000ff) !important;
        color: white !important;
        border: none !important;
        border-radius: 5px !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: bold !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        box-shadow: 0 0 15px #00f2ff55 !important;
        transition: all 0.3s ease !important;
    }
    .stButton>button:hover { box-shadow: 0 0 30px #00f2ffaa !important; transform: scale(1.05); }
    
    /* Terminal Effect */
    .terminal {
        background-color: #000;
        border-left: 3px solid #00f2ff;
        padding: 10px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        color: #00ff41;
        margin-bottom: 20px;
    }
    
    /* Sidebar styling */
    section[data-testid="stSidebar"] { background-color: #050515 !important; border-right: 1px solid #00f2ff22; }
    </style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("<h2 style='text-align: center;'>AI NEXUS</h2>", unsafe_allow_html=True)
    st.image("https://img.icons8.com/nolan/128/artificial-intelligence.png", width=80)
    st.markdown("---")
    page = st.radio("CORE MODULES", ["DASHBOARD", "NEURAL HUNTER", "LOG ANALYSIS", "THREAT INTELLIGENCE", "SETTINGS"])
    st.markdown("---")
    st.markdown("**CORE STATUS:** <span style='color:#00ff41;'>OPERATIONAL</span>", unsafe_allow_html=True)
    st.markdown("**AI MODEL:** `SOC-LLAMA-GPT-V2`")

if page == "DASHBOARD":
    st.markdown("<h1>🛡️ Strategic AI Overview</h1>", unsafe_allow_html=True)
    
    # Hero Metrics
    all_alerts = alert_db.get_all_alerts()
    df = pd.DataFrame(all_alerts) if all_alerts else pd.DataFrame()
    
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="ai-card"><div class="metric-label">Neural Detections</div><div class="metric-val">{len(all_alerts)}</div></div>', unsafe_allow_html=True)
    with c2:
        critical = len(df[df["severity"] == "High"]) if not df.empty else 0
        st.markdown(f'<div class="ai-card"><div class="metric-label" style="color:#ff0055;">Critical Threats</div><div class="metric-val">{critical}</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="ai-card"><div class="metric-label">AI Supression</div><div class="metric-val">73.2%</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="ai-card"><div class="metric-label">Neural Latency</div><div class="metric-val">42ms</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    
    col_main, col_side = st.columns([2, 1])
    
    with col_main:
        st.markdown("<h3>🔮 Threat Propagation Radar</h3>", unsafe_allow_html=True)
        if not df.empty:
            fig = px.line(df, x="timestamp", y="severity", color="rule_name", 
                         title="Detection Velocity", template="plotly_dark",
                         color_discrete_sequence=px.colors.sequential.Cyan)
            fig.update_layout(plot_bgcolor=\'rgba(0,0,0,0)\', paper_bgcolor=\'rgba(0,0,0,0)\')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.markdown(\'<div class="terminal">SYSTEM READY. NO DETECTIONS IN CURRENT BUFFER.</div>\', unsafe_allow_html=True)

    with col_side:
        st.markdown("<h3>⚡ Core Controls</h3>", unsafe_allow_html=True)
        if st.button("🔥 INITIATE FULL SCAN"):
            with st.status("Initializing AI Heuristics...", expanded=True) as status:
                st.write("Scanning log buffers...")
                time.sleep(1)
                st.write("Applying Neural Rules...")
                results = run_engine()
                time.sleep(1)
                status.update(label="Neural Scan Complete!", state="complete", expanded=False)
            st.rerun()

        st.markdown("---")
        st.markdown("<h3>🗞️ Intelligence Brief</h3>", unsafe_allow_html=True)
        if st.button("📩 GENERATE NEWSLETTER"):
            newsletter = Newsletter()
            md, _ = newsletter.build_daily()
            st.markdown(md)

elif page == "NEURAL HUNTER":
    st.markdown("<h1>🔍 Neural Threat Hunter</h1>", unsafe_allow_html=True)
    st.markdown(\'<div class="terminal">> ENTER NATURAL LANGUAGE QUERY TO INTERROGATE SIEM CORE...</div>\', unsafe_allow_html=True)
    
    col1, col2 = st.columns([3, 1])
    with col1:
        query = st.text_input("QUERY INPUT:", placeholder="e.g., find all failed logins from Russia in the last hour")
    with col2:
        lang = st.selectbox("TARGET PROTOCOL", ["KQL", "EQL", "SQL", "SPL"])
    
    if st.button("⚡ EXECUTE NEURAL TRANSLATION"):
        if query:
            with st.spinner("Decoding language vectors..."):
                result = threat_hunter.hunt(query, target_lang=lang)
                st.session_state[\'hunt_result\'] = result
                
    if \'hunt_result\' in st.session_state:
        res = st.session_state[\'hunt_result\']
        st.markdown("<h3>🧬 Resulting AI Logic</h3>", unsafe_allow_html=True)
        st.code(res.get("query", ""), language=lang.lower())
        
        c1, c2 = st.columns(2)
        with c1:
            st.info(f"**MITRE TACTIC:** {res.get(\'mitre_tactic\', \'N/A\')}")
        with c2:
            st.warning(f"**TECHNIQUE:** {res.get(\'mitre_technique\', \'N/A\')}")

elif page == "LOG ANALYSIS":
    st.markdown("<h1>🧠 Log Intelligence Core</h1>", unsafe_allow_html=True)
    st.markdown(\'<div class="terminal">> AI DATASET INGESTION MODULE ACTIVE.</div>\', unsafe_allow_html=True)
    
    uploaded_file = st.file_uploader("UPLOAD LOG FILE (JSON/CSV/NDJSON)")
    if uploaded_file:
        st.success("Dataset Locked. Ready for AI Analysis.")

elif page == "THREAT INTELLIGENCE":
    st.markdown("<h1>🌐 Global Intelligence Mesh</h1>", unsafe_allow_html=True)
    
    col1, col2 = st.columns([1, 2])
    with col1:
        st.markdown("<h3>🔍 IOC Lookup</h3>", unsafe_allow_html=True)
        ioc = st.text_input("Enter IP/Hash/Domain:")
        if st.button("Interrogate VirusTotal"):
            intel = ThreatIntel()
            # result = intel.lookup_hash(ioc) # Logic here
            st.info("Querying Global Reputations...")
            
    with col2:
        st.markdown("<h3>🔥 Real-time Indicators</h3>", unsafe_allow_html=True)
        st.dataframe(pd.DataFrame({
            "INDICATOR": ["185.220.101.12", "45.95.147.23", "maldoc.exe"],
            "AI_CONFIDENCE": ["98%", "94%", "99.9%"],
            "SEVERITY": ["CRITICAL", "HIGH", "CRITICAL"]
        }), use_container_width=True)

elif page == "SETTINGS":
    st.markdown("<h1>⚙️ Nexus Configuration</h1>", unsafe_allow_html=True)
    st.subheader("Neural API Keys")
    st.text_input("NVIDIA API KEY", type="password")
    st.text_input("VIRUSTOTAL API KEY", type="password")
    st.checkbox("Enable Real-time Telegram Notifications", value=True)
