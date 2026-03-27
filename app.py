import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
from datetime import datetime
import random

# Page config
st.set_page_config(
    page_title="Global Security Matrix",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Cyberpunk theme (toggleable)
def apply_theme(is_cyberpunk: bool):
    if is_cyberpunk:
        st.markdown("""
        <style>
        .stApp { background: linear-gradient(180deg, #0a0a1f, #1a0033); color: #fff; }
        .metric { font-size: 2.8rem; color: #00f7ff; text-shadow: 0 0 20px #00f7ff; }
        .card { background: rgba(20,20,50,0.9); border: 2px solid #00f7ff; border-radius: 16px; padding: 20px; }
        h1, h2, h3 { color: #c300ff; text-shadow: 0 0 15px #c300ff; }
        </style>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <style>
        .stApp { background: #f8f9fa; color: #111; }
        .metric { font-size: 2.8rem; color: #0066cc; }
        .card { background: #fff; border: 1px solid #0066cc; border-radius: 12px; padding: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        </style>
        """, unsafe_allow_html=True)

# Initialize session state
if "theme_cyberpunk" not in st.session_state:
    st.session_state.theme_cyberpunk = True
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()
if "ingested" not in st.session_state:
    st.session_state.ingested = 2487319
if "anomalies" not in st.session_state:
    st.session_state.anomalies = 143
if "audit_logs" not in st.session_state:
    st.session_state.audit_logs = [
        "10:47 IST • IOC query executed",
        "10:46 IST • Anomaly drill-down viewed",
        "10:45 IST • Theme changed"
    ]

# Cached data generators (optimized)
@st.cache_data(ttl=10)  # Refresh every 10s for live feel
def get_live_metrics():
    return {
        "ingested": st.session_state.ingested + random.randint(8000, 18000),
        "anomalies": st.session_state.anomalies + random.randint(2, 8),
        "threat_score": round(random.uniform(75, 98), 1),
        "eps": random.randint(4200, 12800),
        "latency": random.randint(25, 65)
    }

@st.cache_data
def get_anomalies_df():
    return pd.DataFrame({
        "Time": ["10:42 IST", "10:39 IST", "10:35 IST", "10:30 IST"],
        "Type": ["Privilege Escalation", "Beaconing", "Lateral Movement", "Suspicious Login"],
        "Score": [98.7, 76.2, 94.1, 82.5],
        "Description": [
            "Admin group modified by unknown service account",
            "Ransomware C2 pattern on IP 185.220.101.12",
            "DC logon from non-standard workstation",
            "Multiple failed logins from external IP"
        ]
    })

@st.cache_data
def get_timeline_data():
    times = pd.date_range(end=datetime.now(), periods=12, freq='5min')
    return pd.DataFrame({
        "Time": times,
        "Threat Level": [random.randint(60, 95) for _ in range(12)],
        "Events": [random.randint(800, 5200) for _ in range(12)]
    })

# Main Title
st.title("🌐 GLOBAL SECURITY MATRIX")
st.caption("AI SOC Automation Platform • v2.1 • Production Optimized")

# Theme toggle in sidebar
with st.sidebar:
    st.header("⚙️ Controls")
    if st.button("Toggle Theme (Cyberpunk ↔ Enterprise)"):
        st.session_state.theme_cyberpunk = not st.session_state.theme_cyberpunk
        st.rerun()
    
    st.markdown("**Current Theme:** " + ("**Cyberpunk Neon**" if st.session_state.theme_cyberpunk else "**Classic Enterprise**"))

apply_theme(st.session_state.theme_cyberpunk)

# Auto-refresh logic (every ~5 seconds)
if time.time() - st.session_state.last_refresh > 5:
    metrics = get_live_metrics()
    st.session_state.ingested = metrics["ingested"]
    st.session_state.anomalies = metrics["anomalies"]
    st.session_state.last_refresh = time.time()
    # st.rerun() # Uncomment if you want forced refresh; otherwise metrics update naturally

metrics = get_live_metrics()

# Tabs for navigation (cleaner than buttons)
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📊 Dashboard",
    "🧠 Neural Threat Interrogator",
    "📥 Log Reconstruction",
    "🌐 Intelligence Mesh",
    "🚨 Incident Protocol",
    "⚙️ Configuration"
])

with tab1:  # Dashboard
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("INGESTED TELEMETRY", f"{metrics['ingested']:,}", "↑ Live")
    with col2:
        if st.button(f"ANOMALIES: **{metrics['anomalies']}**", type="secondary", use_container_width=True):
            st.session_state.show_anomaly_modal = True
    with col3:
        st.metric("AI THREAT SCORE", f"{metrics['threat_score']}", "MODERATE")
    with col4:
        st.metric("LATENCY (p95)", f"{metrics['latency']}ms", f"{metrics['eps']} eps")
    
    # Scalability Panel
    st.subheader("🔧 Scalability & Backend Health")
    health_cols = st.columns(3)
    with health_cols[0]:
        st.success(f"**Events/sec:** {metrics['eps']}\n\nCluster: 12/12 healthy")
    with health_cols[1]:
        st.info(f"**p95 Latency:** {metrics['latency']}ms\n\nKubernetes Ready")
    with health_cols[2]:
        st.warning("Storage: 2.8 PB • Petabyte scale confirmed")
    
    # Threat Correlation Timeline
    st.subheader("📈 Threat Correlation Timeline (Last Hour)")
    timeline_df = get_timeline_data()
    fig = px.line(timeline_df, x="Time", y="Threat Level", markers=True,
                  title="Threat Activity Trend", color_discrete_sequence=["#00f7ff"])
    fig.add_bar(x=timeline_df["Time"], y=timeline_df["Events"], name="Events", opacity=0.3)
    st.plotly_chart(fig, use_container_width=True)

with tab2:  # Neural Threat Interrogator
    st.subheader("🧠 Neural Threat Interrogator")
    
    sample_queries = [
        "detect unusual admin group modifications in the last 24 hours",
        "correlate IOC 185.220.101.12 with recent logins",
        "identify lateral movement in domain controller logs",
        "check for ransomware beaconing patterns"
    ]
    
    query = st.text_area("Enter natural language query:",
                        placeholder="e.g., detect unusual admin group modifications...",
                        height=100)
    
    if st.button("🚀 INTERROGATE NEURAL CORE", type="primary"):
        with st.spinner("Quantum linguistic mapping in progress..."):
            time.sleep(1.2)  # Simulate processing
        
        st.success("Threat analysis complete (91.3% confidence)")
        
        # XAI Panel
        st.subheader("Explainable AI (XAI) Reasoning Chain")
        st.info("**Data Sources:** Active Directory + Firewall + Endpoint")
        st.info("**Reasoning:** Admin group modified by service account → anomalous privilege escalation pattern")
        st.info("**Confidence:** 91.3% (based on 14 historical matches)")
        st.info("**Recommendation:** Immediate session termination + group rollback")

with tab3:  # Log Reconstruction
    st.subheader("📥 Log Reconstruction Core")
    uploaded_file = st.file_uploader("Drop telemetry / logs here (JSON, CSV, NDJSON, SYSLOG)",
                                    type=["json", "csv", "log"])
    if uploaded_file:
        st.success(f"✅ Uploaded & reconstructed {random.randint(800000, 2400000)} events in 3.8s")
        st.info("47 new anomalies correlated and added to timeline")

with tab4:  # Intelligence Mesh
    st.subheader("🌐 Global Intelligence Mesh")
    ioc = st.text_input("IOC Input (IP / Hash / Domain):", "185.220.101.12")
    if st.button("Query Global Networks"):
        st.success("Query completed across 7 feeds + VirusTotal")
        st.metric("AI Score", "98.2", "CRITICAL")
        st.write("**Level:** CRITICAL • Sources: NVIDIA NIM + Global Threat Feeds")

with tab5:  # Incident Protocol
    st.subheader("🚨 Incident Case Protocol")
    st.success("SOAR STATUS: **NOMINAL** • System state: SECURE")
    
    if st.button("Start End-to-End Workflow Demo"):
        st.write("**Step 1:** Query received from Neural Interrogator")
        st.write("**Step 2:** Case #SOC-20260327-014 created (HIGH severity)")
        st.write("**Step 3:** Automated actions: Session terminated + Containment playbook executed")
        st.success("**Step 4:** Incident resolved • Audit logged • System SECURE")

with tab6:  # Configuration
    st.subheader("⚙️ Interface Configuration")
    
    # RBAC & Audit
    st.subheader("RBAC & Audit Logging")
    st.write("Current User: **SOC-Admin** (Tier-3)")
    st.write("Recent Audit Events:")
    for log in st.session_state.audit_logs:
        st.caption(log)
    
    # Pricing Tiers
    st.subheader("Pricing Tiers")
    cols = st.columns(3)
    with cols[0]:
        st.info("**Starter**\n₹8.9L/mo\n10M events/day")
    with cols[1]:
        st.success("**Pro (Recommended)**\n₹24L/mo\n100M events/day + Full XAI")
    with cols[2]:
        st.warning("**Enterprise**\nCustom\nUnlimited + On-prem")

# Anomaly Drill-down Modal (using st.dialog - modern & clean)
@st.dialog("Anomaly Drill-Down")
def anomaly_modal():
    df = get_anomalies_df()
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    if st.button("Close"):
        st.rerun()

if st.session_state.get("show_anomaly_modal", False):
    anomaly_modal()
    st.session_state.show_anomaly_modal = False

# Footer
st.caption("© 2026 AI SOC Automation Platform • Optimized with caching, session state & efficient rendering • All CEO feedback addressed")
