import math
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from socflow_v2.core import (
    compute_ueba,
    copilot_response,
    correlate_incidents,
    executive_summary,
    generate_synthetic_alerts,
    build_attack_graph,
    enrich_threat_intel,
)


st.set_page_config(page_title="SOCFlow v2", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .stApp { background: #0a1220; color: #e4edf9; }
    .block-container { padding-top: 1rem; }
    .metric-card { border: 1px solid #1f3f64; border-radius: 12px; padding: 14px; background: #0f1d33; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ SOCFlow v2 — AI-Powered SOC Platform")
st.caption("Enterprise-ready SOC demo: Correlation • UEBA • MITRE • Copilot • SOAR playbooks")

with st.sidebar:
    st.header("Control Plane")
    seed = st.number_input("Simulation seed", min_value=1, max_value=9999, value=42)
    event_count = st.slider("Alert volume", min_value=60, max_value=500, value=180)
    refresh = st.button("Regenerate scenario")
    st.markdown("---")
    st.write("**Copilot Runtime**")
    ollama_endpoint = st.text_input("Ollama endpoint", value="http://localhost:11434")
    st.caption("Runs locally when available. Dashboard uses deterministic fallback text if unavailable.")

if refresh:
    st.cache_data.clear()


@st.cache_data(show_spinner=False)
def load_data(_seed: int, _count: int):
    alerts = generate_synthetic_alerts(count=_count, seed=_seed)
    incidents = correlate_incidents(alerts)
    ueba = compute_ueba(alerts)
    summary = executive_summary(alerts, incidents)
    return alerts, incidents, ueba, summary


alerts, incidents, ueba_rows, summary = load_data(seed, event_count)
alerts_df = pd.DataFrame([a.__dict__ for a in alerts]).sort_values("timestamp", ascending=False)
incidents_df = pd.DataFrame(incidents)
ueba_df = pd.DataFrame(ueba_rows)

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Alerts", f"{summary['alerts']}")
k2.metric("Correlated Incidents", f"{summary['incidents']}")
k3.metric("Automation Rate", f"{summary['automation_rate']}%")
k4.metric("MTTR", f"{summary['mttr_minutes']} min")
k5.metric("High/Critical Prevented", f"{summary['high_critical_prevented']}")


tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
    [
        "Detection & Correlation",
        "AI SOC Copilot",
        "UEBA",
        "Threat Intel",
        "SOAR + Attack Graph",
        "Compliance Reports",
    ]
)

with tab1:
    st.subheader("Live SIEM-Style Ingestion and Correlation")
    c1, c2 = st.columns([1.3, 1])
    with c1:
        st.dataframe(
            alerts_df[["alert_id", "timestamp", "event_type", "severity", "user", "source_ip", "host", "base_score"]],
            use_container_width=True,
            height=350,
            hide_index=True,
        )
    with c2:
        severity_counts = alerts_df["severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"]).fillna(0)
        fig = px.bar(
            x=severity_counts.index,
            y=severity_counts.values,
            color=severity_counts.index,
            color_discrete_map={"Critical": "#f43f5e", "High": "#f97316", "Medium": "#fbbf24", "Low": "#22c55e"},
            title="Alert Severity Distribution",
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("#### Top Correlated Incidents")
    st.dataframe(
        incidents_df[["incident_id", "entity", "source_ip", "alert_count", "avg_score", "severity", "recommended_playbook"]].head(12),
        use_container_width=True,
        hide_index=True,
    )

with tab2:
    st.subheader("AI SOC Copilot (Local-first)")
    st.caption("This tab is wired for local-LLM workflow and ships with deterministic fallback guidance.")

    prompt = st.text_area(
        "Ask Copilot",
        placeholder="Example: summarize the highest-risk incident and recommend first 3 response actions.",
        height=120,
    )
    top_incident = incidents[0] if incidents else None
    if st.button("Run Copilot Analysis", type="primary"):
        response = copilot_response(prompt, top_incident)
        st.success(response)
        st.info(f"Configured endpoint: {ollama_endpoint}")

    if top_incident:
        st.markdown("#### Active Incident Context")
        st.json(top_incident)

with tab3:
    st.subheader("UEBA — User & Entity Behavior Analytics")
    c1, c2 = st.columns([1, 1])
    with c1:
        st.dataframe(ueba_df, hide_index=True, use_container_width=True)
    with c2:
        fig = px.scatter(
            ueba_df,
            x="alert_volume",
            y="ueba_risk",
            color="status",
            size="avg_alert_score",
            hover_name="user",
            title="UEBA Risk vs Volume",
            color_discrete_map={"Watchlist": "#ef4444", "Normal": "#22c55e"},
        )
        st.plotly_chart(fig, use_container_width=True)

with tab4:
    st.subheader("Threat Intel Enrichment")
    selected_ip = st.selectbox("Select IOC IP", options=sorted(alerts_df["source_ip"].unique()))
    intel = enrich_threat_intel(selected_ip)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Verdict", intel["verdict"])
    c2.metric("Confidence", f"{intel['confidence']}%")
    c3.metric("VirusTotal Detections", intel["virustotal_detections"])
    c4.metric("AbuseIPDB Score", intel["abuseipdb_score"])

    st.json(intel)

with tab5:
    st.subheader("SOAR Playbook Readiness + Attack Graph")
    playbook_counts = incidents_df["recommended_playbook"].value_counts().reset_index()
    playbook_counts.columns = ["playbook", "count"]

    c1, c2 = st.columns([1, 1.1])
    with c1:
        fig = px.bar(playbook_counts, x="count", y="playbook", orientation="h", title="Playbook Execution Demand")
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        nodes, edges = build_attack_graph(alerts)
        coords = {}
        for i, node in enumerate(nodes):
            angle = 2 * math.pi * (i / max(len(nodes), 1))
            coords[node] = (math.cos(angle), math.sin(angle))

        edge_x, edge_y = [], []
        for src, dst in edges:
            x0, y0 = coords[src]
            x1, y1 = coords[dst]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        node_x = [coords[n][0] for n in nodes]
        node_y = [coords[n][1] for n in nodes]

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines", line=dict(width=0.6, color="#64748b"), hoverinfo="none"))
        fig.add_trace(
            go.Scatter(
                x=node_x,
                y=node_y,
                mode="markers+text",
                text=nodes,
                textposition="top center",
                marker=dict(size=11, color="#60a5fa"),
                hoverinfo="text",
            )
        )
        fig.update_layout(title="Attack Path Graph", showlegend=False, xaxis=dict(visible=False), yaxis=dict(visible=False), height=420)
        st.plotly_chart(fig, use_container_width=True)

with tab6:
    st.subheader("Audit Logging & Compliance-Ready Reporting")
    report_df = incidents_df[["incident_id", "entity", "source_ip", "severity", "alert_count", "avg_score", "recommended_playbook"]].copy()
    report_df["generated_at"] = datetime.utcnow().isoformat()

    st.dataframe(report_df, use_container_width=True, hide_index=True)
    st.download_button(
        "Download Incident Report (CSV)",
        report_df.to_csv(index=False).encode("utf-8"),
        file_name=f"socflow_report_{datetime.utcnow():%Y%m%d_%H%M}.csv",
        mime="text/csv",
    )

st.caption("SOCFlow v2 demo app • Designed for enterprise demos and stakeholder storytelling")
