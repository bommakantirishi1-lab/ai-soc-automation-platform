from socflow_v2.core import (
    build_attack_graph,
    compute_ueba,
    correlate_incidents,
    copilot_response,
    enrich_threat_intel,
    executive_summary,
    generate_synthetic_alerts,
)


def test_generate_alerts_is_deterministic_with_seed():
    a1 = generate_synthetic_alerts(count=10, seed=7)
    a2 = generate_synthetic_alerts(count=10, seed=7)
    assert [x.alert_id for x in a1] == [x.alert_id for x in a2]
    assert [x.event_type for x in a1] == [x.event_type for x in a2]


def test_correlation_and_summary_shapes():
    alerts = generate_synthetic_alerts(count=80, seed=11)
    incidents = correlate_incidents(alerts)
    summary = executive_summary(alerts, incidents)

    assert len(incidents) > 0
    assert summary["alerts"] == 80
    assert summary["incidents"] == len(incidents)
    assert 0 <= summary["automation_rate"] <= 100


def test_ueba_returns_ranked_results():
    alerts = generate_synthetic_alerts(count=60, seed=31)
    ueba = compute_ueba(alerts)
    assert len(ueba) > 0
    assert ueba[0]["ueba_risk"] >= ueba[-1]["ueba_risk"]


def test_threat_intel_enrichment_malicious_prefix():
    intel = enrich_threat_intel("185.220.101.12")
    assert intel["verdict"] == "Malicious"
    assert intel["confidence"] >= 80


def test_attack_graph_and_copilot_response():
    alerts = generate_synthetic_alerts(count=50, seed=17)
    incidents = correlate_incidents(alerts)
    nodes, edges = build_attack_graph(alerts)

    assert len(nodes) > 0
    assert len(edges) > 0

    message = copilot_response("what should I do?", incidents[0])
    assert incidents[0]["incident_id"] in message
