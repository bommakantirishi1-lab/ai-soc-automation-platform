import pandas as pd

from alert_database import AlertDatabase
from alert_deduplication import AlertDeduplicator
import engine


def test_alert_database_round_trip(tmp_path):
    db_path = tmp_path / "alerts.db"
    db = AlertDatabase(str(db_path))

    sample = {
        "ip": "192.0.2.10",
        "score": 8,
        "severity": "Medium",
        "events": ["failed_login", "successful_login"],
        "country": "US",
        "city": "Dallas",
        "isp": "Example ISP",
        "lat": 32.7,
        "lon": -96.7,
        "analyst": "Unit Tester",
    }

    assert db.add_alert(sample) is True
    stored = db.get_all_alerts()
    assert len(stored) == 1
    assert stored[0]["ip"] == sample["ip"]
    assert stored[0]["events"] == sample["events"]


def test_deduplicator_suppresses_same_signature(tmp_path):
    model_path = tmp_path / "dedup.pkl"
    dedup = AlertDeduplicator(str(model_path))

    alert = {
        "ip": "198.51.100.5",
        "severity": "High",
        "events": ["failed_login", "process_creation"],
        "score": 11,
    }

    should_trigger, _ = dedup.should_trigger_alert(alert, [])
    assert should_trigger is True

    should_trigger_again, reason = dedup.should_trigger_alert(alert, [])
    assert should_trigger_again is False
    assert "Duplicate" in reason


def test_run_engine_returns_expected_shape(monkeypatch):
    fake_df = pd.DataFrame(
        [
            {"source_ip": "203.0.113.1", "event_type": "failed_login", "timestamp": "2026-04-23T00:00:00"},
            {"source_ip": "203.0.113.1", "event_type": "successful_login", "timestamp": "2026-04-23T00:01:00"},
            {"source_ip": "203.0.113.2", "event_type": "process_creation", "timestamp": "2026-04-23T00:02:00"},
            {"source_ip": "203.0.113.3", "event_type": "outbound_connection", "timestamp": "2026-04-23T00:03:00"},
            {"source_ip": "203.0.113.4", "event_type": "failed_login", "timestamp": "2026-04-23T00:04:00"},
            {"source_ip": "203.0.113.5", "event_type": "successful_login", "timestamp": "2026-04-23T00:05:00"},
        ]
    )

    monkeypatch.setattr(engine, "generate_demo_attacks", lambda: fake_df)
    monkeypatch.setattr(engine, "lookup_ip", lambda ip: {"ip": ip, "country": "Unknown", "city": "Unknown", "isp": "Unknown", "lat": None, "lon": None})
    monkeypatch.setattr(engine, "send_telegram", lambda message: None)

    result = engine.run_engine()

    assert isinstance(result, dict)
    assert "alerts_generated" in result
    assert "visitors" in result
    assert "engine_status" in result
    assert result["engine_status"] == "completed"
