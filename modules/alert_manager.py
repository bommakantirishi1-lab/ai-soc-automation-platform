# modules/alert_manager.py
# Alert Lifecycle Management for AI SOC Automation Platform
# Handles alert storage, status tracking, and MITRE categorization

import sqlite3
import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

class AlertManager:
    """
    Manages the lifecycle of security alerts in the SQLite database.
    """
    def __init__(self, db_path: str = "soc_platform.db"):
        self.db_path = db_path
        self._ensure_schema()

    def _ensure_schema(self):
        """Initialize the alerts table if it doesn't exist."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                rule_id TEXT,
                rule_name TEXT,
                severity TEXT,
                mitre_technique TEXT,
                status TEXT,
                timestamp DATETIME,
                source TEXT,
                description TEXT,
                metadata TEXT
            )
        """)
        conn.commit()
        conn.close()

    def create_alert(self, alert_data: Dict[str, Any]) -> str:
        """Adds a new alert to the database."""
        alert_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO alerts (alert_id, rule_id, rule_name, severity, mitre_technique, status, timestamp, source, description, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_id,
            alert_data.get('rule_id'),
            alert_data.get('rule_name'),
            alert_data.get('severity', 'Medium'),
            alert_data.get('mitre_technique'),
            alert_data.get('status', 'Open'),
            timestamp,
            alert_data.get('source'),
            alert_data.get('description'),
            json.dumps(alert_data.get('metadata', {}))
        ))
        conn.commit()
        conn.close()
        return alert_id

    def update_alert_status(self, alert_id: str, status: str):
        """Updates the status of an existing alert."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
        conn.commit()
        conn.close()

    def get_open_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves open alerts."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM alerts WHERE status = 'Open' ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]

if __name__ == "__main__":
    am = AlertManager()
    alert = {
        "rule_id": "SOC-001",
        "rule_name": "Brute Force Attempt",
        "severity": "High",
        "mitre_technique": "T1110",
        "source": "AuthLog",
        "description": "Multiple failed logins from 192.168.1.50"
    }
    aid = am.create_alert(alert)
    print(f"Created alert: {aid}")
