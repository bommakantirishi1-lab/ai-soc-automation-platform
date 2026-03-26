# modules/alert_manager.py
# Alert Lifecycle Management for AI SOC Automation Platform
# Handles alert storage, status tracking, and MITRE categorization

import sqlite3
import json
import uuid
import datetime as dt
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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                rule_id TEXT,
                rule_name TEXT,
                severity TEXT,
                mitre TEXT,
                status TEXT,
                created_at TEXT,
                updated_at TEXT,
                user TEXT,
                host TEXT,
                src_ip TEXT,
                dest_ip TEXT,
                process_name TEXT,
                command_line TEXT,
                context_json TEXT,
                owner TEXT,
                tags TEXT
            )
            """
        )
        conn.commit()
        conn.close()

    def create_alert(self, alert_data: Dict[str, Any], status: str = "new") -> str:
        """Insert a new alert into the database."""
        now = dt.datetime.utcnow().isoformat()
        alert_id = alert_data.get("alert_id") or str(uuid.uuid4())
        
        # Standardize MITRE as comma-separated string
        mitre_list = alert_data.get("mitre", [])
        mitre_str = ",".join(mitre_list) if isinstance(mitre_list, list) else str(mitre_list)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO alerts (
                alert_id, rule_id, rule_name, severity, mitre, status,
                created_at, updated_at, user, host, src_ip, dest_ip,
                process_name, command_line, context_json, owner
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                alert_id,
                alert_data.get("rule_id"),
                alert_data.get("rule_name"),
                alert_data.get("severity", "medium"),
                mitre_str,
                status,
                alert_data.get("timestamp") or now,
                now,
                alert_data.get("user"),
                alert_data.get("host"),
                alert_data.get("src_ip"),
                alert_data.get("dest_ip"),
                alert_data.get("process_name"),
                alert_data.get("command_line"),
                json.dumps(alert_data.get("context", {}), ensure_ascii=False),
                alert_data.get("owner", "unassigned")
            ),
        )
        conn.commit()
        conn.close()
        return alert_id

    def get_alerts(self, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve alerts from database with optional filters."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        query = "SELECT * FROM alerts"
        params = []
        conditions = []
        
        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY created_at DESC"
        
        cur.execute(query, params)
        rows = [dict(row) for row in cur.fetchall()]
        conn.close()
        return rows

    def update_alert(self, alert_id: str, updates: Dict[str, Any]):
        """Update specific fields of an alert (status, owner, etc.)."""
        if not updates:
            return
        
        updates["updated_at"] = dt.datetime.utcnow().isoformat()
        
        fields = []
        values = []
        for k, v in updates.items():
            fields.append(f"{k} = ?")
            values.append(v)
        
        values.append(alert_id)
        query = f"UPDATE alerts SET {', '.join(fields)} WHERE alert_id = ?"
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(query, values)
        conn.commit()
        conn.close()

    def get_statistics(self) -> Dict[str, Any]:
        """Get summary stats for the SOC dashboard."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        stats = {}
        # Count by severity
        cur.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
        stats["severity_counts"] = dict(cur.fetchall())
        
        # Count by status
        cur.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")
        stats["status_counts"] = dict(cur.fetchall())
        
        # Total alerts today
        today = dt.datetime.utcnow().date().isoformat()
        cur.execute("SELECT COUNT(*) FROM alerts WHERE created_at >= ?", (today,))
        stats["alerts_today"] = cur.fetchone()[0]
        
        conn.close()
        return stats
