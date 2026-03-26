# modules/alert_manager.py
from typing import List, Dict, Any, Optional
import sqlite3
import datetime as dt
import json

class AlertManager:
    def __init__(self, db_path: str = "soc_platform.db"):
        self.db_path = db_path
        self._ensure_schema()

    def _ensure_schema(self):
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
                context_json TEXT
            )
            """
        )
        conn.commit()
        conn.close()

    def create_alert(self, alert: Dict[str, Any], status: str = "new"):
        now = dt.datetime.utcnow().isoformat()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO alerts (
                alert_id, rule_id, rule_name, severity, mitre, status,
                created_at, updated_at, user, host, src_ip, dest_ip,
                process_name, command_line, context_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                alert["alert_id"],
                alert["rule_id"],
                alert["rule_name"],
                alert["severity"],
                ",".join(alert.get("mitre", [])),
                status,
                now,
                now,
                alert.get("user"),
                alert.get("host"),
                alert.get("src_ip"),
                alert.get("dest_ip"),
                alert.get("process_name"),
                alert.get("command_line"),
                json.dumps(alert.get("context", {}), ensure_ascii=False),
            ),
        )
        conn.commit()
        conn.close()

    def update_status(self, alert_id: str, status: str):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE alert_id = ?",
            (status, dt.datetime.utcnow().isoformat(), alert_id),
        )
        conn.commit()
        conn.close()
