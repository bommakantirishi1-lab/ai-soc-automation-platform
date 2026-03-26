# modules/case_manager.py
import uuid
import sqlite3
import datetime as dt
from typing import List

class CaseManager:
    def __init__(self, db_path: str = "soc_platform.db"):
        self.db_path = db_path
        self._ensure_schema()

    def _ensure_schema(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT,
                status TEXT,
                severity TEXT,
                owner TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS case_alerts (
                case_id TEXT,
                alert_id TEXT
            );
            CREATE TABLE IF NOT EXISTS case_timeline (
                event_id TEXT PRIMARY KEY,
                case_id TEXT,
                timestamp TEXT,
                author TEXT,
                type TEXT,
                content TEXT
            );
            """
        )
        conn.commit()
        conn.close()

    def create_case(self, title: str, severity: str, owner: str, alert_ids: List[str]):
        case_id = str(uuid.uuid4())
        now = dt.datetime.utcnow().isoformat()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO cases VALUES (?,?,?,?,?,?,?)",
            (case_id, title, "open", severity, owner, now, now),
        )
        for aid in alert_ids:
            cur.execute(
                "INSERT INTO case_alerts (case_id, alert_id) VALUES (?,?)",
                (case_id, aid),
            )
        conn.commit()
        conn.close()
        return case_id

    def add_timeline_event(self, case_id: str, author: str, type_: str, content: str):
        event_id = str(uuid.uuid4())
        now = dt.datetime.utcnow().isoformat()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO case_timeline VALUES (?,?,?,?,?,?)",
            (event_id, case_id, now, author, type_, content),
        )
        conn.commit()
        conn.close()
