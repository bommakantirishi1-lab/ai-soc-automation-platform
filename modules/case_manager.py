# modules/case_manager.py
# Incident Case Management for AI SOC Automation Platform
# Manages cases, alerts linked to cases, and investigation timelines

import sqlite3
import uuid
import datetime as dt
from typing import List, Dict, Any, Optional

class CaseManager:
    """
    Manages security incident cases, their status, ownership, and timeline events.
    """

    def __init__(self, db_path: str = "soc_platform.db"):
        self.db_path = db_path
        self._ensure_schema()

    def _ensure_schema(self):
        """Initialize the case-related tables."""
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
                updated_at TEXT,
                description TEXT
            );
            CREATE TABLE IF NOT EXISTS case_alerts (
                case_id TEXT,
                alert_id TEXT,
                PRIMARY KEY (case_id, alert_id)
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

    def create_case(self, 
                    title: str, 
                    severity: str, 
                    owner: str, 
                    alert_ids: List[str], 
                    description: str = "") -> str:
        """Create a new case and link specified alerts to it."""
        case_id = str(uuid.uuid4())
        now = dt.datetime.utcnow().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Insert case
        cur.execute(
            "INSERT INTO cases VALUES (?,?,?,?,?,?,?,?)",
            (case_id, title, "open", severity, owner, now, now, description),
        )
        
        # Link alerts
        for aid in alert_ids:
            cur.execute(
                "INSERT OR IGNORE INTO case_alerts (case_id, alert_id) VALUES (?,?)",
                (case_id, aid),
            )
            # Update alert status to 'linked' or similar if needed
        
        # Initial timeline event
        cur.execute(
            "INSERT INTO case_timeline VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), case_id, now, owner, "system", f"Case created and {len(alert_ids)} alerts linked."),
        )
        
        conn.commit()
        conn.close()
        return case_id

    def get_cases(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve cases from database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        query = "SELECT * FROM cases"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        
        query += " ORDER BY updated_at DESC"
        cur.execute(query, params)
        rows = [dict(row) for row in cur.fetchall()]
        conn.close()
        return rows

    def get_case_details(self, case_id: str) -> Dict[str, Any]:
        """Get full case details including linked alerts and timeline."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Case basic info
        cur.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        case_row = cur.fetchone()
        if not case_row:
            return {}
        
        case_data = dict(case_row)
        
        # Linked alerts
        cur.execute(
            """
            SELECT a.* FROM alerts a
            JOIN case_alerts ca ON a.alert_id = ca.alert_id
            WHERE ca.case_id = ?
            """,
            (case_id,)
        )
        case_data["alerts"] = [dict(r) for r in cur.fetchall()]
        
        # Timeline
        cur.execute("SELECT * FROM case_timeline WHERE case_id = ? ORDER BY timestamp ASC", (case_id,))
        case_data["timeline"] = [dict(r) for r in cur.fetchall()]
        
        conn.close()
        return case_data

    def add_timeline_event(self, case_id: str, author: str, event_type: str, content: str):
        """Add a manual note or update to the case timeline."""
        now = dt.datetime.utcnow().isoformat()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        cur.execute(
            "INSERT INTO case_timeline VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), case_id, now, author, event_type, content),
        )
        
        # Update case updated_at
        cur.execute("UPDATE cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        
        conn.commit()
        conn.close()

    def update_case_status(self, case_id: str, status: str, author: str):
        """Update case status (e.g., closed, in-progress)."""
        self.add_timeline_event(case_id, author, "status_change", f"Status changed to {status}")
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("UPDATE cases SET status = ? WHERE case_id = ?", (status, case_id))
        conn.commit()
        conn.close()
