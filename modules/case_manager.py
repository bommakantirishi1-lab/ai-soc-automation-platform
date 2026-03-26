# modules/case_manager.py
# Incident Case Management for AI SOC Automation Platform
# Tracks the investigation lifecycle and analyst assignments

import sqlite3
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

class CaseManager:
    """
    Manages the lifecycle of incident cases.
    """
    def __init__(self, db_path: str = "soc_platform.db"):
        self.db_path = db_path
        self._ensure_schema()

    def _ensure_schema(self):
        """Initialize the cases table."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT,
                severity TEXT,
                status TEXT,
                assignee TEXT,
                created_at DATETIME,
                updated_at DATETIME,
                description TEXT,
                alerts_linked TEXT
            )
        """)
        conn.commit()
        conn.close()

    def create_case(self, case_data: Dict[str, Any]) -> str:
        """Creates a new incident case."""
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}"
        now = datetime.now().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO cases (case_id, title, severity, status, assignee, created_at, updated_at, description, alerts_linked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case_id,
            case_data.get('title'),
            case_data.get('severity', 'Medium'),
            case_data.get('status', 'New'),
            case_data.get('assignee', 'Unassigned'),
            now,
            now,
            case_data.get('description'),
            ",".join(case_data.get('alerts', []))
        ))
        conn.commit()
        conn.close()
        return case_id
    def update_case(self, case_id: str, updates: Dict[str, Any]):
        """Updates case details."""
        now = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        for key, value in updates.items():
            cur.execute(f"UPDATE cases SET {key} = ?, updated_at = ? WHERE case_id = ?", (value, now, case_id))
            
        conn.commit()
        conn.close()

    def get_active_cases(self) -> List[Dict[str, Any]]:
        """Retrieves active cases (not closed)."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM cases WHERE status != 'Closed' ORDER BY updated_at DESC")
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]

if __name__ == "__main__":
    cm = CaseManager()
    cid = cm.create_case({
        "title": "Suspicious Lateral Movement",
        "severity": "High",
        "description": "Potential credential dumping detected on workstation-01",
        "alerts": ["alert-123", "alert-456"]
    })
    print(f"Created case: {cid}")
