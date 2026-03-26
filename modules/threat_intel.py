import json
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

@dataclass
class ThreatIndicator:
    ioc: str
    ioc_type: str
    confidence: str
    source: str
    timestamp: str
    threat_level: str
    tags: List[str]
    last_seen: str

class ThreatIntelligence:
    def __init__(self, db_path="data/threat_intel.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS indicators (
                        ioc TEXT PRIMARY KEY,
                        ioc_type TEXT,
                        confidence TEXT,
                        source TEXT,
                        timestamp TEXT,
                        threat_level TEXT,
                        tags TEXT,
                        last_seen TEXT
                    )
                """)
        except Exception as e:
            logger.error(f"Error initializing threat intel database: {e}")

    def add_indicator(self, indicator: ThreatIndicator):
        data = asdict(indicator)
        data['tags'] = json.dumps(data['tags'])
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO indicators
                    (ioc, ioc_type, confidence, source, timestamp, threat_level, tags, last_seen)
                    VALUES (:ioc, :ioc_type, :confidence, :source, :timestamp, :threat_level, :tags, :last_seen)
                """, data)
        except Exception as e:
            logger.error(f"Error adding indicator {indicator.ioc}: {e}")

    def update_feeds(self):
        """Fetch latest updates from configured threat feeds (Mocked for MVP)"""
        mock_indicators = [
            ThreatIndicator(
                ioc="185.220.101.12",
                ioc_type="IP",
                confidence="High",
                source="Tor Exit Node List",
                timestamp=datetime.utcnow().isoformat(),
                threat_level="Medium",
                tags=["tor", "anonymous"],
                last_seen=datetime.utcnow().isoformat()
            ),
            ThreatIndicator(
                ioc="45.95.147.23",
                ioc_type="IP",
                confidence="High",
                source="Known Brute Forcer",
                timestamp=datetime.utcnow().isoformat(),
                threat_level="High",
                tags=["ssh_brute", "attacker"],
                last_seen=datetime.utcnow().isoformat()
            )
        ]
        for ind in mock_indicators:
            self.add_indicator(ind)
        return len(mock_indicators)

    def check_ioc(self, ioc: str) -> Optional[dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.execute("SELECT * FROM indicators WHERE ioc = ?", (ioc,))
                row = cur.fetchone()
                if row:
                    data = dict(row)
                    data['tags'] = json.loads(data['tags'])
                    return data
        except Exception as e:
            logger.error(f"Error checking IOC {ioc}: {e}")
        return None
