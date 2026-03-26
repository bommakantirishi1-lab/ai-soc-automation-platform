# modules/threat_intel.py
import os
import requests
import sqlite3
import datetime as dt
import json

VT_URL = "https://www.virustotal.com/api/v3"

class ThreatIntel:
    def __init__(self, api_key: str | None = None, db_path: str = "soc_platform.db"):
        self.api_key = api_key or os.getenv("VT_API_KEY", "")
        self.db_path = db_path
        self._ensure_cache()

    def _ensure_cache(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vt_cache (
                ioc TEXT PRIMARY KEY,
                type TEXT,
                last_seen TEXT,
                malicious INT,
                suspicious INT,
                harmless INT,
                json TEXT
            )
            """
        )
        conn.commit()
        conn.close()

    def _cached(self, ioc: str):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT json FROM vt_cache WHERE ioc = ?", (ioc,))
        row = cur.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
        return None

    def _store(self, ioc: str, type_: str, data: dict):
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO vt_cache
            (ioc, type, last_seen, malicious, suspicious, harmless, json)
            VALUES (?,?,?,?,?,?,?)
            """,
            (
                ioc,
                type_,
                dt.datetime.utcnow().isoformat(),
                stats.get("malicious", 0),
                stats.get("suspicious", 0),
                stats.get("harmless", 0),
                json.dumps(data),
            ),
        )
        conn.commit()
        conn.close()

    def _request(self, path: str):
        headers = {"x-apikey": self.api_key}
        resp = requests.get(f"{VT_URL}{path}", headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def lookup_hash(self, sha256: str) -> dict:
        cached = self._cached(sha256)
        if cached:
            return cached
        data = self._request(f"/files/{sha256}")
        self._store(sha256, "hash", data)
        return data
