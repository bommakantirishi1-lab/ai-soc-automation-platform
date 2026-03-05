import sqlite3
import json
from datetime import datetime
from threading import Lock
import os

class AlertDatabase:
    """Persistent alert storage - prevents alerts from being forgotten"""
    
    def __init__(self, db_path="./data/soc_alerts.db"):
        self.db_path = db_path
        self.lock = Lock()
        self._init_db()
    
    def _init_db(self):
        """Initialize database with required tables"""
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    score INTEGER,
                    severity TEXT,
                    events TEXT,
                    country TEXT,
                    city TEXT,
                    isp TEXT,
                    lat REAL,
                    lon REAL,
                    analyst TEXT,
                    status TEXT DEFAULT "Investigating",
                    fingerprint TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Audit log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT,
                    analyst TEXT,
                    alert_id INTEGER,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indices
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip ON alerts(ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_created ON alerts(created_at)')
            conn.commit()
    
    def add_alert(self, alert_data):
        """Add alert to persistent storage (never forget alerts)"""
        with self.lock:
            try:
                fingerprint = self._fingerprint(alert_data)
                
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR IGNORE INTO alerts 
                        (ip, score, severity, events, country, city, isp, lat, lon, analyst, fingerprint)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        alert_data['ip'],
                        alert_data.get('score', 0),
                        alert_data.get('severity', 'Low'),
                        json.dumps(alert_data.get('events', [])),
                        alert_data.get('country', ''),
                        alert_data.get('city', ''),
                        alert_data.get('isp', ''),
                        alert_data.get('lat'),
                        alert_data.get('lon'),
                        alert_data.get('analyst', ''),
                        fingerprint
                    ))
                    conn.commit()
                    return True
            except sqlite3.IntegrityError:
                return False  # Already exists
    
    def get_all_alerts(self):
        """Get all stored alerts - ensures they are never forgotten"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM alerts ORDER BY created_at DESC')
            rows = cursor.fetchall()
        
        alerts = []
        for row in rows:
            alert = dict(row)
            alert['events'] = json.loads(alert['events'])
            alerts.append(alert)
        return alerts
    
    def get_alerts_by_ip(self, ip):
        """Get all alerts for a specific IP"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM alerts WHERE ip = ? ORDER BY created_at DESC', (ip,))
            rows = cursor.fetchall()
        
        return [dict(row) for row in rows]
    
    def _fingerprint(self, alert):
        """Generate unique alert fingerprint for deduplication"""
        import hashlib
        key = f"{alert['ip']}_{alert.get('severity')}_{len(alert.get('events', []))}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def log_action(self, action, analyst, alert_id, details):
        """Log audit action"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_log (action, analyst, alert_id, details)
                VALUES (?, ?, ?, ?)
            ''', (action, analyst, alert_id, json.dumps(details)))
            conn.commit()
    
    def get_alert_count(self):
        """Get total alert count"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM alerts')
            return cursor.fetchone()[0]
