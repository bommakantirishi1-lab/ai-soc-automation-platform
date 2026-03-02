import sqlite3
from datetime import datetime

DB_NAME = "soc_platform.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            score INTEGER,
            severity TEXT,
            assigned_to TEXT,
            status TEXT,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_alert(source_ip, score, severity, assigned_to):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (source_ip, score, severity, assigned_to, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        source_ip,
        score,
        severity,
        assigned_to,
        "Open",
        datetime.utcnow().isoformat()
    ))

    conn.commit()
    conn.close()


def get_alerts():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        alerts.append({
            "id": row[0],
            "source_ip": row[1],
            "score": row[2],
            "severity": row[3],
            "assigned_to": row[4],
            "status": row[5],
            "created_at": row[6]
        })

    return alerts