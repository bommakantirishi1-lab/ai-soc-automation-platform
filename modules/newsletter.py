# modules/newsletter.py

import sqlite3
import datetime as dt
from typing import Tuple


class Newsletter:
    def __init__(self, db_path: str = "soc_platform.db"):
        self.db_path = db_path

    def build_daily(self, date: dt.date | None = None) -> Tuple[str, str]:
        if date is None:
            date = dt.datetime.utcnow().date()

        start = dt.datetime.combine(date, dt.time.min).isoformat()
        end = dt.datetime.combine(date, dt.time.max).isoformat()

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT severity, rule_name, COUNT(*)
            FROM alerts
            WHERE created_at BETWEEN ? AND ?
            GROUP BY severity, rule_name
            """,
            (start, end),
        )
        rows = cur.fetchall()
        conn.close()

        md_lines = [f"# Daily SOC Brief - {date.isoformat()}", ""]
        md_lines.append("## Alert Overview")

        if not rows:
            md_lines.append("- No alerts generated today.")
        else:
            for sev, rule, count in rows:
                md_lines.append(f"- **{sev.upper()}** - {rule}: {count} alerts")

        sep = "\n"
        md = sep.join(md_lines)
        html = md.replace(sep, " ")
        return md, html
