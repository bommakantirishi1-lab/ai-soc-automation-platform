import requests
import pandas as pd
import time
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
import urllib3
from threading import Lock

urllib3.disable_warnings()

# ==================================
# CONFIGURATION
# ==================================

ES_HOST = "https://localhost:9200"
ES_USER = "elastic"
ES_PASS = "123456789"

ALERT_INDEX = "soc-alerts-2026.02"

TELEGRAM_BOT_TOKEN = "8539315269:AAGwjmVnOd1Mmktr-d1TK3ENQtjEHrN7uWg"
TELEGRAM_CHAT_ID = "8555058492"

LOOKBACK_HOURS = 24

# ==================================
# GLOBAL CACHE + LOCK
# ==================================

LATEST_RESULTS = {
    "alerts_generated": [],
    "engine_status": "never_run",
    "last_execution_time": None,
    "execution_duration_seconds": 0
}

cache_lock = Lock()

# ==================================
# ELASTIC CLIENT
# ==================================

def get_es():
    return Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False
    )

# ==================================
# TELEGRAM
# ==================================

def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message
        }
        requests.post(url, data=payload, timeout=5)
    except Exception:
        pass  # Never crash engine because of Telegram

# ==================================
# FETCH ALERTS
# ==================================

def fetch_recent_alerts():
    try:
        es = get_es()
        now = datetime.utcnow()
        past = now - timedelta(hours=LOOKBACK_HOURS)

        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": past.isoformat(),
                        "lte": now.isoformat()
                    }
                }
            },
            "size": 2000
        }

        response = es.search(index=ALERT_INDEX, body=query)
        data = [hit["_source"] for hit in response["hits"]["hits"]]

        return pd.DataFrame(data)

    except Exception:
        # Demo fallback data (for Railway / cloud demo)
        demo_data = [
            {
                "source_ip": "192.168.1.100",
                "event_type": "failed_login",
                "timestamp": datetime.utcnow().isoformat()
            },
            {
                "source_ip": "192.168.1.100",
                "event_type": "successful_login",
                "timestamp": datetime.utcnow().isoformat()
            },
            {
                "source_ip": "192.168.1.100",
                "event_type": "process_creation",
                "timestamp": datetime.utcnow().isoformat()
            },
            {
                "source_ip": "185.220.101.12",
                "event_type": "outbound_connection",
                "timestamp": datetime.utcnow().isoformat()
            }
        ]

        return pd.DataFrame(demo_data)

# ==================================
# CORRELATION ENGINE
# ==================================

def correlate_alerts(df):
    suspicious = []

    if df.empty:
        return suspicious

    if "source_ip" not in df.columns or "event_type" not in df.columns:
        return suspicious

    for ip in df["source_ip"].dropna().unique():
        ip_df = df[df["source_ip"] == ip]
        events = ip_df["event_type"].tolist()

        score = 0

        if "failed_login" in events:
            score += 1
        if "successful_login" in events:
            score += 2
        if "process_creation" in events:
            score += 4
        if "outbound_connection" in events:
            score += 5

        # Multi-stage attack bonus
        if (
            "successful_login" in events and
            "process_creation" in events and
            "outbound_connection" in events
        ):
            score += 6

        if score > 0:
            suspicious.append({
                "source_ip": ip,
                "base_score": score,
                "event_count": len(ip_df)
            })

    return suspicious

# ==================================
# ML ENGINE
# ==================================

def run_ml(df):
    try:
        feature_df = df.groupby("source_ip").size().reset_index(name="event_count")

        if len(feature_df) < 5:
            return 0

        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(feature_df[["event_count"]])

        predictions = model.predict(feature_df[["event_count"]])

        if -1 in predictions:
            return 3

        return 0

    except Exception:
        return 0

# ==================================
# SEVERITY LOGIC
# ==================================

def assign_severity(score):
    if score <= 4:
        return "Informational"
    elif score <= 9:
        return "Low"
    elif score <= 15:
        return "Medium"
    else:
        return "High"

# ==================================
# MAIN ENGINE
# ==================================

def run_engine():
    start_time = time.time()

    df = fetch_recent_alerts()
    suspicious_alerts = correlate_alerts(df)

    if not suspicious_alerts:
        result = {
            "alerts_generated": [],
            "engine_status": "completed_no_alerts",
        }
    else:
        ml_score = run_ml(df)
        generated = []

        for alert in suspicious_alerts:
            final_score = alert["base_score"] + ml_score
            severity = assign_severity(final_score)

            message = (
                f"🚨 Alert Assigned To You\n\n"
                f"IP: {alert['source_ip']}\n"
                f"Events: {alert['event_count']}\n"
                f"Score: {final_score}\n"
                f"Severity: {severity}\n\n"
                f"Please check the SOC queue."
            )

            send_telegram(message)

            generated.append({
                "ip": alert["source_ip"],
                "score": final_score,
                "severity": severity
            })

        result = {
            "alerts_generated": generated,
            "engine_status": "completed_with_alerts",
        }

    end_time = time.time()

    # Update cache safely
    with cache_lock:
        LATEST_RESULTS["alerts_generated"] = result["alerts_generated"]
        LATEST_RESULTS["engine_status"] = result["engine_status"]
        LATEST_RESULTS["last_execution_time"] = datetime.utcnow().isoformat()
        LATEST_RESULTS["execution_duration_seconds"] = round(end_time - start_time, 2)

    return LATEST_RESULTS
