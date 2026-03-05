import requests
import pandas as pd
import random
import time
from datetime import datetime
from sklearn.ensemble import IsolationForest
from threading import Lock

# ===============================
# CONFIG
# ===============================

TELEGRAM_BOT_TOKEN = "8539315269:AAGwjmVnOd1Mmktr-d1TK3ENQtjEHrN7uWg"
TELEGRAM_CHAT_ID = "8555058492"

ANALYST_NAME = "Sai Rishi Kumar Bommakanti"

cache_lock = Lock()

LATEST_RESULTS = {
    "alerts_generated": [],
    "visitors": [],
    "engine_status": "idle",
    "last_execution_time": None,
    "execution_duration_seconds": 0
}

# ===============================
# DEMO ATTACK SIMULATOR
# ===============================

def generate_demo_attacks():

    ips = [
        "185.220.101.12",
        "45.95.147.23",
        "103.21.244.15",
        "91.134.188.10",
        "194.26.192.44",
        "23.129.64.210",
        "176.119.1.22",
        "162.247.74.200",
        "104.244.72.115",
        "5.188.206.22",
        "8.8.8.8",
        "1.1.1.1"
    ]

    events = [
        "failed_login",
        "successful_login",
        "process_creation",
        "outbound_connection"
    ]

    data = []

    for _ in range(random.randint(15,20)):

        data.append({
            "source_ip": random.choice(ips),
            "event_type": random.choice(events),
            "timestamp": datetime.utcnow().isoformat()
        })

    return pd.DataFrame(data)

# ===============================
# THREAT INTEL
# ===============================

def threat_intel_score(ip):

    suspicious_ranges = [
        "185.220",
        "45.95",
        "103.21",
        "91.134",
        "194.26"
    ]

    for r in suspicious_ranges:
        if ip.startswith(r):
            return 3

    return 0

# ===============================
# GEOLOOKUP
# ===============================

def lookup_ip(ip):

    try:

        res = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        ).json()

        return {
            "ip": ip,
            "country": res.get("country"),
            "city": res.get("city"),
            "isp": res.get("isp"),
            "lat": res.get("lat"),
            "lon": res.get("lon")
        }

    except:

        return {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "lat": None,
            "lon": None
        }

# ===============================
# ML ENGINE
# ===============================

def run_ml(df):

    try:

        feature_df = df.groupby("source_ip").size().reset_index(name="event_count")

        if len(feature_df) < 5:
            return 0

        model = IsolationForest(
            contamination=0.1,
            random_state=42
        )

        model.fit(feature_df[["event_count"]])

        preds = model.predict(feature_df[["event_count"]])

        if -1 in preds:
            return 3

        return 0

    except:
        return 0

# ===============================
# SEVERITY
# ===============================

def assign_severity(score):

    if score <= 4:
        return "Low"

    elif score <= 9:
        return "Medium"

    else:
        return "High"

# ===============================
# TELEGRAM ALERT
# ===============================

def send_telegram(message):

    try:

        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

        requests.post(url,data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message
        })

    except:
        pass

# ===============================
# MAIN ENGINE
# ===============================

def run_engine():

    start = time.time()

    df = generate_demo_attacks()

    ml_score = run_ml(df)

    alerts = []
    visitors = []

    for ip in df["source_ip"].unique():

        ip_df = df[df["source_ip"] == ip]

        events = ip_df["event_type"].tolist()

        ti_score = threat_intel_score(ip)

        base_score = len(events)

        final_score = base_score + ml_score + ti_score

        severity = assign_severity(final_score)

        geo = lookup_ip(ip)

        message = f"""
🚨 SOC ALERT

IP: {ip}
Country: {geo.get("country")}

Severity: {severity}
Score: {final_score}

Assigned Analyst:
{ANALYST_NAME}
"""

        send_telegram(message)

        alerts.append({
            "ip": ip,
            "score": final_score,
            "severity": severity,
            "events": events,
            "country": geo.get("country"),
            "city": geo.get("city"),
            "isp": geo.get("isp"),
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "analyst": ANALYST_NAME,
            "status": "Investigating"
        })

        visitors.append(geo)

    end = time.time()

    with cache_lock:

        LATEST_RESULTS["alerts_generated"] = alerts
        LATEST_RESULTS["visitors"] = visitors
        LATEST_RESULTS["engine_status"] = "completed"
        LATEST_RESULTS["last_execution_time"] = datetime.utcnow().isoformat()
        LATEST_RESULTS["execution_duration_seconds"] = round(end-start,2)

    return LATEST_RESULTS