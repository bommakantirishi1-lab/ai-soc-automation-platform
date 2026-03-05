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

ANALYST_NAME = "Sai Rishi Kumar Bommakanti"

# ==================================
# GLOBAL CACHE
# ==================================

LATEST_RESULTS = {
    "alerts_generated": [],
    "engine_status": "never_run",
    "last_execution_time": None,
    "execution_duration_seconds": 0
}

cache_lock = Lock()

# ==================================
# DETECTION RULE ENGINE
# ==================================

RULES = [

    {
        "name": "Brute Force Attack",
        "conditions": ["failed_login", "failed_login", "failed_login"],
        "score": 5,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1110 Brute Force"
    },

    {
        "name": "Suspicious Login Sequence",
        "conditions": ["failed_login", "successful_login"],
        "score": 4,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1078 Valid Accounts"
    },

    {
        "name": "Multi Stage Attack",
        "conditions": [
            "successful_login",
            "process_creation",
            "outbound_connection"
        ],
        "score": 8,
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059 Command Execution"
    }

]

def evaluate_rules(events):

    triggered = []

    for rule in RULES:

        match_count = 0

        for cond in rule["conditions"]:
            if cond in events:
                match_count += 1

        if match_count >= len(rule["conditions"]):
            triggered.append(rule)

    return triggered

# ==================================
# THREAT INTELLIGENCE
# ==================================

def threat_intel_score(ip):

    suspicious_ranges = [
        "185.220",   # TOR
        "45.95",
        "103.21",
        "91.134",
        "194.26"
    ]

    for r in suspicious_ranges:

        if ip.startswith(r):
            return 3

    return 0

# ==================================
# AI EXPLANATION
# ==================================

def generate_explanation(ip, events, severity):

    explanation = f"""
Threat Analysis

IP: {ip}
Severity: {severity}

Observed Events:
{", ".join(events)}

Explanation:
A sequence of authentication or system events indicates
potential malicious activity such as credential abuse,
privilege escalation, or command execution.

Recommended Investigation Steps:

• Review authentication logs
• Check endpoint process activity
• Inspect outbound network traffic
• Correlate with threat intelligence feeds
"""

    return explanation.strip()

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
# TELEGRAM ALERTING
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
        pass

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

        demo_data = [

            {
                "source_ip": "192.168.1.100",
                "event_type": "failed_login",
                "timestamp": datetime.utcnow().isoformat()
            },

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
# ML ENGINE
# ==================================

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

        predictions = model.predict(feature_df[["event_count"]])

        if -1 in predictions:
            return 3

        return 0

    except Exception:
        return 0

# ==================================
# SEVERITY ENGINE
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
# MAIN DETECTION ENGINE
# ==================================

def run_engine():

    start_time = time.time()

    df = fetch_recent_alerts()

    if df.empty:

        return {
            "alerts_generated": [],
            "engine_status": "no_data"
        }

    ml_score = run_ml(df)

    generated = []

    for ip in df["source_ip"].dropna().unique():

        ip_df = df[df["source_ip"] == ip]

        events = ip_df["event_type"].tolist()

        rules = evaluate_rules(events)

        base_score = sum(rule["score"] for rule in rules)

        ti_score = threat_intel_score(ip)

        final_score = base_score + ml_score + ti_score

        severity = assign_severity(final_score)

        explanation = generate_explanation(ip, events, severity)

        message = f"""
🚨 SOC Alert

IP: {ip}
Events: {len(events)}

Score: {final_score}
Severity: {severity}

Threat Intel Score: {ti_score}

Rules Triggered:
{[r["name"] for r in rules]}

MITRE Techniques:
{[r["mitre_technique"] for r in rules]}

Assigned Analyst:
{ANALYST_NAME}

{explanation}
"""

        send_telegram(message)

        generated.append({

            "ip": ip,

            "score": final_score,

            "severity": severity,

            "events": events,

            "event_count": len(events),

            "rules": [r["name"] for r in rules],

            "rule_count": len(rules),

            "mitre_tactic": [r["mitre_tactic"] for r in rules],

            "mitre_technique": [r["mitre_technique"] for r in rules],

            "threat_intel_score": ti_score,

            "analyst": ANALYST_NAME,

            "status": "Investigating",

            "ai_summary": explanation

        })

    end_time = time.time()

    with cache_lock:

        LATEST_RESULTS["alerts_generated"] = generated

        LATEST_RESULTS["engine_status"] = "completed"

        LATEST_RESULTS["last_execution_time"] = datetime.utcnow().isoformat()

        LATEST_RESULTS["execution_duration_seconds"] = round(end_time - start_time, 2)

    return LATEST_RESULTS

# ==================================
# REAL TIME DETECTION LOOP
# ==================================

def start_detection_loop(interval_seconds=300):

    """
    Continuously runs the detection engine
    every X seconds (default 5 minutes)
    """

    print("SOC Detection Engine Started")

    while True:

        try:

            print("Running detection cycle...")

            run_engine()

            print("Detection cycle completed")

        except Exception as e:

            print("Engine error:", str(e))

        time.sleep(interval_seconds)

# ==================================
# RUN ENGINE DIRECTLY
# ==================================

if __name__ == "__main__":

    start_detection_loop()