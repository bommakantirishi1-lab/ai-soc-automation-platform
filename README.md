# AI SOC Automation Platform

Security Operations Center Automation Platform built with Python.

This platform demonstrates automated threat detection, risk scoring, MITRE ATT&CK mapping, and SOC analyst workflow automation.

---

# Architecture

```
                   +----------------------+
                   |   Security Logs      |
                   |  (SIEM / Elastic)    |
                   +----------+-----------+
                              |
                              v
                    +-------------------+
                    | Detection Engine  |
                    | (Rule Correlation)|
                    +-------------------+
                              |
                              v
                    +-------------------+
                    | ML Anomaly Engine |
                    | Isolation Forest  |
                    +-------------------+
                              |
                              v
                    +-------------------+
                    | Threat Intelligence|
                    | IP Risk Scoring   |
                    +-------------------+
                              |
                              v
                    +-------------------+
                    | MITRE ATT&CK Map  |
                    | Tactics & Techniques|
                    +-------------------+
                              |
                              v
                    +-------------------+
                    | Risk Score Engine |
                    +-------------------+
                              |
                              v
                    +-------------------+
                    | AI Explanation    |
                    | Alert Analysis    |
                    +-------------------+
                              |
              +---------------+---------------+
              |                               |
              v                               v
     +-------------------+           +------------------+
     | SOC Dashboard     |           | Telegram Alerts  |
     | (Streamlit UI)    |           | Real-time alerts |
     +-------------------+           +------------------+

```

---

# Features

• Detection Rule Engine
• Machine Learning Anomaly Detection
• MITRE ATT&CK Mapping
• Threat Intelligence Scoring
• Automated Alert Scoring
• SOC Analyst Assignment
• Real-Time Alert Notifications
• Streamlit SOC Dashboard
• Continuous Monitoring Loop

---

# Tech Stack

Python
Pandas
Scikit-learn
ElasticSearch
Streamlit
Telegram API

---

# Example Alert

```
IP: 192.168.1.100
Events: failed_login → successful_login → process_creation

Severity: Medium
Score: 12

Rules Triggered:
- Brute Force Attack
- Suspicious Login Sequence

MITRE Techniques:
- T1110 Brute Force
- T1078 Valid Accounts
```

---

# Author

Sai Rishi Kumar Bommakanti

Security Automation | Detection Engineering | SOC Platforms

---

# Quick Start

## 1) Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2) Configure environment (optional)

Create a `.env` file in the project root:

```env
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
ANALYST_NAME=SOC Analyst
DB_PATH=./data/soc_alerts.db
ML_MODEL_PATH=./models/alert_dedup_model.pkl
AUDIT_LOG_PATH=./logs/audit.log
```

## 3) Run the SOC Dashboard

```bash
streamlit run app.py
```

## 4) Run backend API (optional)

```bash
uvicorn soc_saas.backend.main:app --reload
```

## 5) Run automated checks

```bash
pytest -q
python -m compileall -q .
```


---

# SOCFlow v2 (Enterprise Demo Build)

The dashboard now includes a complete enterprise demo flow:
- Detection + SIEM-style correlation view
- AI SOC Copilot tab (local-first/Ollama-compatible endpoint pattern)
- UEBA risk analytics by user/entity
- Threat intel enrichment panel (VirusTotal/AbuseIPDB style scoring model)
- SOAR playbook demand + attack graph visualization
- Compliance-ready incident report export (CSV)

Run:

```bash
streamlit run app.py
```

For sales positioning notes against large-platform competitors, see:

- `docs/COMPETITIVE_POSITIONING.md`

