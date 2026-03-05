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
