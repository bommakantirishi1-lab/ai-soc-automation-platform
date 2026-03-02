import random
from assignment import assign_analyst

def run_detection():
    sample_ips = [
        "192.168.1.100",
        "185.220.101.12",
        "10.0.0.45",
        "203.0.113.5"
    ]

    ip = random.choice(sample_ips)
    score = random.randint(5, 20)

    if score <= 9:
        severity = "Low"
    elif score <= 15:
        severity = "Medium"
    else:
        severity = "High"

    analyst = assign_analyst()

    return ip, score, severity, analyst