from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
import random
from typing import Dict, List, Tuple


MITRE_BY_EVENT = {
    "failed_login": ["T1110", "T1078"],
    "privilege_change": ["T1068", "T1548"],
    "powershell_encoded": ["T1059.001"],
    "lateral_movement": ["T1021", "T1570"],
    "dns_tunnel": ["T1071.004"],
    "data_exfiltration": ["T1048"],
}


@dataclass(frozen=True)
class AlertEvent:
    alert_id: str
    timestamp: datetime
    user: str
    host: str
    source_ip: str
    destination_ip: str
    event_type: str
    severity: str
    base_score: int


def _severity(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def generate_synthetic_alerts(count: int = 120, seed: int = 42) -> List[AlertEvent]:
    """Generate deterministic synthetic SOC alerts for dashboard demos."""
    rng = random.Random(seed)
    users = ["svc-backup", "jsmith", "apatel", "mnguyen", "secops.bot", "vp-finance"]
    hosts = ["dc-01", "hr-laptop-22", "eng-mac-11", "db-prod-03", "vpn-gw-02"]
    source_ips = ["185.220.101.12", "45.95.147.23", "203.0.113.10", "198.51.100.77", "10.20.40.51"]
    destination_ips = ["10.0.1.11", "10.0.1.22", "10.0.2.5", "172.16.10.8", "8.8.8.8"]
    event_types = list(MITRE_BY_EVENT.keys())

    alerts: List[AlertEvent] = []
    now = datetime.utcnow()
    for i in range(count):
        event = rng.choice(event_types)
        score = rng.randint(30, 99)
        alerts.append(
            AlertEvent(
                alert_id=f"ALRT-{now:%Y%m%d}-{i:04}",
                timestamp=now - timedelta(minutes=i * rng.randint(1, 4)),
                user=rng.choice(users),
                host=rng.choice(hosts),
                source_ip=rng.choice(source_ips),
                destination_ip=rng.choice(destination_ips),
                event_type=event,
                severity=_severity(score),
                base_score=score,
            )
        )
    return alerts


def correlate_incidents(alerts: List[AlertEvent]) -> List[Dict]:
    """Correlate alerts into incidents keyed by user+source IP."""
    grouped: Dict[Tuple[str, str], List[AlertEvent]] = defaultdict(list)
    for alert in alerts:
        grouped[(alert.user, alert.source_ip)].append(alert)

    incidents = []
    for (user, source_ip), items in grouped.items():
        items_sorted = sorted(items, key=lambda x: x.timestamp)
        mitre = sorted({t for event in items_sorted for t in MITRE_BY_EVENT.get(event.event_type, [])})
        avg_score = round(sum(i.base_score for i in items_sorted) / len(items_sorted), 1)
        incidents.append(
            {
                "incident_id": f"INC-{items_sorted[-1].timestamp:%Y%m%d%H%M}-{abs(hash((user, source_ip))) % 1000:03}",
                "entity": user,
                "source_ip": source_ip,
                "alert_count": len(items_sorted),
                "avg_score": avg_score,
                "severity": _severity(int(avg_score)),
                "first_seen": items_sorted[0].timestamp,
                "last_seen": items_sorted[-1].timestamp,
                "mitre": mitre,
                "recommended_playbook": recommend_playbook(items_sorted),
            }
        )

    incidents.sort(key=lambda x: (x["alert_count"], x["avg_score"]), reverse=True)
    return incidents


def recommend_playbook(incident_alerts: List[AlertEvent]) -> str:
    event_counts = Counter(a.event_type for a in incident_alerts)
    top_event, _ = event_counts.most_common(1)[0]
    if top_event in {"failed_login", "privilege_change"}:
        return "Account Lockdown & IAM Verification"
    if top_event in {"powershell_encoded", "lateral_movement"}:
        return "Endpoint Isolation & Lateral Movement Hunt"
    if top_event == "data_exfiltration":
        return "DLP Containment & Egress Firewall Block"
    return "Network Containment & Forensic Snapshot"


def compute_ueba(alerts: List[AlertEvent]) -> List[Dict]:
    """Compute UEBA risk per user based on score deviation + event rarity."""
    by_user: Dict[str, List[AlertEvent]] = defaultdict(list)
    event_freq = Counter(a.event_type for a in alerts)
    max_freq = max(event_freq.values()) if event_freq else 1

    for alert in alerts:
        by_user[alert.user].append(alert)

    results = []
    for user, user_alerts in by_user.items():
        avg_score = sum(a.base_score for a in user_alerts) / len(user_alerts)
        rarity_bonus = sum((1 - (event_freq[a.event_type] / max_freq)) * 20 for a in user_alerts) / len(user_alerts)
        risk = min(99.0, round(avg_score + rarity_bonus, 1))
        results.append(
            {
                "user": user,
                "alert_volume": len(user_alerts),
                "avg_alert_score": round(avg_score, 1),
                "ueba_risk": risk,
                "status": "Watchlist" if risk >= 70 else "Normal",
            }
        )

    results.sort(key=lambda x: x["ueba_risk"], reverse=True)
    return results


def enrich_threat_intel(ip: str) -> Dict:
    """Deterministic mock enrichment for demo dashboard behavior."""
    bad_prefixes = {
        "185.220": (92, 18),
        "45.95": (88, 14),
        "198.51": (63, 3),
    }
    for prefix, (confidence, detections) in bad_prefixes.items():
        if ip.startswith(prefix):
            return {
                "ip": ip,
                "confidence": confidence,
                "virustotal_detections": detections,
                "abuseipdb_score": confidence,
                "verdict": "Malicious" if confidence >= 80 else "Suspicious",
            }

    return {
        "ip": ip,
        "confidence": 18,
        "virustotal_detections": 0,
        "abuseipdb_score": 0,
        "verdict": "Benign",
    }


def build_attack_graph(alerts: List[AlertEvent]) -> Tuple[List[str], List[Tuple[str, str]]]:
    nodes = set()
    edges: List[Tuple[str, str]] = []
    for alert in alerts[:60]:
        src = f"IP:{alert.source_ip}"
        user = f"User:{alert.user}"
        host = f"Host:{alert.host}"
        nodes.update([src, user, host])
        edges.extend([(src, user), (user, host)])
    return sorted(nodes), edges


def executive_summary(alerts: List[AlertEvent], incidents: List[Dict]) -> Dict:
    mttr_minutes = round(18 + (len(alerts) / 18), 1)
    prevented = sum(1 for i in incidents if i["severity"] in {"High", "Critical"})
    automation_rate = round(min(97.0, 55 + prevented * 1.1), 1)
    return {
        "alerts": len(alerts),
        "incidents": len(incidents),
        "mttr_minutes": mttr_minutes,
        "automation_rate": automation_rate,
        "high_critical_prevented": prevented,
    }


def copilot_response(question: str, top_incident: Dict | None) -> str:
    if not question.strip():
        return "Ask me for triage guidance, MITRE mapping, or a containment recommendation."

    if top_incident is None:
        return "No active incidents to analyze."

    return (
        f"Recommended action: run '{top_incident['recommended_playbook']}' for incident {top_incident['incident_id']}. "
        f"This cluster has {top_incident['alert_count']} alerts, average score {top_incident['avg_score']}, "
        f"and MITRE techniques {', '.join(top_incident['mitre'][:4]) or 'N/A'}. "
        "Escalate to Tier-2 if activity continues for 15+ minutes after containment."
    )
