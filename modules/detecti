# modules/detection_engine.py
# Core Detection Rules Engine for AI SOC Automation Platform
# Implements multi-stage security analysis rules

import uuid
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

class DetectionEngine:
    """
    Analyzes security logs and triggers alerts based on behavioral rules.
    """
    def __init__(self):
        self.rules = [
            self._rule_brute_force,
            self._rule_suspicious_powershell,
            self._rule_impossible_travel,
            self._rule_large_outbound_transfer
        ]

    def run(self, logs_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Executes all detection rules against the provided logs."""
        if logs_df.empty:
            return []
            
        new_alerts = []
        for rule in self.rules:
            alerts = rule(logs_df)
            if alerts:
                new_alerts.extend(alerts)
        return new_alerts

    def _rule_brute_force(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detects multiple failed logins from the same source IP."""
        failed_logins = df[(df['event_type'] == 'login') & (df['status'] == 'failed')]
        if failed_logins.empty:
            return []
            
        counts = failed_logins.groupby('source_ip').size()
        violators = counts[counts > 5].index.tolist()
        
        alerts = []
        for ip in violators:
            alerts.append({
                "rule_id": "DET-001",
                "rule_name": "Brute Force Detected",
                "severity": "High",
                "mitre_technique": "T1110",
                "description": f"Detected {counts[ip]} failed login attempts from source IP {ip}",
                "source": "AuthLogs",
                "metadata": {"source_ip": ip, "count": int(counts[ip])}
            })
        return alerts

    def _rule_suspicious_powershell(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detects encoded or obfuscated PowerShell commands."""
        suspicious_keywords = ['-enc', '-encodedcommand', 'iex', 'invoke-expression', 'hidden']
        if 'process_command' not in df.columns:
            return []
            
        matches = df[df['process_command'].str.contains('|'.join(suspicious_keywords), case=False, na=False)]
        
        alerts = []
        for _, row in matches.iterrows():
            alerts.append({
                "rule_id": "DET-002",
                "rule_name": "Suspicious PowerShell Execution",
                "severity": "Medium",
                "mitre_technique": "T1059.001",
                "description": f"Suspicious PowerShell command detected: {row['process_command'][:50]}...",
                "source": "EDRLogs",
                "metadata": {"command": row['process_command'], "user": row.get('user')}
            })
        return alerts

    def _rule_impossible_travel(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Placeholder for impossible travel detection (geographical analysis)."""
        # In a real system, this would calculate distance/time between logins
        return []

    def _rule_large_outbound_transfer(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detects potentially large data exfiltration based on byte counts."""
        if 'bytes_out' not in df.columns:
            return []Add behavioral detection rules engine module
            
        threshold = 100 * 1024 * 1024 # 100MB
        large_transfers = df[df['bytes_out'] > threshold]
        
        alerts = []
        for _, row in large_transfers.iterrows():
            alerts.append({
                "rule_id": "DET-003",
                "rule_name": "Potential Data Exfiltration",
                "severity": "High",
                "mitre_technique": "T1020",
                "description": f"Large outbound data transfer ({row['bytes_out'] // (1024*1024)}MB) to {row.get('dest_ip')}",
                "source": "Netflow",
                "metadata": {"bytes": row['bytes_out'], "dest": row.get('dest_ip')}
            })
        return alerts

if __name__ == "__main__":
    engine = DetectionEngine()
    test_data = pd.DataFrame([
        {"event_type": "login", "status": "failed", "source_ip": "10.0.0.5"},
        {"event_type": "login", "status": "failed", "source_ip": "10.0.0.5"},
        {"event_type": "login", "status": "failed", "source_ip": "10.0.0.5"},
        {"event_type": "login", "status": "failed", "source_ip": "10.0.0.5"},
        {"event_type": "login", "status": "failed", "source_ip": "10.0.0.5"},
        {"event_type": "login", "status": "failed", "source_ip": "10.0.0.5"},
        {"process_command": "powershell.exe -ExecutionPolicy Bypass -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA..."},
    ])
    results = engine.run(test_data)
    print(f"Detected {len(results)} alerts.")
    for a in results:
        print(f"[{a['severity']}] {a['rule_name']}: {a['description']}")
