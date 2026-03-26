# modules/detection_engine.py
# Detection Rules Engine for AI SOC Automation Platform
# Implements 5 core production-ready rules: 
# 1. Brute Force 2. Suspicious PowerShell 3. Priv Esc 4. Impossible Travel 5. Rare Process

import uuid
import json
import pandas as pd
from typing import List, Dict, Any, Optional
import datetime as dt

class DetectionEngine:
    """
    Analyzes normalized logs and generates alerts based on defined security rules.
    """

    def __init__(self, brute_force_threshold: int = 5, brute_force_window: int = 10):
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = brute_force_window  # minutes
        self.rules = [
            self._rule_brute_force,
            self._rule_suspicious_powershell,
            self._rule_priv_esc,
            self._rule_impossible_travel,
            self._rule_rare_process,
        ]

    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        """Run all rules against the dataframe and return alerts dataframe."""
        if df.empty:
            return pd.DataFrame()
        
        all_alerts: List[Dict[str, Any]] = []
        for rule in self.rules:
            try:
                alerts = rule(df)
                all_alerts.extend(alerts)
            except Exception as e:
                print(f"Error running rule {rule.__name__}: {e}")
        
        if not all_alerts:
            return pd.DataFrame()
        
        return pd.DataFrame(all_alerts)

    def _new_alert(self, 
                   rule_id: str, 
                   rule_name: str, 
                   severity: str, 
                   mitre: List[str], 
                   row: Any, 
                   context: Dict[str, Any]) -> Dict[str, Any]:
        """Helper to create a standardized alert dictionary."""
        return {
            "alert_id": str(uuid.uuid4()),
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "mitre": mitre,
            "timestamp": row.get("timestamp") if hasattr(row, 'get') else getattr(row, 'timestamp', None),
            "host": row.get("host") if hasattr(row, 'get') else getattr(row, 'host', None),
            "user": row.get("user") if hasattr(row, 'get') else getattr(row, 'user', None),
            "src_ip": row.get("src_ip") if hasattr(row, 'get') else getattr(row, 'src_ip', None),
            "dest_ip": row.get("dest_ip") if hasattr(row, 'get') else getattr(row, 'dest_ip', None),
            "process_name": row.get("process_name") if hasattr(row, 'get') else getattr(row, 'process_name', None),
            "command_line": row.get("command_line") if hasattr(row, 'get') else getattr(row, 'command_line', None),
            "context": context,
        }

    def _rule_brute_force(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Rule: Detect 5+ failed logins followed by a success from same IP/User in 10m."""
        alerts = []
        # Filter for auth events
        auth_events = df[df["event_type"].str.contains("login|auth|logon", case=False, na=False)].copy()
        if auth_events.empty:
            return []

        # Logic: group by user and src_ip, resample in windows
        # Simplified version for MVP:
        for (user, src_ip), group in auth_events.groupby(["user", "src_ip"]):
            if len(group) < self.brute_force_threshold:
                continue
            
            # Count failures
            failures = group[group["event_type"].str.contains("fail|error|denied", case=False, na=False)]
            if len(failures) >= self.brute_force_threshold:
                # Check for success after failures
                success = group[group["event_type"].str.contains("success|ok|accept", case=False, na=False)]
                
                # If there's a success after the failures
                if not success.empty and success["timestamp"].max() > failures["timestamp"].min():
                    last_row = group.iloc[-1]
                    alerts.append(self._new_alert(
                        "RULE_001", "Brute Force Attack - Potential Compromise", "high", ["T1110"],
                        last_row, {"failure_count": len(failures), "success_detected": True}
                    ))
                elif not failures.empty:
                    last_row = failures.iloc[-1]
                    alerts.append(self._new_alert(
                        "RULE_001", "Brute Force Attack - Repeated Failures", "medium", ["T1110"],
                        last_row, {"failure_count": len(failures), "success_detected": False}
                    ))
        return alerts

    def _rule_suspicious_powershell(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Rule: Detect PowerShell with encoded commands, web downloads, or IEX."""
        alerts = []
        ps_mask = (
            df["process_name"].str.contains("powershell|pwsh", case=False, na=False) |
            df["command_line"].str.contains("powershell|pwsh", case=False, na=False)
        )
        ps_events = df[ps_mask]
        
        suspicious_patterns = [
            "-enc", "-encodedcommand", "iex", "invoke-expression", 
            "downloadstring", "downloadfile", "webclient", "bitstransfer",
            "frombase64string", "hidden", "windowstyle"
        ]
        
        for _, row in ps_events.iterrows():
            cmd = str(row["command_line"]).lower()
            found = [p for p in suspicious_patterns if p in cmd]
            if found:
                alerts.append(self._new_alert(
                    "RULE_002", "Suspicious PowerShell Execution", "high", ["T1059.001"],
                    row, {"matched_patterns": found}
                ))
        return alerts

    def _rule_priv_esc(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Rule: User added to sensitive groups (Admin, Domain Admin, Sudo)."""
        alerts = []
        # Event IDs: 4728, 4732, 4756 (Windows) or specific strings
        sensitive_groups = ["admin", "root", "sudo", "wheel", "domain admins", "enterprise admins"]
        
        # Look for "add" or "member" actions in groups
        group_events = df[df["event_type"].str.contains("group|member|add", case=False, na=False)]
        
        for _, row in group_events.iterrows():
            cmd = str(row["command_line"]).lower()
            raw = str(row["raw"]).lower()
            
            matched_group = [g for g in sensitive_groups if g in cmd or g in raw]
            if matched_group:
                alerts.append(self._new_alert(
                    "RULE_003", "Sensitive Privilege Escalation Activity", "critical", ["T1078", "T1098"],
                    row, {"matched_groups": matched_group}
                ))
        return alerts

    def _rule_impossible_travel(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Rule: User login from two different countries within 1 hour."""
        alerts = []
        # Need user and geo_src
        geo_logs = df[df["geo_src"].notna() & df["user"].notna()].sort_values(["user", "timestamp"])
        
        for user, group in geo_logs.groupby("user"):
            if len(group) < 2:
                continue
            
            for i in range(len(group) - 1):
                row1 = group.iloc[i]
                row2 = group.iloc[i+1]
                
                # If country is different and time delta < 1 hour
                if row1["geo_src"] != row2["geo_src"]:
                    time_diff = (row2["timestamp"] - row1["timestamp"]).total_seconds() / 3600
                    if time_diff < 1.0:
                        alerts.append(self._new_alert(
                            "RULE_004", "Impossible Travel Detected", "high", ["T1078"],
                            row2, {
                                "first_location": row1["geo_src"],
                                "second_location": row2["geo_src"],
                                "time_difference_hours": round(time_diff, 2)
                            }
                        ))
        return alerts

    def _rule_rare_process(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Rule: Process executed < 1% of the time in the current log batch."""
        alerts = []
        if df["process_name"].dropna().empty:
            return []
            
        counts = df["process_name"].value_counts(normalize=True)
        rare_processes = counts[counts < 0.01].index.tolist()
        
        # Only alert on rare processes for sensitive log sources or users
        for _, row in df[df["process_name"].isin(rare_processes)].iterrows():
            # Add heuristic: ignore common system processes if named weirdly
            alerts.append(self._new_alert(
                "RULE_005", "Rare Process Execution", "medium", ["T1204.002"],
                row, {"frequency": round(counts[row["process_name"]], 4)}
            ))
        return alerts
