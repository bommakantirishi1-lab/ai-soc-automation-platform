# modules/detection_engine.py
import uuid
from typing import List, Dict, Any
import pandas as pd

class DetectionEngine:
    def __init__(self):
        self.rules = [
            self._rule_brute_force,
            self._rule_suspicious_powershell,
            self._rule_priv_esc,
            self._rule_impossible_travel,
            self._rule_rare_process,
        ]

    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()
        
        alerts: List[Dict[str, Any]] = []
        for rule in self.rules:
            alerts.extend(rule(df))
        
        if not alerts:
            return pd.DataFrame()
        return pd.DataFrame(alerts)

    def _new_alert(self, rule_id, rule_name, severity, mitre, row, context: Dict[str, Any]):
        return {
            "alert_id": str(uuid.uuid4()),
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "mitre": mitre,
            "timestamp": row.get("timestamp"),
            "host": row.get("host"),
            "user": row.get("user"),
            "src_ip": row.get("src_ip"),
            "dest_ip": row.get("dest_ip"),
            "process_name": row.get("process_name"),
            "command_line": row.get("command_line"),
            "context": context,
        }

    def _rule_brute_force(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        if "user" not in df.columns or "event_type" not in df.columns:
            return alerts
            
        failures = df[df["event_type"].str.contains("fail", case=False, na=False)]
        if failures.empty:
            return alerts
            
        # Simple grouping by user and src_ip
        counts = failures.groupby(["user", "src_ip"]).size().reset_index(name="count")
        threshold = 5
        
        for _, suspect in counts[counts["count"] >= threshold].iterrows():
            # Get the last row for this suspect
            suspect_rows = failures[(failures["user"] == suspect["user"]) & (failures["src_ip"] == suspect["src_ip"])]
            if not suspect_rows.empty:
                row = suspect_rows.iloc[-1]
                alerts.append(
                    self._new_alert(
                        rule_id="R002",
                        rule_name="Brute Force Logon Attempt",
                        severity="high",
                        mitre=["T1110"],
                        row=row,
                        context={"reason": f"Detected {suspect['count']} failed login attempts", "attempts": int(suspect["count"])}
                    )
                )
        return alerts

    def _rule_suspicious_powershell(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        if "process_name" not in df.columns or "command_line" not in df.columns:
            return alerts
            
        ps = df[
            df["process_name"].str.contains("powershell", case=False, na=False) 
            | df["command_line"].str.contains("powershell", case=False, na=False)
        ]
        patterns = ["-enc", "base64string", "iex", "downloadstring", "invoke-expression"]
        mask = ps["command_line"].str.contains("|".join(patterns), case=False, na=False)
        
        for _, row in ps[mask].iterrows():
            alerts.append(
                self._new_alert(
                    rule_id="R001",
                    rule_name="Suspicious PowerShell Command",
                    severity="high",
                    mitre=["T1059"],
                    row=row,
                    context={"reason": "Suspicious PowerShell command line detected"},
                )
            )
        return alerts

    def _rule_priv_esc(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        if "command_line" not in df.columns:
            return alerts
            
        patterns = ["net localgroup administrators", "sudoers", "chmod +s", "chown root"]
        mask = df["command_line"].str.contains("|".join(patterns), case=False, na=False)
        
        for _, row in df[mask].iterrows():
            alerts.append(
                self._new_alert(
                    rule_id="R003",
                    rule_name="Privilege Escalation Attempt",
                    severity="critical",
                    mitre=["T1068", "T1548"],
                    row=row,
                    context={"reason": "Commands associated with privilege escalation detected"},
                )
            )
        return alerts

    def _rule_impossible_travel(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        if "user" not in df.columns or "geo_src" not in df.columns or "timestamp" not in df.columns:
            return alerts
            
        # Ensure timestamp is datetime
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df_sorted = df.dropna(subset=["timestamp"]).sort_values(["user", "timestamp"])
        
        for user, group in df_sorted.groupby("user"):
            if len(group) < 2:
                continue
            
            # Compare consecutive logons
            for i in range(len(group) - 1):
                row1 = group.iloc[i]
                row2 = group.iloc[i+1]
                
                if row1["geo_src"] and row2["geo_src"] and row1["geo_src"] != row2["geo_src"]:
                    # Check time difference (different geo within 1 hour)
                    time_diff = (row2["timestamp"] - row1["timestamp"]).total_seconds() / 3600
                    if time_diff < 1:
                        alerts.append(
                            self._new_alert(
                                rule_id="R004",
                                rule_name="Impossible Travel Detected",
                                severity="high",
                                                                mitre=["T1078"],
                                row=row2,
                                context={
                                    "reason": f"User logged in from {row1['geo_src']} and {row2['geo_src']} within {time_diff:.2f} hours",
                                    "prev_loc": row1["geo_src"],
                                    "curr_loc": row2["geo_src"]
                                }
                            )
                        )
        return alerts

    def _rule_rare_process(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        if "process_name" not in df.columns or df.empty:
            return alerts
            
        counts = df["process_name"].value_counts(normalize=True)
        rare_processes = counts[counts < 0.05].index.tolist() # Raised to 5% for MVP visibility
        
        for _, row in df[df["process_name"].isin(rare_processes)].iterrows():
            alerts.append(
                self._new_alert(
                    rule_id="R005",
                    rule_name="Rare Process Execution",
                    severity="medium",
                    mitre=["T1204"],
                    row=row,
                    context={"reason": "Execution of a process with low global frequency", "frequency": f"{counts[row['process_name']]:.2%}"}
                )
            )
        return alerts
