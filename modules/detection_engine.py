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
        # Implement window-based brute force logic
        return []

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
        # Implement group-change / admin-add detection
        return []

    def _rule_impossible_travel(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        # Implement geo + time heuristic
        return []

    def _rule_rare_process(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        # Implement frequency-based rare process detection
        return []
