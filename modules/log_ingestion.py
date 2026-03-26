# modules/log_ingestion.py
import json
from pathlib import Path
from typing import List, Union, Dict, Any
import pandas as pd

NORMALIZED_FIELDS = [
    "timestamp", "src_ip", "dest_ip", "user", "event_id", "event_type",
    "host", "process_name", "command_line", "log_source", "geo_src",
    "geo_dest", "raw"
]

class LogIngestion:
    def __init__(self, timezone: str = "UTC"):
        self.timezone = timezone
        self.ingestion_errors: List[str] = []

    def _load_from_file(self, path: Union[str, Path]) -> List[Dict[str, Any]]:
        path = Path(path)
        records = []
        with path.open("r", encoding="utf-8") as f:
            text = f.read().strip()
            if not text:
                return records
            try:
                # Try JSON array
                data = json.loads(text)
                if isinstance(data, list):
                    records.extend(data)
                elif isinstance(data, dict):
                    records.append(data)
            except json.JSONDecodeError:
                # Fallback: NDJSON
                f.seek(0)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        self.ingestion_errors.append(f"{path}: {e}")
        return records

    def _normalize_record(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        raw = json.dumps(rec, ensure_ascii=False)
        ts = (rec.get("timestamp")
              or rec.get("@timestamp")
              or rec.get("event_time")
              )
        out = {
            "timestamp": ts,
            "src_ip": rec.get("src_ip") or rec.get("source_ip") or rec.get("client_ip"),
            "dest_ip": rec.get("dest_ip") or rec.get("destination_ip") or rec.get("server_ip"),
            "user": rec.get("user") or rec.get("username") or rec.get("account_name"),
            "event_id": rec.get("event_id") or rec.get("eventID") or rec.get("id"),
            "event_type": rec.get("event_type") or rec.get("event_name") or rec.get("action"),
            "host": rec.get("host") or rec.get("hostname") or rec.get("computer"),
            "process_name": rec.get("process_name") or rec.get("image") or rec.get("process"),
            "command_line": rec.get("command_line") or rec.get("cmdline") or rec.get("process_command_line"),
            "log_source": rec.get("log_source") or rec.get("product") or rec.get("provider"),
            "geo_src": rec.get("geo_src") or rec.get("source_geo"),
            "geo_dest": rec.get("geo_dest") or rec.get("destination_geo"),
            "raw": raw,
        }
        return out

    def from_path(self, path: Union[str, Path]) -> pd.DataFrame:
        path = Path(path)
        all_records: List[Dict[str, Any]] = []
        if path.is_dir():
            for p in path.glob("*.json"):
                all_records.extend(self._load_from_file(p))
        else:
            all_records.extend(self._load_from_file(path))
        normalized = [self._normalize_record(r) for r in all_records]
        df = pd.DataFrame(normalized)
        if not df.empty and "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
            df = df.sort_values("timestamp")
        return df

    def from_list(self, records: List[Dict[str, Any]]) -> pd.DataFrame:
        normalized = [self._normalize_record(r) for r in records]
        df = pd.DataFrame(normalized)
        if not df.empty and "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
            df = df.sort_values("timestamp")
        return df
