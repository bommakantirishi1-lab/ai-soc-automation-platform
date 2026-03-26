# modules/log_ingestion.py
# JSON Log Ingestion Module for AI SOC Automation Platform
# Supports: NDJSON, JSON Array, directory of .json files
# Normalizes all fields to standard schema for detection engine

import json
from pathlib import Path
from typing import List, Union, Dict, Any
import pandas as pd


NORMALIZED_FIELDS = [
    "timestamp",
    "src_ip",
    "dest_ip",
    "user",
    "event_id",
    "event_type",
    "host",
    "process_name",
    "command_line",
    "log_source",
    "geo_src",
    "geo_dest",
    "raw",
]


class LogIngestion:
    """
    Ingests JSON logs from file path, directory, or raw list.
    Normalizes all events to a standard pandas DataFrame schema.
    """

    def __init__(self, timezone: str = "UTC"):
        self.timezone = timezone
        self.ingestion_errors: List[str] = []

    def _load_from_file(self, path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Load records from a single JSON or NDJSON file."""
        path = Path(path)
        records: List[Dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8") as f:
                text = f.read().strip()
            if not text:
                return records
            try:
                # Try JSON array or single object first
                data = json.loads(text)
                if isinstance(data, list):
                    records.extend(data)
                elif isinstance(data, dict):
                    records.append(data)
            except json.JSONDecodeError:
                # Fallback: parse line-by-line as NDJSON
                for i, line in enumerate(text.splitlines(), 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        self.ingestion_errors.append(
                            f"{path.name} line {i}: {e}"
                        )
        except OSError as e:
            self.ingestion_errors.append(f"Cannot open {path}: {e}")
        return records

    def _normalize_record(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        """Map raw log fields to the normalized schema."""
        raw = json.dumps(rec, ensure_ascii=False, default=str)

        # Timestamp: try common field names
        ts = (
            rec.get("timestamp")
            or rec.get("@timestamp")
            or rec.get("event_time")
            or rec.get("time")
            or rec.get("EventTime")
        )

        # Source IP
        src_ip = (
            rec.get("src_ip")
            or rec.get("source_ip")
            or rec.get("client_ip")
            or rec.get("IpAddress")
            or rec.get("ipAddress")
        )

        # Destination IP
        dest_ip = (
            rec.get("dest_ip")
            or rec.get("destination_ip")
            or rec.get("server_ip")
            or rec.get("dst_ip")
        )

        # User
        user = (
            rec.get("user")
            or rec.get("username")
            or rec.get("account_name")
            or rec.get("AccountName")
            or rec.get("SubjectUserName")
            or rec.get("TargetUserName")
        )

        # Event ID
        event_id = (
            rec.get("event_id")
            or rec.get("eventID")
            or rec.get("EventID")
            or rec.get("id")
        )
        if event_id is not None:
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                event_id = str(event_id)

        # Event type / action
        event_type = (
            rec.get("event_type")
            or rec.get("event_name")
            or rec.get("action")
            or rec.get("EventType")
            or rec.get("Category")
        )

        # Hostname
        host = (
            rec.get("host")
            or rec.get("hostname")
            or rec.get("computer")
            or rec.get("ComputerName")
            or rec.get("workstation")
        )

        # Process name
        process_name = (
            rec.get("process_name")
            or rec.get("image")
            or rec.get("Image")
            or rec.get("process")
            or rec.get("ProcessName")
            or rec.get("NewProcessName")
        )

        # Command line
        command_line = (
            rec.get("command_line")
            or rec.get("cmdline")
            or rec.get("CommandLine")
            or rec.get("process_command_line")
            or rec.get("ParentCommandLine")
        )

        # Log source / product
        log_source = (
            rec.get("log_source")
            or rec.get("product")
            or rec.get("provider")
            or rec.get("Channel")
            or rec.get("source")
        )

        # Geo fields
        geo_src = rec.get("geo_src") or rec.get("source_geo") or rec.get("src_country")
        geo_dest = rec.get("geo_dest") or rec.get("destination_geo") or rec.get("dst_country")

        return {
            "timestamp": ts,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "user": user,
            "event_id": event_id,
            "event_type": event_type,
            "host": host,
            "process_name": process_name,
            "command_line": command_line,
            "log_source": log_source,
            "geo_src": geo_src,
            "geo_dest": geo_dest,
            "raw": raw,
        }

    def _build_dataframe(self, records: List[Dict[str, Any]]) -> pd.DataFrame:
        """Convert normalized records list to a sorted DataFrame."""
        if not records:
            return pd.DataFrame(columns=NORMALIZED_FIELDS)
        normalized = [self._normalize_record(r) for r in records]
        df = pd.DataFrame(normalized)
        # Ensure all expected columns exist
        for col in NORMALIZED_FIELDS:
            if col not in df.columns:
                df[col] = None
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df = df.sort_values("timestamp", na_position="last").reset_index(drop=True)
        return df

    def from_path(self, path: Union[str, Path]) -> pd.DataFrame:
        """
        Load logs from a file or directory.
        - Single file: JSON array or NDJSON
        - Directory: all *.json files inside
        Returns normalized DataFrame sorted by timestamp.
        """
        path = Path(path)
        all_records: List[Dict[str, Any]] = []
        if path.is_dir():
            json_files = sorted(path.glob("*.json"))
            if not json_files:
                self.ingestion_errors.append(f"No .json files found in {path}")
            for p in json_files:
                all_records.extend(self._load_from_file(p))
        elif path.is_file():
            all_records.extend(self._load_from_file(path))
        else:
            self.ingestion_errors.append(f"Path not found: {path}")
        return self._build_dataframe(all_records)

    def from_list(self, records: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Load logs from a Python list of dicts (e.g., from API or in-memory stream).
        Returns normalized DataFrame sorted by timestamp.
        """
        if not isinstance(records, list):
            raise TypeError("records must be a list of dicts")
        return self._build_dataframe(records)

    def from_json_string(self, json_str: str) -> pd.DataFrame:
        """
        Load logs from a raw JSON string (array or NDJSON).
        Returns normalized DataFrame sorted by timestamp.
        """
        records: List[Dict[str, Any]] = []
        json_str = json_str.strip()
        if not json_str:
            return pd.DataFrame(columns=NORMALIZED_FIELDS)
        try:
            data = json.loads(json_str)
            if isinstance(data, list):
                records.extend(data)
            elif isinstance(data, dict):
                records.append(data)
        except json.JSONDecodeError:
            for i, line in enumerate(json_str.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    self.ingestion_errors.append(f"String line {i}: {e}")
        return self._build_dataframe(records)

    def get_stats(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Return basic ingestion stats for the dashboard."""
        if df.empty:
            return {"total": 0, "sources": [], "earliest": None, "latest": None}
        return {
            "total": len(df),
            "sources": df["log_source"].dropna().unique().tolist(),
            "hosts": df["host"].dropna().unique().tolist(),
            "users": df["user"].dropna().nunique(),
            "earliest": str(df["timestamp"].min()),
            "latest": str(df["timestamp"].max()),
            "errors": self.ingestion_errors,
        }
