"""
FEPD Data Processor
====================

Standardises heterogeneous forensic event data into a canonical
``ForensicEvent`` format that every chart module can consume.

Pipeline:
    Raw DataFrame / list[dict]
        → normalise column names
        → parse timestamps
        → fill defaults
        → produce list[ForensicEvent]

All charts read from this one structure — no per-chart data wrangling.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Known column aliases → canonical name
_COLUMN_ALIASES: Dict[str, str] = {
    # timestamp
    "time": "timestamp", "date": "timestamp", "datetime": "timestamp",
    "event_time": "timestamp", "created": "timestamp",
    "modified": "timestamp", "date_time": "timestamp",
    # user
    "username": "user", "user_name": "user", "account": "user",
    "user_id": "user", "subject": "user",
    # process
    "process_name": "process", "image": "process",
    "executable": "process", "exe": "process",
    "command_line": "process",
    # file
    "filename": "file", "file_name": "file", "path": "file",
    "filepath": "file", "file_path": "file", "object": "file",
    # category
    "event_type": "category", "type": "category",
    "artifact_type": "category", "action": "category",
    # severity
    "risk": "severity", "risk_level": "severity",
    "threat_level": "severity", "priority": "severity",
    # source
    "source_type": "source", "artifact": "source",
    "log_source": "source", "origin": "source",
    # extras
    "host": "host", "hostname": "host", "computer": "host",
    "src_ip": "source_ip", "dst_ip": "dest_ip",
    "destination_ip": "dest_ip", "source_ip": "source_ip",
    "dest_ip": "dest_ip",
    "port": "port", "dest_port": "port",
}

# Canonical severity levels (normalised)
_SEVERITY_MAP = {
    "critical": "CRITICAL", "crit": "CRITICAL", "4": "CRITICAL",
    "high": "HIGH", "3": "HIGH",
    "medium": "MEDIUM", "moderate": "MEDIUM", "2": "MEDIUM", "med": "MEDIUM",
    "low": "LOW", "info": "LOW", "informational": "LOW",
    "1": "LOW", "0": "LOW", "none": "LOW",
}


# ============================================================================
# CANONICAL EVENT MODEL
# ============================================================================

@dataclass
class ForensicEvent:
    """Single forensic event — the universal currency of the viz engine."""

    timestamp: Optional[datetime] = None
    user: str = "SYSTEM"
    process: str = ""
    file: str = ""
    category: str = "UNKNOWN"
    severity: str = "LOW"
    source: str = ""
    host: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    port: int = 0
    anomaly_score: float = 0.0
    cluster: int = -1
    flags: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    # Derived helpers (used by chart modules)

    @property
    def hour(self) -> int:
        return self.timestamp.hour if self.timestamp else 0

    @property
    def date_str(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d") if self.timestamp else ""

    @property
    def weekday(self) -> int:
        return self.timestamp.weekday() if self.timestamp else 0

    @property
    def weekday_name(self) -> str:
        _names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        return _names[self.weekday] if self.timestamp else ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d["timestamp"]:
            d["timestamp"] = d["timestamp"].isoformat()
        return d


# ============================================================================
# DATA PROCESSOR
# ============================================================================

class DataProcessor:
    """
    Converts raw evidence data into ``list[ForensicEvent]``.

    Accepts:
      • ``pd.DataFrame``
      • ``list[dict]``
      • ``list[ForensicEvent]`` (pass-through)

    All columns are normalised via alias mapping so callers don't need
    to worry about naming conventions.
    """

    def __init__(self):
        self._last_df: Optional[pd.DataFrame] = None
        self._last_events: List[ForensicEvent] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(
        self,
        data: Any,
        *,
        max_events: int = 100_000,
    ) -> List[ForensicEvent]:
        """
        Main entry point.  Returns a list of ``ForensicEvent`` objects.
        """
        if isinstance(data, list) and data and isinstance(data[0], ForensicEvent):
            self._last_events = data[:max_events]
            return self._last_events

        df = self._to_dataframe(data)
        if df.empty:
            self._last_events = []
            return []

        df = self._normalise_columns(df)
        df = self._parse_timestamps(df)
        df = self._normalise_severity(df)

        if len(df) > max_events:
            logger.warning("Dataset trimmed from %d to %d events", len(df), max_events)
            df = df.head(max_events)

        events = self._rows_to_events(df)
        self._last_df = df
        self._last_events = events
        return events

    def to_dataframe(self, events: Optional[List[ForensicEvent]] = None) -> pd.DataFrame:
        """Convert events back into a DataFrame (for aggregations)."""
        evts = events or self._last_events
        if not evts:
            return pd.DataFrame()
        records = [e.to_dict() for e in evts]
        df = pd.DataFrame(records)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df

    @property
    def last_events(self) -> List[ForensicEvent]:
        return self._last_events

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _to_dataframe(data: Any) -> pd.DataFrame:
        if isinstance(data, pd.DataFrame):
            return data.copy()
        if isinstance(data, (list, tuple)):
            if not data:
                return pd.DataFrame()
            if isinstance(data[0], dict):
                return pd.DataFrame(data)
            # Might be ForensicEvent already
            try:
                return pd.DataFrame([asdict(e) for e in data])
            except Exception:
                return pd.DataFrame()
        return pd.DataFrame()

    @staticmethod
    def _normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
        rename_map = {}
        for col in df.columns:
            key = col.strip().lower().replace(" ", "_")
            if key in _COLUMN_ALIASES:
                canon = _COLUMN_ALIASES[key]
                # Don't overwrite a column that already exists
                if canon not in df.columns and canon not in rename_map.values():
                    rename_map[col] = canon
        if rename_map:
            df = df.rename(columns=rename_map)
        return df

    @staticmethod
    def _parse_timestamps(df: pd.DataFrame) -> pd.DataFrame:
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df

    @staticmethod
    def _normalise_severity(df: pd.DataFrame) -> pd.DataFrame:
        if "severity" in df.columns:
            df["severity"] = df["severity"].astype(str).str.strip().str.lower().map(
                lambda s: _SEVERITY_MAP.get(s, "LOW")
            )
        return df

    @staticmethod
    def _rows_to_events(df: pd.DataFrame) -> List[ForensicEvent]:
        events: List[ForensicEvent] = []
        canonical_cols = {
            "timestamp", "user", "process", "file", "category",
            "severity", "source", "host", "source_ip", "dest_ip",
            "port", "anomaly_score", "cluster", "flags",
        }
        for _, row in df.iterrows():
            kw: Dict[str, Any] = {}
            raw: Dict[str, Any] = {}
            for col in df.columns:
                val = row[col]
                if pd.isna(val):
                    continue
                if col in canonical_cols:
                    if col == "timestamp" and isinstance(val, pd.Timestamp):
                        kw[col] = val.to_pydatetime()
                    elif col == "port":
                        try:
                            kw[col] = int(val)
                        except (ValueError, TypeError):
                            kw[col] = 0
                    elif col in ("anomaly_score",):
                        try:
                            kw[col] = float(val)
                        except (ValueError, TypeError):
                            kw[col] = 0.0
                    elif col == "cluster":
                        try:
                            kw[col] = int(val)
                        except (ValueError, TypeError):
                            kw[col] = -1
                    else:
                        kw[col] = str(val)
                else:
                    raw[col] = val if not isinstance(val, (pd.Timestamp,)) else str(val)
            kw["raw"] = raw
            events.append(ForensicEvent(**kw))
        return events

    # ------------------------------------------------------------------
    # Aggregation helpers (for chart modules)
    # ------------------------------------------------------------------

    def hourly_counts(self, events: Optional[List[ForensicEvent]] = None) -> pd.Series:
        """Count events per hour (0-23)."""
        evts = events or self._last_events
        hours = [e.hour for e in evts if e.timestamp]
        s = pd.Series(hours).value_counts().reindex(range(24), fill_value=0).sort_index()
        s.index.name = "hour"
        return s

    def daily_counts(self, events: Optional[List[ForensicEvent]] = None) -> pd.Series:
        """Count events per date string."""
        evts = events or self._last_events
        dates = [e.date_str for e in evts if e.timestamp]
        return pd.Series(dates).value_counts().sort_index()

    def category_counts(self, events: Optional[List[ForensicEvent]] = None) -> pd.Series:
        evts = events or self._last_events
        cats = [e.category for e in evts]
        return pd.Series(cats).value_counts()

    def severity_counts(self, events: Optional[List[ForensicEvent]] = None) -> pd.Series:
        evts = events or self._last_events
        sevs = [e.severity for e in evts]
        ordered = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        return pd.Series(sevs).value_counts().reindex(ordered, fill_value=0)

    def user_hour_matrix(
        self, events: Optional[List[ForensicEvent]] = None
    ) -> pd.DataFrame:
        """Rows = users, Columns = hours (0-23), Values = event count."""
        evts = events or self._last_events
        data = [(e.user, e.hour) for e in evts if e.timestamp and e.user]
        if not data:
            return pd.DataFrame()
        df = pd.DataFrame(data, columns=["user", "hour"])
        matrix = df.groupby("user")["hour"].value_counts().unstack(fill_value=0)
        for h in range(24):
            if h not in matrix.columns:
                matrix[h] = 0
        return matrix[sorted(matrix.columns)]

    def date_hour_matrix(
        self, events: Optional[List[ForensicEvent]] = None
    ) -> pd.DataFrame:
        """Rows = dates, Columns = hours (0-23), Values = event count."""
        evts = events or self._last_events
        data = [(e.date_str, e.hour) for e in evts if e.timestamp]
        if not data:
            return pd.DataFrame()
        df = pd.DataFrame(data, columns=["date", "hour"])
        matrix = df.groupby("date")["hour"].value_counts().unstack(fill_value=0)
        for h in range(24):
            if h not in matrix.columns:
                matrix[h] = 0
        return matrix[sorted(matrix.columns)]

    def source_counts(self, events: Optional[List[ForensicEvent]] = None) -> pd.Series:
        evts = events or self._last_events
        return pd.Series([e.source for e in evts if e.source]).value_counts()

    def process_counts(self, events: Optional[List[ForensicEvent]] = None) -> pd.Series:
        evts = events or self._last_events
        return pd.Series([e.process for e in evts if e.process]).value_counts()
