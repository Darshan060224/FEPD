"""
FEPD ML Feature Builder
========================

Converts raw forensic events into numeric feature vectors
that can be fed directly to Isolation Forest / DBSCAN.

Feature Vector Schema (per event):
    ┌─────────────────────┬────────────────────────────────────┐
    │ Feature             │ Meaning                            │
    ├─────────────────────┼────────────────────────────────────┤
    │ hour_of_day         │ 0–23                               │
    │ is_off_hours        │ 1 if hour ∈ [22,06), else 0        │
    │ day_of_week         │ 0 (Mon) – 6 (Sun)                  │
    │ is_weekend          │ 1 if Sat/Sun                       │
    │ process_frequency   │ relative freq of this process      │
    │ process_rarity      │ 1 / (freq + 1) — rare=high         │
    │ user_event_count    │ total events for this user          │
    │ category_frequency  │ relative freq of this category     │
    │ path_depth          │ number of path separators           │
    │ file_ext_risk       │ 0–1 risk score for file extension   │
    │ execution_gap       │ seconds since previous event        │
    │ severity_numeric    │ LOW=0, MED=1, HIGH=2, CRITICAL=3   │
    └─────────────────────┴────────────────────────────────────┘

Usage:
    builder = FeatureBuilder()
    X, labels = builder.build(events)
    # X is a numpy array, labels is a list of feature names
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


# Risk scores for file extensions (higher = more suspicious)
_EXT_RISK: Dict[str, float] = {
    # critical
    "exe": 0.9, "dll": 0.85, "sys": 0.85, "scr": 0.95,
    "bat": 0.8, "cmd": 0.8, "ps1": 0.85, "vbs": 0.9,
    "wsf": 0.9, "hta": 0.9, "com": 0.85, "msi": 0.7,
    # high
    "js": 0.6, "jar": 0.7, "py": 0.5, "reg": 0.7,
    "lnk": 0.6, "iso": 0.6, "img": 0.5, "vhd": 0.5,
    # moderate
    "zip": 0.4, "rar": 0.4, "7z": 0.4, "cab": 0.35,
    "doc": 0.35, "docx": 0.3, "xls": 0.35, "xlsx": 0.3,
    "ppt": 0.25, "pdf": 0.25,
    # low
    "txt": 0.05, "log": 0.05, "csv": 0.1, "json": 0.1,
    "xml": 0.1, "html": 0.15, "png": 0.05, "jpg": 0.05,
}

_SEVERITY_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class FeatureBuilder:
    """
    Transforms ``ForensicEvent`` objects into a feature matrix.

    Thread-safe and stateless after construction.
    """

    # Feature column names (order must match _build_vector)
    FEATURE_NAMES: List[str] = [
        "hour_of_day",
        "is_off_hours",
        "day_of_week",
        "is_weekend",
        "process_frequency",
        "process_rarity",
        "user_event_count",
        "category_frequency",
        "path_depth",
        "file_ext_risk",
        "execution_gap",
        "severity_numeric",
    ]

    def __init__(self):
        self._process_freq: Dict[str, float] = {}
        self._user_counts: Dict[str, int] = {}
        self._category_freq: Dict[str, float] = {}
        self._total_events: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, events: list) -> Tuple[np.ndarray, List[str]]:
        """
        Build feature matrix from events.

        Args:
            events: list of ForensicEvent (or dicts with the same keys).

        Returns:
            (X, feature_names) where X is shape (n_events, n_features).
        """
        if not events:
            return np.empty((0, len(self.FEATURE_NAMES))), self.FEATURE_NAMES

        self._compute_frequencies(events)
        vectors = [self._build_vector(ev, idx, events) for idx, ev in enumerate(events)]
        X = np.array(vectors, dtype=np.float64)

        # Replace NaN /Inf with 0
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        logger.info("Built feature matrix: %s", X.shape)
        return X, self.FEATURE_NAMES

    def build_dataframe(self, events: list) -> pd.DataFrame:
        """Return features as a labelled DataFrame (handy for inspection)."""
        X, names = self.build(events)
        return pd.DataFrame(X, columns=names)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _compute_frequencies(self, events: list):
        self._total_events = len(events)
        proc_counter = Counter(_attr(ev, "process") for ev in events if _attr(ev, "process"))
        user_counter = Counter(_attr(ev, "user") for ev in events if _attr(ev, "user"))
        cat_counter = Counter(_attr(ev, "category") for ev in events if _attr(ev, "category"))

        total_proc = sum(proc_counter.values()) or 1
        total_cat = sum(cat_counter.values()) or 1

        self._process_freq = {k: v / total_proc for k, v in proc_counter.items()}
        self._user_counts = dict(user_counter)
        self._category_freq = {k: v / total_cat for k, v in cat_counter.items()}

    def _build_vector(self, ev, idx: int, events: list) -> List[float]:
        ts = _attr(ev, "timestamp")
        hour = ts.hour if ts else 0
        dow = ts.weekday() if ts else 0

        process = _attr(ev, "process") or ""
        user = _attr(ev, "user") or ""
        category = _attr(ev, "category") or ""
        file_val = _attr(ev, "file") or ""
        severity = _attr(ev, "severity") or "LOW"

        # Execution gap (seconds between consecutive events)
        gap = 0.0
        if idx > 0 and ts:
            prev_ts = _attr(events[idx - 1], "timestamp")
            if prev_ts:
                gap = abs((ts - prev_ts).total_seconds())

        # File extension risk
        ext = ""
        if "." in file_val:
            ext = file_val.rsplit(".", 1)[-1].lower()
        elif "." in process:
            ext = process.rsplit(".", 1)[-1].lower()

        return [
            float(hour),                                            # hour_of_day
            1.0 if (hour >= 22 or hour < 6) else 0.0,             # is_off_hours
            float(dow),                                             # day_of_week
            1.0 if dow >= 5 else 0.0,                              # is_weekend
            self._process_freq.get(process, 0.0),                  # process_frequency
            1.0 / (self._process_freq.get(process, 0.0) + 1.0),   # process_rarity
            float(self._user_counts.get(user, 0)),                 # user_event_count
            self._category_freq.get(category, 0.0),                # category_frequency
            float(file_val.count("/") + file_val.count("\\")),     # path_depth
            _EXT_RISK.get(ext, 0.1),                               # file_ext_risk
            gap,                                                    # execution_gap
            float(_SEVERITY_MAP.get(severity.upper(), 0)),         # severity_numeric
        ]


# ============================================================================
# Per-User Feature Builder
# ============================================================================

class PerUserFeatureBuilder:
    """
    Builds separate feature matrices per user for per-user training.
    """

    def __init__(self):
        self._builder = FeatureBuilder()

    def build_per_user(
        self, events: list
    ) -> Dict[str, Tuple[np.ndarray, List[str]]]:
        """
        Returns:
            {username: (X, feature_names)}
        """
        user_events: Dict[str, list] = {}
        for ev in events:
            user = _attr(ev, "user") or "SYSTEM"
            user_events.setdefault(user, []).append(ev)

        result = {}
        for user, evts in user_events.items():
            if len(evts) < 5:
                continue  # too few events for meaningful training
            X, names = self._builder.build(evts)
            result[user] = (X, names)

        return result


# ============================================================================
# Helpers
# ============================================================================

def _attr(obj, name: str):
    """Get attribute from object or dict."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)
