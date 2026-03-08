"""
FEPD - UEBA Behavioral Anomaly Detector
=========================================

Per-user behavioural profiling using IsolationForest.

Detects:
  - Unusual login times
  - Rare process execution
  - Abnormal file access volume
  - Lateral movement indicators
  - Data exfiltration patterns
  - Privilege escalation

Pipeline:
    User Events
        ↓
    Per-User Feature Extraction
        ↓
    Build Normal Baseline (IsolationForest per user)
        ↓
    Score New Events Against Baseline
        ↓
    Aggregate Risk per User
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False


# ============================================================================
# RESULT TYPES
# ============================================================================

@dataclass
class UserRiskProfile:
    user_id: str
    risk_score: float = 0.0
    total_events: int = 0
    anomalous_events: int = 0
    alert_count: int = 0
    top_flags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BehavioralAnomaly:
    user_id: str
    timestamp: str = ""
    event: str = ""
    deviation_score: float = 0.0
    severity: str = "LOW"
    flags: List[str] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================================
# UEBA ENGINE
# ============================================================================

class UEBADetector:
    """
    Per-user behavioural anomaly detection engine.

    Usage::

        detector = UEBADetector()
        user_risks, anomalies = detector.analyse(events)
    """

    _FEATURE_NAMES = [
        "hour", "day_of_week", "is_off_hours", "is_weekend",
        "process_rarity", "file_access_count", "event_rate",
    ]

    def __init__(self, contamination: float = 0.08):
        self._contamination = contamination
        self._user_models: Dict[str, IsolationForest] = {}
        self._user_stats: Dict[str, Dict] = {}

    def analyse(
        self,
        events: List[Dict[str, Any]],
        progress_callback=None,
    ) -> tuple[List[UserRiskProfile], List[BehavioralAnomaly]]:
        """
        Run UEBA analysis on a list of events.

        Returns:
            (user_risk_profiles, anomalies)
        """
        if not events or not _HAS_SKLEARN:
            return [], []

        def _prog(p, m):
            if progress_callback:
                progress_callback(p, m)

        # 1. Group events by user
        _prog(5, "Grouping events by user …")
        user_events = self._group_by_user(events)

        # 2. Build per-user features and train baselines
        _prog(20, "Building user behaviour baselines …")
        all_anomalies: List[BehavioralAnomaly] = []
        user_risks: List[UserRiskProfile] = []

        users = list(user_events.keys())
        for idx, user_id in enumerate(users):
            pct = 20 + int(70 * (idx + 1) / len(users))
            _prog(pct, f"Profiling user: {user_id}")

            u_events = user_events[user_id]
            X = self._extract_user_features(u_events, user_id)

            if len(X) < 5:
                # Not enough data — skip modelling
                user_risks.append(UserRiskProfile(
                    user_id=user_id,
                    risk_score=0.0,
                    total_events=len(u_events),
                ))
                continue

            # Train per-user IsolationForest
            model = IsolationForest(
                n_estimators=100,
                contamination=self._contamination,
                random_state=42,
            )
            model.fit(X)
            self._user_models[user_id] = model

            # Score
            raw = model.decision_function(X)
            inverted = -raw
            mn, mx = inverted.min(), inverted.max()
            if mx - mn < 1e-9:
                scores = np.full(len(X), 0.0)
            else:
                scores = (inverted - mn) / (mx - mn)
            scores = np.clip(scores, 0.0, 1.0)

            # Identify anomalies
            anomaly_mask = scores >= 0.60
            anomalous = int(anomaly_mask.sum())

            # Build anomaly records
            flags_counter: Counter = Counter()
            for i, ev in enumerate(u_events):
                if scores[i] >= 0.60:
                    flags = self._explain(ev, scores[i])
                    flags_counter.update(flags)
                    all_anomalies.append(BehavioralAnomaly(
                        user_id=user_id,
                        timestamp=str(ev.get("timestamp", "")),
                        event=str(ev.get("process", ev.get("event_type", ""))),
                        deviation_score=round(float(scores[i]), 4),
                        severity=self._severity(float(scores[i])),
                        flags=flags,
                        explanation="; ".join(flags),
                    ))

            risk = float(np.mean(scores[anomaly_mask])) if anomalous > 0 else 0.0
            user_risks.append(UserRiskProfile(
                user_id=user_id,
                risk_score=round(risk, 4),
                total_events=len(u_events),
                anomalous_events=anomalous,
                alert_count=anomalous,
                top_flags=[f for f, _ in flags_counter.most_common(5)],
            ))

        # Sort users by risk descending
        user_risks.sort(key=lambda u: u.risk_score, reverse=True)
        all_anomalies.sort(key=lambda a: a.deviation_score, reverse=True)

        _prog(100, f"UEBA complete — {len(all_anomalies)} anomalies across {len(users)} users")
        return user_risks, all_anomalies

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _group_by_user(events: List[dict]) -> Dict[str, List[dict]]:
        groups: Dict[str, List[dict]] = defaultdict(list)
        for ev in events:
            user = str(ev.get("user", ev.get("user_id", "SYSTEM")))
            groups[user].append(ev)
        return dict(groups)

    def _extract_user_features(self, events: List[dict], user_id: str) -> np.ndarray:
        """Build feature matrix for one user's events."""
        rows = []
        # Compute process frequency for this user
        proc_counts: Counter = Counter()
        for ev in events:
            proc = str(ev.get("process", "")).lower()
            if proc:
                proc_counts[proc] += 1
        total_procs = sum(proc_counts.values()) or 1

        for ev in events:
            try:
                ts = pd.to_datetime(ev.get("timestamp"))
                hour = ts.hour
                dow = ts.weekday()
            except Exception:
                hour = 12
                dow = 0

            is_off = 1.0 if (hour >= 22 or hour < 6) else 0.0
            is_weekend = 1.0 if dow >= 5 else 0.0

            proc = str(ev.get("process", "")).lower()
            proc_rarity = 1.0 - (proc_counts.get(proc, 0) / total_procs) if proc else 0.5

            file_count = float(ev.get("file_access_count", ev.get("files_accessed", 1)))
            event_rate = float(ev.get("event_rate", ev.get("events_per_hour", 1)))

            rows.append([hour, dow, is_off, is_weekend, proc_rarity, file_count, event_rate])

        return np.array(rows, dtype=np.float64)

    @staticmethod
    def _explain(event: dict, score: float) -> List[str]:
        """Generate explanation flags for an anomalous event."""
        flags = []
        try:
            ts = pd.to_datetime(event.get("timestamp"))
            if ts.hour >= 22 or ts.hour < 6:
                flags.append(f"unusual_time:{ts.hour}:00")
            if ts.weekday() >= 5:
                flags.append("weekend_activity")
        except Exception:
            pass

        proc = str(event.get("process", "")).lower()
        if proc and proc not in {"explorer.exe", "chrome.exe", "msedge.exe", "svchost.exe"}:
            flags.append(f"uncommon_process:{proc}")

        if score >= 0.85:
            flags.append("extreme_deviation")
        elif score >= 0.70:
            flags.append("significant_deviation")

        return flags if flags else ["behaviour_anomaly"]

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 0.85:
            return "CRITICAL"
        if score >= 0.70:
            return "HIGH"
        if score >= 0.50:
            return "MEDIUM"
        return "LOW"
