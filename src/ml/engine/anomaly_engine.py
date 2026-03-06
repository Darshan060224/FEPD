"""
FEPD Anomaly Engine
====================

Full pipeline orchestrator for case-adaptive anomaly detection.

Pipeline:
    Load Case Events
        ↓
    FeatureBuilder.build()
        ↓
    IsolationForestModel.fit()  ← learns normal behaviour
        ↓
    IsolationForestModel.predict()
        ↓
    AnomalyClusterer.cluster()
        ↓
    FlagGenerator.generate()
        ↓
    AnomalyResult list (ready for UI table)

Supports:
  • Global model — one baseline for entire case
  • Per-user model — separate baseline per user account
  • Incremental training — update model as new data arrives
  • Model persistence — save/load trained models per case
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from src.ml.engine.feature_builder import FeatureBuilder, PerUserFeatureBuilder, _attr
from src.ml.models.isolation_forest_model import (
    IsolationForestModel, score_to_severity,
)

logger = logging.getLogger(__name__)


# ============================================================================
# RESULT MODEL
# ============================================================================

@dataclass
class AnomalyResult:
    """Single anomaly finding — maps to one row in the UI table."""

    timestamp: Optional[str] = None
    event_type: str = ""
    source: str = ""
    severity: str = "LOW"
    anomaly_score: float = 0.0
    cluster: int = -1
    flags: str = ""
    user: str = ""
    process: str = ""
    file: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# FLAG GENERATOR
# ============================================================================

class FlagGenerator:
    """Generate human-readable flags explaining why an event is anomalous."""

    # If these processes appear in forensic data, they are inherently suspicious
    _SUSPICIOUS_PROCESSES = {
        "mimikatz", "psexec", "procdump", "cobaltstrike", "beacon",
        "meterpreter", "nc.exe", "ncat", "netcat", "lazagne",
        "bloodhound", "rubeus", "certipy", "secretsdump",
        "wmiexec", "smbexec", "atexec", "dcomexec",
        "powershell -enc", "powershell -e ", "cmd /c ",
        "certutil -urlcache", "bitsadmin /transfer",
    }

    _SUSPICIOUS_PATHS = {
        "temp", "tmp", "$recycle.bin", "appdata\\local\\temp",
        "appdata/local/temp", "programdata", "/dev/shm", "/tmp",
    }

    @classmethod
    def generate(
        cls,
        event,
        score: float,
        feature_vector: Optional[np.ndarray] = None,
        feature_names: Optional[List[str]] = None,
    ) -> List[str]:
        """Generate flags for a single event."""
        flags: List[str] = []

        ts = _attr(event, "timestamp")
        process = (_attr(event, "process") or "").lower()
        file_val = (_attr(event, "file") or "").lower()
        category = (_attr(event, "category") or "").lower()

        # Off-hours activity
        if ts:
            hour = ts.hour if hasattr(ts, "hour") else 0
            if hour >= 22 or hour < 6:
                flags.append("off-hours activity")
            if hasattr(ts, "weekday") and ts.weekday() >= 5:
                flags.append("weekend activity")

        # Suspicious process
        for sp in cls._SUSPICIOUS_PROCESSES:
            if sp in process:
                flags.append(f"known attack tool: {sp}")
                break

        # Suspicious path
        for sp in cls._SUSPICIOUS_PATHS:
            if sp in file_val:
                flags.append(f"suspicious path: {sp}")
                break

        # Feature-based flags
        if feature_vector is not None and feature_names is not None:
            fdict = dict(zip(feature_names, feature_vector))
            if fdict.get("process_rarity", 0) > 0.8:
                flags.append("rare process execution")
            if fdict.get("execution_gap", 0) > 3600:
                flags.append("large time gap before event")
            if fdict.get("file_ext_risk", 0) >= 0.7:
                flags.append("high-risk file extension")
            if fdict.get("path_depth", 0) >= 8:
                flags.append("unusually deep file path")

        # Score-based
        if score >= 0.85:
            flags.append("extreme anomaly score")
        elif score >= 0.65:
            flags.append("high anomaly score")

        # Category-based
        if "registry" in category:
            flags.append("registry modification")
        if "persistence" in category or "autorun" in category:
            flags.append("persistence mechanism")

        return flags if flags else ["statistical anomaly detected"]


# ============================================================================
# ANOMALY ENGINE
# ============================================================================

class AnomalyEngine:
    """
    Full-pipeline anomaly detector that trains on case data.

    Usage:
        engine = AnomalyEngine()
        results = engine.run(events)
        # results is list[AnomalyResult]
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        per_user: bool = False,
        models_dir: Optional[Path] = None,
    ):
        self._contamination = contamination
        self._n_estimators = n_estimators
        self._per_user = per_user
        self._models_dir = models_dir

        self._feature_builder = FeatureBuilder()
        self._per_user_builder = PerUserFeatureBuilder()
        self._global_model: Optional[IsolationForestModel] = None
        self._user_models: Dict[str, IsolationForestModel] = {}

        self._last_results: List[AnomalyResult] = []
        self._feature_importance: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Full pipeline
    # ------------------------------------------------------------------

    def run(
        self,
        events: list,
        *,
        progress_callback=None,
    ) -> List[AnomalyResult]:
        """
        Execute the complete anomaly detection pipeline.

        Args:
            events: list of ForensicEvent (or dicts).
            progress_callback: optional fn(percent, message) for UI updates.

        Returns:
            list[AnomalyResult] sorted by anomaly_score descending.
        """
        if not events:
            return []

        def _progress(pct: int, msg: str):
            if progress_callback:
                progress_callback(pct, msg)

        _progress(5, "Extracting features…")

        if self._per_user:
            results = self._run_per_user(events, _progress)
        else:
            results = self._run_global(events, _progress)

        # Sort by score descending
        results.sort(key=lambda r: r.anomaly_score, reverse=True)
        self._last_results = results

        _progress(100, f"Complete — {len(results)} events analysed")
        return results

    # ------------------------------------------------------------------
    # Global model
    # ------------------------------------------------------------------

    def _run_global(self, events: list, _progress) -> List[AnomalyResult]:
        X, feature_names = self._feature_builder.build(events)
        if X.shape[0] == 0:
            return []

        _progress(20, "Training model on case data…")
        model = IsolationForestModel(
            contamination=self._contamination,
            n_estimators=self._n_estimators,
        )
        model.fit(X)
        self._global_model = model

        _progress(50, "Detecting anomalies…")
        scores, labels, severities = model.predict(X)

        self._feature_importance = model.feature_importance(feature_names)

        _progress(70, "Generating flags…")
        results = self._build_results(events, X, feature_names, scores, labels, severities)

        # Cluster
        _progress(85, "Clustering anomalies…")
        results = self._apply_clustering(results, X, scores)

        return results

    # ------------------------------------------------------------------
    # Per-user models
    # ------------------------------------------------------------------

    def _run_per_user(self, events: list, _progress) -> List[AnomalyResult]:
        user_data = self._per_user_builder.build_per_user(events)

        # Group events by user
        user_events: Dict[str, list] = {}
        for ev in events:
            user = _attr(ev, "user") or "SYSTEM"
            user_events.setdefault(user, []).append(ev)

        all_results: List[AnomalyResult] = []
        total_users = len(user_data)

        for idx, (user, (X, feature_names)) in enumerate(user_data.items()):
            pct = 20 + int(60 * idx / max(total_users, 1))
            _progress(pct, f"Analysing user: {user}…")

            model = IsolationForestModel(
                contamination=self._contamination,
                n_estimators=max(100, self._n_estimators // 2),
            )
            model.fit(X)
            self._user_models[user] = model

            scores, labels, severities = model.predict(X)
            evts = user_events.get(user, [])
            results = self._build_results(evts, X, feature_names, scores, labels, severities)
            all_results.extend(results)

        _progress(85, "Clustering anomalies…")
        # Rebuild a global X for clustering
        global_X, _ = self._feature_builder.build(events)
        global_scores = np.array([r.anomaly_score for r in all_results])
        all_results = self._apply_clustering(all_results, global_X, global_scores)

        return all_results

    # ------------------------------------------------------------------
    # Result building
    # ------------------------------------------------------------------

    def _build_results(
        self,
        events: list,
        X: np.ndarray,
        feature_names: List[str],
        scores: np.ndarray,
        labels: np.ndarray,
        severities: List[str],
    ) -> List[AnomalyResult]:
        results: List[AnomalyResult] = []
        for i, ev in enumerate(events):
            ts = _attr(ev, "timestamp")
            flags = FlagGenerator.generate(
                ev, float(scores[i]), X[i] if i < len(X) else None, feature_names
            )
            results.append(AnomalyResult(
                timestamp=ts.isoformat() if ts else None,
                event_type=_attr(ev, "category") or _attr(ev, "event_type") or "",
                source=_attr(ev, "source") or "",
                severity=severities[i],
                anomaly_score=round(float(scores[i]), 4),
                cluster=-1,
                flags="; ".join(flags),
                user=_attr(ev, "user") or "",
                process=_attr(ev, "process") or "",
                file=_attr(ev, "file") or "",
            ))
        return results

    # ------------------------------------------------------------------
    # Clustering
    # ------------------------------------------------------------------

    def _apply_clustering(
        self,
        results: List[AnomalyResult],
        X: np.ndarray,
        scores: np.ndarray,
    ) -> List[AnomalyResult]:
        """Apply DBSCAN clustering to anomalous events."""
        try:
            from src.ml.clustering.anomaly_cluster import AnomalyClusterer
            clusterer = AnomalyClusterer()
            # Only cluster anomalies (score > 0.45)
            anomaly_mask = scores > 0.45
            if anomaly_mask.sum() < 3:
                return results

            anomaly_X = X[anomaly_mask] if len(X) == len(results) else X[:anomaly_mask.sum()]
            cluster_labels = clusterer.cluster(anomaly_X)

            j = 0
            for i, is_anom in enumerate(anomaly_mask):
                if is_anom and i < len(results):
                    if j < len(cluster_labels):
                        results[i].cluster = int(cluster_labels[j])
                    j += 1
        except Exception as exc:
            logger.warning("Clustering failed: %s", exc)

        return results

    # ------------------------------------------------------------------
    # Model persistence
    # ------------------------------------------------------------------

    def save_model(self, case_id: str):
        """Save trained model(s) to models directory."""
        if not self._models_dir:
            return
        self._models_dir.mkdir(parents=True, exist_ok=True)

        if self._global_model and self._global_model.is_fitted:
            path = self._models_dir / f"{case_id}_global.pkl"
            self._global_model.save(path)

        for user, model in self._user_models.items():
            if model.is_fitted:
                safe_user = user.replace("\\", "_").replace("/", "_")
                path = self._models_dir / f"{case_id}_{safe_user}.pkl"
                model.save(path)

    def load_model(self, case_id: str) -> bool:
        """Load a previously saved model."""
        if not self._models_dir:
            return False
        path = self._models_dir / f"{case_id}_global.pkl"
        if path.exists():
            self._global_model = IsolationForestModel.load(path)
            return True
        return False

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def feature_importance(self) -> Dict[str, float]:
        return self._feature_importance

    def get_report(self) -> Dict[str, Any]:
        """Generate a summary report of the last analysis."""
        if not self._last_results:
            return {"total": 0}

        results = self._last_results
        total = len(results)
        severities = [r.severity for r in results]
        anomalies = [r for r in results if r.anomaly_score > 0.45]

        return {
            "total_events": total,
            "total_anomalies": len(anomalies),
            "anomaly_rate": f"{100 * len(anomalies) / total:.1f}%",
            "severity_breakdown": {
                "CRITICAL": severities.count("CRITICAL"),
                "HIGH": severities.count("HIGH"),
                "MEDIUM": severities.count("MEDIUM"),
                "LOW": severities.count("LOW"),
            },
            "top_flags": self._top_flags(results),
            "unique_clusters": len(set(r.cluster for r in anomalies if r.cluster >= 0)),
            "feature_importance": dict(
                sorted(self._feature_importance.items(), key=lambda x: x[1], reverse=True)[:5]
            ),
            "mode": "per-user" if self._per_user else "global",
        }

    @staticmethod
    def _top_flags(results: List[AnomalyResult], top_n: int = 10) -> List[str]:
        from collections import Counter
        all_flags: List[str] = []
        for r in results:
            if r.flags:
                all_flags.extend(f.strip() for f in r.flags.split(";") if f.strip())
        return [f for f, _ in Counter(all_flags).most_common(top_n)]

    def results_to_dataframe(self) -> pd.DataFrame:
        """Convert results to DataFrame for export."""
        if not self._last_results:
            return pd.DataFrame()
        return pd.DataFrame([r.to_dict() for r in self._last_results])
