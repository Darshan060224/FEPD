"""
FEPD - Hybrid Anomaly Detection Engine
========================================

Combines:
  1. Trained UNSW-NB15 supervised model (network intrusion detection)
  2. Case-adaptive IsolationForest     (artifact behaviour anomalies)
  3. Rule-based forensic detector       (known attack techniques)

Pipeline:
    Events / Artifacts
        ↓
    Feature Engineering
        ↓
    ┌──────────────────────┬───────────────────────┐
    │ Supervised Model     │ Unsupervised Model    │
    │ (UNSW-NB15 trained)  │ (IsolationForest)     │
    └──────────┬───────────┴───────────┬───────────┘
               └───── Fusion ──────────┘
                       ↓
                Risk Scoring
                       ↓
                Severity Classification
                       ↓
                Results Table
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ============================================================================
# RULE ENGINE — known DFIR attack signatures
# ============================================================================

_SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "psexec.exe", "procdump.exe", "lazagne.exe",
    "bloodhound.exe", "rubeus.exe", "sharphound.exe", "cobaltstrike.exe",
    "beacon.exe", "meterpreter.exe", "netcat.exe", "ncat.exe", "nc.exe",
}

_SUSPICIOUS_COMMANDS = [
    "powershell -enc", "powershell -e ", "cmd /c ", "certutil -urlcache",
    "bitsadmin /transfer", "reg add", "schtasks /create",
    "wmic process call create", "net user /add",
]

_HIGH_RISK_PATHS = [
    "\\temp\\", "\\tmp\\", "$recycle.bin", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\public\\", "/dev/shm", "/tmp/",
]


def rule_score(event: dict) -> tuple[float, list[str]]:
    """Apply rule-based detection. Returns (risk_boost, list_of_flags)."""
    flags: list[str] = []
    boost = 0.0

    process = str(event.get("process", "")).lower()
    path = str(event.get("path", event.get("file", ""))).lower()
    cmd = str(event.get("command_line", "")).lower()

    # Known attack tools
    for sp in _SUSPICIOUS_PROCESSES:
        if sp in process:
            flags.append(f"known_attack_tool:{sp}")
            boost = max(boost, 0.35)
            break

    # Suspicious commands
    for sc in _SUSPICIOUS_COMMANDS:
        if sc in cmd or sc in process:
            flags.append(f"suspicious_command:{sc.strip()}")
            boost = max(boost, 0.25)
            break

    # High-risk paths
    for hp in _HIGH_RISK_PATHS:
        if hp in path:
            flags.append(f"risky_path:{hp.strip('\\/')}")
            boost = max(boost, 0.10)
            break

    # Off-hours execution
    ts = event.get("timestamp")
    if ts is not None:
        try:
            hour = pd.to_datetime(ts).hour
            if hour >= 22 or hour < 6:
                flags.append("off_hours_activity")
                boost = max(boost, 0.10)
        except Exception:
            pass

    return boost, flags


# ============================================================================
# SEVERITY CLASSIFICATION
# ============================================================================

def score_to_severity(score: float) -> str:
    """Map fused anomaly score (0-1) → severity label."""
    if score >= 0.90:
        return "CRITICAL"
    if score >= 0.75:
        return "HIGH"
    if score >= 0.50:
        return "MEDIUM"
    return "LOW"


# ============================================================================
# HYBRID RESULT
# ============================================================================

@dataclass
class HybridResult:
    """One row in the ML results table."""

    timestamp: str = ""
    event: str = ""
    source: str = ""
    severity: str = "LOW"
    score: float = 0.0
    cluster: int = -1
    flags: str = ""
    network_score: float = 0.0
    artifact_score: float = 0.0
    rule_boost: float = 0.0
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================================
# HYBRID ENGINE
# ============================================================================

class HybridAnomalyEngine:
    """
    Fuses multiple detection signals for high-confidence forensic results.

    Usage::

        engine = HybridAnomalyEngine()
        engine.load_network_model()
        results = engine.analyse(events)
    """

    def __init__(
        self,
        network_weight: float = 0.45,
        artifact_weight: float = 0.35,
        rule_weight: float = 0.20,
        contamination: float = 0.05,
    ):
        self.network_weight = network_weight
        self.artifact_weight = artifact_weight
        self.rule_weight = rule_weight
        self.contamination = contamination

        self._network_model = None
        self._if_model = None  # IsolationForest for artifacts
        self._loaded = False

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def load_network_model(self) -> bool:
        """Load the trained UNSW-NB15 network intrusion model."""
        try:
            from src.ml.models.network_intrusion_model import NetworkIntrusionModel
            self._network_model = NetworkIntrusionModel()
            ok = self._network_model.load()
            if ok:
                logger.info("Network intrusion model loaded")
            return ok
        except Exception as e:
            logger.warning("Could not load network model: %s", e)
            return False

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    def analyse(
        self,
        events: list[dict],
        progress_callback=None,
    ) -> list[HybridResult]:
        """
        Run hybrid anomaly detection on a list of forensic events.

        Each event should be a dict with keys like:
            timestamp, process, path, source, event_type, size, entropy, user …

        Returns list[HybridResult] sorted by score descending.
        """
        if not events:
            return []

        def _progress(pct: int, msg: str):
            if progress_callback:
                progress_callback(pct, msg)

        _progress(5, "Building feature vectors …")

        # 1. Build artifact feature matrix for IsolationForest
        artifact_features, events_clean = self._build_artifact_features(events)

        # 2. Train IsolationForest on these events (case-adaptive)
        _progress(20, "Training case-adaptive baseline …")
        artifact_scores = self._run_isolation_forest(artifact_features)

        # 3. Try running the trained network model (if loaded)
        _progress(40, "Evaluating network intrusion model …")
        network_scores = self._run_network_model(events_clean)

        # 4. Rule engine
        _progress(60, "Applying rule-based detection …")
        rule_boosts, rule_flags = self._run_rules(events_clean)

        # 5. Fuse scores
        _progress(75, "Fusing detection signals …")
        results = self._fuse(events_clean, artifact_scores, network_scores,
                             rule_boosts, rule_flags)

        # 6. Sort
        results.sort(key=lambda r: r.score, reverse=True)

        _progress(100, f"Complete — {sum(1 for r in results if r.severity != 'LOW')} anomalies")
        return results

    # ------------------------------------------------------------------
    # Feature building for artifact-based anomaly detection
    # ------------------------------------------------------------------

    def _build_artifact_features(self, events: list[dict]):
        """Convert events to numeric vectors for IsolationForest."""
        rows = []
        clean_events = []

        for ev in events:
            try:
                ts = pd.to_datetime(ev.get("timestamp"))
                hour = ts.hour
                dow = ts.weekday()
            except Exception:
                hour = 12
                dow = 0

            size = float(ev.get("size", ev.get("file_size", 0)) or 0)
            entropy = float(ev.get("entropy", 0) or 0)
            path = str(ev.get("path", ev.get("file", "")))
            depth = path.count("\\") + path.count("/")

            rows.append([hour, dow, size, entropy, depth])
            clean_events.append(ev)

        X = np.array(rows, dtype=np.float64) if rows else np.empty((0, 5))
        return X, clean_events

    # ------------------------------------------------------------------
    # IsolationForest
    # ------------------------------------------------------------------

    def _run_isolation_forest(self, X: np.ndarray) -> np.ndarray:
        """Train + predict IsolationForest, return normalised scores 0→1."""
        if len(X) < 5:
            return np.zeros(len(X))

        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            logger.warning("sklearn not available — skipping IsolationForest")
            return np.zeros(len(X))

        model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X)
        raw_scores = model.decision_function(X)

        # Invert and normalise to 0→1 (lower raw = more anomalous)
        inverted = -raw_scores
        mn, mx = inverted.min(), inverted.max()
        if mx - mn < 1e-9:
            return np.full(len(X), 0.5)
        normalised = (inverted - mn) / (mx - mn)
        return np.clip(normalised, 0.0, 1.0)

    # ------------------------------------------------------------------
    # Trained network model
    # ------------------------------------------------------------------

    def _run_network_model(self, events: list[dict]) -> np.ndarray:
        """Run the UNSW-NB15 trained model. Returns probability of attack."""
        n = len(events)
        if self._network_model is None or not self._network_model.is_loaded:
            return np.full(n, 0.5)  # neutral when unavailable

        try:
            # Build DataFrame with expected columns
            df = pd.DataFrame(events)
            results = self._network_model.predict(df)
            return np.array([r["probability"] for r in results])
        except Exception as e:
            logger.debug("Network model prediction skipped: %s", e)
            return np.full(n, 0.5)

    # ------------------------------------------------------------------
    # Rule engine
    # ------------------------------------------------------------------

    def _run_rules(self, events: list[dict]) -> tuple[np.ndarray, list[list[str]]]:
        boosts = []
        all_flags = []
        for ev in events:
            b, f = rule_score(ev)
            boosts.append(b)
            all_flags.append(f)
        return np.array(boosts), all_flags

    # ------------------------------------------------------------------
    # Score fusion
    # ------------------------------------------------------------------

    def _fuse(
        self,
        events: list[dict],
        artifact_scores: np.ndarray,
        network_scores: np.ndarray,
        rule_boosts: np.ndarray,
        rule_flags: list[list[str]],
    ) -> list[HybridResult]:
        """Weighted fusion of all detection signals."""
        results = []
        for i, ev in enumerate(events):
            a_score = float(artifact_scores[i])
            n_score = float(network_scores[i])
            r_boost = float(rule_boosts[i])

            # Weighted combination + rule boost (additive)
            fused = (
                self.artifact_weight * a_score
                + self.network_weight * n_score
                + self.rule_weight * r_boost
            )
            fused = min(fused + r_boost * 0.5, 1.0)  # rules can push score up

            severity = score_to_severity(fused)

            # Build display flags
            flags = list(rule_flags[i])
            if a_score >= 0.70:
                flags.append("artifact_anomaly")
            if n_score >= 0.75:
                flags.append("network_intrusion")
            if not flags and fused >= 0.50:
                flags.append("statistical_anomaly")

            ts = str(ev.get("timestamp", ""))
            event_name = str(ev.get("process", ev.get("event_type", ev.get("event", ""))))
            source = str(ev.get("source", ev.get("artifact_type", "")))

            results.append(HybridResult(
                timestamp=ts,
                event=event_name,
                source=source,
                severity=severity,
                score=round(fused, 4),
                cluster=-1,
                flags=", ".join(flags),
                network_score=round(n_score, 4),
                artifact_score=round(a_score, 4),
                rule_boost=round(r_boost, 4),
                raw=ev,
            ))

        return results
