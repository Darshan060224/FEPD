"""
FEPD Isolation Forest Model
=============================

Case-adaptive anomaly detection using scikit-learn's IsolationForest.

Why Isolation Forest?
  • Unsupervised — no labelled data needed
  • Works well on unknown threats
  • Handles high-dimensional forensic feature spaces
  • Fast training on up to 100k events
  • Court-defensible: well-understood algorithm

Pipeline:
    Feature vectors
        → fit() — learns normal behaviour baseline
        → predict() → anomaly labels (-1 = anomaly, 1 = normal)
        → decision_function() → anomaly scores (lower = more anomalous)
        → score normalisation → 0.0 (normal) … 1.0 (critical)
        → severity mapping

Supports:
  • Global model (all events)
  • Per-user model (separate baseline per user)
  • Warm-start (continue training with new case data)
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False
    logger.warning("scikit-learn not installed — IsolationForest unavailable")


# ============================================================================
# SEVERITY MAPPING
# ============================================================================

def score_to_severity(score: float) -> str:
    """Convert normalised anomaly score to severity label."""
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.45:
        return "MEDIUM"
    return "LOW"


def normalise_scores(raw_scores: np.ndarray) -> np.ndarray:
    """
    Convert IsolationForest decision_function output (negative = anomalous)
    to a 0-1 range where 1 = most anomalous.
    """
    if len(raw_scores) == 0:
        return raw_scores
    min_s = raw_scores.min()
    max_s = raw_scores.max()
    if max_s == min_s:
        return np.zeros_like(raw_scores)
    # Invert: raw IF scores are negative for anomalies
    normalised = (max_s - raw_scores) / (max_s - min_s)
    return np.clip(normalised, 0.0, 1.0)


# ============================================================================
# ISOLATION FOREST MODEL
# ============================================================================

class IsolationForestModel:
    """
    Wrapper around scikit-learn IsolationForest with:
      • StandardScaler preprocessing
      • Score normalisation (0–1)
      • Severity mapping
      • Model persistence (save/load)

    Usage:
        model = IsolationForestModel()
        model.fit(X_train)
        scores, labels, severities = model.predict(X_test)
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        max_samples: str | int = "auto",
        random_state: int = 42,
    ):
        if not _HAS_SKLEARN:
            raise ImportError("scikit-learn is required for IsolationForestModel")

        self._contamination = contamination
        self._n_estimators = n_estimators
        self._max_samples = max_samples
        self._random_state = random_state

        self._scaler = StandardScaler()
        self._model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples=max_samples,
            random_state=random_state,
            warm_start=False,
            n_jobs=-1,
        )
        self._is_fitted = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(self, X: np.ndarray) -> "IsolationForestModel":
        """
        Train on feature matrix X.

        Args:
            X: shape (n_samples, n_features)

        Returns:
            self
        """
        if X.shape[0] < 10:
            logger.warning("Very few samples (%d) — model may be unreliable", X.shape[0])

        X_scaled = self._scaler.fit_transform(X)
        self._model.fit(X_scaled)
        self._is_fitted = True
        logger.info(
            "IsolationForest trained: %d samples, %d features, contamination=%.2f",
            X.shape[0], X.shape[1], self._contamination,
        )
        return self

    def continue_training(self, X: np.ndarray) -> "IsolationForestModel":
        """
        Warm-start: retrain with additional data.
        Creates a new model with warm_start=True and more estimators.
        """
        if not self._is_fitted:
            return self.fit(X)

        X_scaled = self._scaler.transform(X)
        # Rebuild with warm start
        new_model = IsolationForest(
            contamination=self._contamination,
            n_estimators=self._n_estimators + 50,
            max_samples=self._max_samples,
            random_state=self._random_state,
            warm_start=True,
            n_jobs=-1,
        )
        new_model.estimators_ = self._model.estimators_[:]
        new_model.n_estimators = len(new_model.estimators_) + 50
        new_model.fit(X_scaled)
        self._model = new_model
        self._n_estimators = new_model.n_estimators
        logger.info("Model updated with %d new samples", X.shape[0])
        return self

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(
        self, X: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Predict anomalies.

        Args:
            X: shape (n_samples, n_features)

        Returns:
            (anomaly_scores, labels, severities)
            - anomaly_scores: float array 0–1 (1 = most anomalous)
            - labels: int array, -1 = anomaly, 1 = normal
            - severities: list of "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"
        """
        if not self._is_fitted:
            raise RuntimeError("Model not fitted — call fit() first")

        X_scaled = self._scaler.transform(X)
        labels = self._model.predict(X_scaled)
        raw_scores = self._model.decision_function(X_scaled)
        scores = normalise_scores(raw_scores)
        severities = [score_to_severity(s) for s in scores]

        n_anomalies = int((labels == -1).sum())
        logger.info(
            "Prediction: %d samples, %d anomalies (%.1f%%)",
            len(labels), n_anomalies, 100 * n_anomalies / max(len(labels), 1),
        )
        return scores, labels, severities

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    # ------------------------------------------------------------------
    # Feature importance (approximate)
    # ------------------------------------------------------------------

    def feature_importance(self, feature_names: List[str]) -> Dict[str, float]:
        """
        Approximate feature importance based on average path depth
        contribution of each feature.
        """
        if not self._is_fitted:
            return {}

        importances = np.zeros(len(feature_names))
        for tree in self._model.estimators_:
            fi = tree.feature_importances_
            if len(fi) == len(feature_names):
                importances += fi

        importances /= len(self._model.estimators_)
        return dict(zip(feature_names, importances.tolist()))

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path):
        """Save model + scaler to disk."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "model": self._model,
            "scaler": self._scaler,
            "contamination": self._contamination,
            "n_estimators": self._n_estimators,
            "is_fitted": self._is_fitted,
        }
        with open(path, "wb") as f:
            pickle.dump(data, f)
        logger.info("Model saved to %s", path)

    @classmethod
    def load(cls, path: str | Path) -> "IsolationForestModel":
        """Load a previously saved model."""
        with open(path, "rb") as f:
            data = pickle.load(f)
        obj = cls(
            contamination=data["contamination"],
            n_estimators=data["n_estimators"],
        )
        obj._model = data["model"]
        obj._scaler = data["scaler"]
        obj._is_fitted = data["is_fitted"]
        logger.info("Model loaded from %s", path)
        return obj
