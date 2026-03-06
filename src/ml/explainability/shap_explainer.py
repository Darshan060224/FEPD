"""
FEPD Anomaly Explainability
=============================

Generates human-readable explanations for why each event was flagged as
anomalous.  Two approaches are implemented:

1. **Feature-contribution analysis** (always available)
   Compares each event's feature values against the training-set baseline
   to identify which features deviate most.

2. **SHAP approximation** (when SHAP library is installed)
   Uses TreeExplainer on the Isolation Forest for proper Shapley values.

Both produce natural-language *flags* such as:
  • "rare process execution"
  • "off-hours activity"
  • "unusual file extension (.ps1)"
  • "account used for first time in window"
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

try:
    import shap as _shap
    _HAS_SHAP = True
except ImportError:
    _HAS_SHAP = False


# ============================================================================
# Feature-to-language mapping
# ============================================================================

_FEATURE_EXPLANATIONS: Dict[str, Tuple[str, str]] = {
    # feature_name →  (high_description, low_description)
    "hour_of_day":       ("activity at unusual hour", ""),
    "is_off_hours":      ("off-hours activity", ""),
    "day_of_week":       ("unusual day of week", ""),
    "is_weekend":        ("weekend activity", ""),
    "process_frequency": ("", "rare process execution"),
    "process_rarity":    ("rare process execution", ""),
    "user_event_count":  ("low-activity user account", "very active user account"),
    "category_frequency":("", "rare event category"),
    "path_depth":        ("unusually deep file path", ""),
    "file_ext_risk":     ("high-risk file extension", ""),
    "execution_gap":     ("large time gap before event", ""),
    "severity_numeric":  ("high severity event", ""),
}

# Thresholds for "high" and "low" z-score values
_Z_HIGH = 1.5
_Z_LOW = -1.5


# ============================================================================
# Feature Contribution Explainer
# ============================================================================

class FeatureContributionExplainer:
    """
    Compare each event's features against training-set statistics
    to identify the biggest deviators.
    """

    def __init__(self):
        self._mean: Optional[np.ndarray] = None
        self._std: Optional[np.ndarray] = None
        self._feature_names: List[str] = []

    def fit(self, X_train: np.ndarray, feature_names: List[str]):
        """Learn baseline statistics from training data."""
        self._mean = np.nanmean(X_train, axis=0)
        self._std = np.nanstd(X_train, axis=0)
        # Avoid division by zero
        self._std[self._std < 1e-9] = 1.0
        self._feature_names = list(feature_names)

    def explain_event(
        self,
        x: np.ndarray,
        top_n: int = 5,
    ) -> List[str]:
        """
        Generate flags for a single feature vector.

        Returns:
            list of human-readable flag strings.
        """
        if self._mean is None:
            return ["statistical anomaly detected"]

        z = (x - self._mean) / self._std
        flags: List[str] = []

        # Rank features by |z-score|
        ranked = sorted(
            enumerate(z), key=lambda p: abs(p[1]), reverse=True
        )

        for idx, z_val in ranked[:top_n]:
            fname = self._feature_names[idx] if idx < len(self._feature_names) else f"feature_{idx}"
            high_desc, low_desc = _FEATURE_EXPLANATIONS.get(fname, ("", ""))

            if z_val > _Z_HIGH and high_desc:
                flags.append(high_desc)
            elif z_val < _Z_LOW and low_desc:
                flags.append(low_desc)
            elif abs(z_val) > _Z_HIGH:
                flags.append(f"unusual {fname.replace('_', ' ')}")

        return flags if flags else ["statistical anomaly detected"]

    def explain_batch(
        self,
        X: np.ndarray,
        top_n: int = 5,
    ) -> List[List[str]]:
        """Explain multiple events at once."""
        return [self.explain_event(X[i], top_n) for i in range(len(X))]


# ============================================================================
# SHAP Explainer (optional)
# ============================================================================

class ShapExplainer:
    """
    Uses SHAP TreeExplainer for Isolation Forest when the library is
    available.  Falls back to FeatureContributionExplainer otherwise.
    """

    def __init__(self):
        self._explainer = None
        self._feature_names: List[str] = []
        self._fallback = FeatureContributionExplainer()

    @property
    def has_shap(self) -> bool:
        return _HAS_SHAP

    def fit(self, model, X_train: np.ndarray, feature_names: List[str]):
        """
        Fit the explainer.

        Args:
            model: a fitted sklearn IsolationForest, or an IsolationForestModel
                   (we'll extract .model from it).
            X_train: the training feature matrix.
            feature_names: list of feature name strings.
        """
        self._feature_names = list(feature_names)
        self._fallback.fit(X_train, feature_names)

        if not _HAS_SHAP:
            logger.info("SHAP not installed — using feature-contribution fallback")
            return

        try:
            sklearn_model = getattr(model, "model", model)
            self._explainer = _shap.TreeExplainer(sklearn_model)
            logger.info("SHAP TreeExplainer initialised for IsolationForest")
        except Exception as exc:
            logger.warning("SHAP init failed (%s) — using fallback", exc)
            self._explainer = None

    def explain_event(self, x: np.ndarray, top_n: int = 5) -> List[str]:
        """Generate flags for one event."""
        if self._explainer is None:
            return self._fallback.explain_event(x, top_n)

        try:
            shap_values = self._explainer.shap_values(x.reshape(1, -1))[0]
            return self._shap_to_flags(shap_values, x, top_n)
        except Exception:
            return self._fallback.explain_event(x, top_n)

    def explain_batch(self, X: np.ndarray, top_n: int = 5) -> List[List[str]]:
        """Generate flags for multiple events."""
        if self._explainer is None:
            return self._fallback.explain_batch(X, top_n)

        try:
            shap_values = self._explainer.shap_values(X)
            return [self._shap_to_flags(shap_values[i], X[i], top_n) for i in range(len(X))]
        except Exception:
            return self._fallback.explain_batch(X, top_n)

    def _shap_to_flags(
        self,
        shap_vals: np.ndarray,
        x: np.ndarray,
        top_n: int,
    ) -> List[str]:
        """Convert SHAP values to human-readable flags."""
        flags: List[str] = []
        ranked = sorted(
            enumerate(shap_vals), key=lambda p: abs(p[1]), reverse=True
        )

        for idx, sv in ranked[:top_n]:
            fname = self._feature_names[idx] if idx < len(self._feature_names) else f"feature_{idx}"
            high_desc, low_desc = _FEATURE_EXPLANATIONS.get(fname, ("", ""))

            # Positive SHAP = pushes towards anomaly
            if sv > 0 and high_desc:
                flags.append(high_desc)
            elif sv > 0 and low_desc:
                flags.append(low_desc)
            elif abs(sv) > 0.01:
                direction = "high" if x[idx] > 0 else "low"
                flags.append(f"unusual {fname.replace('_', ' ')} ({direction})")

        return flags if flags else ["statistical anomaly detected"]

    def get_importance(self, X: np.ndarray) -> Dict[str, float]:
        """
        Get mean absolute SHAP value per feature (global importance).
        """
        if self._explainer is None:
            return {}
        try:
            shap_values = self._explainer.shap_values(X[:min(500, len(X))])
            mean_abs = np.abs(shap_values).mean(axis=0)
            return dict(zip(self._feature_names, mean_abs))
        except Exception:
            return {}
