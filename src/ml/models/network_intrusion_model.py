"""
FEPD - Network Intrusion Detection Model
==========================================

Loads a trained UNSW-NB15 ensemble model and provides
predict / score / severity APIs for the FEPD ML tab.

Trained by: scripts/ml/train_unsw_nb15.py
Model dir:  models/network_intrusion/
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

try:
    import joblib
    _HAS_JOBLIB = True
except ImportError:
    _HAS_JOBLIB = False

# Severity thresholds (on attack probability 0-1)
_SEVERITY_THRESHOLDS = [
    (0.90, "CRITICAL"),
    (0.75, "HIGH"),
    (0.50, "MEDIUM"),
]


def probability_to_severity(prob: float) -> str:
    """Map attack probability → severity label."""
    for threshold, label in _SEVERITY_THRESHOLDS:
        if prob >= threshold:
            return label
    return "LOW"


class NetworkIntrusionModel:
    """
    Wrapper around the trained UNSW-NB15 network intrusion model.

    Usage::

        model = NetworkIntrusionModel()
        model.load()
        results = model.predict(features_df)
    """

    DEFAULT_MODEL_DIR = Path(__file__).resolve().parent.parent.parent.parent / "models" / "network_intrusion"

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = Path(model_dir) if model_dir else self.DEFAULT_MODEL_DIR
        self.model = None
        self.scaler = None
        self.encoders: dict = {}
        self.metadata: dict = {}
        self.feature_names: list[str] = []
        self._loaded = False

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self) -> bool:
        """Load model, scaler, encoders and metadata from disk."""
        if not _HAS_JOBLIB:
            logger.error("joblib not installed — cannot load model")
            return False

        model_path = self.model_dir / "model.pkl"
        if not model_path.exists():
            logger.warning("Model not found at %s — run training first", model_path)
            return False

        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(self.model_dir / "scaler.pkl")
            self.encoders = joblib.load(self.model_dir / "encoders.pkl")

            meta_path = self.model_dir / "metadata.json"
            if meta_path.exists():
                with open(meta_path) as f:
                    self.metadata = json.load(f)
                self.feature_names = self.metadata.get("features", [])

            self._loaded = True
            logger.info("Loaded network intrusion model from %s (acc=%.4f)",
                        self.model_dir,
                        self.metadata.get("metrics", {}).get("accuracy", 0))
            return True
        except Exception as e:
            logger.error("Failed to load model: %s", e)
            return False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Run intrusion detection on a DataFrame of network features.

        Args:
            df: DataFrame with columns matching the training features
                (including raw categorical columns 'proto', 'service', 'state').

        Returns:
            List of dicts with keys:
                prediction (0/1), probability, severity, flags
        """
        if not self._loaded:
            raise RuntimeError("Model not loaded — call load() first")

        # Prepare features
        X = self._prepare_features(df)

        # Predict
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)[:, 1]  # P(attack)

        results = []
        for i in range(len(predictions)):
            prob = float(probabilities[i])
            severity = probability_to_severity(prob)
            flags = self._generate_flags(prob, severity)

            results.append({
                "prediction": int(predictions[i]),
                "probability": round(prob, 4),
                "severity": severity,
                "label": "Attack" if predictions[i] == 1 else "Normal",
                "flags": flags,
            })

        return results

    def predict_single(self, features: dict) -> Dict[str, Any]:
        """Predict for a single event dict."""
        df = pd.DataFrame([features])
        return self.predict(df)[0]

    def get_model_info(self) -> Dict[str, Any]:
        """Return model metadata for display in UI."""
        return {
            "name": self.metadata.get("model_name", "Unknown"),
            "version": self.metadata.get("version", "?"),
            "dataset": self.metadata.get("dataset", "?"),
            "trained_date": self.metadata.get("trained_date", "?"),
            "n_features": self.metadata.get("n_features", 0),
            "metrics": self.metadata.get("metrics", {}),
            "top_features": self.metadata.get("feature_importance_top10", {}),
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _prepare_features(self, df: pd.DataFrame) -> np.ndarray:
        """Encode categoricals, align columns, scale."""
        df = df.copy()

        # Drop columns not needed
        for col in ("id", "attack_cat", "label"):
            if col in df.columns:
                df = df.drop(columns=[col])

        # Encode categoricals
        cat_cols = self.metadata.get("categorical_columns", ["proto", "service", "state"])
        for col in cat_cols:
            if col in df.columns and col in self.encoders:
                enc = self.encoders[col]
                known = set(enc.classes_)
                # Replace unseen values with the most common class
                df[col] = df[col].astype(str).apply(
                    lambda v: v if v in known else enc.classes_[0]
                )
                df[col] = enc.transform(df[col])

        # Align columns to training feature order
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0
        df = df[self.feature_names]

        # Fill NaN
        df = df.fillna(0)

        # Scale (only if scaler was used during training)
        if self.scaler is not None and self.metadata.get("scaled", False):
            X = self.scaler.transform(df)
        else:
            X = df.values
        return X

    @staticmethod
    def _generate_flags(prob: float, severity: str) -> List[str]:
        """Generate human-readable flags for a prediction."""
        flags = []
        if prob >= 0.90:
            flags.append("HIGH_CONFIDENCE_ATTACK")
        if prob >= 0.75:
            flags.append("NETWORK_ANOMALY")
        if severity == "CRITICAL":
            flags.append("IMMEDIATE_REVIEW")
        return flags
