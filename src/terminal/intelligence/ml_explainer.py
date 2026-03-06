"""
FEPD ML Explainer
===================

Court-explainable AI module that translates ML model outputs
into human-readable forensic explanations.

Makes algorithmic decisions transparent for:
  - Court testimony
  - Report generation
  - Investigator understanding

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ExplanationReport:
    """Structured explanation of ML analysis."""
    file_path: str
    risk_score: float
    severity: str
    summary: str
    reasons: List[str] = field(default_factory=list)
    feature_contributions: Dict[str, float] = field(default_factory=dict)
    recommendation: str = ""
    confidence: float = 0.0


class MLExplainer:
    """
    Translates ML model outputs into court-explainable reports.

    Supports:
      - Feature importance explanations
      - Risk score interpretation
      - Natural language reasoning
      - SHAP-style contribution analysis

    Usage:
        explainer = MLExplainer(ml_bridge=ml_bridge)
        report = explainer.explain("malware.exe", score=0.92, meta={...})
    """

    SEVERITY_MAP = [
        (0.9, "CRITICAL"),
        (0.7, "HIGH"),
        (0.5, "MEDIUM"),
        (0.3, "LOW"),
        (0.0, "CLEAN"),
    ]

    def __init__(self, ml_bridge: Any = None) -> None:
        self.ml_bridge = ml_bridge

    def explain(
        self,
        file_path: str,
        score: Optional[float] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> ExplanationReport:
        """
        Generate a court-explainable report for a file.

        Args:
            file_path: Path to the evidence file.
            score:     ML risk score (0.0 - 1.0).
            meta:      File metadata dict.

        Returns:
            ExplanationReport with structured explanation.
        """
        meta = meta or {}
        score = score if score is not None else float(meta.get("ml_score", 0) or 0)

        severity = self._get_severity(score)
        reasons = self._analyze_reasons(file_path, score, meta)
        features = self._get_feature_contributions(file_path, meta)
        summary = self._generate_summary(file_path, score, severity, reasons)
        recommendation = self._generate_recommendation(score, severity)

        return ExplanationReport(
            file_path=file_path,
            risk_score=score,
            severity=severity,
            summary=summary,
            reasons=reasons,
            feature_contributions=features,
            recommendation=recommendation,
            confidence=min(0.95, score + 0.1) if score > 0 else 0.5,
        )

    def _get_severity(self, score: float) -> str:
        for threshold, label in self.SEVERITY_MAP:
            if score >= threshold:
                return label
        return "UNKNOWN"

    def _analyze_reasons(
        self,
        file_path: str,
        score: float,
        meta: Dict[str, Any],
    ) -> List[str]:
        """Generate human-readable reasons for the risk assessment."""
        reasons = []
        path_lower = file_path.lower()

        # File type analysis
        if any(path_lower.endswith(ext) for ext in (".exe", ".dll", ".scr", ".com")):
            reasons.append("File is a Windows executable type")
        if any(path_lower.endswith(ext) for ext in (".bat", ".cmd", ".ps1", ".vbs", ".js")):
            reasons.append("File is a script that can execute commands")

        # Location analysis
        if "temp" in path_lower or "tmp" in path_lower:
            reasons.append("Located in temporary directory (common malware staging area)")
        if "download" in path_lower:
            reasons.append("Located in downloads folder (external origin)")
        if "appdata" in path_lower:
            reasons.append("Located in AppData (common persistence mechanism)")
        if "startup" in path_lower:
            reasons.append("Located in startup folder (auto-execution on boot)")
        if "system32" in path_lower:
            reasons.append("Located in system directory (potential DLL hijacking)")

        # Size anomalies
        size = meta.get("size", 0)
        if size and size < 500:
            reasons.append(f"File is unusually small ({size} bytes) — possible dropper")
        if size and size > 100 * 1024 * 1024:
            reasons.append(f"File is very large ({size / 1024 / 1024:.1f} MB) — potential data staging")

        # Score-based
        if score >= 0.9:
            reasons.append("Anomaly score exceeds critical threshold (≥ 0.90)")
        elif score >= 0.7:
            reasons.append("Anomaly score exceeds high alert threshold (≥ 0.70)")

        # ML bridge analysis
        if self.ml_bridge and hasattr(self.ml_bridge, "get_feature_importances"):
            try:
                importances = self.ml_bridge.get_feature_importances(file_path)
                for feature, importance in sorted(importances.items(), key=lambda x: -x[1])[:3]:
                    reasons.append(f"ML feature '{feature}' contributed {importance:.2f} to score")
            except Exception:
                pass

        if not reasons:
            reasons.append("No specific anomaly indicators detected")

        return reasons

    def _get_feature_contributions(
        self,
        file_path: str,
        meta: Dict[str, Any],
    ) -> Dict[str, float]:
        """Get feature contribution values (SHAP-like)."""
        contributions = {}

        # If ML bridge supports SHAP values
        if self.ml_bridge and hasattr(self.ml_bridge, "shap_values"):
            try:
                return self.ml_bridge.shap_values(file_path)
            except Exception:
                pass

        # Fallback: heuristic contributions
        path_lower = file_path.lower()
        size = meta.get("size", 0)

        if any(path_lower.endswith(ext) for ext in (".exe", ".dll")):
            contributions["file_type"] = 0.3
        if "temp" in path_lower or "download" in path_lower:
            contributions["location"] = 0.25
        if size and (size < 500 or size > 50_000_000):
            contributions["size_anomaly"] = 0.2
        if meta.get("ml_score"):
            contributions["ml_model"] = float(meta["ml_score"])

        return contributions

    def _generate_summary(
        self,
        file_path: str,
        score: float,
        severity: str,
        reasons: List[str],
    ) -> str:
        """Generate a natural language summary."""
        import os
        filename = os.path.basename(file_path)

        if score >= 0.9:
            return (
                f"'{filename}' shows strongly anomalous characteristics "
                f"with a risk score of {score:.2f} ({severity}). "
                f"Immediate investigation recommended."
            )
        elif score >= 0.7:
            return (
                f"'{filename}' exhibits multiple suspicious indicators "
                f"with a risk score of {score:.2f} ({severity}). "
                f"Further analysis recommended."
            )
        elif score >= 0.4:
            return (
                f"'{filename}' has some unusual properties "
                f"with a risk score of {score:.2f} ({severity}). "
                f"Review suggested."
            )
        else:
            return (
                f"'{filename}' appears within normal parameters "
                f"with a risk score of {score:.2f} ({severity})."
            )

    def _generate_recommendation(self, score: float, severity: str) -> str:
        """Generate an actionable recommendation."""
        if score >= 0.9:
            return "QUARANTINE: Isolate file and investigate thoroughly. Check for related artifacts."
        if score >= 0.7:
            return "INVESTIGATE: Examine file relationships, timeline, and network connections."
        if score >= 0.4:
            return "REVIEW: Check file context and owner activity."
        return "MONITOR: No immediate action required."
