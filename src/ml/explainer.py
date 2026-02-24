"""
FEPD - Forensic Evidence Parser Dashboard
ML Explainability Module

Provides transparent explanations for machine learning detections, anomalies, and alerts.

Features:
    - Natural language explanations for ML predictions
    - SHAP (SHapley Additive exPlanations) integration
    - Feature importance analysis
    - Evidence-based justifications
    - Confidence scoring
    - Rule explanation templates
    - Interactive explanation visualization
    - Counterfactual explanations

Purpose:
    Transform "black box" ML detections into transparent, understandable alerts
    that forensic analysts can trust and act upon.

Supported Explanation Types:
    - Anomaly detections (why flagged as unusual)
    - UEBA alerts (behavioral deviations)
    - Threat intelligence matches
    - Risk scores

Architecture:
    - Explainer: Main interface for generating explanations
    - SHAPExplainer: Feature importance using SHAP
    - RuleExplainer: Template-based rule explanations
    - EvidenceCollector: Gather supporting evidence
    - ExplanationFormatter: Natural language generation

Usage:
    from src.ml.explainer import Explainer
    
    # Initialize
    explainer = Explainer()
    
    # Explain anomaly
    explanation = explainer.explain_anomaly(event, model, features)
    
    # Get natural language description
    print(explanation.to_natural_language())
    # "This event was flagged as CRITICAL because:
    #  1. File access occurred at unusual time (3:47 AM)
    #  2. User accessed sensitive files not in their normal pattern
    #  3. Data volume transferred (125 MB) is 10x higher than typical"

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
import json
import pandas as pd

# ML libraries
import numpy as np
from sklearn.base import BaseEstimator

# SHAP for explainability (required for court-defensible explanations)
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    shap = None

# LIME for local interpretability (optional alternative)
try:
    import lime
    import lime.lime_tabular
    LIME_AVAILABLE = True
except ImportError:
    LIME_AVAILABLE = False
    lime = None


@dataclass
class Evidence:
    """
    Supporting evidence for an explanation.
    
    Attributes:
        factor: Factor name (e.g., "unusual_time", "high_volume")
        value: Actual value
        baseline: Expected/normal value
        deviation: How much it deviates (as percentage or score)
        importance: Contribution to decision (0-1)
        description: Human-readable description
    """
    factor: str
    value: Any
    baseline: Any
    deviation: float
    importance: float
    description: str


@dataclass
class Explanation:
    """
    Complete explanation for an ML detection.
    
    Attributes:
        event_id: ID of explained event
        detection_type: Type of detection (anomaly, ueba, threat_intel)
        severity: Detection severity
        confidence: Model confidence (0-1)
        primary_reason: Main reason for detection
        evidence: List of supporting evidence
        counterfactual: What would make it not flagged
        recommendations: Suggested analyst actions
        metadata: Additional context
    """
    event_id: str
    detection_type: str
    severity: str
    confidence: float
    primary_reason: str
    evidence: List[Evidence] = field(default_factory=list)
    counterfactual: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_natural_language(self, verbose: bool = False) -> str:
        """
        Generate natural language explanation.
        
        Args:
            verbose: Include detailed evidence
        
        Returns:
            Human-readable explanation string
        """
        lines = []
        
        # Header
        lines.append(f"🔍 {self.detection_type.upper()} Detection - {self.severity}")
        lines.append(f"Confidence: {self.confidence*100:.1f}%")
        lines.append("")
        
        # Primary reason
        lines.append(f"📌 {self.primary_reason}")
        lines.append("")
        
        # Evidence
        if self.evidence:
            lines.append("Evidence:")
            for i, ev in enumerate(sorted(self.evidence, key=lambda x: x.importance, reverse=True), 1):
                importance_bar = "█" * int(ev.importance * 10)
                lines.append(f"  {i}. {ev.description}")
                if verbose:
                    lines.append(f"     Value: {ev.value} (baseline: {ev.baseline}, deviation: {ev.deviation:+.1%})")
                    lines.append(f"     Importance: {importance_bar} {ev.importance:.2f}")
        
        # Counterfactual
        if self.counterfactual:
            lines.append("")
            lines.append(f"💡 Counterfactual: {self.counterfactual}")
        
        # Recommendations
        if self.recommendations:
            lines.append("")
            lines.append("Recommended Actions:")
            for i, rec in enumerate(self.recommendations, 1):
                lines.append(f"  {i}. {rec}")
        
        return "\n".join(lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'event_id': self.event_id,
            'detection_type': self.detection_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'primary_reason': self.primary_reason,
            'evidence': [
                {
                    'factor': e.factor,
                    'value': str(e.value),
                    'baseline': str(e.baseline),
                    'deviation': e.deviation,
                    'importance': e.importance,
                    'description': e.description
                }
                for e in self.evidence
            ],
            'counterfactual': self.counterfactual,
            'recommendations': self.recommendations,
            'metadata': self.metadata
        }


class SHAPExplainer:
    """
    SHAP-based feature importance explainer.
    
    Uses SHAP (SHapley Additive exPlanations) to compute feature contributions
    to model predictions.
    """
    
    def __init__(
        self,
        model: BaseEstimator,
        background_data: Optional[np.ndarray] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize SHAP explainer.
        
        Args:
            model: Trained sklearn model
            background_data: Background dataset for SHAP (optional)
            logger: Optional logger
        """
        self.logger = logger or logging.getLogger(__name__)
        self.model = model
        
        if not SHAP_AVAILABLE:
            self.logger.warning("SHAP not available. Install with: pip install shap")
            self.explainer = None
            return
        
        # Initialize SHAP explainer
        try:
            if hasattr(model, 'predict_proba'):
                # For classifiers
                self.explainer = shap.TreeExplainer(model) if hasattr(model, 'tree_') else shap.KernelExplainer(
                    model.predict_proba,
                    background_data if background_data is not None else shap.sample(background_data, 100)
                )
            else:
                # For regressors/anomaly detectors
                self.explainer = shap.TreeExplainer(model) if hasattr(model, 'tree_') else shap.Explainer(model)
            
            self.logger.info("SHAP explainer initialized")
        
        except Exception as e:
            self.logger.error(f"Failed to initialize SHAP: {e}")
            self.explainer = None
    
    def explain(
        self,
        features: np.ndarray,
        feature_names: List[str]
    ) -> List[Tuple[str, float]]:
        """
        Compute SHAP values for features.
        
        Args:
            features: Feature vector
            feature_names: Names of features
        
        Returns:
            List of (feature_name, importance) tuples, sorted by importance
        """
        if self.explainer is None:
            return []
        
        try:
            # Compute SHAP values
            shap_values = self.explainer.shap_values(features)
            
            # Handle multi-dimensional output
            if isinstance(shap_values, list):
                shap_values = shap_values[0]
            
            # Flatten if needed
            if len(shap_values.shape) > 1:
                shap_values = shap_values[0]
            
            # Pair with feature names and sort by absolute importance
            importance = list(zip(feature_names, np.abs(shap_values)))
            importance.sort(key=lambda x: x[1], reverse=True)
            
            return importance
        
        except Exception as e:
            self.logger.error(f"SHAP explanation failed: {e}")
            return []


class RuleExplainer:
    """
    Template-based rule explanations.
    
    Provides human-readable explanations for detection rules.
    """
    
    # Explanation templates
    TEMPLATES = {
        'unusual_time': "Access occurred at unusual time ({value}) outside normal hours ({baseline})",
        'unusual_volume': "Data volume ({value}) is {deviation:.1f}x higher than typical ({baseline})",
        'sensitive_file': "Accessed sensitive file: {value}",
        'privilege_escalation': "Privilege escalation detected: {value}",
        'failed_auth': "Multiple failed authentication attempts: {value} failures in {timeframe}",
        'new_location': "Access from new geographic location: {value}",
        'rare_activity': "Rare activity for this user (occurs {frequency}% of time)",
        'threat_match': "Matched threat intelligence: {value} (source: {source})",
        'anomaly_score': "Anomaly score ({value}) exceeds threshold ({baseline})"
    }
    
    def explain_rule(
        self,
        rule_type: str,
        context: Dict[str, Any]
    ) -> str:
        """
        Generate explanation for a rule match.
        
        Args:
            rule_type: Type of rule (e.g., 'unusual_time')
            context: Context variables for template
        
        Returns:
            Human-readable explanation
        """
        template = self.TEMPLATES.get(rule_type, "Detection rule matched: {rule_type}")
        
        try:
            return template.format(rule_type=rule_type, **context)
        except KeyError:
            return template


class EvidenceCollector:
    """
    Collects supporting evidence for explanations.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
    
    def collect_anomaly_evidence(
        self,
        event: Dict[str, Any],
        features: Dict[str, float],
        baselines: Dict[str, float],
        importances: List[Tuple[str, float]]
    ) -> List[Evidence]:
        """
        Collect evidence for anomaly detection.
        
        Args:
            event: Event data
            features: Feature values
            baselines: Baseline values
            importances: Feature importances from SHAP
        
        Returns:
            List of Evidence objects
        """
        evidence = []
        
        # Map importances to dict
        importance_dict = dict(importances) if importances else {}
        
        for feature_name, value in features.items():
            baseline = baselines.get(feature_name, 0)
            
            # Calculate deviation
            if baseline != 0:
                deviation = (value - baseline) / baseline
            else:
                deviation = 1.0 if value != 0 else 0.0
            
            # Get importance
            importance = importance_dict.get(feature_name, 0.5)
            
            # Generate description using rule explainer
            description = self._generate_description(feature_name, value, baseline, deviation)
            
            evidence.append(Evidence(
                factor=feature_name,
                value=value,
                baseline=baseline,
                deviation=deviation,
                importance=importance,
                description=description
            ))
        
        return evidence
    
    def _generate_description(
        self,
        feature: str,
        value: Any,
        baseline: Any,
        deviation: float
    ) -> str:
        """Generate human-readable description for evidence."""
        # Map feature names to explanations
        descriptions = {
            'hour': f"Access at hour {value} (typical: {baseline})",
            'file_size': f"File size {value} bytes ({abs(deviation)*100:.0f}% {'above' if deviation > 0 else 'below'} normal)",
            'process_count': f"{value} processes ({abs(deviation)*100:.0f}% {'more' if deviation > 0 else 'fewer'} than usual)",
            'network_bytes': f"Network transfer {value} bytes ({abs(deviation)*100:.0f}% {'above' if deviation > 0 else 'below'} typical)",
            'auth_failures': f"{value} failed authentications (baseline: {baseline})"
        }
        
        return descriptions.get(feature, f"{feature}: {value} (baseline: {baseline})")


class Explainer:
    """
    Main explainability interface for FEPD.
    
    Provides unified API for explaining all types of ML detections.
    """
    
    def __init__(
        self,
        models: Optional[Dict[str, BaseEstimator]] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize explainer.
        
        Args:
            models: Dictionary of trained models (optional)
            logger: Optional logger
        """
        self.logger = logger or logging.getLogger(__name__)
        self.models = models or {}
        
        # Initialize sub-explainers
        self.shap_explainers: Dict[str, SHAPExplainer] = {}
        self.rule_explainer = RuleExplainer()
        self.evidence_collector = EvidenceCollector(logger=logger)
        
        self.logger.info("Explainer initialized")
    
    def register_model(
        self,
        model_name: str,
        model: BaseEstimator,
        background_data: Optional[np.ndarray] = None
    ) -> None:
        """
        Register a model for explanation.
        
        Args:
            model_name: Name identifier for model
            model: Trained model
            background_data: Optional background data for SHAP
        """
        self.models[model_name] = model
        
        # Create SHAP explainer
        if SHAP_AVAILABLE:
            self.shap_explainers[model_name] = SHAPExplainer(
                model=model,
                background_data=background_data,
                logger=self.logger
            )
        
        self.logger.info(f"Registered model: {model_name}")
    
    def explain_anomaly(
        self,
        event: Dict[str, Any],
        model_name: str = 'anomaly_detector',
        features: Optional[Dict[str, float]] = None,
        feature_names: Optional[List[str]] = None,
        baselines: Optional[Dict[str, float]] = None
    ) -> Explanation:
        """
        Explain why event was flagged as anomaly.
        
        Args:
            event: Event data
            model_name: Name of anomaly detection model
            features: Feature values (optional)
            feature_names: Feature names (optional)
            baselines: Baseline values (optional)
        
        Returns:
            Explanation object
        """
        # Get anomaly score
        anomaly_score = event.get('anomaly_score', 0.0)
        confidence = min(abs(anomaly_score), 1.0)
        
        # Determine severity
        if anomaly_score > 0.8:
            severity = 'CRITICAL'
        elif anomaly_score > 0.6:
            severity = 'HIGH'
        elif anomaly_score > 0.4:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        # Compute feature importances
        importances = []
        if model_name in self.shap_explainers and features and feature_names:
            feature_array = np.array([features.get(name, 0) for name in feature_names]).reshape(1, -1)
            importances = self.shap_explainers[model_name].explain(feature_array, feature_names)
        
        # Collect evidence
        evidence = []
        if features and baselines:
            evidence = self.evidence_collector.collect_anomaly_evidence(
                event=event,
                features=features,
                baselines=baselines,
                importances=importances
            )
        
        # Primary reason (top evidence)
        if evidence:
            primary_reason = f"Unusual behavior detected: {evidence[0].description}"
        else:
            primary_reason = f"Event exhibits anomalous patterns (score: {anomaly_score:.2f})"
        
        # Generate counterfactual
        counterfactual = self._generate_counterfactual(evidence[:3]) if evidence else None
        
        # Recommendations
        recommendations = self._generate_recommendations(event, severity, evidence)
        
        return Explanation(
            event_id=event.get('id', 'unknown'),
            detection_type='anomaly',
            severity=severity,
            confidence=confidence,
            primary_reason=primary_reason,
            evidence=evidence,
            counterfactual=counterfactual,
            recommendations=recommendations,
            metadata={'anomaly_score': anomaly_score}
        )
    
    def explain_ueba_alert(
        self,
        event: Dict[str, Any],
        user_profile: Dict[str, Any],
        deviations: List[Dict[str, Any]]
    ) -> Explanation:
        """
        Explain UEBA behavioral anomaly.
        
        Args:
            event: Event data
            user_profile: User's baseline profile
            deviations: List of detected deviations
        
        Returns:
            Explanation object
        """
        # Calculate confidence from deviations
        confidence = min(len(deviations) * 0.3, 1.0)
        
        # Determine severity
        severity_scores = {'high': 3, 'medium': 2, 'low': 1}
        max_severity = max([severity_scores.get(d.get('severity', 'low'), 1) for d in deviations])
        
        if max_severity >= 3:
            severity = 'HIGH'
        elif max_severity >= 2:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        # Convert deviations to evidence
        evidence = []
        for dev in deviations[:5]:  # Top 5
            evidence.append(Evidence(
                factor=dev.get('type', 'unknown'),
                value=dev.get('current_value', 'N/A'),
                baseline=dev.get('baseline_value', 'N/A'),
                deviation=dev.get('deviation_score', 0.0),
                importance=dev.get('importance', 0.5),
                description=dev.get('description', 'Behavioral deviation detected')
            ))
        
        # Primary reason
        user = event.get('user', 'Unknown user')
        primary_reason = f"User '{user}' exhibited {len(deviations)} behavioral deviations from baseline profile"
        
        # Recommendations
        recommendations = [
            f"Review user '{user}' recent activity for suspicious patterns",
            "Verify user identity through secondary authentication",
            "Check for compromised credentials or account takeover",
            "Investigate if legitimate business need for unusual behavior"
        ]
        
        return Explanation(
            event_id=event.get('id', 'unknown'),
            detection_type='ueba',
            severity=severity,
            confidence=confidence,
            primary_reason=primary_reason,
            evidence=evidence,
            counterfactual="Activity would not be flagged if it matched user's historical patterns",
            recommendations=recommendations,
            metadata={'user': user, 'profile_age_days': user_profile.get('profile_age_days', 0)}
        )
    
    def explain_threat_match(
        self,
        event: Dict[str, Any],
        threat_matches: List[Dict[str, Any]]
    ) -> Explanation:
        """
        Explain threat intelligence match.
        
        Args:
            event: Event data
            threat_matches: List of matched threat indicators
        
        Returns:
            Explanation object
        """
        # High confidence for threat matches
        confidence = 0.95
        
        # Severity from threat data
        severities = [m.get('severity', 'MEDIUM') for m in threat_matches]
        if 'CRITICAL' in severities:
            severity = 'CRITICAL'
        elif 'HIGH' in severities:
            severity = 'HIGH'
        else:
            severity = 'MEDIUM'
        
        # Convert matches to evidence
        evidence = []
        for match in threat_matches[:5]:
            evidence.append(Evidence(
                factor='threat_intelligence',
                value=match.get('indicator', 'N/A'),
                baseline='clean',
                deviation=1.0,
                importance=0.9,
                description=f"Matched IOC: {match.get('indicator')} ({match.get('type', 'unknown')} from {match.get('source', 'unknown')})"
            ))
        
        # Primary reason
        ioc_count = len(threat_matches)
        primary_reason = f"Matched {ioc_count} threat intelligence indicator{'s' if ioc_count > 1 else ''}"
        
        # Recommendations
        recommendations = [
            "Isolate affected system immediately",
            "Block malicious indicators at network perimeter",
            "Scan for additional compromise indicators",
            "Initiate incident response procedures",
            "Review related events in same timeframe"
        ]
        
        return Explanation(
            event_id=event.get('id', 'unknown'),
            detection_type='threat_intelligence',
            severity=severity,
            confidence=confidence,
            primary_reason=primary_reason,
            evidence=evidence,
            counterfactual="Event would not be flagged if indicators were not in threat databases",
            recommendations=recommendations,
            metadata={'match_count': ioc_count, 'sources': list(set(m.get('source') for m in threat_matches))}
        )
    
    def _generate_counterfactual(self, top_evidence: List[Evidence]) -> str:
        """Generate counterfactual explanation."""
        if not top_evidence:
            return None
        
        factors = [e.description.split(':')[0] for e in top_evidence]
        if len(factors) == 1:
            return f"Event would not be flagged if {factors[0]} was within normal range"
        else:
            return f"Event would not be flagged if {', '.join(factors[:-1])} and {factors[-1]} were within normal ranges"
    
    def _generate_recommendations(
        self,
        event: Dict[str, Any],
        severity: str,
        evidence: List[Evidence]
    ) -> List[str]:
        """Generate analyst recommendations."""
        recommendations = []
        
        # Severity-based recommendations
        if severity in ['CRITICAL', 'HIGH']:
            recommendations.append("Immediate investigation required")
            recommendations.append("Review all related events in timeline")
        else:
            recommendations.append("Review when time permits")
        
        # Evidence-based recommendations
        for ev in evidence[:3]:
            if 'time' in ev.factor.lower():
                recommendations.append("Verify if off-hours access was authorized")
            elif 'file' in ev.factor.lower():
                recommendations.append("Check file access permissions and sensitivity classification")
            elif 'network' in ev.factor.lower():
                recommendations.append("Analyze network traffic for data exfiltration")
            elif 'process' in ev.factor.lower():
                recommendations.append("Investigate process execution chain")
        
        return list(set(recommendations))  # Remove duplicates
    
    def export_explanation(
        self,
        explanation: Explanation,
        output_path: Path,
        format: str = 'json'
    ) -> None:
        """
        Export explanation to file.
        
        Args:
            explanation: Explanation to export
            output_path: Output file path
            format: Export format ('json', 'txt')
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(explanation.to_dict(), f, indent=2)
        
        elif format == 'txt':
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(explanation.to_natural_language(verbose=True))
        
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        self.logger.info(f"Exported explanation to: {output_path}")


# Example usage
if __name__ == '__main__':
    # Example: Explain anomaly
    explainer = Explainer()
    
    # Mock event
    event = {
        'id': 'evt_12345',
        'timestamp': '2025-11-07 03:47:22',
        'category': 'File Activity',
        'user': 'john.doe',
        'description': 'Accessed confidential_data.xlsx',
        'anomaly_score': 0.87
    }
    
    # Mock features and baselines
    features = {
        'hour': 3,
        'file_size': 125000000,
        'is_sensitive': 1,
        'access_frequency': 0.01
    }
    
    baselines = {
        'hour': 14,
        'file_size': 12500000,
        'is_sensitive': 0,
        'access_frequency': 0.5
    }
    
    # Generate explanation
    explanation = explainer.explain_anomaly(
        event=event,
        features=features,
        baselines=baselines
    )
    
    # Print natural language
    print(explanation.to_natural_language(verbose=True))
