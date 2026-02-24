"""
FEPD - Enhanced Explainability Framework
==========================================
SHAP and LIME integration for court-defensible ML explanations.

This module extends the base explainer.py with:
- SHAP (SHapley Additive exPlanations) integration
- LIME (Local Interpretable Model-agnostic Explanations) integration
- Feature importance visualization
- Counterfactual generation
- Court-ready explanation reports

Principles:
- Every prediction must be explainable
- Explanations must be deterministic
- Explanations must be court-defensible
- Multiple explanation methods for validation

Copyright (c) 2026 FEPD Development Team
"""

import logging
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import json

# Try to import SHAP
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logging.warning("SHAP not available. Install with: pip install shap")

# Try to import LIME
try:
    import lime
    import lime.lime_tabular
    LIME_AVAILABLE = True
except ImportError:
    LIME_AVAILABLE = False
    logging.warning("LIME not available. Install with: pip install lime")


@dataclass
class ExplanationReport:
    """Court-defensible explanation report"""
    case_id: str
    evidence_id: str
    model_name: str
    model_version: str
    prediction: int
    confidence: float
    shap_values: Optional[Dict[str, float]]
    lime_values: Optional[Dict[str, float]]
    feature_values: Dict[str, Any]
    explanation_text: str
    generated_at: str
    analyst_notes: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "prediction": self.prediction,
            "confidence": self.confidence,
            "shap_values": self.shap_values,
            "lime_values": self.lime_values,
            "feature_values": self.feature_values,
            "explanation_text": self.explanation_text,
            "generated_at": self.generated_at,
            "analyst_notes": self.analyst_notes
        }
    
    def save(self, output_path: Path):
        """Save explanation report to JSON"""
        with open(output_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    def to_markdown(self) -> str:
        """Generate markdown report for court documentation"""
        lines = [
            f"# ML Explanation Report",
            f"",
            f"**Case ID**: {self.case_id}  ",
            f"**Evidence ID**: {self.evidence_id}  ",
            f"**Model**: {self.model_name} v{self.model_version}  ",
            f"**Generated**: {self.generated_at}  ",
            f"",
            f"## Prediction",
            f"",
            f"- **Result**: {'SUSPICIOUS' if self.prediction == 1 else 'BENIGN'}",
            f"- **Confidence**: {self.confidence:.2%}",
            f"",
            f"## Explanation",
            f"",
            self.explanation_text,
            f"",
            f"## Feature Importance (SHAP)",
            f""
        ]
        
        if self.shap_values:
            lines.append("| Feature | SHAP Value | Contribution |")
            lines.append("|---------|------------|--------------|")
            for feature, value in sorted(self.shap_values.items(), key=lambda x: abs(x[1]), reverse=True):
                contribution = "Increases risk" if value > 0 else "Decreases risk"
                lines.append(f"| {feature} | {value:.4f} | {contribution} |")
        
        lines.extend([
            f"",
            f"## Feature Values",
            f""
        ])
        
        lines.append("| Feature | Value |")
        lines.append("|---------|-------|")
        for feature, value in self.feature_values.items():
            lines.append(f"| {feature} | {value} |")
        
        if self.analyst_notes:
            lines.extend([
                f"",
                f"## Analyst Notes",
                f"",
                self.analyst_notes
            ])
        
        return "\n".join(lines)


class SHAPExplainer:
    """
    SHAP-based explainer for tree models.
    
    SHAP provides:
    - Theoretically grounded explanations
    - Feature importance values
    - Additive feature attribution
    - Visualization capabilities
    """
    
    def __init__(self, model, X_background: pd.DataFrame = None, logger=None):
        """
        Initialize SHAP explainer.
        
        Args:
            model: Trained model (scikit-learn compatible)
            X_background: Background dataset for SHAP (100-1000 samples recommended)
            logger: Optional logger
        """
        if not SHAP_AVAILABLE:
            raise ImportError("SHAP not installed. Install with: pip install shap")
        
        self.model = model
        self.logger = logger or logging.getLogger(__name__)
        
        # Create SHAP explainer based on model type
        try:
            # For tree-based models (Random Forest, XGBoost, etc.)
            self.explainer = shap.TreeExplainer(model)
            self.logger.info("Using TreeExplainer (exact SHAP values)")
        except Exception as e:
            # Fallback to KernelExplainer (model-agnostic but slower)
            if X_background is None:
                raise ValueError("X_background required for KernelExplainer")
            self.explainer = shap.KernelExplainer(model.predict, X_background)
            self.logger.info("Using KernelExplainer (approximate SHAP values)")
    
    def explain(self, X: pd.DataFrame) -> Dict[str, float]:
        """
        Generate SHAP explanations for prediction.
        
        Args:
            X: Feature matrix (single row or multiple rows)
            
        Returns:
            Dictionary of feature names to SHAP values
        """
        # Calculate SHAP values
        shap_values = self.explainer.shap_values(X)
        
        # For binary classification, get values for positive class
        if isinstance(shap_values, list):
            shap_values = shap_values[1]  # Positive class
        
        # Convert to dictionary
        if len(X) == 1:
            # Single prediction
            feature_names = X.columns.tolist()
            shap_dict = dict(zip(feature_names, shap_values[0]))
        else:
            # Multiple predictions - return average
            feature_names = X.columns.tolist()
            shap_dict = dict(zip(feature_names, shap_values.mean(axis=0)))
        
        return shap_dict
    
    def get_top_features(self, shap_values: Dict[str, float], n: int = 5) -> List[Tuple[str, float]]:
        """
        Get top N features by absolute SHAP value.
        
        Args:
            shap_values: Dictionary of SHAP values
            n: Number of top features
            
        Returns:
            List of (feature_name, shap_value) tuples
        """
        sorted_features = sorted(shap_values.items(), key=lambda x: abs(x[1]), reverse=True)
        return sorted_features[:n]


class LIMEExplainer:
    """
    LIME-based explainer for any model.
    
    LIME provides:
    - Local linear approximations
    - Model-agnostic explanations
    - Interpretable representations
    """
    
    def __init__(self, model, X_train: pd.DataFrame, feature_names: List[str] = None, logger=None):
        """
        Initialize LIME explainer.
        
        Args:
            model: Trained model with predict_proba method
            X_train: Training data for LIME
            feature_names: Optional feature names
            logger: Optional logger
        """
        if not LIME_AVAILABLE:
            raise ImportError("LIME not installed. Install with: pip install lime")
        
        self.model = model
        self.feature_names = feature_names or list(X_train.columns)
        self.logger = logger or logging.getLogger(__name__)
        
        # Create LIME explainer
        self.explainer = lime.lime_tabular.LimeTabularExplainer(
            training_data=X_train.values,
            feature_names=self.feature_names,
            class_names=['Benign', 'Suspicious'],
            mode='classification'
        )
    
    def explain(self, X: np.ndarray, num_features: int = 10) -> Dict[str, float]:
        """
        Generate LIME explanation for prediction.
        
        Args:
            X: Feature vector (single instance)
            num_features: Number of features to include in explanation
            
        Returns:
            Dictionary of feature names to importance values
        """
        # Generate explanation
        exp = self.explainer.explain_instance(
            X[0] if len(X.shape) > 1 else X,
            self.model.predict_proba,
            num_features=num_features
        )
        
        # Convert to dictionary
        lime_dict = dict(exp.as_list())
        
        return lime_dict


class ForensicExplainer:
    """
    Unified explainer combining SHAP, LIME, and forensic domain knowledge.
    
    This is the main explainer used by FEPD for court-defensible explanations.
    """
    
    def __init__(self, model, model_name: str, model_version: str, 
                 X_background: pd.DataFrame = None, logger=None):
        """
        Initialize forensic explainer.
        
        Args:
            model: Trained model
            model_name: Name of the model
            model_version: Version of the model
            X_background: Background data for SHAP
            logger: Optional logger
        """
        self.model = model
        self.model_name = model_name
        self.model_version = model_version
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize SHAP if available
        if SHAP_AVAILABLE:
            try:
                self.shap_explainer = SHAPExplainer(model, X_background, logger)
                self.logger.info("SHAP explainer initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize SHAP: {e}")
                self.shap_explainer = None
        else:
            self.shap_explainer = None
        
        # LIME requires training data
        self.lime_explainer = None
        if LIME_AVAILABLE and X_background is not None:
            try:
                self.lime_explainer = LIMEExplainer(model, X_background, logger=logger)
                self.logger.info("LIME explainer initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize LIME: {e}")
    
    def explain_prediction(self, X: pd.DataFrame, case_id: str, evidence_id: str,
                          prediction: int, confidence: float) -> ExplanationReport:
        """
        Generate comprehensive explanation for a prediction.
        
        Args:
            X: Feature matrix (single row)
            case_id: Case identifier
            evidence_id: Evidence identifier
            prediction: Model prediction (0 or 1)
            confidence: Prediction confidence
            
        Returns:
            ExplanationReport with SHAP, LIME, and natural language explanation
        """
        from datetime import datetime
        
        # Get SHAP values
        shap_values = None
        if self.shap_explainer:
            try:
                shap_values = self.shap_explainer.explain(X)
                self.logger.info("SHAP explanation generated")
            except Exception as e:
                self.logger.error(f"SHAP explanation failed: {e}")
        
        # Get LIME values
        lime_values = None
        if self.lime_explainer:
            try:
                lime_values = self.lime_explainer.explain(X.values)
                self.logger.info("LIME explanation generated")
            except Exception as e:
                self.logger.error(f"LIME explanation failed: {e}")
        
        # Generate natural language explanation
        explanation_text = self._generate_explanation_text(
            X, prediction, confidence, shap_values, lime_values
        )
        
        # Create report
        report = ExplanationReport(
            case_id=case_id,
            evidence_id=evidence_id,
            model_name=self.model_name,
            model_version=self.model_version,
            prediction=prediction,
            confidence=confidence,
            shap_values=shap_values,
            lime_values=lime_values,
            feature_values=X.iloc[0].to_dict() if isinstance(X, pd.DataFrame) else dict(enumerate(X[0])),
            explanation_text=explanation_text,
            generated_at=datetime.now().isoformat()
        )
        
        return report
    
    def _generate_explanation_text(self, X: pd.DataFrame, prediction: int, 
                                   confidence: float, shap_values: Dict, 
                                   lime_values: Dict) -> str:
        """Generate natural language explanation"""
        lines = []
        
        if prediction == 1:
            lines.append(f"This evidence was flagged as SUSPICIOUS with {confidence:.1%} confidence.")
            lines.append("")
            lines.append("Key contributing factors:")
            
            # Use SHAP if available, otherwise LIME
            values = shap_values if shap_values else lime_values
            
            if values:
                top_features = sorted(values.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
                for i, (feature, value) in enumerate(top_features, 1):
                    direction = "increases" if value > 0 else "decreases"
                    lines.append(f"{i}. {feature}: {direction} suspicion (impact: {abs(value):.4f})")
        else:
            lines.append(f"This evidence appears BENIGN with {1-confidence:.1%} confidence.")
        
        return "\n".join(lines)


if __name__ == "__main__":
    # Test explainability framework
    logging.basicConfig(level=logging.INFO)
    
    from sklearn.ensemble import RandomForestClassifier
    
    # Create synthetic data
    np.random.seed(42)
    X_train = pd.DataFrame({
        'entropy': np.random.rand(100) * 8,
        'size_log': np.random.rand(100) * 10,
        'path_depth': np.random.randint(1, 10, 100)
    })
    y_train = (X_train['entropy'] > 6).astype(int)
    
    # Train model
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X_train, y_train)
    
    # Create explainer
    explainer = ForensicExplainer(
        model=model,
        model_name="test_classifier",
        model_version="1.0",
        X_background=X_train.sample(50)
    )
    
    # Test explanation
    X_test = pd.DataFrame({
        'entropy': [7.5],
        'size_log': [8.0],
        'path_depth': [5]
    })
    
    prediction = model.predict(X_test)[0]
    confidence = model.predict_proba(X_test)[0][1]
    
    report = explainer.explain_prediction(
        X=X_test,
        case_id="TEST001",
        evidence_id="FILE001",
        prediction=prediction,
        confidence=confidence
    )
    
    print("\n=== Explanation Report ===")
    print(report.to_markdown())
