"""
FEPD - ML Integrity Binding
Bind ML predictions to artifact SHA-256 hashes for court-defensible results.
"""

import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from dataclasses import dataclass, asdict


logger = logging.getLogger(__name__)


@dataclass
class MLPrediction:
    """
    ML prediction bound to artifact hash for integrity verification.
    """
    artifact_path: str  # Original artifact path
    artifact_sha256: str  # SHA-256 hash of artifact
    model_name: str  # ML model used (e.g., "malware_detector_v1")
    model_version: str  # Model version
    prediction: str  # Prediction result
    confidence: float  # Confidence score (0.0-1.0)
    predicted_at: str  # ISO 8601 timestamp
    metadata: Dict[str, Any]  # Additional model-specific metadata
    
    def verify_integrity(self, current_hash: str) -> bool:
        """
        Verify that artifact hasn't been modified since prediction.
        
        Args:
            current_hash: Current SHA-256 hash of artifact
        
        Returns:
            True if hash matches, False if modified
        """
        return self.artifact_sha256 == current_hash
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MLPrediction':
        """Create from dictionary."""
        return cls(**data)


class MLIntegrityManager:
    """
    Manages ML prediction integrity and verification.
    """
    
    def __init__(self, case_dir: Path):
        """
        Initialize ML integrity manager.
        
        Args:
            case_dir: Case directory
        """
        self.case_dir = case_dir
        self.predictions_file = case_dir / "ml_predictions.json"
        self.logger = logging.getLogger(__name__)
        
        # Create predictions file if it doesn't exist
        if not self.predictions_file.exists():
            self._init_predictions()
    
    def _init_predictions(self):
        """Initialize empty predictions file."""
        predictions = {
            "version": "1.0.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "predictions": []
        }
        with open(self.predictions_file, 'w') as f:
            json.dump(predictions, f, indent=2)
        self.logger.info(f"Initialized ML predictions: {self.predictions_file}")
    
    def _load_predictions(self) -> Dict[str, Any]:
        """Load predictions from disk."""
        try:
            with open(self.predictions_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load predictions: {e}")
            return {"version": "1.0.0", "predictions": []}
    
    def _save_predictions(self, predictions: Dict[str, Any]):
        """Save predictions to disk."""
        try:
            with open(self.predictions_file, 'w') as f:
                json.dump(predictions, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save predictions: {e}")
    
    def record_prediction(
        self,
        artifact_path: str,
        artifact_sha256: str,
        model_name: str,
        model_version: str,
        prediction: str,
        confidence: float,
        metadata: Optional[Dict[str, Any]] = None
    ) -> MLPrediction:
        """
        Record an ML prediction bound to artifact hash.
        
        Args:
            artifact_path: Path to analyzed artifact
            artifact_sha256: SHA-256 hash of artifact
            model_name: ML model name
            model_version: Model version
            prediction: Prediction result
            confidence: Confidence score (0.0-1.0)
            metadata: Additional model-specific metadata
        
        Returns:
            MLPrediction object
        """
        ml_pred = MLPrediction(
            artifact_path=artifact_path,
            artifact_sha256=artifact_sha256,
            model_name=model_name,
            model_version=model_version,
            prediction=prediction,
            confidence=confidence,
            predicted_at=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {}
        )
        
        # Load existing predictions
        predictions = self._load_predictions()
        predictions["predictions"].append(ml_pred.to_dict())
        
        # Save to disk
        self._save_predictions(predictions)
        
        self.logger.info(
            f"Recorded ML prediction: {model_name} on {artifact_path} "
            f"(hash: {artifact_sha256[:16]}...)"
        )
        
        return ml_pred
    
    def get_predictions_for_artifact(self, artifact_sha256: str) -> List[MLPrediction]:
        """
        Get all predictions for a specific artifact hash.
        
        Args:
            artifact_sha256: SHA-256 hash of artifact
        
        Returns:
            List of MLPrediction objects
        """
        predictions = self._load_predictions()
        
        return [
            MLPrediction.from_dict(p)
            for p in predictions.get("predictions", [])
            if p["artifact_sha256"] == artifact_sha256
        ]
    
    def verify_all_predictions(self) -> Dict[str, List[str]]:
        """
        Verify integrity of all predictions in the case.
        
        Returns:
            Dict with "valid" and "invalid" lists of artifact paths
        """
        predictions = self._load_predictions()
        results = {"valid": [], "invalid": []}
        
        for pred_data in predictions.get("predictions", []):
            pred = MLPrediction.from_dict(pred_data)
            artifact_path = Path(pred.artifact_path)
            
            if artifact_path.exists():
                # Calculate current hash
                import hashlib
                current_hash = hashlib.sha256()
                with open(artifact_path, 'rb') as f:
                    while chunk := f.read(8192):
                        current_hash.update(chunk)
                
                if pred.verify_integrity(current_hash.hexdigest()):
                    results["valid"].append(pred.artifact_path)
                else:
                    results["invalid"].append(pred.artifact_path)
                    self.logger.warning(
                        f"ML prediction integrity FAILED for {pred.artifact_path} - "
                        f"artifact modified after analysis"
                    )
            else:
                results["invalid"].append(pred.artifact_path)
                self.logger.warning(
                    f"ML prediction integrity FAILED for {pred.artifact_path} - "
                    f"artifact not found"
                )
        
        return results
    
    def get_all_predictions(self) -> List[MLPrediction]:
        """
        Get all ML predictions for this case.
        
        Returns:
            List of all MLPrediction objects
        """
        predictions = self._load_predictions()
        return [
            MLPrediction.from_dict(p)
            for p in predictions.get("predictions", [])
        ]
