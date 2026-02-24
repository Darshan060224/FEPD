"""
FEPD - Inference Pipeline
===========================
Real-time inference during evidence processing.

This pipeline is SEPARATE from training and uses frozen models.

Inference Principles:
- Fast execution
- Read-only evidence
- Frozen models (no retraining)
- Explainable outputs
- Chain of custody preserved

Flow:
Upload → Detect → Extract → Feature → Predict → Explain → Display

Copyright (c) 2026 FEPD Development Team
"""

import logging
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import json

from src.core.evidence_detector import EvidenceDetector, EvidenceType
from src.core.integrity import IntegrityManager
from src.core.ml_integrity import MLIntegrityManager  # CRITICAL-003 FIX
from src.ml.feature_engineering import FeatureEngineeringPipeline
from src.ml.specialized_models import ModelRegistry
from src.ml.explainability_framework import ForensicExplainer
import hashlib  # CRITICAL-003 FIX


class InferencePipeline:
    """
    Real-time ML inference during evidence processing.
    
    This pipeline:
    1. Validates evidence integrity
    2. Detects evidence type
    3. Extracts artifacts
    4. Engineers features
    5. Runs ML predictions
    6. Generates explanations
    7. Logs results
    """
    
    def __init__(self, case_id: str, case_path: Path, operator: str = "system", logger=None):
        self.case_id = case_id
        self.case_path = Path(case_path)
        self.operator = operator
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize components
        self.evidence_detector = EvidenceDetector(logger)
        self.integrity_mgr = IntegrityManager(case_path, operator, logger)
        self.ml_integrity_mgr = MLIntegrityManager(case_path)  # CRITICAL-003 FIX
        self.feature_pipeline = FeatureEngineeringPipeline(logger=logger)
        self.model_registry = ModelRegistry(logger=logger)
        
        # Create inference output directory
        self.output_dir = self.case_path / "ml_analysis"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def process_evidence(self, evidence_path: Path) -> Dict:
        """
        Process evidence through complete ML pipeline.
        
        Args:
            evidence_path: Path to evidence file
            
        Returns:
            Dictionary with analysis results
        """
        self.logger.info("=" * 80)
        self.logger.info(f"ML Inference Pipeline - Case {self.case_id}")
        self.logger.info(f"Evidence: {evidence_path.name}")
        self.logger.info("=" * 80)
        
        results = {
            "case_id": self.case_id,
            "evidence_path": str(evidence_path),
            "timestamp": datetime.now().isoformat(),
            "stages": {}
        }
        
        # Stage 1: Verify integrity
        self.logger.info("Stage 1: Verifying integrity...")
        integrity_result = self._verify_integrity(evidence_path)
        results["stages"]["integrity"] = integrity_result
        
        if not integrity_result["verified"]:
            self.logger.error("INTEGRITY CHECK FAILED - Aborting pipeline")
            results["status"] = "failed"
            results["reason"] = "integrity_check_failed"
            return results
        
        # Stage 2: Detect evidence type
        self.logger.info("Stage 2: Detecting evidence type...")
        detection_result = self._detect_type(evidence_path)
        results["stages"]["detection"] = detection_result
        
        # Stage 3: Extract artifacts
        self.logger.info("Stage 3: Extracting artifacts...")
        artifacts_result = self._extract_artifacts(evidence_path, detection_result["evidence_type"])
        results["stages"]["artifacts"] = artifacts_result
        
        if not artifacts_result["success"]:
            results["status"] = "completed_no_ml"
            results["reason"] = "no_artifacts_extracted"
            return results
        
        # Stage 4: Engineer features
        self.logger.info("Stage 4: Engineering features...")
        features_result = self._engineer_features(artifacts_result["data"])
        results["stages"]["features"] = features_result
        
        # Stage 5: Run ML predictions
        self.logger.info("Stage 5: Running ML predictions...")
        predictions_result = self._run_predictions(
            features_result["data"],
            detection_result["evidence_type"],
            artifact_path=evidence_path  # CRITICAL-003 FIX: Pass artifact path
        )
        results["stages"]["predictions"] = predictions_result
        
        # Stage 6: Generate explanations
        self.logger.info("Stage 6: Generating explanations...")
        explanations_result = self._generate_explanations(
            features_result["data"],
            predictions_result
        )
        results["stages"]["explanations"] = explanations_result
        
        # Stage 7: Save results
        self.logger.info("Stage 7: Saving results...")
        self._save_results(results)
        
        results["status"] = "completed"
        
        self.logger.info("=" * 80)
        self.logger.info("ML Inference Complete!")
        self.logger.info("=" * 80)
        
        return results
    
    def _verify_integrity(self, evidence_path: Path) -> Dict:
        """Verify evidence integrity"""
        try:
            # Check if hash file exists
            hash_file = evidence_path.with_suffix(evidence_path.suffix + '.sha256')
            if hash_file.exists():
                verified = self.integrity_mgr.verify_integrity(evidence_path)
            else:
                # First time - register evidence
                record = self.integrity_mgr.register_evidence(evidence_path, operation="ml_analysis")
                verified = True
            
            return {
                "verified": verified,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Integrity check failed: {e}")
            return {
                "verified": False,
                "error": str(e)
            }
    
    def _detect_type(self, evidence_path: Path) -> Dict:
        """Detect evidence type using magic numbers"""
        detection = self.evidence_detector.detect(evidence_path)
        
        return {
            "evidence_type": detection.evidence_type.value,
            "confidence": detection.confidence,
            "detected_by": detection.detected_by,
            "sha256": detection.sha256
        }
    
    def _extract_artifacts(self, evidence_path: Path, evidence_type: str) -> Dict:
        """Extract forensic artifacts (placeholder - implement per evidence type)"""
        # This would call appropriate parsers based on evidence type
        # For now, return mock data
        
        self.logger.info(f"Extracting artifacts from {evidence_type}")
        
        # Mock extraction - in reality, this would parse EVTX, registry, etc.
        return {
            "success": True,
            "artifact_count": 0,
            "data": pd.DataFrame()
        }
    
    def _engineer_features(self, artifacts_df: pd.DataFrame) -> Dict:
        """Engineer numeric features from artifacts"""
        if artifacts_df.empty:
            return {
                "success": False,
                "feature_count": 0,
                "data": pd.DataFrame()
            }
        
        # Feature extraction based on artifact type
        # This would use FeatureEngineeringPipeline
        
        return {
            "success": True,
            "feature_count": len(artifacts_df.columns),
            "data": artifacts_df
        }
    
    def _run_predictions(self, features_df: pd.DataFrame, evidence_type: str, 
                        artifact_path: Optional[Path] = None) -> Dict:
        """Run ML predictions on features and bind to artifact hash (CRITICAL-003 FIX)"""
        if features_df.empty:
            return {"predictions": []}
        
        # CRITICAL-003 FIX: Calculate artifact hash BEFORE analysis
        artifact_hash = None
        if artifact_path and artifact_path.exists():
            try:
                with open(artifact_path, 'rb') as f:
                    artifact_hash = hashlib.sha256(f.read()).hexdigest()
                self.logger.info(f"Artifact hash: {artifact_hash}")
            except Exception as e:
                self.logger.error(f"Failed to hash artifact: {e}")
        
        # Select appropriate models for evidence type
        models_to_run = self._select_models(evidence_type)
        
        predictions = []
        for model_name in models_to_run:
            try:
                model = self.model_registry.get_model(model_name)
                result = model.predict(features_df)
                pred_dict = result.to_dict()
                
                # CRITICAL-003 FIX: Bind prediction to artifact hash
                if artifact_hash and artifact_path:
                    try:
                        self.ml_integrity_mgr.record_prediction(
                            artifact_path=str(artifact_path),
                            artifact_sha256=artifact_hash,
                            model_name=model_name,
                            model_version=getattr(model, 'version', '1.0.0'),
                            prediction=pred_dict.get('prediction', 'unknown'),
                            confidence=pred_dict.get('confidence', 0.0),
                            metadata=pred_dict
                        )
                        self.logger.info(f"Prediction bound to artifact hash: {model_name}")
                    except Exception as e:
                        self.logger.error(f"Failed to bind prediction: {e}")
                
                predictions.append(pred_dict)
            except Exception as e:
                self.logger.error(f"Prediction failed for {model_name}: {e}")
        
        return {
            "predictions": predictions,
            "model_count": len(predictions),
            "artifact_hash": artifact_hash  # Include hash in results
        }
    
    def _generate_explanations(self, features_df: pd.DataFrame, predictions: Dict) -> Dict:
        """Generate SHAP/LIME explanations"""
        explanations = []
        
        for pred in predictions.get("predictions", []):
            # Generate explanation using ForensicExplainer
            explanation = {
                "model": pred.get("model_name"),
                "prediction": pred.get("prediction"),
                "confidence": pred.get("confidence"),
                "explanation": pred.get("explanation")
            }
            explanations.append(explanation)
        
        return {
            "explanations": explanations
        }
    
    def _select_models(self, evidence_type: str) -> List[str]:
        """Select appropriate models for evidence type"""
        model_mapping = {
            "evtx": ["evtx_anomaly"],
            "registry": ["registry_persistence"],
            "dd": ["malware_classifier"],
            "e01": ["malware_classifier"],
            "pcap": ["network_anomaly"],
            "windows_memory": ["memory_anomaly"]
        }
        return model_mapping.get(evidence_type, [])
    
    def _save_results(self, results: Dict):
        """Save inference results to disk"""
        output_file = self.output_dir / f"inference_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Results saved: {output_file}")


if __name__ == "__main__":
    # Test inference pipeline
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create test case
    case_path = Path("cases/TEST_ML_001")
    case_path.mkdir(parents=True, exist_ok=True)
    
    # Initialize pipeline
    pipeline = InferencePipeline(
        case_id="TEST_ML_001",
        case_path=case_path,
        operator="test_analyst"
    )
    
    print("Inference pipeline initialized")
    print("Ready for evidence processing")
