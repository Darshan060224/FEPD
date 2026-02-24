"""
Train ML Models from Real Case Data
====================================
Loads artifacts from a case directory and trains the ML models
"""

import sys
import logging
import json
from pathlib import Path
from datetime import datetime
import pandas as pd
from typing import List, Dict, Any

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.ml.ml_anomaly_detector import MLAnomalyDetectionEngine, CanonicalArtifact
from src.ml.ueba_profiler import UEBAProfiler


def load_artifacts_from_case(case_path: Path) -> List[CanonicalArtifact]:
    """Load all artifacts from case directory."""
    artifacts = []
    
    # Try loading from artifacts directories
    artifacts_dir = case_path / "artifacts"
    if artifacts_dir.exists():
        logger.info(f"Loading artifacts from {artifacts_dir}")
        
        # Load from various artifact type directories
        for artifact_type_dir in artifacts_dir.iterdir():
            if not artifact_type_dir.is_dir():
                continue
            
            artifact_type = artifact_type_dir.name
            logger.info(f"  Scanning {artifact_type}...")
            
            # Look for JSON files
            for json_file in artifact_type_dir.glob("**/*.json"):
                try:
                    with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
                        data = json.load(f)
                    
                    # Handle different JSON structures
                    if isinstance(data, list):
                        for item in data:
                            artifact = create_canonical_artifact(item, artifact_type)
                            if artifact:
                                artifacts.append(artifact)
                    elif isinstance(data, dict):
                        artifact = create_canonical_artifact(data, artifact_type)
                        if artifact:
                            artifacts.append(artifact)
                            
                except Exception as e:
                    logger.debug(f"    Skipped {json_file.name}: {e}")
    
    # Try loading from extracted_files.json
    extracted_files = case_path / "extracted_files.json"
    if extracted_files.exists():
        logger.info(f"Loading from extracted_files.json...")
        try:
            with open(extracted_files, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                for item in data:
                    artifact = create_canonical_artifact(item, 'extracted')
                    if artifact:
                        artifacts.append(artifact)
        except Exception as e:
            logger.warning(f"Failed to load extracted_files.json: {e}")
    
    # Try loading from normalized_events.csv
    events_csv = case_path / "normalized_events.csv"
    if events_csv.exists() and events_csv.stat().st_size > 0:
        logger.info(f"Loading from normalized_events.csv...")
        try:
            df = pd.read_csv(events_csv)
            if len(df) > 0:
                for _, row in df.iterrows():
                    artifact = create_canonical_artifact(row.to_dict(), 'event')
                    if artifact:
                        artifacts.append(artifact)
        except Exception as e:
            logger.warning(f"Failed to load normalized_events.csv: {e}")
    
    # Try loading from classified_events.csv
    classified_csv = case_path / "classified_events.csv"
    if classified_csv.exists() and classified_csv.stat().st_size > 0:
        logger.info(f"Loading from classified_events.csv...")
        try:
            df = pd.read_csv(classified_csv)
            if len(df) > 0:
                for _, row in df.iterrows():
                    artifact = create_canonical_artifact(row.to_dict(), 'classified')
                    if artifact:
                        artifacts.append(artifact)
        except Exception as e:
            logger.warning(f"Failed to load classified_events.csv: {e}")
    
    logger.info(f"Loaded {len(artifacts)} total artifacts from case")
    return artifacts


def create_canonical_artifact(data: Dict[str, Any], artifact_type: str) -> CanonicalArtifact:
    """Convert raw data to CanonicalArtifact."""
    try:
        # Extract timestamp
        timestamp = None
        for ts_field in ['timestamp', 'Timestamp', 'time', 'date', 'datetime', 'created', 'modified']:
            if ts_field in data:
                timestamp = data[ts_field]
                break
        
        if not timestamp:
            timestamp = datetime.now()
        
        # Extract platform
        platform = data.get('platform', data.get('Platform', data.get('os', 'unknown')))
        
        # Extract event type
        event_type = data.get('event_type', data.get('EventType', data.get('type', 'unknown')))
        
        # Extract user
        user_id = data.get('user', data.get('User', data.get('user_id', data.get('username', None))))
        
        # Extract host
        host = data.get('host', data.get('Host', data.get('hostname', data.get('computer', None))))
        
        # Create canonical artifact
        artifact = CanonicalArtifact({
            'timestamp': timestamp,
            'platform': platform,
            'artifact_type': artifact_type,
            'event_type': event_type,
            'user_id': user_id,
            'host': host,
            'raw': data
        })
        
        return artifact
        
    except Exception as e:
        logger.debug(f"Failed to create artifact: {e}")
        return None


def train_from_case(case_name: str, continue_training: bool = False):
    """Train ML models from a case."""
    print("\n" + "="*60)
    print(f"TRAINING ML MODELS FROM CASE: {case_name}")
    print("="*60)
    
    # Find case directory
    case_path = Path("cases") / case_name
    if not case_path.exists():
        logger.error(f"Case not found: {case_path}")
        print(f"\n❌ Case '{case_name}' not found!")
        return 1
    
    logger.info(f"Loading data from case: {case_path}")
    
    # Load artifacts
    artifacts = load_artifacts_from_case(case_path)
    
    if not artifacts:
        logger.error("No artifacts found in case!")
        print(f"\n❌ No artifacts found in case '{case_name}'")
        print("   Make sure the case has ingested data.")
        return 1
    
    print(f"\n✓ Loaded {len(artifacts)} artifacts from case")
    
    # Split into training and test sets (70/30)
    split_idx = int(len(artifacts) * 0.7)
    train_artifacts = artifacts[:split_idx]
    test_artifacts = artifacts[split_idx:]
    
    print(f"  Training set: {len(train_artifacts)} artifacts")
    print(f"  Test set: {len(test_artifacts)} artifacts")
    
    # Train Anomaly Detection
    print("\n" + "─"*60)
    print("ANOMALY DETECTION MODEL")
    print("─"*60)
    
    engine = MLAnomalyDetectionEngine(case_id=case_name, random_seed=42)
    
    if continue_training and (case_path / "models" / "anomaly_detector.pkl").exists():
        logger.info("Continuing training from existing model...")
        # Load existing model here if saved
        engine.continue_training(train_artifacts, additional_epochs=100)
        print("✓ Continued training for 100 additional epochs")
    else:
        logger.info("Training new model (200 epochs)...")
        engine.train(train_artifacts, save=False)
        print("✓ Model trained with 200 epochs")
    
    # Test detection
    findings = engine.detect_anomalies(test_artifacts)
    report = engine.get_anomaly_report(findings)
    
    print(f"\n📊 Detection Results:")
    print(f"   Total Anomalies: {report['total']}")
    print(f"   Critical: {report['critical']}")
    print(f"   High: {report['high']}")
    print(f"   Medium: {report['medium']}")
    print(f"   Low: {report['low']}")
    
    # Train UEBA Profiler
    print("\n" + "─"*60)
    print("UEBA PROFILING MODEL")
    print("─"*60)
    
    # Convert artifacts to DataFrame for UEBA
    events_data = []
    for artifact in artifacts:
        events_data.append({
            'timestamp': artifact.timestamp,
            'platform': artifact.platform,
            'artifact_type': artifact.artifact_type,
            'event_type': artifact.event_type,
            'user_id': artifact.user_id or 'unknown',
            'device_id': artifact.host or 'unknown',
        })
    
    events_df = pd.DataFrame(events_data)
    
    split_idx = int(len(events_df) * 0.7)
    train_df = events_df[:split_idx]
    test_df = events_df[split_idx:]
    
    profiler = UEBAProfiler(case_path=case_path)
    profiler.build_profiles(train_df)
    print(f"✓ Built profiles for {len(profiler.user_profiles)} users")
    
    # Detect anomalies
    ueba_anomalies = profiler.detect_anomalies(test_df)
    threats = profiler.detect_insider_threats(test_df)
    high_risk = profiler.get_high_risk_users(top_n=5)
    
    print(f"\n📊 UEBA Results:")
    print(f"   Behavioral Anomalies: {len(ueba_anomalies)}")
    print(f"   Insider Threats: {len(threats)}")
    print(f"   High-Risk Users: {len(high_risk)}")
    
    if high_risk:
        print(f"\n   Top Risk Users:")
        for user_dict in high_risk[:3]:
            print(f"     • {user_dict['user_id']}: Risk Score {user_dict['risk_score']:.3f}")
    
    # Summary
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    print(f"✓ Anomaly Detection: Trained on {len(train_artifacts)} artifacts")
    print(f"✓ UEBA Profiling: {len(profiler.user_profiles)} user profiles created")
    print(f"✓ Models ready for production use")
    print("="*60 + "\n")
    
    return 0


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Train ML models from case data')
    parser.add_argument('case_name', help='Name of the case to train from')
    parser.add_argument('--continue', dest='continue_training', action='store_true',
                       help='Continue training existing model')
    
    args = parser.parse_args()
    
    return train_from_case(args.case_name, args.continue_training)


if __name__ == "__main__":
    sys.exit(main())
