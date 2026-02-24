"""
Comprehensive Test Suite for ML Anomaly Detection Module
=========================================================

Tests all components:
- EventEncoder
- AutoencoderAnomalyDetector
- ClusteringAnomalyDetector
- ClockSkewDetector
- MLAnomalyDetectionEngine
"""

import numpy as np
import pandas as pd
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml_anomaly_detector import (
    EventEncoder,
    AutoencoderAnomalyDetector,
    ClusteringAnomalyDetector,
    ClockSkewDetector,
    MLAnomalyDetectionEngine,
    ML_AVAILABLE
)

# ANSI color codes for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class TestRunner:
    """Simple test runner with colorful output."""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def test(self, name, func):
        """Run a test and record results."""
        print(f"\n{BLUE}Testing:{RESET} {name}")
        try:
            func()
            print(f"  {GREEN}✓ PASSED{RESET}")
            self.passed += 1
            self.tests.append((name, True, None))
        except Exception as e:
            print(f"  {RED}✗ FAILED: {str(e)}{RESET}")
            self.failed += 1
            self.tests.append((name, False, str(e)))
    
    def summary(self):
        """Print test summary."""
        total = self.passed + self.failed
        print("\n" + "=" * 70)
        print(f"{BLUE}TEST SUMMARY{RESET}")
        print("=" * 70)
        print(f"Total Tests: {total}")
        print(f"{GREEN}Passed: {self.passed}{RESET}")
        print(f"{RED}Failed: {self.failed}{RESET}")
        
        if self.failed > 0:
            print(f"\n{RED}Failed Tests:{RESET}")
            for name, passed, error in self.tests:
                if not passed:
                    print(f"  - {name}: {error}")
        
        print("=" * 70)
        return self.failed == 0


def generate_sample_events(n=1000, include_anomalies=False):
    """Generate synthetic forensic events for testing."""
    np.random.seed(42)
    
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    timestamps = [base_time + timedelta(minutes=i) for i in range(n)]
    
    event_data = {
        'timestamp': timestamps,
        'event_type': np.random.choice(['login', 'logout', 'file_access', 'process_start', 'network_conn'], n),
        'source': np.random.choice(['system', 'application', 'kernel', 'security'], n),
        'severity': np.random.choice(['low', 'medium', 'high'], n, p=[0.7, 0.25, 0.05]),
        'description': [f'Event {i}' for i in range(n)]
    }
    
    df = pd.DataFrame(event_data)
    
    if include_anomalies and n > 50:
        # Add time jump (at 50% of data)
        idx1 = min(n // 2, n - 1)
        df.loc[idx1, 'timestamp'] = base_time + timedelta(hours=48)
        # Add rare event type
        idx2 = min(idx1 + 1, n - 1)
        df.loc[idx2, 'event_type'] = 'RARE_SUSPICIOUS_EVENT'
        # Add critical severity spike
        idx3 = min(idx1 + 2, n - 5)
        df.loc[idx3:idx3+3, 'severity'] = 'critical'
        # Add reverse chronology (at 60% of data)
        idx4 = min(int(n * 0.6), n - 1)
        if idx4 > 0:
            prev_timestamp = pd.to_datetime(df.loc[idx4-1, 'timestamp'])
            df.loc[idx4, 'timestamp'] = prev_timestamp - timedelta(minutes=10)
    
    return df


# ============================================================================
# EventEncoder Tests
# ============================================================================

def test_event_encoder_initialization():
    """Test EventEncoder can be initialized."""
    encoder = EventEncoder()
    assert not encoder.fitted, "Encoder should not be fitted initially"
    assert encoder.event_type_encoder is not None
    assert encoder.source_encoder is not None
    assert encoder.scaler is not None
    print("    - Initialization successful")


def test_event_encoder_fit_transform():
    """Test EventEncoder fit and transform operations."""
    encoder = EventEncoder()
    events = generate_sample_events(100)
    
    # Fit encoder
    encoder.fit(events)
    assert encoder.fitted, "Encoder should be fitted"
    print("    - Fit successful")
    
    # Transform events
    features = encoder.transform(events)
    assert features.shape[0] == len(events), "Feature count mismatch"
    assert features.shape[1] > 0, "No features extracted"
    print(f"    - Transformed to {features.shape[1]} features")
    
    # Check feature range (should be scaled)
    assert np.isfinite(features).all(), "Features contain NaN/inf"
    print("    - All features are finite")


def test_event_encoder_save_load():
    """Test EventEncoder save and load functionality."""
    encoder = EventEncoder()
    events = generate_sample_events(100)
    encoder.fit(events)
    
    # Save encoder
    with tempfile.TemporaryDirectory() as tmpdir:
        save_path = Path(tmpdir) / 'encoder.json'
        encoder.save(save_path)
        assert save_path.exists(), "Encoder file not saved"
        print("    - Save successful")
        
        # Load encoder
        encoder2 = EventEncoder()
        encoder2.load(save_path)
        assert encoder2.fitted, "Loaded encoder should be fitted"
        print("    - Load successful")
        
        # Verify same transformation
        features1 = encoder.transform(events)
        features2 = encoder2.transform(events)
        assert np.allclose(features1, features2), "Loaded encoder produces different features"
        print("    - Transformations match")


# ============================================================================
# AutoencoderAnomalyDetector Tests
# ============================================================================

def test_autoencoder_initialization():
    """Test AutoencoderAnomalyDetector initialization."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    detector = AutoencoderAnomalyDetector(encoding_dim=8)
    assert detector.encoding_dim == 8
    assert detector.model is None, "Model should be None initially"
    assert detector.threshold is None, "Threshold should be None initially"
    print("    - Initialization successful")


def test_autoencoder_build_model():
    """Test autoencoder model building."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    detector = AutoencoderAnomalyDetector(encoding_dim=4)
    detector.build_model(input_dim=10)
    
    assert detector.model is not None, "Model not built"
    assert len(detector.model.layers) > 0, "Model has no layers"
    print(f"    - Built model with {len(detector.model.layers)} layers")


def test_autoencoder_training():
    """Test autoencoder training on benign events."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    detector = AutoencoderAnomalyDetector(encoding_dim=4)
    events = generate_sample_events(200)
    
    # Train
    history = detector.train(events, epochs=5, validation_split=0.2)
    
    assert detector.model is not None, "Model not trained"
    assert detector.threshold is not None, "Threshold not set"
    assert detector.threshold > 0, "Invalid threshold"
    print(f"    - Training complete, threshold: {detector.threshold:.4f}")


def test_autoencoder_prediction():
    """Test autoencoder anomaly prediction."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    detector = AutoencoderAnomalyDetector(encoding_dim=4)
    
    # Train on benign events
    benign_events = generate_sample_events(200)
    detector.train(benign_events, epochs=5)
    
    # Predict on events with anomalies
    test_events = generate_sample_events(100, include_anomalies=True)
    scores, is_anomaly = detector.predict(test_events)
    
    assert len(scores) == len(test_events), "Score count mismatch"
    assert len(is_anomaly) == len(test_events), "Anomaly flag count mismatch"
    assert scores.max() > 0, "No anomaly scores computed"
    
    anomaly_count = is_anomaly.sum()
    print(f"    - Detected {anomaly_count} anomalies out of {len(test_events)} events")


def test_autoencoder_save_load():
    """Test autoencoder save and load."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    detector = AutoencoderAnomalyDetector(encoding_dim=4)
    events = generate_sample_events(100)
    detector.train(events, epochs=3)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        model_dir = Path(tmpdir) / 'autoencoder'
        
        # Save
        detector.save(model_dir)
        assert (model_dir / 'autoencoder_model.keras').exists(), "Model file not saved"
        assert (model_dir / 'encoder_state.json').exists(), "Encoder state not saved"
        assert (model_dir / 'threshold.txt').exists(), "Threshold not saved"
        print("    - Save successful")
        
        # Load
        detector2 = AutoencoderAnomalyDetector()
        detector2.load(model_dir)
        assert detector2.model is not None, "Model not loaded"
        assert detector2.threshold is not None, "Threshold not loaded"
        print("    - Load successful")


# ============================================================================
# ClusteringAnomalyDetector Tests
# ============================================================================

def test_clustering_initialization():
    """Test ClusteringAnomalyDetector initialization."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    detector = ClusteringAnomalyDetector(n_clusters=5)
    assert detector.n_clusters == 5
    assert detector.kmeans is None
    assert detector.dbscan is None
    print("    - Initialization successful")


def test_clustering_training():
    """Test clustering model training."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    detector = ClusteringAnomalyDetector(n_clusters=5)
    events = generate_sample_events(200)
    
    detector.train(events)
    
    assert detector.kmeans is not None, "K-means not trained"
    assert detector.dbscan is not None, "DBSCAN not trained"
    assert detector.isolation_forest is not None, "Isolation Forest not trained"
    print("    - Training complete (K-means, DBSCAN, Isolation Forest)")


def test_clustering_prediction():
    """Test clustering anomaly prediction."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    detector = ClusteringAnomalyDetector(n_clusters=5)
    
    # Train
    benign_events = generate_sample_events(200)
    detector.train(benign_events)
    
    # Predict
    test_events = generate_sample_events(100, include_anomalies=True)
    results = detector.predict(test_events)
    
    assert 'kmeans_distance' in results
    assert 'dbscan_outliers' in results
    assert 'isolation_anomalies' in results
    assert 'combined_score' in results
    
    outlier_count = results['dbscan_outliers'].sum()
    iso_count = results['isolation_anomalies'].sum()
    print(f"    - DBSCAN outliers: {outlier_count}, Isolation anomalies: {iso_count}")


def test_clustering_save_load():
    """Test clustering save and load."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    detector = ClusteringAnomalyDetector(n_clusters=3)
    events = generate_sample_events(100)
    detector.train(events)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        model_dir = Path(tmpdir) / 'clustering'
        
        # Save
        detector.save(model_dir)
        assert (model_dir / 'kmeans.pkl').exists()
        assert (model_dir / 'dbscan.pkl').exists()
        assert (model_dir / 'isolation_forest.pkl').exists()
        print("    - Save successful")
        
        # Load
        detector2 = ClusteringAnomalyDetector()
        detector2.load(model_dir)
        assert detector2.kmeans is not None
        assert detector2.dbscan is not None
        print("    - Load successful")


# ============================================================================
# ClockSkewDetector Tests
# ============================================================================

def test_clock_skew_initialization():
    """Test ClockSkewDetector initialization."""
    detector = ClockSkewDetector()
    assert detector is not None
    print("    - Initialization successful")


def test_clock_skew_linear_drift():
    """Test linear drift detection."""
    detector = ClockSkewDetector()
    
    # Create events with linear drift
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    timestamps = [base_time + timedelta(seconds=i*60 + i*0.5) for i in range(100)]  # Drift
    
    events = pd.DataFrame({
        'timestamp': timestamps,
        'event_type': ['login'] * 100
    })
    
    result = detector._detect_linear_drift(pd.to_datetime(events['timestamp']))
    
    assert 'detected' in result
    assert 'drift_rate_sec_per_hour' in result
    print(f"    - Drift detection: {result['detected']}, rate: {result.get('drift_rate_sec_per_hour', 0):.2f} sec/hr")


def test_clock_skew_time_jumps():
    """Test time jump detection."""
    detector = ClockSkewDetector()
    
    # Create events with a time jump
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    timestamps = [base_time + timedelta(minutes=i) for i in range(100)]
    timestamps[50] = base_time + timedelta(hours=5)  # Big jump
    
    events = pd.DataFrame({'timestamp': timestamps})
    
    result = detector._detect_time_jumps(pd.to_datetime(events['timestamp']))
    
    assert isinstance(result, list)
    print(f"    - Detected {len(result)} time jumps")


def test_clock_skew_reverse_chronology():
    """Test reverse chronology detection."""
    detector = ClockSkewDetector()
    
    # Create events with reverse timestamps
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    timestamps = [base_time + timedelta(minutes=i) for i in range(100)]
    timestamps[50] = timestamps[48]  # Goes backwards
    
    events = pd.DataFrame({'timestamp': timestamps})
    
    result = detector._detect_reverse_chronology(events)
    
    assert isinstance(result, list)
    print(f"    - Detected {len(result)} reverse chronology events")


def test_clock_skew_full_analysis():
    """Test full clock-skew analysis."""
    detector = ClockSkewDetector()
    events = generate_sample_events(200, include_anomalies=True)
    
    result = detector.detect_anomalies(events)
    
    assert 'linear_drift' in result
    assert 'time_jumps' in result
    assert 'reverse_events' in result
    assert 'outlier_gaps' in result
    
    print(f"    - Full analysis complete")
    print(f"      Time jumps: {len(result['time_jumps'])}")
    print(f"      Reverse events: {len(result['reverse_events'])}")
    print(f"      Outlier gaps: {len(result['outlier_gaps'])}")


# ============================================================================
# MLAnomalyDetectionEngine Tests
# ============================================================================

def test_engine_initialization():
    """Test MLAnomalyDetectionEngine initialization."""
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = MLAnomalyDetectionEngine(model_dir=Path(tmpdir))
        
        assert engine.autoencoder is not None
        assert engine.clustering is not None
        assert engine.clock_skew is not None
        print("    - Engine initialized with all components")


def test_engine_training():
    """Test full engine training."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = MLAnomalyDetectionEngine(model_dir=Path(tmpdir))
        events = generate_sample_events(300)
        
        engine.train(events, save=True)
        
        assert engine.autoencoder.model is not None
        assert engine.clustering.kmeans is not None
        print("    - Engine training complete")


def test_engine_detection():
    """Test full engine anomaly detection."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = MLAnomalyDetectionEngine(model_dir=Path(tmpdir))
        
        # Train
        benign_events = generate_sample_events(300)
        engine.train(benign_events, save=False)
        
        # Detect
        test_events = generate_sample_events(100, include_anomalies=True)
        results = engine.detect_anomalies(test_events)
        
        assert 'anomaly_score' in results.columns
        assert 'is_anomaly' in results.columns
        assert 'ae_score' in results.columns
        assert 'cluster_score' in results.columns
        
        anomaly_count = results['is_anomaly'].sum()
        print(f"    - Detected {anomaly_count} anomalies")


def test_engine_report_generation():
    """Test anomaly report generation."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = MLAnomalyDetectionEngine(model_dir=Path(tmpdir))
        
        # Train and detect
        benign_events = generate_sample_events(200)
        engine.train(benign_events, save=False)
        
        test_events = generate_sample_events(100, include_anomalies=True)
        results = engine.detect_anomalies(test_events)
        
        # Generate report
        report = engine.get_anomaly_report(results)
        
        assert 'total_events' in report
        assert 'anomalies_detected' in report
        assert 'anomaly_rate' in report
        assert 'top_anomalies' in report
        assert 'clock_skew_analysis' in report
        
        print(f"    - Report generated:")
        print(f"      Total events: {report['total_events']}")
        print(f"      Anomalies: {report['anomalies_detected']}")
        print(f"      Rate: {report['anomaly_rate']:.2%}")


def test_engine_save_load():
    """Test engine model persistence."""
    if not ML_AVAILABLE:
        print(f"    {YELLOW}⊘ SKIPPED - ML libraries not available{RESET}")
        return
    
    with tempfile.TemporaryDirectory() as tmpdir:
        model_dir = Path(tmpdir) / 'models'
        
        # Train and save
        engine1 = MLAnomalyDetectionEngine(model_dir=model_dir)
        events = generate_sample_events(200)
        engine1.train(events, save=True)
        
        assert (model_dir / 'autoencoder').exists()
        assert (model_dir / 'clustering').exists()
        print("    - Models saved successfully")
        
        # Load
        engine2 = MLAnomalyDetectionEngine(model_dir=model_dir)
        engine2.load_models()
        
        assert engine2.autoencoder.model is not None
        assert engine2.clustering.kmeans is not None
        print("    - Models loaded successfully")


# ============================================================================
# Main Test Execution
# ============================================================================

def run_all_tests():
    """Run all tests."""
    print("\n" + "=" * 70)
    print(f"{BLUE}ML ANOMALY DETECTOR - COMPREHENSIVE TEST SUITE{RESET}")
    print("=" * 70)
    print(f"ML Libraries Available: {ML_AVAILABLE}")
    
    runner = TestRunner()
    
    # EventEncoder tests
    print(f"\n{YELLOW}═══ EventEncoder Tests ═══{RESET}")
    runner.test("EventEncoder Initialization", test_event_encoder_initialization)
    runner.test("EventEncoder Fit & Transform", test_event_encoder_fit_transform)
    runner.test("EventEncoder Save & Load", test_event_encoder_save_load)
    
    # AutoencoderAnomalyDetector tests
    print(f"\n{YELLOW}═══ Autoencoder Tests ═══{RESET}")
    runner.test("Autoencoder Initialization", test_autoencoder_initialization)
    runner.test("Autoencoder Build Model", test_autoencoder_build_model)
    runner.test("Autoencoder Training", test_autoencoder_training)
    runner.test("Autoencoder Prediction", test_autoencoder_prediction)
    runner.test("Autoencoder Save & Load", test_autoencoder_save_load)
    
    # ClusteringAnomalyDetector tests
    print(f"\n{YELLOW}═══ Clustering Tests ═══{RESET}")
    runner.test("Clustering Initialization", test_clustering_initialization)
    runner.test("Clustering Training", test_clustering_training)
    runner.test("Clustering Prediction", test_clustering_prediction)
    runner.test("Clustering Save & Load", test_clustering_save_load)
    
    # ClockSkewDetector tests
    print(f"\n{YELLOW}═══ Clock Skew Detection Tests ═══{RESET}")
    runner.test("ClockSkew Initialization", test_clock_skew_initialization)
    runner.test("ClockSkew Linear Drift", test_clock_skew_linear_drift)
    runner.test("ClockSkew Time Jumps", test_clock_skew_time_jumps)
    runner.test("ClockSkew Reverse Chronology", test_clock_skew_reverse_chronology)
    runner.test("ClockSkew Full Analysis", test_clock_skew_full_analysis)
    
    # MLAnomalyDetectionEngine tests
    print(f"\n{YELLOW}═══ ML Engine Tests ═══{RESET}")
    runner.test("Engine Initialization", test_engine_initialization)
    runner.test("Engine Training", test_engine_training)
    runner.test("Engine Detection", test_engine_detection)
    runner.test("Engine Report Generation", test_engine_report_generation)
    runner.test("Engine Save & Load", test_engine_save_load)
    
    # Print summary
    success = runner.summary()
    
    return 0 if success else 1


if __name__ == "__main__":
    import sys
    sys.exit(run_all_tests())
