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
    CanonicalArtifact,
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


def generate_sample_artifacts(n=100):
    """Generate synthetic CanonicalArtifact objects for testing."""
    np.random.seed(42)
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    artifacts = []
    event_types = ['login', 'logout', 'file_access', 'process_start', 'network_conn']
    platforms = ['windows', 'linux']
    artifact_types = ['evtx', 'registry', 'prefetch', 'network', 'file']

    for i in range(n):
        event = {
            'timestamp': base_time + timedelta(minutes=i),
            'event_type': np.random.choice(event_types),
            'platform': np.random.choice(platforms),
            'artifact_type': np.random.choice(artifact_types),
        }
        artifacts.append(CanonicalArtifact(event))
    return artifacts


def generate_sample_events(n=1000, include_anomalies=False):
    """Generate synthetic forensic events as a DataFrame for testing."""
    np.random.seed(42)
    
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    timestamps = [base_time + timedelta(minutes=i) for i in range(n)]
    
    event_data = {
        'timestamp': timestamps,
        'event_type': np.random.choice(['login', 'logout', 'file_access', 'process_start', 'network_conn'], n),
        'platform': np.random.choice(['windows', 'linux'], n),
        'artifact_type': np.random.choice(['evtx', 'registry', 'prefetch', 'network', 'file'], n),
    }
    
    df = pd.DataFrame(event_data)
    
    if include_anomalies and n > 50:
        idx1 = min(n // 2, n - 1)
        df.loc[idx1, 'timestamp'] = base_time + timedelta(hours=48)
        idx2 = min(idx1 + 1, n - 1)
        df.loc[idx2, 'event_type'] = 'RARE_SUSPICIOUS_EVENT'
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
    assert isinstance(encoder.vocabulary, dict), "Vocabulary should be a dict"
    assert len(encoder.vocabulary) == 0, "Vocabulary should start empty"
    print("    - Initialization successful")


def test_event_encoder_encode():
    """Test EventEncoder encode operation."""
    encoder = EventEncoder()
    event = {
        'timestamp': datetime(2024, 1, 1, 12, 0, 0),
        'type': 'login',
    }
    
    features = encoder.encode(event)
    assert isinstance(features, np.ndarray), "Should return ndarray"
    assert len(features) > 0, "Should produce features"
    assert np.isfinite(features).all(), "Features should be finite"
    print(f"    - Encoded to {len(features)} features")
    
    # Encoding a second event should grow vocabulary
    event2 = {'timestamp': datetime(2024, 1, 1, 13, 0, 0), 'type': 'logout'}
    features2 = encoder.encode(event2)
    assert len(encoder.vocabulary) == 2, "Vocabulary should have 2 entries"
    print("    - Vocabulary grows correctly")


def test_event_encoder_decode():
    """Test EventEncoder decode operation."""
    encoder = EventEncoder()
    event = {'timestamp': datetime(2024, 1, 1, 12, 0, 0), 'type': 'login'}
    encoded = encoder.encode(event)
    decoded = encoder.decode(encoded)
    
    assert 'type' in decoded, "Decoded should contain 'type'"
    assert decoded['type'] == 'login', "Decoded type should match"
    print("    - Decode round-trip successful")


# ============================================================================
# AutoencoderAnomalyDetector Tests
# ============================================================================

def test_autoencoder_initialization():
    """Test AutoencoderAnomalyDetector initialization."""
    detector = AutoencoderAnomalyDetector(input_dim=10, encoding_dim=5)
    assert detector.encoding_dim == 5
    assert detector.input_dim == 10
    assert detector.weights_encoder is None, "Weights should be None initially"
    assert detector.weights_decoder is None, "Weights should be None initially"
    assert detector.threshold is None, "Threshold should be None initially"
    print("    - Initialization successful")


def test_autoencoder_training():
    """Test autoencoder training on synthetic data."""
    np.random.seed(42)
    data = np.random.randn(200, 6).astype(np.float32)
    
    detector = AutoencoderAnomalyDetector(input_dim=6, encoding_dim=3)
    detector.fit(data, epochs=50)
    
    assert detector.weights_encoder is not None, "Encoder weights not set"
    assert detector.weights_decoder is not None, "Decoder weights not set"
    assert detector.threshold is not None, "Threshold not set"
    assert detector.threshold > 0, "Invalid threshold"
    assert len(detector.training_loss_history) == 50, "Training history length mismatch"
    print(f"    - Training complete, threshold: {detector.threshold:.6f}")


def test_autoencoder_prediction():
    """Test autoencoder anomaly prediction."""
    np.random.seed(42)
    normal_data = np.random.randn(200, 6).astype(np.float32)
    
    detector = AutoencoderAnomalyDetector(input_dim=6, encoding_dim=3)
    detector.fit(normal_data, epochs=100)
    
    # Test on normal data - most should not be anomalous
    anomalies, scores = detector.predict(normal_data)
    assert len(anomalies) == len(normal_data), "Anomaly flag count mismatch"
    assert len(scores) == len(normal_data), "Score count mismatch"
    print(f"    - Normal data: {anomalies.sum()} anomalies out of {len(normal_data)}")
    
    # Test on outlier data - should detect more anomalies
    outlier_data = np.random.randn(20, 6).astype(np.float32) * 10
    anomalies_out, scores_out = detector.predict(outlier_data)
    print(f"    - Outlier data: {anomalies_out.sum()} anomalies out of {len(outlier_data)}")


def test_autoencoder_predict_with_explanation():
    """Test autoencoder prediction with explanations."""
    np.random.seed(42)
    data = np.random.randn(100, 6).astype(np.float32)
    
    detector = AutoencoderAnomalyDetector(input_dim=6, encoding_dim=3)
    detector.fit(data, epochs=50)
    
    results = detector.predict_with_explanation(data[:5])
    assert len(results) == 5, "Should return results for each input"
    
    for r in results:
        assert 'is_anomaly' in r
        assert 'reconstruction_error' in r
        assert 'normalized_score' in r
        assert 'explanation' in r
        assert 'confidence' in r
        assert 'contributing_features' in r
    
    print("    - Explanations generated correctly")


def test_autoencoder_continue_training():
    """Test autoencoder incremental training."""
    np.random.seed(42)
    data1 = np.random.randn(100, 6).astype(np.float32)
    data2 = np.random.randn(50, 6).astype(np.float32)
    
    detector = AutoencoderAnomalyDetector(input_dim=6, encoding_dim=3)
    detector.fit(data1, epochs=30)
    initial_epochs = len(detector.training_loss_history)
    
    detector.continue_training(data2, additional_epochs=20)
    assert len(detector.training_loss_history) == initial_epochs + 20
    print("    - Continue training successful")


# ============================================================================
# ClusteringAnomalyDetector Tests
# ============================================================================

def test_clustering_initialization():
    """Test ClusteringAnomalyDetector initialization."""
    detector = ClusteringAnomalyDetector(n_clusters=5)
    assert detector.n_clusters == 5
    assert detector.cluster_centers is None, "Cluster centers should be None initially"
    print("    - Initialization successful")


def test_clustering_training():
    """Test clustering model training."""
    np.random.seed(42)
    data = np.random.randn(200, 4).astype(np.float32)
    
    detector = ClusteringAnomalyDetector(n_clusters=3)
    detector.fit(data)
    
    assert detector.cluster_centers is not None, "Cluster centers not set"
    assert detector.cluster_centers.shape[0] == 3, "Should have 3 cluster centers"
    print("    - Training complete with 3 cluster centers")


def test_clustering_prediction():
    """Test clustering anomaly prediction."""
    np.random.seed(42)
    normal_data = np.random.randn(200, 4).astype(np.float32)
    
    detector = ClusteringAnomalyDetector(n_clusters=3)
    detector.fit(normal_data)
    
    anomalies, scores = detector.predict(normal_data)
    assert len(anomalies) == len(normal_data), "Anomaly flag count mismatch"
    assert len(scores) == len(normal_data), "Score count mismatch"
    print(f"    - Normal data: {anomalies.sum()} anomalies out of {len(normal_data)}")
    
    # Outlier data
    outlier_data = np.random.randn(20, 4).astype(np.float32) * 10
    anomalies_out, scores_out = detector.predict(outlier_data)
    print(f"    - Outlier data: {anomalies_out.sum()} anomalies out of {len(outlier_data)}")


def test_clustering_unfitted_prediction():
    """Test clustering prediction without fitting."""
    detector = ClusteringAnomalyDetector(n_clusters=3)
    data = np.random.randn(10, 4).astype(np.float32)
    anomalies, scores = detector.predict(data)
    assert not anomalies.any(), "Unfitted detector should not flag anomalies"
    print("    - Unfitted prediction returns zeros correctly")


# ============================================================================
# ClockSkewDetector Tests
# ============================================================================

def test_clock_skew_initialization():
    """Test ClockSkewDetector initialization."""
    detector = ClockSkewDetector()
    assert detector is not None
    assert detector.tolerance == 300
    print("    - Initialization successful")


def test_clock_skew_calibrate():
    """Test ClockSkewDetector calibration."""
    detector = ClockSkewDetector()
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    timestamps = [base_time + timedelta(minutes=i) for i in range(100)]
    
    detector.calibrate(timestamps)
    assert detector.min_timestamp == timestamps[0]
    assert detector.max_timestamp == timestamps[-1]
    assert len(detector.baseline_timestamps) == 100
    print("    - Calibration successful")


def test_clock_skew_detect_normal():
    """Test clock skew detection on normal timestamps."""
    detector = ClockSkewDetector()
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    timestamps = [base_time + timedelta(minutes=i) for i in range(100)]
    detector.calibrate(timestamps)
    
    # Test with a timestamp within range
    result = detector.detect_skew(base_time + timedelta(minutes=50))
    assert not result['has_skew'], "Should not detect skew for in-range timestamp"
    print("    - Normal timestamp: no skew detected")


def test_clock_skew_detect_anomalous():
    """Test clock skew detection on anomalous timestamps."""
    detector = ClockSkewDetector(tolerance_seconds=60)
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    timestamps = [base_time + timedelta(minutes=i) for i in range(10)]
    detector.calibrate(timestamps)
    
    # Test with a timestamp far outside range
    far_future = base_time + timedelta(days=30)
    result = detector.detect_skew(far_future)
    assert result['has_skew'], "Should detect skew for far-future timestamp"
    assert result['confidence'] > 0, "Confidence should be positive"
    print(f"    - Anomalous timestamp: skew detected, confidence={result['confidence']:.2f}")


def test_clock_skew_no_baseline():
    """Test clock skew detection without baseline."""
    detector = ClockSkewDetector()
    result = detector.detect_skew(datetime.now())
    assert not result['has_skew'], "Should not detect skew without baseline"
    print("    - No baseline: correctly returns no skew")


# ============================================================================
# MLAnomalyDetectionEngine Tests
# ============================================================================

def test_engine_initialization():
    """Test MLAnomalyDetectionEngine initialization."""
    engine = MLAnomalyDetectionEngine(case_id='test_case')
    
    assert engine.encoder is not None
    assert engine.clustering_detector is not None
    assert engine.clock_detector is not None
    assert engine.case_id == 'test_case'
    assert not engine.trained
    print("    - Engine initialized with all components")


def test_engine_training_with_dataframe():
    """Test engine training with DataFrame input."""
    engine = MLAnomalyDetectionEngine(case_id='train_test')
    events = generate_sample_events(200)
    
    engine.train(events, save=False, epochs=30)
    
    assert engine.trained, "Engine should be marked as trained"
    assert len(engine.baselines) > 0, "Should have behavioral baselines"
    print(f"    - Engine trained, {len(engine.baselines)} baselines created")


def test_engine_training_with_artifacts():
    """Test engine training with artifact list input."""
    engine = MLAnomalyDetectionEngine(case_id='artifact_test')
    artifacts = generate_sample_artifacts(100)
    
    engine.train(artifacts, save=False, epochs=30)
    
    assert engine.trained
    print(f"    - Engine trained with artifacts, {len(engine.baselines)} baselines")


def test_engine_detection():
    """Test engine anomaly detection."""
    engine = MLAnomalyDetectionEngine(case_id='detect_test')
    
    # Train
    train_events = generate_sample_events(200)
    engine.train(train_events, save=False, epochs=30)
    
    # Detect
    test_events = generate_sample_events(50, include_anomalies=True)
    findings = engine.detect_anomalies(test_events)
    
    assert isinstance(findings, list), "Should return list of findings"
    print(f"    - Detected {len(findings)} findings from {50} events")


def test_engine_report_generation():
    """Test anomaly report generation."""
    engine = MLAnomalyDetectionEngine(case_id='report_test')
    
    # Train and detect
    train_events = generate_sample_events(200)
    engine.train(train_events, save=False, epochs=30)
    
    test_events = generate_sample_events(50, include_anomalies=True)
    findings = engine.detect_anomalies(test_events)
    
    # Generate report
    report = engine.get_anomaly_report(findings)
    
    assert 'total_events' in report
    assert 'anomalies_detected' in report
    assert 'anomaly_rate' in report
    assert 'clock_skew_analysis' in report
    
    print(f"    - Report generated:")
    print(f"      Total events: {report['total_events']}")
    print(f"      Anomalies: {report['anomalies_detected']}")
    print(f"      Rate: {report['anomaly_rate']:.2%}")


def test_engine_continue_training():
    """Test engine incremental training."""
    engine = MLAnomalyDetectionEngine(case_id='continue_test')
    
    # Initial training
    train_events = generate_sample_events(200)
    engine.train(train_events, save=False, epochs=30)
    
    # Continue training with more data
    more_events = generate_sample_events(100)
    engine.continue_training(more_events, additional_epochs=20)
    
    assert engine.trained
    print("    - Continue training successful")


def test_engine_empty_report():
    """Test report with no findings."""
    engine = MLAnomalyDetectionEngine(case_id='empty_test')
    report = engine.get_anomaly_report([])
    
    assert report['total'] == 0
    assert report['anomalies_detected'] == 0
    print("    - Empty report generated correctly")


# ============================================================================
# Main Test Execution
# ============================================================================

def run_all_tests():
    """Run all tests."""
    print("\n" + "=" * 70)
    print(f"{BLUE}ML ANOMALY DETECTOR - COMPREHENSIVE TEST SUITE{RESET}")
    print("=" * 70)
    
    runner = TestRunner()
    
    # EventEncoder tests
    print(f"\n{YELLOW}═══ EventEncoder Tests ═══{RESET}")
    runner.test("EventEncoder Initialization", test_event_encoder_initialization)
    runner.test("EventEncoder Encode", test_event_encoder_encode)
    runner.test("EventEncoder Decode", test_event_encoder_decode)
    
    # AutoencoderAnomalyDetector tests
    print(f"\n{YELLOW}═══ Autoencoder Tests ═══{RESET}")
    runner.test("Autoencoder Initialization", test_autoencoder_initialization)
    runner.test("Autoencoder Training", test_autoencoder_training)
    runner.test("Autoencoder Prediction", test_autoencoder_prediction)
    runner.test("Autoencoder Predict with Explanation", test_autoencoder_predict_with_explanation)
    runner.test("Autoencoder Continue Training", test_autoencoder_continue_training)
    
    # ClusteringAnomalyDetector tests
    print(f"\n{YELLOW}═══ Clustering Tests ═══{RESET}")
    runner.test("Clustering Initialization", test_clustering_initialization)
    runner.test("Clustering Training", test_clustering_training)
    runner.test("Clustering Prediction", test_clustering_prediction)
    runner.test("Clustering Unfitted Prediction", test_clustering_unfitted_prediction)
    
    # ClockSkewDetector tests
    print(f"\n{YELLOW}═══ Clock Skew Detection Tests ═══{RESET}")
    runner.test("ClockSkew Initialization", test_clock_skew_initialization)
    runner.test("ClockSkew Calibrate", test_clock_skew_calibrate)
    runner.test("ClockSkew Detect Normal", test_clock_skew_detect_normal)
    runner.test("ClockSkew Detect Anomalous", test_clock_skew_detect_anomalous)
    runner.test("ClockSkew No Baseline", test_clock_skew_no_baseline)
    
    # MLAnomalyDetectionEngine tests
    print(f"\n{YELLOW}═══ ML Engine Tests ═══{RESET}")
    runner.test("Engine Initialization", test_engine_initialization)
    runner.test("Engine Training (DataFrame)", test_engine_training_with_dataframe)
    runner.test("Engine Training (Artifacts)", test_engine_training_with_artifacts)
    runner.test("Engine Detection", test_engine_detection)
    runner.test("Engine Report Generation", test_engine_report_generation)
    runner.test("Engine Continue Training", test_engine_continue_training)
    runner.test("Engine Empty Report", test_engine_empty_report)
    
    # Print summary
    success = runner.summary()
    
    return 0 if success else 1


if __name__ == "__main__":
    import sys
    sys.exit(run_all_tests())
