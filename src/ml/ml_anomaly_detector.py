"""
FEPD Intelligence Core - ML Anomaly Detection Engine
Constitutional Implementation: Court-Defensible, Explainable, Read-Only

This module operates under the FEPD constitutional constraints:
- Evidence is immutable and sacred
- All operations are read-only
- Every output must be explainable
- All findings must be court-defensible
- Behavioral intelligence (UEBA) is primary
- Artifact-first reasoning
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import hashlib
import json
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# FORENSIC SCORE UTILITIES
# ============================================================================

def normalize_anomaly_scores(scores: np.ndarray) -> np.ndarray:
    """
    Normalize anomaly scores to 0-1 range with proper handling.
    
    This ensures scores are meaningful and relative:
    - 0.05 = Normal
    - 0.35 = Suspicious  
    - 0.72 = Anomalous
    - 0.93 = Critical
    
    Args:
        scores: Raw anomaly scores (e.g., reconstruction errors)
        
    Returns:
        Normalized scores in [0, 1] range
    """
    if len(scores) == 0:
        return scores
    
    min_score = np.min(scores)
    max_score = np.max(scores)
    
    # Avoid division by zero when all scores are identical
    if max_score - min_score < 1e-9:
        # All scores are the same - return midpoint
        return np.full_like(scores, 0.5)
    
    # Normalize with epsilon for numerical stability
    normalized = (scores - min_score) / (max_score - min_score + 1e-9)
    return np.clip(normalized, 0.0, 1.0)


def score_to_severity(score: float) -> str:
    """
    Map normalized anomaly score to forensic severity level.
    
    Args:
        score: Normalized score in [0, 1] range
        
    Returns:
        Severity string: 'low', 'medium', 'high', or 'critical'
    """
    if score < 0.3:
        return 'low'
    elif score < 0.6:
        return 'medium'
    elif score < 0.85:
        return 'high'
    else:
        return 'critical'


def generate_forensic_flags(
    score: float,
    cluster_size: Optional[int] = None,
    timestamp_delta: Optional[float] = None,
    user_changed: bool = False,
    is_rare_event: bool = False
) -> List[str]:
    """
    Generate forensic flag strings based on detection conditions.
    
    Args:
        score: Normalized anomaly score
        cluster_size: Size of the cluster this event belongs to
        timestamp_delta: Time delta from expected (seconds)
        user_changed: Whether user account changed unexpectedly
        is_rare_event: Whether this event type is rare
        
    Returns:
        List of forensic flag strings (e.g., ['RARE_BEHAVIOR', 'TIME_ANOMALY'])
    """
    flags = []
    
    # Score-based flags
    if score > 0.85:
        flags.append('RARE_BEHAVIOR')
    elif score > 0.6:
        flags.append('UNUSUAL_PATTERN')
    
    # Cluster-based flags
    if cluster_size is not None and cluster_size < 3:
        flags.append('OUTLIER_GROUP')
    
    # Time-based flags
    if timestamp_delta is not None:
        if abs(timestamp_delta) > 3600:  # More than 1 hour off
            flags.append('TIME_ANOMALY')
        if timestamp_delta < -60:  # Negative time (clock manipulation)
            flags.append('CLOCK_SKEW')
    
    # User-based flags
    if user_changed:
        flags.append('ACCOUNT_SHIFT')
    
    # Rarity flags
    if is_rare_event:
        flags.append('FIRST_OCCURRENCE')
    
    return flags


def flags_to_string(flags: List[str]) -> str:
    """Convert flag list to comma-separated string for display."""
    return ', '.join(flags) if flags else ''


# ============================================================================
# CANONICAL ARTIFACT SCHEMA
# ============================================================================

class CanonicalArtifact:
    """
    Universal artifact schema for FEPD.
    All evidence must be normalized to this format.
    """
    
    REQUIRED_FIELDS = ['timestamp', 'platform', 'artifact_type', 'event_type']
    PLATFORMS = ['windows', 'linux', 'macos', 'android', 'ios', 'cloud', 'unknown']
    ARTIFACT_TYPES = ['evtx', 'registry', 'browser', 'memory', 'network', 'mobile', 'filesystem', 'prefetch', 'mft', 'unknown']
    
    def __init__(self, artifact_data: Dict[str, Any]):
        """Initialize canonical artifact with validation."""
        self.timestamp = artifact_data.get('timestamp')
        self.platform = artifact_data.get('platform', 'unknown')
        self.artifact_type = artifact_data.get('artifact_type', 'unknown')
        self.user_id = artifact_data.get('user_id')
        self.host = artifact_data.get('host')
        self.event_type = artifact_data.get('event_type')
        self.process = artifact_data.get('process')
        self.file_path = artifact_data.get('file_path')
        self.ip = artifact_data.get('ip')
        self.raw = artifact_data.get('raw', {})
        
        # Compute immutable artifact ID
        self.artifact_id = self._compute_artifact_id()
        
    def _compute_artifact_id(self) -> str:
        """Compute cryptographic hash as immutable artifact identifier."""
        canonical_repr = json.dumps({
            'timestamp': str(self.timestamp),
            'platform': self.platform,
            'artifact_type': self.artifact_type,
            'event_type': self.event_type,
            'raw': self.raw
        }, sort_keys=True)
        return hashlib.sha256(canonical_repr.encode()).hexdigest()[:16]
    
    def validate(self) -> Tuple[bool, List[str]]:
        """Validate artifact against constitutional requirements."""
        errors = []
        
        if not self.timestamp:
            errors.append("Missing required field: timestamp")
        if self.platform not in self.PLATFORMS:
            errors.append(f"Invalid platform: {self.platform}")
        if self.artifact_type not in self.ARTIFACT_TYPES:
            errors.append(f"Invalid artifact_type: {self.artifact_type}")
            
        return len(errors) == 0, errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Export to dictionary format."""
        return {
            'artifact_id': self.artifact_id,
            'timestamp': self.timestamp,
            'platform': self.platform,
            'artifact_type': self.artifact_type,
            'user_id': self.user_id,
            'host': self.host,
            'event_type': self.event_type,
            'process': self.process,
            'file_path': self.file_path,
            'ip': self.ip,
            'raw': self.raw
        }


# ============================================================================
# COURT-DEFENSIBLE FINDING SCHEMA
# ============================================================================

class ForensicFinding:
    """
    Constitutional finding format - court-defensible, explainable, auditable.
    """
    
    def __init__(
        self,
        finding_id: str,
        finding_type: str,
        severity: str,
        score: float,
        title: str,
        description: str,
        evidence_ids: List[str],
        explanations: List[str],
        recommendation: str,
        confidence: float = 0.0,
        metadata: Optional[Dict] = None
    ):
        self.finding_id = finding_id
        self.type = finding_type
        self.severity = severity  # low, medium, high, critical
        self.score = score  # 0.0 - 1.0
        self.title = title
        self.description = description
        self.evidence = evidence_ids
        self.explanations = explanations
        self.recommendation = recommendation
        self.confidence = confidence
        self.metadata = metadata or {}
        self.timestamp = datetime.now()
        
    def to_dict(self) -> Dict[str, Any]:
        """Export to court-defensible report format."""
        return {
            'finding_id': self.finding_id,
            'type': self.type,
            'severity': self.severity,
            'score': self.score,
            'confidence': self.confidence,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence,
            'explanations': self.explanations,
            'recommendation': self.recommendation,
            'metadata': self.metadata,
            'timestamp': str(self.timestamp)
        }
    
    def is_court_defensible(self) -> Tuple[bool, List[str]]:
        """Validate court-defensibility requirements."""
        issues = []
        
        if not self.explanations:
            issues.append("No explanations provided - not defensible")
        if not self.evidence:
            issues.append("No evidence artifacts linked - not defensible")
        if self.confidence < 0.5:
            issues.append("Low confidence (<50%) - requires manual validation")
        if not self.recommendation:
            issues.append("No recommendation - incomplete finding")
            
        return len(issues) == 0, issues


# ============================================================================
# BEHAVIORAL BASELINE ENGINE (UEBA)
# ============================================================================

class BehavioralBaseline:
    """
    User and Entity Behavior Analytics (UEBA) engine.
    Learns "normal" behavior to detect "unusual" patterns.
    """
    
    def __init__(self, entity_id: str):
        """Initialize behavioral baseline for an entity (user/host)."""
        self.entity_id = entity_id
        self.login_patterns = []  # Hour-of-day distribution
        self.process_baseline = set()  # Normal processes
        self.file_access_baseline = set()  # Normal file paths
        self.network_baseline = set()  # Normal IPs/domains
        self.session_durations = []
        self.active_hours = set()
        self.artifact_count = 0
        
    def learn(self, artifacts: List[CanonicalArtifact]):
        """Build behavioral baseline from historical artifacts."""
        for artifact in artifacts:
            self.artifact_count += 1
            
            # Learn time-of-day patterns
            if artifact.timestamp:
                if isinstance(artifact.timestamp, str):
                    try:
                        ts = datetime.fromisoformat(artifact.timestamp)
                    except ValueError:
                        ts = None
                else:
                    ts = artifact.timestamp
                    
                if ts:
                    self.active_hours.add(ts.hour)
                    self.login_patterns.append(ts.hour)
            
            # Learn process baselines
            if artifact.process:
                self.process_baseline.add(artifact.process)
            
            # Learn file access baselines
            if artifact.file_path:
                self.file_access_baseline.add(artifact.file_path)
            
            # Learn network baselines
            if artifact.ip:
                self.network_baseline.add(artifact.ip)
    
    def detect_deviation(self, artifact: CanonicalArtifact) -> Dict[str, Any]:
        """
        Detect behavioral deviations from baseline.
        
        Uses a scoring approach where multiple minor deviations are needed
        to flag as anomaly, unless a single high-severity deviation occurs.
        """
        deviations = {
            'is_anomaly': False,
            'deviation_score': 0.0,
            'anomaly_types': [],
            'explanations': []
        }
        
        deviation_count = 0
        
        # Time-of-day deviation (lower weight - time variation is common)
        if artifact.timestamp:
            if isinstance(artifact.timestamp, str):
                try:
                    ts = datetime.fromisoformat(artifact.timestamp)
                except ValueError:
                    ts = None
            else:
                ts = artifact.timestamp
                
            if ts and self.active_hours:
                # Check if hour is within 2 hours of any known active hour
                hour_deviation = min(
                    min(abs(ts.hour - h), 24 - abs(ts.hour - h)) 
                    for h in self.active_hours
                ) if self.active_hours else 0
                
                if hour_deviation > 4:  # More than 4 hours from any baseline hour
                    deviation_count += 1
                    deviations['anomaly_types'].append('unusual_time')
                    deviations['explanations'].append(
                        f"Event at {ts.hour:02d}:00 is {hour_deviation}h from nearest baseline hour"
                    )
                    deviations['deviation_score'] += 0.15
        
        # Process deviation (medium weight)
        if artifact.process and self.process_baseline:
            if artifact.process not in self.process_baseline:
                deviation_count += 1
                deviations['anomaly_types'].append('new_process')
                deviations['explanations'].append(
                    f"Process '{artifact.process}' not in baseline ({len(self.process_baseline)} known)"
                )
                deviations['deviation_score'] += 0.25
        
        # File access deviation (lower weight - file access varies)
        if artifact.file_path and self.file_access_baseline:
            if artifact.file_path not in self.file_access_baseline:
                # Only flag if baseline has significant data
                if len(self.file_access_baseline) > 20:
                    deviation_count += 1
                    deviations['anomaly_types'].append('new_file_access')
                    deviations['explanations'].append(
                        f"New file path: '{artifact.file_path}'"
                    )
                    deviations['deviation_score'] += 0.1
        
        # Network deviation (high weight - new IPs are suspicious)
        if artifact.ip and self.network_baseline:
            if artifact.ip not in self.network_baseline:
                deviation_count += 1
                deviations['anomaly_types'].append('new_network_connection')
                deviations['explanations'].append(
                    f"Connection to new IP '{artifact.ip}' (baseline: {len(self.network_baseline)} known)"
                )
                deviations['deviation_score'] += 0.35
        
        # Only flag as anomaly if score exceeds threshold OR multiple deviations
        anomaly_threshold = 0.5
        deviations['deviation_score'] = min(1.0, deviations['deviation_score'])
        
        # Require significant evidence before flagging
        if deviations['deviation_score'] >= anomaly_threshold or deviation_count >= 3:
            deviations['is_anomaly'] = True
        
        return deviations


class EventEncoder:
    """Encode forensic events for ML processing."""
    
    def __init__(self):
        """Initialize the event encoder."""
        self.vocabulary = {}
        
    def encode(self, event: Dict[str, Any]) -> np.ndarray:
        """Encode an event into numerical features."""
        features = []
        # Encode timestamp
        if 'timestamp' in event:
            ts = event['timestamp']
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except (ValueError, AttributeError):
                    ts = datetime.now()
            features.append(ts.timestamp() if hasattr(ts, 'timestamp') else 0)
        else:
            features.append(0)
        
        # Encode event type
        event_type = event.get('type', 'unknown')
        if event_type not in self.vocabulary:
            self.vocabulary[event_type] = len(self.vocabulary)
        features.append(self.vocabulary[event_type])
        
        return np.array(features, dtype=np.float32)
    
    def decode(self, encoded: np.ndarray) -> Dict[str, Any]:
        """Decode numerical features back to event."""
        if len(encoded) < 2:
            return {}
        
        timestamp = datetime.fromtimestamp(float(encoded[0])) if encoded[0] > 0 else None
        type_idx = int(float(encoded[1]))
        
        # Reverse vocabulary lookup
        event_type = 'unknown'
        for k, v in self.vocabulary.items():
            if v == type_idx:
                event_type = k
                break
        
        return {
            'timestamp': timestamp,
            'type': event_type
        }


class ClockSkewDetector:
    """Detect timestamp anomalies and clock manipulation (anti-forensics)."""
    
    def __init__(self, tolerance_seconds: float = 300):
        """Initialize with tolerance threshold."""
        self.tolerance = tolerance_seconds
        self.baseline_timestamps = []
        self.min_timestamp = None
        self.max_timestamp = None
        self.timestamp_history = []
        
    def calibrate(self, timestamps: List[datetime]):
        """Establish baseline from known-good timestamps."""
        self.baseline_timestamps = sorted(timestamps)
        self.timestamp_history = list(timestamps)
        if timestamps:
            self.min_timestamp = min(timestamps)
            self.max_timestamp = max(timestamps)
    
    def detect_skew(self, timestamp: datetime) -> Dict[str, Any]:
        """
        Detect clock skew with full court-defensible explanation.
        
        Clock skew is detected when a timestamp falls significantly outside
        the expected time range of the evidence, suggesting potential
        timestamp manipulation (anti-forensics technique).
        
        Returns:
            {
                'has_skew': bool,
                'skew_seconds': float,
                'explanation': str,
                'confidence': float
            }
        """
        if not self.min_timestamp or not self.max_timestamp:
            return {
                'has_skew': False,
                'skew_seconds': 0.0,
                'explanation': 'No baseline - cannot detect skew',
                'confidence': 0.0
            }
        
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except ValueError:
                return {
                    'has_skew': True,
                    'skew_seconds': 0.0,
                    'explanation': 'Invalid timestamp format',
                    'confidence': 1.0
                }
        
        # Calculate time range of baseline evidence
        time_range = (self.max_timestamp - self.min_timestamp).total_seconds()
        # Add buffer equal to tolerance on each side of the range
        buffer = max(self.tolerance, time_range * 0.1)  # 10% of range or tolerance, whichever is larger
        
        # Check if timestamp is within the extended range
        if timestamp < self.min_timestamp:
            delta = (self.min_timestamp - timestamp).total_seconds()
        elif timestamp > self.max_timestamp:
            delta = (timestamp - self.max_timestamp).total_seconds()
        else:
            delta = 0  # Within range
        
        # Only flag as skew if significantly outside the range
        has_skew = delta > buffer
        
        if has_skew:
            explanation = (
                f"Timestamp {timestamp.isoformat()} is {delta:.1f}s outside baseline range "
                f"[{self.min_timestamp.isoformat()} to {self.max_timestamp.isoformat()}]. "
                f"Buffer: {buffer:.1f}s. POTENTIAL CLOCK MANIPULATION."
            )
        else:
            explanation = f"Timestamp within expected range."
        
        return {
            'has_skew': has_skew,
            'skew_seconds': delta,
            'explanation': explanation,
            'confidence': min(1.0, delta / (buffer + 1)) if has_skew else 0.0
        }


class ClusteringAnomalyDetector:
    """Detect anomalies using clustering algorithms."""
    
    def __init__(self, n_clusters: int = 5):
        """Initialize clustering-based detector.
        
        Args:
            n_clusters: Number of clusters for normal behavior
        """
        self.n_clusters = n_clusters
        self.cluster_centers = None
        
    def fit(self, data: np.ndarray):
        """Fit clustering model on normal data.
        
        Args:
            data: Normal behavior data
        """
        # Simple K-means implementation
        if len(data) == 0:
            return
        
        # Initialize random centers
        indices = np.random.choice(len(data), min(self.n_clusters, len(data)), replace=False)
        self.cluster_centers = data[indices].copy()
        
        # Iterate to convergence (simplified)
        for _ in range(10):
            # Assign to nearest cluster
            distances = np.array([[np.linalg.norm(x - c) for c in self.cluster_centers] for x in data])
            labels = np.argmin(distances, axis=1)
            
            # Update centers
            for i in range(self.n_clusters):
                cluster_points = data[labels == i]
                if len(cluster_points) > 0:
                    self.cluster_centers[i] = cluster_points.mean(axis=0)
    
    def predict(self, data: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomalies based on distance to clusters.
        
        Args:
            data: Data to evaluate
            
        Returns:
            Tuple of (anomaly_flags, anomaly_scores)
        """
        if self.cluster_centers is None:
            return np.zeros(len(data), dtype=bool), np.zeros(len(data))
        
        # Calculate distance to nearest cluster
        distances = np.array([[np.linalg.norm(x - c) for c in self.cluster_centers] for x in data])
        min_distances = np.min(distances, axis=1)
        
        # Threshold based on mean + 2*std
        threshold = np.mean(min_distances) + 2 * np.std(min_distances)
        anomalies = min_distances > threshold
        
        # Normalize scores
        scores = np.clip(min_distances / (threshold + 1e-8), 0, 1)
        
        return anomalies, scores


class AutoencoderAnomalyDetector:
    """
    Reconstruction-based anomaly detection with full explainability.
    Constitutional constraints: deterministic, replayable, auditable.
    
    Uses normalized features and proper threshold calibration to avoid
    marking all artifacts as anomalies.
    """
    
    def __init__(self, input_dim: int = 10, encoding_dim: int = 5, random_seed: int = 42):
        """Initialize with fixed random seed for determinism."""
        np.random.seed(random_seed)
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.weights_encoder = None
        self.weights_decoder = None
        self.threshold = None
        self.training_loss_history = []
        # Feature normalization parameters
        self.feature_mean = None
        self.feature_std = None
        
    def _sigmoid(self, x: np.ndarray) -> np.ndarray:
        """Sigmoid activation (deterministic)."""
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))
    
    def _normalize_features(self, data: np.ndarray, fit: bool = False) -> np.ndarray:
        """Normalize features to zero mean and unit variance."""
        if fit:
            self.feature_mean = np.mean(data, axis=0)
            self.feature_std = np.std(data, axis=0)
            # Prevent division by zero
            self.feature_std = np.where(self.feature_std < 1e-8, 1.0, self.feature_std)
        
        if self.feature_mean is None or self.feature_std is None:
            return data
        
        return (data - self.feature_mean) / self.feature_std
    
    def fit(self, data: np.ndarray, epochs: int = 200, learning_rate: float = 0.01):
        """Train autoencoder with full audit trail and proper normalization."""
        if len(data) == 0:
            logger.warning("No data provided for training")
            return
        
        # Normalize features first (critical for proper threshold calculation)
        normalized_data = self._normalize_features(data, fit=True)
        
        # Initialize weights (deterministic)
        self.weights_encoder = np.random.randn(self.input_dim, self.encoding_dim) * 0.1
        self.weights_decoder = np.random.randn(self.encoding_dim, self.input_dim) * 0.1
        
        # Training loop with audit
        for epoch in range(epochs):
            # Forward pass
            encoded = self._sigmoid(normalized_data @ self.weights_encoder)
            reconstructed = self._sigmoid(encoded @ self.weights_decoder)
            
            # Loss
            error = normalized_data - reconstructed
            loss = np.mean(error ** 2)
            self.training_loss_history.append(loss)
            
            # Backward pass
            grad_decoder = -2 * encoded.T @ error / len(normalized_data)
            self.weights_decoder -= learning_rate * grad_decoder
            
            decoder_error = error @ self.weights_decoder.T
            grad_encoder = -2 * normalized_data.T @ (decoder_error * encoded * (1 - encoded)) / len(normalized_data)
            self.weights_encoder -= learning_rate * grad_encoder
        
        # Set threshold based on reconstruction errors of training data
        # Using percentile-based threshold for robustness (95th percentile)
        reconstructed = self._sigmoid(self._sigmoid(normalized_data @ self.weights_encoder) @ self.weights_decoder)
        errors = np.mean((normalized_data - reconstructed) ** 2, axis=1)
        
        # Use 95th percentile as threshold - only top 5% should be flagged as anomalies
        self.threshold = np.percentile(errors, 95)
        # Ensure minimum threshold
        self.threshold = max(self.threshold, 0.01)
        
        logger.info(f"Autoencoder trained: {epochs} epochs, final loss={loss:.6f}, threshold={self.threshold:.6f}")
    
    def continue_training(self, data: np.ndarray, additional_epochs: int = 100, learning_rate: float = 0.01):
        """
        Continue training existing model for additional epochs.
        Useful for incremental learning without losing previous training.
        """
        if self.weights_encoder is None or self.weights_decoder is None:
            logger.warning("No existing model to continue training. Use fit() first.")
            return
        
        if len(data) == 0:
            logger.warning("No data provided for continued training")
            return
        
        # Normalize using existing parameters
        normalized_data = self._normalize_features(data, fit=False)
        
        logger.info(f"Continuing training for {additional_epochs} additional epochs...")
        initial_loss = self.training_loss_history[-1] if self.training_loss_history else 0.0
        
        # Continue training loop
        for epoch in range(additional_epochs):
            # Forward pass
            encoded = self._sigmoid(normalized_data @ self.weights_encoder)
            reconstructed = self._sigmoid(encoded @ self.weights_decoder)
            
            # Loss
            error = normalized_data - reconstructed
            loss = np.mean(error ** 2)
            self.training_loss_history.append(loss)
            
            # Backward pass
            grad_decoder = -2 * encoded.T @ error / len(normalized_data)
            self.weights_decoder -= learning_rate * grad_decoder
            
            decoder_error = error @ self.weights_decoder.T
            grad_encoder = -2 * normalized_data.T @ (decoder_error * encoded * (1 - encoded)) / len(normalized_data)
            self.weights_encoder -= learning_rate * grad_encoder
        
        # Update threshold with percentile-based approach
        reconstructed = self._sigmoid(self._sigmoid(normalized_data @ self.weights_encoder) @ self.weights_decoder)
        errors = np.mean((normalized_data - reconstructed) ** 2, axis=1)
        self.threshold = max(np.percentile(errors, 95), 0.01)
        
        logger.info(f"Continued training: {additional_epochs} additional epochs, "
                   f"loss improved from {initial_loss:.6f} to {loss:.6f}, "
                   f"new threshold={self.threshold:.6f}")
    
    def predict(self, data: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomalies based on reconstruction error."""
        if self.weights_encoder is None or self.weights_decoder is None:
            return np.zeros(len(data), dtype=bool), np.zeros(len(data))
        
        # Normalize using training parameters
        normalized_data = self._normalize_features(data, fit=False)
        
        # Reconstruct and compute error
        encoded = self._sigmoid(normalized_data @ self.weights_encoder)
        reconstructed = self._sigmoid(encoded @ self.weights_decoder)
        reconstruction_errors = np.mean((normalized_data - reconstructed) ** 2, axis=1)
        
        # Detect anomalies - use calibrated threshold
        if self.threshold is None:
            self.threshold = max(np.percentile(reconstruction_errors, 95), 0.01)
        
        anomalies = reconstruction_errors > self.threshold
        # Normalize scores using the batch-aware normalization function
        # This ensures scores are relative and meaningful (not all 1.0)
        scores = normalize_anomaly_scores(reconstruction_errors)
        
        return anomalies, scores
    
    def predict_with_explanation(self, data: np.ndarray) -> List[Dict[str, Any]]:
        """
        Predict anomalies with full constitutional explanation.
        
        Returns list of:
        {
            'is_anomaly': bool,
            'reconstruction_error': float,
            'normalized_score': float,
            'explanation': str,
            'confidence': float,
            'contributing_features': List[int]
        }
        """
        if self.weights_encoder is None:
            return [{'is_anomaly': False, 'explanation': 'Model not trained'}] * len(data)
        
        if self.threshold is None:
            self.threshold = 0.1  # Default threshold if not set
        
        # Normalize data before prediction
        normalized_data = self._normalize_features(data, fit=False)
        
        encoded = self._sigmoid(normalized_data @ self.weights_encoder)
        reconstructed = self._sigmoid(encoded @ self.weights_decoder)
        
        results = []
        for i, (original, recon) in enumerate(zip(normalized_data, reconstructed)):
            feature_errors = (original - recon) ** 2
            total_error = np.mean(feature_errors)
            
            is_anomaly = total_error > self.threshold
            # More conservative scoring - divide by 2x threshold
            score = min(1.0, total_error / (self.threshold * 2 + 1e-8))
            
            # Identify top contributing features
            top_features = np.argsort(feature_errors)[-3:][::-1].tolist()
            
            explanation = (
                f"Reconstruction error: {total_error:.6f} "
                f"(threshold: {self.threshold:.6f}). "
                f"Top anomalous features: {top_features}. "
                f"{'ANOMALY' if is_anomaly else 'NORMAL'}."
            )
            
            results.append({
                'is_anomaly': is_anomaly,
                'reconstruction_error': float(total_error),
                'normalized_score': float(score),
                'explanation': explanation,
                'confidence': float(score) if is_anomaly else float(1.0 - score),
                'contributing_features': top_features
            })
        
        return results


class MLAnomalyDetectionEngine:
    """
    Constitutional ML Anomaly Detection Engine.
    
    Principles:
    - Read-only operations
    - Artifact-first reasoning
    - UEBA primary layer
    - Full explainability
    - Deterministic outputs
    - Chain-of-custody logging
    """
    
    def __init__(self, case_id: str = 'default', random_seed: int = 42):
        """Initialize engine with case context."""
        self.case_id = case_id
        self.random_seed = random_seed
        
        # Behavioral baselines per entity
        self.baselines: Dict[str, BehavioralBaseline] = {}
        
        # Detectors
        self.encoder = EventEncoder()
        self.clock_detector = ClockSkewDetector()
        self.clustering_detector = ClusteringAnomalyDetector()
        self.autoencoder_detector = None  # Lazy initialization
        
        # Audit trail
        self.operations_log = []
        self.trained = False
        self.last_analyzed_count = 0
        
        logger.info(f"MLAnomalyDetectionEngine initialized for case: {case_id}")
    
    def normalize_dataframe(self, df) -> List[CanonicalArtifact]:
        """
        Convert pandas DataFrame to canonical artifact format.
        
        Args:
            df: pandas DataFrame with event data
            
        Returns:
            List of CanonicalArtifact objects
        """
        import pandas as pd
        
        if not isinstance(df, pd.DataFrame):
            raise ValueError("Input must be a pandas DataFrame")
        
        artifacts = []
        for _, row in df.iterrows():
            event_dict = row.to_dict()
            
            # Map common column names to canonical fields
            if 'ts_utc' in event_dict and 'timestamp' not in event_dict:
                event_dict['timestamp'] = event_dict['ts_utc']
            if 'artifact_source' in event_dict and 'artifact_type' not in event_dict:
                # Normalize artifact_source to lowercase artifact_type
                source = str(event_dict['artifact_source']).lower()
                event_dict['artifact_type'] = source if source in CanonicalArtifact.ARTIFACT_TYPES else 'unknown'
            
            # Ensure required fields exist with defaults
            if 'timestamp' not in event_dict or not event_dict['timestamp']:
                event_dict['timestamp'] = datetime.now()
            if 'platform' not in event_dict or not event_dict['platform']:
                event_dict['platform'] = 'windows'  # Default to windows for EVTX/Registry/Prefetch
            if 'artifact_type' not in event_dict or not event_dict['artifact_type']:
                event_dict['artifact_type'] = 'unknown'
            if 'event_type' not in event_dict or not event_dict['event_type']:
                event_dict['event_type'] = 'unknown'
            
            try:
                artifact = CanonicalArtifact(event_dict)
                is_valid, errors = artifact.validate()
                if is_valid:
                    artifacts.append(artifact)
                else:
                    logger.debug(f"Skipping invalid artifact: {errors}")
            except Exception as e:
                logger.debug(f"Failed to create artifact: {e}")
                continue
        
        logger.info(f"Converted {len(artifacts)} artifacts from DataFrame ({len(df)} rows)")
        return artifacts
    
    def normalize_artifacts(self, raw_events: List[Dict]) -> List[CanonicalArtifact]:
        """Convert raw events to canonical artifact format."""
        artifacts = []
        for event in raw_events:
            artifact = CanonicalArtifact(event)
            is_valid, errors = artifact.validate()
            if is_valid:
                artifacts.append(artifact)
            else:
                logger.warning(f"Invalid artifact: {errors}")
        
        self._log_operation('normalize_artifacts', {
            'input_count': len(raw_events),
            'output_count': len(artifacts)
        })
        
        return artifacts
    
    def train(self, training_data, save: bool = True, epochs: int = 200):
        """
        Train all intelligence layers on baseline artifacts.
        
        Constitutional constraints:
        - Training data must be read-only
        - All transformations must be logged
        - Models must be deterministic
        
        Args:
            training_data: Either a pandas DataFrame or List of CanonicalArtifact objects
            save: Whether to persist the trained model (default True)
            epochs: Number of training epochs for autoencoder (default 200)
        """
        # Convert DataFrame to artifacts if needed
        import pandas as pd
        if isinstance(training_data, pd.DataFrame):
            training_artifacts = self.normalize_dataframe(training_data)
        elif isinstance(training_data, list):
            training_artifacts = training_data
        else:
            raise ValueError("training_data must be either pandas DataFrame or List[CanonicalArtifact]")
        
        if not training_artifacts:
            logger.warning("No training artifacts provided")
            return
        
        logger.info(f"Training on {len(training_artifacts)} baseline artifacts")
        
        # Build behavioral baselines per entity
        entity_artifacts = {}
        for artifact in training_artifacts:
            entity_id = artifact.user_id or artifact.host or 'unknown'
            if entity_id not in entity_artifacts:
                entity_artifacts[entity_id] = []
            entity_artifacts[entity_id].append(artifact)
        
        for entity_id, artifacts in entity_artifacts.items():
            baseline = BehavioralBaseline(entity_id)
            baseline.learn(artifacts)
            self.baselines[entity_id] = baseline
            logger.info(f"Baseline created for {entity_id}: {baseline.artifact_count} events")
        
        # Note: save parameter accepted but not used yet (future: model persistence)
        # Train clustering detector
        encoded_events = np.array([self.encoder.encode(a.to_dict()) for a in training_artifacts])
        self.clustering_detector.fit(encoded_events)
        
        # Train autoencoder (if sufficient data)
        if len(training_artifacts) > 50:
            features = self._extract_features(training_artifacts)
            if features.shape[1] > 0:
                self.autoencoder_detector = AutoencoderAnomalyDetector(
                    input_dim=features.shape[1],
                    encoding_dim=max(2, features.shape[1] // 2),
                    random_seed=self.random_seed
                )
                self.autoencoder_detector.fit(features, epochs=epochs)
                logger.info(f"Autoencoder trained with {epochs} epochs")
        
        # Calibrate clock detector
        timestamps = [a.timestamp for a in training_artifacts if a.timestamp]
        timestamps = [ts if isinstance(ts, datetime) else datetime.fromisoformat(ts) 
                     for ts in timestamps if ts]
        if timestamps:
            self.clock_detector.calibrate(timestamps)
        
        self.trained = True
        self._log_operation('train', {
            'artifact_count': len(training_artifacts),
            'entities': len(self.baselines),
            'autoencoder_trained': self.autoencoder_detector is not None
        })
    
    def continue_training(self, additional_data, additional_epochs: int = 100):
        """
        Continue training the model with additional data and epochs.
        Useful for incremental learning without losing previous training.
        
        Args:
            additional_data: DataFrame or List[CanonicalArtifact] with new training data
            additional_epochs: Number of additional epochs to train (default 100)
        """
        if not self.trained:
            logger.warning("Model not yet trained. Use train() first.")
            return
        
        # Convert DataFrame to artifacts if needed
        if isinstance(additional_data, pd.DataFrame):
            additional_artifacts = self.normalize_dataframe(additional_data)
        elif isinstance(additional_data, list):
            additional_artifacts = additional_data
        else:
            raise ValueError("additional_data must be either pandas DataFrame or List[CanonicalArtifact]")
        
        if not additional_artifacts:
            logger.warning("No additional training artifacts provided")
            return
        
        logger.info(f"Continuing training with {len(additional_artifacts)} additional artifacts for {additional_epochs} epochs")
        
        # Update behavioral baselines with new data
        entity_artifacts = {}
        for artifact in additional_artifacts:
            entity_id = artifact.user_id or artifact.host or 'unknown'
            if entity_id not in entity_artifacts:
                entity_artifacts[entity_id] = []
            entity_artifacts[entity_id].append(artifact)
        
        for entity_id, artifacts in entity_artifacts.items():
            if entity_id in self.baselines:
                # Update existing baseline
                self.baselines[entity_id].learn(artifacts)
                logger.info(f"Updated baseline for {entity_id}: now {self.baselines[entity_id].artifact_count} events")
            else:
                # Create new baseline
                baseline = BehavioralBaseline(entity_id)
                baseline.learn(artifacts)
                self.baselines[entity_id] = baseline
                logger.info(f"New baseline created for {entity_id}: {baseline.artifact_count} events")
        
        # Continue training autoencoder if it exists
        if self.autoencoder_detector is not None and len(additional_artifacts) > 10:
            features = self._extract_features(additional_artifacts)
            if features.shape[1] > 0:
                self.autoencoder_detector.continue_training(features, additional_epochs=additional_epochs)
        
        # Update clock detector calibration
        timestamps = [a.timestamp for a in additional_artifacts if a.timestamp]
        timestamps = [ts if isinstance(ts, datetime) else datetime.fromisoformat(ts) 
                     for ts in timestamps if ts]
        if timestamps:
            existing_timestamps = list(self.clock_detector.timestamp_history) if hasattr(self.clock_detector, 'timestamp_history') else []
            all_timestamps = existing_timestamps + timestamps
            if all_timestamps:
                self.clock_detector.calibrate(all_timestamps)
        
        self._log_operation('continue_training', {
            'additional_artifact_count': len(additional_artifacts),
            'total_entities': len(self.baselines),
            'additional_epochs': additional_epochs
        })
        
        logger.info(f"Continued training complete. Model now trained on {sum(b.artifact_count for b in self.baselines.values())} total events")
    
    def detect_anomalies(self, test_data) -> List[ForensicFinding]:
        """
        Detect anomalies and produce court-defensible findings.
        
        Args:
            test_data: Either a pandas DataFrame or List of CanonicalArtifact objects
        
        Returns:
            List of ForensicFinding objects with full explanations
        """
        # Convert DataFrame to artifacts if needed
        import pandas as pd
        if isinstance(test_data, pd.DataFrame):
            artifacts = self.normalize_dataframe(test_data)
        elif isinstance(test_data, list):
            artifacts = test_data
        else:
            raise ValueError("test_data must be either pandas DataFrame or List[CanonicalArtifact]")
        
        findings = []
        self.last_analyzed_count = len(artifacts)
        
        for artifact in artifacts:
            entity_id = artifact.user_id or artifact.host or 'unknown'
            
            # Multi-layer analysis
            all_explanations = []
            max_score = 0.0
            anomaly_types = []
            
            # Layer 1: UEBA (primary)
            if entity_id in self.baselines:
                ueba_result = self.baselines[entity_id].detect_deviation(artifact)
                if ueba_result['is_anomaly']:
                    all_explanations.extend(ueba_result['explanations'])
                    anomaly_types.extend(ueba_result['anomaly_types'])
                    max_score = max(max_score, ueba_result['deviation_score'])
            
            # Layer 2: Clock skew
            if artifact.timestamp:
                skew_result = self.clock_detector.detect_skew(artifact.timestamp)
                if skew_result['has_skew']:
                    all_explanations.append(skew_result['explanation'])
                    anomaly_types.append('clock_skew')
                    max_score = max(max_score, skew_result['confidence'])
            
            # Layer 3: Autoencoder (if trained)
            if self.autoencoder_detector:
                features = self._extract_features([artifact])
                ae_results = self.autoencoder_detector.predict_with_explanation(features)
                if ae_results[0]['is_anomaly']:
                    all_explanations.append(ae_results[0]['explanation'])
                    anomaly_types.append('reconstruction_error')
                    max_score = max(max_score, ae_results[0]['normalized_score'])
            
            # Generate finding if anomaly detected
            if all_explanations:
                severity = self._calculate_severity(max_score)
                
                finding = ForensicFinding(
                    finding_id=f"ANOM-{artifact.artifact_id}",
                    finding_type='behavioral_anomaly',
                    severity=severity,
                    score=max_score,
                    title=f"Behavioral Anomaly Detected - {entity_id}",
                    description=f"Anomaly detected in {artifact.artifact_type} artifact from {entity_id}",
                    evidence_ids=[artifact.artifact_id],
                    explanations=all_explanations,
                    recommendation=self._generate_recommendation(anomaly_types, severity),
                    confidence=max_score,
                    metadata={
                        'entity_id': entity_id,
                        'anomaly_types': anomaly_types,
                        'artifact_type': artifact.artifact_type,
                        'platform': artifact.platform
                    }
                )
                
                findings.append(finding)
        
        self._log_operation('detect_anomalies', {
            'analyzed_count': len(artifacts),
            'findings_count': len(findings)
        })
        
        return findings
    
    def _extract_features(self, artifacts: List[CanonicalArtifact]) -> np.ndarray:
        """
        Extract numerical features for ML anomaly detection.
        
        Features extracted:
        - Hour of day (0-23) - normalized
        - Day of week (0-6) - normalized
        - Artifact type encoded (0-1)
        - Event type hash (0-1)
        - Has user indicator (0/1)
        - Path depth (normalized)
        """
        features = []
        
        # Artifact type to numeric encoding
        artifact_type_map = {
            'evtx': 0.0, 'registry': 0.1, 'prefetch': 0.2, 'mft': 0.3,
            'network': 0.4, 'file': 0.5, 'process': 0.6, 'memory': 0.7,
            'browser': 0.8, 'unknown': 0.9
        }
        
        for artifact in artifacts:
            row = []
            
            # Feature 1: Hour of day (normalized 0-1)
            if artifact.timestamp:
                if isinstance(artifact.timestamp, str):
                    try:
                        ts = datetime.fromisoformat(artifact.timestamp)
                    except ValueError:
                        ts = datetime.now()
                else:
                    ts = artifact.timestamp
                row.append(ts.hour / 24.0)  # Normalized hour
                row.append(ts.weekday() / 7.0)  # Normalized day of week
            else:
                row.append(0.5)  # Default to midday
                row.append(0.5)  # Default to mid-week
            
            # Feature 2: Artifact type encoded
            art_type = str(artifact.artifact_type).lower() if artifact.artifact_type else 'unknown'
            row.append(artifact_type_map.get(art_type, 0.9))
            
            # Feature 3: Event type hash (simple hash to 0-1 range)
            event_type = str(artifact.event_type) if artifact.event_type else 'unknown'
            event_hash = (hash(event_type) % 1000) / 1000.0
            row.append(event_hash)
            
            # Feature 4: Has user indicator
            has_user = 1.0 if (artifact.user_id and artifact.user_id != 'unknown') else 0.0
            row.append(has_user)
            
            # Feature 5: Platform encoded
            platform = str(artifact.platform).lower() if artifact.platform else 'unknown'
            platform_map = {'windows': 0.0, 'linux': 0.33, 'macos': 0.66, 'unknown': 1.0}
            row.append(platform_map.get(platform, 1.0))
            
            features.append(row)
        
        return np.array(features, dtype=np.float32)
    
    def _calculate_severity(self, score: float) -> str:
        """Map score to severity level."""
        if score >= 0.8:
            return 'critical'
        elif score >= 0.6:
            return 'high'
        elif score >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendation(self, anomaly_types: List[str], severity: str) -> str:
        """Generate actionable recommendation."""
        if severity in ['critical', 'high']:
            return "Immediate investigation required. Manually validate artifact and correlate with other evidence."
        elif 'clock_skew' in anomaly_types:
            return "Potential anti-forensics detected. Verify system time integrity and timeline consistency."
        else:
            return "Review for context. May indicate legitimate behavior change or configuration drift."
    
    def _log_operation(self, operation: str, metadata: Dict):
        """Log operation to audit trail."""
        self.operations_log.append({
            'timestamp': datetime.now(),
            'operation': operation,
            'metadata': metadata
        })
    
    def get_anomaly_report(self, findings: List[ForensicFinding], total_events: Optional[int] = None) -> Dict:
        """
        Generate summary report from anomaly findings.
        
        Args:
            findings: List of ForensicFinding objects from detect_anomalies()
            total_events: Optional total events analyzed (for rate calculations)
            
        Returns:
            Dictionary with anomaly statistics and summary
        """
        anomalies_detected = len(findings)
        total_events = total_events or getattr(self, 'last_analyzed_count', 0) or anomalies_detected
        anomaly_rate = (anomalies_detected / total_events) if total_events else 0.0
        
        if not findings:
            return {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'summary': 'No anomalies detected',
                'total_events': total_events,
                'anomalies_detected': anomalies_detected,
                'anomaly_rate': anomaly_rate,
                'clock_skew_analysis': {'potential_attacks': 0}
            }
        
        # Count by severity and flag potential clock skew issues
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        clock_skew_flags = 0
        for finding in findings:
            severity = getattr(finding, 'severity', None) or finding.metadata.get('severity', 'low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            if 'clock_skew' in finding.metadata.get('anomaly_types', []):
                clock_skew_flags += 1
        
        return {
            'total': anomalies_detected,
            'critical': severity_counts['critical'],
            'high': severity_counts['high'],
            'medium': severity_counts['medium'],
            'low': severity_counts['low'],
            'summary': f"Detected {anomalies_detected} anomalies: {severity_counts['critical']} critical, {severity_counts['high']} high",
            'total_events': total_events,
            'anomalies_detected': anomalies_detected,
            'anomaly_rate': anomaly_rate,
            'clock_skew_analysis': {
                'potential_attacks': clock_skew_flags
            }
        }


class AnomalyDetector:
    """Legacy interface - wraps constitutional engine for backward compatibility."""
    
    def __init__(self):
        """Initialize legacy detector."""
        self.engine = MLAnomalyDetectionEngine(case_id='legacy', random_seed=42)
        logger.warning("Using legacy AnomalyDetector interface - consider migrating to MLAnomalyDetectionEngine")
    
    def train(self, normal_data: np.ndarray, save: bool = True):
        """
        Train on numerical data (legacy).
        
        Args:
            normal_data: Numerical feature array
            save: Whether to persist the trained model (default True) - not used in legacy mode
        """
        # Convert to minimal canonical artifacts
        artifacts = []
        for i, row in enumerate(normal_data):
            artifacts.append(CanonicalArtifact({
                'timestamp': datetime.now(),
                'platform': 'unknown',
                'artifact_type': 'unknown',
                'event_type': f'legacy_event_{i}',
                'raw': {'features': row.tolist()}
            }))
        self.engine.train(artifacts, save=save)
    
    def detect(self, data: np.ndarray) -> Tuple[bool, float]:
        """Detect anomalies (legacy interface)."""
        artifacts = [CanonicalArtifact({
            'timestamp': datetime.now(),
            'platform': 'unknown',
            'artifact_type': 'unknown',
            'event_type': 'test_event',
            'raw': {'features': row.tolist()}
        }) for row in data]
        
        findings = self.engine.detect_anomalies(artifacts)
        
        if findings:
            return True, findings[0].score
        return False, 0.0
    
    def explain(self, data: np.ndarray) -> Dict[str, Any]:
        """Explain detection result (legacy)."""
        artifacts = [CanonicalArtifact({
            'timestamp': datetime.now(),
            'platform': 'unknown',
            'artifact_type': 'unknown',
            'event_type': 'explain_event',
            'raw': {'features': row.tolist()}
        }) for row in data]
        
        findings = self.engine.detect_anomalies(artifacts)
        
        if findings:
            finding = findings[0]
            return {
                "score": finding.score,
                "reasons": finding.explanations,
                "contributing_features": finding.metadata.get('anomaly_types', [])
            }
        
        return {
            "score": 0.0,
            "reasons": ["No anomalies detected"],
            "contributing_features": []
        }


def calculate_risk_score(artifact_metadata: Dict) -> float:
    """Calculate risk score for artifact."""
    engine = MLAnomalyDetectionEngine(case_id='risk_calc', random_seed=42)
    artifact = CanonicalArtifact(artifact_metadata)
    
    # Simple heuristic scoring
    score = 0.0
    
    if artifact.artifact_type in ['memory', 'network']:
        score += 0.3
    if artifact.platform == 'unknown':
        score += 0.2
    if not artifact.timestamp:
        score += 0.5
    
    return min(1.0, score)


def get_ml_explanation(artifact_path: str, score: float) -> List[str]:
    """Generate human-readable ML explanation."""
    explanations = []
    
    if score >= 0.8:
        explanations.append(f"Critical risk score ({score:.2f}) - immediate investigation required")
    elif score >= 0.6:
        explanations.append(f"High risk score ({score:.2f}) - priority review needed")
    elif score >= 0.4:
        explanations.append(f"Medium risk score ({score:.2f}) - standard review")
    else:
        explanations.append(f"Low risk score ({score:.2f}) - routine monitoring")
    
    explanations.append(f"Artifact: {artifact_path}")
    explanations.append("This is an advisory finding - manual validation required")
    
    return explanations

