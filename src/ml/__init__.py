"""
Machine Learning Module for FEPD
=================================

Advanced analytics using machine learning for:
- Anomaly detection (autoencoders, clustering)
- User behavior profiling (UEBA)
- Threat intelligence integration
- Pattern recognition
"""

# Import main classes
from .ml_anomaly_detector import MLAnomalyDetectionEngine
from .ueba_profiler import UEBAProfiler

try:
    from .threat_intel import ThreatIntelligenceEngine
except ImportError:
    ThreatIntelligenceEngine = None

__all__ = [
    'MLAnomalyDetectionEngine',
    'UEBAProfiler',
    'ThreatIntelligenceEngine'
]

