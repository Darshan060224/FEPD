"""
FEPD Core Module

Core functionality for case management and forensic operations.
"""

from .case_manager import CaseManager
from .evidence_orchestrator import EvidenceOrchestrator
from .evidence_relationship_analyzer import (
    EvidenceRelationshipAnalyzer,
    EvidenceDataCombiner,
    CombinedEvidenceSet,
    EvidenceRelationType
)

__all__ = [
    'CaseManager',
    'EvidenceOrchestrator',
    'EvidenceRelationshipAnalyzer',
    'EvidenceDataCombiner',
    'CombinedEvidenceSet',
    'EvidenceRelationType'
]
