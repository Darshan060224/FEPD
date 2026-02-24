"""
FEPD Dialog Components

Enhanced dialog windows for artifact and timeline event details.
Case management dialogs for creating and opening forensic cases.
Evidence upload dialogs for single and multi-evidence processing.
"""

from .artifact_detail_dialog import ArtifactDetailDialog, ArtifactChoiceDialog
from .timeline_event_dialog import TimelineEventDetailDialog
from .case_dialog import CaseDialog
from .case_creation_dialog import CaseCreationDialog
from .case_open_dialog import CaseOpenDialog
from .evidence_upload_dialog import EvidenceUploadDialog, EvidenceProcessingDialog
from .multi_evidence_dialog import MultiEvidenceUploadDialog, MultiEvidenceSelection

__all__ = [
    'ArtifactDetailDialog',
    'ArtifactChoiceDialog',
    'TimelineEventDetailDialog',
    'CaseDialog',
    'CaseCreationDialog',
    'CaseOpenDialog',
    'EvidenceUploadDialog',
    'EvidenceProcessingDialog',
    'MultiEvidenceUploadDialog',
    'MultiEvidenceSelection'
]
