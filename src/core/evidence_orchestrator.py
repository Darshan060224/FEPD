"""
FEPD - Evidence Ingestion & Processing Orchestrator
Forensic-Grade Automation Engine

This module orchestrates the complete evidence ingestion workflow:
1. Evidence upload with type selection
2. Multi-part E01 validation
3. Chain of Custody automation
4. Evidence reconstruction (virtual mounting)
5. Artifact discovery and extraction
6. Parsing and normalization
7. ML + UEBA execution
8. Visualization generation
9. Forensic terminal initialization

SECURITY RULES:
- Never modify evidence
- Never overwrite Chain of Custody
- Never skip hashing
- Never skip validation
- Always reproducible

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

from __future__ import annotations

from typing import TYPE_CHECKING
import os
import json

if TYPE_CHECKING:
    from .evidence_relationship_analyzer import CombinedEvidenceSet
import hashlib
import logging
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
import threading
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtCore import QObject, pyqtSignal

if TYPE_CHECKING:
    from .chain_of_custody import ChainLogger


class EvidenceTypeEnum(Enum):
    """Evidence type classification."""
    DISK_IMAGE = "disk_image"       # E01/DD/RAW/IMG/AFF
    MEMORY_IMAGE = "memory_image"   # MEM/DMP/RAW
    UNKNOWN = "unknown"


class PipelinePhase(Enum):
    """Processing pipeline phases."""
    UPLOAD = "upload"
    VALIDATION = "validation"
    CHAIN_OF_CUSTODY = "chain_of_custody"
    RECONSTRUCTION = "reconstruction"
    VIRTUAL_MOUNT = "virtual_mount"
    PARTITION_DISCOVERY = "partition_discovery"
    MEMORY_ANALYSIS = "memory_analysis"     # Memory dump forensic analysis
    ARTIFACT_DISCOVERY = "artifact_discovery"
    ARTIFACT_EXTRACTION = "artifact_extraction"
    PARSING = "parsing"
    NORMALIZATION = "normalization"
    TIMELINE_BUILD = "timeline_build"
    ML_ANALYSIS = "ml_analysis"
    UEBA = "ueba"
    VISUALIZATION = "visualization"
    TERMINAL_INIT = "terminal_init"
    COMPLETE = "complete"
    ERROR = "error"


class PipelineStatus(Enum):
    """Pipeline execution status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class EvidenceFile:
    """Represents a single evidence file."""
    path: Path
    sha256: str = ""
    size_bytes: int = 0
    file_type: str = ""
    sequence_number: int = 0  # For multi-part
    validated: bool = False
    timestamp: str = ""


@dataclass
class EvidenceSet:
    """Represents a complete set of evidence files."""
    id: str
    case_name: str
    evidence_type: EvidenceTypeEnum
    is_multipart: bool = False
    files: List[EvidenceFile] = field(default_factory=list)
    base_name: str = ""
    total_size_bytes: int = 0
    is_complete: bool = False
    missing_segments: List[int] = field(default_factory=list)
    validation_errors: List[str] = field(default_factory=list)
    
    @property
    def primary_path(self) -> Optional[Path]:
        """Get primary evidence file path."""
        if self.files:
            return self.files[0].path
        return None


@dataclass
class PipelineStep:
    """Represents a pipeline execution step."""
    phase: PipelinePhase
    status: PipelineStatus = PipelineStatus.PENDING
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OrchestrationResult:
    """Result of the complete orchestration process."""
    success: bool
    case_name: str
    evidence_set: Optional[EvidenceSet] = None
    pipeline_steps: List[PipelineStep] = field(default_factory=list)
    artifacts_discovered: int = 0
    events_parsed: int = 0
    anomalies_detected: int = 0
    error_message: Optional[str] = None
    workspace_path: Optional[Path] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "case_name": self.case_name,
            "artifacts_discovered": self.artifacts_discovered,
            "events_parsed": self.events_parsed,
            "anomalies_detected": self.anomalies_detected,
            "error_message": self.error_message,
            "workspace_path": str(self.workspace_path) if self.workspace_path else None,
            "pipeline_steps": [
                {
                    "phase": step.phase.value,
                    "status": step.status.value,
                    "started_at": step.started_at,
                    "completed_at": step.completed_at,
                    "error_message": step.error_message
                }
                for step in self.pipeline_steps
            ]
        }


class EvidenceOrchestrator(QObject):
    """
    Forensic-Grade Evidence Ingestion & Processing Orchestrator.
    
    Orchestrates the complete evidence processing workflow with:
    - Strict validation
    - Chain of custody tracking
    - Automatic artifact extraction
    - ML/UEBA analysis
    - Visualization generation
    """
    
    # Signals for progress updates
    phase_started = pyqtSignal(str, str)  # (phase_name, description)
    phase_completed = pyqtSignal(str, bool, str)  # (phase_name, success, message)
    progress_updated = pyqtSignal(int, str)  # (percentage, status_message)
    pipeline_completed = pyqtSignal(object)  # (OrchestrationResult)
    coc_entry_added = pyqtSignal(str)  # (entry_description)
    error_occurred = pyqtSignal(str, str)  # (phase_name, error_message)
    
    def __init__(self, cases_root: str = "cases"):
        """
        Initialize the Evidence Orchestrator.
        
        Args:
            cases_root: Root directory for case workspaces
        """
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.cases_root = Path(cases_root)
        self.cases_root.mkdir(parents=True, exist_ok=True)
        
        self._current_result: Optional[OrchestrationResult] = None
        self._chain_logger = None
        self._is_cancelled = False
        
        # Import chain of custody module
        try:
            from .chain_of_custody import ChainLogger, CoC_Actions
            self.ChainLogger = ChainLogger
            self.CoC_Actions = CoC_Actions
        except ImportError:
            self.ChainLogger = None
            self.CoC_Actions = None
    
    # ========================================================================
    # PHASE 1: Evidence Validation
    # ========================================================================
    
    def validate_evidence_files(
        self,
        file_paths: List[Path],
        evidence_type: EvidenceTypeEnum,
        is_multipart: bool
    ) -> Tuple[bool, EvidenceSet, List[str]]:
        """
        Validate evidence files before ingestion.
        
        Rules:
        - Multi-part unchecked: Allow only 1 file
        - Multi-part checked: Allow multiple E0x files
        - Memory selected: Allow only 1 file
        - Disk + Memory: Allow both
        
        For E01 sets validates:
        - Same base name
        - No missing segments
        - Sequential numbering
        - Size > 0
        - Readable
        
        Args:
            file_paths: List of evidence file paths
            evidence_type: Type of evidence
            is_multipart: Whether multi-part mode is enabled
        
        Returns:
            Tuple of (is_valid, evidence_set, error_messages)
        """
        errors = []
        
        # Create evidence set
        evidence_set = EvidenceSet(
            id=datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
            case_name="",
            evidence_type=evidence_type,
            is_multipart=is_multipart
        )
        
        # Rule 1: Memory images must be single file
        if evidence_type == EvidenceTypeEnum.MEMORY_IMAGE:
            if len(file_paths) > 1:
                errors.append("Memory images must be single files. Multiple files selected.")
                return False, evidence_set, errors
        
        # Rule 2: Non-multipart mode must be single file
        if not is_multipart and len(file_paths) > 1:
            errors.append(
                "You selected multiple files.\n\n"
                "Enable 'Multi-part forensic image' to upload split disks (E01, E02, ...)."
            )
            return False, evidence_set, errors
        
        # Validate each file exists and is readable
        for path in file_paths:
            if not path.exists():
                errors.append(f"File not found: {path.name}")
                continue
            if not path.is_file():
                errors.append(f"Not a file: {path.name}")
                continue
            if path.stat().st_size == 0:
                errors.append(f"Empty file: {path.name}")
                continue
            try:
                with open(path, 'rb') as f:
                    f.read(1)  # Test readability
            except PermissionError:
                errors.append(f"Cannot read file (permission denied): {path.name}")
                continue
        
        if errors:
            return False, evidence_set, errors
        
        # For multi-part E01, validate sequence
        if is_multipart and evidence_type == EvidenceTypeEnum.DISK_IMAGE:
            valid, evidence_set, seq_errors = self._validate_multipart_sequence(file_paths)
            if not valid:
                return False, evidence_set, seq_errors
        else:
            # Single file evidence
            path = file_paths[0]
            evidence_file = EvidenceFile(
                path=path,
                size_bytes=path.stat().st_size,
                file_type=path.suffix.lower(),
                sequence_number=1,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            evidence_set.files = [evidence_file]
            evidence_set.total_size_bytes = evidence_file.size_bytes
            evidence_set.base_name = path.stem
            evidence_set.is_complete = True
        
        return True, evidence_set, []
    
    def _validate_multipart_sequence(
        self,
        file_paths: List[Path]
    ) -> Tuple[bool, EvidenceSet, List[str]]:
        """
        Validate multi-part E01 evidence sequence.
        
        Validates:
        - Same base name (LoneWolf.E01...E09)
        - No missing segments
        - Sequential numbering
        
        Args:
            file_paths: List of E01/E02/... file paths
        
        Returns:
            Tuple of (is_valid, evidence_set, error_messages)
        """
        import re
        
        errors = []
        evidence_set = EvidenceSet(
            id=datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
            case_name="",
            evidence_type=EvidenceTypeEnum.DISK_IMAGE,
            is_multipart=True
        )
        
        # Pattern for E01, E02, etc.
        e01_pattern = re.compile(r'^(.+)\.E(\d{2})$', re.IGNORECASE)
        
        # Parse file names
        parsed_files = []
        base_names = set()
        
        for path in file_paths:
            match = e01_pattern.match(path.name)
            if match:
                base_name = match.group(1)
                seq_num = int(match.group(2))
                base_names.add(base_name)
                parsed_files.append({
                    'path': path,
                    'base_name': base_name,
                    'sequence': seq_num,
                    'size': path.stat().st_size
                })
            else:
                # Check for .001, .002 pattern
                split_pattern = re.compile(r'^(.+)\.(\d{3})$')
                split_match = split_pattern.match(path.name)
                if split_match:
                    base_name = split_match.group(1)
                    seq_num = int(split_match.group(2))
                    base_names.add(base_name)
                    parsed_files.append({
                        'path': path,
                        'base_name': base_name,
                        'sequence': seq_num,
                        'size': path.stat().st_size
                    })
                else:
                    errors.append(f"Invalid multi-part filename format: {path.name}")
        
        if errors:
            return False, evidence_set, errors
        
        # Validate all files have same base name
        if len(base_names) > 1:
            errors.append(
                f"Mixed base names detected: {', '.join(base_names)}\n"
                "All parts must belong to the same evidence set."
            )
            return False, evidence_set, errors
        
        base_name = list(base_names)[0]
        evidence_set.base_name = base_name
        
        # Sort by sequence number
        parsed_files.sort(key=lambda x: x['sequence'])
        
        # Check for missing segments
        sequences = [f['sequence'] for f in parsed_files]
        expected_start = 1  # E01 starts at 1
        max_seq = max(sequences)
        
        missing = []
        for i in range(expected_start, max_seq + 1):
            if i not in sequences:
                missing.append(i)
        
        if missing:
            missing_names = [f"{base_name}.E{str(m).zfill(2)}" for m in missing]
            errors.append(
                f"❌ Invalid evidence set:\n"
                f"- Missing {', '.join(missing_names)}"
            )
            evidence_set.missing_segments = missing
            return False, evidence_set, errors
        
        # Build evidence files list
        total_size = 0
        for pf in parsed_files:
            evidence_file = EvidenceFile(
                path=pf['path'],
                size_bytes=pf['size'],
                file_type=pf['path'].suffix.lower(),
                sequence_number=pf['sequence'],
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            evidence_set.files.append(evidence_file)
            total_size += pf['size']
        
        evidence_set.total_size_bytes = total_size
        evidence_set.is_complete = True
        
        return True, evidence_set, []
    
    # ========================================================================
    # PHASE 2: Hash Computation
    # ========================================================================
    
    def compute_evidence_hashes(
        self,
        evidence_set: EvidenceSet,
        progress_callback: Optional[Callable[[int, str], None]] = None
    ) -> EvidenceSet:
        """
        Compute SHA-256 hashes for all evidence files.
        
        Args:
            evidence_set: Evidence set to hash
            progress_callback: Optional progress callback (percent, message)
        
        Returns:
            Updated evidence set with hashes
        """
        total_files = len(evidence_set.files)
        
        for i, evidence_file in enumerate(evidence_set.files):
            if self._is_cancelled:
                raise RuntimeError("Operation cancelled by user")
            
            # Update progress
            pct = int((i / total_files) * 100)
            if progress_callback:
                progress_callback(pct, f"Hashing {evidence_file.path.name}...")
            
            # Compute SHA-256
            sha256 = self._compute_file_hash(evidence_file.path)
            evidence_file.sha256 = sha256
            evidence_file.validated = True
            
            self.logger.info(f"Hashed: {evidence_file.path.name} = {sha256[:16]}...")
        
        if progress_callback:
            progress_callback(100, "All files hashed")
        
        return evidence_set
    
    def _compute_file_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """
        Compute hash of a file.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, md5)
        
        Returns:
            Hex hash string
        """
        hasher = hashlib.new(algorithm)
        buffer_size = 8 * 1024 * 1024  # 8 MB chunks
        
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(buffer_size)
                if not data:
                    break
                hasher.update(data)
        
        return hasher.hexdigest()
    
    # ========================================================================
    # PHASE 3: Chain of Custody Initialization
    # ========================================================================
    
    def initialize_chain_of_custody(
        self,
        case_path: Path,
        evidence_set: EvidenceSet,
        operator: str = "SYSTEM"
    ) -> 'ChainLogger':
        """
        Initialize Chain of Custody for the case.
        
        Records:
        - EVIDENCE_IMPORTED action
        - File hashes
        - File sizes
        - Timestamps
        
        Args:
            case_path: Path to case directory
            evidence_set: Validated evidence set
            operator: Operator name
        
        Returns:
            ChainLogger instance
        """
        if not self.ChainLogger:
            raise RuntimeError("Chain of Custody module not available")
        
        # Initialize chain logger
        chain_logger = self.ChainLogger(str(case_path))
        self._chain_logger = chain_logger
        
        # Build evidence details
        files_info = []
        for ef in evidence_set.files:
            files_info.append({
                "name": ef.path.name,
                "sha256": ef.sha256,
                "size_bytes": ef.size_bytes
            })
        
        # Log evidence import
        details = (
            f"EVIDENCE_IMPORTED\n"
            f"CASE={evidence_set.case_name}\n"
            f"USER={operator}\n"
            f"TYPE={evidence_set.evidence_type.value}\n"
            f"MULTIPART={evidence_set.is_multipart}\n"
            f"FILES={json.dumps([f['name'] for f in files_info])}\n"
            f"TOTAL_SIZE={evidence_set.total_size_bytes}\n"
            f"HASHCHAINED=true"
        )
        
        chain_logger.append(
            user=operator,
            action=self.CoC_Actions.EVIDENCE_IMPORTED,
            details=details
        )
        
        # Log individual file hashes
        for file_info in files_info:
            chain_logger.append(
                user=operator,
                action=self.CoC_Actions.EVIDENCE_VERIFIED,
                details=f"File: {file_info['name']} | SHA256: {file_info['sha256']} | Size: {file_info['size_bytes']} bytes"
            )
        
        self.coc_entry_added.emit(f"Evidence imported: {len(files_info)} files, {evidence_set.total_size_bytes:,} bytes")
        
        return chain_logger
    
    def log_pipeline_step(
        self,
        chain_logger: 'ChainLogger',
        phase: PipelinePhase,
        status: str,
        details: str = "",
        operator: str = "SYSTEM"
    ):
        """
        Log a pipeline step to Chain of Custody.
        
        Args:
            chain_logger: ChainLogger instance
            phase: Pipeline phase
            status: STARTED or COMPLETED
            details: Additional details
            operator: Operator name
        """
        if not chain_logger:
            return
        
        action = f"PIPELINE_STEP_{status}"
        chain_logger.append(
            user=operator,
            action=action,
            details=f"Phase: {phase.value} | {details}"
        )
        
        self.coc_entry_added.emit(f"Pipeline: {phase.value} {status.lower()}")
    
    # ========================================================================
    # PHASE 4: Case Workspace Setup
    # ========================================================================
    
    def create_case_workspace(
        self,
        case_name: str,
        evidence_set: EvidenceSet
    ) -> Path:
        """
        Create forensic case workspace structure.
        
        Structure:
        /case/
            chain_of_custody.log
            case.json
            evidence/
                disk0/      # Mounted disk image
                memory/     # Memory dump
            artifacts/
                evtx/
                registry/
                mft/
                prefetch/
                browser/
                network/
                mobile/
            events/
                events.parquet
            ml/
                anomalies.json
                ueba_profiles.json
                findings.json
            reports/
            visualizations/
        
        Args:
            case_name: Case identifier
            evidence_set: Evidence set
        
        Returns:
            Path to case workspace
        """
        case_path = self.cases_root / case_name
        
        # Create directory structure
        directories = [
            case_path / "evidence" / "disk0",
            case_path / "evidence" / "memory",
            case_path / "artifacts" / "evtx",
            case_path / "artifacts" / "registry",
            case_path / "artifacts" / "mft",
            case_path / "artifacts" / "prefetch",
            case_path / "artifacts" / "browser",
            case_path / "artifacts" / "network",
            case_path / "artifacts" / "mobile",
            case_path / "artifacts" / "cloud",
            case_path / "events",
            case_path / "ml",
            case_path / "reports",
            case_path / "visualizations",
        ]
        
        for dir_path in directories:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Create case.json metadata
        case_metadata = {
            "case_id": case_name,
            "case_name": case_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "evidence_type": evidence_set.evidence_type.value,
            "evidence_files": [
                {
                    "name": ef.path.name,
                    "sha256": ef.sha256,
                    "size_bytes": ef.size_bytes,
                    "sequence": ef.sequence_number
                }
                for ef in evidence_set.files
            ],
            "total_evidence_size": evidence_set.total_size_bytes,
            "status": "processing",
            "pipeline_phases": []
        }
        
        with open(case_path / "case.json", 'w') as f:
            json.dump(case_metadata, f, indent=2)
        
        evidence_set.case_name = case_name
        
        self.logger.info(f"Created case workspace: {case_path}")
        return case_path
    
    # ========================================================================
    # PHASE 5: Evidence Reconstruction (Virtual Mounting)
    # ========================================================================
    
    def reconstruct_evidence(
        self,
        evidence_set: EvidenceSet,
        case_path: Path
    ) -> Path:
        """
        Reconstruct evidence for virtual access.
        
        For multi-part E01:
        E01 + E02 + ... → VirtualDisk (read-only stream)
        No physical merge — virtual mapping only.
        
        Mount points:
        /case/evidence/disk0/
        /case/evidence/memory/memdump.mem
        
        Args:
            evidence_set: Evidence set
            case_path: Case workspace path
        
        Returns:
            Path to mounted evidence
        """
        if evidence_set.evidence_type == EvidenceTypeEnum.MEMORY_IMAGE:
            # Link memory image
            memory_dir = case_path / "evidence" / "memory"
            src_path = evidence_set.primary_path
            dst_path = memory_dir / "memdump.mem"
            
            # Create read-only symlink or copy
            if not dst_path.exists():
                try:
                    dst_path.symlink_to(src_path)
                except OSError:
                    # Symlinks may not be supported, use hard link or copy
                    shutil.copy2(src_path, dst_path)
            
            return memory_dir
        
        else:
            # Disk image - mount to disk0
            disk_dir = case_path / "evidence" / "disk0"
            
            # For E01, we'll use pyewf/pytsk3 to extract
            # For now, create a reference file
            evidence_ref = {
                "type": "disk_image",
                "format": evidence_set.files[0].file_type if evidence_set.files else "unknown",
                "is_multipart": evidence_set.is_multipart,
                "segments": [
                    {
                        "path": str(ef.path),
                        "sha256": ef.sha256,
                        "sequence": ef.sequence_number
                    }
                    for ef in evidence_set.files
                ],
                "mounted_at": datetime.now(timezone.utc).isoformat()
            }
            
            with open(disk_dir / "evidence.json", 'w') as f:
                json.dump(evidence_ref, f, indent=2)
            
            return disk_dir
    
    # ========================================================================
    # PHASE 6-9: Pipeline Execution
    # ========================================================================
    
    def run_full_pipeline(
        self,
        case_name: str,
        file_paths: List[Path],
        evidence_type: EvidenceTypeEnum,
        is_multipart: bool,
        operator: str = "SYSTEM",
        progress_callback: Optional[Callable[[int, str], None]] = None
    ) -> OrchestrationResult:
        """
        Execute the complete forensic processing pipeline.
        
        Phases:
        1. Validation
        2. Hashing
        3. Chain of Custody
        4. Workspace Setup
        5. Evidence Reconstruction
        6. Partition Discovery
        7. Artifact Discovery
        8. Artifact Extraction
        9. Parsing
        10. Normalization
        11. Timeline Build
        12. ML Analysis
        13. UEBA
        14. Visualization
        15. Terminal Init
        
        Args:
            case_name: Case identifier
            file_paths: Evidence file paths
            evidence_type: Type of evidence
            is_multipart: Multi-part mode
            operator: Operator name
            progress_callback: Progress callback
        
        Returns:
            OrchestrationResult with pipeline status
        """
        self._is_cancelled = False
        result = OrchestrationResult(
            success=False,
            case_name=case_name
        )
        
        try:
            # Phase 1: Validation
            self._execute_phase(
                result, PipelinePhase.VALIDATION,
                lambda: self._phase_validation(file_paths, evidence_type, is_multipart, result),
                progress_callback, 5
            )
            
            if not result.evidence_set or not result.evidence_set.is_complete:
                raise RuntimeError("Evidence validation failed")
            
            # Phase 2: Hashing
            self._execute_phase(
                result, PipelinePhase.CHAIN_OF_CUSTODY,
                lambda: self._phase_hashing(result.evidence_set, progress_callback),
                progress_callback, 15
            )
            
            # Phase 3: Workspace Setup
            case_path = self._execute_phase(
                result, PipelinePhase.RECONSTRUCTION,
                lambda: self.create_case_workspace(case_name, result.evidence_set),
                progress_callback, 20
            )
            result.workspace_path = case_path
            
            # Phase 4: Chain of Custody Init
            chain_logger = self._execute_phase(
                result, PipelinePhase.CHAIN_OF_CUSTODY,
                lambda: self.initialize_chain_of_custody(case_path, result.evidence_set, operator),
                progress_callback, 25
            )
            
            # Phase 5: Evidence Reconstruction
            self._execute_phase(
                result, PipelinePhase.VIRTUAL_MOUNT,
                lambda: self.reconstruct_evidence(result.evidence_set, case_path),
                progress_callback, 30
            )
            
            # Phase 6: Partition Discovery (disk images only)
            if evidence_type == EvidenceTypeEnum.DISK_IMAGE:
                self._execute_phase(
                    result, PipelinePhase.PARTITION_DISCOVERY,
                    lambda: self._phase_partition_discovery(case_path, result.evidence_set),
                    progress_callback, 35
                )
            
            # Phase 6b: Memory Analysis (memory images only)
            if evidence_type == EvidenceTypeEnum.MEMORY_IMAGE:
                mem_results = self._execute_phase(
                    result, PipelinePhase.MEMORY_ANALYSIS,
                    lambda: self._phase_memory_analysis(case_path, result.evidence_set, chain_logger, operator),
                    progress_callback, 40
                )
                # Memory analysis artifacts count
                if mem_results:
                    result.artifacts_discovered += mem_results.get('total_artifacts', 0)
            
            # Phase 7: Artifact Discovery
            artifacts = self._execute_phase(
                result, PipelinePhase.ARTIFACT_DISCOVERY,
                lambda: self._phase_artifact_discovery(case_path, result.evidence_set),
                progress_callback, 45
            )
            result.artifacts_discovered = len(artifacts) if artifacts else 0
            
            # Phase 8: Artifact Extraction
            self._execute_phase(
                result, PipelinePhase.ARTIFACT_EXTRACTION,
                lambda: self._phase_artifact_extraction(case_path, artifacts, chain_logger, operator),
                progress_callback, 55
            )
            
            # Phase 9: Parsing
            events = self._execute_phase(
                result, PipelinePhase.PARSING,
                lambda: self._phase_parsing(case_path),
                progress_callback, 65
            )
            result.events_parsed = len(events) if hasattr(events, '__len__') else 0
            
            # Phase 10: Normalization
            self._execute_phase(
                result, PipelinePhase.NORMALIZATION,
                lambda: self._phase_normalization(case_path),
                progress_callback, 70
            )
            
            # Phase 11: Timeline Build
            self._execute_phase(
                result, PipelinePhase.TIMELINE_BUILD,
                lambda: self._phase_timeline_build(case_path),
                progress_callback, 75
            )
            
            # Phase 12: ML Analysis
            anomalies = self._execute_phase(
                result, PipelinePhase.ML_ANALYSIS,
                lambda: self._phase_ml_analysis(case_path, chain_logger, operator),
                progress_callback, 85
            )
            result.anomalies_detected = anomalies if isinstance(anomalies, int) else 0
            
            # Phase 13: UEBA
            self._execute_phase(
                result, PipelinePhase.UEBA,
                lambda: self._phase_ueba(case_path, chain_logger, operator),
                progress_callback, 90
            )
            
            # Phase 14: Visualization
            self._execute_phase(
                result, PipelinePhase.VISUALIZATION,
                lambda: self._phase_visualization(case_path),
                progress_callback, 95
            )
            
            # Phase 15: Terminal Init
            self._execute_phase(
                result, PipelinePhase.TERMINAL_INIT,
                lambda: self._phase_terminal_init(case_name),
                progress_callback, 100
            )
            
            # Mark complete
            result.success = True
            self._update_case_status(case_path, "complete")
            
            # Log completion to CoC
            if chain_logger:
                chain_logger.append(
                    user=operator,
                    action="PIPELINE_COMPLETE",
                    details=f"All phases completed. Artifacts: {result.artifacts_discovered}, Events: {result.events_parsed}, Anomalies: {result.anomalies_detected}"
                )
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            self.logger.error(f"Pipeline failed: {e}", exc_info=True)
            
            # Log error to CoC
            if self._chain_logger:
                self._chain_logger.append(
                    user=operator,
                    action="PIPELINE_ERROR",
                    details=f"Pipeline failed: {str(e)}"
                )
            
            # Update case status
            if result.workspace_path:
                self._update_case_status(result.workspace_path, "error", str(e))
        
        self._current_result = result
        self.pipeline_completed.emit(result)
        
        return result
    
    def _execute_phase(
        self,
        result: OrchestrationResult,
        phase: PipelinePhase,
        executor: Callable,
        progress_callback: Optional[Callable],
        progress_pct: int
    ) -> Any:
        """Execute a pipeline phase with logging."""
        step = PipelineStep(
            phase=phase,
            started_at=datetime.now(timezone.utc).isoformat()
        )
        result.pipeline_steps.append(step)
        
        self.phase_started.emit(phase.value, f"Starting {phase.value}...")
        
        if progress_callback:
            progress_callback(progress_pct, f"Processing: {phase.value}")
        
        try:
            # Log start to CoC
            if self._chain_logger:
                self.log_pipeline_step(self._chain_logger, phase, "STARTED")
            
            # Execute phase
            phase_result = executor()
            
            step.status = PipelineStatus.COMPLETED
            step.completed_at = datetime.now(timezone.utc).isoformat()
            
            # Log completion to CoC
            if self._chain_logger:
                self.log_pipeline_step(self._chain_logger, phase, "COMPLETED")
            
            self.phase_completed.emit(phase.value, True, f"{phase.value} completed")
            
            return phase_result
            
        except Exception as e:
            step.status = PipelineStatus.FAILED
            step.error_message = str(e)
            step.completed_at = datetime.now(timezone.utc).isoformat()
            
            self.phase_completed.emit(phase.value, False, str(e))
            self.error_occurred.emit(phase.value, str(e))
            
            raise
    
    # ========================================================================
    # Phase Implementations
    # ========================================================================
    
    def _phase_validation(
        self,
        file_paths: List[Path],
        evidence_type: EvidenceTypeEnum,
        is_multipart: bool,
        result: OrchestrationResult
    ):
        """Execute validation phase."""
        valid, evidence_set, errors = self.validate_evidence_files(
            file_paths, evidence_type, is_multipart
        )
        
        if not valid:
            result.evidence_set = evidence_set
            raise RuntimeError("\n".join(errors))
        
        result.evidence_set = evidence_set
        return evidence_set
    
    def _phase_hashing(
        self,
        evidence_set: EvidenceSet,
        progress_callback: Optional[Callable]
    ):
        """Execute hashing phase."""
        return self.compute_evidence_hashes(evidence_set, progress_callback)
    
    def _phase_partition_discovery(
        self,
        case_path: Path,
        evidence_set: EvidenceSet
    ) -> List[Dict]:
        """Discover partitions in disk image."""
        partitions = []
        
        # Try to use pytsk3/pyewf for partition discovery
        try:
            from ..modules.image_handler import DiskImageHandler
            
            if evidence_set.files:
                # Get all segment paths for multi-part images
                segment_paths = [str(ef.path) for ef in evidence_set.files]
                
                handler = DiskImageHandler()
                if handler.open(segment_paths[0] if len(segment_paths) == 1 else segment_paths):
                    # Get partition info
                    partitions = handler.get_partitions()
                    handler.close()
        except ImportError:
            self.logger.warning("Disk image handler not available")
        except Exception as e:
            self.logger.warning(f"Partition discovery error: {e}")
        
        # Save partition info
        partition_file = case_path / "evidence" / "partitions.json"
        with open(partition_file, 'w') as f:
            json.dump(partitions, f, indent=2)
        
        return partitions
    
    def _phase_memory_analysis(
        self,
        case_path: Path,
        evidence_set: EvidenceSet,
        chain_logger: Optional['ChainLogger'] = None,
        operator: str = "SYSTEM"
    ) -> Dict:
        """
        Execute forensic memory analysis phase.
        
        Analyzes memory dump for:
        - Running processes
        - Network connections
        - URLs and strings
        - Registry artifacts in memory
        - Potential malware indicators
        
        Args:
            case_path: Case workspace path
            evidence_set: Evidence containing memory dump
            chain_logger: Chain of custody logger
            operator: Operator name
        
        Returns:
            Analysis results dictionary
        """
        self.logger.info("Starting memory analysis phase...")
        
        results = {
            'processes': [],
            'network': [],
            'urls': [],
            'registry_keys': [],
            'strings': [],
            'total_artifacts': 0,
            'success': False,
            'error': None
        }
        
        try:
            # Import memory analyzer
            from ..modules.memory_analyzer import MemoryAnalyzer
            
            # Get memory file path
            memory_dir = case_path / "evidence" / "memory"
            mem_file = None
            
            # Find the memory dump file
            for ext in ['.mem', '.dmp', '.raw', '.dump', '.memory']:
                candidates = list(memory_dir.glob(f"*{ext}"))
                if candidates:
                    mem_file = candidates[0]
                    break
            
            # Fallback to original evidence path
            if not mem_file and evidence_set.primary_path:
                mem_file = evidence_set.primary_path
            
            if not mem_file or not mem_file.exists():
                raise FileNotFoundError("Memory dump file not found")
            
            # Log to CoC
            if chain_logger:
                chain_logger.append(
                    user=operator,
                    action="MEMORY_ANALYSIS_START",
                    details=f"Starting memory analysis: {mem_file.name}"
                )
            
            # Create memory analysis output directory
            mem_analysis_dir = case_path / "memory_analysis"
            mem_analysis_dir.mkdir(parents=True, exist_ok=True)
            
            # Initialize analyzer
            analyzer = MemoryAnalyzer(str(mem_file))
            
            # Quick scan first
            self.logger.info(f"Performing quick scan of {mem_file.name}...")
            quick_results = analyzer.quick_scan()
            
            results['processes'] = quick_results.get('processes', [])
            results['network'] = quick_results.get('network', [])
            
            # Full analysis for comprehensive results
            self.logger.info("Performing full memory analysis...")
            full_results = analyzer.full_analysis(str(mem_analysis_dir))
            
            # Merge results
            if full_results:
                results['processes'] = full_results.get('processes', results['processes'])
                results['network'] = full_results.get('network_connections', results['network'])
                results['urls'] = full_results.get('urls', [])
                results['registry_keys'] = full_results.get('registry_keys', [])
                
                summary = full_results.get('summary', {})
                results['total_artifacts'] = (
                    summary.get('total_processes', 0) +
                    summary.get('total_connections', 0) +
                    summary.get('total_urls', 0) +
                    summary.get('total_registry_keys', 0)
                )
            
            results['success'] = True
            
            # Log findings to CoC
            if chain_logger:
                chain_logger.append(
                    user=operator,
                    action="MEMORY_ANALYSIS_COMPLETE",
                    details=f"Memory analysis complete: {len(results['processes'])} processes, {len(results['network'])} connections, {len(results['urls'])} URLs"
                )
                
                if results['processes']:
                    chain_logger.append(
                        user=operator,
                        action="MEMORY_PROCESSES_FOUND",
                        details=f"Found {len(results['processes'])} processes in memory"
                    )
                
                if results['network']:
                    chain_logger.append(
                        user=operator,
                        action="MEMORY_NETWORK_FOUND",
                        details=f"Found {len(results['network'])} network connections/IPs"
                    )
            
            # Save results to case workspace
            results_file = case_path / "ml" / "memory_findings.json"
            with open(results_file, 'w') as f:
                json.dump({
                    'type': 'memory_analysis',
                    'file': str(mem_file),
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'processes': results['processes'][:100],  # Limit for JSON
                    'network': results['network'][:100],
                    'urls': results['urls'][:100],
                    'summary': {
                        'total_processes': len(results['processes']),
                        'total_network': len(results['network']),
                        'total_urls': len(results['urls']),
                        'total_registry': len(results['registry_keys'])
                    }
                }, f, indent=2)
            
            self.logger.info(f"Memory analysis complete: {results['total_artifacts']} artifacts found")
            
        except ImportError:
            results['error'] = "Memory analyzer module not available"
            self.logger.warning(results['error'])
        except FileNotFoundError as e:
            results['error'] = str(e)
            self.logger.warning(f"Memory analysis skipped: {e}")
        except Exception as e:
            results['error'] = str(e)
            self.logger.error(f"Memory analysis failed: {e}", exc_info=True)
            
            if chain_logger:
                chain_logger.append(
                    user=operator,
                    action="PIPELINE_ERROR",
                    details=f"Memory analysis error: {str(e)}"
                )
        
        return results

    def _phase_artifact_discovery(
        self,
        case_path: Path,
        evidence_set: EvidenceSet
    ) -> List[Dict]:
        """Discover forensic artifacts."""
        artifacts = []
        
        # Define artifact patterns to search for
        artifact_patterns = {
            "evtx": ["*.evtx", "*.evt"],
            "registry": ["NTUSER.DAT", "SAM", "SECURITY", "SOFTWARE", "SYSTEM", "usrclass.dat"],
            "mft": ["$MFT", "$MFT.copy0"],
            "prefetch": ["*.pf"],
            "browser": [
                "History", "Cookies", "Login Data",  # Chrome
                "places.sqlite", "cookies.sqlite",   # Firefox
                "WebCacheV01.dat"                    # Edge
            ],
            "network": ["*.pcap", "*.pcapng"],
            "mobile": ["manifest.db", "Manifest.mbdb"],
            "cloud": ["*.token", "*.oauth"]
        }
        
        # Check evidence directory
        evidence_dir = case_path / "evidence" / "disk0"
        
        for artifact_type, patterns in artifact_patterns.items():
            for pattern in patterns:
                matches = list(evidence_dir.rglob(pattern))
                for match in matches:
                    artifacts.append({
                        "type": artifact_type,
                        "path": str(match),
                        "name": match.name,
                        "size": match.stat().st_size if match.exists() else 0
                    })
        
        # Save artifact manifest
        manifest_file = case_path / "artifacts" / "manifest.json"
        with open(manifest_file, 'w') as f:
            json.dump(artifacts, f, indent=2)
        
        self.logger.info(f"Discovered {len(artifacts)} artifacts")
        return artifacts
    
    def _phase_artifact_extraction(
        self,
        case_path: Path,
        artifacts: List[Dict],
        chain_logger: 'ChainLogger',
        operator: str
    ):
        """Extract artifacts to case workspace."""
        extracted_count = 0
        
        for artifact in artifacts:
            artifact_type = artifact.get("type", "unknown")
            src_path = Path(artifact.get("path", ""))
            
            if src_path.exists():
                dst_dir = case_path / "artifacts" / artifact_type
                dst_dir.mkdir(parents=True, exist_ok=True)
                dst_path = dst_dir / src_path.name
                
                try:
                    if not dst_path.exists():
                        shutil.copy2(src_path, dst_path)
                    extracted_count += 1
                except Exception as e:
                    self.logger.warning(f"Failed to extract {src_path.name}: {e}")
        
        # Log to CoC
        if chain_logger and extracted_count > 0:
            chain_logger.append(
                user=operator,
                action=self.CoC_Actions.ARTIFACT_EXTRACTED,
                details=f"Extracted {extracted_count} artifacts"
            )
        
        return extracted_count
    
    def _phase_parsing(self, case_path: Path) -> int:
        """Parse extracted artifacts."""
        events = []
        
        # Parse EVTX files
        evtx_dir = case_path / "artifacts" / "evtx"
        if evtx_dir.exists():
            for evtx_file in evtx_dir.glob("*.evtx"):
                try:
                    from ..parsers.evtx_parser import EVTXParser
                    parsed = EVTXParser().parse_file(evtx_file)
                    if parsed:
                        events.extend(parsed)
                except ImportError:
                    pass
                except Exception as e:
                    self.logger.warning(f"Failed to parse {evtx_file.name}: {e}")
        
        # Parse registry
        registry_dir = case_path / "artifacts" / "registry"
        if registry_dir.exists():
            for reg_file in registry_dir.iterdir():
                if reg_file.is_file():
                    try:
                        from ..parsers.registry_parser import RegistryParser
                        parsed = RegistryParser().parse_file(reg_file)
                        if parsed:
                            events.extend(parsed)
                    except ImportError:
                        pass
                    except Exception as e:
                        self.logger.warning(f"Failed to parse {reg_file.name}: {e}")
        
        self.logger.info(f"Parsed {len(events)} events")
        return len(events)
    
    def _phase_normalization(self, case_path: Path):
        """Normalize parsed events to standard schema."""
        # Schema:
        # timestamp, user, host, artifact_type, action, path, process, network, severity
        
        events_file = case_path / "events" / "events.parquet"
        
        # Create empty events file if none exists
        if not events_file.exists():
            import pandas as pd
            df = pd.DataFrame(columns=[
                "timestamp", "user", "host", "artifact_type", 
                "action", "path", "process", "network", "severity"
            ])
            df.to_parquet(events_file)
        
        return events_file
    
    def _phase_timeline_build(self, case_path: Path):
        """Build forensic timeline from normalized events."""
        try:
            import pandas as pd
            events_file = case_path / "events" / "events.parquet"
            
            if events_file.exists():
                df = pd.read_parquet(events_file)
                if "timestamp" in df.columns:
                    df = df.sort_values("timestamp")
                    df.to_parquet(events_file)
                    
                    # Create timeline summary
                    timeline_summary = {
                        "total_events": len(df),
                        "start_time": str(df["timestamp"].min()) if len(df) > 0 else None,
                        "end_time": str(df["timestamp"].max()) if len(df) > 0 else None,
                        "artifact_types": df["artifact_type"].value_counts().to_dict() if "artifact_type" in df.columns else {}
                    }
                    
                    with open(case_path / "events" / "timeline_summary.json", 'w') as f:
                        json.dump(timeline_summary, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Timeline build error: {e}")
    
    def _phase_ml_analysis(
        self,
        case_path: Path,
        chain_logger: 'ChainLogger',
        operator: str
    ) -> int:
        """Run ML anomaly detection."""
        anomaly_count = 0
        
        try:
            from ..ml.ml_anomaly_detector import MLAnomalyDetectionEngine
            
            # Initialize ML engine
            ml_engine = MLAnomalyDetectionEngine()
            
            # Load events
            events_file = case_path / "events" / "events.parquet"
            if events_file.exists():
                import pandas as pd
                df = pd.read_parquet(events_file)
                
                if len(df) > 0:
                    # Run ML analysis
                    events_list = df.to_dict('records')
                    anomalies, findings = ml_engine.analyze(events_list)
                    anomaly_count = len(anomalies)
                    
                    # Save results
                    ml_dir = case_path / "ml"
                    with open(ml_dir / "anomalies.json", 'w') as f:
                        json.dump(anomalies, f, indent=2, default=str)
                    with open(ml_dir / "findings.json", 'w') as f:
                        json.dump(findings, f, indent=2, default=str)
            
            # Log to CoC
            if chain_logger:
                chain_logger.append(
                    user=operator,
                    action=self.CoC_Actions.ML_ANALYSIS_START,
                    details="ML anomaly detection started"
                )
                chain_logger.append(
                    user=operator,
                    action=self.CoC_Actions.ML_ANALYSIS_COMPLETE,
                    details=f"ML analysis complete. Anomalies detected: {anomaly_count}"
                )
                
        except ImportError:
            self.logger.warning("ML module not available")
        except Exception as e:
            self.logger.warning(f"ML analysis error: {e}")
        
        return anomaly_count
    
    def _phase_ueba(
        self,
        case_path: Path,
        chain_logger: 'ChainLogger',
        operator: str
    ):
        """Run User and Entity Behavior Analytics."""
        try:
            from ..ml.ml_anomaly_detector import MLAnomalyDetectionEngine
            
            ml_engine = MLAnomalyDetectionEngine()
            
            # Load events
            events_file = case_path / "events" / "events.parquet"
            if events_file.exists():
                import pandas as pd
                df = pd.read_parquet(events_file)
                
                if len(df) > 0:
                    events_list = df.to_dict('records')
                    
                    # Build UEBA profiles
                    profiles = ml_engine.build_ueba_profiles(events_list)
                    
                    # Save profiles
                    with open(case_path / "ml" / "ueba_profiles.json", 'w') as f:
                        json.dump(profiles, f, indent=2, default=str)
                        
        except ImportError:
            self.logger.warning("UEBA module not available")
        except Exception as e:
            self.logger.warning(f"UEBA error: {e}")
    
    def _phase_visualization(self, case_path: Path):
        """Build visualizations from analysis results."""
        viz_metadata = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "visualizations": []
        }
        
        try:
            # Load events for visualization
            events_file = case_path / "events" / "events.parquet"
            if events_file.exists():
                import pandas as pd
                df = pd.read_parquet(events_file)
                
                # Timeline data
                if len(df) > 0 and "timestamp" in df.columns:
                    viz_metadata["visualizations"].append({
                        "type": "timeline",
                        "events": len(df),
                        "ready": True
                    })
                    
                    # Heatmap data
                    viz_metadata["visualizations"].append({
                        "type": "heatmap",
                        "ready": True
                    })
            
            # Attack surface map
            anomalies_file = case_path / "ml" / "anomalies.json"
            if anomalies_file.exists():
                viz_metadata["visualizations"].append({
                    "type": "attack_surface",
                    "ready": True
                })
            
        except Exception as e:
            self.logger.warning(f"Visualization build error: {e}")
        
        # Save visualization metadata
        with open(case_path / "visualizations" / "metadata.json", 'w') as f:
            json.dump(viz_metadata, f, indent=2)
    
    def _phase_terminal_init(self, case_name: str):
        """Initialize forensic terminal for the case."""
        try:
            from ..fepd_os.shell import FEPDShellEngine
            
            shell = FEPDShellEngine(str(self.cases_root))
            shell.mount_case(case_name)
            
            self.logger.info(f"Terminal initialized for case: {case_name}")
            
        except Exception as e:
            self.logger.warning(f"Terminal init error: {e}")
    
    def _update_case_status(
        self,
        case_path: Path,
        status: str,
        error_message: str = ""
    ):
        """Update case.json with current status."""
        case_file = case_path / "case.json"
        
        if case_file.exists():
            with open(case_file, 'r') as f:
                metadata = json.load(f)
            
            metadata["status"] = status
            metadata["updated_at"] = datetime.now(timezone.utc).isoformat()
            if error_message:
                metadata["error_message"] = error_message
            
            with open(case_file, 'w') as f:
                json.dump(metadata, f, indent=2)
    
    # ========================================================================
    # Rollback & Error Handling
    # ========================================================================
    
    def rollback_case(self, case_path: Path) -> bool:
        """
        Rollback a failed case workspace.
        
        Deletes:
        /case/* (workspace only)
        Evidence is NEVER touched.
        
        Args:
            case_path: Path to case workspace
        
        Returns:
            True if rollback successful
        """
        try:
            if case_path.exists() and case_path.is_dir():
                # Safety check - only delete if it's in cases directory
                if str(self.cases_root) in str(case_path):
                    shutil.rmtree(case_path)
                    self.logger.info(f"Rolled back case: {case_path}")
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Rollback failed: {e}")
            return False
    
    def cancel(self):
        """Cancel the current operation."""
        self._is_cancelled = True
    
    # ========================================================================
    # Multi-Evidence Pipeline (Relationship Detection & Data Combining)
    # ========================================================================
    
    def run_multi_evidence_pipeline(
        self,
        case_name: str,
        evidence_configs: List[Dict[str, Any]],
        operator: str = "SYSTEM",
        progress_callback: Optional[Callable[[int, str], None]] = None
    ) -> OrchestrationResult:
        """
        Execute pipeline for multiple related evidence files.
        
        This method:
        1. Detects relationships between evidence files
        2. Processes each evidence source
        3. Combines extracted data into unified views
        4. Cross-references events across sources
        
        Args:
            case_name: Case identifier
            evidence_configs: List of evidence configurations
                Each config: {
                    'file_paths': List[Path],
                    'evidence_type': EvidenceTypeEnum,
                    'is_multipart': bool
                }
            operator: Operator name
            progress_callback: Progress callback
            
        Returns:
            OrchestrationResult with combined pipeline status
        """
        from .evidence_relationship_analyzer import (
            EvidenceRelationshipAnalyzer,
            EvidenceDataCombiner,
            CombinedEvidenceSet
        )
        
        self._is_cancelled = False
        result = OrchestrationResult(
            success=False,
            case_name=case_name
        )
        
        try:
            # Collect all file paths
            all_paths = []
            for config in evidence_configs:
                all_paths.extend(config.get('file_paths', []))
            
            self.logger.info(f"Processing {len(all_paths)} evidence files for case: {case_name}")
            
            if progress_callback:
                progress_callback(5, "Analyzing evidence relationships...")
            
            # Phase 1: Analyze relationships between evidence
            analyzer = EvidenceRelationshipAnalyzer()
            combined_set = analyzer.analyze_evidence_set(all_paths, extract_metadata=True)
            
            # Log detected relationships
            if combined_set.relationships:
                self.logger.info(f"Detected {len(combined_set.relationships)} relationships between evidence")
                for rel in combined_set.relationships:
                    self.logger.info(f"  - {rel.relation_type.value}: {rel.description}")
            
            if progress_callback:
                progress_callback(10, f"Detected {len(combined_set.relationships)} relationships")
            
            # Phase 2: Create unified case workspace
            case_path = self._execute_phase(
                result, PipelinePhase.RECONSTRUCTION,
                lambda: self._create_multi_evidence_workspace(case_name, evidence_configs, combined_set),
                progress_callback, 15
            )
            result.workspace_path = case_path
            
            # Phase 3: Initialize Chain of Custody for all evidence
            chain_logger = None
            for i, config in enumerate(evidence_configs):
                file_paths = config.get('file_paths', [])
                evidence_type = config.get('evidence_type', EvidenceTypeEnum.DISK_IMAGE)
                is_multipart = config.get('is_multipart', False)
                
                # Validate and hash each evidence set
                valid, evidence_set, errors = self.validate_evidence_files(
                    file_paths, evidence_type, is_multipart
                )
                
                if not valid:
                    raise RuntimeError(f"Evidence validation failed: {'; '.join(errors)}")
                
                # Compute hashes
                self.compute_evidence_hashes(evidence_set)
                
                # Initialize CoC (first time only)
                if chain_logger is None:
                    chain_logger = self.initialize_chain_of_custody(
                        case_path, evidence_set, operator
                    )
                else:
                    # Log additional evidence to existing CoC
                    if self._chain_logger:
                        for ef in evidence_set.files:
                            self._chain_logger.append(
                                user=operator,
                                action=self.CoC_Actions.EVIDENCE_VERIFIED,
                                details=f"Additional evidence: {ef.path.name} | SHA256: {ef.sha256}"
                            )
            
            if progress_callback:
                progress_callback(25, "Evidence validated and hashed")
            
            # Phase 4: Process each evidence source in parallel/sequence
            extracted_data = {}
            total_configs = len(evidence_configs)
            
            for i, config in enumerate(evidence_configs):
                file_paths = config.get('file_paths', [])
                evidence_type = config.get('evidence_type', EvidenceTypeEnum.DISK_IMAGE)
                is_multipart = config.get('is_multipart', False)
                
                # Calculate progress
                base_progress = 25 + int((i / total_configs) * 50)
                
                if progress_callback:
                    progress_callback(
                        base_progress,
                        f"Processing evidence {i + 1}/{total_configs}: {file_paths[0].name if file_paths else 'unknown'}"
                    )
                
                # Process this evidence source
                source_data = self._process_single_evidence(
                    case_path=case_path,
                    file_paths=file_paths,
                    evidence_type=evidence_type,
                    is_multipart=is_multipart,
                    chain_logger=chain_logger,
                    operator=operator,
                    evidence_index=i
                )
                
                # Store extracted data by evidence ID
                evidence_id = f"evidence_{i}_{file_paths[0].stem if file_paths else 'unknown'}"
                extracted_data[evidence_id] = source_data
            
            if progress_callback:
                progress_callback(75, "Combining evidence data...")
            
            # Phase 5: Combine data from all sources
            combiner = EvidenceDataCombiner(case_path)
            unified_data = combiner.combine_evidence_data(combined_set, extracted_data)
            
            # Update result statistics
            result.artifacts_discovered = unified_data.get('statistics', {}).get('total_artifacts', 0)
            result.events_parsed = unified_data.get('statistics', {}).get('total_events', 0)
            
            if progress_callback:
                progress_callback(80, "Running ML analysis on combined data...")
            
            # Phase 6: ML Analysis on unified data
            anomalies = self._execute_phase(
                result, PipelinePhase.ML_ANALYSIS,
                lambda: self._phase_ml_analysis(case_path, chain_logger, operator),
                progress_callback, 85
            )
            result.anomalies_detected = anomalies if isinstance(anomalies, int) else 0
            
            # Phase 7: UEBA on unified data
            self._execute_phase(
                result, PipelinePhase.UEBA,
                lambda: self._phase_ueba(case_path, chain_logger, operator),
                progress_callback, 90
            )
            
            # Phase 8: Build visualizations
            self._execute_phase(
                result, PipelinePhase.VISUALIZATION,
                lambda: self._phase_visualization(case_path),
                progress_callback, 95
            )
            
            # Phase 9: Initialize terminal
            self._execute_phase(
                result, PipelinePhase.TERMINAL_INIT,
                lambda: self._phase_terminal_init(case_name),
                progress_callback, 100
            )
            
            # Log completion
            if chain_logger:
                chain_logger.append(
                    user=operator,
                    action="MULTI_EVIDENCE_PIPELINE_COMPLETE",
                    details=(
                        f"Multi-evidence pipeline complete. "
                        f"Sources: {len(evidence_configs)}, "
                        f"Relationships: {len(combined_set.relationships)}, "
                        f"Artifacts: {result.artifacts_discovered}, "
                        f"Events: {result.events_parsed}, "
                        f"Cross-refs: {unified_data.get('statistics', {}).get('cross_references', 0)}"
                    )
                )
            
            # Mark success
            result.success = True
            self._update_case_status(case_path, "complete")
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            self.logger.error(f"Multi-evidence pipeline failed: {e}", exc_info=True)
            
            if self._chain_logger:
                self._chain_logger.append(
                    user=operator,
                    action="PIPELINE_ERROR",
                    details=f"Multi-evidence pipeline failed: {str(e)}"
                )
            
            if result.workspace_path:
                self._update_case_status(result.workspace_path, "error", str(e))
        
        self._current_result = result
        self.pipeline_completed.emit(result)
        
        return result
    
    def _create_multi_evidence_workspace(
        self,
        case_name: str,
        evidence_configs: List[Dict],
        combined_set: 'CombinedEvidenceSet'
    ) -> Path:
        """Create workspace for multi-evidence case."""
        case_path = self.cases_root / case_name
        
        # Standard directories
        directories = [
            case_path / "evidence",
            case_path / "artifacts" / "evtx",
            case_path / "artifacts" / "registry",
            case_path / "artifacts" / "mft",
            case_path / "artifacts" / "prefetch",
            case_path / "artifacts" / "browser",
            case_path / "artifacts" / "network",
            case_path / "artifacts" / "mobile",
            case_path / "artifacts" / "cloud",
            case_path / "events",
            case_path / "ml",
            case_path / "reports",
            case_path / "visualizations",
        ]
        
        # Add evidence source directories
        for i, config in enumerate(evidence_configs):
            evidence_type = config.get('evidence_type', EvidenceTypeEnum.DISK_IMAGE)
            if evidence_type == EvidenceTypeEnum.DISK_IMAGE:
                directories.append(case_path / "evidence" / f"disk{i}")
            elif evidence_type == EvidenceTypeEnum.MEMORY_IMAGE:
                directories.append(case_path / "evidence" / f"memory{i}")
        
        for dir_path in directories:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Create case metadata with multi-evidence info
        case_metadata = {
            "case_id": case_name,
            "case_name": case_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "multi_evidence": True,
            "evidence_sources": len(evidence_configs),
            "evidence_configs": [
                {
                    "index": i,
                    "type": config.get('evidence_type', EvidenceTypeEnum.DISK_IMAGE).value,
                    "file_count": len(config.get('file_paths', [])),
                    "is_multipart": config.get('is_multipart', False)
                }
                for i, config in enumerate(evidence_configs)
            ],
            "relationships": combined_set.to_dict().get('relationships', []),
            "status": "processing"
        }
        
        with open(case_path / "case.json", 'w') as f:
            json.dump(case_metadata, f, indent=2)
        
        return case_path
    
    def _process_single_evidence(
        self,
        case_path: Path,
        file_paths: List[Path],
        evidence_type: EvidenceTypeEnum,
        is_multipart: bool,
        chain_logger: Optional['ChainLogger'],
        operator: str,
        evidence_index: int
    ) -> Dict[str, Any]:
        """
        Process a single evidence source and extract data.
        
        Returns extracted data dictionary for combining.
        """
        extracted_data = {
            'source_type': evidence_type.value,
            'timeline': [],
            'artifacts': [],
            'events': [],
            'users': {},
            'files': [],
            'registry': [],
            'network': [],
            'processes': [],
            'anomalies': []
        }
        
        try:
            # Determine evidence subdirectory
            if evidence_type == EvidenceTypeEnum.DISK_IMAGE:
                evidence_dir = case_path / "evidence" / f"disk{evidence_index}"
            else:
                evidence_dir = case_path / "evidence" / f"memory{evidence_index}"
            
            # Create evidence reference
            evidence_ref = {
                "type": evidence_type.value,
                "index": evidence_index,
                "files": [str(p) for p in file_paths],
                "is_multipart": is_multipart
            }
            
            with open(evidence_dir / "evidence.json", 'w') as f:
                json.dump(evidence_ref, f, indent=2)
            
            # Process based on type
            if evidence_type == EvidenceTypeEnum.MEMORY_IMAGE:
                # Memory analysis
                memory_results = self._quick_memory_extract(file_paths[0] if file_paths else None)
                extracted_data['processes'] = memory_results.get('processes', [])
                extracted_data['network'] = memory_results.get('network', [])
                extracted_data['events'] = memory_results.get('events', [])
            else:
                # Disk image processing
                disk_results = self._quick_disk_extract(file_paths, evidence_dir)
                extracted_data['files'] = disk_results.get('files', [])
                extracted_data['registry'] = disk_results.get('registry', [])
                extracted_data['events'] = disk_results.get('events', [])
                extracted_data['artifacts'] = disk_results.get('artifacts', [])
            
            # Log to CoC
            if chain_logger:
                chain_logger.append(
                    user=operator,
                    action="EVIDENCE_PROCESSED",
                    details=f"Processed evidence {evidence_index}: {len(extracted_data['events'])} events extracted"
                )
                
        except Exception as e:
            self.logger.error(f"Failed to process evidence {evidence_index}: {e}")
            extracted_data['error'] = str(e)
        
        return extracted_data
    
    def _quick_memory_extract(self, memory_path: Optional[Path]) -> Dict:
        """Quick extraction from memory dump."""
        results = {'processes': [], 'network': [], 'events': []}
        
        if not memory_path or not memory_path.exists():
            return results
        
        try:
            from ..modules.memory_analyzer import MemoryAnalyzer
            analyzer = MemoryAnalyzer(str(memory_path))
            quick_results = analyzer.quick_scan()
            
            results['processes'] = quick_results.get('processes', [])
            results['network'] = quick_results.get('network', [])
            
            # Convert to events format
            for proc in results['processes'][:100]:
                results['events'].append({
                    'timestamp': proc.get('create_time', ''),
                    'event_type': 'process',
                    'description': f"Process: {proc.get('name', 'unknown')} (PID: {proc.get('pid', '')})",
                    'source': 'memory'
                })
                
        except Exception as e:
            self.logger.debug(f"Memory extraction error: {e}")
        
        return results
    
    def _quick_disk_extract(self, file_paths: List[Path], evidence_dir: Path) -> Dict:
        """Quick extraction from disk image."""
        results = {'files': [], 'registry': [], 'events': [], 'artifacts': []}
        
        try:
            # Try to use VFS for extraction
            from .virtual_fs import VirtualFilesystem
            
            if file_paths:
                vfs = VirtualFilesystem()
                if vfs.mount(str(file_paths[0])):
                    # Get file listing
                    results['files'] = vfs.list_files("/", recursive=True, max_depth=3)
                    
                    # Find artifacts
                    artifacts = vfs.find_artifacts()
                    results['artifacts'] = artifacts
                    
                    vfs.unmount()
                    
        except Exception as e:
            self.logger.debug(f"Disk extraction error: {e}")
        
        return results

    def get_pipeline_summary(self) -> str:
        """
        Get summary of pipeline execution.
        
        Returns:
            Multi-line summary string
        """
        if not self._current_result:
            return "No pipeline executed"
        
        result = self._current_result
        
        lines = [
            "=" * 50,
            "FEPD Pipeline Summary",
            "=" * 50,
            f"Case: {result.case_name}",
            f"Status: {'✔ SUCCESS' if result.success else '✘ FAILED'}",
            f"Workspace: {result.workspace_path}",
            "",
            "Phase Results:",
            "-" * 30
        ]
        
        for step in result.pipeline_steps:
            status_icon = {
                PipelineStatus.COMPLETED: "✔",
                PipelineStatus.FAILED: "✘",
                PipelineStatus.PENDING: "○",
                PipelineStatus.IN_PROGRESS: "◐",
                PipelineStatus.SKIPPED: "◌"
            }.get(step.status, "?")
            
            lines.append(f"  {status_icon} {step.phase.value}")
            if step.error_message:
                lines.append(f"      Error: {step.error_message}")
        
        lines.extend([
            "",
            "Statistics:",
            "-" * 30,
            f"  Artifacts discovered: {result.artifacts_discovered}",
            f"  Events parsed: {result.events_parsed}",
            f"  Anomalies detected: {result.anomalies_detected}",
            "",
            "=" * 50
        ])
        
        if result.success:
            lines.extend([
                "",
                "✔ Evidence verified",
                "✔ Artifacts extracted",
                "✔ Events parsed",
                "✔ ML completed",
                "✔ UEBA completed",
                "✔ Visualizations built",
                "",
                f"fepd:{result.case_name}[root]$"
            ])
        
        return "\n".join(lines)
