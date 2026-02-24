"""
FEPD - Forensic Evidence Parser Dashboard
Artifact Extraction Module

Extracts discovered artifacts from forensic images to case workspace.
Computes SHA-256 hashes and logs to Chain of Custody.

Implements FR-07, FR-08, FR-09: Extract artifacts, hash, and log to CoC

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .discovery import DiscoveredArtifact, ArtifactType
from ..utils.hash_utils import ForensicHasher
from ..utils.chain_of_custody import ChainOfCustody


@dataclass
class ExtractedArtifact:
    """
    Represents an extracted forensic artifact with dual-path tracking.
    
    FORENSIC PATH DISTINCTION:
    - internal_path: Original location INSIDE the evidence image
      Example: /C:/Windows/System32/config/SYSTEM
      This is the "source of truth" for forensic purposes.
      
    - extracted_path: Location in FEPD workspace where artifact was copied
      Example: cases/case-001/artifacts/registry/SYSTEM.hive
      This is where FEPD stores the extracted copy.
    
    UI should always display BOTH paths clearly labeled:
      📀 Source: EVIDENCE:/C:/Windows/System32/config/SYSTEM
      📁 Stored: cases/case-001/artifacts/registry/SYSTEM.hive
    
    Attributes:
        artifact_type: Type of artifact (EVTX, Registry, etc.)
        internal_path: Original path inside forensic image [EVIDENCE]
        extracted_path: Path to extracted file in workspace [WORKSPACE]
        sha256_hash: SHA-256 hash of extracted file
        size_bytes: File size in bytes
        extracted_at: ISO timestamp of extraction
    """
    artifact_type: ArtifactType
    internal_path: str           # [EVIDENCE] - Original path inside image
    extracted_path: Path         # [WORKSPACE] - Extracted copy location
    sha256_hash: str
    size_bytes: int
    extracted_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    @property
    def evidence_path(self) -> str:
        """Alias for internal_path - the original evidence location."""
        return self.internal_path
    
    @property
    def workspace_path(self) -> str:
        """Alias for extracted_path as string."""
        return str(self.extracted_path)
    
    def get_display_paths(self) -> dict:
        """
        Get paths formatted for UI display.
        
        Returns:
            {
                'evidence': '📀 EVIDENCE:/C:/Windows/System32/config/SYSTEM',
                'workspace': '📁 cases/case-001/artifacts/SYSTEM.hive',
                'both': 'Source: ... / Stored: ...'
            }
        """
        return {
            'evidence': f"📀 EVIDENCE:{self.internal_path}",
            'workspace': f"📁 {self.extracted_path}",
            'both': f"📀 Source: EVIDENCE:{self.internal_path}\n📁 Stored: {self.extracted_path}"
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation with clear path labels."""
        return {
            'artifact_type': self.artifact_type.value,
            'internal_path': self.internal_path,      # [EVIDENCE] path
            'evidence_path': self.internal_path,      # Alias for clarity
            'extracted_path': str(self.extracted_path),  # [WORKSPACE] path
            'workspace_path': str(self.extracted_path),  # Alias for clarity
            'sha256_hash': self.sha256_hash,
            'size_bytes': self.size_bytes,
            'extracted_at': self.extracted_at
        }


class ArtifactExtraction:
    """
    Artifact Extraction Engine.
    
    Extracts artifacts from mounted forensic images to case workspace.
    Features:
    - Read-only source access
    - SHA-256 hash computation
    - Chain of Custody logging
    - Progress tracking
    - Error handling (skip corrupted artifacts)
    """
    
    def __init__(
        self,
        workspace_dir: Path,
        coc: ChainOfCustody,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize Artifact Extraction engine.
        
        Args:
            workspace_dir: Case workspace directory for extracted artifacts
            coc: Chain of Custody logger
            logger: Optional logger instance
        """
        self.workspace_dir = Path(workspace_dir)
        self.coc = coc
        self.logger = logger or logging.getLogger(__name__)
        
        self.extracted_artifacts: List[ExtractedArtifact] = []
        
        # Create workspace subdirectories
        self._create_workspace_structure()
    
    def _create_workspace_structure(self) -> None:
        """Create workspace directory structure for extracted artifacts."""
        subdirs = ['evtx', 'registry', 'prefetch', 'mft', 'browser', 'lnk', 
                   'linux_config', 'linux_log', 'script', 'binary', 'other']
        
        for subdir in subdirs:
            (self.workspace_dir / subdir).mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Workspace structure created at: {self.workspace_dir}")
    
    def extract(
        self,
        artifacts: List[DiscoveredArtifact],
        mount_point: Path,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> List[ExtractedArtifact]:
        """
        Extract discovered artifacts from mounted image.
        
        Args:
            artifacts: List of discovered artifacts to extract
            mount_point: Path to mounted image root
            progress_callback: Optional callback(current, total, message)
            
        Returns:
            List of successfully extracted artifacts
        """
        self.logger.info(f"Starting extraction of {len(artifacts)} artifacts...")
        self.extracted_artifacts = []
        
        total = len(artifacts)
        
        for idx, artifact in enumerate(artifacts, 1):
            try:
                # Progress callback
                if progress_callback:
                    progress_callback(
                        idx, 
                        total, 
                        f"Extracting {artifact.description}..."
                    )
                
                extracted = self._extract_artifact(artifact, mount_point)
                self.extracted_artifacts.append(extracted)
                
                self.logger.debug(f"Extracted: {artifact.description}")
            
            except Exception as e:
                self.logger.warning(f"Failed to extract {artifact.internal_path}: {e}")
                # Continue with next artifact (NFR-09 compliance)
                continue
        
        # Final progress callback
        if progress_callback:
            progress_callback(total, total, "Extraction complete")
        
        self.logger.info(f"Successfully extracted {len(self.extracted_artifacts)} artifacts")
        return self.extracted_artifacts
    
    def _extract_artifact(
        self,
        artifact: DiscoveredArtifact,
        mount_point: Path
    ) -> ExtractedArtifact:
        """
        Extract a single artifact.
        
        Args:
            artifact: Artifact to extract
            mount_point: Mount point of image
            
        Returns:
            ExtractedArtifact instance
            
        Raises:
            Exception: If extraction fails
        """
        # Source path
        source_path = mount_point / artifact.internal_path
        
        if not source_path.exists():
            raise FileNotFoundError(f"Source artifact not found: {source_path}")
        
        # Determine destination subdirectory
        subdir = self._get_artifact_subdir(artifact.artifact_type)
        
        # Destination path (preserve original filename)
        dest_filename = source_path.name
        dest_path = self.workspace_dir / subdir / dest_filename
        
        # Handle filename collisions
        counter = 1
        while dest_path.exists():
            stem = source_path.stem
            suffix = source_path.suffix
            dest_filename = f"{stem}_{counter}{suffix}"
            dest_path = self.workspace_dir / subdir / dest_filename
            counter += 1
        
        # Copy file (read-only source)
        shutil.copy2(source_path, dest_path)
        
        # Compute SHA-256 hash
        hasher = ForensicHasher()
        sha256_hash = hasher.hash_file(dest_path)
        
        # Log to Chain of Custody
        self.coc.log_entry(
            event="ARTIFACT_EXTRACTED",
            hash_value=sha256_hash,
            reason=f"Extracted {artifact.description}",
            metadata={
                'artifact_type': artifact.artifact_type.value,
                'internal_path': artifact.internal_path,
                'extracted_path': str(dest_path),
                'size_bytes': artifact.size_bytes
            }
        )
        
        # Create extracted artifact record
        extracted = ExtractedArtifact(
            artifact_type=artifact.artifact_type,
            internal_path=artifact.internal_path,
            extracted_path=dest_path,
            sha256_hash=sha256_hash,
            size_bytes=artifact.size_bytes
        )
        
        return extracted
    
    def _get_artifact_subdir(self, artifact_type: ArtifactType) -> str:
        """Get workspace subdirectory name for artifact type."""
        mapping = {
            ArtifactType.EVTX: 'evtx',
            ArtifactType.REGISTRY: 'registry',
            ArtifactType.PREFETCH: 'prefetch',
            ArtifactType.MFT: 'mft',
            ArtifactType.BROWSER: 'browser',
            ArtifactType.LNK: 'lnk',
            ArtifactType.LINUX_CONFIG: 'linux_config',
            ArtifactType.LINUX_LOG: 'linux_log',
            ArtifactType.SCRIPT: 'script',
            ArtifactType.BINARY: 'binary',
            ArtifactType.UNKNOWN: 'other'
        }
        return mapping.get(artifact_type, 'other')
    
    def get_extracted_by_type(self, artifact_type: ArtifactType) -> List[ExtractedArtifact]:
        """
        Get all extracted artifacts of a specific type.
        
        Args:
            artifact_type: Type to filter
            
        Returns:
            List of extracted artifacts
        """
        return [a for a in self.extracted_artifacts if a.artifact_type == artifact_type]
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get extraction summary statistics.
        
        Returns:
            Dictionary with statistics
        """
        summary = {
            'total_extracted': len(self.extracted_artifacts),
            'total_size_bytes': sum(a.size_bytes for a in self.extracted_artifacts),
            'by_type': {}
        }
        
        for artifact_type in ArtifactType:
            artifacts = self.get_extracted_by_type(artifact_type)
            if artifacts:
                summary['by_type'][artifact_type.value] = {
                    'count': len(artifacts),
                    'size_bytes': sum(a.size_bytes for a in artifacts)
                }
        
        return summary
    
    def export_to_list(self) -> List[Dict[str, Any]]:
        """
        Export extracted artifacts to list of dictionaries.
        
        Returns:
            List of artifact dictionaries
        """
        return [artifact.to_dict() for artifact in self.extracted_artifacts]
    
    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify integrity of all extracted artifacts by re-computing hashes.
        
        Returns:
            Dictionary with verification results
        """
        self.logger.info("Verifying integrity of extracted artifacts...")
        
        results = {
            'total_checked': len(self.extracted_artifacts),
            'verified': 0,
            'failed': 0,
            'missing': 0,
            'failures': []
        }
        
        for artifact in self.extracted_artifacts:
            if not artifact.extracted_path.exists():
                results['missing'] += 1
                results['failures'].append({
                    'path': str(artifact.extracted_path),
                    'reason': 'File missing'
                })
                continue
            
            # Re-compute hash
            hasher = ForensicHasher()
            current_hash = hasher.hash_file(artifact.extracted_path)
            
            if current_hash == artifact.sha256_hash:
                results['verified'] += 1
            else:
                results['failed'] += 1
                results['failures'].append({
                    'path': str(artifact.extracted_path),
                    'reason': 'Hash mismatch',
                    'expected': artifact.sha256_hash,
                    'actual': current_hash
                })
        
        self.logger.info(
            f"Integrity check: {results['verified']}/{results['total_checked']} verified, "
            f"{results['failed']} failed, {results['missing']} missing"
        )
        
        return results
