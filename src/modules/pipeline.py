"""
FEPD - Forensic Evidence Parser Dashboard
Pipeline Integration Module

Orchestrates the complete forensic analysis pipeline:
1. Image Ingestion & Mounting (E01/DD support)
2. Artifact Discovery
3. Artifact Extraction
4. Parsing (PARALLEL - multiprocessing + threading)
5. Normalization
6. Classification
7. Timeline Visualization
8. Report Generation

Implements end-to-end workflow with progress tracking and error handling.
Now supports parallel processing for improved performance on multi-core systems.

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List
from datetime import datetime, timezone
import pandas as pd
import multiprocessing as mp
from multiprocessing import Queue, Process, cpu_count
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from queue import Queue as ThreadQueue
import time

from ..modules.discovery import ArtifactDiscovery
from ..modules.extraction import ArtifactExtraction
from ..modules.normalization import NormalizationEngine
from ..modules.rule_engine import RuleEngine
from ..parsers.evtx_parser import EVTXParser
from ..parsers.registry_parser import RegistryParser
from ..parsers.prefetch_parser import PrefetchParser
from ..parsers.mft_parser import MFTParser
from ..parsers.browser_parser import BrowserParser
from ..utils.config import Config
from ..utils.logger import ForensicLogger
from ..utils.chain_of_custody import ChainOfCustody
from ..utils.hash_utils import ForensicHasher
from ..core.chain_of_custody import ChainLogger, CoC_Actions

# Import forensic disk image handling
try:
    from ..modules.image_handler import DiskImageHandler
    from ..modules.memory_analyzer import MemoryAnalyzer, analyze_memory_dump
    from ..modules.artifact_extractor import extract_artifacts_from_image
    IMAGE_HANDLER_AVAILABLE = True
except ImportError:
    IMAGE_HANDLER_AVAILABLE = False
    logging.warning("Disk image handling not available (pytsk3/pyewf not installed)")


class PipelineStage:
    """Pipeline stage enumeration."""
    INIT = "Initialization"
    MOUNT = "Image Mounting"
    DISCOVERY = "Artifact Discovery"
    EXTRACTION = "Artifact Extraction"
    PARSING = "Artifact Parsing"
    PARALLEL_PARSING = "Parallel Artifact Parsing"
    NORMALIZATION = "Data Normalization"
    CLASSIFICATION = "Event Classification"
    COMPLETE = "Pipeline Complete"
    ERROR = "Error"


class ParsingWorker:
    """
    Worker process for parallel artifact parsing.
    
    This class is designed to be pickled and sent to worker processes.
    It initializes its own parser instances to avoid sharing state.
    """
    
    @staticmethod
    def parse_artifact_task(artifact_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a single artifact (executed in worker process).
        
        Args:
            artifact_data: Dictionary with artifact info
                {
                    'artifact_type': str,
                    'file_path': str,
                    'artifact_id': int
                }
        
        Returns:
            Dictionary with parsed events and metadata:
                {
                    'artifact_id': int,
                    'events': List[Dict],
                    'success': bool,
                    'error': Optional[str]
                }
        """
        from ..parsers.evtx_parser import EVTXParser
        from ..parsers.registry_parser import RegistryParser
        from ..parsers.prefetch_parser import PrefetchParser
        from ..parsers.mft_parser import MFTParser
        from ..parsers.browser_parser import BrowserParser
        from datetime import datetime
        
        artifact_id = artifact_data['artifact_id']
        artifact_type = artifact_data['artifact_type']
        file_path = Path(artifact_data['file_path'])
        
        try:
            # Initialize parser (each worker has its own instances)
            if artifact_type == 'EVTX':
                parser = EVTXParser()
                events = parser.parse_file(file_path)
            
            elif artifact_type == 'Registry':
                parser = RegistryParser()
                events = parser.parse_file(file_path)
            
            elif artifact_type == 'Prefetch':
                parser = PrefetchParser()
                events = parser.parse_file(file_path)
            
            elif artifact_type == 'MFT':
                parser = MFTParser()
                events = parser.parse_file(file_path)
            
            elif artifact_type == 'Browser':
                parser = BrowserParser()
                # BrowserParser.parse() auto-detects browser type
                events = parser.parse(file_path)
            
            elif artifact_type in ['Linux Config', 'Linux Log', 'Script']:
                # Parse Linux artifacts - create timeline event from file metadata
                events = [{
                    'timestamp': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                    'event_type': artifact_type,
                    'source': str(file_path.name),
                    'description': f'{artifact_type}: {file_path.name}',
                    'file_path': str(file_path),
                    'file_size': file_path.stat().st_size,
                }]
            
            elif artifact_type == 'Unknown':
                # Carved / unknown files — mirror the serial-path logic
                file_ext = file_path.suffix.lower()
                if file_ext in ['.jpg', '.jpeg', '.png', '.gif']:
                    label = 'Image File'
                elif file_ext in ['.db', '.sqlite']:
                    label = 'Database'
                else:
                    label = 'Carved File'
                stat = file_path.stat()
                events = [{
                    'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'event_type': label,
                    'source': str(file_path.name),
                    'description': f'{label}: {file_path.name}',
                    'file_path': str(file_path),
                    'file_size': stat.st_size,
                }]
            
            else:
                # Any other unhandled type — still create a file-metadata event
                stat = file_path.stat()
                events = [{
                    'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'event_type': artifact_type or 'File',
                    'source': str(file_path.name),
                    'description': f'{artifact_type}: {file_path.name}',
                    'file_path': str(file_path),
                    'file_size': stat.st_size,
                }]
            
            return {
                'artifact_id': artifact_id,
                'events': events,
                'success': True,
                'error': None,
                'event_count': len(events)
            }
        
        except Exception as e:
            return {
                'artifact_id': artifact_id,
                'events': [],
                'success': False,
                'error': str(e),
                'event_count': 0
            }


class ProgressAggregator:
    """
    Thread-safe progress aggregator for parallel operations.
    
    Collects progress updates from multiple workers and provides
    aggregate statistics for UI updates.
    """
    
    def __init__(self, total_tasks: int):
        """
        Initialize progress aggregator.
        
        Args:
            total_tasks: Total number of tasks to track
        """
        self.total_tasks = total_tasks
        self.completed_tasks = 0
        self.failed_tasks = 0
        self.total_events = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
    
    def update(self, success: bool, event_count: int = 0) -> None:
        """
        Update progress statistics.
        
        Args:
            success: Whether task succeeded
            event_count: Number of events parsed (if applicable)
        """
        with self.lock:
            self.completed_tasks += 1
            if success:
                self.total_events += event_count
            else:
                self.failed_tasks += 1
    
    def get_progress(self) -> Dict[str, Any]:
        """
        Get current progress statistics.
        
        Returns:
            Dictionary with progress metrics
        """
        with self.lock:
            elapsed = time.time() - self.start_time
            rate = self.completed_tasks / elapsed if elapsed > 0 else 0
            eta = (self.total_tasks - self.completed_tasks) / rate if rate > 0 else 0
            
            return {
                'completed': self.completed_tasks,
                'total': self.total_tasks,
                'failed': self.failed_tasks,
                'events': self.total_events,
                'percent': (self.completed_tasks / self.total_tasks * 100) if self.total_tasks > 0 else 0,
                'elapsed': elapsed,
                'rate': rate,
                'eta': eta
            }


class FEPDPipeline:
    """
    Forensic Evidence Parser Dashboard - Main Analysis Pipeline.
    
    Orchestrates complete forensic analysis workflow from image ingestion
    to classified timeline events ready for visualization and reporting.
    """
    
    def __init__(
        self,
        case_id: str,
        workspace_dir: Path,
        config: Config,
        logger: Optional[logging.Logger] = None,
        case_path: Optional[Path] = None
    ):
        """
        Initialize FEPD Analysis Pipeline.
        
        Args:
            case_id: Unique case identifier
            workspace_dir: Case workspace directory
            config: Configuration instance
            logger: Optional logger instance
            case_path: Path to case directory for chain of custody logging
        """
        self.case_id = case_id
        self.workspace_dir = Path(workspace_dir)
        self.case_path = Path(case_path) if case_path else None
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Parallel processing configuration
        self.max_workers = config.get('max_workers', None)  # None = auto-detect
        self.use_parallel = config.get('use_parallel_processing', True)
        self.io_threads = config.get('io_thread_pool_size', 4)
        
        # Auto-detect CPU count if not specified
        if self.max_workers is None:
            self.max_workers = max(1, cpu_count() - 1)  # Leave 1 core for OS
        
        self.logger.info(f"Parallel processing: {'Enabled' if self.use_parallel else 'Disabled'}")
        if self.use_parallel:
            self.logger.info(f"Worker processes: {self.max_workers}")
            self.logger.info(f"I/O thread pool: {self.io_threads}")
        
        # Initialize Chain of Custody (pass Config object)
        self.coc = ChainOfCustody(config)
        
        # Pipeline components
        self.discovery = ArtifactDiscovery(logger=self.logger)
        self.extraction = ArtifactExtraction(
            workspace_dir=self.workspace_dir / 'artifacts',
            coc=self.coc,
            logger=self.logger
        )
        self.normalization = NormalizationEngine(logger=self.logger)
        self.rule_engine = RuleEngine(
            rules_path=self.config.get('rules_path', 'config/rules/forensic_rules.yaml'),
            logger=self.logger
        )
        
        # Parsers
        self.evtx_parser = EVTXParser(logger=self.logger)
        self.registry_parser = RegistryParser(logger=self.logger)
        self.prefetch_parser = PrefetchParser(logger=self.logger)
        self.mft_parser = MFTParser(logger=self.logger)
        self.browser_parser = BrowserParser(logger=self.logger)
        
        # Linux parser
        try:
            from ..parsers.linux_parser import LinuxParser
            self.linux_parser = LinuxParser()
            self.logger.info("Linux parser initialized")
        except Exception as e:
            self.logger.warning(f"Linux parser not available: {e}")
            self.linux_parser = None
        
        # Pipeline state
        self.current_stage = PipelineStage.INIT
        self.image_hash: Optional[str] = None
        self.mount_point: Optional[Path] = None
        self.discovered_artifacts = []
        self.extracted_artifacts = []
        self.parsed_events = []
        self.normalized_df: Optional[pd.DataFrame] = None
        self.classified_df: Optional[pd.DataFrame] = None
        
        # Database handler (for storing memory analysis and other artifacts)
        try:
            from ..modules.memory_db import MemoryDatabaseHandler
            self.db_handler = MemoryDatabaseHandler(self.workspace_dir, logger=self.logger)
            self.logger.info("Memory database handler initialized")
        except Exception as e:
            self.logger.warning(f"Memory database handler not available: {e}")
            self.db_handler = None
        
        self.logger.info(f"Pipeline initialized for case: {case_id}")
    
    def run(
        self,
        image_path: Path,
        mount_point: Path,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None
    ) -> pd.DataFrame:
        """
        Run complete forensic analysis pipeline.
        
        Args:
            image_path: Path to forensic disk image
            mount_point: Path where image is mounted (read-only)
            progress_callback: Optional callback(stage, current, total, message)
            
        Returns:
            Pandas DataFrame with classified timeline events
            
        Raises:
            Exception: If critical pipeline stage fails
        """
        try:
            self.logger.info("=" * 80)
            self.logger.info(f"Starting FEPD Pipeline - Case ID: {self.case_id}")
            self.logger.info("=" * 80)
            
            # Stage 1: Image validation and hashing
            self._update_stage(PipelineStage.MOUNT, progress_callback)
            self._validate_image(image_path, progress_callback)
            self.mount_point = Path(mount_point)
            
            # Stage 2: Artifact Discovery
            self._update_stage(PipelineStage.DISCOVERY, progress_callback)
            self._discover_artifacts(progress_callback)
            
            # Stage 3: Artifact Extraction
            self._update_stage(PipelineStage.EXTRACTION, progress_callback)
            self._extract_artifacts(progress_callback)
            
            # Stage 4: Parsing
            self._update_stage(PipelineStage.PARSING, progress_callback)
            self._parse_artifacts(progress_callback)
            
            # Stage 5: Normalization
            self._update_stage(PipelineStage.NORMALIZATION, progress_callback)
            self._normalize_events(progress_callback)
            
            # Stage 6: Classification
            self._update_stage(PipelineStage.CLASSIFICATION, progress_callback)
            self._classify_events(progress_callback)
            
            # Stage 7: Complete
            self._update_stage(PipelineStage.COMPLETE, progress_callback)
            
            self.logger.info("=" * 80)
            self.logger.info("Pipeline completed successfully!")
            
            # Handle case when no events were found
            if self.classified_df is not None:
                self.logger.info(f"Total events: {len(self.classified_df)}")
            else:
                self.logger.warning("No events found - returning empty DataFrame")
                import pandas as pd
                self.classified_df = pd.DataFrame()
            
            self.logger.info("=" * 80)
            
            return self.classified_df
        
        except Exception as e:
            self.current_stage = PipelineStage.ERROR
            self.logger.error(f"Pipeline failed: {e}", exc_info=True)
            if progress_callback:
                progress_callback(PipelineStage.ERROR, 0, 0, f"Error: {str(e)}")
            raise
    
    def _update_stage(
        self,
        stage: str,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None
    ) -> None:
        """Update current pipeline stage."""
        self.current_stage = stage
        self.logger.info(f"Pipeline Stage: {stage}")
        if progress_callback:
            progress_callback(stage, 0, 0, f"Starting {stage}...")
    
    def _validate_image(self, image_path: Path, progress_callback: Optional[Callable[[str, int, int, str], None]] = None) -> None:
        """
        Validate forensic image and compute hash.
        Uses DiskImageHandler for E01/DD images when available.
        """
        if not image_path.exists():
            # Provide helpful error with available files
            parent_dir = image_path.parent
            if parent_dir.exists():
                available_e01 = list(parent_dir.glob("*.E01")) + list(parent_dir.glob("*.e01"))
                if available_e01:
                    available_list = "\n  - ".join([f.name for f in available_e01[:10]])
                    raise FileNotFoundError(
                        f"Image not found: {image_path}\n\n"
                        f"Available E01 files in {parent_dir}:\n  - {available_list}"
                    )
            raise FileNotFoundError(f"Image not found: {image_path}")
        
        file_size_mb = image_path.stat().st_size / (1024 * 1024)
        self.logger.info(f"Validating image: {image_path.name} ({file_size_mb:.1f} MB)")
        
        # Check if it's a forensic disk image (E01/DD)
        image_ext = image_path.suffix.lower()
        is_disk_image = image_ext in ['.e01', '.001', '.dd', '.raw', '.img']
        
        if IMAGE_HANDLER_AVAILABLE and is_disk_image:
            self.logger.info(f"Detected forensic disk image format: {image_ext}")
            self.logger.info("Using DiskImageHandler for forensically-sound processing...")
            
            try:
                with DiskImageHandler(str(image_path), verify_hash=True) as handler:
                    if not handler.open_image():
                        raise Exception("Failed to open disk image")
                    
                    self.image_hash = handler.image_hash
                    
                    self.logger.info(f"Image Type: {handler.image_type.upper()}")
                    self.logger.info(f"Image Size: {handler.image_size:,} bytes ({handler.image_size / (1024*1024):.2f} MB)")
                    self.logger.info(f"Image Hash: {self.image_hash}")
                    
                    # Log to CoC
                    self.coc.log_entry(
                        event="IMAGE_MOUNTED",
                        hash_value=self.image_hash,
                        reason="Forensic disk image validation (read-only)",
                        metadata={
                            'image_path': str(image_path),
                            'image_type': handler.image_type,
                            'size_bytes': handler.image_size,
                            'handler': 'DiskImageHandler',
                            'verify_hash': True
                        }
                    )
                    
                    if progress_callback:
                        hash_display = (handler.image_hash[:16] + '...') if handler.image_hash else 'N/A'
                        progress_callback(
                            PipelineStage.MOUNT,
                            1,
                            1,
                            f"Image validated: {handler.image_type.upper()} ({hash_display})"
                        )
                    
                    return
                    
            except Exception as e:
                self.logger.warning(f"DiskImageHandler failed: {e}")
                self.logger.warning("Falling back to standard file hashing...")
        
        # Fallback to standard file hashing
        self.logger.info("Computing SHA-256 hash of file...")
        self.logger.info("This may take a few minutes for large files...")
        
        # Hash progress callback
        def hash_progress(bytes_processed, total_bytes):
            if progress_callback and total_bytes > 0:
                percentage = int((bytes_processed / total_bytes) * 100)
                mb_processed = bytes_processed / (1024 * 1024)
                mb_total = total_bytes / (1024 * 1024)
                progress_callback(
                    PipelineStage.MOUNT,
                    bytes_processed,
                    total_bytes,
                    f"Computing SHA-256: {percentage}% ({mb_processed:.1f}/{mb_total:.1f} MB)"
                )
        
        hasher = ForensicHasher()
        self.image_hash = hasher.hash_file(image_path, callback=hash_progress)
        
        # Log to CoC
        self.coc.log_entry(
            event="IMAGE_LOADED",
            hash_value=self.image_hash,
            reason="Forensic analysis",
            metadata={'image_path': str(image_path), 'size_bytes': image_path.stat().st_size}
        )
        
        self.logger.info(f"Image hash: {self.image_hash}")
        self.logger.info("Image validation complete")
    
    def _discover_artifacts(
        self,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None
    ) -> None:
        """Discover artifacts in mounted image."""
        if not self.mount_point or not self.mount_point.exists():
            raise FileNotFoundError(f"Mount point not accessible: {self.mount_point}")
        
        # Validate mount point is not empty
        try:
            mount_contents = list(self.mount_point.iterdir())
            if not mount_contents:
                self.logger.error(f"❌ CRITICAL: Mount point is EMPTY: {self.mount_point}")
                self.logger.error("This indicates:")
                self.logger.error("  • Filesystem extraction completely failed")
                self.logger.error("  • Image is corrupted or unreadable")
                self.logger.error("  • Wrong partition offset or unpartitioned image")
                self.logger.error("  • Android/mobile image with unsupported filesystem")
                self.logger.info("💡 Attempting alternative discovery for carved/raw data...")
                
                # Don't raise - try to discover any carved files or raw data
                # The discovery module should handle this gracefully
            else:
                self.logger.info(f"✓ Mount point contains {len(mount_contents)} items")
        except Exception as e:
            self.logger.error(f"❌ Cannot validate mount point: {e}")
            # Don't raise - let discovery try anyway
        
        def discovery_progress(current: int, total: int, message: str):
            if progress_callback:
                progress_callback(PipelineStage.DISCOVERY, current, total, message)
        
        self.discovered_artifacts = self.discovery.discover(
            mount_point=self.mount_point,
            progress_callback=discovery_progress
        )
        
        summary = self.discovery.get_summary()
        self.logger.info(f"Discovery complete: {summary}")
        
        # Validate that we actually discovered something
        if not self.discovered_artifacts:
            self.logger.error("❌ CRITICAL: NO ARTIFACTS DISCOVERED")
            self.logger.error("Check previous logs for filesystem detection issues")
            self.logger.warning("Pipeline will continue but will produce empty results")
        
        # Log to CoC
        self.coc.log_entry(
            event="ARTIFACTS_DISCOVERED",
            hash_value=self.image_hash,
            reason="Artifact discovery scan",
            metadata={'discovered_count': len(self.discovered_artifacts), 'summary': summary}
        )
    
    def _extract_artifacts(
        self,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None
    ) -> None:
        """
        Extract discovered artifacts to workspace.
        
        Uses ThreadPoolExecutor for I/O-bound extraction tasks when parallel
        processing is enabled and workload justifies it.
        """
        if not self.discovered_artifacts:
            self.logger.warning("No artifacts discovered to extract")
            return
        
        total = len(self.discovered_artifacts)
        
        # Use parallel extraction for workloads > 3 artifacts if enabled (lowered threshold)
        if self.use_parallel and total > 3:
            self.logger.info(f"Using parallel extraction with {self.io_threads} threads for {total} artifacts")
            self._extract_artifacts_parallel(progress_callback)
        else:
            self.logger.info(f"Using serial extraction for {total} artifacts")
            self._extract_artifacts_serial(progress_callback)
    
    def _extract_artifacts_serial(
        self,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None
    ) -> None:
        """
        Serial artifact extraction (original implementation).
        
        Used for small workloads or when parallel processing is disabled.
        """
        def extraction_progress(current: int, total: int, message: str):
            if progress_callback:
                progress_callback(PipelineStage.EXTRACTION, current, total, message)
        
        self.extracted_artifacts = self.extraction.extract(
            artifacts=self.discovered_artifacts,
            mount_point=self.mount_point,
            progress_callback=extraction_progress
        )
        
        summary = self.extraction.get_summary()
        self.logger.info(f"Extraction complete: {summary}")
        
        # Log to blockchain-style chain of custody
        if self.case_path:
            try:
                import os
                from ..core.chain_of_custody import ChainLogger, CoC_Actions
                chain_logger = ChainLogger(str(self.case_path))
                chain_logger.append(
                    user=os.getenv("USERNAME", "system"),
                    action=CoC_Actions.ARTIFACT_EXTRACTED,
                    details=f"Extracted {len(self.extracted_artifacts)} artifacts: {summary}"
                )
            except Exception as e:
                self.logger.warning(f"Failed to log to chain of custody: {e}")
        
        # Log to chain of custody
        if self.case_path:
            try:
                chain_logger = ChainLogger(str(self.case_path))
                chain_logger.append(
                    user=os.getenv("USERNAME", "system"),
                    action=CoC_Actions.ARTIFACT_EXTRACTED,
                    details=f"Extracted {len(self.extracted_artifacts)} artifacts: {summary}"
                )
            except Exception as e:
                self.logger.warning(f"Failed to log to chain of custody: {e}")
    
    def _extract_artifacts_parallel(
        self,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None
    ) -> None:
        """
        Parallel artifact extraction using ThreadPoolExecutor.
        
        I/O-bound operations benefit from threading rather than multiprocessing
        due to GIL release during file operations.
        
        Note: This requires the extraction module to support per-artifact extraction.
        Falls back to serial if not supported.
        """
        # Check if extraction module supports parallel mode
        if not hasattr(self.extraction, 'extract_single'):
            self.logger.warning(
                "Extraction module doesn't support parallel extraction, falling back to serial"
            )
            self._extract_artifacts_serial(progress_callback)
            return
        
        total = len(self.discovered_artifacts)
        self.extracted_artifacts = []
        extracted_lock = threading.Lock()
        
        # Progress tracking
        progress_agg = ProgressAggregator(total_tasks=total)
        stop_progress_thread = threading.Event()
        
        def progress_monitor():
            """Background thread for progress updates."""
            while not stop_progress_thread.is_set():
                stats = progress_agg.get_progress()
                if progress_callback:
                    progress_callback(
                        PipelineStage.EXTRACTION,
                        stats['completed'],
                        stats['total'],
                        f"Extracting: {stats['completed']}/{stats['total']} "
                        f"({stats['percent']:.1f}%) | "
                        f"{stats['rate']:.1f} files/sec"
                    )
                time.sleep(0.5)
        
        progress_thread = threading.Thread(target=progress_monitor, daemon=True)
        progress_thread.start()
        
        try:
            with ThreadPoolExecutor(max_workers=self.io_threads) as executor:
                # Submit extraction tasks
                future_to_artifact = {
                    executor.submit(
                        self.extraction.extract_single,
                        artifact,
                        self.mount_point
                    ): artifact
                    for artifact in self.discovered_artifacts
                }
                
                # Collect results
                for future in as_completed(future_to_artifact):
                    artifact = future_to_artifact[future]
                    try:
                        extracted = future.result()
                        if extracted:
                            with extracted_lock:
                                self.extracted_artifacts.append(extracted)
                            progress_agg.update(success=True)
                        else:
                            progress_agg.update(success=False)
                    
                    except Exception as e:
                        self.logger.warning(f"Extraction failed for {artifact}: {e}")
                        progress_agg.update(success=False)
        
        finally:
            stop_progress_thread.set()
            progress_thread.join(timeout=1.0)
        
        final_stats = progress_agg.get_progress()
        self.logger.info(
            f"Parallel extraction complete: {len(self.extracted_artifacts)} artifacts "
            f"in {final_stats['elapsed']:.1f}s ({final_stats['rate']:.1f} files/sec)"
        )
    
    def _parse_artifacts(
        self,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None
    ) -> None:
        """
        Parse extracted artifacts using specialized parsers.
        
        Uses parallel processing (multiprocessing) when enabled and beneficial,
        otherwise falls back to serial processing for small workloads.
        """
        if not self.extracted_artifacts:
            self.logger.warning("No artifacts extracted to parse")
            return
        
        total = len(self.extracted_artifacts)
        
        # Use parallel processing for workloads > 3 artifacts if enabled (lowered threshold)
        if self.use_parallel and total > 3:
            self.logger.info(f"Using parallel parsing with {self.max_workers} workers for {total} artifacts")
            self._parse_artifacts_parallel(progress_callback)
        else:
            self.logger.info(f"Using serial parsing for {total} artifacts")
            self._parse_artifacts_serial(progress_callback)
    
    def _parse_artifacts_serial(
        self,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None
    ) -> None:
        """
        Serial artifact parsing (original implementation).
        
        Used for small workloads or when parallel processing is disabled.
        """
        total = len(self.extracted_artifacts)
        self.parsed_events = []
        
        for idx, artifact in enumerate(self.extracted_artifacts, 1):
            try:
                if progress_callback:
                    progress_callback(
                        PipelineStage.PARSING,
                        idx,
                        total,
                        f"Parsing {artifact.artifact_type.value}... ({idx}/{total})"
                    )
                
                # Route to appropriate parser
                events = self._parse_artifact(artifact)
                self.parsed_events.extend(events)
                
                self.logger.debug(
                    f"Parsed {len(events)} events from {artifact.extracted_path.name}"
                )
            
            except Exception as e:
                # NFR-09: Skip failed artifact and continue
                self.logger.warning(
                    f"Failed to parse {artifact.extracted_path}: {e}"
                )
                continue
        
        self.logger.info(f"Parsing complete: {len(self.parsed_events)} events extracted")
    
    def _parse_artifacts_parallel(
        self,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None
    ) -> None:
        """
        OPTIMIZED: Hybrid parallel parsing (threading + multiprocessing).
        
        Strategy:
            - Small files (< 1MB): ThreadPoolExecutor (I/O-bound, low overhead)
            - Large files (>= 1MB): ProcessPoolExecutor (CPU-bound, worth overhead)
        
        This dramatically improves speed by avoiding process spawning overhead
        for small files (most artifacts are < 1MB).
        
        Expected: 47s → 10s for typical workloads (4-5x faster)
        """
        total = len(self.extracted_artifacts)
        self.parsed_events = []
        
        # Categorize artifacts by size for optimal processing
        small_artifacts = []  # < 1MB → threading
        large_artifacts = []  # >= 1MB → multiprocessing
        
        SIZE_THRESHOLD = 1_000_000  # 1MB
        
        for idx, artifact in enumerate(self.extracted_artifacts):
            try:
                file_size = artifact.extracted_path.stat().st_size
                task = {
                    'artifact_id': idx,
                    'artifact_type': artifact.artifact_type.value,
                    'file_path': str(artifact.extracted_path),
                    'size': file_size
                }
                
                if file_size < SIZE_THRESHOLD:
                    small_artifacts.append(task)
                else:
                    large_artifacts.append(task)
            except Exception as e:
                self.logger.warning(f"Cannot stat {artifact.extracted_path}: {e}")
                # Assume small if can't determine size
                task = {
                    'artifact_id': idx,
                    'artifact_type': artifact.artifact_type.value,
                    'file_path': str(artifact.extracted_path),
                    'size': 0
                }
                small_artifacts.append(task)
        
        self.logger.info(f"⚡ Smart parsing: {len(small_artifacts)} small files (threading), {len(large_artifacts)} large files (multiprocessing)")
        
        # Initialize progress aggregator
        progress_agg = ProgressAggregator(total_tasks=total)
        
        # PHASE 1: Parse small files with threading (fast, low overhead)
        if small_artifacts:
            from concurrent.futures import ThreadPoolExecutor
            
            self.logger.info(f"Starting ThreadPool with 32 workers for {len(small_artifacts)} small artifacts...")
            
            with ThreadPoolExecutor(max_workers=32) as executor:
                future_to_task = {
                    executor.submit(ParsingWorker.parse_artifact_task, task): task
                    for task in small_artifacts
                }
                
                for future in as_completed(future_to_task):
                    task = future_to_task[future]
                    try:
                        result = future.result()
                        progress_agg.update(
                            success=result['success'],
                            event_count=result['event_count']
                        )
                        
                        if result['success']:
                            self.parsed_events.extend(result['events'])
                        else:
                            self.logger.warning(f"Failed to parse artifact {result['artifact_id']}: {result['error']}")
                    except Exception as e:
                        self.logger.error(f"Thread exception: {e}")
                        progress_agg.update(success=False)
            
            self.logger.info(f"✅ Threading phase complete: {len(small_artifacts)} artifacts")
        
        # PHASE 2: Parse large files with multiprocessing (CPU-intensive)
        if large_artifacts:
            from concurrent.futures import ProcessPoolExecutor
            
            self.logger.info(f"Starting ProcessPool with {self.max_workers} workers for {len(large_artifacts)} large artifacts...")
            
            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_task = {
                    executor.submit(ParsingWorker.parse_artifact_task, task): task
                    for task in large_artifacts
                }
                
                for future in as_completed(future_to_task):
                    task = future_to_task[future]
                    try:
                        result = future.result()
                        progress_agg.update(
                            success=result['success'],
                            event_count=result['event_count']
                        )
                        
                        if result['success']:
                            self.parsed_events.extend(result['events'])
                        else:
                            self.logger.warning(f"Failed to parse artifact {result['artifact_id']}: {result['error']}")
                    except Exception as e:
                        self.logger.error(f"Process exception: {e}")
                        progress_agg.update(success=False)
            
            self.logger.info(f"✅ Multiprocessing phase complete: {len(large_artifacts)} artifacts")
        
        # Progress update thread
        stop_progress_thread = threading.Event()
        
        def progress_monitor():
            """Background thread for progress updates."""
            while not stop_progress_thread.is_set():
                stats = progress_agg.get_progress()
                if progress_callback:
                    progress_callback(
                        PipelineStage.PARALLEL_PARSING,
                        stats['completed'],
                        stats['total'],
                        f"⚡ Smart parsing: {stats['completed']}/{stats['total']} "
                        f"({stats['percent']:.1f}%) | "
                        f"{stats['events']} events | "
                        f"{stats['rate']:.1f} artifacts/sec | "
                        f"ETA: {stats['eta']:.0f}s"
                    )
                time.sleep(0.5)  # Update every 500ms
        
        # Start progress monitor  
        progress_thread = threading.Thread(target=progress_monitor, daemon=True)
        progress_thread.start()
        
        try:
            # Wait for completion (both phases already done above)
            pass
        
        finally:
            # Stop progress monitor
            stop_progress_thread.set()
            progress_thread.join(timeout=1.0)
        
        # Final statistics
        final_stats = progress_agg.get_progress()
        self.logger.info(
            f"⚡ Smart parsing complete: {final_stats['completed']}/{final_stats['total']} artifacts "
            f"({final_stats['failed']} failed) in {final_stats['elapsed']:.1f}s "
            f"({final_stats['rate']:.1f} artifacts/sec)"
        )
        
        # Final progress callback
        if progress_callback:
            progress_callback(
                PipelineStage.PARSING,
                total,
                total,
                f"⚡ Parsed {len(self.parsed_events)} events from {total} artifacts ({final_stats['rate']:.1f} artifacts/sec)"
            )
    
    def _parse_artifact(self, artifact) -> List[Dict[str, Any]]:
        """Parse individual artifact using appropriate parser."""
        artifact_type = artifact.artifact_type.value
        file_path = artifact.extracted_path
        
        # Debug: Log what we're trying to parse
        self.logger.debug(f"Parsing artifact: type={artifact_type}, path={file_path}")
        
        if artifact_type == 'EVTX':
            return self.evtx_parser.parse_file(file_path)
        
        elif artifact_type == 'Registry':
            return self.registry_parser.parse_file(file_path)
        
        elif artifact_type == 'Prefetch':
            return self.prefetch_parser.parse_file(file_path)
        
        elif artifact_type == 'MFT':
            return self.mft_parser.parse_file(file_path)
        
        elif artifact_type == 'Browser':
            # BrowserParser.parse() auto-detects browser type
            return self.browser_parser.parse(file_path)
        
        elif artifact_type in ['Database', 'Mobile Database']:
            # Android SQLite databases or generic databases
            self.logger.info(f"Parsing database artifact: {file_path.name}")
            try:
                # Try to parse as mobile database
                from src.parsers.mobile_parser import MobileParser
                mobile_parser = MobileParser(platform='android')
                
                raw_events = []
                # Detect database type from filename
                if 'mms' in file_path.name.lower() or 'sms' in file_path.name.lower():
                    self.logger.info(f"Parsing Android SMS database: {file_path.name}")
                    raw_events = list(mobile_parser.parse_android_sms(file_path))
                elif 'call' in file_path.name.lower():
                    self.logger.info(f"Parsing Android call log: {file_path.name}")
                    raw_events = list(mobile_parser.parse_android_calls(file_path))
                elif 'contact' in file_path.name.lower():
                    self.logger.info(f"Parsing Android contacts: {file_path.name}")
                    raw_events = list(mobile_parser.parse_android_contacts(file_path))
                elif 'history' in file_path.name.lower() or 'chrome' in file_path.name.lower():
                    self.logger.info(f"Parsing Android Chrome history: {file_path.name}")
                    raw_events = list(mobile_parser.parse_android_chrome_history(file_path))
                else:
                    # Generic SQLite database - create file event
                    self.logger.info(f"Generic database file: {file_path.name}")
                    return self._parse_generic_database(file_path)
                
                # Convert mobile parser events to timeline format
                events = self._convert_mobile_events(raw_events)
                
                if events:
                    self.logger.info(f"✅ Parsed {len(events)} events from mobile database: {file_path.name}")
                else:
                    self.logger.warning(f"⚠ No events extracted from database: {file_path.name}")
                    events = self._create_file_event(file_path, 'Android Database')
                
                return events
            except Exception as e:
                self.logger.error(f"Failed to parse mobile database {file_path}: {e}", exc_info=True)
                return self._create_file_event(file_path, 'Database')
        
        elif artifact_type in ['Mobile SMS', 'Mobile Call Log', 'Mobile Contacts']:
            # Specific mobile artifact types
            self.logger.info(f"Parsing {artifact_type}: {file_path.name}")
            try:
                from src.parsers.mobile_parser import MobileParser
                mobile_parser = MobileParser(platform='android')
                
                raw_events = []
                if artifact_type == 'Mobile SMS':
                    raw_events = list(mobile_parser.parse_android_sms(file_path))
                elif artifact_type == 'Mobile Call Log':
                    raw_events = list(mobile_parser.parse_android_calls(file_path))
                elif artifact_type == 'Mobile Contacts':
                    raw_events = list(mobile_parser.parse_android_contacts(file_path))
                
                events = self._convert_mobile_events(raw_events)
                
                if events:
                    self.logger.info(f"✅ Parsed {len(events)} events from {artifact_type}")
                else:
                    self.logger.warning(f"⚠ No events from {artifact_type}")
                    events = self._create_file_event(file_path, artifact_type)
                
                return events
            except Exception as e:
                self.logger.error(f"Failed to parse {artifact_type}: {e}", exc_info=True)
                return self._create_file_event(file_path, artifact_type)
        
        elif artifact_type in ['Log', 'Mobile Log']:
            # Android or system logs
            self.logger.info(f"Creating timeline event for log: {file_path.name}")
            return self._create_file_event(file_path, artifact_type)
        
        elif artifact_type in ['Mobile App', 'Mobile Media']:
            # Mobile apps (APKs) or media files
            self.logger.info(f"Creating timeline event for {artifact_type}: {file_path.name}")
            return self._create_file_event(file_path, artifact_type)
        
        elif artifact_type == 'Unknown':
            # Carved files or unknown artifacts
            file_ext = file_path.suffix.lower()
            
            # Handle different file types
            if file_ext in ['.jpg', '.jpeg', '.png', '.gif']:
                # Image file - create timeline event with EXIF data if possible
                return self._parse_image_file(file_path)
            elif file_ext == '.db' or file_ext == '.sqlite':
                # Try to parse as SQLite database
                return self._parse_generic_database(file_path)
            else:
                # Generic file event
                return self._create_file_event(file_path, 'Carved File')
        
        elif artifact_type in ['Linux Config', 'Linux Log', 'Script']:
            # Parse Linux artifacts
            self.logger.info(f"Creating timeline event for {artifact_type}: {file_path.name}")
            return self._create_file_event(file_path, artifact_type)
        
        self.logger.warning(f"No parser available for artifact type: {artifact_type}")
        return []
    
    def _convert_mobile_events(self, mobile_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert mobile parser events to timeline-compatible format."""
        converted = []
        
        for event in mobile_events:
            try:
                # Convert datetime object to ISO string if needed
                timestamp = event.get('timestamp')
                if isinstance(timestamp, datetime):
                    timestamp_str = timestamp.isoformat()
                else:
                    timestamp_str = str(timestamp)
                
                # Create timeline event
                timeline_event = {
                    'timestamp': timestamp_str,
                    'event_type': event.get('category', 'Mobile Event'),
                    'source': event.get('source', 'Mobile Device'),
                    'description': event.get('description', 'Mobile artifact'),
                    'details': event.get('details', {}),
                    'user': event.get('user', 'unknown')
                }
                
                converted.append(timeline_event)
            except Exception as e:
                self.logger.warning(f"Failed to convert mobile event: {e}")
                continue
        
        return converted
    
    def _create_file_event(self, file_path: Path, artifact_type: str) -> List[Dict[str, Any]]:
        """Create a timeline event for a file based on its metadata."""
        try:
            stat = file_path.stat()
            events = [{
                'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'event_type': artifact_type,
                'source': str(file_path.name),
                'description': f'{artifact_type}: {file_path.name}',
                'file_path': str(file_path),
                'file_size': stat.st_size,
            }]
            return events
        except Exception as e:
            self.logger.warning(f"Failed to create file event for {file_path}: {e}")
            return []
    
    def _parse_image_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse image file and extract EXIF metadata if available."""
        try:
            stat = file_path.stat()
            
            # Try to extract EXIF data
            try:
                from PIL import Image
                from PIL.ExifTags import TAGS
                
                img = Image.open(file_path)
                exif_data = img._getexif()
                
                exif_dict = {}
                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag = TAGS.get(tag_id, tag_id)
                        exif_dict[tag] = value
                    
                    # Try to get DateTimeOriginal
                    if 'DateTimeOriginal' in exif_dict:
                        timestamp = datetime.strptime(exif_dict['DateTimeOriginal'], '%Y:%m:%d %H:%M:%S').isoformat()
                    else:
                        timestamp = datetime.fromtimestamp(stat.st_mtime).isoformat()
                else:
                    timestamp = datetime.fromtimestamp(stat.st_mtime).isoformat()
                
                description = f"Image: {file_path.name}"
                if 'Make' in exif_dict and 'Model' in exif_dict:
                    description += f" (Camera: {exif_dict['Make']} {exif_dict['Model']})"
                
            except Exception as e:
                # Fallback if EXIF extraction fails
                self.logger.debug(f"EXIF extraction failed for {file_path.name}: {e}")
                timestamp = datetime.fromtimestamp(stat.st_mtime).isoformat()
                description = f"Image: {file_path.name}"
            
            events = [{
                'timestamp': timestamp,
                'event_type': 'Image File',
                'source': str(file_path.name),
                'description': description,
                'file_path': str(file_path),
                'file_size': stat.st_size,
            }]
            return events
        except Exception as e:
            self.logger.warning(f"Failed to parse image file {file_path}: {e}")
            return []
    
    def _parse_generic_database(self, file_path: Path) -> List[Dict[str, Any]]:
        """Try to parse a generic SQLite database and create events."""
        try:
            import sqlite3
            
            conn = sqlite3.connect(str(file_path))
            cursor = conn.cursor()
            
            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            
            self.logger.info(f"Found {len(tables)} tables in {file_path.name}: {tables}")
            
            # Create event for database
            stat = file_path.stat()
            events = [{
                'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'event_type': 'SQLite Database',
                'source': str(file_path.name),
                'description': f"Database: {file_path.name} ({len(tables)} tables: {', '.join(tables[:5])})",
                'file_path': str(file_path),
                'file_size': stat.st_size,
            }]
            
            conn.close()
            return events
        except Exception as e:
            self.logger.warning(f"Failed to parse database {file_path}: {e}")
            return self._create_file_event(file_path, 'Database File')
    
    def _normalize_events(
        self,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None
    ) -> None:
        """Normalize parsed events to unified schema."""
        if not self.parsed_events:
            self.logger.warning("No parsed events to normalize")
            # Set empty DataFrame to avoid None
            import pandas as pd
            self.normalized_df = pd.DataFrame()
            return
        
        if progress_callback:
            progress_callback(
                PipelineStage.NORMALIZATION,
                0,
                1,
                f"Normalizing {len(self.parsed_events)} events..."
            )
        
        # Use unified normalization API
        self.normalized_df = self.normalization.normalize(self.parsed_events)
        
        self.logger.info(
            f"Normalization complete: {len(self.normalized_df)} normalized events"
        )
        
        if progress_callback:
            progress_callback(
                PipelineStage.NORMALIZATION,
                1,
                1,
                f"Normalized {len(self.normalized_df)} events"
            )
    
    def _classify_events(
        self,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None
    ) -> None:
        """Classify normalized events using rule engine."""
        if self.normalized_df is None or self.normalized_df.empty:
            self.logger.warning("No normalized events to classify")
            # Set empty DataFrame to avoid None
            import pandas as pd
            self.classified_df = pd.DataFrame()
            return
        
        if progress_callback:
            progress_callback(
                PipelineStage.CLASSIFICATION,
                0,
                1,
                f"Classifying {len(self.normalized_df)} events..."
            )
        
        # Use RuleEngine.classify which accepts a pandas DataFrame
        self.classified_df = self.rule_engine.classify(self.normalized_df)
        
        # Get classification summary
        class_counts = self.classified_df['rule_class'].value_counts().to_dict()
        self.logger.info(f"Classification complete: {class_counts}")
        
        if progress_callback:
            progress_callback(
                PipelineStage.CLASSIFICATION,
                1,
                1,
                f"Classified {len(self.classified_df)} events"
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get pipeline execution statistics.
        
        Returns:
            Dictionary with statistics including parallel processing metrics
        """
        stats = {
            'case_id': self.case_id,
            'image_hash': self.image_hash,
            'current_stage': self.current_stage,
            'discovered_artifacts': len(self.discovered_artifacts),
            'extracted_artifacts': len(self.extracted_artifacts),
            'parsed_events': len(self.parsed_events),
            'normalized_events': len(self.normalized_df) if self.normalized_df is not None else 0,
            'classified_events': len(self.classified_df) if self.classified_df is not None else 0,
            'parallel_processing': {
                'enabled': self.use_parallel,
                'max_workers': self.max_workers if self.use_parallel else 0,
                'io_threads': self.io_threads if self.use_parallel else 0,
                'cpu_count': cpu_count()
            }
        }
        
        if self.classified_df is not None and not self.classified_df.empty:
            stats['classification_summary'] = (
                self.classified_df['rule_class'].value_counts().to_dict()
            )
            stats['severity_summary'] = (
                self.classified_df['severity'].value_counts().to_dict()
            )
        
        return stats
    
    def set_parallel_config(
        self,
        enabled: bool = True,
        max_workers: Optional[int] = None,
        io_threads: Optional[int] = None
    ) -> None:
        """
        Configure parallel processing settings.
        
        Args:
            enabled: Enable/disable parallel processing
            max_workers: Number of worker processes (None = auto-detect)
            io_threads: Number of I/O threads (None = keep current)
        
        Example:
            # Use 4 worker processes and 8 I/O threads
            pipeline.set_parallel_config(enabled=True, max_workers=4, io_threads=8)
        """
        self.use_parallel = enabled
        
        if max_workers is not None:
            self.max_workers = max_workers
        elif enabled and self.max_workers is None:
            self.max_workers = max(1, cpu_count() - 1)
        
        if io_threads is not None:
            self.io_threads = io_threads
        
        self.logger.info(
            f"Parallel processing: {'Enabled' if self.use_parallel else 'Disabled'} "
            f"(workers={self.max_workers}, io_threads={self.io_threads})"
        )
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get detailed performance metrics for parallel operations.
        
        Returns:
            Dictionary with performance statistics:
                - cpu_utilization: Percentage of CPU cores used
                - memory_usage: Current memory usage (MB)
                - worker_efficiency: Tasks completed per worker
                - recommended_workers: Optimal worker count for this workload
        
        Example:
            metrics = pipeline.get_performance_metrics()
            print(f"CPU Utilization: {metrics['cpu_utilization']:.1f}%")
        """
        import psutil
        
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        
        # Calculate worker efficiency
        total_artifacts = len(self.extracted_artifacts)
        worker_efficiency = (
            total_artifacts / self.max_workers 
            if self.max_workers > 0 and total_artifacts > 0 
            else 0
        )
        
        # Recommend optimal worker count
        # Rule of thumb: 1 worker per core, but adjust based on workload
        if total_artifacts < 10:
            recommended = 1
        elif total_artifacts < 50:
            recommended = min(4, cpu_count())
        else:
            recommended = max(1, cpu_count() - 1)
        
        return {
            'cpu_utilization': cpu_percent,
            'memory_usage_mb': memory.used / (1024 * 1024),
            'memory_percent': memory.percent,
            'worker_efficiency': worker_efficiency,
            'recommended_workers': recommended,
            'current_workers': self.max_workers,
            'total_cpu_cores': cpu_count(),
            'parallel_enabled': self.use_parallel
        }
    
    def export_results(self, output_dir: Path) -> None:
        """
        Export pipeline results to files.
        
        Args:
            output_dir: Directory for output files
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Export classified events to CSV
        if self.classified_df is not None and not self.classified_df.empty:
            csv_path = output_dir / f'{self.case_id}_timeline.csv'
            self.classified_df.to_csv(csv_path, index=False)
            self.logger.info(f"Exported timeline to: {csv_path}")
        
        # Export statistics to JSON
        import json
        stats_path = output_dir / f'{self.case_id}_statistics.json'
        with open(stats_path, 'w') as f:
            json.dump(self.get_statistics(), f, indent=2, default=str)
        self.logger.info(f"Exported statistics to: {stats_path}")
        
        # Copy Chain of Custody log
        coc_dest = output_dir / f'{self.case_id}_chain_of_custody.log'
        shutil.copy2(self.coc.log_path, coc_dest)
        self.logger.info(f"Exported CoC log to: {coc_dest}")


import shutil  # Added for CoC log copy
