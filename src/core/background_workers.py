"""
FEPD Background Worker System - Non-Blocking Forensic I/O
==========================================================

This module provides the architecture to keep FEPD responsive while
performing heavy forensic operations on large disk images.

Core Principle:
---------------
    "The UI thread must NEVER perform disk I/O."
    
    Heavy operations (mounting, parsing, hashing) happen in worker
    threads/processes. The UI only receives progress events and
    completed results via Qt signals.

Architecture:
-------------
    [ UI Thread ]
         |
         |  (signals only, no blocking)
         v
    [ Worker Engine ]
         |
         |  (forensic I/O)
         v
    [ Evidence Backend ]

This is how EnCase, FTK, Autopsy, and X-Ways stay alive while
processing terabytes.

Copyright (c) 2026 FEPD Development Team
"""

import sys
import traceback
import logging
from typing import Optional, Dict, Any, Callable, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from PyQt6.QtCore import (
    QObject, QThread, QRunnable, QThreadPool,
    pyqtSignal, pyqtSlot, QMutex, QMutexLocker
)

logger = logging.getLogger(__name__)


# ============================================================================
# TASK TYPES & STATES
# ============================================================================

class TaskType(Enum):
    """Types of background forensic tasks."""
    # Image operations
    MOUNT_IMAGE = "mount_image"
    HASH_IMAGE = "hash_image"
    SCAN_PARTITIONS = "scan_partitions"
    
    # Filesystem operations
    BUILD_VFS = "build_vfs"
    WALK_FILESYSTEM = "walk_filesystem"
    INDEX_FILES = "index_files"
    
    # Artifact operations
    DISCOVER_ARTIFACTS = "discover_artifacts"
    EXTRACT_ARTIFACTS = "extract_artifacts"
    PARSE_ARTIFACTS = "parse_artifacts"
    
    # Analysis operations
    ML_ANALYSIS = "ml_analysis"
    ANOMALY_DETECTION = "anomaly_detection"
    TIMELINE_BUILD = "timeline_build"
    
    # Export operations
    EXPORT_REPORT = "export_report"
    EXPORT_FILES = "export_files"


class TaskState(Enum):
    """States of a background task."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TaskProgress:
    """Progress information for a task."""
    task_id: str
    task_type: TaskType
    state: TaskState
    percent: float = 0.0
    message: str = ""
    current_item: str = ""
    items_processed: int = 0
    items_total: int = 0
    bytes_processed: int = 0
    bytes_total: int = 0
    started_at: Optional[str] = None
    eta_seconds: Optional[int] = None
    error: Optional[str] = None


# ============================================================================
# WORKER SIGNALS
# ============================================================================

class WorkerSignals(QObject):
    """
    Signals emitted by background workers.
    
    These signals are the ONLY communication between worker
    threads and the UI thread.
    """
    # Progress updates
    progress = pyqtSignal(TaskProgress)
    message = pyqtSignal(str)
    
    # Task lifecycle
    started = pyqtSignal(str, TaskType)  # task_id, task_type
    completed = pyqtSignal(str, object)  # task_id, result
    failed = pyqtSignal(str, str)        # task_id, error_message
    cancelled = pyqtSignal(str)           # task_id
    
    # Specific result types
    vfs_ready = pyqtSignal(object)        # VirtualFilesystem
    artifacts_found = pyqtSignal(list)    # List of discovered artifacts
    artifacts_extracted = pyqtSignal(list) # List of extracted artifacts
    events_parsed = pyqtSignal(int)       # Number of events
    hash_computed = pyqtSignal(str, str)  # file_path, hash_value
    
    # UI updates
    status_update = pyqtSignal(str)       # Status bar message
    show_spinner = pyqtSignal(bool)       # Show/hide spinner


# ============================================================================
# BASE WORKER CLASS
# ============================================================================

class ForensicWorker(QRunnable):
    """
    Base class for all forensic background workers.
    
    Subclass this for specific operations (mount, parse, etc.)
    
    Usage:
        class MountImageWorker(ForensicWorker):
            def run_task(self):
                # Do heavy I/O here
                return result
    
        worker = MountImageWorker(image_path)
        worker.signals.completed.connect(on_mount_complete)
        QThreadPool.globalInstance().start(worker)
    """
    
    def __init__(self, task_id: str, task_type: TaskType):
        super().__init__()
        self.task_id = task_id
        self.task_type = task_type
        self.signals = WorkerSignals()
        
        self._cancelled = False
        self._paused = False
        self._mutex = QMutex()
        
        self.setAutoDelete(True)
    
    @pyqtSlot()
    def run(self):
        """Execute the worker task."""
        try:
            # Emit started signal
            self.signals.started.emit(self.task_id, self.task_type)
            self.signals.show_spinner.emit(True)
            
            # Run the actual task (implemented by subclasses)
            result = self.run_task()
            
            if self._cancelled:
                self.signals.cancelled.emit(self.task_id)
            else:
                self.signals.completed.emit(self.task_id, result)
                
        except Exception as e:
            logger.error(f"Worker {self.task_id} failed: {e}")
            logger.error(traceback.format_exc())
            self.signals.failed.emit(self.task_id, str(e))
            
        finally:
            self.signals.show_spinner.emit(False)
    
    def run_task(self) -> Any:
        """
        Override this method to implement the actual work.
        
        Returns:
            The result of the task
        """
        raise NotImplementedError("Subclasses must implement run_task()")
    
    def cancel(self):
        """Request cancellation of this task."""
        with QMutexLocker(self._mutex):
            self._cancelled = True
    
    def pause(self):
        """Request pause of this task."""
        with QMutexLocker(self._mutex):
            self._paused = True
    
    def resume(self):
        """Resume a paused task."""
        with QMutexLocker(self._mutex):
            self._paused = False
    
    def is_cancelled(self) -> bool:
        """Check if cancellation was requested."""
        with QMutexLocker(self._mutex):
            return self._cancelled
    
    def is_paused(self) -> bool:
        """Check if pause was requested."""
        with QMutexLocker(self._mutex):
            return self._paused
    
    def check_cancelled(self):
        """Check cancellation and raise if cancelled."""
        if self.is_cancelled():
            raise TaskCancelled(f"Task {self.task_id} was cancelled")
    
    def wait_while_paused(self):
        """Block while task is paused."""
        import time
        while self.is_paused() and not self.is_cancelled():
            time.sleep(0.1)
        self.check_cancelled()
    
    def emit_progress(
        self,
        percent: float = 0,
        message: str = "",
        current_item: str = "",
        items_processed: int = 0,
        items_total: int = 0
    ):
        """Emit a progress update."""
        progress = TaskProgress(
            task_id=self.task_id,
            task_type=self.task_type,
            state=TaskState.RUNNING,
            percent=percent,
            message=message,
            current_item=current_item,
            items_processed=items_processed,
            items_total=items_total
        )
        self.signals.progress.emit(progress)
        self.signals.message.emit(message)


class TaskCancelled(Exception):
    """Raised when a task is cancelled."""
    pass


# ============================================================================
# SPECIFIC WORKERS
# ============================================================================

class MountImageWorker(ForensicWorker):
    """
    Worker for mounting forensic images.
    
    This handles the heavy I/O of opening E01/DD images
    without blocking the UI.
    """
    
    def __init__(self, image_path: Path, case_path: Path):
        super().__init__(
            task_id=f"mount_{datetime.now().strftime('%H%M%S')}",
            task_type=TaskType.MOUNT_IMAGE
        )
        self.image_path = image_path
        self.case_path = case_path
    
    def run_task(self):
        """Mount the forensic image."""
        from src.modules.image_handler import DiskImageHandler
        
        self.emit_progress(0, f"Opening {self.image_path.name}...")
        
        # Open image
        handler = DiskImageHandler()
        
        self.emit_progress(10, "Reading image header...")
        self.check_cancelled()
        
        result = handler.open_image(str(self.image_path))
        
        self.emit_progress(30, "Scanning partitions...")
        self.check_cancelled()
        
        # Scan for partitions
        partitions = handler.list_partitions()
        
        self.emit_progress(50, f"Found {len(partitions)} partitions")
        
        return {
            'handler': handler,
            'partitions': partitions,
            'image_path': self.image_path
        }


class BuildVFSWorker(ForensicWorker):
    """
    Worker for building the Virtual Evidence File System.
    
    Walks the evidence filesystem and builds the VFS tree
    without blocking the UI.
    """
    
    def __init__(
        self,
        handler,
        case_path: Path,
        vfs_db_path: Path,
        max_depth: int = 10
    ):
        super().__init__(
            task_id=f"vfs_{datetime.now().strftime('%H%M%S')}",
            task_type=TaskType.BUILD_VFS
        )
        self.handler = handler
        self.case_path = case_path
        self.vfs_db_path = vfs_db_path
        self.max_depth = max_depth
    
    def run_task(self):
        """Build the VFS from evidence image."""
        from src.core.vfs_builder import VEFSBuilder
        from src.core.virtual_fs import VirtualFilesystem
        
        self.emit_progress(0, "Initializing Virtual Filesystem...")
        
        # Create VFS database
        vfs = VirtualFilesystem(str(self.vfs_db_path))
        
        self.emit_progress(5, "Analyzing partition structure...")
        self.check_cancelled()
        
        # Build VEFS using the builder
        builder = VEFSBuilder(self.handler, vfs)
        
        # Track progress through callback
        def on_progress(percent, message, current=""):
            self.emit_progress(5 + percent * 0.9, message, current)
            self.check_cancelled()
        
        builder.build_vefs(progress_callback=on_progress)
        
        self.emit_progress(100, "Virtual Filesystem ready")
        
        # Emit the VFS through dedicated signal
        self.signals.vfs_ready.emit(vfs)
        
        return {
            'vfs': vfs,
            'stats': builder.stats,
            'partitions': builder.partitions,
            'os_type': builder.os_type
        }


class ExtractArtifactsWorker(ForensicWorker):
    """
    Worker for extracting forensic artifacts.
    
    Scans and extracts artifacts like Event Logs, Registry,
    Prefetch, etc. without blocking the UI.
    """
    
    def __init__(self, handler, output_dir: Path, artifact_types: List[str] = None):
        super().__init__(
            task_id=f"extract_{datetime.now().strftime('%H%M%S')}",
            task_type=TaskType.EXTRACT_ARTIFACTS
        )
        self.handler = handler
        self.output_dir = output_dir
        self.artifact_types = artifact_types
    
    def run_task(self):
        """Extract artifacts from evidence."""
        from src.modules.discovery import ArtifactDiscovery
        from src.modules.extraction import ArtifactExtraction
        
        self.emit_progress(0, "Scanning for artifacts...")
        
        # Discover artifacts
        discovery = ArtifactDiscovery()
        discovered = discovery.scan(self.handler)
        
        total = len(discovered)
        self.emit_progress(10, f"Found {total} artifacts")
        
        self.signals.artifacts_found.emit(discovered)
        self.check_cancelled()
        
        # Extract artifacts
        extraction = ArtifactExtraction(self.output_dir)
        extracted = []
        
        for i, artifact in enumerate(discovered):
            self.check_cancelled()
            self.wait_while_paused()
            
            percent = 10 + (i / total) * 80 if total > 0 else 90
            self.emit_progress(
                percent,
                f"Extracting {artifact.description}",
                artifact.internal_path,
                i + 1,
                total
            )
            
            try:
                result = extraction.extract(self.handler, artifact)
                if result:
                    extracted.append(result)
            except Exception as e:
                logger.warning(f"Failed to extract {artifact.internal_path}: {e}")
        
        self.emit_progress(95, f"Extracted {len(extracted)} artifacts")
        
        self.signals.artifacts_extracted.emit(extracted)
        
        return {
            'discovered': discovered,
            'extracted': extracted,
            'output_dir': self.output_dir
        }


class ParseEventsWorker(ForensicWorker):
    """
    Worker for parsing forensic events.
    
    Parses Event Logs, Registry hives, Prefetch, etc.
    into normalized events.
    """
    
    def __init__(self, extracted_artifacts: list, output_db: Path):
        super().__init__(
            task_id=f"parse_{datetime.now().strftime('%H%M%S')}",
            task_type=TaskType.PARSE_ARTIFACTS
        )
        self.extracted_artifacts = extracted_artifacts
        self.output_db = output_db
    
    def run_task(self):
        """Parse extracted artifacts."""
        from src.parsers import get_parser_for_artifact
        
        self.emit_progress(0, "Initializing parsers...")
        
        total = len(self.extracted_artifacts)
        all_events = []
        
        for i, artifact in enumerate(self.extracted_artifacts):
            self.check_cancelled()
            self.wait_while_paused()
            
            percent = (i / total) * 95 if total > 0 else 95
            self.emit_progress(
                percent,
                f"Parsing {artifact.artifact_type.value}",
                str(artifact.extracted_path),
                i + 1,
                total
            )
            
            try:
                parser = get_parser_for_artifact(artifact.artifact_type)
                if parser:
                    events = parser.parse(artifact.extracted_path)
                    all_events.extend(events)
            except Exception as e:
                logger.warning(f"Failed to parse {artifact.extracted_path}: {e}")
        
        self.emit_progress(98, f"Parsed {len(all_events)} events")
        
        self.signals.events_parsed.emit(len(all_events))
        
        return {
            'events': all_events,
            'event_count': len(all_events)
        }


class HashFileWorker(ForensicWorker):
    """
    Worker for computing file hashes.
    
    Computes SHA-256 hashes without blocking UI.
    """
    
    def __init__(self, file_path: Path):
        super().__init__(
            task_id=f"hash_{datetime.now().strftime('%H%M%S')}",
            task_type=TaskType.HASH_IMAGE
        )
        self.file_path = file_path
    
    def run_task(self):
        """Compute file hash."""
        import hashlib
        
        self.emit_progress(0, f"Computing hash for {self.file_path.name}...")
        
        sha256 = hashlib.sha256()
        file_size = self.file_path.stat().st_size
        bytes_read = 0
        
        with open(self.file_path, 'rb') as f:
            while True:
                self.check_cancelled()
                
                chunk = f.read(8 * 1024 * 1024)  # 8MB chunks
                if not chunk:
                    break
                
                sha256.update(chunk)
                bytes_read += len(chunk)
                
                percent = (bytes_read / file_size) * 100 if file_size > 0 else 100
                self.emit_progress(percent, "Computing SHA-256...")
        
        hash_value = sha256.hexdigest()
        
        self.signals.hash_computed.emit(str(self.file_path), hash_value)
        
        return {
            'file_path': self.file_path,
            'hash': hash_value,
            'algorithm': 'SHA-256'
        }


# ============================================================================
# TASK MANAGER
# ============================================================================

class TaskManager(QObject):
    """
    Manages all background forensic tasks.
    
    Usage:
        task_manager = TaskManager()
        
        # Start a task
        task_id = task_manager.start_mount(image_path, case_path)
        
        # Connect to progress
        task_manager.task_progress.connect(on_progress)
        task_manager.task_completed.connect(on_complete)
        
        # Cancel if needed
        task_manager.cancel(task_id)
    """
    
    # Signals
    task_started = pyqtSignal(str, TaskType)
    task_progress = pyqtSignal(TaskProgress)
    task_completed = pyqtSignal(str, object)
    task_failed = pyqtSignal(str, str)
    task_cancelled = pyqtSignal(str)
    
    status_message = pyqtSignal(str)
    spinner_visible = pyqtSignal(bool)
    
    def __init__(self, max_workers: int = 4, parent=None):
        super().__init__(parent)
        
        self._pool = QThreadPool.globalInstance()
        self._pool.setMaxThreadCount(max_workers)
        
        self._active_tasks: Dict[str, ForensicWorker] = {}
        self._mutex = QMutex()
    
    def _connect_worker(self, worker: ForensicWorker):
        """Connect worker signals to manager signals."""
        worker.signals.started.connect(self.task_started.emit)
        worker.signals.progress.connect(self.task_progress.emit)
        worker.signals.completed.connect(self._on_completed)
        worker.signals.failed.connect(self._on_failed)
        worker.signals.cancelled.connect(self._on_cancelled)
        worker.signals.message.connect(self.status_message.emit)
        worker.signals.show_spinner.connect(self.spinner_visible.emit)
    
    def _on_completed(self, task_id: str, result: Any):
        """Handle task completion."""
        with QMutexLocker(self._mutex):
            self._active_tasks.pop(task_id, None)
        self.task_completed.emit(task_id, result)
    
    def _on_failed(self, task_id: str, error: str):
        """Handle task failure."""
        with QMutexLocker(self._mutex):
            self._active_tasks.pop(task_id, None)
        self.task_failed.emit(task_id, error)
    
    def _on_cancelled(self, task_id: str):
        """Handle task cancellation."""
        with QMutexLocker(self._mutex):
            self._active_tasks.pop(task_id, None)
        self.task_cancelled.emit(task_id)
    
    def start_mount(self, image_path: Path, case_path: Path) -> str:
        """Start mounting a forensic image."""
        worker = MountImageWorker(image_path, case_path)
        self._connect_worker(worker)
        
        with QMutexLocker(self._mutex):
            self._active_tasks[worker.task_id] = worker
        
        self._pool.start(worker)
        return worker.task_id
    
    def start_build_vfs(
        self,
        handler,
        case_path: Path,
        vfs_db_path: Path
    ) -> str:
        """Start building Virtual Evidence File System."""
        worker = BuildVFSWorker(handler, case_path, vfs_db_path)
        self._connect_worker(worker)
        
        with QMutexLocker(self._mutex):
            self._active_tasks[worker.task_id] = worker
        
        self._pool.start(worker)
        return worker.task_id
    
    def start_extract(
        self,
        handler,
        output_dir: Path,
        artifact_types: List[str] = None
    ) -> str:
        """Start artifact extraction."""
        worker = ExtractArtifactsWorker(handler, output_dir, artifact_types)
        self._connect_worker(worker)
        
        with QMutexLocker(self._mutex):
            self._active_tasks[worker.task_id] = worker
        
        self._pool.start(worker)
        return worker.task_id
    
    def start_parse(self, extracted_artifacts: list, output_db: Path) -> str:
        """Start parsing artifacts."""
        worker = ParseEventsWorker(extracted_artifacts, output_db)
        self._connect_worker(worker)
        
        with QMutexLocker(self._mutex):
            self._active_tasks[worker.task_id] = worker
        
        self._pool.start(worker)
        return worker.task_id
    
    def start_hash(self, file_path: Path) -> str:
        """Start computing file hash."""
        worker = HashFileWorker(file_path)
        self._connect_worker(worker)
        
        with QMutexLocker(self._mutex):
            self._active_tasks[worker.task_id] = worker
        
        self._pool.start(worker)
        return worker.task_id
    
    def cancel(self, task_id: str):
        """Cancel a running task."""
        with QMutexLocker(self._mutex):
            worker = self._active_tasks.get(task_id)
            if worker:
                worker.cancel()
    
    def cancel_all(self):
        """Cancel all running tasks."""
        with QMutexLocker(self._mutex):
            for worker in self._active_tasks.values():
                worker.cancel()
    
    def pause(self, task_id: str):
        """Pause a running task."""
        with QMutexLocker(self._mutex):
            worker = self._active_tasks.get(task_id)
            if worker:
                worker.pause()
    
    def resume(self, task_id: str):
        """Resume a paused task."""
        with QMutexLocker(self._mutex):
            worker = self._active_tasks.get(task_id)
            if worker:
                worker.resume()
    
    def get_active_tasks(self) -> List[str]:
        """Get list of active task IDs."""
        with QMutexLocker(self._mutex):
            return list(self._active_tasks.keys())
    
    def is_busy(self) -> bool:
        """Check if any tasks are running."""
        with QMutexLocker(self._mutex):
            return len(self._active_tasks) > 0


# ============================================================================
# SINGLETON ACCESSOR
# ============================================================================

_global_task_manager: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    """Get the global task manager instance."""
    global _global_task_manager
    if _global_task_manager is None:
        _global_task_manager = TaskManager()
    return _global_task_manager


# ============================================================================
# CONVENIENCE DECORATORS
# ============================================================================

def run_in_background(task_type: TaskType):
    """
    Decorator to run a function in background thread.
    
    Usage:
        @run_in_background(TaskType.PARSE_ARTIFACTS)
        def process_evidence(self, artifact):
            # This runs in background
            return result
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            class GenericWorker(ForensicWorker):
                def __init__(self):
                    super().__init__(
                        task_id=f"generic_{datetime.now().strftime('%H%M%S%f')}",
                        task_type=task_type
                    )
                    self.args = args
                    self.kwargs = kwargs
                
                def run_task(self):
                    return func(*self.args, **self.kwargs)
            
            worker = GenericWorker()
            manager = get_task_manager()
            manager._connect_worker(worker)
            
            with QMutexLocker(manager._mutex):
                manager._active_tasks[worker.task_id] = worker
            
            manager._pool.start(worker)
            return worker.task_id
        
        return wrapper
    return decorator


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════╗
║          FEPD Background Worker System                           ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  This module keeps FEPD responsive by:                          ║
║                                                                  ║
║  1. Running heavy forensic I/O in background threads            ║
║  2. Communicating with UI only via Qt signals                   ║
║  3. Supporting cancellation and pause/resume                    ║
║  4. Tracking progress for user feedback                         ║
║                                                                  ║
║  Usage:                                                          ║
║      manager = get_task_manager()                               ║
║      task_id = manager.start_mount(image_path, case_path)       ║
║      manager.task_completed.connect(on_done)                    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
