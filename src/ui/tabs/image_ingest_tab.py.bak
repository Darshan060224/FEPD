"""
FEPD - TAB 2: IMAGE INGEST
===========================

Complete image ingestion tab with VEOS builder integration.

Workflow:
1. User clicks "Add Evidence Image"
2. Selects E01/DD/RAW/Memory file
3. System validates format, computes hash
4. Mounts image read-only with pytsk3/pyewf
5. Discovers partitions
6. Builds VEOS layer (evidence-native paths)
7. Logs to Chain of Custody

Features:
- E01/DD/RAW/Memory support
- SHA256 hash verification
- Partition discovery (NTFS/FAT/EXT4/APFS)
- VEOS builder integration
- Chain of Custody logging
- Evidence-native path display

Copyright (c) 2026 FEPD Development Team
"""

import logging
import os
import hashlib
import json
import time
import csv
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

# ============================================================================
# CONSTANTS - Forensic Standards & Configuration
# ============================================================================

# Hash computation
HASH_BUFFER_SIZE: int = 8192 * 1024  # 8MB chunks for hash computation
SUPPORTED_HASH_ALGORITHMS: List[str] = ['SHA256', 'MD5', 'SHA1']

# Progress stages (percentages)
PROGRESS_VALIDATE: int = 10
PROGRESS_HASH_START: int = 20
PROGRESS_HASH_END: int = 40
PROGRESS_MOUNT: int = 50
PROGRESS_PARTITION: int = 60
PROGRESS_VEOS: int = 80
PROGRESS_METADATA: int = 90
PROGRESS_COMPLETE: int = 100

# Supported formats
SUPPORTED_EXTENSIONS: set = {'.e01', '.dd', '.raw', '.img', '.001', '.mem', '.vmem'}
FORMAT_DESCRIPTIONS: Dict[str, str] = {
    '.e01': 'EnCase Evidence File',
    '.001': 'EnCase Segmented Evidence',
    '.dd': 'Raw Disk Image',
    '.raw': 'Raw Forensic Image',
    '.img': 'Disk Image File',
    '.mem': 'Memory Dump',
    '.vmem': 'VMware Memory File'
}

# File size limits
WARN_SIZE_GB: int = 100  # Warn for files > 100GB
MAX_BATCH_IMAGES: int = 10  # Maximum images in batch import

# Export formats
EXPORT_FORMATS: List[str] = ['JSON', 'CSV', 'HTML']

# Chain of Custody detail levels
COC_DETAIL_BASIC: str = 'basic'
COC_DETAIL_VERBOSE: str = 'verbose'

# UI update intervals
PROGRESS_UPDATE_INTERVAL_MS: int = 500  # Update progress every 500ms
SPEED_CALC_WINDOW_SEC: int = 5  # Calculate speed over 5 second window

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QMessageBox, QProgressDialog, QGroupBox,
    QLineEdit, QTextEdit, QComboBox, QCheckBox, QProgressBar
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QColor

# Local imports
import sys
sys.path.insert(0, str(__file__).replace('\\', '/').rsplit('/src/', 1)[0])

from src.core.case_manager import CaseManager
from src.core.chain_of_custody import ChainLogger
from src.core.veos import VirtualEvidenceOS, VEOSDrive

logger = logging.getLogger(__name__)


class ImageIngestWorker(QThread):
    """Worker thread for image ingestion with hash computation and VEOS building."""
    
    progress = pyqtSignal(int, str)  # (percentage, status_message)
    speed_update = pyqtSignal(float, float)  # (mb_per_sec, time_remaining_sec)
    finished = pyqtSignal(dict)  # (result_dict)
    error = pyqtSignal(str)  # (error_message)
    
    def __init__(self, image_path: str, case_manager: CaseManager, config: Dict[str, Any]):
        super().__init__()
        self.image_path = Path(image_path)
        self.case_manager = case_manager
        self.config = config
        self._cancelled = False
        self._start_time: float = 0.0
        self._bytes_processed: int = 0
    
    def run(self) -> None:
        """Run ingestion process."""
        try:
            self._start_time = time.time()
            result: Dict[str, Any] = {}
            
            # Step 1: Validate format
            self.progress.emit(PROGRESS_VALIDATE, f"Validating format: {self.image_path.suffix}...")
            if not self._validate_format():
                format_desc = FORMAT_DESCRIPTIONS.get(self.image_path.suffix.lower(), 'Unknown format')
                self.error.emit(
                    f"❌ Unsupported format: {self.image_path.suffix}\n\n"
                    f"Detected: {format_desc}\n\n"
                    f"💡 Supported formats:\n" +
                    "\n".join([f"  • {ext}: {desc}" for ext, desc in FORMAT_DESCRIPTIONS.items()]) +
                    "\n\n🔧 Recovery: Convert image to .dd or .e01 format using FTK Imager or dd command."
                )
                return
            
            # Step 2: Compute hash
            self.progress.emit(PROGRESS_HASH_START, "Computing SHA256 hash for integrity...")
            sha256_hash = self._compute_hash()
            result['hash'] = sha256_hash
            result['hash_algorithm'] = 'SHA256'
            
            # Step 2b: Verify hash if provided
            if 'expected_hash' in self.config and self.config['expected_hash']:
                if sha256_hash.lower() != self.config['expected_hash'].lower():
                    self.error.emit(
                        f"❌ Hash Mismatch Detected!\n\n"
                        f"Expected:  {self.config['expected_hash']}\n"
                        f"Computed:  {sha256_hash}\n\n"
                        f"⚠️ Evidence integrity compromised!\n\n"
                        f"💡 Recovery: Verify source image is not corrupted or re-acquire evidence."
                    )
                    return
                result['hash_verified'] = True
            else:
                result['hash_verified'] = False
            
            # Step 3: Mount image read-only
            self.progress.emit(PROGRESS_MOUNT, "Mounting image read-only...")
            mount_info = self._mount_image_readonly()
            result['mount_info'] = mount_info
            
            # Step 4: Discover partitions
            self.progress.emit(PROGRESS_PARTITION, "Discovering partitions...")
            partitions = self._discover_partitions()
            result['partitions'] = partitions
            
            # Step 5: Build VEOS layer
            self.progress.emit(PROGRESS_VEOS, "Building Virtual Evidence OS layer...")
            veos_drives = self._build_veos_layer(partitions)
            result['veos_drives'] = veos_drives
            
            # Step 6: Save metadata
            self.progress.emit(PROGRESS_METADATA, "Saving evidence metadata...")
            self._save_evidence_metadata(result)
            
            # Calculate total time
            total_time = time.time() - self._start_time
            result['ingestion_time_sec'] = total_time
            
            self.progress.emit(PROGRESS_COMPLETE, f"Ingestion complete! ({total_time:.1f}s)")
            self.finished.emit(result)
            
        except Exception as e:
            logger.error(f"Ingestion error: {e}", exc_info=True)
            error_msg = (
                f"❌ Ingestion Failed: {str(e)}\n\n"
                f"💡 Common Solutions:\n"
                f"  • Ensure pytsk3/pyewf are installed: pip install pytsk3 pyewf\n"
                f"  • Verify image file is not corrupted\n"
                f"  • Check file permissions (run as administrator)\n"
                f"  • Ensure sufficient disk space for hash computation\n\n"
                f"🔧 Recovery: Check logs for detailed error information."
            )
            self.error.emit(error_msg)
    
    def _validate_format(self) -> bool:
        """Validate image format against supported extensions."""
        return self.image_path.suffix.lower() in SUPPORTED_EXTENSIONS
    
    def _compute_hash(self) -> str:
        """Compute SHA256 hash with speed and time estimation."""
        sha256 = hashlib.sha256()
        
        total_size = self.image_path.stat().st_size
        bytes_read = 0
        last_update_time = time.time()
        last_bytes = 0
        
        with open(self.image_path, 'rb') as f:
            while True:
                if self._cancelled:
                    raise Exception("⚠️ Cancelled by user")
                
                chunk = f.read(HASH_BUFFER_SIZE)
                if not chunk:
                    break
                
                sha256.update(chunk)
                bytes_read += len(chunk)
                self._bytes_processed = bytes_read
                
                # Update progress and speed
                current_time = time.time()
                if current_time - last_update_time >= (PROGRESS_UPDATE_INTERVAL_MS / 1000):
                    hash_progress = PROGRESS_HASH_START + int((bytes_read / total_size) * (PROGRESS_HASH_END - PROGRESS_HASH_START))
                    
                    # Calculate speed
                    time_delta = current_time - last_update_time
                    bytes_delta = bytes_read - last_bytes
                    speed_mb_s = (bytes_delta / (1024**2)) / time_delta if time_delta > 0 else 0
                    
                    # Estimate time remaining
                    bytes_remaining = total_size - bytes_read
                    time_remaining = bytes_remaining / (bytes_delta / time_delta) if bytes_delta > 0 else 0
                    
                    self.progress.emit(
                        hash_progress,
                        f"Hashing: {bytes_read / (1024**3):.2f} GB / {total_size / (1024**3):.2f} GB "
                        f"({speed_mb_s:.1f} MB/s, ~{time_remaining:.0f}s remaining)"
                    )
                    self.speed_update.emit(speed_mb_s, time_remaining)
                    
                    last_update_time = current_time
                    last_bytes = bytes_read
        
        return sha256.hexdigest()
    
    def _mount_image_readonly(self) -> Dict[str, Any]:
        """Mount image in read-only mode using pytsk3/pyewf."""
        # Attempt to use pytsk3/pyewf for proper forensic mounting
        try:
            import pytsk3
            import pyewf
            
            # For E01 images
            if self.image_path.suffix.lower() in ['.e01', '.001']:
                filenames = pyewf.glob(str(self.image_path))
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                
                img_info = pytsk3.Img_Info(ewf_handle)
            else:
                # Raw DD/IMG
                img_info = pytsk3.Img_Info(str(self.image_path))
            
            return {
                'status': 'mounted',
                'readonly': True,
                'handler': 'pytsk3',
                'image_size': img_info.get_size()
            }
        except ImportError:
            logger.warning("pytsk3/pyewf not available, using basic file access")
            return {
                'status': 'file_access',
                'readonly': True,
                'handler': 'basic',
                'image_size': self.image_path.stat().st_size
            }
    
    def _discover_partitions(self) -> List[Dict[str, Any]]:
        """Discover partitions in disk image using pytsk3."""
        partitions: List[Dict[str, Any]] = []
        
        try:
            import pytsk3
            
            # Open image
            if self.image_path.suffix.lower() in ['.e01', '.001']:
                import pyewf
                filenames = pyewf.glob(str(self.image_path))
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                img_info = pytsk3.Img_Info(ewf_handle)
            else:
                img_info = pytsk3.Img_Info(str(self.image_path))
            
            # Read volume system
            try:
                volume = pytsk3.Volume_Info(img_info)
                
                for part in volume:
                    if part.len > 0:
                        partition_info = {
                            'index': part.addr,
                            'start_offset': part.start * volume.info.block_size,
                            'size_bytes': part.len * volume.info.block_size,
                            'description': part.desc.decode('utf-8', errors='ignore'),
                            'flags': str(part.flags)
                        }
                        
                        # Try to detect filesystem
                        try:
                            fs_info = pytsk3.FS_Info(img_info, offset=partition_info['start_offset'])
                            partition_info['filesystem'] = fs_info.info.ftype
                        except:
                            partition_info['filesystem'] = 'unknown'
                        
                        partitions.append(partition_info)
            except:
                # No volume system, try direct filesystem
                logger.info("No volume system found, trying direct filesystem access")
                try:
                    fs_info = pytsk3.FS_Info(img_info)
                    partitions.append({
                        'index': 0,
                        'start_offset': 0,
                        'size_bytes': img_info.get_size(),
                        'description': 'Entire image',
                        'filesystem': fs_info.info.ftype,
                        'flags': 'active'
                    })
                except:
                    pass
        
        except ImportError:
            logger.warning("pytsk3 not available for partition discovery")
            # Mock partition for basic mode
            partitions.append({
                'index': 0,
                'start_offset': 0,
                'size_bytes': self.image_path.stat().st_size,
                'description': 'Disk Image (partition discovery unavailable)',
                'filesystem': 'unknown',
                'flags': 'basic_mode'
            })
        
        return partitions
    
    def _build_veos_layer(self, partitions: List[Dict[str, Any]]) -> List[str]:
        """Build VEOS drives from discovered partitions."""
        veos_drives: List[str] = []
        
        # Build VEOS for each partition
        for part in partitions:
            drive_letter = self._assign_drive_letter(part['index'])
            
            # Create VEOS drive
            veos_drive = VEOSDrive(
                letter=drive_letter,
                source_image=str(self.image_path),
                partition_index=part['index'],
                filesystem=part.get('filesystem', 'unknown'),
                offset=part['start_offset']
            )
            
            veos_drives.append(f"{drive_letter}:")
        
        return veos_drives
    
    def _assign_drive_letter(self, partition_index: int) -> str:
        """Assign drive letter based on partition index."""
        letters = ['C', 'D', 'E', 'F', 'G', 'H']
        if partition_index < len(letters):
            return letters[partition_index]
        return 'X'
    
    def _save_evidence_metadata(self, result: Dict[str, Any]) -> None:
        """Save evidence metadata to case database with enhanced CoC logging."""
        if not self.case_manager or not self.case_manager.current_case:
            return
        
        case_db = self.case_manager.current_case['path'] / "case.db"
        conn = sqlite3.connect(str(case_db))
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO evidence (
                evidence_id, source_path, hash, hash_algorithm,
                ingestion_date, operator, partition_count, veos_drives
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            hashlib.md5(str(self.image_path).encode()).hexdigest()[:16],
            str(self.image_path),
            result['hash'],
            result['hash_algorithm'],
            datetime.now().isoformat(),
            os.getenv('USERNAME', 'unknown'),
            len(result['partitions']),
            json.dumps(result['veos_drives'])
        ))
        
        conn.commit()
        conn.close()
    
    def cancel(self) -> None:
        """Cancel the ingestion process."""
        self._cancelled = True
        logger.info(f"Ingestion cancelled by user: {self.image_path}")


class ImageIngestTab(QWidget):
    """
    TAB 2: IMAGE INGEST
    
    Provides complete evidence ingestion workflow with VEOS builder.
    Features: batch import, hash verification, progress tracking, CoC logging.
    """
    
    ingest_complete = pyqtSignal(dict)  # Emits ingestion result
    
    def __init__(self, case_manager: CaseManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.case_manager = case_manager
        self.chain_logger: Optional[ChainLogger] = None
        self.worker: Optional[ImageIngestWorker] = None
        self._batch_queue: List[str] = []
        self._current_batch_index: int = 0
        
        self._init_ui()
    
    def _init_ui(self) -> None:
        """Initialize UI with enhanced controls."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = QLabel("<h2>📥 IMAGE INGEST - Evidence Acquisition</h2>")
        layout.addWidget(header)
        
        # Add Evidence buttons
        btn_layout = QHBoxLayout()
        btn_add = QPushButton("➕ Add Evidence Image")
        btn_add.setMinimumHeight(40)
        btn_add.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold; font-size: 14px;")
        btn_add.clicked.connect(self._on_add_evidence)
        btn_layout.addWidget(btn_add)
        
        btn_batch = QPushButton("📚 Batch Import (Multiple)")
        btn_batch.setMinimumHeight(40)
        btn_batch.setStyleSheet("background-color: #2980b9; color: white; font-weight: bold;")
        btn_batch.clicked.connect(self._on_batch_import)
        btn_layout.addWidget(btn_batch)
        
        btn_add_folder = QPushButton("📁 Add Artifact Folder")
        btn_add_folder.setMinimumHeight(40)
        btn_add_folder.clicked.connect(self._on_add_artifact_folder)
        btn_layout.addWidget(btn_add_folder)
        
        btn_export = QPushButton("💾 Export Evidence List")
        btn_export.setMinimumHeight(40)
        btn_export.clicked.connect(self._on_export_evidence_list)
        btn_layout.addWidget(btn_export)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        # Hash verification panel
        hash_group = QGroupBox("🔒 Hash Verification (Optional)")
        hash_layout = QHBoxLayout()
        hash_layout.addWidget(QLabel("Expected SHA256:"))
        self.txt_expected_hash = QLineEdit()
        self.txt_expected_hash.setPlaceholderText("Paste expected hash here for verification (optional)")
        hash_layout.addWidget(self.txt_expected_hash)
        btn_import_hash = QPushButton("📂 Import from .sha256 file")
        btn_import_hash.clicked.connect(self._on_import_hash_file)
        hash_layout.addWidget(btn_import_hash)
        hash_group.setLayout(hash_layout)
        layout.addWidget(hash_group)
        
        # Evidence table
        evidence_group = QGroupBox("Ingested Evidence")
        evidence_layout = QVBoxLayout()
        
        self.table_evidence = QTableWidget(0, 8)
        self.table_evidence.setHorizontalHeaderLabels([
            "Evidence ID", "Source File", "Hash (SHA256)", "Verified", "Size", "Partitions", "VEOS Drives", "Status"
        ])
        self.table_evidence.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table_evidence.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        evidence_layout.addWidget(self.table_evidence)
        
        evidence_group.setLayout(evidence_layout)
        layout.addWidget(evidence_group)
        
        # Status panel
        status_group = QGroupBox("Ingestion Status")
        status_layout = QVBoxLayout()
        
        self.lbl_status = QLabel("Ready to ingest evidence")
        status_layout.addWidget(self.lbl_status)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        status_layout.addWidget(self.progress_bar)
        
        # Speed and time info
        speed_layout = QHBoxLayout()
        self.lbl_speed = QLabel("Speed: --")
        speed_layout.addWidget(self.lbl_speed)
        self.lbl_time_remaining = QLabel("Time Remaining: --")
        speed_layout.addWidget(self.lbl_time_remaining)
        speed_layout.addStretch()
        self.btn_cancel = QPushButton("❌ Cancel")
        self.btn_cancel.setVisible(False)
        self.btn_cancel.setStyleSheet("background-color: #e74c3c; color: white; font-weight: bold;")
        self.btn_cancel.clicked.connect(self._on_cancel_ingestion)
        speed_layout.addWidget(self.btn_cancel)
        status_layout.addLayout(speed_layout)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        layout.addStretch()
    
    def _on_add_evidence(self) -> None:
        """Handle Add Evidence button click."""
        # Check if case is loaded
        if not self.case_manager or not self.case_manager.current_case:
            QMessageBox.warning(
                self,
                "No Case Loaded",
                "❌ No active case loaded!\n\n"
                "💡 Recovery: Go to Case tab and create/open a case first."
            )
            return
        
        # Open file dialog
        filter_str = "Forensic Images (" + " ".join([f"*{ext}" for ext in SUPPORTED_EXTENSIONS]) + ");;All Files (*)"
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Evidence Image",
            str(Path.home()),
            filter_str
        )
        
        if not file_path:
            return
        
        # Warn for large files
        file_size_gb = Path(file_path).stat().st_size / (1024**3)
        if file_size_gb > WARN_SIZE_GB:
            reply = QMessageBox.question(
                self,
                "Large File Warning",
                f"⚠️ Large image file detected: {file_size_gb:.1f} GB\n\n"
                f"Hash computation may take significant time.\n\n"
                f"Continue with ingestion?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        # Start ingestion
        self._start_ingestion(file_path)
    
    def _on_add_artifact_folder(self) -> None:
        """Handle Add Artifact Folder button click."""
        if not self.case_manager or not self.case_manager.current_case:
            QMessageBox.warning(
                self,
                "No Case Loaded",
                "❌ No active case loaded!\n\n"
                "💡 Recovery: Go to Case tab and create/open a case first."
            )
            return
        
        folder_path = QFileDialog.getExistingDirectory(
            self,
            "Select Artifact Folder",
            str(Path.home())
        )
        
        if folder_path:
            QMessageBox.information(
                self,
                "Artifact Folder",
                f"📁 Selected: {folder_path}\n\n"
                f"ℹ️ Artifact folder import coming soon!\n\n"
                f"This feature will allow direct ingestion of extracted artifacts."
            )
    
    def _on_batch_import(self) -> None:
        """Handle batch import of multiple images."""
        if not self.case_manager or not self.case_manager.current_case:
            QMessageBox.warning(
                self,
                "No Case Loaded",
                "❌ No active case loaded!\n\n"
                "💡 Recovery: Go to Case tab and create/open a case first."
            )
            return
        
        filter_str = "Forensic Images (" + " ".join([f"*{ext}" for ext in SUPPORTED_EXTENSIONS]) + ");;All Files (*)"
        file_paths, _ = QFileDialog.getOpenFileNames(
            self,
            f"Select Evidence Images (Max {MAX_BATCH_IMAGES})",
            str(Path.home()),
            filter_str
        )
        
        if not file_paths:
            return
        
        if len(file_paths) > MAX_BATCH_IMAGES:
            QMessageBox.warning(
                self,
                "Too Many Files",
                f"⚠️ Selected {len(file_paths)} files, maximum is {MAX_BATCH_IMAGES}.\n\n"
                f"💡 Please select fewer files or ingest in multiple batches."
            )
            return
        
        # Setup batch queue
        self._batch_queue = file_paths
        self._current_batch_index = 0
        
        QMessageBox.information(
            self,
            "Batch Import",
            f"📚 Queued {len(file_paths)} images for ingestion.\n\n"
            f"Starting batch processing..."
        )
        
        # Start first image
        self._process_next_batch_item()
    
    def _process_next_batch_item(self) -> None:
        """Process next image in batch queue."""
        if self._current_batch_index < len(self._batch_queue):
            image_path = self._batch_queue[self._current_batch_index]
            self.lbl_status.setText(
                f"Batch: {self._current_batch_index + 1}/{len(self._batch_queue)} - {Path(image_path).name}"
            )
            self._start_ingestion(image_path)
        else:
            # Batch complete
            self._batch_queue = []
            self._current_batch_index = 0
            QMessageBox.information(
                self,
                "Batch Complete",
                f"✅ All images in batch have been processed!"
            )
    
    def _on_import_hash_file(self) -> None:
        """Import expected hash from .sha256 or .md5 file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Hash File",
            str(Path.home()),
            "Hash Files (*.sha256 *.md5 *.sha1);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
                # Extract hash (usually first 64 chars for SHA256)
                hash_value = content.split()[0] if ' ' in content else content
                self.txt_expected_hash.setText(hash_value)
                QMessageBox.information(
                    self,
                    "Hash Imported",
                    f"✅ Hash imported successfully!\n\n{hash_value[:32]}..."
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Import Error",
                f"❌ Failed to import hash file:\n\n{str(e)}"
            )
    
    def _on_export_evidence_list(self) -> None:
        """Export evidence list to JSON/CSV."""
        if self.table_evidence.rowCount() == 0:
            QMessageBox.warning(
                self,
                "No Evidence",
                "⚠️ No evidence to export.\n\n"
                "💡 Ingest evidence first, then export the list."
            )
            return
        
        # Ask format
        from PyQt6.QtWidgets import QInputDialog
        format_choice, ok = QInputDialog.getItem(
            self,
            "Export Format",
            "Select export format:",
            EXPORT_FORMATS,
            0,
            False
        )
        
        if not ok:
            return
        
        # Get save path
        ext = format_choice.lower()
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Evidence List",
            str(Path.home() / f"evidence_list.{ext}"),
            f"{format_choice} Files (*.{ext});;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            self._export_evidence_to_file(file_path, format_choice)
            QMessageBox.information(
                self,
                "Export Complete",
                f"✅ Evidence list exported successfully!\n\n{file_path}"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"❌ Failed to export evidence list:\n\n{str(e)}"
            )
    
    def _export_evidence_to_file(self, file_path: str, format_type: str) -> None:
        """Export evidence table to file."""
        evidence_list = []
        for row in range(self.table_evidence.rowCount()):
            evidence_list.append({
                'evidence_id': self.table_evidence.item(row, 0).text(),
                'source_file': self.table_evidence.item(row, 1).text(),
                'hash': self.table_evidence.item(row, 2).text(),
                'verified': self.table_evidence.item(row, 3).text(),
                'size': self.table_evidence.item(row, 4).text(),
                'partitions': self.table_evidence.item(row, 5).text(),
                'veos_drives': self.table_evidence.item(row, 6).text(),
                'status': self.table_evidence.item(row, 7).text()
            })
        
        if format_type == 'JSON':
            with open(file_path, 'w') as f:
                json.dump(evidence_list, f, indent=2)
        elif format_type == 'CSV':
            with open(file_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=evidence_list[0].keys())
                writer.writeheader()
                writer.writerows(evidence_list)
        elif format_type == 'HTML':
            html = "<html><body><table border='1'>\n"
            html += "<tr>" + "".join([f"<th>{k}</th>" for k in evidence_list[0].keys()]) + "</tr>\n"
            for item in evidence_list:
                html += "<tr>" + "".join([f"<td>{v}</td>" for v in item.values()]) + "</tr>\n"
            html += "</table></body></html>"
            with open(file_path, 'w') as f:
                f.write(html)
    
    def _on_cancel_ingestion(self) -> None:
        """Cancel ongoing ingestion."""
        if self.worker and self.worker.isRunning():
            reply = QMessageBox.question(
                self,
                "Cancel Ingestion",
                "⚠️ Are you sure you want to cancel the ongoing ingestion?\n\n"
                "Progress will be lost.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.worker.cancel()
                self.btn_cancel.setVisible(False)
                self.lbl_status.setText("Ingestion cancelled by user")
    
    def _start_ingestion(self, image_path: str) -> None:
        """Start evidence ingestion process with hash verification."""
        # Initialize Chain of Custody logger
        case_path = self.case_manager.current_case['path']
        self.chain_logger = ChainLogger(str(case_path))
        
        # Log to CoC
        self.chain_logger.log(
            action="EVIDENCE_INGEST_START",
            operator=os.getenv('USERNAME', 'unknown'),
            details={
                'source_image': image_path,
                'timestamp': datetime.now().isoformat()
            }
        )
        
        # Show progress
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.btn_cancel.setVisible(True)
        self.lbl_status.setText(f"Ingesting: {Path(image_path).name}")
        self.lbl_speed.setText("Speed: --")
        self.lbl_time_remaining.setText("Time Remaining: --")
        
        # Create worker thread with hash verification
        expected_hash = self.txt_expected_hash.text().strip()
        config = {
            'verify_hash': True,
            'readonly': True,
            'expected_hash': expected_hash if expected_hash else None
        }
        
        self.worker = ImageIngestWorker(image_path, self.case_manager, config)
        self.worker.progress.connect(self._on_progress)
        self.worker.speed_update.connect(self._on_speed_update)
        self.worker.finished.connect(self._on_ingest_complete)
        self.worker.error.connect(self._on_ingest_error)
        self.worker.start()
    
    def _on_progress(self, percentage: int, message: str) -> None:
        """Handle progress update."""
        self.progress_bar.setValue(percentage)
        self.lbl_status.setText(message)
    
    def _on_speed_update(self, speed_mb_s: float, time_remaining_sec: float) -> None:
        """Handle speed and time remaining update."""
        self.lbl_speed.setText(f"Speed: {speed_mb_s:.1f} MB/s")
        if time_remaining_sec < 60:
            self.lbl_time_remaining.setText(f"Time Remaining: {time_remaining_sec:.0f}s")
        else:
            minutes = int(time_remaining_sec / 60)
            seconds = int(time_remaining_sec % 60)
            self.lbl_time_remaining.setText(f"Time Remaining: {minutes}m {seconds}s")
    
    def _on_ingest_complete(self, result: Dict[str, Any]) -> None:
        """Handle ingestion completion with enhanced CoC logging."""
        self.progress_bar.setVisible(False)
        self.btn_cancel.setVisible(False)
        self.lbl_status.setText(f"Ingestion complete! ({result.get('ingestion_time_sec', 0):.1f}s)")
        
        # Enhanced CoC logging
        if self.chain_logger:
            coc_details = {
                'hash': result['hash'],
                'hash_algorithm': result['hash_algorithm'],
                'hash_verified': result.get('hash_verified', False),
                'partitions': len(result['partitions']),
                'veos_drives': result['veos_drives'],
                'mount_handler': result['mount_info'].get('handler', 'unknown'),
                'ingestion_time_sec': result.get('ingestion_time_sec', 0),
                'image_size_bytes': self.worker.image_path.stat().st_size
            }
            
            # Log partition details
            for idx, part in enumerate(result['partitions']):
                coc_details[f'partition_{idx}'] = {
                    'filesystem': part.get('filesystem', 'unknown'),
                    'size_bytes': part.get('size_bytes', 0),
                    'offset': part.get('start_offset', 0)
                }
            
            self.chain_logger.log(
                action="EVIDENCE_INGEST_COMPLETE",
                operator=os.getenv('USERNAME', 'unknown'),
                details=coc_details
            )
        
        # Add to table
        row = self.table_evidence.rowCount()
        self.table_evidence.insertRow(row)
        
        self.table_evidence.setItem(row, 0, QTableWidgetItem(result['hash'][:16]))
        self.table_evidence.setItem(row, 1, QTableWidgetItem(str(self.worker.image_path.name)))
        self.table_evidence.setItem(row, 2, QTableWidgetItem(result['hash'][:32] + "..."))
        
        # Verification status
        verified_text = "✅ Yes" if result.get('hash_verified', False) else "➖ N/A"
        verified_item = QTableWidgetItem(verified_text)
        if result.get('hash_verified', False):
            verified_item.setForeground(QColor("#27ae60"))
        self.table_evidence.setItem(row, 3, verified_item)
        
        size_gb = self.worker.image_path.stat().st_size / (1024**3)
        self.table_evidence.setItem(row, 4, QTableWidgetItem(f"{size_gb:.2f} GB"))
        self.table_evidence.setItem(row, 5, QTableWidgetItem(str(len(result['partitions']))))
        self.table_evidence.setItem(row, 6, QTableWidgetItem(", ".join(result['veos_drives'])))
        
        status_item = QTableWidgetItem("✅ Ready")
        status_item.setForeground(QColor("#27ae60"))
        self.table_evidence.setItem(row, 7, status_item)
        
        # Emit signal
        self.ingest_complete.emit(result)
        
        # Show completion message
        verified_msg = "✅ Hash verified!" if result.get('hash_verified', False) else ""
        QMessageBox.information(
            self,
            "Ingestion Complete",
            f"✅ Evidence ingested successfully!\n\n"
            f"Hash: {result['hash'][:32]}...\n"
            f"{verified_msg}\n"
            f"Partitions: {len(result['partitions'])}\n"
            f"VEOS Drives: {', '.join(result['veos_drives'])}\n"
            f"Time: {result.get('ingestion_time_sec', 0):.1f}s"
        )
        
        # Process next batch item if in batch mode
        if self._batch_queue:
            self._current_batch_index += 1
            self._process_next_batch_item()
    
    def _on_ingest_error(self, error_msg: str) -> None:
        """Handle ingestion error with enhanced logging."""
        self.progress_bar.setVisible(False)
        self.btn_cancel.setVisible(False)
        self.lbl_status.setText("Error occurred")
        
        if self.chain_logger:
            self.chain_logger.log(
                action="EVIDENCE_INGEST_ERROR",
                operator=os.getenv('USERNAME', 'unknown'),
                details={
                    'error': error_msg,
                    'image_path': str(self.worker.image_path) if self.worker else 'unknown'
                }
            )
        
        QMessageBox.critical(self, "Ingestion Error", error_msg)
        
        # Continue batch if applicable
        if self._batch_queue:
            self._current_batch_index += 1
            self._process_next_batch_item()
    
    def set_case(self, case_info: Dict[str, Any]) -> None:
        """Set current case for ingestion."""
        self.case_manager.current_case = case_info
        self._load_existing_evidence()
    
    def _load_existing_evidence(self) -> None:
        """Load existing evidence from case database with verification status."""
        if not self.case_manager or not self.case_manager.current_case:
            return
        
        case_db = self.case_manager.current_case['path'] / "case.db"
        if not case_db.exists():
            return
        
        import sqlite3
        import json
        
        conn = sqlite3.connect(str(case_db))
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT evidence_id, source_path, hash, partition_count, veos_drives FROM evidence')
            rows = cursor.fetchall()
            
            for row in rows:
                evidence_id, source_path, hash_val, partition_count, veos_drives_json = row
                
                table_row = self.table_evidence.rowCount()
                self.table_evidence.insertRow(table_row)
                
                self.table_evidence.setItem(table_row, 0, QTableWidgetItem(evidence_id))
                self.table_evidence.setItem(table_row, 1, QTableWidgetItem(Path(source_path).name))
                self.table_evidence.setItem(table_row, 2, QTableWidgetItem(hash_val[:32] + "..."))
                self.table_evidence.setItem(table_row, 3, QTableWidgetItem("➖ N/A"))  # Verification status unknown for loaded evidence
                self.table_evidence.setItem(table_row, 4, QTableWidgetItem("-"))
                self.table_evidence.setItem(table_row, 5, QTableWidgetItem(str(partition_count)))
                
                veos_drives = json.loads(veos_drives_json) if veos_drives_json else []
                self.table_evidence.setItem(table_row, 6, QTableWidgetItem(", ".join(veos_drives)))
                
                status_item = QTableWidgetItem("✅ Ready")
                status_item.setForeground(QColor("#27ae60"))
                self.table_evidence.setItem(table_row, 7, status_item)
        
        except Exception as e:
            logger.error(f"Error loading evidence: {e}")
        finally:
            conn.close()


import sqlite3


def ensure_evidence_table_exists(case_db_path: Path) -> None:
    """Ensure evidence table exists in case database with all required columns."""
    conn = sqlite3.connect(str(case_db_path))
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id TEXT PRIMARY KEY,
            source_path TEXT NOT NULL,
            hash TEXT,
            hash_algorithm TEXT,
            ingestion_date TEXT,
            operator TEXT,
            partition_count INTEGER,
            veos_drives TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
