"""
FEPD - Evidence Upload Dialog
Forensic-Grade Evidence Selection with Type Classification

Features:
- Evidence Type Selection (Disk Image / Memory Image)
- Multi-part E01 mode toggle
- Strict validation rules
- Drag-and-drop support
- Real-time file validation

RULES (Phase 1):
- Multi-part unchecked: Allow only 1 file
- Multi-part checked: Allow multiple E0x files
- Memory selected: Allow only 1 file
- Disk + Memory: Allow both

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import re
import logging
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QRadioButton, QButtonGroup, QGroupBox,
    QListWidget, QListWidgetItem, QFileDialog, QFrame,
    QMessageBox, QProgressBar, QSplitter, QWidget, QScrollArea
)
from PyQt6.QtCore import Qt, pyqtSignal, QMimeData
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QColor, QFont


class EvidenceTypeChoice(Enum):
    """Evidence type selection."""
    DISK_IMAGE = "disk"
    MEMORY_IMAGE = "memory"


@dataclass
class EvidenceSelection:
    """Result of evidence selection."""
    evidence_type: EvidenceTypeChoice
    is_multipart: bool
    file_paths: List[Path]
    case_name: str = ""
    operator: str = ""


class EvidenceDropArea(QFrame):
    """Drag-and-drop area for evidence files."""
    
    files_dropped = pyqtSignal(list)  # List[Path]
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Sunken)
        self.setLineWidth(2)
        self.setMinimumHeight(180)
        
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Icon
        icon_label = QLabel("📦")
        icon_label.setStyleSheet("font-size: 64px;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)
        
        # Title
        title_label = QLabel("Drop Evidence Files Here")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        # Hint
        self.hint_label = QLabel(
            "Disk: E01, DD, RAW, IMG, AFF\n"
            "Memory: MEM, DMP, RAW"
        )
        self.hint_label.setStyleSheet("font-size: 12px; color: #888;")
        self.hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.hint_label)
        
        self.setLayout(layout)
        
        # Styles
        self._default_style = """
            QFrame {
                background-color: #2c3e50;
                border: 3px dashed #7f8c8d;
                border-radius: 10px;
            }
        """
        self._hover_style = """
            QFrame {
                background-color: #34495e;
                border: 3px dashed #3498db;
                border-radius: 10px;
            }
        """
        self.setStyleSheet(self._default_style)
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet(self._hover_style)
    
    def dragLeaveEvent(self, event):
        """Handle drag leave."""
        self.setStyleSheet(self._default_style)
    
    def dropEvent(self, event: QDropEvent):
        """Handle file drop."""
        self.setStyleSheet(self._default_style)
        
        urls = event.mimeData().urls()
        if urls:
            paths = [Path(url.toLocalFile()) for url in urls]
            self.files_dropped.emit(paths)
    
    def update_hint(self, evidence_type: EvidenceTypeChoice):
        """Update hint based on evidence type."""
        if evidence_type == EvidenceTypeChoice.DISK_IMAGE:
            self.hint_label.setText(
                "Disk Image Formats:\n"
                "E01, E02, ... (Expert Witness)\n"
                "DD, RAW, IMG, AFF"
            )
        else:
            self.hint_label.setText(
                "Memory Image Formats:\n"
                "MEM, DMP, RAW\n"
                "(Single file only)"
            )


class EvidenceUploadDialog(QDialog):
    """
    Evidence Upload Dialog with Type Selection.
    
    Implements Phase 1 UI Logic:
    - Evidence Type selection
    - Multi-part E01 mode
    - Strict validation rules
    """
    
    # Signal emitted when evidence is selected and validated
    evidence_selected = pyqtSignal(object)  # EvidenceSelection
    
    def __init__(self, parent=None, case_name: str = "", operator: str = "SYSTEM"):
        super().__init__(parent)
        self.case_name = case_name
        self.operator = operator
        self.selected_files: List[Path] = []
        self.logger = logging.getLogger(__name__)
        
        self._setup_ui()
        self._connect_signals()
        self._validate_selection()
    
    def _setup_ui(self):
        """Setup the dialog UI."""
        self.setWindowTitle("Upload Evidence")
        self.setMinimumSize(700, 600)
        self.setModal(True)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Header
        header = QLabel("📁 Upload Forensic Evidence")
        header.setStyleSheet("font-size: 20px; font-weight: bold; padding: 10px;")
        layout.addWidget(header)
        
        # ================================================================
        # Evidence Type Selection
        # ================================================================
        type_group = QGroupBox("Evidence Type")
        type_layout = QVBoxLayout()
        
        self.type_button_group = QButtonGroup(self)
        
        # Disk Image option
        self.radio_disk = QRadioButton("💿 Disk Image (E01 / E02+ / DD / RAW / AFF)")
        self.radio_disk.setChecked(True)
        self.radio_disk.setStyleSheet("font-size: 14px; padding: 5px;")
        self.type_button_group.addButton(self.radio_disk)
        type_layout.addWidget(self.radio_disk)
        
        # Memory Image option
        self.radio_memory = QRadioButton("🧠 Memory Image (MEM / DMP / RAW)")
        self.radio_memory.setStyleSheet("font-size: 14px; padding: 5px;")
        self.type_button_group.addButton(self.radio_memory)
        type_layout.addWidget(self.radio_memory)
        
        type_group.setLayout(type_layout)
        layout.addWidget(type_group)
        
        # ================================================================
        # Options
        # ================================================================
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        
        self.chk_multipart = QCheckBox("🔗 Multi-part E01 evidence (E01 + E02 + ...)")
        self.chk_multipart.setStyleSheet("font-size: 13px; padding: 5px;")
        self.chk_multipart.setToolTip(
            "Enable this to upload split forensic images.\n"
            "All segments must have the same base name (e.g., LoneWolf.E01, LoneWolf.E02, ...)."
        )
        options_layout.addWidget(self.chk_multipart)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # ================================================================
        # Drop Area
        # ================================================================
        self.drop_area = EvidenceDropArea()
        self.drop_area.files_dropped.connect(self._on_files_dropped)
        layout.addWidget(self.drop_area)
        
        # Browse button
        browse_layout = QHBoxLayout()
        browse_layout.addStretch()
        
        self.btn_browse = QPushButton("📂 Browse for Evidence Files...")
        self.btn_browse.setMinimumHeight(40)
        self.btn_browse.setStyleSheet("font-size: 14px; padding: 10px 20px;")
        self.btn_browse.clicked.connect(self._browse_files)
        browse_layout.addWidget(self.btn_browse)
        
        browse_layout.addStretch()
        layout.addLayout(browse_layout)
        
        # ================================================================
        # Selected Files List
        # ================================================================
        files_group = QGroupBox("Selected Evidence Files")
        files_layout = QVBoxLayout()
        
        self.files_list = QListWidget()
        self.files_list.setMinimumHeight(120)
        self.files_list.setAlternatingRowColors(True)
        files_layout.addWidget(self.files_list)
        
        # File actions
        file_actions = QHBoxLayout()
        
        self.btn_remove = QPushButton("🗑️ Remove Selected")
        self.btn_remove.clicked.connect(self._remove_selected)
        self.btn_remove.setEnabled(False)
        file_actions.addWidget(self.btn_remove)
        
        self.btn_clear = QPushButton("🧹 Clear All")
        self.btn_clear.clicked.connect(self._clear_files)
        self.btn_clear.setEnabled(False)
        file_actions.addWidget(self.btn_clear)
        
        file_actions.addStretch()
        
        self.lbl_summary = QLabel("")
        self.lbl_summary.setStyleSheet("font-weight: bold;")
        file_actions.addWidget(self.lbl_summary)
        
        files_layout.addLayout(file_actions)
        files_group.setLayout(files_layout)
        layout.addWidget(files_group)
        
        # ================================================================
        # Validation Status
        # ================================================================
        self.validation_frame = QFrame()
        self.validation_frame.setFrameStyle(QFrame.Shape.Box)
        self.validation_frame.setStyleSheet("padding: 10px;")
        validation_layout = QVBoxLayout()
        
        self.lbl_validation = QLabel("")
        self.lbl_validation.setWordWrap(True)
        self.lbl_validation.setAlignment(Qt.AlignmentFlag.AlignCenter)
        validation_layout.addWidget(self.lbl_validation)
        
        self.validation_frame.setLayout(validation_layout)
        layout.addWidget(self.validation_frame)
        
        # ================================================================
        # Dialog Buttons
        # ================================================================
        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setMinimumHeight(40)
        self.btn_cancel.clicked.connect(self.reject)
        buttons_layout.addWidget(self.btn_cancel)
        
        self.btn_upload = QPushButton("✅ Upload Evidence")
        self.btn_upload.setMinimumHeight(40)
        self.btn_upload.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                font-weight: bold;
                font-size: 14px;
                padding: 10px 30px;
            }
            QPushButton:disabled {
                background-color: #7f8c8d;
            }
            QPushButton:hover:enabled {
                background-color: #2ecc71;
            }
        """)
        self.btn_upload.setEnabled(False)
        self.btn_upload.clicked.connect(self._on_upload)
        buttons_layout.addWidget(self.btn_upload)
        
        layout.addLayout(buttons_layout)
        
        self.setLayout(layout)
    
    def _connect_signals(self):
        """Connect UI signals."""
        self.radio_disk.toggled.connect(self._on_type_changed)
        self.radio_memory.toggled.connect(self._on_type_changed)
        self.chk_multipart.toggled.connect(self._on_multipart_changed)
        self.files_list.itemSelectionChanged.connect(self._on_selection_changed)
    
    def _on_type_changed(self, checked: bool):
        """Handle evidence type change."""
        if not checked:
            return
        
        evidence_type = self._get_evidence_type()
        
        # Update drop area hint
        self.drop_area.update_hint(evidence_type)
        
        # Disable multi-part for memory images
        if evidence_type == EvidenceTypeChoice.MEMORY_IMAGE:
            self.chk_multipart.setChecked(False)
            self.chk_multipart.setEnabled(False)
        else:
            self.chk_multipart.setEnabled(True)
        
        # Re-validate
        self._validate_selection()
    
    def _on_multipart_changed(self, checked: bool):
        """Handle multi-part mode change."""
        self._validate_selection()
    
    def _on_selection_changed(self):
        """Handle file selection change in list."""
        has_selection = len(self.files_list.selectedItems()) > 0
        self.btn_remove.setEnabled(has_selection)
    
    def _get_evidence_type(self) -> EvidenceTypeChoice:
        """Get currently selected evidence type."""
        if self.radio_disk.isChecked():
            return EvidenceTypeChoice.DISK_IMAGE
        return EvidenceTypeChoice.MEMORY_IMAGE
    
    def _browse_files(self):
        """Open file browser for evidence selection."""
        evidence_type = self._get_evidence_type()
        is_multipart = self.chk_multipart.isChecked()
        
        # Set file filter based on type
        if evidence_type == EvidenceTypeChoice.DISK_IMAGE:
            filter_str = (
                "Disk Images (*.e01 *.E01 *.e02 *.E02 *.e03 *.E03 *.e04 *.E04 "
                "*.e05 *.E05 *.e06 *.E06 *.e07 *.E07 *.e08 *.E08 *.e09 *.E09 "
                "*.dd *.DD *.raw *.RAW *.img *.IMG *.aff *.AFF *.001 *.002 *.003);;"
                "All Files (*)"
            )
        else:
            filter_str = (
                "Memory Images (*.mem *.MEM *.dmp *.DMP *.raw *.RAW);;"
                "All Files (*)"
            )
        
        # Determine if multi-select is allowed
        if is_multipart:
            file_paths, _ = QFileDialog.getOpenFileNames(
                self,
                "Select Evidence Files",
                str(Path.home()),
                filter_str
            )
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Evidence File",
                str(Path.home()),
                filter_str
            )
            file_paths = [file_path] if file_path else []
        
        if file_paths:
            paths = [Path(p) for p in file_paths]
            self._add_files(paths)
    
    def _on_files_dropped(self, paths: List[Path]):
        """Handle dropped files."""
        self._add_files(paths)
    
    def _add_files(self, paths: List[Path]):
        """Add files to selection."""
        is_multipart = self.chk_multipart.isChecked()
        evidence_type = self._get_evidence_type()
        
        # Rule: Non-multipart mode replaces existing selection
        if not is_multipart:
            self.selected_files = paths[:1]  # Take only first file
        else:
            # Add to existing (avoid duplicates)
            for path in paths:
                if path not in self.selected_files:
                    self.selected_files.append(path)
        
        self._update_files_list()
        self._validate_selection()
    
    def _remove_selected(self):
        """Remove selected files from list."""
        selected = self.files_list.selectedItems()
        for item in selected:
            path = Path(item.data(Qt.ItemDataRole.UserRole))
            if path in self.selected_files:
                self.selected_files.remove(path)
        
        self._update_files_list()
        self._validate_selection()
    
    def _clear_files(self):
        """Clear all selected files."""
        self.selected_files = []
        self._update_files_list()
        self._validate_selection()
    
    def _update_files_list(self):
        """Update the files list widget."""
        self.files_list.clear()
        
        total_size = 0
        for path in self.selected_files:
            item = QListWidgetItem()
            
            # Format size
            if path.exists():
                size = path.stat().st_size
                total_size += size
                size_str = self._format_size(size)
            else:
                size_str = "N/A"
            
            # Set display text
            item.setText(f"📄 {path.name}  [{size_str}]")
            item.setData(Qt.ItemDataRole.UserRole, str(path))
            
            # Color-code by extension
            ext = path.suffix.lower()
            if ext in ['.e01', '.e02', '.e03', '.e04', '.e05', '.e06', '.e07', '.e08', '.e09']:
                item.setForeground(QColor("#3498db"))  # Blue for E01
            elif ext in ['.mem', '.dmp']:
                item.setForeground(QColor("#9b59b6"))  # Purple for memory
            
            self.files_list.addItem(item)
        
        # Update buttons
        has_files = len(self.selected_files) > 0
        self.btn_clear.setEnabled(has_files)
        
        # Update summary
        if has_files:
            self.lbl_summary.setText(
                f"{len(self.selected_files)} file(s) | {self._format_size(total_size)}"
            )
        else:
            self.lbl_summary.setText("")
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size for display."""
        if size_bytes >= 1024 * 1024 * 1024:
            return f"{size_bytes / (1024*1024*1024):.2f} GB"
        elif size_bytes >= 1024 * 1024:
            return f"{size_bytes / (1024*1024):.2f} MB"
        elif size_bytes >= 1024:
            return f"{size_bytes / 1024:.2f} KB"
        return f"{size_bytes} bytes"
    
    def _validate_selection(self) -> Tuple[bool, str]:
        """
        Validate the current selection against rules.
        
        Rules:
        - Multi-part unchecked: Allow only 1 file
        - Multi-part checked: Allow multiple E0x files
        - Memory selected: Allow only 1 file
        - Disk + Memory: Allow both
        
        For E01 sets:
        - Same base name
        - No missing segments
        - Sequential numbering
        - Size > 0
        - Readable
        """
        evidence_type = self._get_evidence_type()
        is_multipart = self.chk_multipart.isChecked()
        
        # Reset validation display
        self.validation_frame.setStyleSheet("padding: 10px;")
        
        # No files selected
        if not self.selected_files:
            self._set_validation_status(
                "ℹ️ Select evidence files to continue",
                "info"
            )
            self.btn_upload.setEnabled(False)
            return False, "No files selected"
        
        # Rule: Memory images must be single file
        if evidence_type == EvidenceTypeChoice.MEMORY_IMAGE and len(self.selected_files) > 1:
            self._set_validation_status(
                "❌ Memory images must be single files.\n"
                "Multiple files are not allowed for memory evidence.",
                "error"
            )
            self.btn_upload.setEnabled(False)
            return False, "Memory images must be single file"
        
        # Rule: Non-multipart mode must be single file
        if not is_multipart and len(self.selected_files) > 1:
            self._set_validation_status(
                "❌ You selected multiple files.\n\n"
                "Enable 'Multi-part forensic image' to upload split disks (E01, E02, ...).",
                "error"
            )
            self.btn_upload.setEnabled(False)
            return False, "Enable multi-part mode for multiple files"
        
        # Validate file existence and readability
        for path in self.selected_files:
            if not path.exists():
                self._set_validation_status(
                    f"❌ File not found: {path.name}",
                    "error"
                )
                self.btn_upload.setEnabled(False)
                return False, f"File not found: {path.name}"
            
            if path.stat().st_size == 0:
                self._set_validation_status(
                    f"❌ Empty file: {path.name}",
                    "error"
                )
                self.btn_upload.setEnabled(False)
                return False, f"Empty file: {path.name}"
        
        # For multi-part, validate sequence
        if is_multipart and len(self.selected_files) > 1:
            valid, error = self._validate_multipart()
            if not valid:
                self._set_validation_status(error, "error")
                self.btn_upload.setEnabled(False)
                return False, error
        
        # All validations passed
        total_size = sum(p.stat().st_size for p in self.selected_files)
        
        if is_multipart and len(self.selected_files) > 1:
            self._set_validation_status(
                f"✅ Valid multi-part evidence set\n"
                f"{len(self.selected_files)} segments | {self._format_size(total_size)}",
                "success"
            )
        else:
            self._set_validation_status(
                f"✅ Evidence file ready for upload\n"
                f"{self._format_size(total_size)}",
                "success"
            )
        
        self.btn_upload.setEnabled(True)
        return True, ""
    
    def _validate_multipart(self) -> Tuple[bool, str]:
        """
        Validate multi-part evidence sequence.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # E01 pattern
        e01_pattern = re.compile(r'^(.+)\.E(\d{2})$', re.IGNORECASE)
        
        # Parse files
        base_names = set()
        sequences = []
        
        for path in self.selected_files:
            match = e01_pattern.match(path.name)
            if match:
                base_names.add(match.group(1))
                sequences.append(int(match.group(2)))
            else:
                # Check .001 pattern
                split_pattern = re.compile(r'^(.+)\.(\d{3})$')
                split_match = split_pattern.match(path.name)
                if split_match:
                    base_names.add(split_match.group(1))
                    sequences.append(int(split_match.group(2)))
                else:
                    return False, f"❌ Invalid multi-part filename: {path.name}\nExpected: name.E01, name.E02, ..."
        
        # Check all same base name
        if len(base_names) > 1:
            return False, f"❌ Mixed evidence sets detected:\n{', '.join(base_names)}\n\nAll parts must belong to the same evidence set."
        
        # Check for missing segments
        base_name = list(base_names)[0] if base_names else ""
        sequences.sort()
        
        expected_start = 1
        missing = []
        for i in range(expected_start, max(sequences) + 1):
            if i not in sequences:
                missing.append(i)
        
        if missing:
            missing_names = [f"{base_name}.E{str(m).zfill(2)}" for m in missing[:5]]
            suffix = f" (+{len(missing)-5} more)" if len(missing) > 5 else ""
            return False, f"❌ Invalid evidence set:\nMissing: {', '.join(missing_names)}{suffix}"
        
        return True, ""
    
    def _set_validation_status(self, message: str, status: str):
        """Set validation status display."""
        self.lbl_validation.setText(message)
        
        if status == "error":
            self.validation_frame.setStyleSheet("""
                QFrame {
                    background-color: #c0392b;
                    border-radius: 5px;
                    padding: 10px;
                }
                QLabel {
                    color: white;
                    font-size: 13px;
                }
            """)
        elif status == "success":
            self.validation_frame.setStyleSheet("""
                QFrame {
                    background-color: #27ae60;
                    border-radius: 5px;
                    padding: 10px;
                }
                QLabel {
                    color: white;
                    font-size: 13px;
                }
            """)
        else:  # info
            self.validation_frame.setStyleSheet("""
                QFrame {
                    background-color: #2980b9;
                    border-radius: 5px;
                    padding: 10px;
                }
                QLabel {
                    color: white;
                    font-size: 13px;
                }
            """)
    
    def _on_upload(self):
        """Handle upload button click."""
        # Final validation
        valid, error = self._validate_selection()
        if not valid:
            QMessageBox.critical(self, "Validation Error", error)
            return
        
        # Create selection result
        selection = EvidenceSelection(
            evidence_type=self._get_evidence_type(),
            is_multipart=self.chk_multipart.isChecked(),
            file_paths=self.selected_files.copy(),
            case_name=self.case_name,
            operator=self.operator
        )
        
        # Emit signal and accept dialog
        self.evidence_selected.emit(selection)
        self.accept()
    
    def get_selection(self) -> Optional[EvidenceSelection]:
        """Get the evidence selection after dialog closes."""
        if self.result() == QDialog.DialogCode.Accepted:
            return EvidenceSelection(
                evidence_type=self._get_evidence_type(),
                is_multipart=self.chk_multipart.isChecked(),
                file_paths=self.selected_files.copy(),
                case_name=self.case_name,
                operator=self.operator
            )
        return None


class EvidenceProcessingDialog(QDialog):
    """
    Dialog showing evidence processing progress.
    
    Displays all pipeline phases with real-time progress.
    """
    
    # Signals
    cancel_requested = pyqtSignal()
    
    def __init__(self, parent=None, case_name: str = ""):
        super().__init__(parent)
        self.case_name = case_name
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the processing dialog UI."""
        self.setWindowTitle(f"Processing Evidence - {self.case_name}")
        self.setMinimumSize(600, 500)
        self.setModal(True)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Header
        header = QLabel("🔄 Processing Forensic Evidence")
        header.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(header)
        
        # Overall progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(30)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        self.lbl_status = QLabel("Initializing...")
        self.lbl_status.setStyleSheet("font-size: 14px;")
        layout.addWidget(self.lbl_status)
        
        # Phase list
        phases_group = QGroupBox("Pipeline Phases")
        phases_layout = QVBoxLayout()
        
        self.phase_labels = {}
        phases = [
            ("validation", "🔍 Validation"),
            ("hashing", "🔐 Computing Hashes"),
            ("chain_of_custody", "📜 Chain of Custody"),
            ("reconstruction", "🔧 Evidence Reconstruction"),
            ("partition_discovery", "💾 Partition Discovery"),
            ("artifact_discovery", "🔎 Artifact Discovery"),
            ("artifact_extraction", "📤 Artifact Extraction"),
            ("parsing", "📝 Parsing"),
            ("normalization", "📊 Normalization"),
            ("timeline_build", "⏱️ Timeline Build"),
            ("ml_analysis", "🤖 ML Analysis"),
            ("ueba", "👤 UEBA Profiling"),
            ("visualization", "📈 Visualization"),
            ("terminal_init", "🖥️ Terminal Init"),
        ]
        
        for phase_id, phase_name in phases:
            lbl = QLabel(f"○ {phase_name}")
            lbl.setStyleSheet("font-size: 12px; color: #888;")
            self.phase_labels[phase_id] = lbl
            phases_layout.addWidget(lbl)
        
        phases_group.setLayout(phases_layout)
        
        # Scroll area for phases
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(phases_group)
        scroll.setMaximumHeight(300)
        layout.addWidget(scroll)
        
        # Chain of Custody log
        coc_group = QGroupBox("Chain of Custody Log")
        coc_layout = QVBoxLayout()
        
        self.coc_list = QListWidget()
        self.coc_list.setMaximumHeight(100)
        coc_layout.addWidget(self.coc_list)
        
        coc_group.setLayout(coc_layout)
        layout.addWidget(coc_group)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        
        self.btn_cancel = QPushButton("⏹️ Cancel")
        self.btn_cancel.clicked.connect(self._on_cancel)
        buttons_layout.addWidget(self.btn_cancel)
        
        self.btn_close = QPushButton("Close")
        self.btn_close.setEnabled(False)
        self.btn_close.clicked.connect(self.accept)
        buttons_layout.addWidget(self.btn_close)
        
        layout.addLayout(buttons_layout)
        
        self.setLayout(layout)
    
    def update_progress(self, percentage: int, status: str):
        """Update overall progress."""
        self.progress_bar.setValue(percentage)
        self.lbl_status.setText(status)
    
    def update_phase(self, phase_id: str, status: str):
        """
        Update phase status.
        
        Args:
            phase_id: Phase identifier
            status: 'pending', 'in_progress', 'completed', 'failed'
        """
        if phase_id in self.phase_labels:
            lbl = self.phase_labels[phase_id]
            text = lbl.text()[2:]  # Remove status icon
            
            if status == "in_progress":
                lbl.setText(f"◐ {text}")
                lbl.setStyleSheet("font-size: 12px; color: #3498db; font-weight: bold;")
            elif status == "completed":
                lbl.setText(f"✔ {text}")
                lbl.setStyleSheet("font-size: 12px; color: #27ae60;")
            elif status == "failed":
                lbl.setText(f"✘ {text}")
                lbl.setStyleSheet("font-size: 12px; color: #e74c3c;")
            else:
                lbl.setText(f"○ {text}")
                lbl.setStyleSheet("font-size: 12px; color: #888;")
    
    def add_coc_entry(self, message: str):
        """Add entry to CoC log display."""
        self.coc_list.addItem(f"📝 {message}")
        self.coc_list.scrollToBottom()
    
    def set_complete(self, success: bool, message: str = ""):
        """Mark processing as complete."""
        self.btn_cancel.setEnabled(False)
        self.btn_close.setEnabled(True)
        
        if success:
            self.lbl_status.setText("✅ Processing Complete!")
            self.lbl_status.setStyleSheet("font-size: 14px; color: #27ae60; font-weight: bold;")
        else:
            self.lbl_status.setText(f"❌ Processing Failed: {message}")
            self.lbl_status.setStyleSheet("font-size: 14px; color: #e74c3c; font-weight: bold;")
    
    def _on_cancel(self):
        """Handle cancel button."""
        reply = QMessageBox.question(
            self,
            "Cancel Processing",
            "Are you sure you want to cancel?\n\nPartially processed data will be removed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.cancel_requested.emit()
            self.reject()
