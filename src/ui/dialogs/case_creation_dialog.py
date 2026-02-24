"""
Case Creation Dialog for FEPD
Dialog for creating a new forensic case with validation.
Supports both single file and multi-part forensic images.
"""

import os
import logging
from pathlib import Path
from typing import List
from datetime import datetime, timezone
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, 
    QLabel, QLineEdit, QPushButton, QFileDialog, 
    QMessageBox, QProgressDialog, QCheckBox, QGroupBox,
    QTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from src.core.case_manager import CaseManager
from src.modules.evidence_validator import get_evidence_validator, EvidenceObject
from src.core.evidence_registry import EvidenceRegistry
from src.core.forensic_audit_logger import ForensicAuditLogger

logger = logging.getLogger(__name__)


class HashCalculationThread(QThread):
    """Background thread for case creation with pre-computed hash."""
    
    finished = pyqtSignal(dict)  # Emits case metadata on success
    error = pyqtSignal(str)  # Emits error message on failure
    progress = pyqtSignal(int, str)  # (percent, status_message)
    
    def __init__(self, case_manager, case_id, case_name, investigator, evidence_obj):
        super().__init__()
        self.case_manager = case_manager
        self.case_id = case_id
        self.case_name = case_name
        self.investigator = investigator
        self.evidence_obj = evidence_obj
    
    def run(self):
        """Run the case creation in background."""
        try:
            # Get primary path (E01 for multi-part, single file for single)
            primary_path = str(self.evidence_obj.get_primary_path())
            
            # CRITICAL FIX: Extract pre-computed hash from evidence validator
            # Eliminates double hashing (CRITICAL-002)
            precomputed_hash = None
            if self.evidence_obj.parts and len(self.evidence_obj.parts) > 0:
                precomputed_hash = self.evidence_obj.parts[0].sha256_hash
            
            self.progress.emit(10, "Creating case directory...")
            
            # Pass pre-computed hash to avoid re-hashing
            case_metadata = self.case_manager.create_case(
                self.case_id,
                self.case_name,
                self.investigator,
                primary_path,
                precomputed_hash=precomputed_hash
            )
            
            self.progress.emit(90, "Finalizing case metadata...")
            
            # Add evidence object to metadata
            case_metadata['evidence_object'] = self.evidence_obj.to_dict()
            
            self.progress.emit(100, "Case creation complete")
            self.finished.emit(case_metadata)
        except Exception as e:
            self.error.emit(str(e))


class CaseCreationDialog(QDialog):
    """
    Dialog for creating a new forensic case.
    Collects case information and validates inputs.
    Supports single file and multi-part forensic images.
    """
    
    def __init__(self, parent=None):
        """
        Initialize the Case Creation Dialog.
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.case_manager = CaseManager()
        self.case_metadata = None
        self.hash_thread = None
        self.evidence_validator = get_evidence_validator()
        self.evidence_object = None
        self.selected_files = []
        self.validation_timestamp = None  # Track when evidence was validated
        
        # Initialize evidence registry
        cases_base_dir = Path("cases")
        cases_base_dir.mkdir(exist_ok=True)
        self.evidence_registry = EvidenceRegistry(cases_base_dir)
        
        # Initialize audit logger
        self.audit_logger = ForensicAuditLogger()
        
        self._init_ui()
        
        logger.info("Case Creation Dialog initialized")
    
    def _init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Create New Case")
        self.setModal(True)
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)
        
        # Main layout
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(25, 25, 25, 25)
        
        # Title
        title_label = QLabel("Create Case")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)
        
        # Description
        desc_label = QLabel("Enter case metadata. All actions are audit-logged.")
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #666;")
        layout.addWidget(desc_label)
        
        # Add spacing
        layout.addSpacing(10)
        
        # Form layout
        form_layout = QFormLayout()
        form_layout.setSpacing(15)
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        # Case ID field
        self.case_id_input = QLineEdit()
        self.case_id_input.setPlaceholderText("CASE-YYYY-NNN")
        self.case_id_input.setMinimumHeight(30)
        self.case_id_input.textChanged.connect(self._validate_inputs)
        form_layout.addRow("Case ID:", self.case_id_input)
        
        # Case Name field
        self.case_name_input = QLineEdit()
        self.case_name_input.setPlaceholderText("")
        self.case_name_input.setMinimumHeight(30)
        self.case_name_input.textChanged.connect(self._validate_inputs)
        form_layout.addRow("Case Name:", self.case_name_input)
        
        # Investigator Name field
        self.investigator_input = QLineEdit()
        self.investigator_input.setPlaceholderText("")
        self.investigator_input.setMinimumHeight(30)
        self.investigator_input.textChanged.connect(self._validate_inputs)
        form_layout.addRow("Operator:", self.investigator_input)
        
        layout.addLayout(form_layout)
        
        # Add spacing
        layout.addSpacing(15)
        
        # === EVIDENCE TYPE SELECTION ===
        evidence_group = QGroupBox("Evidence Type Selection")
        evidence_layout = QVBoxLayout()
        
        # Multi-part checkbox
        self.multipart_checkbox = QCheckBox("Multi-part forensic image (E01/E02/...)")
        self.multipart_checkbox.setToolTip("Enable for split disk images")
        self.multipart_checkbox.stateChanged.connect(self._on_evidence_type_changed)
        evidence_layout.addWidget(self.multipart_checkbox)
        
        # Info labels
        self.single_mode_label = QLabel("Single-file evidence mode")
        self.single_mode_label.setWordWrap(True)
        self.single_mode_label.setStyleSheet("color: #666; padding: 5px; font-size: 9pt;")
        evidence_layout.addWidget(self.single_mode_label)
        
        self.multipart_mode_label = QLabel("Multi-part evidence mode")
        self.multipart_mode_label.setWordWrap(True)
        self.multipart_mode_label.setStyleSheet("color: #666; padding: 5px; font-size: 9pt;")
        self.multipart_mode_label.hide()
        evidence_layout.addWidget(self.multipart_mode_label)
        
        evidence_group.setLayout(evidence_layout)
        layout.addWidget(evidence_group)
        
        # Add spacing
        layout.addSpacing(10)
        
        # === IMAGE PATH SELECTION ===
        image_group = QGroupBox("Evidence Files")
        image_group_layout = QVBoxLayout()
        
        # Browse button
        browse_layout = QHBoxLayout()
        self.browse_btn = QPushButton("Select Evidence Files")
        self.browse_btn.setMinimumHeight(35)
        self.browse_btn.clicked.connect(self._browse_image)
        browse_layout.addWidget(self.browse_btn)
        image_group_layout.addLayout(browse_layout)
        
        # Selected files display
        self.evidence_summary = QTextEdit()
        self.evidence_summary.setReadOnly(True)
        self.evidence_summary.setMaximumHeight(100)
        self.evidence_summary.setPlaceholderText("No evidence selected")
        self.evidence_summary.setStyleSheet("""
            QTextEdit {
                background-color: #f5f5f5;
                border: 1px solid #ccc;
                border-radius: 3px;
                padding: 5px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 9pt;
            }
        """)
        image_group_layout.addWidget(self.evidence_summary)
        
        image_group.setLayout(image_group_layout)
        layout.addWidget(image_group)
        
        # Add spacing
        layout.addSpacing(10)
        
        # Validation info label
        self.validation_label = QLabel("")
        self.validation_label.setWordWrap(True)
        self.validation_label.setStyleSheet("""
            background-color: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #f5c6cb;
        """)
        self.validation_label.hide()
        layout.addWidget(self.validation_label)
        
        # Add stretch
        layout.addStretch()
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        # Cancel button
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setMinimumHeight(35)
        self.cancel_btn.setMinimumWidth(100)
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        # Create button
        self.create_btn = QPushButton("Create Case")
        self.create_btn.setMinimumHeight(35)
        self.create_btn.setMinimumWidth(120)
        self.create_btn.setEnabled(False)
        self.create_btn.setStyleSheet("""
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover:enabled {
                background-color: #106ebe;
            }
            QPushButton:pressed:enabled {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.create_btn.clicked.connect(self._create_case)
        button_layout.addWidget(self.create_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _on_evidence_type_changed(self):
        """Handle evidence type checkbox change."""
        is_multipart = self.multipart_checkbox.isChecked()
        
        # Toggle info labels
        self.single_mode_label.setVisible(not is_multipart)
        self.multipart_mode_label.setVisible(is_multipart)
        
        # Update browse button text
        if is_multipart:
            self.browse_btn.setText("Select Evidence Parts")
        else:
            self.browse_btn.setText("Select Evidence File")
        
        # Clear selection when mode changes
        self.selected_files = []
        self.evidence_object = None
        self.evidence_summary.clear()
        self._validate_inputs()
    
    def _browse_image(self):
        """Open file dialog to select evidence image(s)."""
        is_multipart = self.multipart_checkbox.isChecked()
        
        if is_multipart:
            # Multi-part mode: allow multiple file selection
            file_paths, _ = QFileDialog.getOpenFileNames(
                self,
                "Select All Evidence Parts (E01, E02, ...)",
                "",
                "Forensic Images (*.E01 *.E02 *.E03 *.E04 *.E05 *.E06 *.E07 *.E08 *.E09 "
                "*.e01 *.e02 *.e03 *.L01 *.L02 *.L03 *.001 *.002 *.003);;All Files (*.*)"
            )
            
            if file_paths:
                self.selected_files = [Path(p) for p in file_paths]
                logger.info(f"Selected {len(file_paths)} evidence parts")
                self._validate_evidence()
        else:
            # Single file mode: allow only one file
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Evidence File",
                "",
                "Evidence Files (*.img *.dd *.raw *.mem *.dmp *.aff *.log *.zip *.001);;All Files (*.*)"
            )
            
            if file_path:
                self.selected_files = [Path(file_path)]
                logger.info(f"Evidence file selected: {file_path}")
                self._validate_evidence()
    
    def _validate_evidence(self):
        """Validate selected evidence files."""
        if not self.selected_files:
            self.evidence_object = None
            self.evidence_summary.clear()
            self._validate_inputs()
            return
        
        is_multipart = self.multipart_checkbox.isChecked()
        
        # Validate using evidence validator
        is_valid, evidence_obj, error_msg = self.evidence_validator.validate_evidence(
            self.selected_files,
            is_multipart
        )
        
        if is_valid:
            self.evidence_object = evidence_obj
            self.validation_timestamp = evidence_obj.validation_timestamp
            summary = self.evidence_validator.format_evidence_summary(evidence_obj)
            self.evidence_summary.setText(summary)
            self.evidence_summary.setStyleSheet("""
                QTextEdit {
                    background-color: #d4edda;
                    border: 1px solid #c3e6cb;
                    color: #155724;
                    border-radius: 3px;
                    padding: 8px;
                    font-family: 'Consolas', 'Courier New', monospace;
                    font-size: 9pt;
                }
            """)
        else:
            self.evidence_object = None
            if evidence_obj and not evidence_obj.is_complete:
                # Show partial info for incomplete multi-part
                summary = self.evidence_validator.format_evidence_summary(evidence_obj)
            else:
                summary = f"❌ Invalid Evidence:\n{error_msg}"
            
            self.evidence_summary.setText(summary)
            self.evidence_summary.setStyleSheet("""
                QTextEdit {
                    background-color: #f8d7da;
                    border: 1px solid #f5c6cb;
                    color: #721c24;
                    border-radius: 3px;
                    padding: 8px;
                    font-family: 'Consolas', 'Courier New', monospace;
                    font-size: 9pt;
                }
            """)
        
        self._validate_inputs()
    
    def _validate_inputs(self):
        """Validate all input fields and enable/disable Create button."""
        case_id = self.case_id_input.text().strip()
        case_name = self.case_name_input.text().strip()
        investigator = self.investigator_input.text().strip()
        
        # Check if all fields are filled
        all_filled = all([case_id, case_name, investigator]) and self.evidence_object is not None
        
        # Validate case ID format (alphanumeric, dashes, underscores)
        valid_case_id = bool(case_id) and all(c.isalnum() or c in '-_' for c in case_id)
        
        # Check if case already exists
        case_exists = (self.case_manager.base_cases_dir / case_id).exists() if case_id else False
        
        # Determine validation status
        if not all_filled:
            if not self.evidence_object:
                self.validation_label.setText("⚠️ Please select valid evidence file(s)")
            else:
                self.validation_label.setText("⚠️ All fields are required")
            self.validation_label.show()
            self.create_btn.setEnabled(False)
        elif not valid_case_id:
            self.validation_label.setText("⚠️ Case ID can only contain letters, numbers, dashes, and underscores")
            self.validation_label.show()
            self.create_btn.setEnabled(False)
        elif case_exists:
            self.validation_label.setText(f"⚠️ Case '{case_id}' already exists. Please choose a different Case ID.")
            self.validation_label.show()
            self.create_btn.setEnabled(False)
        else:
            # Check for duplicate evidence across cases
            primary_hash = self.evidence_object.parts[0].sha256_hash if self.evidence_object.parts else None
            if primary_hash:
                duplicate_info = self.evidence_registry.check_duplicate(primary_hash)
                if duplicate_info:
                    # Show warning but allow proceed (user may intentionally re-ingest in another case)
                    self.validation_label.setText(
                        f"⚠️ This evidence already exists in case '{duplicate_info['case_id']}'. "
                        f"Proceeding will create a new case with the same evidence."
                    )
                    self.validation_label.show()
                    self.create_btn.setEnabled(True)
                    return
            
            self.validation_label.hide()
            self.create_btn.setEnabled(True)
    
    def _create_case(self):
        """Create the case with provided information."""
        case_id = self.case_id_input.text().strip()
        case_name = self.case_name_input.text().strip()
        investigator = self.investigator_input.text().strip()
        
        if not self.evidence_object:
            QMessageBox.warning(self, "No Evidence", "Please select valid evidence file(s).")
            return
        
        # CRITICAL: Verify files haven't been modified since validation (TOCTOU protection)
        modified_files = []
        if self.evidence_object.parts:
            # Multi-part evidence
            for part in self.evidence_object.parts:
                try:
                    current_mtime = part.path.stat().st_mtime
                    if part.file_mtime and current_mtime > part.file_mtime:
                        modified_files.append(part.path.name)
                        # AUDIT: Log TOCTOU violation
                        self.audit_logger.log_toctou_violation(
                            file_path=str(part.path),
                            validation_time=self.validation_timestamp or "unknown",
                            ingestion_time=datetime.now(timezone.utc).isoformat(),
                            user=investigator
                        )
                except Exception as e:
                    QMessageBox.critical(
                        self,
                        "Evidence Access Error",
                        f"Cannot access evidence file {part.path.name}:\n{e}\n\n"
                        "Evidence may have been moved or deleted."
                    )
                    return
        elif self.evidence_object.single_path:
            # Single file evidence
            try:
                self.evidence_object.single_path.stat()
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Evidence Access Error",
                    f"Cannot access evidence file:\n{e}\n\n"
                    "Evidence may have been moved or deleted."
                )
                return
        
        if modified_files:
            QMessageBox.critical(
                self,
                "Evidence Integrity Violation",
                f"The following evidence files were MODIFIED after validation:\n\n"
                + "\n".join(f"  • {f}" for f in modified_files) +
                "\n\nThis violates forensic integrity requirements.\n"
                "Evidence must remain unchanged from validation to ingestion.\n\n"
                "Please re-select the evidence and try again."
            )
            return
        
        logger.info(f"Creating case: {case_id}")
        logger.info(f"Evidence type: {self.evidence_object.type.value}")
        
        # Get total size for progress estimation
        file_size_gb = self.evidence_object.total_size_bytes / (1024 ** 3)
        
        # Show warning for large files
        if file_size_gb > 5:
            reply = QMessageBox.question(
                self,
                "Large Evidence Detected",
                f"The selected evidence is {file_size_gb:.2f} GB. "
                f"Calculating SHA-256 hash may take several minutes.\n\n"
                f"Do you want to continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            
            if reply == QMessageBox.StandardButton.No:
                return
        
        # Create progress dialog
        progress = QProgressDialog(
            "Initializing case creation...\nThis may take several minutes for large files.",
            None,  # No cancel button
            0, 100,  # 0-100 percent
            self
        )
        progress.setWindowTitle("Creating Case")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(0)
        progress.setAutoClose(False)  # Keep open until we close it
        progress.show()
        
        # Disable buttons
        self.create_btn.setEnabled(False)
        self.cancel_btn.setEnabled(False)
        
        # Create case in background thread
        self.hash_thread = HashCalculationThread(
            self.case_manager,
            case_id,
            case_name,
            investigator,
            self.evidence_object
        )
        
        self.hash_thread.progress.connect(lambda pct, msg: self._on_progress(progress, pct, msg))
        self.hash_thread.finished.connect(lambda metadata: self._on_case_created(metadata, progress))
        self.hash_thread.error.connect(lambda error: self._on_case_creation_error(error, progress))
        
        self.hash_thread.start()
    
    def _on_progress(self, progress_dialog, percent, message):
        """Update progress dialog."""
        progress_dialog.setValue(percent)
        progress_dialog.setLabelText(message)
    
    def _on_case_created(self, case_metadata, progress):
        """Handle successful case creation."""
        progress.close()
        
        self.case_metadata = case_metadata
        
        logger.info(f"Case created successfully: {case_metadata['case_id']}")
        
        # Register evidence in global registry to prevent duplicates
        if self.evidence_object and self.evidence_object.parts:
            primary_hash = self.evidence_object.parts[0].sha256_hash
            self.evidence_registry.register_evidence(
                evidence_hash=primary_hash,
                case_id=case_metadata['case_id'],
                evidence_name=self.evidence_object.base_name,
                evidence_type=self.evidence_object.type.value
            )
            logger.info(f"Registered evidence {primary_hash[:16]}... in global registry")
            
            # AUDIT: Log case creation
            investigator = case_metadata.get('investigator', 'unknown')
            self.audit_logger.log_case_created(
                case_id=case_metadata['case_id'],
                evidence_hash=primary_hash,
                user=investigator
            )
        
        # Format message based on evidence type
        evidence_info = ""
        if self.evidence_object:
            if self.evidence_object.type.value == "multi_part_disk":
                evidence_info = (
                    f"Evidence Type: Multi-Part Forensic Image\n"
                    f"Base Name: {self.evidence_object.base_name}\n"
                    f"Total Parts: {self.evidence_object.total_parts}\n"
                    f"Primary Hash: {case_metadata['evidence_image']['sha256_hash'][:16]}..."
                )
            else:
                evidence_info = (
                    f"Evidence Type: Single File\n"
                    f"Evidence Hash: {case_metadata['evidence_image']['sha256_hash'][:16]}..."
                )
        
        QMessageBox.information(
            self,
            "Case Created",
            f"Case '{case_metadata['case_id']}' has been created successfully!\n\n"
            f"Case Directory: {self.case_manager.get_case_path()}\n"
            f"{evidence_info}"
        )
        
        self.accept()
    
    def _on_case_creation_error(self, error_msg, progress):
        """Handle case creation error."""
        progress.close()
        
        # Re-enable buttons
        self.create_btn.setEnabled(True)
        self.cancel_btn.setEnabled(True)
        
        logger.error(f"Case creation failed: {error_msg}")
        
        QMessageBox.critical(
            self,
            "Case Creation Failed",
            f"Failed to create case:\n\n{error_msg}"
        )
    
    def get_case_metadata(self):
        """
        Get the created case metadata.
        
        Returns:
            Dictionary containing case metadata, or None if case not created
        """
        return self.case_metadata
    
    def get_image_path(self):
        """
        Get the selected forensic image path.
        
        Returns:
            str: Path to the forensic image, or None if not selected
        """
        if self.case_metadata:
            return self.case_metadata.get('evidence_image', {}).get('path')
        return None
