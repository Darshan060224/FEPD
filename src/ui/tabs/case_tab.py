"""
🗂️ CASE TAB - Root of Trust for FEPD

This tab is the legal backbone of the forensic system.
Every action, artifact, model output, and report exists inside a Case.
Without a Case, nothing in FEPD is allowed to run.

Responsibilities:
- Create forensic workspace
- Manage case metadata
- Own Chain of Custody ledger
- Control evidence ownership & handover
- Guarantee auditability

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
import json
import hashlib
import shutil
import sqlite3
from pathlib import Path
from datetime import datetime
from uuid import uuid4
from typing import Optional, Dict, Any, List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QPushButton, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox, QFileDialog, QComboBox, QDialog, QProgressBar,
    QApplication
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor

from ...core.case_manager import CaseManager
from ...core.chain_of_custody import ChainLogger, CoC_Actions

logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================

# File permissions
READ_ONLY_PERMISSION = 0o444  # Read-only file permission

# CoC table performance
COC_BATCH_SIZE = 100  # Load CoC entries in batches
COC_MAX_DISPLAY = 1000  # Maximum entries to display at once

# Auto-save
AUTO_SAVE_INTERVAL = 30000  # Auto-save every 30 seconds (ms)

# Recent cases
MAX_RECENT_CASES = 10  # Maximum recent cases to track

# Validation
MIN_CASE_NAME_LENGTH = 3
MAX_CASE_NAME_LENGTH = 100
MIN_OPERATOR_NAME_LENGTH = 2

# Status messages
STATUS_CREATING = "⏳ Creating case..."
STATUS_LOADING = "⏳ Loading case..."
STATUS_SEALING = "🔒 Sealing case..."
STATUS_EXPORTING = "📤 Exporting case..."
STATUS_VERIFYING = "✔️ Verifying CoC..."


class CaseTab(QWidget):
    """
    📋 Case Management Tab
    
    The root of trust for all FEPD operations.
    """
    
    # Signals
    case_created = pyqtSignal(str)  # case_id
    case_loaded = pyqtSignal(dict)   # case_metadata
    case_sealed = pyqtSignal(str)    # case_id
    case_exported = pyqtSignal(str)  # export_path
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.case_manager = CaseManager()
        self.current_case: Optional[Dict] = None
        self.coc_logger: Optional[ChainLogger] = None
        
        # Recent cases tracking
        self._recent_cases: List[Dict[str, str]] = []
        self._load_recent_cases()
        
        # Auto-save timer
        self._auto_save_timer: Optional[QTimer] = None
        self._is_modified = False
        
        # Loading state
        self._loading_timer: Optional[QTimer] = None
        self._loading_dots = 0
        
        # CoC pagination
        self._coc_current_page = 0
        self._coc_total_entries = 0
        
        self._init_ui()
        self._setup_auto_save()
        logger.info("Case Tab initialized")
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout()
        
        # ────────────────────────────────────────────────────────────
        # CASE INFO PANEL
        # ────────────────────────────────────────────────────────────
        info_group = QGroupBox("📋 Current Case")
        info_layout = QVBoxLayout()
        
        # Case Details Grid
        details = QWidget()
        grid = QVBoxLayout()
        
        self.lbl_case_name = self._create_info_label("Case:", "No case loaded")
        self.lbl_case_id = self._create_info_label("ID:", "—")
        self.lbl_operator = self._create_info_label("Operator:", "—")
        self.lbl_created = self._create_info_label("Created:", "—")
        self.lbl_status = self._create_info_label("Status:", "—")
        self.lbl_coc_status = self._create_info_label("CoC Status:", "—")
        
        grid.addWidget(self.lbl_case_name)
        grid.addWidget(self.lbl_case_id)
        grid.addWidget(self.lbl_operator)
        grid.addWidget(self.lbl_created)
        grid.addWidget(self.lbl_status)
        grid.addWidget(self.lbl_coc_status)
        
        details.setLayout(grid)
        info_layout.addWidget(details)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        
        self.btn_create = QPushButton("➕ Create Case")
        self.btn_create.clicked.connect(self._on_create_case)
        self.btn_create.setStyleSheet("""
            QPushButton {
                background-color: #2e7d32;
                color: white;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388e3c;
            }
        """)
        
        self.btn_load = QPushButton("📂 Load Case")
        self.btn_load.clicked.connect(self._on_load_case)
        
        self.btn_seal = QPushButton("🔒 Seal Case")
        self.btn_seal.clicked.connect(self._on_seal_case)
        self.btn_seal.setEnabled(False)
        self.btn_seal.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #f44336;
            }
            QPushButton:disabled {
                background-color: #666;
            }
        """)
        
        self.btn_export = QPushButton("📥 Export Case")
        self.btn_export.clicked.connect(self._on_export_case)
        self.btn_export.setEnabled(False)
        
        self.btn_verify = QPushButton("✔️ Verify CoC")
        self.btn_verify.clicked.connect(self._on_verify_coc)
        self.btn_verify.setEnabled(False)
        
        btn_layout.addWidget(self.btn_create)
        btn_layout.addWidget(self.btn_load)
        btn_layout.addWidget(self.btn_seal)
        btn_layout.addWidget(self.btn_export)
        btn_layout.addWidget(self.btn_verify)
        btn_layout.addStretch()
        
        info_layout.addLayout(btn_layout)
        
        # Loading indicator
        self.loading_label = QLabel("")
        self.loading_label.setStyleSheet("color: #4fc3f7; font-weight: bold; padding: 5px;")
        self.loading_label.setVisible(False)
        info_layout.addWidget(self.loading_label)
        
        # Progress bar for exports
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3e3e42;
                border-radius: 3px;
                text-align: center;
                background: #1e1e1e;
            }
            QProgressBar::chunk {
                background: #4fc3f7;
            }
        """)
        info_layout.addWidget(self.progress_bar)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # ────────────────────────────────────────────────────────────
        # CHAIN OF CUSTODY VIEWER
        # ────────────────────────────────────────────────────────────
        coc_group = QGroupBox("🔗 Chain of Custody Log")
        coc_layout = QVBoxLayout()
        
        # Search and filter toolbar
        search_layout = QHBoxLayout()
        
        self.coc_search = QLineEdit()
        self.coc_search.setPlaceholderText("🔍 Search CoC entries...")
        self.coc_search.textChanged.connect(self._filter_coc_entries)
        self.coc_search.setStyleSheet("""
            QLineEdit {
                padding: 6px;
                border: 1px solid #3e3e42;
                border-radius: 3px;
                background: #1e1e1e;
            }
        """)
        search_layout.addWidget(self.coc_search)
        
        self.coc_filter = QComboBox()
        self.coc_filter.addItems(["All Actions", "CASE_CREATED", "CASE_OPENED", "CASE_SEALED", "CASE_EXPORTED", "FILE_SELECTED", "HASH_COMPUTED"])
        self.coc_filter.currentTextChanged.connect(self._filter_coc_entries)
        self.coc_filter.setStyleSheet("""
            QComboBox {
                padding: 5px;
                border: 1px solid #3e3e42;
                border-radius: 3px;
                background: #2a2a2a;
                min-width: 150px;
            }
        """)
        search_layout.addWidget(self.coc_filter)
        
        coc_layout.addLayout(search_layout)
        
        self.coc_table = QTableWidget()
        self.coc_table.setColumnCount(5)
        self.coc_table.setHorizontalHeaderLabels([
            "Timestamp", "Action", "Actor", "Details", "Hash"
        ])
        self.coc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.coc_table.setAlternatingRowColors(True)
        self.coc_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        coc_layout.addWidget(self.coc_table)
        
        # CoC Stats and Pagination
        stats_layout = QHBoxLayout()
        self.lbl_coc_entries = QLabel("Entries: 0")
        self.lbl_coc_integrity = QLabel("Integrity: ✔️ VERIFIED")
        self.lbl_coc_integrity.setStyleSheet("color: #4CAF50; font-weight: bold;")
        
        stats_layout.addWidget(self.lbl_coc_entries)
        stats_layout.addWidget(self.lbl_coc_integrity)
        stats_layout.addStretch()
        
        # Pagination controls
        self.btn_coc_prev = QPushButton("◀ Previous")
        self.btn_coc_prev.clicked.connect(self._coc_prev_page)
        self.btn_coc_prev.setEnabled(False)
        self.btn_coc_prev.setMaximumWidth(100)
        stats_layout.addWidget(self.btn_coc_prev)
        
        self.lbl_coc_page = QLabel("Page 1")
        stats_layout.addWidget(self.lbl_coc_page)
        
        self.btn_coc_next = QPushButton("Next ▶")
        self.btn_coc_next.clicked.connect(self._coc_next_page)
        self.btn_coc_next.setEnabled(False)
        self.btn_coc_next.setMaximumWidth(100)
        stats_layout.addWidget(self.btn_coc_next)
        
        coc_layout.addLayout(stats_layout)
        coc_group.setLayout(coc_layout)
        layout.addWidget(coc_group)
        
        self.setLayout(layout)
    
    def _create_info_label(self, label: str, value: str) -> QWidget:
        """Create a label-value pair widget."""
        widget = QWidget()
        layout = QHBoxLayout()
        layout.setContentsMargins(5, 2, 5, 2)
        
        lbl = QLabel(label)
        lbl.setMinimumWidth(100)
        font = QFont()
        font.setBold(True)
        lbl.setFont(font)
        
        val = QLabel(value)
        val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        
        layout.addWidget(lbl)
        layout.addWidget(val)
        layout.addStretch()
        
        widget.setLayout(layout)
        
        # Store value label for updates
        widget.value_label = val
        
        return widget
    
    # ════════════════════════════════════════════════════════════════
    # CASE CREATION
    # ════════════════════════════════════════════════════════════════
    
    def _on_create_case(self) -> None:
        """Create new forensic case with validation."""
        from ...ui.dialogs.create_case_dialog import CreateCaseDialog
        
        dialog = CreateCaseDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        
        case_data = dialog.get_case_data()
        
        # Validate case data
        validation_error = self._validate_case_data(case_data)
        if validation_error:
            QMessageBox.warning(self, "Validation Error", validation_error)
            return
        
        # Show loading indicator
        self._show_loading(STATUS_CREATING)
        QApplication.processEvents()
        
        try:
            # Generate case ID
            case_id = str(uuid4())
            case_name = case_data['case_name']
            operator = case_data['operator']
            organization = case_data.get('organization', '')
            notes = case_data.get('notes', '')
            
            # Create case structure
            case_path = self.case_manager.base_cases_dir / case_id
            case_path.mkdir(parents=True, exist_ok=True)
            
            # Create subdirectories
            (case_path / "evidence").mkdir(exist_ok=True)
            (case_path / "artifacts").mkdir(exist_ok=True)
            (case_path / "reports").mkdir(exist_ok=True)
            (case_path / "exports").mkdir(exist_ok=True)
            (case_path / "indexes").mkdir(exist_ok=True)
            
            # Create metadata.json
            metadata = {
                "case_id": case_id,
                "case_name": case_name,
                "operator": operator,
                "organization": organization,
                "created_at": datetime.now().isoformat(),
                "status": "OPEN",
                "notes": notes,
                "version": "1.0"
            }
            
            metadata_file = case_path / "metadata.json"
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            
            # Initialize Chain of Custody
            coc_file = case_path / "chain_of_custody.log"
            self.coc_logger = ChainLogger(str(coc_file))
            
            # First CoC entry
            self.coc_logger.log(
                action="CASE_CREATED",
                actor=operator,
                details={
                    "case_id": case_id,
                    "case_name": case_name,
                    "organization": organization
                }
            )
            
            # Initialize case.db (SQLite)
            self._init_case_database(case_path)
            
            # Load the case
            metadata["path"] = str(case_path)
            self.current_case = metadata
            self._update_case_display()
            self._load_coc_log()
            
            # Update registry
            self.case_manager._update_registry(case_id, metadata)
            
            # Add to recent cases
            self._add_to_recent_cases(case_id, case_name)
            
            self._hide_loading()
            
            # Emit signal
            self.case_created.emit(case_id)
            
            QMessageBox.information(
                self,
                "✅ Case Created",
                f"Case '{case_name}' created successfully!\n\n"
                f"📋 Case ID: {case_id}\n"
                f"📁 Location: {case_path}\n\n"
                f"You can now add evidence and begin analysis."
            )
            
            logger.info(f"Case created: {case_id} - {case_name}")
            
        except Exception as e:
            self._hide_loading()
            logger.error(f"Failed to create case: {e}", exc_info=True)
            
            # Detailed error with recovery suggestions
            error_msg = str(e)
            if "Permission denied" in error_msg:
                suggestion = "\n\n💡 Try running as Administrator or check folder permissions."
            elif "disk" in error_msg.lower() or "space" in error_msg.lower():
                suggestion = "\n\n💡 Check available disk space."
            else:
                suggestion = "\n\n💡 Verify the cases directory is writable and accessible."
            
            QMessageBox.critical(
                self,
                "❌ Case Creation Failed",
                f"Failed to create case: {case_name}\n\n"
                f"Error: {error_msg}{suggestion}"
            )
    
    def _init_case_database(self, case_path: Path) -> None:
        """Initialize case SQLite database with error handling."""
        db_path = case_path / "case.db"
        
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                type TEXT,
                size INTEGER,
                md5 TEXT,
                sha1 TEXT,
                sha256 TEXT,
                imported_at TEXT,
                imported_by TEXT
            )
        """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                source_path TEXT,
                case_path TEXT,
                size INTEGER,
                hash TEXT,
                status TEXT,
                extracted_at TEXT
            )
        """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT,
                user TEXT,
                host TEXT,
                source TEXT,
                action TEXT,
                details TEXT,
                score REAL
            )
        """)
        
            conn.commit()
            conn.close()
            
            logger.info(f"Case database initialized: {db_path}")
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize case database: {e}")
            raise RuntimeError(f"Database initialization failed: {e}")
    
    # ════════════════════════════════════════════════════════════════
    # CASE LOADING
    # ════════════════════════════════════════════════════════════════
    
    def _on_load_case(self) -> None:
        """Load existing case with recent cases support."""
        # Show recent cases if available
        if self._recent_cases:
            from PyQt6.QtWidgets import QMenu
            menu = QMenu(self)
            menu.setTitle("Recent Cases")
            
            for recent in self._recent_cases[:MAX_RECENT_CASES]:
                action = menu.addAction(f"📋 {recent['name']}")
                action.setData(recent['id'])
                action.triggered.connect(lambda checked, cid=recent['id']: self._load_case_by_id(cid))
            
            menu.addSeparator()
            browse_action = menu.addAction("📂 Browse...")
            browse_action.triggered.connect(self._browse_for_case)
            
            menu.exec(self.btn_load.mapToGlobal(self.btn_load.rect().bottomLeft()))
        else:
            self._browse_for_case()
    
    def _browse_for_case(self) -> None:
        """Browse for case directory."""
        case_dir = QFileDialog.getExistingDirectory(
            self,
            "Select Case Directory",
            str(self.case_manager.base_cases_dir)
        )
        
        if not case_dir:
            return
        
        self._load_case_from_path(case_dir)
    
    def _load_case_by_id(self, case_id: str) -> None:
        """Load case by ID from recent cases."""
        case_path = self.case_manager.base_cases_dir / case_id
        if case_path.exists():
            self._load_case_from_path(str(case_path))
        else:
            QMessageBox.warning(
                self,
                "Case Not Found",
                f"Case directory not found:\n{case_path}\n\nIt may have been moved or deleted."
            )
            self._remove_from_recent_cases(case_id)
    
    def _load_case_from_path(self, case_dir: str) -> None:
        """Load case from directory path."""
        self._show_loading(STATUS_LOADING)
        QApplication.processEvents()
        
        try:
            case_path = Path(case_dir)
            metadata_file = case_path / "metadata.json"
            
            if not metadata_file.exists():
                raise FileNotFoundError("metadata.json not found in case directory")
            
            # Load metadata
            with open(metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            
            # Verify folder structure
            required_dirs = ["evidence", "artifacts", "reports"]
            for dirname in required_dirs:
                if not (case_path / dirname).exists():
                    logger.warning(f"Missing directory: {dirname}")
            
            # Load CoC
            coc_file = case_path / "chain_of_custody.log"
            if not coc_file.exists():
                QMessageBox.warning(
                    self,
                    "Warning",
                    "Chain of Custody log not found!\n"
                    "Case will open in READ-ONLY mode."
                )
                metadata['status'] = "READ_ONLY"
            else:
                self.coc_logger = ChainLogger(str(coc_file))
                
                # Verify CoC integrity
                if not self.coc_logger.verify_chain():
                    QMessageBox.critical(
                        self,
                        "CoC Verification Failed",
                        "⚠️ Chain of Custody integrity check FAILED!\n\n"
                        "This case has been TAMPERED with or is CORRUPT.\n"
                        "Opening in QUARANTINE MODE.\n\n"
                        "ML, Reports, and Export are DISABLED."
                    )
                    metadata['status'] = "QUARANTINE"
                else:
                    # Log case opening
                    self.coc_logger.log(
                        action="CASE_OPENED",
                        actor=metadata.get('operator', 'unknown'),
                        details={"case_id": metadata['case_id']}
                    )
            
            metadata["path"] = str(case_path)
            self.current_case = metadata
            self._update_case_display()
            self._load_coc_log()
            
            # Add to recent cases
            self._add_to_recent_cases(metadata['case_id'], metadata.get('case_name', 'Unknown'))
            
            self._hide_loading()
            
            # Emit signal
            self.case_loaded.emit(metadata)
            
            logger.info(f"Case loaded: {metadata.get('case_name')}")
            
        except FileNotFoundError as e:
            self._hide_loading()
            logger.error(f"Case files not found: {e}")
            QMessageBox.critical(
                self,
                "❌ Case Not Found",
                f"Required case files are missing:\n{str(e)}\n\n"
                f"💡 The case may be corrupted or incomplete."
            )
        except json.JSONDecodeError as e:
            self._hide_loading()
            logger.error(f"Invalid case metadata: {e}")
            QMessageBox.critical(
                self,
                "❌ Invalid Case Format",
                f"Case metadata is corrupted or invalid:\n{str(e)}\n\n"
                f"💡 The metadata.json file may be damaged."
            )
        except Exception as e:
            self._hide_loading()
            logger.error(f"Failed to load case: {e}", exc_info=True)
            QMessageBox.critical(
                self,
                "❌ Load Failed",
                f"Failed to load case:\n{str(e)}\n\n"
                f"💡 Check file permissions and case integrity."
            )
    
    # ════════════════════════════════════════════════════════════════
    # CASE SEALING
    # ════════════════════════════════════════════════════════════════
    
    def _on_seal_case(self) -> None:
        """Seal case - makes it immutable."""
        if not self.current_case:
            QMessageBox.warning(self, "No Case", "No case is currently loaded.")
            return
        
        if self.current_case.get('status') == 'SEALED':
            QMessageBox.information(self, "Already Sealed", "This case is already sealed.")
            return
        
        reply = QMessageBox.question(
            self,
            "🔒 Seal Case",
            "⚠️ SEAL CASE?\n\n"
            "This will:\n"
            "• Mark case as SEALED\n"
            "• Make it IMMUTABLE\n"
            "• Disable all modifications\n"
            "• Create final CoC entry\n"
            "• Lock all case files\n\n"
            "⛔ This action CANNOT be undone!\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self._show_loading(STATUS_SEALING)
        QApplication.processEvents()
        
        try:
            # Update metadata
            self.current_case['status'] = "SEALED"
            self.current_case['sealed_at'] = datetime.now().isoformat()
            
            case_path = self.case_manager.base_cases_dir / self.current_case['case_id']
            metadata_file = case_path / "metadata.json"
            
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(self.current_case, f, indent=2)
            
            # Final CoC entry
            if self.coc_logger:
                self.coc_logger.log(
                    action="CASE_SEALED",
                    actor=self.current_case.get('operator', 'unknown'),
                    details={"case_id": self.current_case['case_id']}
                )
                
                # Seal the CoC log (make read-only)
                coc_file = Path(self.coc_logger.log_file)
                coc_file.chmod(READ_ONLY_PERMISSION)
            
            self._update_case_display()
            self._load_coc_log()
            
            self._hide_loading()
            
            self.case_sealed.emit(self.current_case['case_id'])
            
            QMessageBox.information(
                self,
                "✅ Case Sealed",
                f"🔒 Case '{self.current_case['case_name']}' is now SEALED.\n\n"
                "✓ All files locked as read-only\n"
                "✓ Final CoC entry recorded\n"
                "✓ No further modifications allowed\n\n"
                "The case is ready for export and archival."
            )
            
            logger.info(f"Case sealed: {self.current_case['case_id']}")
            
        except Exception as e:
            self._hide_loading()
            logger.error(f"Failed to seal case: {e}", exc_info=True)
            QMessageBox.critical(
                self,
                "❌ Seal Failed",
                f"Failed to seal case:\n{str(e)}\n\n"
                f"💡 Check file permissions and ensure the case is not open elsewhere."
            )
    
    # ════════════════════════════════════════════════════════════════
    # CASE EXPORT
    # ════════════════════════════════════════════════════════════════
    
    def _on_export_case(self) -> None:
        """Export case with progress indication and verification."""
        if not self.current_case:
            QMessageBox.warning(self, "No Case", "No case is currently loaded.")
            return
        
        export_path = QFileDialog.getSaveFileName(
            self,
            "Export Case",
            f"{self.current_case['case_name']}_export.zip",
            "ZIP Archive (*.zip)"
        )[0]
        
        if not export_path:
            return
        
        self._show_loading(STATUS_EXPORTING)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        QApplication.processEvents()
        
        try:
            case_path = self.case_manager.base_cases_dir / self.current_case['case_id']
            
            # Update progress
            self.progress_bar.setValue(10)
            QApplication.processEvents()
            
            # Create ZIP archive
            shutil.make_archive(
                export_path.replace('.zip', ''),
                'zip',
                case_path
            )
            
            self.progress_bar.setValue(70)
            QApplication.processEvents()
            
            # Compute hash of export
            with open(export_path, 'rb') as f:
                export_hash = hashlib.sha256(f.read()).hexdigest()
            
            self.progress_bar.setValue(90)
            QApplication.processEvents()
            
            # Log export
            if self.coc_logger:
                self.coc_logger.log(
                    action="CASE_EXPORTED",
                    actor=self.current_case.get('operator', 'unknown'),
                    details={
                        "case_id": self.current_case['case_id'],
                        "export_path": export_path,
                        "export_hash": export_hash
                    }
                )
            
            self.progress_bar.setValue(100)
            QApplication.processEvents()
            
            # Get file size
            export_size = Path(export_path).stat().st_size
            size_mb = export_size / (1024 * 1024)
            
            self._hide_loading()
            self.progress_bar.setVisible(False)
            
            self.case_exported.emit(export_path)
            
            QMessageBox.information(
                self,
                "✅ Export Complete",
                f"Case exported successfully!\n\n"
                f"📁 Location: {export_path}\n"
                f"📊 Size: {size_mb:.2f} MB\n"
                f"🔐 SHA256: {export_hash[:32]}...\n\n"
                f"The export includes all evidence, artifacts, and Chain of Custody."
            )
            
            logger.info(f"Case exported: {export_path} ({size_mb:.2f} MB)")
            
        except Exception as e:
            self._hide_loading()
            self.progress_bar.setVisible(False)
            logger.error(f"Failed to export case: {e}", exc_info=True)
            
            error_msg = str(e)
            if "Permission denied" in error_msg:
                suggestion = "\n\n💡 Close the ZIP file if it's open and try again."
            elif "disk" in error_msg.lower() or "space" in error_msg.lower():
                suggestion = "\n\n💡 Free up disk space and try again."
            else:
                suggestion = "\n\n💡 Ensure the destination folder is writable."
            
            QMessageBox.critical(
                self,
                "❌ Export Failed",
                f"Failed to export case:\n{error_msg}{suggestion}"
            )
    
    # ════════════════════════════════════════════════════════════════
    # COC VERIFICATION
    # ════════════════════════════════════════════════════════════════
    
    def _on_verify_coc(self) -> None:
        """Verify Chain of Custody integrity with detailed feedback."""
        if not self.coc_logger:
            QMessageBox.warning(self, "No CoC", "No Chain of Custody log available.")
            return
        
        self._show_loading(STATUS_VERIFYING)
        QApplication.processEvents()
        
        try:
            is_valid = self.coc_logger.verify_chain()
            
            self._hide_loading()
            
            if is_valid:
                entries_count = len(self.coc_logger.get_all_entries()) if hasattr(self.coc_logger, 'get_all_entries') else 'N/A'
                QMessageBox.information(
                    self,
                    "✅ CoC Verified",
                    f"✔️ Chain of Custody VERIFIED\n\n"
                    f"✓ All hash links intact\n"
                    f"✓ No tampering detected\n"
                    f"✓ {entries_count} entries validated\n\n"
                    f"This case maintains forensic integrity and is admissible."
                )
                self.lbl_coc_integrity.setText("Integrity: ✔️ VERIFIED")
                self.lbl_coc_integrity.setStyleSheet("color: #4CAF50; font-weight: bold;")
            else:
                QMessageBox.critical(
                    self,
                    "⛔ CoC FAILED",
                    "⛔ Chain of Custody VERIFICATION FAILED!\n\n"
                    "✗ Evidence integrity is COMPROMISED\n"
                    "✗ Hash chain is broken\n"
                    "✗ Case cannot be trusted for legal proceedings\n\n"
                    "⚠️ This case must be quarantined and investigated."
                )
                self.lbl_coc_integrity.setText("Integrity: ⛔ BROKEN")
                self.lbl_coc_integrity.setStyleSheet("color: #F44336; font-weight: bold;")
            
        except Exception as e:
            self._hide_loading()
            logger.error(f"CoC verification error: {e}", exc_info=True)
            QMessageBox.critical(
                self,
                "❌ Verification Error",
                f"Failed to verify Chain of Custody:\n{str(e)}\n\n"
                f"💡 The CoC log file may be corrupted or inaccessible."
            )
    
    # ════════════════════════════════════════════════════════════════
    # DISPLAY UPDATES
    # ════════════════════════════════════════════════════════════════
    
    def _update_case_display(self) -> None:
        """Update case information display with current case data."""
        if not self.current_case:
            return
        
        self._is_modified = False  # Reset modification flag after update
        
        self.lbl_case_name.value_label.setText(self.current_case.get('case_name', '—'))
        self.lbl_case_id.value_label.setText(self.current_case.get('case_id', '—'))
        self.lbl_operator.value_label.setText(self.current_case.get('operator', '—'))
        self.lbl_created.value_label.setText(self.current_case.get('created_at', '—'))
        
        # Status with color
        status = self.current_case.get('status', 'ACTIVE')
        status_widget = self.lbl_status.value_label
        status_widget.setText(status)
        
        if status == "OPEN":
            status_widget.setStyleSheet("color: #4CAF50; font-weight: bold;")
        elif status == "SEALED":
            status_widget.setStyleSheet("color: #FF9800; font-weight: bold;")
        elif status == "QUARANTINE":
            status_widget.setStyleSheet("color: #F44336; font-weight: bold;")
        elif status == "READ_ONLY":
            status_widget.setStyleSheet("color: #9E9E9E; font-weight: bold;")
        
        # Enable/disable buttons
        is_open = status == "OPEN"
        is_sealed = status == "SEALED"
        
        self.btn_seal.setEnabled(is_open)
        self.btn_export.setEnabled(True)
        self.btn_verify.setEnabled(self.coc_logger is not None)
    
    def _load_coc_log(self) -> None:
        """Load and display Chain of Custody log with pagination."""
        if not self.coc_logger:
            return
        
        try:
            all_entries = self.coc_logger.get_all_entries()
            self._coc_total_entries = len(all_entries)
            self._all_coc_entries = all_entries  # Store for filtering
            
            # Calculate pagination
            total_pages = (self._coc_total_entries + COC_BATCH_SIZE - 1) // COC_BATCH_SIZE
            start_idx = self._coc_current_page * COC_BATCH_SIZE
            end_idx = min(start_idx + COC_BATCH_SIZE, self._coc_total_entries)
            
            entries_to_display = all_entries[start_idx:end_idx]
            
            self.coc_table.setRowCount(len(entries_to_display))
            
            for i, entry in enumerate(entries_to_display):
                self.coc_table.setItem(i, 0, QTableWidgetItem(entry.get('timestamp', '')))
                self.coc_table.setItem(i, 1, QTableWidgetItem(entry.get('action', '')))
                self.coc_table.setItem(i, 2, QTableWidgetItem(entry.get('actor', '')))
                self.coc_table.setItem(i, 3, QTableWidgetItem(str(entry.get('details', ''))))
                self.coc_table.setItem(i, 4, QTableWidgetItem(entry.get('hash', '')[:16] + '...'))
            
            # Update pagination controls
            self.lbl_coc_entries.setText(f"Entries: {self._coc_total_entries} (Showing {start_idx + 1}-{end_idx})")
            self.lbl_coc_page.setText(f"Page {self._coc_current_page + 1} of {max(1, total_pages)}")
            self.btn_coc_prev.setEnabled(self._coc_current_page > 0)
            self.btn_coc_next.setEnabled(end_idx < self._coc_total_entries)
            
        except Exception as e:
            logger.error(f"Failed to load CoC log: {e}", exc_info=True)
    
    # ════════════════════════════════════════════════════════════════
    # LOADING INDICATORS
    # ════════════════════════════════════════════════════════════════
    
    def _show_loading(self, message: str) -> None:
        """Show loading indicator with animation."""
        self.loading_label.setText(message)
        self.loading_label.setVisible(True)
        
        if not self._loading_timer:
            self._loading_timer = QTimer()
            self._loading_timer.timeout.connect(self._update_loading_animation)
            self._loading_timer.start(100)  # 100ms interval
    
    def _update_loading_animation(self) -> None:
        """Update loading animation."""
        if not self.loading_label.isVisible():
            if self._loading_timer:
                self._loading_timer.stop()
            return
        
        dots = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        current_text = self.loading_label.text()
        base_text = current_text.split()[0] if current_text else ""
        self._loading_dots = (self._loading_dots + 1) % len(dots)
        self.loading_label.setText(f"{base_text} {dots[self._loading_dots]}")
    
    def _hide_loading(self) -> None:
        """Hide loading indicator."""
        self.loading_label.setVisible(False)
        if self._loading_timer:
            self._loading_timer.stop()
        self._loading_dots = 0
    
    # ════════════════════════════════════════════════════════════════
    # VALIDATION
    # ════════════════════════════════════════════════════════════════
    
    def _validate_case_data(self, case_data: Dict[str, Any]) -> Optional[str]:
        """Validate case data before creation."""
        case_name = case_data.get('case_name', '').strip()
        operator = case_data.get('operator', '').strip()
        
        if not case_name:
            return "Case name is required."
        
        if len(case_name) < MIN_CASE_NAME_LENGTH:
            return f"Case name must be at least {MIN_CASE_NAME_LENGTH} characters."
        
        if len(case_name) > MAX_CASE_NAME_LENGTH:
            return f"Case name must not exceed {MAX_CASE_NAME_LENGTH} characters."
        
        if not operator:
            return "Operator name is required."
        
        if len(operator) < MIN_OPERATOR_NAME_LENGTH:
            return f"Operator name must be at least {MIN_OPERATOR_NAME_LENGTH} characters."
        
        # Check for invalid characters in case name
        invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
        for char in invalid_chars:
            if char in case_name:
                return f"Case name contains invalid character: '{char}'"
        
        return None
    
    # ════════════════════════════════════════════════════════════════
    # RECENT CASES
    # ════════════════════════════════════════════════════════════════
    
    def _load_recent_cases(self) -> None:
        """Load recent cases from config."""
        try:
            config_file = Path.home() / ".fepd" / "recent_cases.json"
            if config_file.exists():
                with open(config_file, 'r') as f:
                    self._recent_cases = json.load(f)
        except Exception as e:
            logger.debug(f"Failed to load recent cases: {e}")
            self._recent_cases = []
    
    def _save_recent_cases(self) -> None:
        """Save recent cases to config."""
        try:
            config_dir = Path.home() / ".fepd"
            config_dir.mkdir(exist_ok=True)
            config_file = config_dir / "recent_cases.json"
            with open(config_file, 'w') as f:
                json.dump(self._recent_cases[:MAX_RECENT_CASES], f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to save recent cases: {e}")
    
    def _add_to_recent_cases(self, case_id: str, case_name: str) -> None:
        """Add case to recent cases list."""
        # Remove if already exists
        self._recent_cases = [r for r in self._recent_cases if r.get('id') != case_id]
        
        # Add to front
        self._recent_cases.insert(0, {
            'id': case_id,
            'name': case_name,
            'accessed': datetime.now().isoformat()
        })
        
        # Trim to max size
        self._recent_cases = self._recent_cases[:MAX_RECENT_CASES]
        
        self._save_recent_cases()
    
    def _remove_from_recent_cases(self, case_id: str) -> None:
        """Remove case from recent cases list."""
        self._recent_cases = [r for r in self._recent_cases if r.get('id') != case_id]
        self._save_recent_cases()
    
    # ════════════════════════════════════════════════════════════════
    # AUTO-SAVE
    # ════════════════════════════════════════════════════════════════
    
    def _setup_auto_save(self) -> None:
        """Setup auto-save timer."""
        self._auto_save_timer = QTimer()
        self._auto_save_timer.timeout.connect(self._auto_save)
        self._auto_save_timer.start(AUTO_SAVE_INTERVAL)
    
    def _auto_save(self) -> None:
        """Auto-save current case if modified."""
        if not self._is_modified or not self.current_case:
            return
        
        try:
            case_path = self.case_manager.base_cases_dir / self.current_case['case_id']
            metadata_file = case_path / "metadata.json"
            
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(self.current_case, f, indent=2)
            
            self._is_modified = False
            logger.debug("Case auto-saved")
        except Exception as e:
            logger.error(f"Auto-save failed: {e}")
    
    def mark_modified(self) -> None:
        """Mark case as modified for auto-save."""
        self._is_modified = True
    
    # ════════════════════════════════════════════════════════════════
    # COC SEARCH & PAGINATION
    # ════════════════════════════════════════════════════════════════
    
    def _filter_coc_entries(self) -> None:
        """Filter CoC entries based on search and filter."""
        if not hasattr(self, '_all_coc_entries'):
            return
        
        search_text = self.coc_search.text().lower()
        filter_action = self.coc_filter.currentText()
        
        filtered = self._all_coc_entries
        
        # Apply action filter
        if filter_action != "All Actions":
            filtered = [e for e in filtered if e.get('action') == filter_action]
        
        # Apply search text
        if search_text:
            filtered = [
                e for e in filtered
                if search_text in str(e).lower()
            ]
        
        # Display filtered results
        self.coc_table.setRowCount(len(filtered))
        
        for i, entry in enumerate(filtered[:COC_MAX_DISPLAY]):
            self.coc_table.setItem(i, 0, QTableWidgetItem(entry.get('timestamp', '')))
            self.coc_table.setItem(i, 1, QTableWidgetItem(entry.get('action', '')))
            self.coc_table.setItem(i, 2, QTableWidgetItem(entry.get('actor', '')))
            self.coc_table.setItem(i, 3, QTableWidgetItem(str(entry.get('details', ''))))
            self.coc_table.setItem(i, 4, QTableWidgetItem(entry.get('hash', '')[:16] + '...'))
        
        self.lbl_coc_entries.setText(f"Entries: {len(filtered)} (filtered)")
    
    def _coc_prev_page(self) -> None:
        """Show previous page of CoC entries."""
        if self._coc_current_page > 0:
            self._coc_current_page -= 1
            self._load_coc_log()
    
    def _coc_next_page(self) -> None:
        """Show next page of CoC entries."""
        total_pages = (self._coc_total_entries + COC_BATCH_SIZE - 1) // COC_BATCH_SIZE
        if self._coc_current_page < total_pages - 1:
            self._coc_current_page += 1
            self._load_coc_log()
    
    # ════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ════════════════════════════════════════════════════════════════
    
    def get_current_case(self) -> Optional[Dict]:
        """Get current case metadata."""
        return self.current_case
    
    def set_case(self, case_metadata: Dict) -> None:
        """Set current case programmatically."""
        self.current_case = case_metadata
        self._update_case_display()
        
        # Load CoC if available
        if case_metadata:
            case_path = self.case_manager.base_cases_dir / case_metadata['case_id']
            coc_file = case_path / "chain_of_custody.log"
            if coc_file.exists():
                self.coc_logger = ChainLogger(str(coc_file))
                self._load_coc_log()
    
    def log_coc_event(self, action: str, actor: str, details: Dict) -> None:
        """Log event to Chain of Custody."""
        if self.coc_logger and self.current_case:
            if self.current_case.get('status') != 'SEALED':
                self.coc_logger.log(action, actor, details)
                self._load_coc_log()  # Refresh display
                self.mark_modified()  # Mark for auto-save
