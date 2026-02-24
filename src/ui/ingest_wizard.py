"""
FEPD - Image Ingest Wizard
Multi-step wizard for adding disk images with proper forensic controls

Features:
- Drag-and-drop support
- Multi-step wizard (file selection, timezone, options)
- Ingest module checklist
- Progress tracking with cancel
- Hash verification display
- Acquisition metadata capture
- Forensic disk image extraction (E01/DD support)
"""

import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from PyQt6.QtWidgets import (
    QWizard, QWizardPage, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QComboBox, QCheckBox, QTextEdit,
    QGroupBox, QFileDialog, QProgressBar, QListWidget, QListWidgetItem,
    QWidget, QScrollArea, QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QPalette, QColor

# Import forensic image handling
try:
    from modules.image_handler import DiskImageHandler
    from modules.artifact_extractor import extract_artifacts_from_image
    IMAGE_HANDLER_AVAILABLE = True
except ImportError:
    IMAGE_HANDLER_AVAILABLE = False
    logging.warning("Disk image handling not available (pytsk3/pyewf not installed)")


class ImageSelectionPage(QWizardPage):
    """Step 1: File/Folder selection with drag-drop support."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Select Disk Image or Artifact Folder")
        self.setSubTitle("Choose a forensic image file or a folder containing forensic artifacts. Supports E01, L01, RAW, DD formats, and artifact directories.")
        
        layout = QVBoxLayout()
        
        # Drag-drop area
        self.drop_area = DragDropArea()
        self.drop_area.file_dropped.connect(self._on_file_dropped)
        layout.addWidget(self.drop_area)
        
        # Browse buttons
        browse_layout = QHBoxLayout()
        browse_layout.addStretch()
        self.btn_browse = QPushButton("📂 Browse for Image File...")
        self.btn_browse.clicked.connect(self._browse_image)
        self.btn_browse.setMinimumHeight(40)
        browse_layout.addWidget(self.btn_browse)
        
        self.btn_browse_folder = QPushButton("📁 Browse for Artifact Folder...")
        self.btn_browse_folder.clicked.connect(self._browse_folder)
        self.btn_browse_folder.setMinimumHeight(40)
        browse_layout.addWidget(self.btn_browse_folder)
        browse_layout.addStretch()
        layout.addLayout(browse_layout)
        
        # Selected file display
        file_group = QGroupBox("Selected Image")
        file_layout = QVBoxLayout()
        
        self.lbl_filename = QLabel("No file selected")
        self.lbl_filename.setWordWrap(True)
        file_layout.addWidget(self.lbl_filename)
        
        self.lbl_size = QLabel("")
        file_layout.addWidget(self.lbl_size)
        
        self.lbl_format = QLabel("")
        file_layout.addWidget(self.lbl_format)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        self.setLayout(layout)
        
        # Register field for wizard
        self.registerField("image_path*", self, "imagePath", self.imagePathChanged)
        self._image_path = ""
    
    def _browse_image(self):
        """Open file dialog to browse for image."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Disk Image",
            str(Path.home()),
            "Forensic Images (*.e01 *.E01 *.001 *.raw *.dd *.img *.l01 *.L01);;All Files (*)"
        )
        
        if file_path:
            self._set_image_path(file_path)
    
    def _browse_folder(self):
        """Open file dialog to browse for artifact folder."""
        folder_path = QFileDialog.getExistingDirectory(
            self,
            "Select Artifact Folder",
            str(Path.home()),
            QFileDialog.Option.ShowDirsOnly
        )
        
        if folder_path:
            self._set_image_path(folder_path)
    
    def _on_file_dropped(self, file_path: str):
        """Handle drag-dropped file."""
        self._set_image_path(file_path)
    
    def _set_image_path(self, path: str):
        """Set the selected image path or folder path."""
        self._image_path = path
        path_obj = Path(path)
        
        # Update display
        if path_obj.is_dir():
            # Folder selected
            self.lbl_filename.setText(f"<b>Folder:</b> {path_obj.name}")
            
            # Count files in folder
            file_count = sum(1 for _ in path_obj.rglob('*') if _.is_file())
            self.lbl_size.setText(f"<b>Contains:</b> {file_count} files")
            
            # Detect platform type
            platform_indicators = {
                'windows': ['Windows', 'Prefetch', 'Registry', 'winevt'],
                'macos': ['Library', 'fseventsd', 'diagnostics', 'Safari'],
                'linux': ['var/log', 'etc', 'home'],
                'android': ['android', 'com.android'],
                'ios': ['ios', 'mobile/Library']
            }
            
            detected_platforms = []
            path_str = str(path_obj).lower()
            for platform, indicators in platform_indicators.items():
                if any(ind.lower() in path_str for ind in indicators):
                    detected_platforms.append(platform.upper())
            
            if detected_platforms:
                self.lbl_format.setText(f"<b>Detected Platforms:</b> {', '.join(detected_platforms)}")
            else:
                self.lbl_format.setText(f"<b>Format:</b> Artifact Directory")
        else:
            # File selected
            self.lbl_filename.setText(f"<b>File:</b> {path_obj.name}")
            
            if path_obj.exists():
                size_mb = path_obj.stat().st_size / (1024 * 1024)
                self.lbl_size.setText(f"<b>Size:</b> {size_mb:,.2f} MB")
                
                # Detect format
                ext = path_obj.suffix.lower()
                format_map = {
                    '.e01': 'E01 (Expert Witness Format)',
                    '.001': 'E01 Segmented',
                    '.l01': 'L01 (Logical Evidence File)',
                    '.raw': 'RAW Disk Image',
                    '.dd': 'DD Disk Dump',
                    '.img': 'IMG Disk Image'
                }
                self.lbl_format.setText(f"<b>Format:</b> {format_map.get(ext, 'Unknown')}")
        
        self.imagePathChanged.emit()
        self.completeChanged.emit()
    
    # Custom property for wizard field
    imagePathChanged = pyqtSignal()
    
    def imagePath(self) -> str:
        return self._image_path
    
    def isComplete(self) -> bool:
        """Wizard can proceed if image path is set."""
        return bool(self._image_path and Path(self._image_path).exists())


class DragDropArea(QFrame):
    """Drag-and-drop area for image files."""
    
    file_dropped = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Sunken)
        self.setLineWidth(2)
        self.setMinimumHeight(150)
        
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        icon_label = QLabel("📦")
        icon_label.setStyleSheet("font-size: 48px;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)
        
        text_label = QLabel("Drag and Drop Disk Image or Artifact Folder Here")
        text_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(text_label)
        
        hint_label = QLabel("Supports: E01, L01, RAW, DD, IMG formats or Artifact Directories")
        hint_label.setStyleSheet("font-size: 12px; color: #888;")
        hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(hint_label)
        
        self.setLayout(layout)
        
        # Style for drag-over
        self._default_style = "background-color: #2c3e50; border: 2px dashed #7f8c8d;"
        self._hover_style = "background-color: #34495e; border: 2px dashed #3498db;"
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
            file_path = urls[0].toLocalFile()
            self.file_dropped.emit(file_path)

        
class TimezoneOptionsPage(QWizardPage):
    """Step 2: Timezone and acquisition options."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Timezone & Options")
        self.setSubTitle("Configure timezone and acquisition parameters for proper timestamp interpretation.")
        
        layout = QVBoxLayout()
        
        # Timezone selection
        tz_group = QGroupBox("Timezone Configuration")
        tz_layout = QVBoxLayout()
        
        tz_layout.addWidget(QLabel("Select the timezone of the original system:"))
        self.cmb_timezone = QComboBox()
        self.cmb_timezone.addItems([
            "UTC (Universal Time)",
            "Local System Time",
            "EST (UTC-5)",
            "CST (UTC-6)",
            "MST (UTC-7)",
            "PST (UTC-8)",
            "CET (UTC+1)",
            "GMT (UTC+0)",
        ])
        self.cmb_timezone.setCurrentIndex(0)  # Default to UTC
        tz_layout.addWidget(self.cmb_timezone)
        
        tz_group.setLayout(tz_layout)
        layout.addWidget(tz_group)
        
        # Acquisition options
        options_group = QGroupBox("Acquisition Options")
        options_layout = QVBoxLayout()
        
        self.chk_verify_hash = QCheckBox("Verify image hash on load (recommended)")
        self.chk_verify_hash.setChecked(True)
        self.chk_verify_hash.setToolTip("Verify MD5/SHA-256 hash to ensure image integrity")
        options_layout.addWidget(self.chk_verify_hash)
        
        self.chk_readonly = QCheckBox("Enforce read-only mode (forensic standard)")
        self.chk_readonly.setChecked(True)
        self.chk_readonly.setToolTip("Prevent any writes to the source image")
        options_layout.addWidget(self.chk_readonly)
        
        self.chk_orphan_search = QCheckBox("Search for orphan files (unallocated)")
        self.chk_orphan_search.setChecked(True)
        self.chk_orphan_search.setToolTip("Find files in unallocated space - slower but more thorough")
        options_layout.addWidget(self.chk_orphan_search)
        
        self.chk_carve_deleted = QCheckBox("Carve deleted files from unallocated space")
        self.chk_carve_deleted.setChecked(False)
        self.chk_carve_deleted.setToolTip("File carving is time-intensive but recovers more evidence")
        options_layout.addWidget(self.chk_carve_deleted)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Evidence metadata
        metadata_group = QGroupBox("Evidence Metadata (Optional)")
        metadata_layout = QVBoxLayout()
        
        metadata_layout.addWidget(QLabel("Evidence Number:"))
        self.txt_evidence_number = QLineEdit()
        self.txt_evidence_number.setPlaceholderText("e.g., EVID-2025-001")
        metadata_layout.addWidget(self.txt_evidence_number)
        
        metadata_layout.addWidget(QLabel("Examiner Name:"))
        self.txt_examiner = QLineEdit()
        self.txt_examiner.setPlaceholderText("e.g., John Doe")
        metadata_layout.addWidget(self.txt_examiner)
        
        metadata_layout.addWidget(QLabel("Notes:"))
        self.txt_notes = QTextEdit()
        self.txt_notes.setPlaceholderText("Additional acquisition notes...")
        self.txt_notes.setMaximumHeight(80)
        metadata_layout.addWidget(self.txt_notes)
        
        metadata_group.setLayout(metadata_layout)
        layout.addWidget(metadata_group)
        
        layout.addStretch()
        self.setLayout(layout)


class IngestModulesPage(QWizardPage):
    """Step 3: Select ingest modules to run."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Select Ingest Modules")
        self.setSubTitle("Choose which analysis modules to run during ingestion. Customize based on investigation needs.")
        
        layout = QVBoxLayout()
        
        info_label = QLabel(
            "✓ Check modules to enable\n"
            "Hover over each module for description"
        )
        info_label.setStyleSheet("font-size: 12px; color: #888; margin-bottom: 10px;")
        layout.addWidget(info_label)
        
        # Scrollable module list
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        modules_widget = QWidget()
        modules_layout = QVBoxLayout()
        modules_layout.setSpacing(5)
        
        # Define ingest modules with descriptions
        self.modules = [
            {
                'name': 'File System Analysis',
                'key': 'filesystem',
                'description': 'Parse file system metadata, timestamps, and directory structure',
                'enabled': True,
                'category': 'Core'
            },
            {
                'name': 'Hash Lookup (NSRL)',
                'key': 'hash_lookup',
                'description': 'Identify known files using NSRL hash database',
                'enabled': True,
                'category': 'Core'
            },
            {
                'name': 'Registry Parser',
                'key': 'registry',
                'description': 'Extract Windows Registry artifacts (autoruns, USB, recent docs)',
                'enabled': True,
                'category': 'Core'
            },
            {
                'name': 'MFT Parser',
                'key': 'mft',
                'description': 'Parse NTFS Master File Table for complete file timeline',
                'enabled': True,
                'category': 'Core'
            },
            {
                'name': 'Browser History',
                'key': 'browser',
                'description': 'Extract web history, downloads, cookies (Chrome, Firefox, Edge)',
                'enabled': True,
                'category': 'Internet'
            },
            {
                'name': 'Email Parser',
                'key': 'email',
                'description': 'Parse email stores (PST, OST, MBOX, EML)',
                'enabled': True,
                'category': 'Communication'
            },
            {
                'name': 'Chat & Messaging',
                'key': 'chat',
                'description': 'Extract chat logs (WhatsApp, Telegram, Signal)',
                'enabled': False,
                'category': 'Communication'
            },
            {
                'name': 'EXIF Metadata',
                'key': 'exif',
                'description': 'Extract photo/video metadata (GPS, timestamps, device info)',
                'enabled': True,
                'category': 'Media'
            },
            {
                'name': 'File Carving',
                'key': 'carving',
                'description': 'Recover deleted files from unallocated space (SLOW)',
                'enabled': False,
                'category': 'Recovery'
            },
            {
                'name': 'Deleted File Recovery',
                'key': 'deleted',
                'description': 'Recover files marked as deleted in file system',
                'enabled': True,
                'category': 'Recovery'
            },
            {
                'name': 'Keyword Search',
                'key': 'keyword',
                'description': 'Search disk for keywords (configure in settings)',
                'enabled': False,
                'category': 'Search'
            },
            {
                'name': 'Encrypted File Detection',
                'key': 'encryption',
                'description': 'Identify encrypted files and containers',
                'enabled': True,
                'category': 'Analysis'
            },
            {
                'name': 'Malware Signature Scan',
                'key': 'malware',
                'description': 'Scan for known malware signatures (requires signature DB)',
                'enabled': False,
                'category': 'Security'
            },
        ]
        
        self.module_checkboxes = {}
        
        # Group modules by category
        categories = {}
        for module in self.modules:
            cat = module['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(module)
        
        # Create grouped checkboxes
        for category, cat_modules in categories.items():
            cat_group = QGroupBox(f"📂 {category} Modules")
            cat_layout = QVBoxLayout()
            cat_layout.setSpacing(3)
            
            for module in cat_modules:
                chk = QCheckBox(module['name'])
                chk.setChecked(module['enabled'])
                chk.setToolTip(module['description'])
                self.module_checkboxes[module['key']] = chk
                cat_layout.addWidget(chk)
            
            cat_group.setLayout(cat_layout)
            modules_layout.addWidget(cat_group)
        
        modules_widget.setLayout(modules_layout)
        scroll.setWidget(modules_widget)
        layout.addWidget(scroll)
        
        # Quick select buttons
        buttons_layout = QHBoxLayout()
        
        btn_select_all = QPushButton("✓ Select All")
        btn_select_all.clicked.connect(self._select_all)
        buttons_layout.addWidget(btn_select_all)
        
        btn_select_recommended = QPushButton("⭐ Recommended Only")
        btn_select_recommended.clicked.connect(self._select_recommended)
        buttons_layout.addWidget(btn_select_recommended)
        
        btn_deselect_all = QPushButton("✗ Deselect All")
        btn_deselect_all.clicked.connect(self._deselect_all)
        buttons_layout.addWidget(btn_deselect_all)
        
        layout.addLayout(buttons_layout)
        
        self.setLayout(layout)
    
    def _select_all(self):
        """Select all modules."""
        for chk in self.module_checkboxes.values():
            chk.setChecked(True)
    
    def _deselect_all(self):
        """Deselect all modules."""
        for chk in self.module_checkboxes.values():
            chk.setChecked(False)
    
    def _select_recommended(self):
        """Select recommended modules only."""
        recommended = ['filesystem', 'hash_lookup', 'registry', 'mft', 'browser', 'email', 'exif', 'deleted', 'encryption']
        for key, chk in self.module_checkboxes.items():
            chk.setChecked(key in recommended)
    
    def get_selected_modules(self) -> List[str]:
        """Get list of selected module keys."""
        return [key for key, chk in self.module_checkboxes.items() if chk.isChecked()]


class IngestProgressPage(QWizardPage):
    """Step 4: Progress tracking with live updates."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Ingesting Disk Image")
        self.setSubTitle("Processing image and running selected modules. This may take several minutes to hours depending on image size.")
        
        layout = QVBoxLayout()
        
        # Global progress
        layout.addWidget(QLabel("<b>Overall Progress:</b>"))
        self.progress_global = QProgressBar()
        self.progress_global.setMinimumHeight(30)
        layout.addWidget(self.progress_global)
        
        self.lbl_global_status = QLabel("Preparing...")
        layout.addWidget(self.lbl_global_status)
        
        layout.addSpacing(20)
        
        # Module-specific progress table
        layout.addWidget(QLabel("<b>Module Progress:</b>"))
        
        self.table_progress = QTableWidget(0, 3)
        self.table_progress.setHorizontalHeaderLabels(["Module", "Status", "Progress"])
        self.table_progress.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_progress.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_progress.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table_progress.horizontalHeader().resizeSection(2, 150)
        self.table_progress.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_progress.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table_progress.itemClicked.connect(self._on_module_clicked)
        layout.addWidget(self.table_progress)
        
        # Detailed log
        layout.addWidget(QLabel("<b>Detailed Log:</b>"))
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setMaximumHeight(150)
        layout.addWidget(self.txt_log)
        
        # Cancel button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        self.btn_cancel = QPushButton("⏹ Cancel Ingestion")
        self.btn_cancel.clicked.connect(self._cancel_ingestion)
        self.btn_cancel.setStyleSheet("background-color: #e74c3c; color: white;")
        button_layout.addWidget(self.btn_cancel)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        self._is_cancelled = False
    
    def initialize_modules(self, modules: List[str]):
        """Initialize progress table with selected modules."""
        self.table_progress.setRowCount(len(modules))
        
        for i, module_key in enumerate(modules):
            # Module name
            item_name = QTableWidgetItem(module_key.replace('_', ' ').title())
            item_name.setFlags(item_name.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table_progress.setItem(i, 0, item_name)
            
            # Status
            item_status = QTableWidgetItem("⏳ Pending")
            item_status.setFlags(item_status.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table_progress.setItem(i, 1, item_status)
            
            # Progress
            progress_widget = QProgressBar()
            progress_widget.setMinimum(0)
            progress_widget.setMaximum(100)
            progress_widget.setValue(0)
            self.table_progress.setCellWidget(i, 2, progress_widget)
    
    def update_module_progress(self, module_index: int, status: str, progress: int):
        """Update specific module progress."""
        if module_index < self.table_progress.rowCount():
            # Update status
            status_item = self.table_progress.item(module_index, 1)
            if status_item:
                status_item.setText(status)
            
            # Update progress bar
            progress_widget = self.table_progress.cellWidget(module_index, 2)
            if progress_widget:
                progress_widget.setValue(progress)
    
    def update_global_progress(self, progress: int, status: str):
        """Update global progress."""
        self.progress_global.setValue(progress)
        self.lbl_global_status.setText(status)
    
    def add_log(self, message: str):
        """Add message to log."""
        self.txt_log.append(message)
        # Auto-scroll to bottom
        self.txt_log.verticalScrollBar().setValue(
            self.txt_log.verticalScrollBar().maximum()
        )
    
    def _on_module_clicked(self, item):
        """Handle module row click - show detailed info."""
        row = item.row()
        module_name = self.table_progress.item(row, 0).text()
        self.add_log(f"\n📋 Selected module: {module_name}")
    
    def _cancel_ingestion(self):
        """Cancel the ingestion process."""
        self._is_cancelled = True
        self.btn_cancel.setEnabled(False)
        self.add_log("\n🛑 Cancellation requested - stopping modules gracefully...")
        self.lbl_global_status.setText("Cancelling...")
    
    def is_cancelled(self) -> bool:
        """Check if cancellation was requested."""
        return self._is_cancelled


class ImageExtractionWorker(QThread):
    """Worker thread for extracting artifacts from disk images."""
    
    progress_updated = pyqtSignal(str, int)  # (message, progress_percentage)
    extraction_complete = pyqtSignal(dict)   # (results)
    extraction_error = pyqtSignal(str)       # (error_message)
    
    def __init__(self, image_path: str, output_dir: str, verify_hash: bool = True):
        super().__init__()
        self.image_path = image_path
        self.output_dir = output_dir
        self.verify_hash = verify_hash
        self._cancelled = False
    
    def run(self):
        """Run the extraction process."""
        try:
            if not IMAGE_HANDLER_AVAILABLE:
                self.extraction_error.emit("Disk image handler not available. Install pytsk3 and pyewf.")
                return
            
            self.progress_updated.emit("Opening disk image...", 5)
            
            # Progress callback for real-time updates
            def progress_callback(message: str, percentage: int):
                if not self._cancelled:
                    self.progress_updated.emit(message, percentage)
            
            # Use the artifact extractor for automated extraction with progress callback
            results = extract_artifacts_from_image(
                image_path=self.image_path,
                output_dir=self.output_dir,
                verify_hash=self.verify_hash,
                progress_callback=progress_callback
            )
            
            if self._cancelled:
                self.extraction_error.emit("Extraction cancelled by user")
                return
            
            self.progress_updated.emit("Extraction complete!", 100)
            self.extraction_complete.emit(results)
            
        except Exception as e:
            import traceback
            error_msg = f"Extraction error: {str(e)}\n{traceback.format_exc()}"
            self.extraction_error.emit(error_msg)
    
    def cancel(self):
        """Cancel the extraction."""
        self._cancelled = True


class ImageIngestWizard(QWizard):
    """
    Multi-step wizard for ingesting disk images.
    
    Steps:
    1. File Selection (with drag-drop)
    2. Timezone & Options
    3. Ingest Modules Selection
    4. Progress Tracking
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.setWindowTitle("Image Ingest Wizard")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setOption(QWizard.WizardOption.HaveHelpButton, False)
        self.setMinimumSize(800, 600)
        
        # Add pages
        self.page_selection = ImageSelectionPage()
        self.page_options = TimezoneOptionsPage()
        self.page_modules = IngestModulesPage()
        self.page_progress = IngestProgressPage()
        
        self.addPage(self.page_selection)
        self.addPage(self.page_options)
        self.addPage(self.page_modules)
        self.addPage(self.page_progress)
        
        # Connect finish button
        self.button(QWizard.WizardButton.FinishButton).clicked.connect(self._on_finish)
    
    def _on_finish(self):
        """Handle wizard completion."""
        # This will be overridden by the parent to start actual ingestion
        pass
    
    def get_ingestion_config(self) -> Dict[str, Any]:
        """Get the complete ingestion configuration."""
        return {
            'image_path': self.page_selection.imagePath(),
            'timezone': self.page_options.cmb_timezone.currentText(),
            'verify_hash': self.page_options.chk_verify_hash.isChecked(),
            'readonly': self.page_options.chk_readonly.isChecked(),
            'orphan_search': self.page_options.chk_orphan_search.isChecked(),
            'carve_deleted': self.page_options.chk_carve_deleted.isChecked(),
            'evidence_number': self.page_options.txt_evidence_number.text(),
            'examiner': self.page_options.txt_examiner.text(),
            'notes': self.page_options.txt_notes.toPlainText(),
            'selected_modules': self.page_modules.get_selected_modules(),
        }
