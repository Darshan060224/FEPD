"""
FEPD - Multi-Evidence Upload Dialog
Advanced evidence selection supporting multiple related evidence files.

Features:
- Select multiple evidence files (disk + memory)
- Automatic relationship detection
- Combined processing option
- Evidence grouping preview

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from typing import List, Optional, Dict
from dataclasses import dataclass, field
from enum import Enum

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QRadioButton, QButtonGroup, QGroupBox,
    QListWidget, QListWidgetItem, QFileDialog, QFrame,
    QMessageBox, QProgressBar, QTreeWidget, QTreeWidgetItem,
    QSplitter, QWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QComboBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QIcon


class EvidenceSourceCategory(Enum):
    """Categories of evidence sources."""
    DISK = "disk"
    MEMORY = "memory"
    NETWORK = "network"
    LOG = "log"
    MOBILE = "mobile"


@dataclass
class EvidenceItem:
    """Represents a single evidence item."""
    path: Path
    category: EvidenceSourceCategory
    is_multipart: bool = False
    related_parts: List[Path] = field(default_factory=list)


@dataclass 
class MultiEvidenceSelection:
    """Selection result with multiple evidence sources."""
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    case_name: str = ""
    operator: str = ""
    combine_related: bool = True  # Whether to combine related evidence
    detected_relationships: List[Dict] = field(default_factory=list)


class MultiEvidenceUploadDialog(QDialog):
    """
    Advanced dialog for selecting multiple related evidence files.
    
    Supports:
    - Disk images (E01/DD/RAW/IMG)
    - Memory dumps (MEM/DMP)
    - Network captures (PCAP)
    - Log files
    - Combinations of above
    """
    
    # Signal emitted when evidence is selected
    evidence_selected = pyqtSignal(object)  # MultiEvidenceSelection
    
    def __init__(self, parent=None, case_name: str = "", operator: str = "SYSTEM"):
        super().__init__(parent)
        self.case_name = case_name
        self.operator = operator
        self.evidence_items: List[EvidenceItem] = []
        self.detected_relationships: List[Dict] = []
        self.logger = logging.getLogger(__name__)
        
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Setup the dialog UI."""
        self.setWindowTitle("Upload Multiple Evidence Files")
        self.setMinimumSize(900, 700)
        self.setModal(True)
        
        layout = QVBoxLayout()
        layout.setSpacing(10)
        
        # Header
        header_layout = QHBoxLayout()
        header = QLabel("📁 Upload Multiple Evidence Files")
        header.setStyleSheet("font-size: 20px; font-weight: bold;")
        header_layout.addWidget(header)
        header_layout.addStretch()
        
        # Help button
        btn_help = QPushButton("❓ Help")
        btn_help.clicked.connect(self._show_help)
        header_layout.addWidget(btn_help)
        layout.addLayout(header_layout)
        
        # Info label
        info = QLabel(
            "Select multiple evidence files to analyze together. "
            "FEPD will automatically detect relationships and combine related data."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #888; padding: 5px;")
        layout.addWidget(info)
        
        # Main content splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Add evidence
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        
        # Add buttons
        btn_frame = QFrame()
        btn_layout = QVBoxLayout()
        
        self.btn_add_disk = QPushButton("💿 Add Disk Image(s)")
        self.btn_add_disk.setMinimumHeight(40)
        self.btn_add_disk.clicked.connect(lambda: self._add_evidence(EvidenceSourceCategory.DISK))
        btn_layout.addWidget(self.btn_add_disk)
        
        self.btn_add_memory = QPushButton("🧠 Add Memory Dump")
        self.btn_add_memory.setMinimumHeight(40)
        self.btn_add_memory.clicked.connect(lambda: self._add_evidence(EvidenceSourceCategory.MEMORY))
        btn_layout.addWidget(self.btn_add_memory)
        
        self.btn_add_network = QPushButton("🌐 Add Network Capture")
        self.btn_add_network.setMinimumHeight(40)
        self.btn_add_network.clicked.connect(lambda: self._add_evidence(EvidenceSourceCategory.NETWORK))
        btn_layout.addWidget(self.btn_add_network)
        
        self.btn_add_log = QPushButton("📝 Add Log Files")
        self.btn_add_log.setMinimumHeight(40)
        self.btn_add_log.clicked.connect(lambda: self._add_evidence(EvidenceSourceCategory.LOG))
        btn_layout.addWidget(self.btn_add_log)
        
        self.btn_add_mobile = QPushButton("📱 Add Mobile Backup")
        self.btn_add_mobile.setMinimumHeight(40)
        self.btn_add_mobile.clicked.connect(lambda: self._add_evidence(EvidenceSourceCategory.MOBILE))
        btn_layout.addWidget(self.btn_add_mobile)
        
        btn_layout.addStretch()
        btn_frame.setLayout(btn_layout)
        left_layout.addWidget(btn_frame)
        
        left_panel.setLayout(left_layout)
        splitter.addWidget(left_panel)
        
        # Right panel - Evidence list and relationships
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        
        # Evidence table
        evidence_group = QGroupBox("Selected Evidence")
        evidence_layout = QVBoxLayout()
        
        self.evidence_table = QTableWidget()
        self.evidence_table.setColumnCount(5)
        self.evidence_table.setHorizontalHeaderLabels([
            "Type", "File Name", "Size", "Parts", "Actions"
        ])
        self.evidence_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.evidence_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.evidence_table.setAlternatingRowColors(True)
        evidence_layout.addWidget(self.evidence_table)
        
        # Evidence actions
        ev_actions = QHBoxLayout()
        self.btn_remove_selected = QPushButton("🗑️ Remove Selected")
        self.btn_remove_selected.clicked.connect(self._remove_selected)
        self.btn_remove_selected.setEnabled(False)
        ev_actions.addWidget(self.btn_remove_selected)
        
        self.btn_clear_all = QPushButton("🧹 Clear All")
        self.btn_clear_all.clicked.connect(self._clear_all)
        self.btn_clear_all.setEnabled(False)
        ev_actions.addWidget(self.btn_clear_all)
        
        ev_actions.addStretch()
        
        self.lbl_total = QLabel("0 evidence sources")
        ev_actions.addWidget(self.lbl_total)
        
        evidence_layout.addLayout(ev_actions)
        evidence_group.setLayout(evidence_layout)
        right_layout.addWidget(evidence_group)
        
        # Relationships preview
        rel_group = QGroupBox("Detected Relationships")
        rel_layout = QVBoxLayout()
        
        self.rel_tree = QTreeWidget()
        self.rel_tree.setHeaderLabels(["Relationship", "Confidence", "Description"])
        self.rel_tree.setAlternatingRowColors(True)
        rel_layout.addWidget(self.rel_tree)
        
        # Analyze button
        self.btn_analyze = QPushButton("🔍 Analyze Relationships")
        self.btn_analyze.clicked.connect(self._analyze_relationships)
        self.btn_analyze.setEnabled(False)
        rel_layout.addWidget(self.btn_analyze)
        
        rel_group.setLayout(rel_layout)
        right_layout.addWidget(rel_group)
        
        right_panel.setLayout(right_layout)
        splitter.addWidget(right_panel)
        
        # Set splitter sizes
        splitter.setSizes([250, 650])
        layout.addWidget(splitter)
        
        # Options
        options_group = QGroupBox("Processing Options")
        options_layout = QHBoxLayout()
        
        self.chk_combine = QCheckBox("🔗 Combine related evidence data")
        self.chk_combine.setChecked(True)
        self.chk_combine.setToolTip(
            "When enabled, data from related evidence sources will be combined\n"
            "into unified views for all tabs (timeline, artifacts, etc.)"
        )
        options_layout.addWidget(self.chk_combine)
        
        self.chk_cross_ref = QCheckBox("🔀 Cross-reference events")
        self.chk_cross_ref.setChecked(True)
        self.chk_cross_ref.setToolTip(
            "Identify events that correlate across different evidence sources"
        )
        options_layout.addWidget(self.chk_cross_ref)
        
        options_layout.addStretch()
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Validation status
        self.validation_frame = QFrame()
        self.validation_frame.setFrameStyle(QFrame.Shape.Box)
        validation_layout = QVBoxLayout()
        
        self.lbl_validation = QLabel("ℹ️ Add evidence files to continue")
        self.lbl_validation.setWordWrap(True)
        self.lbl_validation.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_validation.setStyleSheet("padding: 10px;")
        validation_layout.addWidget(self.lbl_validation)
        
        self.validation_frame.setLayout(validation_layout)
        layout.addWidget(self.validation_frame)
        
        # Dialog buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setMinimumHeight(40)
        self.btn_cancel.clicked.connect(self.reject)
        buttons_layout.addWidget(self.btn_cancel)
        
        self.btn_upload = QPushButton("✅ Process Evidence")
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
        self._update_validation()
    
    def _connect_signals(self):
        """Connect UI signals."""
        self.evidence_table.itemSelectionChanged.connect(self._on_selection_changed)
    
    def _add_evidence(self, category: EvidenceSourceCategory):
        """Add evidence files of specified category."""
        # Set file filters based on category
        filters = {
            EvidenceSourceCategory.DISK: (
                "Disk Images (*.e01 *.E01 *.e02 *.E02 *.dd *.DD *.raw *.RAW *.img *.IMG *.aff *.AFF *.vmdk *.vhd);;"
                "All Files (*)"
            ),
            EvidenceSourceCategory.MEMORY: (
                "Memory Dumps (*.mem *.MEM *.dmp *.DMP *.raw *.RAW *.vmem);;"
                "All Files (*)"
            ),
            EvidenceSourceCategory.NETWORK: (
                "Network Captures (*.pcap *.PCAP *.pcapng *.cap);;"
                "All Files (*)"
            ),
            EvidenceSourceCategory.LOG: (
                "Log Files (*.log *.LOG *.evtx *.EVTX *.evt *.txt *.csv *.json);;"
                "All Files (*)"
            ),
            EvidenceSourceCategory.MOBILE: (
                "Mobile Backups (*.tar *.ab *.backup *.ufed);;"
                "All Files (*)"
            )
        }
        
        titles = {
            EvidenceSourceCategory.DISK: "Select Disk Image(s)",
            EvidenceSourceCategory.MEMORY: "Select Memory Dump",
            EvidenceSourceCategory.NETWORK: "Select Network Capture",
            EvidenceSourceCategory.LOG: "Select Log File(s)",
            EvidenceSourceCategory.MOBILE: "Select Mobile Backup"
        }
        
        # Multi-select for disk and logs
        if category in [EvidenceSourceCategory.DISK, EvidenceSourceCategory.LOG]:
            file_paths, _ = QFileDialog.getOpenFileNames(
                self,
                titles[category],
                str(Path.home()),
                filters[category]
            )
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                titles[category],
                str(Path.home()),
                filters[category]
            )
            file_paths = [file_path] if file_path else []
        
        if file_paths:
            # Check for multi-part images
            if category == EvidenceSourceCategory.DISK:
                self._process_disk_files([Path(p) for p in file_paths])
            else:
                for path in file_paths:
                    self._add_evidence_item(Path(path), category)
            
            self._update_table()
            self._update_validation()
    
    def _process_disk_files(self, paths: List[Path]):
        """Process disk image files, detecting multi-part sets."""
        import re
        
        # Group E01 files by base name
        e01_pattern = re.compile(r'^(.+)\.E(\d{2})$', re.IGNORECASE)
        groups: Dict[str, List[Path]] = {}
        other_files: List[Path] = []
        
        for path in paths:
            match = e01_pattern.match(path.name)
            if match:
                base = match.group(1)
                if base not in groups:
                    groups[base] = []
                groups[base].append(path)
            else:
                other_files.append(path)
        
        # Add multi-part sets
        for base_name, group_paths in groups.items():
            if len(group_paths) > 1:
                # Multi-part set
                sorted_paths = sorted(group_paths, key=lambda p: p.name)
                item = EvidenceItem(
                    path=sorted_paths[0],
                    category=EvidenceSourceCategory.DISK,
                    is_multipart=True,
                    related_parts=sorted_paths[1:]
                )
                self.evidence_items.append(item)
            else:
                # Single E01
                self._add_evidence_item(group_paths[0], EvidenceSourceCategory.DISK)
        
        # Add other disk files
        for path in other_files:
            self._add_evidence_item(path, EvidenceSourceCategory.DISK)
    
    def _add_evidence_item(self, path: Path, category: EvidenceSourceCategory):
        """Add a single evidence item."""
        # Check for duplicates
        for item in self.evidence_items:
            if item.path == path:
                return
        
        item = EvidenceItem(
            path=path,
            category=category,
            is_multipart=False
        )
        self.evidence_items.append(item)
    
    def _update_table(self):
        """Update the evidence table."""
        self.evidence_table.setRowCount(len(self.evidence_items))
        
        category_icons = {
            EvidenceSourceCategory.DISK: "💿",
            EvidenceSourceCategory.MEMORY: "🧠",
            EvidenceSourceCategory.NETWORK: "🌐",
            EvidenceSourceCategory.LOG: "📝",
            EvidenceSourceCategory.MOBILE: "📱"
        }
        
        for row, item in enumerate(self.evidence_items):
            # Type
            type_item = QTableWidgetItem(f"{category_icons.get(item.category, '📄')} {item.category.value.title()}")
            self.evidence_table.setItem(row, 0, type_item)
            
            # File name
            name_item = QTableWidgetItem(item.path.name)
            self.evidence_table.setItem(row, 1, name_item)
            
            # Size
            try:
                size = item.path.stat().st_size
                if item.is_multipart:
                    for part in item.related_parts:
                        size += part.stat().st_size
                size_str = self._format_size(size)
            except:
                size_str = "N/A"
            size_item = QTableWidgetItem(size_str)
            self.evidence_table.setItem(row, 2, size_item)
            
            # Parts
            if item.is_multipart:
                parts_str = f"{1 + len(item.related_parts)} parts"
            else:
                parts_str = "Single"
            parts_item = QTableWidgetItem(parts_str)
            self.evidence_table.setItem(row, 3, parts_item)
            
            # Actions (remove button)
            btn_remove = QPushButton("🗑️")
            btn_remove.setFixedWidth(40)
            btn_remove.clicked.connect(lambda checked, r=row: self._remove_row(r))
            self.evidence_table.setCellWidget(row, 4, btn_remove)
        
        # Update counts
        self.lbl_total.setText(f"{len(self.evidence_items)} evidence source(s)")
        self.btn_clear_all.setEnabled(len(self.evidence_items) > 0)
        self.btn_analyze.setEnabled(len(self.evidence_items) > 1)
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size."""
        if size_bytes >= 1024 * 1024 * 1024:
            return f"{size_bytes / (1024*1024*1024):.2f} GB"
        elif size_bytes >= 1024 * 1024:
            return f"{size_bytes / (1024*1024):.2f} MB"
        elif size_bytes >= 1024:
            return f"{size_bytes / 1024:.2f} KB"
        return f"{size_bytes} bytes"
    
    def _remove_row(self, row: int):
        """Remove evidence item at row."""
        if 0 <= row < len(self.evidence_items):
            del self.evidence_items[row]
            self._update_table()
            self._update_validation()
            self.rel_tree.clear()
            self.detected_relationships = []
    
    def _remove_selected(self):
        """Remove selected evidence items."""
        selected_rows = set(item.row() for item in self.evidence_table.selectedItems())
        for row in sorted(selected_rows, reverse=True):
            if 0 <= row < len(self.evidence_items):
                del self.evidence_items[row]
        
        self._update_table()
        self._update_validation()
        self.rel_tree.clear()
        self.detected_relationships = []
    
    def _clear_all(self):
        """Clear all evidence items."""
        self.evidence_items = []
        self._update_table()
        self._update_validation()
        self.rel_tree.clear()
        self.detected_relationships = []
    
    def _on_selection_changed(self):
        """Handle table selection change."""
        has_selection = len(self.evidence_table.selectedItems()) > 0
        self.btn_remove_selected.setEnabled(has_selection)
    
    def _analyze_relationships(self):
        """Analyze relationships between evidence items."""
        if len(self.evidence_items) < 2:
            QMessageBox.information(
                self,
                "Analysis",
                "Need at least 2 evidence sources to analyze relationships."
            )
            return
        
        try:
            from src.core.evidence_relationship_analyzer import (
                EvidenceRelationshipAnalyzer,
                EvidenceRelationType
            )
            
            # Collect all paths
            all_paths = []
            for item in self.evidence_items:
                all_paths.append(item.path)
                all_paths.extend(item.related_parts)
            
            # Analyze
            analyzer = EvidenceRelationshipAnalyzer()
            combined_set = analyzer.analyze_evidence_set(all_paths, extract_metadata=True)
            
            # Update relationships
            self.detected_relationships = [
                {
                    'source': r.source_id,
                    'target': r.target_id,
                    'type': r.relation_type.value,
                    'confidence': r.confidence,
                    'factors': r.correlation_factors,
                    'description': r.description
                }
                for r in combined_set.relationships
            ]
            
            # Update tree
            self._update_relationship_tree()
            
            # Show results
            if self.detected_relationships:
                QMessageBox.information(
                    self,
                    "Relationships Detected",
                    f"Found {len(self.detected_relationships)} relationship(s) between evidence sources.\n\n"
                    "Data from related sources will be combined for comprehensive analysis."
                )
            else:
                QMessageBox.information(
                    self,
                    "No Relationships",
                    "No automatic relationships detected between evidence sources.\n\n"
                    "Evidence will still be processed together if 'Combine related evidence' is enabled."
                )
                
        except Exception as e:
            self.logger.error(f"Relationship analysis failed: {e}")
            QMessageBox.warning(
                self,
                "Analysis Error",
                f"Failed to analyze relationships: {str(e)}"
            )
    
    def _update_relationship_tree(self):
        """Update the relationship tree widget."""
        self.rel_tree.clear()
        
        type_icons = {
            'same_device': '🔗',
            'same_user': '👤',
            'timeline_overlap': '⏰',
            'multipart_set': '📦',
            'network_related': '🌐',
            'same_case': '📁'
        }
        
        for rel in self.detected_relationships:
            rel_type = rel.get('type', 'unknown')
            icon = type_icons.get(rel_type, '🔹')
            
            item = QTreeWidgetItem([
                f"{icon} {rel_type.replace('_', ' ').title()}",
                f"{rel.get('confidence', 0) * 100:.0f}%",
                rel.get('description', '')
            ])
            
            # Add correlation factors as children
            for factor in rel.get('factors', []):
                child = QTreeWidgetItem(['', '', f"• {factor}"])
                item.addChild(child)
            
            self.rel_tree.addTopLevelItem(item)
        
        self.rel_tree.expandAll()
    
    def _update_validation(self):
        """Update validation status."""
        if not self.evidence_items:
            self._set_validation_status(
                "ℹ️ Add evidence files to continue",
                "info"
            )
            self.btn_upload.setEnabled(False)
            return
        
        # Check all files exist
        for item in self.evidence_items:
            if not item.path.exists():
                self._set_validation_status(
                    f"❌ File not found: {item.path.name}",
                    "error"
                )
                self.btn_upload.setEnabled(False)
                return
            
            for part in item.related_parts:
                if not part.exists():
                    self._set_validation_status(
                        f"❌ Part file not found: {part.name}",
                        "error"
                    )
                    self.btn_upload.setEnabled(False)
                    return
        
        # Calculate total size
        total_size = 0
        for item in self.evidence_items:
            try:
                total_size += item.path.stat().st_size
                for part in item.related_parts:
                    total_size += part.stat().st_size
            except:
                pass
        
        # Check for mixed types
        categories = set(item.category for item in self.evidence_items)
        
        if len(categories) > 1:
            cat_str = ', '.join(c.value.title() for c in categories)
            self._set_validation_status(
                f"✅ Multi-source evidence ready\n"
                f"{len(self.evidence_items)} sources ({cat_str})\n"
                f"Total: {self._format_size(total_size)}",
                "success"
            )
        else:
            self._set_validation_status(
                f"✅ Evidence ready for processing\n"
                f"{len(self.evidence_items)} source(s) | {self._format_size(total_size)}",
                "success"
            )
        
        self.btn_upload.setEnabled(True)
    
    def _set_validation_status(self, message: str, status: str):
        """Set validation display status."""
        self.lbl_validation.setText(message)
        
        styles = {
            "error": """
                QFrame { background-color: #c0392b; border-radius: 5px; }
                QLabel { color: white; font-size: 13px; }
            """,
            "success": """
                QFrame { background-color: #27ae60; border-radius: 5px; }
                QLabel { color: white; font-size: 13px; }
            """,
            "info": """
                QFrame { background-color: #2980b9; border-radius: 5px; }
                QLabel { color: white; font-size: 13px; }
            """
        }
        
        self.validation_frame.setStyleSheet(styles.get(status, styles["info"]))
    
    def _show_help(self):
        """Show help dialog."""
        help_text = """
<h3>Multi-Evidence Upload</h3>
<p>FEPD supports analyzing multiple related evidence sources together:</p>

<h4>Supported Evidence Types:</h4>
<ul>
<li><b>💿 Disk Images:</b> E01, DD, RAW, IMG, AFF, VMDK, VHD</li>
<li><b>🧠 Memory Dumps:</b> MEM, DMP, VMEM, RAW</li>
<li><b>🌐 Network Captures:</b> PCAP, PCAPNG, CAP</li>
<li><b>📝 Log Files:</b> EVTX, EVT, LOG, CSV, JSON</li>
<li><b>📱 Mobile Backups:</b> TAR, AB, UFED</li>
</ul>

<h4>Relationship Detection:</h4>
<p>FEPD automatically detects relationships between evidence:</p>
<ul>
<li><b>Same Device:</b> Disk image + memory from same computer</li>
<li><b>Same User:</b> Evidence containing same user accounts</li>
<li><b>Timeline Overlap:</b> Evidence with overlapping time periods</li>
<li><b>Multi-part Sets:</b> Split forensic images (E01, E02, ...)</li>
</ul>

<h4>Combined Processing:</h4>
<p>When evidence sources are related, FEPD will:</p>
<ul>
<li>Merge artifacts into unified views</li>
<li>Cross-reference events across sources</li>
<li>Build comprehensive timelines</li>
<li>Correlate user activities</li>
</ul>
        """
        
        QMessageBox.information(self, "Help - Multi-Evidence Upload", help_text)
    
    def _on_upload(self):
        """Handle upload/process button click."""
        if not self.evidence_items:
            return
        
        # Create selection result
        selection = MultiEvidenceSelection(
            evidence_items=self.evidence_items.copy(),
            case_name=self.case_name,
            operator=self.operator,
            combine_related=self.chk_combine.isChecked(),
            detected_relationships=self.detected_relationships
        )
        
        self.evidence_selected.emit(selection)
        self.accept()
    
    def get_selection(self) -> Optional[MultiEvidenceSelection]:
        """Get the selection after dialog closes."""
        if self.result() == QDialog.DialogCode.Accepted:
            return MultiEvidenceSelection(
                evidence_items=self.evidence_items.copy(),
                case_name=self.case_name,
                operator=self.operator,
                combine_related=self.chk_combine.isChecked(),
                detected_relationships=self.detected_relationships
            )
        return None
