"""
FEPD - Artifacts Tab
Comprehensive artifact browser with filtering, preview, and tagging

Features:
- Category tree navigation (left pane)
- Sortable artifact table (center)
- Filter bar with facets
- Preview/detail pane (right)
- Tagging/bookmarking
- Color-coded artifact types
- Context tooltips
"""

import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTreeWidget,
    QTreeWidgetItem, QTableWidget, QTableWidgetItem, QLineEdit,
    QPushButton, QComboBox, QLabel, QTextEdit, QGroupBox,
    QHeaderView, QMenu, QCheckBox, QFrame, QScrollArea, QDateEdit,
    QDialog
)
from PyQt6.QtCore import Qt, pyqtSignal, QDate
from PyQt6.QtGui import QIcon, QColor, QBrush, QAction


class ArtifactsTab(QWidget):
    """
    Complete artifacts browser with tree navigation, table view, filtering, and preview.
    """
    
    artifact_selected = pyqtSignal(dict)  # Emits selected artifact data
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        
        self._artifacts = []  # All artifacts
        self._filtered_artifacts = []  # Currently filtered
        self._tagged_artifacts = set()  # Tagged artifact IDs
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Main splitter (tree | table+filters | preview)
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # LEFT PANE: Category Tree
        left_widget = self._create_category_tree()
        main_splitter.addWidget(left_widget)
        
        # CENTER PANE: Filters + Table
        center_widget = self._create_center_pane()
        main_splitter.addWidget(center_widget)
        
        # RIGHT PANE: Preview/Detail
        right_widget = self._create_preview_pane()
        main_splitter.addWidget(right_widget)
        
        # Set splitter proportions (20% | 50% | 30%)
        main_splitter.setSizes([250, 600, 350])
        
        layout.addWidget(main_splitter)
    
    def _create_category_tree(self) -> QWidget:
        """Create left navigation tree."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        layout.addWidget(QLabel("<b>📂 Data Sources & Views</b>"))
        
        self.tree_categories = QTreeWidget()
        self.tree_categories.setHeaderLabel("Categories")
        self.tree_categories.itemClicked.connect(self._on_category_clicked)
        
        # Build tree structure
        self._build_category_tree()
        
        layout.addWidget(self.tree_categories)
        
        # Stats panel
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout()
        stats_layout.setSpacing(2)
        
        self.lbl_total_artifacts = QLabel("Total: 0")
        self.lbl_filtered_artifacts = QLabel("Filtered: 0")
        self.lbl_tagged_artifacts = QLabel("Tagged: 0")
        
        stats_layout.addWidget(self.lbl_total_artifacts)
        stats_layout.addWidget(self.lbl_filtered_artifacts)
        stats_layout.addWidget(self.lbl_tagged_artifacts)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Smart Recommendation Engine
        recommendations_group = QGroupBox("🔎 Suggested Focus Areas")
        rec_layout = QVBoxLayout()
        
        self.txt_recommendations = QTextEdit()
        self.txt_recommendations.setReadOnly(True)
        self.txt_recommendations.setMaximumHeight(200)
        self.txt_recommendations.setPlaceholderText("Load artifacts to see intelligent recommendations...")
        self.txt_recommendations.setStyleSheet("background-color: #2a2a2a; color: #f0f0f0; border: 1px solid #555;")
        rec_layout.addWidget(self.txt_recommendations)
        
        btn_refresh_rec = QPushButton("🔄 Refresh Recommendations")
        btn_refresh_rec.clicked.connect(self._generate_recommendations)
        rec_layout.addWidget(btn_refresh_rec)
        
        recommendations_group.setLayout(rec_layout)
        layout.addWidget(recommendations_group)
        
        return widget
    
    def _build_category_tree(self):
        """Build the category tree structure."""
        # Data Sources
        data_sources = QTreeWidgetItem(self.tree_categories, ["💾 Data Sources"])
        data_sources.setExpanded(True)
        
        # Placeholder for actual images (will be populated when images are ingested)
        QTreeWidgetItem(data_sources, ["📀 No images ingested yet"])
        
        # Results/Views Tree
        results = QTreeWidgetItem(self.tree_categories, ["🔍 Results"])
        results.setExpanded(True)
        
        # File System
        fs_item = QTreeWidgetItem(results, ["📁 File System"])
        QTreeWidgetItem(fs_item, ["All Files"])
        QTreeWidgetItem(fs_item, ["Deleted Files"])
        QTreeWidgetItem(fs_item, ["Carved Files"])
        
        # Registry
        registry_item = QTreeWidgetItem(results, ["🔐 Registry"])
        QTreeWidgetItem(registry_item, ["Autorun Entries"])
        QTreeWidgetItem(registry_item, ["USB Devices"])
        QTreeWidgetItem(registry_item, ["Recent Documents"])
        QTreeWidgetItem(registry_item, ["User Accounts"])
        
        # Web Activity
        web_item = QTreeWidgetItem(results, ["🌐 Web Activity"])
        QTreeWidgetItem(web_item, ["Browser History"])
        QTreeWidgetItem(web_item, ["Downloads"])
        QTreeWidgetItem(web_item, ["Cookies"])
        QTreeWidgetItem(web_item, ["Bookmarks"])
        
        # Communication
        comm_item = QTreeWidgetItem(results, ["💬 Communication"])
        QTreeWidgetItem(comm_item, ["Email"])
        QTreeWidgetItem(comm_item, ["Chat Messages"])
        QTreeWidgetItem(comm_item, ["Contacts"])
        
        # Media
        media_item = QTreeWidgetItem(results, ["📸 Media"])
        QTreeWidgetItem(media_item, ["Images"])
        QTreeWidgetItem(media_item, ["Videos"])
        QTreeWidgetItem(media_item, ["Audio"])
        QTreeWidgetItem(media_item, ["EXIF Data"])
        
        # Tagged Items
        tagged = QTreeWidgetItem(self.tree_categories, ["⭐ Tagged Items"])
        tagged.setExpanded(False)
        
        # Hash Matches
        hash_matches = QTreeWidgetItem(self.tree_categories, ["🔍 Hash Matches"])
        QTreeWidgetItem(hash_matches, ["Known Files (NSRL)"])
        QTreeWidgetItem(hash_matches, ["Known Bad (Malware)"])
    
    def _create_center_pane(self) -> QWidget:
        """Create center pane with filters and table."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        
        # Filter Bar
        filter_group = self._create_filter_bar()
        layout.addWidget(filter_group)
        
        # Artifacts Table with ID column
        self.table_artifacts = QTableWidget(0, 10)
        self.table_artifacts.setHorizontalHeaderLabels([
            "#ID", "📌", "Type", "Name", "Path/Location", "Date/Time", 
            "Size", "Hash", "Owner", "Status"
        ])
        
        # Configure table
        self.table_artifacts.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_artifacts.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table_artifacts.setAlternatingRowColors(True)
        self.table_artifacts.setSortingEnabled(True)
        self.table_artifacts.verticalHeader().setVisible(False)
        
        # Set column widths
        header = self.table_artifacts.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)  # ID column
        header.resizeSection(0, 60)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)  # Tag column
        header.resizeSection(1, 40)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Type
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)  # Name
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)  # Path
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Date
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Size
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  # Hash
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)  # Owner
        header.setSectionResizeMode(9, QHeaderView.ResizeMode.ResizeToContents)  # Status
        
        # Context menu
        self.table_artifacts.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_artifacts.customContextMenuRequested.connect(self._show_context_menu)
        
        # Connect cell click for ID column
        self.table_artifacts.cellClicked.connect(self._on_cell_clicked)
        
        # Selection changed
        self.table_artifacts.itemSelectionChanged.connect(self._on_artifact_selected)
        
        layout.addWidget(self.table_artifacts)
        
        # Status bar for table
        status_layout = QHBoxLayout()
        self.lbl_table_status = QLabel("No artifacts loaded")
        status_layout.addWidget(self.lbl_table_status)
        status_layout.addStretch()
        
        btn_export = QPushButton("📤 Export Filtered Results...")
        btn_export.clicked.connect(self._export_artifacts)
        status_layout.addWidget(btn_export)
        
        layout.addLayout(status_layout)
        
        return widget
    
    def _create_filter_bar(self) -> QGroupBox:
        """Create filter bar with search and facets."""
        filter_group = QGroupBox("🔎 Filters")
        filter_layout = QVBoxLayout()
        filter_layout.setSpacing(5)
        
        # Search bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Search by name, path, hash...")
        self.txt_search.textChanged.connect(self._apply_filters)
        search_layout.addWidget(self.txt_search)
        
        btn_clear_search = QPushButton("✗")
        btn_clear_search.setMaximumWidth(30)
        btn_clear_search.setToolTip("Clear search")
        btn_clear_search.clicked.connect(lambda: self.txt_search.clear())
        search_layout.addWidget(btn_clear_search)
        
        filter_layout.addLayout(search_layout)
        
        # Facets row 1 - Artifact Type
        facets_row1 = QHBoxLayout()
        
        facets_row1.addWidget(QLabel("📂 Artifact Type:"))
        self.cmb_type = QComboBox()
        self.cmb_type.addItems([
            "All Types",
            "EVTX (Event Logs)",
            "Registry Hives",
            "Browser History",
            "Prefetch Files",
            "MFT Records",
            "Email",
            "Chat",
            "Media Files",
            "Documents",
            "Executables"
        ])
        self.cmb_type.currentTextChanged.connect(self._apply_filters)
        facets_row1.addWidget(self.cmb_type)
        
        facets_row1.addWidget(QLabel("📄 Status:"))
        self.cmb_status = QComboBox()
        self.cmb_status.addItems([
            "All Status",
            "Active",
            "Deleted",
            "Carved",
            "Encrypted",
            "Hash Match"
        ])
        self.cmb_status.currentTextChanged.connect(self._apply_filters)
        facets_row1.addWidget(self.cmb_status)
        
        facets_row1.addWidget(QLabel("📏 Size:"))
        self.cmb_size = QComboBox()
        self.cmb_size.addItems([
            "Any Size",
            "< 1 MB",
            "1-10 MB",
            "10-100 MB",
            "> 100 MB"
        ])
        self.cmb_size.currentTextChanged.connect(self._apply_filters)
        facets_row1.addWidget(self.cmb_size)
        
        facets_row1.addStretch()
        filter_layout.addLayout(facets_row1)
        
        # Facets row 1B - Source File Filter
        facets_row1b = QHBoxLayout()
        
        facets_row1b.addWidget(QLabel("🧩 Source File:"))
        self.cmb_source_file = QComboBox()
        self.cmb_source_file.addItems([
            "All Sources",
            "NTUSER.DAT",
            "SYSTEM",
            "SOFTWARE",
            "SAM",
            "SECURITY",
            "Security.evtx",
            "System.evtx",
            "Application.evtx",
            "$MFT"
        ])
        self.cmb_source_file.currentTextChanged.connect(self._apply_filters)
        facets_row1b.addWidget(self.cmb_source_file)
        
        facets_row1b.addWidget(QLabel("🔐 Integrity:"))
        self.cmb_integrity = QComboBox()
        self.cmb_integrity.addItems([
            "All",
            "Clean",
            "Corrupted",
            "Suspicious"
        ])
        self.cmb_integrity.currentTextChanged.connect(self._apply_filters)
        facets_row1b.addWidget(self.cmb_integrity)
        
        facets_row1b.addStretch()
        filter_layout.addLayout(facets_row1b)
        
        # Facets row 2 (Timestamp filters)
        facets_row2 = QHBoxLayout()
        
        facets_row2.addWidget(QLabel("⌛ First Seen:"))
        self.date_first_seen = QDateEdit()
        self.date_first_seen.setCalendarPopup(True)
        self.date_first_seen.setDisplayFormat("yyyy-MM-dd")
        self.date_first_seen.setDate(QDate(2000, 1, 1))
        self.date_first_seen.dateChanged.connect(self._apply_filters)
        facets_row2.addWidget(self.date_first_seen)
        
        facets_row2.addWidget(QLabel("⌛ Last Modified:"))
        self.date_last_modified = QDateEdit()
        self.date_last_modified.setCalendarPopup(True)
        self.date_last_modified.setDisplayFormat("yyyy-MM-dd")
        self.date_last_modified.setDate(QDate.currentDate())
        self.date_last_modified.dateChanged.connect(self._apply_filters)
        facets_row2.addWidget(self.date_last_modified)
        
        facets_row2.addStretch()
        filter_layout.addLayout(facets_row2)
        
        # Facets row 3 (Checkboxes + Reset)
        facets_row3 = QHBoxLayout()
        
        self.chk_tagged_only = QCheckBox("⭐ Tagged Only")
        self.chk_tagged_only.toggled.connect(self._apply_filters)
        facets_row3.addWidget(self.chk_tagged_only)
        
        self.chk_hide_known = QCheckBox("Hide Known Files")
        self.chk_hide_known.toggled.connect(self._apply_filters)
        self.chk_hide_known.setToolTip("Hide files matching NSRL known-good database")
        facets_row3.addWidget(self.chk_hide_known)
        
        self.chk_deleted_only = QCheckBox("🗑️ Deleted Only")
        self.chk_deleted_only.toggled.connect(self._apply_filters)
        self.chk_deleted_only.setToolTip("Show only deleted files")
        facets_row3.addWidget(self.chk_deleted_only)
        
        facets_row3.addStretch()
        
        btn_reset_filters = QPushButton("🔄 Reset Filters")
        btn_reset_filters.clicked.connect(self._reset_filters)
        facets_row3.addWidget(btn_reset_filters)
        
        filter_layout.addLayout(facets_row3)
        
        filter_group.setLayout(filter_layout)
        return filter_group
    
    def _create_preview_pane(self) -> QWidget:
        """Create right preview/detail pane."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        layout.addWidget(QLabel("<b>📋 Artifact Details</b>"))
        
        # Scrollable detail area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        
        # Basic Info
        info_group = QGroupBox("Basic Information")
        info_layout = QVBoxLayout()
        
        self.lbl_preview_name = QLabel("<i>No artifact selected</i>")
        self.lbl_preview_name.setWordWrap(True)
        info_layout.addWidget(self.lbl_preview_name)
        
        self.lbl_preview_type = QLabel("")
        info_layout.addWidget(self.lbl_preview_type)
        
        self.lbl_preview_path = QLabel("")
        self.lbl_preview_path.setWordWrap(True)
        info_layout.addWidget(self.lbl_preview_path)
        
        self.lbl_preview_size = QLabel("")
        info_layout.addWidget(self.lbl_preview_size)
        
        info_group.setLayout(info_layout)
        detail_layout.addWidget(info_group)
        
        # Timestamps
        time_group = QGroupBox("Timestamps (MACB)")
        time_layout = QVBoxLayout()
        
        self.lbl_preview_modified = QLabel("Modified: -")
        time_layout.addWidget(self.lbl_preview_modified)
        
        self.lbl_preview_accessed = QLabel("Accessed: -")
        time_layout.addWidget(self.lbl_preview_accessed)
        
        self.lbl_preview_created = QLabel("Created: -")
        time_layout.addWidget(self.lbl_preview_created)
        
        self.lbl_preview_birth = QLabel("Birth: -")
        time_layout.addWidget(self.lbl_preview_birth)
        
        time_group.setLayout(time_layout)
        detail_layout.addWidget(time_group)
        
        # Hashes
        hash_group = QGroupBox("Cryptographic Hashes")
        hash_layout = QVBoxLayout()
        
        self.lbl_preview_md5 = QLabel("MD5: -")
        self.lbl_preview_md5.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        hash_layout.addWidget(self.lbl_preview_md5)
        
        self.lbl_preview_sha256 = QLabel("SHA-256: -")
        self.lbl_preview_sha256.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        hash_layout.addWidget(self.lbl_preview_sha256)
        
        hash_group.setLayout(hash_layout)
        detail_layout.addWidget(hash_group)
        
        # Content Preview
        preview_group = QGroupBox("Content Preview")
        preview_layout = QVBoxLayout()
        
        self.txt_preview_content = QTextEdit()
        self.txt_preview_content.setReadOnly(True)
        self.txt_preview_content.setMaximumHeight(200)
        self.txt_preview_content.setPlaceholderText("Content preview will appear here...")
        preview_layout.addWidget(self.txt_preview_content)
        
        preview_group.setLayout(preview_layout)
        detail_layout.addWidget(preview_group)
        
        # Actions
        actions_group = QGroupBox("Actions")
        actions_layout = QVBoxLayout()
        
        self.btn_tag = QPushButton("⭐ Tag as Notable")
        self.btn_tag.clicked.connect(self._tag_selected)
        actions_layout.addWidget(self.btn_tag)
        
        btn_export_artifact = QPushButton("💾 Export Artifact...")
        btn_export_artifact.clicked.connect(self._export_selected_artifact)
        actions_layout.addWidget(btn_export_artifact)
        
        btn_view_hex = QPushButton("🔍 View in Hex Viewer")
        btn_view_hex.clicked.connect(self._view_hex)
        actions_layout.addWidget(btn_view_hex)
        
        actions_group.setLayout(actions_layout)
        detail_layout.addWidget(actions_group)
        
        detail_layout.addStretch()
        
        scroll.setWidget(detail_widget)
        layout.addWidget(scroll)
        
        return widget
    
    def _on_category_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle category tree item click."""
        category = item.text(0)
        self.logger.info(f"Category selected: {category}")
        
        # Filter artifacts by category
        # TODO: Implement category-based filtering
        self._apply_filters()
    
    def _on_artifact_selected(self):
        """Handle artifact table selection change."""
        selected = self.table_artifacts.selectedItems()
        if not selected:
            return
        
        row = selected[0].row()
        
        # Get artifact data from row
        artifact_data = {
            'name': self.table_artifacts.item(row, 2).text() if self.table_artifacts.item(row, 2) else "",
            'type': self.table_artifacts.item(row, 1).text() if self.table_artifacts.item(row, 1) else "",
            'path': self.table_artifacts.item(row, 3).text() if self.table_artifacts.item(row, 3) else "",
            'date': self.table_artifacts.item(row, 4).text() if self.table_artifacts.item(row, 4) else "",
            'size': self.table_artifacts.item(row, 5).text() if self.table_artifacts.item(row, 5) else "",
            'hash': self.table_artifacts.item(row, 6).text() if self.table_artifacts.item(row, 6) else "",
        }
        
        # Update preview pane
        self._update_preview(artifact_data)
        
        # Emit signal
        self.artifact_selected.emit(artifact_data)
    
    def _update_preview(self, artifact: Dict[str, Any]):
        """Update preview pane with artifact details."""
        self.lbl_preview_name.setText(f"<b>{artifact.get('name', 'Unknown')}</b>")
        self.lbl_preview_type.setText(f"Type: {artifact.get('type', '-')}")
        self.lbl_preview_path.setText(f"Path: {artifact.get('path', '-')}")
        self.lbl_preview_size.setText(f"Size: {artifact.get('size', '-')}")
        
        # Timestamps (placeholder)
        self.lbl_preview_modified.setText(f"Modified: {artifact.get('date', '-')}")
        self.lbl_preview_accessed.setText(f"Accessed: -")
        self.lbl_preview_created.setText(f"Created: -")
        self.lbl_preview_birth.setText(f"Birth: -")
        
        # Hashes
        hash_val = artifact.get('hash', '-')
        if hash_val and len(hash_val) == 32:
            self.lbl_preview_md5.setText(f"MD5: {hash_val}")
            self.lbl_preview_sha256.setText(f"SHA-256: -")
        elif hash_val and len(hash_val) == 64:
            self.lbl_preview_md5.setText(f"MD5: -")
            self.lbl_preview_sha256.setText(f"SHA-256: {hash_val}")
        else:
            self.lbl_preview_md5.setText(f"MD5: -")
            self.lbl_preview_sha256.setText(f"SHA-256: -")
        
        # Content preview (placeholder)
        self.txt_preview_content.setText("Content preview not yet implemented")
    
    def _apply_filters(self):
        """Apply all active filters to artifact list."""
        # TODO: Implement filtering logic
        search_text = self.txt_search.text().lower()
        type_filter = self.cmb_type.currentText()
        status_filter = self.cmb_status.currentText()
        size_filter = self.cmb_size.currentText()
        tagged_only = self.chk_tagged_only.isChecked()
        hide_known = self.chk_hide_known.isChecked()
        
        self.logger.info(f"Applying filters: search={search_text}, type={type_filter}, status={status_filter}")
        
        # Update status
        self.lbl_table_status.setText(f"Filters active - showing {self.table_artifacts.rowCount()} artifacts")
    
    def _reset_filters(self):
        """Reset all filters to default."""
        self.txt_search.clear()
        self.cmb_type.setCurrentIndex(0)
        self.cmb_status.setCurrentIndex(0)
        self.cmb_size.setCurrentIndex(0)
        self.date_start.setDate(QDate(2000, 1, 1))
        self.date_end.setDate(QDate.currentDate())
        self.chk_tagged_only.setChecked(False)
        self.chk_hide_known.setChecked(False)
        self.chk_deleted_only.setChecked(False)
    
    def _show_context_menu(self, position):
        """Show context menu for artifact table."""
        menu = QMenu()
        
        tag_action = QAction("⭐ Tag as Notable", self)
        tag_action.triggered.connect(self._tag_selected)
        menu.addAction(tag_action)
        
        untag_action = QAction("Remove Tag", self)
        untag_action.triggered.connect(self._untag_selected)
        menu.addAction(untag_action)
        
        menu.addSeparator()
        
        export_action = QAction("💾 Export Selected...", self)
        export_action.triggered.connect(self._export_selected_artifact)
        menu.addAction(export_action)
        
        hex_action = QAction("🔍 View in Hex", self)
        hex_action.triggered.connect(self._view_hex)
        menu.addAction(hex_action)
        
        menu.addSeparator()
        
        copy_hash_action = QAction("📋 Copy Hash", self)
        copy_hash_action.triggered.connect(self._copy_hash)
        menu.addAction(copy_hash_action)
        
        copy_path_action = QAction("📋 Copy Path", self)
        copy_path_action.triggered.connect(self._copy_path)
        menu.addAction(copy_path_action)
        
        menu.exec(self.table_artifacts.viewport().mapToGlobal(position))
    
    def _tag_selected(self):
        """Tag selected artifacts as notable."""
        selected_rows = set(item.row() for item in self.table_artifacts.selectedItems())
        for row in selected_rows:
            # Update tag column
            tag_item = self.table_artifacts.item(row, 0)
            if not tag_item:
                tag_item = QTableWidgetItem("⭐")
                self.table_artifacts.setItem(row, 0, tag_item)
            else:
                tag_item.setText("⭐")
        
        self.logger.info(f"Tagged {len(selected_rows)} artifacts")
        self._update_stats()
    
    def _untag_selected(self):
        """Remove tag from selected artifacts."""
        selected_rows = set(item.row() for item in self.table_artifacts.selectedItems())
        for row in selected_rows:
            tag_item = self.table_artifacts.item(row, 0)
            if tag_item:
                tag_item.setText("")
        
        self.logger.info(f"Untagged {len(selected_rows)} artifacts")
        self._update_stats()
    
    def _export_artifacts(self):
        """Export filtered artifacts to CSV."""
        # TODO: Implement CSV export
        self.logger.info("Export artifacts requested")
    
    def _export_selected_artifact(self):
        """Export selected artifact to file."""
        # TODO: Implement artifact export
        self.logger.info("Export selected artifact requested")
    
    def _view_hex(self):
        """Open hex viewer for selected artifact."""
        # TODO: Implement hex viewer
        self.logger.info("Hex view requested")
    
    def _copy_hash(self):
        """Copy hash to clipboard."""
        # TODO: Implement clipboard copy
        self.logger.info("Copy hash requested")
    
    def _copy_path(self):
        """Copy path to clipboard."""
        # TODO: Implement clipboard copy
        self.logger.info("Copy path requested")
    
    def _update_stats(self):
        """Update statistics labels."""
        total = len(self._artifacts)
        filtered = self.table_artifacts.rowCount()
        tagged = len(self._tagged_artifacts)
        
        self.lbl_total_artifacts.setText(f"Total: {total:,}")
        self.lbl_filtered_artifacts.setText(f"Filtered: {filtered:,}")
        self.lbl_tagged_artifacts.setText(f"Tagged: {tagged}")
    
    def load_artifacts(self, artifacts: List[Dict[str, Any]]):
        """Load artifacts into table."""
        self._artifacts = artifacts
        self._filtered_artifacts = artifacts.copy()
        
        self.table_artifacts.setRowCount(len(artifacts))
        
        for i, artifact in enumerate(artifacts):
            # ID column (clickable)
            id_item = QTableWidgetItem(f"#{i+1}")
            id_item.setForeground(QBrush(QColor(52, 152, 219)))  # Blue for clickable
            id_item.setToolTip("Click to view details or timeline")
            id_item.setData(Qt.ItemDataRole.UserRole, artifact)  # Store artifact data
            self.table_artifacts.setItem(i, 0, id_item)
            
            # Tag column
            self.table_artifacts.setItem(i, 1, QTableWidgetItem(""))
            
            # Type with icon
            type_item = QTableWidgetItem(self._get_type_icon(artifact.get('type', '')))
            self.table_artifacts.setItem(i, 2, type_item)
            
            # Other columns
            self.table_artifacts.setItem(i, 3, QTableWidgetItem(artifact.get('name', '')))
            self.table_artifacts.setItem(i, 4, QTableWidgetItem(artifact.get('path', '')))
            self.table_artifacts.setItem(i, 5, QTableWidgetItem(artifact.get('date', '')))
            self.table_artifacts.setItem(i, 6, QTableWidgetItem(artifact.get('size', '')))
            self.table_artifacts.setItem(i, 7, QTableWidgetItem(artifact.get('hash', '')))
            self.table_artifacts.setItem(i, 8, QTableWidgetItem(artifact.get('owner', '')))
            
            # Status with color coding
            status_item = QTableWidgetItem(artifact.get('status', 'Active'))
            status_item.setBackground(QBrush(self._get_status_color(artifact.get('status', ''))))
            self.table_artifacts.setItem(i, 9, status_item)
        
        self._update_stats()
        self.lbl_table_status.setText(f"Loaded {len(artifacts):,} artifacts")
    
    def _get_type_icon(self, artifact_type: str) -> str:
        """Get icon for artifact type."""
        icons = {
            'file': '📄',
            'registry': '🔐',
            'browser': '🌐',
            'email': '📧',
            'chat': '💬',
            'image': '🖼️',
            'video': '🎬',
            'audio': '🎵',
            'document': '📝',
            'executable': '⚙️',
        }
        return icons.get(artifact_type.lower(), '📦')
    
    def _get_status_color(self, status: str) -> QColor:
        """Get color for status."""
        colors = {
            'active': QColor(46, 204, 113, 50),  # Green
            'deleted': QColor(231, 76, 60, 50),   # Red
            'carved': QColor(241, 196, 15, 50),   # Yellow
            'encrypted': QColor(155, 89, 182, 50), # Purple
        }
        return colors.get(status.lower(), QColor(0, 0, 0, 0))
    
    def _generate_recommendations(self):
        """Generate smart recommendations based on loaded artifacts."""
        if not self._artifacts:
            self.txt_recommendations.setHtml("<i>No artifacts loaded yet.</i>")
            return
        
        recommendations = []
        recommendations.append("<b>🔎 Intelligent Analysis Recommendations:</b><br><br>")
        
        # Analyze artifact types
        artifact_types = {}
        deleted_count = 0
        recent_activity = []
        suspicious_patterns = []
        
        for artifact in self._artifacts:
            atype = artifact.get('type', 'unknown')
            artifact_types[atype] = artifact_types.get(atype, 0) + 1
            
            if artifact.get('status') == 'Deleted':
                deleted_count += 1
            
            # Check for unusual times
            date_str = artifact.get('date', '')
            if '03:' in date_str or '02:' in date_str or '04:' in date_str:
                recent_activity.append(artifact.get('name', 'Unknown'))
        
        # Generate contextual recommendations
        if deleted_count > 10:
            recommendations.append(f"⚠️ <b>High deletion activity:</b> {deleted_count} deleted artifacts found<br>")
            recommendations.append("   → Investigate recent file deletions for anti-forensics<br><br>")
        
        if recent_activity:
            recommendations.append(f"🌙 <b>Unusual late-night activity:</b> {len(recent_activity)} artifacts modified between 02:00-04:00<br>")
            recommendations.append(f"   → Suspicious: {', '.join(recent_activity[:3])}<br><br>")
        
        # Registry analysis
        if artifact_types.get('registry', 0) > 0:
            recommendations.append(f"🔐 <b>Registry artifacts found:</b> {artifact_types['registry']} items<br>")
            recommendations.append("   → Check for persistence mechanisms (Run keys, Services)<br>")
            recommendations.append("   → Review USB history and recent documents<br><br>")
        
        # Browser analysis
        if artifact_types.get('browser', 0) > 0:
            recommendations.append(f"🌐 <b>Browser artifacts found:</b> {artifact_types['browser']} items<br>")
            recommendations.append("   → Look for malicious downloads or suspicious URLs<br>")
            recommendations.append("   → Check timing correlation with other events<br><br>")
        
        # Prefetch analysis
        if artifact_types.get('prefetch', 0) > 0:
            recommendations.append(f"📊 <b>Prefetch files found:</b> {artifact_types.get('prefetch', 0)} items<br>")
            recommendations.append("   → Identify programs launched only once (potential malware)<br>")
            recommendations.append("   → Build execution timeline<br><br>")
        
        # Event logs
        if artifact_types.get('evtx', 0) > 0:
            recommendations.append(f"📜 <b>Event logs found:</b> {artifact_types.get('evtx', 0)} items<br>")
            recommendations.append("   → Check Security.evtx for logon events (4624/4625)<br>")
            recommendations.append("   → Look for process creation events (4688)<br><br>")
        
        if not any([deleted_count, recent_activity, artifact_types]):
            recommendations.append("<i>Load artifacts to receive intelligent analysis suggestions</i>")
        
        self.txt_recommendations.setHtml("".join(recommendations))
        self.logger.info("Generated smart recommendations for artifacts")
    
    def _on_cell_clicked(self, row, column):
        """Handle cell click - show enhanced dialog for ID column."""
        if column != 0:  # Only handle ID column
            return
        
        from src.ui.dialogs.artifact_detail_dialog import ArtifactChoiceDialog, ArtifactDetailDialog
        
        # Get artifact data
        id_item = self.table_artifacts.item(row, 0)
        if not id_item:
            return
        
        artifact = id_item.data(Qt.ItemDataRole.UserRole)
        if not artifact:
            return
        
        # Check if artifact has timeline events (simulated for now)
        # TODO: Query actual timeline database for this artifact
        has_timeline_events = self._check_timeline_events(artifact)
        
        # Show choice dialog
        choice_dialog = ArtifactChoiceDialog(artifact, has_timeline_events, self)
        
        if choice_dialog.exec() == QDialog.DialogCode.Accepted:
            choice = choice_dialog.get_choice()
            
            if choice == 'details':
                # Show detailed artifact information
                self._show_enhanced_artifact_details(artifact)
            
            elif choice == 'timeline':
                # Navigate to timeline and filter by this artifact
                self._navigate_to_timeline(artifact)
    
    def _show_artifact_details(self, artifact, parent_dialog=None):
        """Show detailed information about artifact."""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
        
        if parent_dialog:
            parent_dialog.accept()
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Artifact Details - {artifact.get('name', 'Unknown')}")
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(dialog)
        
        # Details text
        details_text = QTextEdit()
        details_text.setReadOnly(True)
        
        html = []
        html.append(f"<h2>📋 Artifact Details</h2>")
        html.append(f"<b>Name:</b> {artifact.get('name', 'N/A')}<br>")
        html.append(f"<b>Type:</b> {artifact.get('type', 'N/A')}<br>")
        html.append(f"<b>Path:</b> {artifact.get('path', 'N/A')}<br>")
        html.append(f"<b>Size:</b> {artifact.get('size', 'N/A')}<br>")
        html.append(f"<b>Date/Time:</b> {artifact.get('date', 'N/A')}<br>")
        html.append(f"<b>Hash:</b> {artifact.get('hash', 'N/A')}<br>")
        html.append(f"<b>Owner:</b> {artifact.get('owner', 'N/A')}<br>")
        html.append(f"<b>Status:</b> {artifact.get('status', 'N/A')}<br>")
        
        if artifact.get('description'):
            html.append(f"<br><b>Description:</b><br>{artifact.get('description')}")
        
        details_text.setHtml("".join(html))
        layout.addWidget(details_text)
        
        # Close button
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dialog.accept)
        layout.addWidget(btn_close)
        
        dialog.exec()
    
    def _go_to_timeline(self, artifact, parent_dialog=None):
        """Navigate to timeline tab and filter to this artifact."""
        if parent_dialog:
            parent_dialog.accept()
        
        # Get main window
        main_window = self.window()
        if hasattr(main_window, 'tabs'):
            # Switch to timeline tab
            for i in range(main_window.tabs.count()):
                if 'Timeline' in main_window.tabs.tabText(i):
                    main_window.tabs.setCurrentIndex(i)
                    
                    # Try to filter timeline by this artifact
                    if hasattr(main_window, 'timeline_tab'):
                        # TODO: Add filtering logic in timeline tab
                        self.logger.info(f"Navigated to timeline for artifact: {artifact.get('name')}")
                    break
        
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.information(self, "Timeline", 
                              f"Navigated to Timeline tab.\nLook for events related to:\n{artifact.get('name', 'this artifact')}")
    
    def _check_timeline_events(self, artifact: dict) -> bool:
        """
        Check if artifact has associated timeline events.
        
        Args:
            artifact: Artifact dictionary
            
        Returns:
            bool: True if timeline events exist
        """
        # TODO: Implement actual database query
        # For now, simulate based on artifact type
        timeline_types = ['evtx', 'prefetch', 'registry', 'browser', 'log']
        artifact_type = artifact.get('type', '').lower()
        
        return any(t in artifact_type for t in timeline_types)
    
    def _show_enhanced_artifact_details(self, artifact: dict):
        """
        Show enhanced artifact details dialog with tabs.
        
        Args:
            artifact: Artifact dictionary
        """
        from src.ui.dialogs.artifact_detail_dialog import ArtifactDetailDialog
        
        # Get timeline events for this artifact (simulated for now)
        timeline_events = self._get_timeline_events_for_artifact(artifact)
        
        # Show detail dialog
        detail_dialog = ArtifactDetailDialog(artifact, timeline_events, self)
        detail_dialog.show_in_timeline.connect(self._navigate_to_timeline)
        detail_dialog.exec()
    
    def _get_timeline_events_for_artifact(self, artifact: dict) -> list:
        """
        Get timeline events associated with this artifact.
        
        Args:
            artifact: Artifact dictionary
            
        Returns:
            list: List of timeline event dictionaries
        """
        # TODO: Implement actual database query
        # For now, return simulated events
        events = []
        
        if self._check_timeline_events(artifact):
            # Simulate some events
            events = [
                {
                    'timestamp': artifact.get('date', 'Unknown'),
                    'event_type': f"{artifact.get('type', 'Unknown')} Modified",
                    'severity': 'INFO',
                    'user': artifact.get('owner', 'Unknown'),
                    'description': f"File modified: {artifact.get('name', 'Unknown')}"
                },
                {
                    'timestamp': artifact.get('date', 'Unknown'),
                    'event_type': f"{artifact.get('type', 'Unknown')} Accessed",
                    'severity': 'INFO',
                    'user': artifact.get('owner', 'Unknown'),
                    'description': f"File accessed: {artifact.get('name', 'Unknown')}"
                }
            ]
        
        return events
    
    def _navigate_to_timeline(self, artifact: dict):
        """
        Navigate to timeline tab and highlight/filter for this artifact.
        
        Args:
            artifact: Artifact dictionary
        """
        main_window = self.window()
        
        if hasattr(main_window, 'tabs'):
            # Find and switch to timeline tab
            for i in range(main_window.tabs.count()):
                tab_text = main_window.tabs.tabText(i)
                if 'Timeline' in tab_text or 'Activity' in tab_text:
                    main_window.tabs.setCurrentIndex(i)
                    self.logger.info(f"Switched to timeline tab for artifact: {artifact.get('name')}")
                    
                    # Try to filter timeline
                    if hasattr(main_window, 'timeline_tab'):
                        # TODO: Call timeline tab's filter method
                        # main_window.timeline_tab.filter_by_artifact(artifact)
                        pass
                    
                    break
        
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.information(
            self,
            "Timeline Navigation",
            f"Navigated to Timeline tab.\n\n"
            f"Artifact: {artifact.get('name', 'Unknown')}\n"
            f"Path: {artifact.get('path', 'Unknown')}\n\n"
            f"Timeline will be filtered to show related events."
        )
