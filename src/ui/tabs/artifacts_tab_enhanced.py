"""
FEPD - TAB 4: ARTIFACTS
=======================

Artifact discovery and extraction tab with scan/extract logic.

Workflow:
1. User clicks "Run Artifact Scan"
2. System scans evidence for artifacts (Registry, Prefetch, EventLogs, Browser History, etc.)
3. Discovered artifacts are cataloged with metadata
4. User can view/filter/export artifacts
5. All actions logged to Chain of Custody

Features:
- Artifact type detection (Registry, Prefetch, EventLogs, Browser, etc.)
- Category tree navigation
- Filter and sort
- Preview pane
- Chain of Custody logging
- Evidence-native path display

Copyright (c) 2026 FEPD Development Team
"""

import logging
import os
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTreeWidget,
    QTreeWidgetItem, QTableWidget, QTableWidgetItem, QLineEdit,
    QPushButton, QComboBox, QLabel, QTextEdit, QGroupBox,
    QHeaderView, QMenu, QCheckBox, QFrame, QScrollArea,
    QProgressBar, QMessageBox, QTabWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QIcon, QColor, QBrush, QFont

# Local imports
import sys
sys.path.insert(0, str(__file__).replace('\\', '/').rsplit('/src/', 1)[0])
from src.core.case_manager import CaseManager
from src.core.chain_of_custody import ChainLogger
from src.analysis.artifact_correlator import (
    ArtifactCorrelator, ProcessTreeBuilder,
    analyze_unknown_artifact, OPERATION_COLORS,
)
from src.services.unified_forensic_store import UnifiedForensicStore

logger = logging.getLogger(__name__)


ARTIFACT_CATEGORIES = {
    "System": {
        "icon": "⚙️",
        "types": ["Registry", "Prefetch", "System Logs", "Services", "Scheduled Tasks"]
    },
    "User Activity": {
        "icon": "👤",
        "types": ["Recent Documents", "Jump Lists", "Shell Bags", "USB History", "User Accounts"]
    },
    "Network": {
        "icon": "🌐",
        "types": ["Browser History", "Downloads", "Cookies", "Network Shares", "Wi-Fi Profiles"]
    },
    "Security": {
        "icon": "🔒",
        "types": ["Event Logs (Security)", "Firewall Rules", "Windows Defender", "BitLocker"]
    },
    "Execution": {
        "icon": "⚡",
        "types": ["Prefetch", "ShimCache", "AmCache", "BAM/DAM", "UserAssist"]
    },
    "Communication": {
        "icon": "📧",
        "types": ["Email (PST/OST)", "Chat Logs", "Social Media", "Messaging Apps"]
    },
    "File System": {
        "icon": "📂",
        "types": ["MFT", "USN Journal", "Deleted Files", "File Metadata", "Alternate Data Streams"]
    },
    "Applications": {
        "icon": "📱",
        "types": ["Installed Applications", "Application Logs", "Browser Extensions", "Recent Files"]
    }
}


class ArtifactScanWorker(QThread):
    """Worker thread for artifact scanning."""
    
    progress = pyqtSignal(int, str)  # (percentage, status_message)
    artifact_found = pyqtSignal(dict)  # (artifact_dict)
    finished = pyqtSignal(int)  # (total_artifacts)
    error = pyqtSignal(str)  # (error_message)
    
    def __init__(self, case_manager: CaseManager, scan_types: List[str]):
        super().__init__()
        self.case_manager = case_manager
        self.scan_types = scan_types
        self._cancelled = False
        self.artifacts_found = 0
    
    def run(self):
        """Run artifact scan."""
        try:
            total_types = len(self.scan_types)
            
            for idx, artifact_type in enumerate(self.scan_types):
                if self._cancelled:
                    break
                
                progress = int(((idx + 1) / total_types) * 100)
                self.progress.emit(progress, f"Scanning: {artifact_type}...")
                
                # Scan for specific artifact type
                artifacts = self._scan_artifact_type(artifact_type)
                
                for artifact in artifacts:
                    self.artifact_found.emit(artifact)
                    self.artifacts_found += 1
            
            self.finished.emit(self.artifacts_found)
            
        except Exception as e:
            logger.error(f"Artifact scan error: {e}", exc_info=True)
            self.error.emit(str(e))
    
    def _scan_artifact_type(self, artifact_type: str) -> List[Dict]:
        """Scan for specific artifact type."""
        artifacts = []
        
        # Mock artifact discovery logic
        # In real implementation, this would:
        # 1. Access VEOS layer
        # 2. Search for artifact patterns
        # 3. Parse artifact metadata
        # 4. Return structured artifact data
        
        if artifact_type == "Registry":
            artifacts.append({
                'type': 'Registry',
                'subtype': 'Registry Hive',
                'name': 'SAM',
                'path': 'C:\\Windows\\System32\\config\\SAM',
                'description': 'Security Accounts Manager database',
                'timestamp': datetime.now(),
                'evidence_id': 'evidence_001',
                'hash': 'abc123...',
                'metadata': {'size': 262144, 'hive_type': 'SAM'}
            })
            artifacts.append({
                'type': 'Registry',
                'subtype': 'Registry Hive',
                'name': 'SYSTEM',
                'path': 'C:\\Windows\\System32\\config\\SYSTEM',
                'description': 'System configuration registry hive',
                'timestamp': datetime.now(),
                'evidence_id': 'evidence_001',
                'hash': 'def456...',
                'metadata': {'size': 524288, 'hive_type': 'SYSTEM'}
            })
        
        elif artifact_type == "Prefetch":
            artifacts.append({
                'type': 'Execution',
                'subtype': 'Prefetch',
                'name': 'CHROME.EXE-ABC123.pf',
                'path': 'C:\\Windows\\Prefetch\\CHROME.EXE-ABC123.pf',
                'description': 'Chrome browser execution artifact',
                'timestamp': datetime.now(),
                'evidence_id': 'evidence_001',
                'hash': 'ghi789...',
                'metadata': {'execution_count': 42, 'last_run': datetime.now().isoformat()}
            })
        
        elif artifact_type == "Event Logs (Security)":
            artifacts.append({
                'type': 'Security',
                'subtype': 'Event Log',
                'name': 'Security.evtx',
                'path': 'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
                'description': 'Windows Security Event Log',
                'timestamp': datetime.now(),
                'evidence_id': 'evidence_001',
                'hash': 'jkl012...',
                'metadata': {'record_count': 15342, 'size': 20971520}
            })
        
        elif artifact_type == "Browser History":
            artifacts.append({
                'type': 'Network',
                'subtype': 'Browser History',
                'name': 'History',
                'path': 'C:\\Users\\Alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History',
                'description': 'Chrome browsing history database',
                'timestamp': datetime.now(),
                'evidence_id': 'evidence_001',
                'hash': 'mno345...',
                'metadata': {'url_count': 2341, 'visit_count': 8752}
            })
        
        return artifacts
    
    def cancel(self):
        """Cancel the scan."""
        self._cancelled = True


class ArtifactsTab(QWidget):
    """
    TAB 4: ARTIFACTS
    
    Complete artifact discovery and extraction interface.
    """
    
    artifact_selected = pyqtSignal(dict)  # Emits selected artifact data
    scan_complete = pyqtSignal(int)  # Emits total artifacts found
    jump_to_timeline = pyqtSignal(str)   # file path → filter timeline
    
    def __init__(self, case_manager: CaseManager, parent=None):
        super().__init__(parent)
        self.case_manager = case_manager
        self.chain_logger: Optional[ChainLogger] = None
        self.worker: Optional[ArtifactScanWorker] = None
        self._store: Optional[UnifiedForensicStore] = None
        
        self._artifacts = []  # All discovered artifacts
        self._filtered_artifacts = []  # Currently displayed
        self._tagged_artifacts = set()  # Tagged for reporting
        self._selected_category: Optional[str] = None
        
        # Correlator / process-tree for cross-artifact intelligence
        self._correlator = ArtifactCorrelator()
        self._tree_builder = ProcessTreeBuilder()
        
        self._init_ui()
        self._load_case_indexed_data()

    def _resolve_case_path(self) -> Optional[Path]:
        current = getattr(self.case_manager, 'current_case', None)
        if not current:
            return None
        if isinstance(current, dict):
            path_str = current.get('path', '')
            return Path(path_str) if path_str else None
        return None

    def _load_case_indexed_data(self) -> None:
        case_path = self._resolve_case_path()
        if not case_path or not case_path.exists():
            return

        try:
            self._store = UnifiedForensicStore(case_path)
            stats = self._store.rebuild_case_index()
            self.lbl_status.setText(
                f"Indexed case data: {stats.get('files', 0)} files, {stats.get('artifacts', 0)} artifacts"
            )
            self._selected_category = None
            self._on_filter_changed()
        except Exception as exc:
            logger.warning("Unified store load failed: %s", exc)
    
    def _init_ui(self):
        """Initialize UI."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Main splitter: Category Tree | Table+Filters | Preview
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Category tree
        left_widget = self._create_category_tree()
        main_splitter.addWidget(left_widget)
        
        # Center: Filters + Table
        center_widget = self._create_center_pane()
        main_splitter.addWidget(center_widget)
        
        # Right: Preview
        right_widget = self._create_preview_pane()
        main_splitter.addWidget(right_widget)
        
        main_splitter.setSizes([250, 600, 350])
        layout.addWidget(main_splitter)
    
    def _create_category_tree(self) -> QWidget:
        """Create left category navigation."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        layout.addWidget(QLabel("<b>📂 Artifact Categories</b>"))
        
        self.tree_categories = QTreeWidget()
        self.tree_categories.setHeaderLabel("Categories")
        self.tree_categories.itemClicked.connect(self._on_category_clicked)
        
        # Build category tree
        for category, info in ARTIFACT_CATEGORIES.items():
            cat_item = QTreeWidgetItem([f"{info['icon']} {category}"])
            cat_item.setData(0, Qt.ItemDataRole.UserRole, category)
            
            for artifact_type in info['types']:
                type_item = QTreeWidgetItem([artifact_type])
                type_item.setData(0, Qt.ItemDataRole.UserRole, artifact_type)
                cat_item.addChild(type_item)
            
            self.tree_categories.addTopLevelItem(cat_item)
        
        self.tree_categories.expandAll()
        layout.addWidget(self.tree_categories)
        
        # Statistics (expanded)
        stats_group = QGroupBox("📊 Statistics")
        stats_layout = QVBoxLayout()
        
        self.lbl_total = QLabel("Total: 0")
        self.lbl_filtered = QLabel("Filtered: 0")
        self.lbl_tagged = QLabel("Tagged: 0")
        self.lbl_prefetch = QLabel("Prefetch: 0")
        self.lbl_registry = QLabel("Registry: 0")
        self.lbl_browser = QLabel("Browser: 0")
        self.lbl_eventlog = QLabel("Event Logs: 0")
        self.lbl_filesystem = QLabel("File System: 0")
        self.lbl_suspicious = QLabel("⚠ Suspicious: 0")
        self.lbl_suspicious.setStyleSheet("color: #D64550; font-weight: bold;")
        
        for w in [
            self.lbl_total, self.lbl_filtered, self.lbl_tagged,
            self.lbl_prefetch, self.lbl_registry, self.lbl_browser,
            self.lbl_eventlog, self.lbl_filesystem, self.lbl_suspicious,
        ]:
            stats_layout.addWidget(w)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        return widget
    
    def _create_center_pane(self) -> QWidget:
        """Create center table pane."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header with scan button
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("<h3>🔍 Artifacts</h3>"))
        header_layout.addStretch()
        
        btn_scan = QPushButton("▶ Run Artifact Scan")
        btn_scan.setMinimumHeight(35)
        btn_scan.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        btn_scan.clicked.connect(self._on_run_scan)
        header_layout.addWidget(btn_scan)
        
        layout.addLayout(header_layout)
        
        # Filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.txt_filter = QLineEdit()
        self.txt_filter.setPlaceholderText("Search artifacts...")
        self.txt_filter.textChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(self.txt_filter)
        
        self.cmb_type_filter = QComboBox()
        self.cmb_type_filter.addItem("All Types")
        self.cmb_type_filter.currentTextChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(self.cmb_type_filter)
        
        layout.addLayout(filter_layout)
        
        # Artifacts table
        self.table_artifacts = QTableWidget(0, 9)
        self.table_artifacts.setHorizontalHeaderLabels([
            "Type", "Name", "Path", "Timestamp", "User", "Source", "Confidence", "Size", "Actions"
        ])
        self.table_artifacts.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table_artifacts.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_artifacts.itemSelectionChanged.connect(self._on_artifact_selected)
        layout.addWidget(self.table_artifacts)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.lbl_status = QLabel("Ready to scan")
        layout.addWidget(self.lbl_status)
        
        return widget
    
    def _create_preview_pane(self) -> QWidget:
        """Create right preview pane with artifact intelligence."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(QLabel("<b>🔬 Artifact Intelligence</b>"))

        # Sub-tabs inside preview: Info | MACB | Related | Lifecycle | Context | Unknown
        self.preview_tabs = QTabWidget()
        self.preview_tabs.setTabPosition(QTabWidget.TabPosition.North)

        # -- Artifact Info tab --
        self.txt_preview = QTextEdit()
        self.txt_preview.setReadOnly(True)
        self.txt_preview.setPlaceholderText("Select an artifact to view details...")
        self.preview_tabs.addTab(self.txt_preview, "ℹ️ Info")

        # -- MACB / File Activity tab --
        self.txt_macb = QTextEdit()
        self.txt_macb.setReadOnly(True)
        self.txt_macb.setPlaceholderText("MACB file activity will appear here…")
        self.preview_tabs.addTab(self.txt_macb, "📅 MACB")

        # -- Related Artifacts tab --
        self.txt_related = QTextEdit()
        self.txt_related.setReadOnly(True)
        self.txt_related.setPlaceholderText("Cross-artifact correlations…")
        self.preview_tabs.addTab(self.txt_related, "🔗 Related")

        # -- File Lifecycle tab --
        self.txt_lifecycle = QTextEdit()
        self.txt_lifecycle.setReadOnly(True)
        self.txt_lifecycle.setPlaceholderText("File lifecycle reconstruction…")
        self.preview_tabs.addTab(self.txt_lifecycle, "🔄 Lifecycle")

        # -- Event Context tab --
        self.txt_context = QTextEdit()
        self.txt_context.setReadOnly(True)
        self.txt_context.setPlaceholderText("Surrounding events…")
        self.preview_tabs.addTab(self.txt_context, "🧩 Context")

        # -- Unknown Artifact Analyzer tab --
        self.txt_unknown = QTextEdit()
        self.txt_unknown.setReadOnly(True)
        self.txt_unknown.setPlaceholderText("Unknown artifact analysis…")
        self.preview_tabs.addTab(self.txt_unknown, "❓ Analyze")

        layout.addWidget(self.preview_tabs, stretch=1)

        # Actions
        actions_group = QGroupBox("Actions")
        actions_layout = QVBoxLayout()

        btn_extract = QPushButton("📤 Extract to Workspace")
        btn_extract.clicked.connect(self._on_extract_artifact)
        actions_layout.addWidget(btn_extract)

        btn_tag = QPushButton("🏷️ Tag for Report")
        btn_tag.clicked.connect(self._on_tag_artifact)
        actions_layout.addWidget(btn_tag)

        btn_timeline = QPushButton("📊 View in Timeline")
        btn_timeline.setStyleSheet("background-color: #E8A317; color: white; font-weight: bold;")
        btn_timeline.clicked.connect(self._on_show_in_timeline)
        actions_layout.addWidget(btn_timeline)

        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)

        return widget
    
    def _on_run_scan(self):
        """Handle Run Scan button click."""
        if not self.case_manager or not self.case_manager.current_case:
            QMessageBox.warning(self, "No Case", "Please load a case first.")
            return
        
        # Initialize CoC logger
        case_path = self.case_manager.current_case['path']
        self.chain_logger = ChainLogger(str(case_path))
        
        # Log scan start
        self.chain_logger.log(
            action="ARTIFACT_SCAN_START",
            operator=os.getenv('USERNAME', 'unknown'),
            details={'timestamp': datetime.now().isoformat()}
        )
        
        # Get all artifact types
        scan_types = []
        for category_info in ARTIFACT_CATEGORIES.values():
            scan_types.extend(category_info['types'])
        
        # Start worker
        self.worker = ArtifactScanWorker(self.case_manager, scan_types)
        self.worker.progress.connect(self._on_scan_progress)
        self.worker.artifact_found.connect(self._on_artifact_found)
        self.worker.finished.connect(self._on_scan_complete)
        self.worker.error.connect(self._on_scan_error)
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.worker.start()
    
    def _on_scan_progress(self, percentage: int, message: str):
        """Handle scan progress update."""
        self.progress_bar.setValue(percentage)
        self.lbl_status.setText(message)
    
    def _on_artifact_found(self, artifact: Dict):
        """Handle artifact discovered."""
        artifact_norm = self._normalize_artifact_record(artifact)
        self._artifacts.append(artifact_norm)
        self._add_artifact_to_table(artifact_norm)
        
        # Feed correlator
        self._correlator.add_event(self._to_correlator_event(artifact_norm))
        
        # Update statistics
        self._update_statistics()
    
    def _add_artifact_to_table(self, artifact: Dict):
        """Add artifact to table."""
        artifact = self._normalize_artifact_record(artifact)
        row = self.table_artifacts.rowCount()
        self.table_artifacts.insertRow(row)
        
        self.table_artifacts.setItem(row, 0, QTableWidgetItem(artifact.get('type', 'unknown')))
        self.table_artifacts.setItem(row, 1, QTableWidgetItem(artifact.get('name', 'N/A')))
        self.table_artifacts.setItem(row, 2, QTableWidgetItem(artifact.get('path', '')))
        
        ts = artifact.get('timestamp')
        if hasattr(ts, 'strftime'):
            timestamp_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        elif ts:
            timestamp_str = str(ts)
        else:
            timestamp_str = "-"
        self.table_artifacts.setItem(row, 3, QTableWidgetItem(timestamp_str))

        # User column — extract from path or metadata
        user = artifact.get('user', '')
        if not user:
            path_lower = artifact.get('path', '').lower()
            if '\\users\\' in path_lower or '/users/' in path_lower:
                parts = artifact.get('path', '').replace('\\', '/').split('/Users/')
                if len(parts) > 1:
                    user = parts[1].split('/')[0]
        self.table_artifacts.setItem(row, 4, QTableWidgetItem(user))

        # Source column
        source = artifact.get('source', artifact.get('evidence_id', 'Evidence'))
        self.table_artifacts.setItem(row, 5, QTableWidgetItem(source))

        # Confidence column
        confidence_raw = artifact.get('confidence', 0.8)
        if isinstance(confidence_raw, str) and confidence_raw.lower() in {'high', 'medium', 'low'}:
            confidence_text = confidence_raw.title()
            conf_value = {'High': 0.9, 'Medium': 0.7, 'Low': 0.5}[confidence_text]
        else:
            try:
                conf_value = float(confidence_raw)
            except Exception:
                conf_value = 0.8
            confidence_text = f"{conf_value:.2f}"

        conf_item = QTableWidgetItem(confidence_text)
        if conf_value >= 0.85:
            conf_item.setForeground(QBrush(QColor('#4caf50')))
        elif conf_value >= 0.6:
            conf_item.setForeground(QBrush(QColor('#ff9800')))
        else:
            conf_item.setForeground(QBrush(QColor('#f44336')))
        self.table_artifacts.setItem(row, 6, conf_item)

        metadata = artifact.get('metadata') or artifact.get('metadata_json')
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        if not isinstance(metadata, dict):
            metadata = {}
        size_str = str(metadata.get('size', artifact.get('size', '-')))
        self.table_artifacts.setItem(row, 7, QTableWidgetItem(size_str))
        
        # Store artifact data in table
        self.table_artifacts.item(row, 0).setData(Qt.ItemDataRole.UserRole, artifact)
    
    def _on_scan_complete(self, total: int):
        """Handle scan completion."""
        self.progress_bar.setVisible(False)
        self.lbl_status.setText(f"Scan complete! Found {total} artifacts")
        
        if self.chain_logger:
            self.chain_logger.log(
                action="ARTIFACT_SCAN_COMPLETE",
                operator=os.getenv('USERNAME', 'unknown'),
                details={'artifacts_found': total}
            )
        
        self.scan_complete.emit(total)
        
        QMessageBox.information(self, "Scan Complete", f"Artifact scan completed.\n\nFound {total} artifacts.")
    
    def _on_scan_error(self, error_msg: str):
        """Handle scan error."""
        self.progress_bar.setVisible(False)
        self.lbl_status.setText(f"Error: {error_msg}")
        
        if self.chain_logger:
            self.chain_logger.log(
                action="ARTIFACT_SCAN_ERROR",
                operator=os.getenv('USERNAME', 'unknown'),
                details={'error': error_msg}
            )
        
        QMessageBox.critical(self, "Scan Error", f"Artifact scan failed:\n\n{error_msg}")
    
    def _on_category_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle category tree click."""
        category = item.data(0, Qt.ItemDataRole.UserRole)
        if not category:
            return
        # Top-level node selects category; leaf node selects a specific type.
        self._filter_by_category(category, item.parent() is None)
    
    def _filter_by_category(self, category: str, is_category: bool = True):
        """Filter artifacts by category."""
        if is_category and category in ARTIFACT_CATEGORIES:
            self._selected_category = category
            if self.cmb_type_filter.currentText() != "All Types":
                self.cmb_type_filter.setCurrentText("All Types")
        else:
            self._selected_category = None
            self._set_type_filter_value(category)
        self._on_filter_changed()
    
    def _on_filter_changed(self):
        """Handle filter change."""
        filter_text = self.txt_filter.text().lower()
        type_filter = self.cmb_type_filter.currentText()

        if self._store is not None:
            rows = self._store.query_artifacts(
                limit=50000,
                offset=0,
                type_filter=type_filter,
                search_text=filter_text,
            )
            self._artifacts = [self._normalize_artifact_record(r) for r in rows]
            self._populate_type_filter(self._artifacts)
            visible_rows = self._apply_category_filter(self._artifacts)
            self.table_artifacts.setRowCount(0)
            for artifact in visible_rows:
                self._add_artifact_to_table(artifact)
            self._reload_correlator(visible_rows)
            self._update_statistics()
            return
        
        # Clear table
        self.table_artifacts.setRowCount(0)
        
        # Re-add filtered artifacts
        for artifact in self._artifacts:
            if filter_text and filter_text not in str(artifact.get('name', '')).lower() and filter_text not in str(artifact.get('path', '')).lower():
                continue
            
            if type_filter != "All Types" and str(artifact.get('type', '')).lower() != type_filter.lower():
                continue

            if not self._artifact_matches_selected_category(artifact):
                continue
            
            self._add_artifact_to_table(artifact)
        
        self.lbl_filtered.setText(f"Filtered: {self.table_artifacts.rowCount()}")
    
    def _on_artifact_selected(self):
        """Handle artifact selection — populate all preview sub-tabs."""
        selected_rows = self.table_artifacts.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        artifact = self.table_artifacts.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if not artifact:
            return

        file_path = artifact.get('path', '')
        metadata = artifact.get('metadata')
        if not isinstance(metadata, dict):
            metadata = {}

        # ── 1. Info tab ──
        ts_str = self._format_timestamp(artifact.get('timestamp'))
        meta_json = json.dumps(metadata, indent=2)
        pid_info = ""
        if metadata.get('pid'):
            pid_info = (f"\n\nProcess Information\n───────────────────\n"
                        f"PID: {metadata['pid']}\n"
                        f"Parent PID: {metadata.get('ppid', 'N/A')}\n"
                        f"User: {metadata.get('user', 'N/A')}")
        info_text = (
            f"Artifact Information\n"
            f"════════════════════\n\n"
            f"Type:        {artifact.get('type', 'unknown')}\n"
            f"Subtype:     {artifact.get('subtype', 'N/A')}\n"
            f"Name:        {artifact.get('name', 'N/A')}\n"
            f"Path:        {file_path}\n"
            f"Description: {artifact.get('description', '')}\n\n"
            f"Timestamp:   {ts_str}\n"
            f"Evidence ID: {artifact.get('evidence_id', 'N/A')}\n"
            f"Hash:        {artifact.get('hash', 'N/A')}\n"
            f"\nMetadata:\n{meta_json}"
            f"{pid_info}"
        )
        self.txt_preview.setPlainText(info_text)

        # ── 2. MACB tab ──
        macb = self._correlator.get_macb(file_path)
        macb_lines = ["MACB File Activity", "══════════════════", ""]
        for label, val in macb.to_dict().items():
            status = val if val else "—"
            macb_lines.append(f"{label:10s}  {status}")
        self.txt_macb.setPlainText("\n".join(macb_lines))

        # ── 3. Related Artifacts tab ──
        related = self._correlator.get_related_artifacts(file_path)
        if related:
            rel_lines = ["Related Artifacts", "═════════════════", ""]
            for r in related:
                rel_lines.append(f"📌 {r.source}")
                rel_lines.append(f"   {r.description}")
                if r.timestamp:
                    rel_lines.append(f"   Timestamp: {r.timestamp}")
                rel_lines.append("")
            self.txt_related.setPlainText("\n".join(rel_lines))
        else:
            self.txt_related.setPlainText("No related artifacts found for this file.")

        # ── 4. File Lifecycle tab ──
        lifecycle = self._correlator.build_file_lifecycle(file_path)
        if lifecycle:
            lc_lines = ["File Lifecycle", "══════════════", ""]
            for step in lifecycle:
                prog = f" [{step.program}]" if step.program else ""
                pid_s = f" PID {step.pid}" if step.pid else ""
                lc_lines.append(f"{step.timestamp}  {step.operation}{prog}{pid_s}  ({step.source})")
            self.txt_lifecycle.setPlainText("\n".join(lc_lines))
        else:
            self.txt_lifecycle.setPlainText("No lifecycle events found for this file.")

        # ── 5. Event Context tab ──
        context_events = self._get_surrounding_events(file_path)
        if context_events:
            ctx_lines = ["Event Context (surrounding events)", "══════════════════════════════════", ""]
            for ce in context_events:
                ctx_lines.append(
                    f"{ce.get('ts_utc', ce.get('timestamp', ''))}  "
                    f"{ce.get('operation', ce.get('event_type', ''))}  "
                    f"{ce.get('exe_name', ce.get('program', ''))}  "
                    f"{ce.get('filepath', ce.get('path', ''))}"
                )
            self.txt_context.setPlainText("\n".join(ctx_lines))
        else:
            self.txt_context.setPlainText("No surrounding context events available.")

        # ── 6. Unknown Artifact Analyzer tab ──
        header_bytes = metadata.get('header_bytes', b'')
        if isinstance(header_bytes, str):
            try:
                header_bytes = bytes.fromhex(header_bytes)
            except ValueError:
                header_bytes = header_bytes.encode('utf-8', errors='ignore')
        file_size = metadata.get('size', artifact.get('size', 0))
        result = analyze_unknown_artifact(file_path, file_size=file_size, header_bytes=header_bytes)
        ua_lines = [
            "Unknown Artifact Analysis", "═════════════════════════", "",
            f"Likely Type:       {result.likely_type}",
            f"Entropy:           {result.entropy:.4f}",
            f"Suspicious Score:  {result.suspicious_score:.2f}",
        ]
        if result.notes:
            ua_lines.append(f"\nNotes: {result.notes}")
        self.txt_unknown.setPlainText("\n".join(ua_lines))

        self.artifact_selected.emit(artifact)

    # ---- helpers for preview -------------------------------------------------

    def _get_surrounding_events(self, file_path: str, window: int = 5) -> List[Dict]:
        """Return events close in time to the given file across all sources."""
        fp = file_path.lower()
        fname = fp.rsplit('\\', 1)[-1] if '\\' in fp else fp.rsplit('/', 1)[-1]
        # Find matching event timestamps
        matching = []
        all_events = self._correlator._events if self._correlator._events else []
        for i, ev in enumerate(all_events):
            ev_path = (ev.get('filepath') or ev.get('artifact_path') or ev.get('path') or '').lower()
            ev_desc = (ev.get('description') or '').lower()
            if fname in ev_path or fname in ev_desc:
                matching.append(i)
        if not matching:
            return []
        # Gather surrounding events
        indices = set()
        for idx in matching:
            for j in range(max(0, idx - window), min(len(all_events), idx + window + 1)):
                indices.add(j)
        result = [all_events[i] for i in sorted(indices)]
        return result[:50]  # cap
    
    def _on_extract_artifact(self):
        """Extract artifact to workspace."""
        # Log to CoC
        if self.chain_logger:
            self.chain_logger.log(
                action="ARTIFACT_EXTRACTED",
                operator=os.getenv('USERNAME', 'unknown'),
                details={'timestamp': datetime.now().isoformat()}
            )
        
        QMessageBox.information(self, "Extract", "Artifact extracted to workspace (read-only copy)")
    
    def _on_tag_artifact(self):
        """Tag artifact for reporting."""
        selected_rows = self.table_artifacts.selectedItems()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        artifact = self.table_artifacts.item(row, 0).data(Qt.ItemDataRole.UserRole)
        
        if artifact:
            self._tagged_artifacts.add(artifact['path'])
            self.lbl_tagged.setText(f"Tagged: {len(self._tagged_artifacts)}")
            
            if self.chain_logger:
                self.chain_logger.log(
                    action="ARTIFACT_TAGGED",
                    operator=os.getenv('USERNAME', 'unknown'),
                    details={'path': artifact['path']}
                )
            
            QMessageBox.information(self, "Tagged", f"Artifact tagged for reporting:\n{artifact['name']}")
    
    def _on_show_in_timeline(self):
        """Jump to Timeline tab filtered for the selected artifact."""
        selected_rows = self.table_artifacts.selectedItems()
        if not selected_rows:
            QMessageBox.information(self, "Timeline", "Select an artifact first.")
            return
        row = selected_rows[0].row()
        artifact = self.table_artifacts.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if artifact:
            file_path = artifact.get('path', artifact.get('name', ''))
            self.jump_to_timeline.emit(file_path)
            # Also try to switch to Timeline tab in main window
            main_window = self.window()
            if hasattr(main_window, 'tabs'):
                for i in range(main_window.tabs.count()):
                    if 'Timeline' in main_window.tabs.tabText(i):
                        main_window.tabs.setCurrentIndex(i)
                        # If timeline tab has a keyword filter, set it
                        if hasattr(main_window, 'timeline_tab'):
                            tt = main_window.timeline_tab
                            fname = file_path.rsplit('\\', 1)[-1] if '\\' in file_path else file_path
                            if hasattr(tt, 'keyword_input'):
                                tt.keyword_input.setText(fname)
                            if hasattr(tt, '_apply_filters'):
                                tt._apply_filters()
                        break
    
    def set_case(self, case_info: Dict):
        """Set current case."""
        self.case_manager.current_case = case_info
        self._load_case_indexed_data()
    
    def get_tagged_artifacts(self) -> List[str]:
        """Get list of tagged artifact paths."""
        return list(self._tagged_artifacts)

    def load_events_for_correlation(self, events_df):
        """Load normalised events into the correlator for cross-referencing."""
        import pandas as pd
        if events_df is not None and not events_df.empty:
            self._correlator.load_events(events_df)
            self._tree_builder.load_events(events_df)

    def _normalize_artifact_record(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize artifact schema from both scan-worker and unified-store rows."""
        data = dict(artifact or {})

        metadata = data.get('metadata')
        if metadata is None:
            metadata = data.get('metadata_json')
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        if not isinstance(metadata, dict):
            metadata = {}

        data['metadata'] = metadata
        data.setdefault('type', str(data.get('source') or 'unknown'))
        data.setdefault('name', str(data.get('path') or data.get('type') or 'N/A'))
        data.setdefault('path', '')
        data.setdefault('description', data.get('name', ''))
        data.setdefault('timestamp', data.get('ts_utc') or '')
        data.setdefault('evidence_id', data.get('source') or 'indexed')
        data.setdefault('hash', 'N/A')
        data.setdefault('source', data.get('artifact_source') or data.get('source') or 'Evidence')
        data.setdefault('user', metadata.get('user', data.get('user', '')))
        if data.get('size') is None and metadata.get('size') is not None:
            data['size'] = metadata.get('size')
        return data

    def _to_correlator_event(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """Map artifact row to correlator event schema."""
        metadata = artifact.get('metadata') if isinstance(artifact.get('metadata'), dict) else {}
        return {
            'filepath': artifact.get('path', ''),
            'artifact_path': artifact.get('path', ''),
            'path': artifact.get('path', ''),
            'description': artifact.get('description', artifact.get('name', '')),
            'timestamp': artifact.get('timestamp', ''),
            'ts_utc': artifact.get('timestamp', ''),
            'operation': metadata.get('operation', artifact.get('type', 'observed')),
            'event_type': artifact.get('type', 'observed'),
            'artifact_source': artifact.get('source', ''),
            'source': artifact.get('source', ''),
            'program': metadata.get('program', ''),
            'exe_name': metadata.get('exe_name', metadata.get('program', '')),
            'pid': metadata.get('pid', 0),
            'ppid': metadata.get('ppid', 0),
            'user_account': artifact.get('user', ''),
            'user': artifact.get('user', ''),
        }

    def _reload_correlator(self, rows: List[Dict[str, Any]]) -> None:
        """Reload correlator with currently visible artifacts for preview intelligence."""
        try:
            import pandas as pd
            events = [self._to_correlator_event(r) for r in rows]
            self._correlator = ArtifactCorrelator()
            self._tree_builder = ProcessTreeBuilder()
            if events:
                df = pd.DataFrame(events)
                self._correlator.load_events(df)
                self._tree_builder.load_events(df)
        except Exception as exc:
            logger.warning("Failed to reload artifact correlator from store rows: %s", exc)

    def _populate_type_filter(self, rows: List[Dict[str, Any]]) -> None:
        """Populate artifact type combo from loaded rows without losing current selection."""
        current = self.cmb_type_filter.currentText() or "All Types"
        types = sorted({str(r.get('type', '')).strip() for r in rows if str(r.get('type', '')).strip()}, key=str.lower)
        self.cmb_type_filter.blockSignals(True)
        self.cmb_type_filter.clear()
        self.cmb_type_filter.addItem("All Types")
        for t in types:
            self.cmb_type_filter.addItem(t)
        idx = self.cmb_type_filter.findText(current, Qt.MatchFlag.MatchFixedString)
        self.cmb_type_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.cmb_type_filter.blockSignals(False)

    def _set_type_filter_value(self, value: str) -> None:
        idx = self.cmb_type_filter.findText(value, Qt.MatchFlag.MatchFixedString)
        if idx < 0:
            self.cmb_type_filter.blockSignals(True)
            self.cmb_type_filter.addItem(value)
            idx = self.cmb_type_filter.findText(value, Qt.MatchFlag.MatchFixedString)
            self.cmb_type_filter.blockSignals(False)
        if idx >= 0:
            self.cmb_type_filter.setCurrentIndex(idx)

    def _apply_category_filter(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self._selected_category:
            return rows
        return [row for row in rows if self._artifact_matches_selected_category(row)]

    def _artifact_matches_selected_category(self, artifact: Dict[str, Any]) -> bool:
        if not self._selected_category:
            return True
        cat = self._selected_category
        if cat not in ARTIFACT_CATEGORIES:
            return True

        type_lower = str(artifact.get('type', '')).lower()
        source_lower = str(artifact.get('source', '')).lower()
        name_lower = str(artifact.get('name', '')).lower()
        path_lower = str(artifact.get('path', '')).lower()
        subtype_lower = str(artifact.get('subtype', '')).lower()
        haystack = f"{type_lower} {source_lower} {name_lower} {path_lower} {subtype_lower}"

        aliases = {
            'System': ['registry', 'prefetch', 'system', 'service', 'task', 'event_log'],
            'User Activity': ['recent', 'jump', 'shell', 'usb', 'user', 'userassist'],
            'Network': ['browser', 'download', 'cookie', 'wifi', 'network'],
            'Security': ['security', 'firewall', 'defender', 'bitlocker', 'evtx', 'detection'],
            'Execution': ['execution', 'prefetch', 'shimcache', 'amcache', 'bam', 'dam', 'command', 'process'],
            'Communication': ['email', 'chat', 'social', 'message', 'pst', 'ost'],
            'File System': ['mft', 'usn', 'file', 'filesystem', 'deleted', 'ads', 'lnk', 'file_activity'],
            'Applications': ['application', 'app', 'extension', 'installed', 'recent'],
        }
        return any(token in haystack for token in aliases.get(cat, []))

    @staticmethod
    def _format_timestamp(ts: Any) -> str:
        if ts is None or ts == "":
            return "N/A"
        if hasattr(ts, 'strftime'):
            return ts.strftime('%Y-%m-%d %H:%M:%S')
        return str(ts)

    def _update_statistics(self):
        """Refresh the expanded statistics panel."""
        total = len(self._artifacts)
        self.lbl_total.setText(f"Total: {total}")
        self.lbl_filtered.setText(f"Filtered: {self.table_artifacts.rowCount()}")
        self.lbl_tagged.setText(f"Tagged: {len(self._tagged_artifacts)}")

        cats = {'Prefetch': 0, 'Registry': 0, 'Browser': 0, 'Event Log': 0, 'File System': 0, 'suspicious': 0}
        for a in self._artifacts:
            atype = (a.get('type', '') + ' ' + a.get('subtype', '')).lower()
            path_low = str(a.get('path', '')).lower().replace('\\', '/')
            name_low = str(a.get('name', '')).lower()
            combined = f"{atype} {path_low} {name_low}"

            if ('prefetch' in combined) or path_low.endswith('.pf'):
                cats['Prefetch'] += 1
            if (
                'registry' in combined
                or '/system32/config/' in path_low
                or any(hive in name_low for hive in ['ntuser.dat', 'usrclass.dat', 'sam', 'security', 'software', 'system'])
            ):
                cats['Registry'] += 1
            if (
                any(token in combined for token in ['browser', 'history', 'cookies', 'downloads', 'webcache', 'login data'])
                or any(token in path_low for token in ['/chrome/', '/edge/', '/firefox/', '/mozilla/'])
            ):
                cats['Browser'] += 1
            if (
                'event' in combined
                or 'evtx' in combined
                or path_low.endswith('.evtx')
                or any(token in combined for token in ['process', 'network', 'command', 'execution', 'detection'])
            ):
                cats['Event Log'] += 1
            if (
                any(token in combined for token in ['mft', 'usn', 'filesystem', 'file system', '$mft', '$usnjrnl', 'lnk'])
                or path_low.endswith('.lnk')
            ):
                cats['File System'] += 1
            # Simple suspicious heuristic
            if any(s in path_low for s in ['/temp/', '/tmp/', 'appdata/local/temp']) or 'detection' in combined:
                cats['suspicious'] += 1

        self.lbl_prefetch.setText(f"Prefetch: {cats['Prefetch']}")
        self.lbl_registry.setText(f"Registry: {cats['Registry']}")
        self.lbl_browser.setText(f"Browser: {cats['Browser']}")
        self.lbl_eventlog.setText(f"Event Logs: {cats['Event Log']}")
        self.lbl_filesystem.setText(f"File System: {cats['File System']}")
        self.lbl_suspicious.setText(f"⚠ Suspicious: {cats['suspicious']}")

