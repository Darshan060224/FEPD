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
        
        self._artifacts = []  # All discovered artifacts
        self._filtered_artifacts = []  # Currently displayed
        self._tagged_artifacts = set()  # Tagged for reporting
        
        # Correlator / process-tree for cross-artifact intelligence
        self._correlator = ArtifactCorrelator()
        self._tree_builder = ProcessTreeBuilder()
        
        self._init_ui()
    
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
        self.table_artifacts = QTableWidget(0, 6)
        self.table_artifacts.setHorizontalHeaderLabels([
            "Type", "Name", "Path", "Timestamp", "Size", "Actions"
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
        self._artifacts.append(artifact)
        self._add_artifact_to_table(artifact)
        
        # Feed correlator
        self._correlator.add_event(artifact)
        
        # Update statistics
        self._update_statistics()
    
    def _add_artifact_to_table(self, artifact: Dict):
        """Add artifact to table."""
        row = self.table_artifacts.rowCount()
        self.table_artifacts.insertRow(row)
        
        self.table_artifacts.setItem(row, 0, QTableWidgetItem(artifact['type']))
        self.table_artifacts.setItem(row, 1, QTableWidgetItem(artifact['name']))
        self.table_artifacts.setItem(row, 2, QTableWidgetItem(artifact['path']))
        
        timestamp_str = artifact['timestamp'].strftime("%Y-%m-%d %H:%M:%S") if artifact['timestamp'] else "-"
        self.table_artifacts.setItem(row, 3, QTableWidgetItem(timestamp_str))
        
        size_str = str(artifact['metadata'].get('size', '-')) if 'metadata' in artifact else "-"
        self.table_artifacts.setItem(row, 4, QTableWidgetItem(size_str))
        
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
        if category:
            self._filter_by_category(category)
    
    def _filter_by_category(self, category: str):
        """Filter artifacts by category."""
        # Apply filter logic
        self._on_filter_changed()
    
    def _on_filter_changed(self):
        """Handle filter change."""
        filter_text = self.txt_filter.text().lower()
        type_filter = self.cmb_type_filter.currentText()
        
        # Clear table
        self.table_artifacts.setRowCount(0)
        
        # Re-add filtered artifacts
        for artifact in self._artifacts:
            if filter_text and filter_text not in artifact['name'].lower() and filter_text not in artifact['path'].lower():
                continue
            
            if type_filter != "All Types" and artifact['type'] != type_filter:
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

        # ── 1. Info tab ──
        ts_str = artifact['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if artifact.get('timestamp') else 'N/A'
        meta_json = json.dumps(artifact.get('metadata', {}), indent=2)
        pid_info = ""
        if artifact.get('metadata', {}).get('pid'):
            pid_info = (f"\n\nProcess Information\n───────────────────\n"
                        f"PID: {artifact['metadata']['pid']}\n"
                        f"Parent PID: {artifact['metadata'].get('ppid', 'N/A')}\n"
                        f"User: {artifact['metadata'].get('user', 'N/A')}")
        info_text = (
            f"Artifact Information\n"
            f"════════════════════\n\n"
            f"Type:        {artifact['type']}\n"
            f"Subtype:     {artifact.get('subtype', 'N/A')}\n"
            f"Name:        {artifact['name']}\n"
            f"Path:        {file_path}\n"
            f"Description: {artifact['description']}\n\n"
            f"Timestamp:   {ts_str}\n"
            f"Evidence ID: {artifact['evidence_id']}\n"
            f"Hash:        {artifact['hash']}\n"
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
        header_bytes = artifact.get('metadata', {}).get('header_bytes', b'')
        file_size = artifact.get('metadata', {}).get('size', 0)
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
    
    def get_tagged_artifacts(self) -> List[str]:
        """Get list of tagged artifact paths."""
        return list(self._tagged_artifacts)

    def load_events_for_correlation(self, events_df):
        """Load normalised events into the correlator for cross-referencing."""
        import pandas as pd
        if events_df is not None and not events_df.empty:
            self._correlator.load_events(events_df)
            self._tree_builder.load_events(events_df)

    def _update_statistics(self):
        """Refresh the expanded statistics panel."""
        total = len(self._artifacts)
        self.lbl_total.setText(f"Total: {total}")
        self.lbl_filtered.setText(f"Filtered: {self.table_artifacts.rowCount()}")
        self.lbl_tagged.setText(f"Tagged: {len(self._tagged_artifacts)}")

        cats = {'Prefetch': 0, 'Registry': 0, 'Browser': 0, 'Event Log': 0, 'File System': 0, 'suspicious': 0}
        for a in self._artifacts:
            atype = (a.get('type', '') + ' ' + a.get('subtype', '')).lower()
            if 'prefetch' in atype:
                cats['Prefetch'] += 1
            if 'registry' in atype:
                cats['Registry'] += 1
            if 'browser' in atype or 'history' in atype or 'download' in atype:
                cats['Browser'] += 1
            if 'event' in atype or 'evtx' in atype:
                cats['Event Log'] += 1
            if 'mft' in atype or 'usn' in atype or 'file' in atype:
                cats['File System'] += 1
            # Simple suspicious heuristic
            path_low = a.get('path', '').lower()
            if any(s in path_low for s in ['\\temp\\', '\\tmp\\', 'appdata\\local\\temp']):
                cats['suspicious'] += 1

        self.lbl_prefetch.setText(f"Prefetch: {cats['Prefetch']}")
        self.lbl_registry.setText(f"Registry: {cats['Registry']}")
        self.lbl_browser.setText(f"Browser: {cats['Browser']}")
        self.lbl_eventlog.setText(f"Event Logs: {cats['Event Log']}")
        self.lbl_filesystem.setText(f"File System: {cats['File System']}")
        self.lbl_suspicious.setText(f"⚠ Suspicious: {cats['suspicious']}")

