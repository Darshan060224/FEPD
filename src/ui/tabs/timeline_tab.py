"""
FEPD - Forensic Evidence Parser Dashboard
Timeline Tab UI

Interactive timeline visualization with filtering and event detail display.

Implements FR-18, FR-19, FR-27: Timeline display, filtering, keyword search

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from typing import Optional, List, Dict, Any
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QGroupBox, QCheckBox, QLineEdit, QComboBox, QSlider,
    QDateTimeEdit, QTextEdit, QHeaderView, QAbstractItemView,
    QMessageBox, QTabWidget
)
from PyQt6.QtCore import Qt, QDateTime, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QFont
import pandas as pd

from src.analysis.artifact_correlator import (
    ArtifactCorrelator, ProcessTreeBuilder, AttackStoryGenerator,
    OPERATION_COLORS, ATTACK_PHASES, classify_phase, _normalise_operation,
)


class TimelineTab(QWidget):
    """
    Timeline visualization tab with filtering and event details.
    
    Features:
    - Vertical timeline sorted by timestamp
    - Color-coded by event classification
    - Filter panel (event class, severity, keywords, timestamps)
    - Event detail panel
    - UTC/Local time toggle
    """
    
    # Signals
    event_selected = pyqtSignal(dict)  # Emitted when event selected
    filter_changed = pyqtSignal()      # Emitted when filters change
    
    # Color scheme for classifications
    CLASSIFICATION_COLORS = {
        'USER_ACTIVITY': '#E9E9E9',
        'REMOTE_ACCESS': '#3C7DD9',
        'PERSISTENCE': '#E8C547',
        'STAGING': '#E8C547',
        'EXFIL_PREP': '#22B573',
        'ANTI_FORENSICS': '#D64550',
        'NORMAL': '#B3B5BB',
        'UNKNOWN': '#808080'
    }
    
    def __init__(self, parent=None, logger: Optional[logging.Logger] = None):
        super().__init__(parent)
        self.logger = logger or logging.getLogger(__name__)
        
        self.events_df: Optional[pd.DataFrame] = None
        self.filtered_df: Optional[pd.DataFrame] = None
        self.use_utc = True
        
        # Context drill-down state
        self._context_mode = False
        self._full_filtered_df: Optional[pd.DataFrame] = None  # saved before drill-down
        
        # Backend engines
        self._correlator = ArtifactCorrelator()
        self._tree_builder = ProcessTreeBuilder()
        self._story_generator = AttackStoryGenerator()
        
        self._init_ui()
    
    def _init_ui(self) -> None:
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Title and controls
        header_layout = QHBoxLayout()
        title = QLabel("⏱ Activity Timeline")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # UTC/Local toggle
        self.time_toggle = QComboBox()
        self.time_toggle.addItems(["UTC Time", "Local Time"])
        self.time_toggle.currentIndexChanged.connect(self._toggle_time_mode)
        header_layout.addWidget(QLabel("Display:"))
        header_layout.addWidget(self.time_toggle)
        
        # Refresh button
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self._apply_filters)
        header_layout.addWidget(self.refresh_btn)
        
        # Attack Story button
        self.story_btn = QPushButton("📜 Attack Story")
        self.story_btn.setStyleSheet("background-color: #9B59B6; color: white; font-weight: bold;")
        self.story_btn.clicked.connect(self._show_attack_story)
        header_layout.addWidget(self.story_btn)
        
        # Export button
        self.export_btn = QPushButton("💾 Export Filtered Events")
        self.export_btn.clicked.connect(self._export_events)
        header_layout.addWidget(self.export_btn)
        
        layout.addLayout(header_layout)
        
        # Main splitter (filter panel | timeline | detail panel)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Filter panel
        filter_widget = self._create_filter_panel()
        splitter.addWidget(filter_widget)
        
        # Center: Timeline table
        timeline_widget = self._create_timeline_table()
        splitter.addWidget(timeline_widget)
        
        # Right: Detail panel
        detail_widget = self._create_detail_panel()
        splitter.addWidget(detail_widget)
        
        # Set splitter proportions (1:3:1)
        splitter.setSizes([200, 600, 200])
        
        layout.addWidget(splitter)
        
        self.logger.info("Timeline Tab UI initialized")
    
    def _create_filter_panel(self) -> QWidget:
        """Create filter panel widget."""
        panel = QGroupBox("🔎 Filter Events")
        layout = QVBoxLayout(panel)
        
        # Event Class filters with better icons
        layout.addWidget(QLabel("<b>Event Class:</b>"))
        self.class_checks = {}
        classifications = [
            ('USER_ACTIVITY', '👤 User Activity'),
            ('REMOTE_ACCESS', '🌐 Remote Access'),
            ('PERSISTENCE', '🔒 Persistence'),
            ('STAGING', '📦 Staging'),
            ('EXFIL_PREP', '📤 Data Preparation'),
            ('ANTI_FORENSICS', '🛡️ Anti-Forensics'),
            ('NORMAL', '✅ Normal Activity'),
            ('ADMIN_ACTION', '⚙️ Admin Action'),
            ('DELETION', '🗑️ Deletion'),
            ('EXECUTION', '▶️ Execution')
        ]
        for cls_id, cls_name in classifications:
            cb = QCheckBox(cls_name)
            cb.setChecked(True)
            cb.stateChanged.connect(self.filter_changed.emit)
            self.class_checks[cls_id] = cb
            layout.addWidget(cb)
        
        layout.addSpacing(10)
        
        # Severity filter
        layout.addWidget(QLabel("<b>Severity Level (1-5):</b>"))
        severity_layout = QHBoxLayout()
        self.severity_min = QSlider(Qt.Orientation.Horizontal)
        self.severity_min.setRange(1, 5)
        self.severity_min.setValue(1)
        self.severity_min.valueChanged.connect(self.filter_changed.emit)
        self.severity_max = QSlider(Qt.Orientation.Horizontal)
        self.severity_max.setRange(1, 5)
        self.severity_max.setValue(5)
        self.severity_max.valueChanged.connect(self.filter_changed.emit)
        severity_layout.addWidget(QLabel("Min:"))
        severity_layout.addWidget(self.severity_min)
        severity_layout.addWidget(QLabel("Max:"))
        severity_layout.addWidget(self.severity_max)
        layout.addLayout(severity_layout)
        
        layout.addSpacing(10)
        
        # Keyword search
        layout.addWidget(QLabel("<b>🔤 Keyword Filter:</b>"))
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText("Search in descriptions...")
        self.keyword_input.returnPressed.connect(self._apply_filters)
        layout.addWidget(self.keyword_input)
        
        layout.addSpacing(10)
        
        # Artifact source filter
        layout.addWidget(QLabel("<b>📂 Data Source:</b>"))
        self.source_combo = QComboBox()
        self.source_combo.addItems(['All', 'EVTX', 'Registry', 'Prefetch', 'MFT', 'Browser'])
        self.source_combo.currentIndexChanged.connect(self.filter_changed.emit)
        layout.addWidget(self.source_combo)
        
        layout.addSpacing(10)
        
        # User filter
        layout.addWidget(QLabel("<b>👤 User Account:</b>"))
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Filter by username...")
        self.user_input.returnPressed.connect(self._apply_filters)
        layout.addWidget(self.user_input)
        
        layout.addSpacing(10)

        # PID filter
        layout.addWidget(QLabel("<b>🔢 PID / Process Filter:</b>"))
        self.pid_input = QLineEdit()
        self.pid_input.setPlaceholderText("Filter by PID…")
        self.pid_input.returnPressed.connect(self._apply_filters)
        layout.addWidget(self.pid_input)

        self.process_input = QLineEdit()
        self.process_input.setPlaceholderText("Filter by process name…")
        self.process_input.returnPressed.connect(self._apply_filters)
        layout.addWidget(self.process_input)

        layout.addSpacing(10)
        
        # Timestamp range
        layout.addWidget(QLabel("<b>⏱ Time Range (From - To):</b>"))
        self.start_time = QDateTimeEdit()
        self.start_time.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.start_time.dateTimeChanged.connect(self.filter_changed.emit)
        layout.addWidget(QLabel("Start:"))
        layout.addWidget(self.start_time)
        
        self.end_time = QDateTimeEdit()
        self.end_time.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.end_time.dateTimeChanged.connect(self.filter_changed.emit)
        layout.addWidget(QLabel("End:"))
        layout.addWidget(self.end_time)
        
        layout.addSpacing(10)
        
        # Time-of-day filter (24h slider)
        layout.addWidget(QLabel("<b>🕐 Time of Day Filter:</b>"))
        tod_layout = QHBoxLayout()
        self.tod_min = QSlider(Qt.Orientation.Horizontal)
        self.tod_min.setRange(0, 23)
        self.tod_min.setValue(0)
        self.tod_min.valueChanged.connect(self._update_tod_labels)
        self.tod_max = QSlider(Qt.Orientation.Horizontal)
        self.tod_max.setRange(0, 23)
        self.tod_max.setValue(23)
        self.tod_max.valueChanged.connect(self._update_tod_labels)
        
        self.tod_min_label = QLabel("00:00")
        self.tod_max_label = QLabel("23:00")
        
        tod_layout.addWidget(self.tod_min_label)
        tod_layout.addWidget(self.tod_min)
        tod_layout.addWidget(QLabel("-"))
        tod_layout.addWidget(self.tod_max)
        tod_layout.addWidget(self.tod_max_label)
        layout.addLayout(tod_layout)
        
        layout.addSpacing(10)
        
        # Timezone toggle
        layout.addWidget(QLabel("<b>🌍 Timezone:</b>"))
        timezone_layout = QHBoxLayout()
        self.tz_utc_radio = QCheckBox("UTC")
        self.tz_utc_radio.setChecked(True)
        self.tz_local_radio = QCheckBox("Local")
        self.tz_utc_radio.toggled.connect(self._on_timezone_changed)
        self.tz_local_radio.toggled.connect(self._on_timezone_changed)
        timezone_layout.addWidget(self.tz_utc_radio)
        timezone_layout.addWidget(self.tz_local_radio)
        timezone_layout.addStretch()
        layout.addLayout(timezone_layout)
        layout.addWidget(self.end_time)
        
        layout.addSpacing(20)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        apply_btn = QPushButton("Apply Filters")
        apply_btn.clicked.connect(self._apply_filters)
        reset_btn = QPushButton("Reset")
        reset_btn.clicked.connect(self._reset_filters)
        btn_layout.addWidget(apply_btn)
        btn_layout.addWidget(reset_btn)
        layout.addLayout(btn_layout)
        
        layout.addStretch()
        
        return panel
    
    def _create_timeline_table(self) -> QWidget:
        """Create timeline table widget with PID / Operation columns."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        # Context-mode banner (hidden by default)
        self._context_bar = QWidget()
        ctx_layout = QHBoxLayout(self._context_bar)
        ctx_layout.setContentsMargins(4, 4, 4, 4)
        ctx_lbl = QLabel("🔍 <b>Context Mode</b> — showing related events only")
        ctx_lbl.setStyleSheet("color: #9B59B6;")
        ctx_layout.addWidget(ctx_lbl)
        ctx_layout.addStretch()
        self.btn_clear_context = QPushButton("✖ Back to Full Timeline")
        self.btn_clear_context.setStyleSheet("background-color: #D64550; color: white; font-weight: bold;")
        self.btn_clear_context.clicked.connect(self._clear_context_mode)
        ctx_layout.addWidget(self.btn_clear_context)
        self._context_bar.setVisible(False)
        layout.addWidget(self._context_bar)

        # Event count label
        self.event_count_label = QLabel("Events: 0")
        self.event_count_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.event_count_label)
        
        # Table — 12 columns
        self.timeline_table = QTableWidget()
        self.timeline_table.setColumnCount(12)
        self.timeline_table.setHorizontalHeaderLabels([
            'Time', 'Event Type', 'Level', 'Operation', 'Activity',
            'User', 'Program', 'PID', 'PPID', 'Path', 'Source', 'Details'
        ])
        
        # Table properties
        self.timeline_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.timeline_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.timeline_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.timeline_table.setAlternatingRowColors(True)
        self.timeline_table.setSortingEnabled(True)
        
        # Column widths
        header = self.timeline_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)   # Time
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)   # Event Type
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)   # Level
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)   # Operation
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)         # Activity
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)         # User
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)         # Program
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)   # PID
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)   # PPID
        header.setSectionResizeMode(9, QHeaderView.ResizeMode.Interactive)         # Path
        header.setSectionResizeMode(10, QHeaderView.ResizeMode.ResizeToContents)  # Source
        header.setSectionResizeMode(11, QHeaderView.ResizeMode.Stretch)           # Details
        
        # Connect selection signal
        self.timeline_table.itemSelectionChanged.connect(self._on_event_selected)
        
        # Connect cell click signal for popup details
        self.timeline_table.cellClicked.connect(self._on_cell_clicked)

        # Double-click → context drill-down
        self.timeline_table.cellDoubleClicked.connect(self._on_event_double_clicked)
        
        layout.addWidget(self.timeline_table)
        
        return container
    
    def _create_detail_panel(self) -> QWidget:
        """Create event detail panel with process context."""
        panel = QGroupBox("Event Details")
        layout = QVBoxLayout(panel)

        self.detail_tabs = QTabWidget()

        # -- Event details tab --
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setPlaceholderText("Select an event to view details...")
        self.detail_tabs.addTab(self.detail_text, "ℹ️ Details")

        # -- Process context tab --
        self.process_context_text = QTextEdit()
        self.process_context_text.setReadOnly(True)
        self.process_context_text.setPlaceholderText("Process tree context…")
        self.detail_tabs.addTab(self.process_context_text, "🌳 Process Tree")

        # -- Attack Story tab --
        self.story_text = QTextEdit()
        self.story_text.setReadOnly(True)
        self.story_text.setPlaceholderText("Generate attack story from filtered events…")
        self.detail_tabs.addTab(self.story_text, "📜 Story")

        layout.addWidget(self.detail_tabs)

        # Action buttons
        btn_layout = QHBoxLayout()
        self.note_btn = QPushButton("Add Note")
        self.note_btn.setEnabled(False)
        self.note_btn.clicked.connect(self._add_note)
        
        self.report_btn = QPushButton("Send to Report")
        self.report_btn.setEnabled(False)
        self.report_btn.clicked.connect(self._send_to_report)
        
        btn_layout.addWidget(self.note_btn)
        btn_layout.addWidget(self.report_btn)
        layout.addLayout(btn_layout)
        
        return panel
    
    def load_events(self, events_df: pd.DataFrame) -> None:
        """Load events DataFrame into timeline."""
        self.events_df = events_df.copy()
        self.logger.info(f"Loaded {len(self.events_df)} events into timeline")

        # Ensure PID / PPID / operation columns exist
        for col in ('pid', 'ppid', 'operation'):
            if col not in self.events_df.columns:
                self.events_df[col] = 0 if col in ('pid', 'ppid') else ''

        # Feed correlator / tree / story engines
        self._correlator.load_events(self.events_df)
        self._tree_builder.load_events(self.events_df)
        
        # Set timestamp range filters to data bounds
        if not self.events_df.empty and 'ts_utc' in self.events_df.columns:
            min_ts = pd.to_datetime(self.events_df['ts_utc']).min()
            max_ts = pd.to_datetime(self.events_df['ts_utc']).max()
            
            self.start_time.setDateTime(QDateTime.fromString(str(min_ts), Qt.DateFormat.ISODate))
            self.end_time.setDateTime(QDateTime.fromString(str(max_ts), Qt.DateFormat.ISODate))
        
        self._apply_filters()
    
    def _apply_filters(self) -> None:
        """Apply current filters to events and update table."""
        if self.events_df is None or self.events_df.empty:
            self.logger.warning("No events loaded")
            return
        
        # Exit context mode when user explicitly re-filters
        if self._context_mode:
            self._context_mode = False
            self._context_bar.setVisible(False)
        
        self.logger.info("Applying filters...")
        
        filtered = self.events_df.copy()
        
        # Classification
        selected_classes = [cls for cls, cb in self.class_checks.items() if cb.isChecked()]
        if selected_classes and 'rule_class' in filtered.columns:
            filtered = filtered[filtered['rule_class'].isin(selected_classes)]
        
        # Severity
        min_sev = self.severity_min.value()
        max_sev = self.severity_max.value()
        if 'severity' in filtered.columns:
            filtered = filtered[
                (filtered['severity'] >= min_sev) & 
                (filtered['severity'] <= max_sev)
            ]
        
        # Keyword
        keyword = self.keyword_input.text().strip()
        if keyword and 'description' in filtered.columns:
            filtered = filtered[
                filtered['description'].str.contains(keyword, case=False, na=False, regex=True)
            ]
        
        # Source
        source = self.source_combo.currentText()
        if source != 'All' and 'artifact_source' in filtered.columns:
            filtered = filtered[filtered['artifact_source'] == source]
        
        # User
        user = self.user_input.text().strip()
        if user and 'user_account' in filtered.columns:
            filtered = filtered[
                filtered['user_account'].str.contains(user, case=False, na=False)
            ]

        # PID
        pid_text = self.pid_input.text().strip()
        if pid_text and pid_text.isdigit() and 'pid' in filtered.columns:
            filtered = filtered[filtered['pid'].astype(str) == pid_text]

        # Process name
        proc = self.process_input.text().strip()
        if proc:
            exe_col = 'exe_name' if 'exe_name' in filtered.columns else 'program'
            if exe_col in filtered.columns:
                filtered = filtered[
                    filtered[exe_col].str.contains(proc, case=False, na=False)
                ]
        
        self.filtered_df = filtered
        self._populate_table()
        
        self.logger.info(f"Filters applied: {len(self.filtered_df)} events match")
    
    def _populate_table(self) -> None:
        """Populate timeline table with filtered events (12 columns)."""
        if self.filtered_df is None or self.filtered_df.empty:
            self.timeline_table.setRowCount(0)
            self.event_count_label.setText("Events: 0")
            return
        
        self.timeline_table.setSortingEnabled(False)
        self.timeline_table.setRowCount(len(self.filtered_df))
        
        for row_idx, (_, event) in enumerate(self.filtered_df.iterrows()):
            # 0 - Time
            ts = event.get('ts_utc', '') if self.use_utc else event.get('ts_local', '')
            ts_item = QTableWidgetItem(str(ts))
            self.timeline_table.setItem(row_idx, 0, ts_item)
            
            # 1 - Event Type (classification)
            rule_class = str(event.get('rule_class', 'UNKNOWN'))
            self.timeline_table.setItem(row_idx, 1, QTableWidgetItem(rule_class))
            
            # 2 - Level (severity)
            severity = str(event.get('severity', ''))
            self.timeline_table.setItem(row_idx, 2, QTableWidgetItem(severity))
            
            # 3 - Operation (color-coded)
            raw_op = str(event.get('operation', event.get('event_type', '')))
            norm_op = _normalise_operation(raw_op) if raw_op else ''
            op_item = QTableWidgetItem(norm_op)
            op_color = OPERATION_COLORS.get(norm_op)
            if op_color:
                op_item.setForeground(QBrush(QColor(op_color)))
                op_item.setFont(QFont('', -1, QFont.Weight.Bold))
            self.timeline_table.setItem(row_idx, 3, op_item)
            
            # 4 - Activity (event_type / description)
            activity = str(event.get('event_type', ''))
            self.timeline_table.setItem(row_idx, 4, QTableWidgetItem(activity))
            
            # 5 - User
            user = str(event.get('user_account', event.get('user', '')))
            self.timeline_table.setItem(row_idx, 5, QTableWidgetItem(user))
            
            # 6 - Program
            exe = str(event.get('exe_name', event.get('program', '')))
            self.timeline_table.setItem(row_idx, 6, QTableWidgetItem(exe))
            
            # 7 - PID
            pid_val = str(int(event.get('pid', 0))) if event.get('pid') else ''
            self.timeline_table.setItem(row_idx, 7, QTableWidgetItem(pid_val))
            
            # 8 - PPID
            ppid_val = str(int(event.get('ppid', 0))) if event.get('ppid') else ''
            self.timeline_table.setItem(row_idx, 8, QTableWidgetItem(ppid_val))
            
            # 9 - Path
            path = str(event.get('filepath', event.get('artifact_path', '')))
            self.timeline_table.setItem(row_idx, 9, QTableWidgetItem(path))
            
            # 10 - Source
            src = str(event.get('artifact_source', event.get('source', '')))
            self.timeline_table.setItem(row_idx, 10, QTableWidgetItem(src))
            
            # 11 - Details
            desc = str(event.get('description', ''))
            self.timeline_table.setItem(row_idx, 11, QTableWidgetItem(desc))
            
            # Row background: context-mode colouring or classification
            if self._context_mode:
                self._apply_context_row_color(row_idx, event)
            else:
                color = self._get_classification_color(rule_class)
                for col in range(12):
                    item = self.timeline_table.item(row_idx, col)
                    if item:
                        item.setBackground(QBrush(QColor(color)))
        
        self.timeline_table.setSortingEnabled(True)
        self.timeline_table.sortItems(0, Qt.SortOrder.DescendingOrder)
        
        suffix = "  (Context Mode)" if self._context_mode else ""
        self.event_count_label.setText(f"Events: {len(self.filtered_df)}{suffix}")
    
    def _get_classification_color(self, classification: str) -> str:
        """Get color for classification."""
        return self.CLASSIFICATION_COLORS.get(classification, self.CLASSIFICATION_COLORS['UNKNOWN'])

    def _apply_context_row_color(self, row_idx: int, event: Any) -> None:
        """Apply context-mode row colouring based on relationship to triggered event."""
        if not self._context_event:
            return
        ctx_pid = self._context_event.get('pid')
        ev_pid = event.get('pid')
        ev_ppid = event.get('ppid')
        # Triggered event itself
        if ctx_pid and ev_pid and str(ev_pid) == str(ctx_pid) and str(event.get('ts_utc','')) == str(self._context_event.get('ts_utc','')):
            bg = '#FFF9C4'  # yellow
        elif ctx_pid and ev_ppid and str(ev_ppid) == str(ctx_pid):
            bg = '#FFCC80'  # orange – child
        elif ctx_pid and ev_pid and str(ev_pid) == str(self._context_event.get('ppid','')):
            bg = '#BBDEFB'  # blue – parent
        elif ctx_pid and ev_pid and str(ev_pid) == str(ctx_pid):
            bg = '#C8E6C9'  # green – same PID
        else:
            bg = '#FFFFFF'
        for col in range(12):
            item = self.timeline_table.item(row_idx, col)
            if item:
                item.setBackground(QBrush(QColor(bg)))

    def _on_event_selected(self) -> None:
        """Handle event selection in table."""
        selected = self.timeline_table.selectedItems()
        if not selected:
            return
        
        row = selected[0].row()
        
        if self.filtered_df is not None and row < len(self.filtered_df):
            event = self.filtered_df.iloc[row].to_dict()
            
            self._display_event_details(event)
            self._populate_process_context(event)
            
            self.note_btn.setEnabled(True)
            self.report_btn.setEnabled(True)
            self.event_selected.emit(event)

    def _populate_process_context(self, event: Dict[str, Any]) -> None:
        """Populate the process context panel for the selected event."""
        pid = event.get('pid')
        if not pid or int(pid) == 0:
            self.process_context_text.setHtml("<i>No PID data for this event.</i>")
            return
        pid = int(pid)
        node = self._tree_builder._nodes.get(pid)
        if not node:
            self.process_context_text.setHtml(f"<i>PID {pid} not found in process tree.</i>")
            return
        root_pid = self._tree_builder.get_root_pid(pid)
        tree_text = self._tree_builder.get_tree_text(root_pid)
        html_lines = []
        for line in tree_text.split('\n'):
            if f"PID {pid})" in line:
                html_lines.append(f"<span style='color:#FDD835;font-weight:bold;'>{line}</span>")
            else:
                html_lines.append(f"<span style='color:#90CAF9;'>{line}</span>")
        self.process_context_text.setHtml(
            "<pre style='font-family:monospace;font-size:13px;'>"
            + "<br>".join(html_lines)
            + "</pre>"
        )
    
    def _on_cell_clicked(self, row: int, column: int) -> None:
        """Handle cell click - show enhanced popup with event details."""
        from src.ui.dialogs.timeline_event_dialog import TimelineEventDetailDialog
        
        # Get event data from filtered DataFrame
        if self.filtered_df is None or row >= len(self.filtered_df):
            return
        
        event = self.filtered_df.iloc[row].to_dict()
        
        # Create and show enhanced detail dialog
        dialog = TimelineEventDetailDialog(event, self)
        dialog.show_artifact.connect(self._navigate_to_artifact)
        dialog.exec()
    
    def _display_event_details(self, event: Dict[str, Any]) -> None:
        """Display event details in detail panel."""
        details = []
        details.append(f"<b>Event ID:</b> {event.get('event_id', 'N/A')}")
        details.append(f"<b>Timestamp (UTC):</b> {event.get('ts_utc', 'N/A')}")
        details.append(f"<b>Timestamp (Local):</b> {event.get('ts_local', 'N/A')}")
        details.append(f"<b>Classification:</b> {event.get('rule_class', 'UNKNOWN')}")
        details.append(f"<b>Severity:</b> {event.get('severity', 'N/A')}")
        details.append(f"<b>Artifact Source:</b> {event.get('artifact_source', 'N/A')}")
        details.append(f"<b>Artifact Path:</b> {event.get('artifact_path', 'N/A')}")
        details.append(f"<b>Event Type:</b> {event.get('event_type', 'N/A')}")
        
        if event.get('user_account'):
            details.append(f"<b>User Account:</b> {event.get('user_account')}")
        
        if event.get('exe_name'):
            details.append(f"<b>Executable:</b> {event.get('exe_name')}")
        
        if event.get('event_id_native'):
            details.append(f"<b>Native Event ID:</b> {event.get('event_id_native')}")
        
        if event.get('filepath'):
            details.append(f"<b>File Path:</b> {event.get('filepath')}")
        
        if event.get('macb'):
            details.append(f"<b>MACB:</b> {event.get('macb')}")
        
        if event.get('operation'):
            details.append(f"<b>Operation:</b> {event.get('operation')}")

        if event.get('pid'):
            details.append(f"<b>PID:</b> {event.get('pid')}")
        if event.get('ppid'):
            details.append(f"<b>PPID:</b> {event.get('ppid')}")

        details.append(f"<br><b>Description:</b><br>{event.get('description', 'No description')}")
        
        html = "<br>".join(details)
        self.detail_text.setHtml(html)
    
    def _toggle_time_mode(self) -> None:
        """Toggle between UTC and Local time display."""
        self.use_utc = (self.time_toggle.currentIndex() == 0)
        self.logger.info(f"Time mode: {'UTC' if self.use_utc else 'Local'}")
        
        # Refresh table to update timestamps
        self._populate_table()
    
    def _update_tod_labels(self) -> None:
        """Update time-of-day filter labels."""
        min_hour = self.tod_min.value()
        max_hour = self.tod_max.value()
        self.tod_min_label.setText(f"{min_hour:02d}:00")
        self.tod_max_label.setText(f"{max_hour:02d}:00")
        self.filter_changed.emit()
    
    def _on_timezone_changed(self) -> None:
        """Handle timezone checkbox changes."""
        if self.tz_utc_radio.isChecked():
            self.tz_local_radio.setChecked(False)
            self.use_utc = True
        else:
            self.tz_utc_radio.setChecked(False)
            self.use_utc = False
        self._populate_table()
    
    def _reset_filters(self) -> None:
        """Reset all filters to default values."""
        # Reset classification checkboxes
        for cb in self.class_checks.values():
            cb.setChecked(True)
        
        # Reset severity
        self.severity_min.setValue(1)
        self.severity_max.setValue(5)
        
        # Clear keyword
        self.keyword_input.clear()
        
        # Reset source
        self.source_combo.setCurrentIndex(0)
        
        # Clear user
        self.user_input.clear()

        # Clear PID / process
        self.pid_input.clear()
        if hasattr(self, 'ppid_input'):
            self.ppid_input.clear()
        self.process_input.clear()
        
        # Reset timestamp range
        if self.events_df is not None and not self.events_df.empty:
            min_ts = pd.to_datetime(self.events_df['ts_utc']).min()
            max_ts = pd.to_datetime(self.events_df['ts_utc']).max()
            self.start_time.setDateTime(QDateTime.fromString(str(min_ts), Qt.DateFormat.ISODate))
            self.end_time.setDateTime(QDateTime.fromString(str(max_ts), Qt.DateFormat.ISODate))
        
        self.logger.info("Filters reset")
        self._apply_filters()
    
    def _add_note(self) -> None:
        """Add note to selected event (placeholder)."""
        self.logger.info("Add note button clicked (feature not implemented)")
        # TODO: Implement note dialog
    
    def _send_to_report(self) -> None:
        """Send selected event to report (placeholder)."""
        self.logger.info("Send to report button clicked (feature not implemented)")
        # TODO: Implement report integration
    
    def _export_events(self) -> None:
        """Export filtered events to CSV file."""
        from PyQt6.QtWidgets import QFileDialog
        from datetime import datetime
        
        if self.filtered_df is None or self.filtered_df.empty:
            self.logger.warning("No events to export")
            return
        
        # Default filename with timestamp
        default_name = f"timeline_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Timeline Events",
            default_name,
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                self.export_filtered_events(Path(file_path))
                self.logger.info(f"Exported {len(self.filtered_df)} events to {file_path}")
            except Exception as e:
                self.logger.error(f"Failed to export events: {e}")
    
    def export_filtered_events(self, output_path: Path) -> None:
        """
        Export currently filtered events to CSV.
        
        Args:
            output_path: Path to output CSV file
        """
        if self.filtered_df is None or self.filtered_df.empty:
            self.logger.warning("No filtered events to export")
            return
        
        self.filtered_df.to_csv(output_path, index=False)
        self.logger.info(f"Exported {len(self.filtered_df)} events to {output_path}")
    
    def _navigate_to_artifact(self, artifact: dict):
        """
        Navigate to artifacts tab and highlight/filter for this artifact.
        
        Args:
            artifact: Artifact dictionary from timeline event
        """
        main_window = self.window()
        
        if hasattr(main_window, 'tabs'):
            # Find and switch to artifacts tab
            for i in range(main_window.tabs.count()):
                tab_text = main_window.tabs.tabText(i)
                if 'Artifact' in tab_text:
                    main_window.tabs.setCurrentIndex(i)
                    self.logger.info(f"Switched to artifacts tab for: {artifact.get('name')}")
                    
                    # Try to filter artifacts
                    if hasattr(main_window, 'artifacts_tab'):
                        # TODO: Call artifacts tab's filter method
                        # main_window.artifacts_tab.filter_by_name(artifact.get('name'))
                        pass
                    
                    break
        
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.information(
            self,
            "Artifact Navigation",
            f"Navigated to Artifacts tab.\n\n"
            f"Artifact: {artifact.get('name', 'Unknown')}\n"
            f"Type: {artifact.get('type', 'Unknown')}\n\n"
            f"Artifacts list will be filtered to show this item."
        )

    # ─────────── Context drill-down ───────────────────────────────────

    def _on_event_double_clicked(self, row: int, column: int) -> None:
        """Double-click an event row to enter context / drill-down mode."""
        if self.filtered_df is None or row >= len(self.filtered_df):
            return
        event = self.filtered_df.iloc[row].to_dict()
        pid = event.get('pid')
        if not pid or int(pid) == 0:
            return
        self._enter_context_mode(event)

    def _enter_context_mode(self, event: Dict[str, Any]) -> None:
        """Show only events related to the selected event's process chain."""
        pid = int(event.get('pid', 0))
        if pid == 0:
            return
        related_pids = self._tree_builder.get_related_pids(pid)
        # Save full filtered view
        self._full_filtered_df = self.filtered_df.copy()
        self._context_event = event
        self._context_mode = True
        # Filter to related PIDs
        self.filtered_df = self._full_filtered_df[
            self._full_filtered_df['pid'].isin(related_pids)
        ].copy()
        self._context_bar.setVisible(True)
        self._populate_table()

    def _clear_context_mode(self) -> None:
        """Exit context mode and restore all events."""
        self._context_mode = False
        self._context_event = None
        self._context_bar.setVisible(False)
        if self._full_filtered_df is not None:
            self.filtered_df = self._full_filtered_df
            self._full_filtered_df = None
        self._populate_table()

    # ─────────── Attack story ─────────────────────────────────────────

    def _show_attack_story(self) -> None:
        """Generate and display an attack-story narrative."""
        df = self.filtered_df if self.filtered_df is not None else self.events_df
        if df is None or df.empty:
            QMessageBox.information(self, "Attack Story", "No events to analyse.")
            return
        steps = self._story_generator.generate(df)
        if not steps:
            self.story_text.setHtml("<i>No attack phases identified in current events.</i>")
            self.detail_tabs.setCurrentWidget(self.story_text)
            return
        grouped = self._story_generator.group_by_phase(steps)
        html_parts = ["<h3>⚔ Attack Story</h3>"]
        phase_icons = {
            'Reconnaissance': '🔎', 'Initial Access': '🚪',
            'Execution': '⚙', 'Persistence': '📌',
            'Privilege Escalation': '🔓', 'Lateral Movement': '🔀',
            'Collection': '📦', 'Exfiltration': '📤',
            'Command & Control': '📡', 'Anti-Forensics': '🧹',
        }
        for phase, phase_steps in grouped.items():
            icon = phase_icons.get(phase, '•')
            html_parts.append(f"<h4>{icon} {phase} ({len(phase_steps)} events)</h4><ul>")
            for s in phase_steps[:15]:
                html_parts.append(
                    f"<li><b>{s.timestamp}</b> — {s.program or 'unknown'} (PID {s.pid})"
                    f"<br><small>{s.description[:120]}</small></li>"
                )
            if len(phase_steps) > 15:
                html_parts.append(f"<li><i>…{len(phase_steps)-15} more</i></li>")
            html_parts.append("</ul>")
        self.story_text.setHtml("".join(html_parts))
        self.detail_tabs.setCurrentWidget(self.story_text)
