"""
FEPD - Timeline Event Detail Dialog
Enhanced popup for viewing timeline event details

Features:
- Complete event metadata display
- Artifact source information
- Link to artifact view
- Copy/export capabilities
- Color-coded severity
"""

import logging
from typing import Optional, Dict, Any
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QGroupBox, QTabWidget, QWidget, QTableWidget,
    QTableWidgetItem
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor


class TimelineEventDetailDialog(QDialog):
    """
    Enhanced timeline event detail viewer with artifact navigation.
    """
    
    # Signals
    show_artifact = pyqtSignal(dict)  # Request to show related artifact
    
    def __init__(self, event: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.event = event
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        self.setWindowTitle(f"Event Details - {self.event.get('event_type', 'Unknown')}")
        self.setMinimumSize(700, 500)
        
        layout = QVBoxLayout(self)
        
        # Header with severity color
        header_widget = self._create_header()
        layout.addWidget(header_widget)
        
        # Tab widget for different views
        tabs = QTabWidget()
        
        # Tab 1: Overview
        overview_tab = self._create_overview_tab()
        tabs.addTab(overview_tab, "📄 Overview")
        
        # Tab 2: Source Information
        source_tab = self._create_source_tab()
        tabs.addTab(source_tab, "📂 Source")
        
        # Tab 3: Raw Data
        raw_tab = self._create_raw_tab()
        tabs.addTab(raw_tab, "🔧 Raw Data")
        
        layout.addWidget(tabs)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        # Show artifact button (if artifact source exists)
        if self.event.get('artifact_source') or self.event.get('artifact_path'):
            btn_show_artifact = QPushButton("📋 Show Artifact")
            btn_show_artifact.clicked.connect(self._on_show_artifact)
            btn_show_artifact.setStyleSheet("""
                QPushButton {
                    background-color: #3498db;
                    color: white;
                    padding: 8px 16px;
                    font-weight: bold;
                    border: none;
                    border-radius: 4px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
            """)
            btn_layout.addWidget(btn_show_artifact)
        
        btn_copy = QPushButton("📋 Copy Details")
        btn_copy.clicked.connect(self._copy_details)
        btn_layout.addWidget(btn_copy)
        
        btn_export = QPushButton("💾 Export")
        btn_export.clicked.connect(self._export_event)
        btn_layout.addWidget(btn_export)
        
        btn_layout.addStretch()
        
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)
        
        layout.addLayout(btn_layout)
    
    def _create_header(self) -> QWidget:
        """Create colored header with event type and severity."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 10)
        
        # Event Type
        event_type = QLabel(f"📅 {self.event.get('event_type', 'Unknown Event')}")
        event_type_font = QFont()
        event_type_font.setPointSize(16)
        event_type_font.setBold(True)
        event_type.setFont(event_type_font)
        layout.addWidget(event_type)
        
        # Severity and timestamp
        severity = self.event.get('severity', 'UNKNOWN')
        severity_colors = {
            'CRITICAL': '#e74c3c',
            'HIGH': '#e67e22',
            'MEDIUM': '#f39c12',
            'LOW': '#3498db',
            'INFO': '#95a5a6'
        }
        severity_color = severity_colors.get(severity, '#95a5a6')
        
        info_label = QLabel(
            f"<span style='background-color: {severity_color}; color: white; padding: 4px 8px; "
            f"border-radius: 3px; font-weight: bold;'>{severity}</span> "
            f"&nbsp;&nbsp;|&nbsp;&nbsp;"
            f"<b>Time:</b> {self.event.get('ts_utc', 'N/A')}"
        )
        info_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(info_label)
        
        return widget
    
    def _create_overview_tab(self) -> QWidget:
        """Create overview tab with main event information."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Event Information
        info_group = QGroupBox("📋 Event Information")
        info_layout = QVBoxLayout()
        
        info_html = []
        info_html.append(f"<b>Event ID:</b> {self.event.get('event_id', 'N/A')}<br>")
        info_html.append(f"<b>Event Type:</b> {self.event.get('event_type', 'N/A')}<br>")
        info_html.append(f"<b>Classification:</b> {self.event.get('rule_class', 'UNKNOWN')}<br>")
        info_html.append(f"<b>Severity:</b> {self.event.get('severity', 'N/A')}<br>")
        info_html.append("<br>")
        info_html.append(f"<b>Timestamp (UTC):</b> {self.event.get('ts_utc', 'N/A')}<br>")
        info_html.append(f"<b>Timestamp (Local):</b> {self.event.get('ts_local', 'N/A')}<br>")
        info_html.append("<br>")
        
        if self.event.get('user_account'):
            info_html.append(f"<b>User Account:</b> {self.event.get('user_account')}<br>")
        
        if self.event.get('exe_name'):
            info_html.append(f"<b>Executable:</b> {self.event.get('exe_name')}<br>")
        
        if self.event.get('filepath'):
            info_html.append(f"<b>File Path:</b> {self.event.get('filepath')}<br>")
        
        if self.event.get('macb'):
            info_html.append(f"<b>MACB:</b> {self.event.get('macb')}<br>")
        
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setHtml("".join(info_html))
        info_text.setMaximumHeight(250)
        info_layout.addWidget(info_text)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Description
        desc_group = QGroupBox("📝 Description")
        desc_layout = QVBoxLayout()
        
        desc_text = QTextEdit()
        desc_text.setReadOnly(True)
        desc_text.setPlainText(self.event.get('description', 'No description available'))
        desc_layout.addWidget(desc_text)
        
        desc_group.setLayout(desc_layout)
        layout.addWidget(desc_group)
        
        return widget
    
    def _create_source_tab(self) -> QWidget:
        """Create source information tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        source_group = QGroupBox("📂 Artifact Source")
        source_layout = QVBoxLayout()
        
        source_html = []
        source_html.append(f"<b>Artifact Source:</b> {self.event.get('artifact_source', 'N/A')}<br>")
        source_html.append(f"<b>Artifact Path:</b> {self.event.get('artifact_path', 'N/A')}<br>")
        
        if self.event.get('event_id_native'):
            source_html.append(f"<br><b>Native Event ID:</b> {self.event.get('event_id_native')}<br>")
        
        if self.event.get('event_record_id'):
            source_html.append(f"<b>Record ID:</b> {self.event.get('event_record_id')}<br>")
        
        source_text = QTextEdit()
        source_text.setReadOnly(True)
        source_text.setHtml("".join(source_html))
        source_layout.addWidget(source_text)
        
        source_group.setLayout(source_layout)
        layout.addWidget(source_group)
        
        layout.addStretch()
        return widget
    
    def _create_raw_tab(self) -> QWidget:
        """Create raw data tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        raw_text = QTextEdit()
        raw_text.setReadOnly(True)
        raw_text.setFontFamily("Courier New")
        
        # Display all event data
        raw_content = []
        raw_content.append("=" * 60)
        raw_content.append("RAW EVENT DATA")
        raw_content.append("=" * 60)
        raw_content.append("")
        
        for key, value in self.event.items():
            raw_content.append(f"{key}: {value}")
        
        raw_content.append("")
        raw_content.append("=" * 60)
        
        raw_text.setPlainText("\n".join(raw_content))
        layout.addWidget(raw_text)
        
        return widget
    
    def _on_show_artifact(self):
        """Emit signal to show related artifact."""
        # Create artifact dict from event data
        artifact = {
            'name': self.event.get('artifact_source', 'Unknown'),
            'path': self.event.get('artifact_path', 'Unknown'),
            'type': self._infer_artifact_type(),
            'date': self.event.get('ts_utc', 'Unknown')
        }
        
        self.show_artifact.emit(artifact)
        self.accept()
    
    def _infer_artifact_type(self) -> str:
        """Infer artifact type from event data."""
        source = str(self.event.get('artifact_source', '')).lower()
        
        if 'evtx' in source or 'event log' in source:
            return 'Event Log'
        elif 'prefetch' in source:
            return 'Prefetch'
        elif 'registry' in source:
            return 'Registry'
        elif 'browser' in source or 'chrome' in source or 'firefox' in source:
            return 'Browser'
        elif 'mft' in source:
            return 'MFT'
        else:
            return 'Unknown'
    
    def _copy_details(self):
        """Copy event details to clipboard."""
        from PyQt6.QtWidgets import QApplication
        
        details = []
        details.append(f"Event Type: {self.event.get('event_type', 'N/A')}")
        details.append(f"Timestamp: {self.event.get('ts_utc', 'N/A')}")
        details.append(f"Severity: {self.event.get('severity', 'N/A')}")
        details.append(f"Description: {self.event.get('description', 'N/A')}")
        details.append(f"Source: {self.event.get('artifact_source', 'N/A')}")
        
        clipboard = QApplication.clipboard()
        clipboard.setText("\n".join(details))
        
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.information(self, "Copied", "Event details copied to clipboard")
    
    def _export_event(self):
        """Export event to file."""
        from PyQt6.QtWidgets import QFileDialog, QMessageBox
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Event",
            f"event_{self.event.get('event_id', 'unknown')}.json",
            "JSON Files (*.json);;Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    # Export as JSON
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(self.event, f, indent=2, default=str)
                else:
                    # Export as text
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write("=" * 60 + "\n")
                        f.write("TIMELINE EVENT DETAILS\n")
                        f.write("=" * 60 + "\n\n")
                        
                        for key, value in self.event.items():
                            f.write(f"{key}: {value}\n")
                
                QMessageBox.information(self, "Export Successful", f"Event exported to:\n{filename}")
                
            except Exception as e:
                QMessageBox.warning(self, "Export Failed", f"Failed to export event: {e}")
