"""
FEPD - Artifact Detail Dialog
Enhanced popup for viewing artifact details and timeline navigation

Features:
- Complete artifact metadata display
- Timeline event count
- Navigation options (View Details / Show in Timeline)
- Hash verification
- Export capabilities
"""

import logging
from typing import Optional, Dict, Any, List
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QGroupBox, QTableWidget, QTableWidgetItem, QTabWidget,
    QWidget, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont


class ArtifactDetailDialog(QDialog):
    """
    Enhanced artifact detail viewer with timeline navigation.
    """
    
    # Signals
    show_in_timeline = pyqtSignal(dict)  # Request to show artifact in timeline
    
    def __init__(self, artifact: Dict[str, Any], timeline_events: Optional[List[Dict]] = None, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.artifact = artifact
        self.timeline_events = timeline_events or []
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        self.setWindowTitle(f"Artifact Details - {self.artifact.get('name', 'Unknown')}")
        self.setMinimumSize(800, 600)
        
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel(f"📋 {self.artifact.get('name', 'Unknown Artifact')}")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Subtitle with type and status
        subtitle = QLabel(
            f"Type: <b>{self.artifact.get('type', 'N/A')}</b> | "
            f"Status: <b>{self.artifact.get('status', 'N/A')}</b> | "
            f"Timeline Events: <b>{len(self.timeline_events)}</b>"
        )
        subtitle.setStyleSheet("color: #666; padding: 5px;")
        layout.addWidget(subtitle)
        
        # Tab widget for different views
        tabs = QTabWidget()
        
        # Tab 1: Overview
        overview_tab = self._create_overview_tab()
        tabs.addTab(overview_tab, "📄 Overview")
        
        # Tab 2: Timeline Events (if available)
        if self.timeline_events:
            timeline_tab = self._create_timeline_tab()
            tabs.addTab(timeline_tab, f"⏱ Timeline ({len(self.timeline_events)})")
        
        # Tab 3: Technical Details
        technical_tab = self._create_technical_tab()
        tabs.addTab(technical_tab, "🔧 Technical")
        
        layout.addWidget(tabs)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        if self.timeline_events:
            btn_show_timeline = QPushButton("📅 Show in Timeline")
            btn_show_timeline.clicked.connect(self._on_show_timeline)
            btn_show_timeline.setStyleSheet("""
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
            btn_layout.addWidget(btn_show_timeline)
        
        btn_export = QPushButton("💾 Export Details")
        btn_export.clicked.connect(self._export_details)
        btn_layout.addWidget(btn_export)
        
        btn_layout.addStretch()
        
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)
        
        layout.addLayout(btn_layout)
    
    def _create_overview_tab(self) -> QWidget:
        """Create overview tab with main artifact information."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Basic Information
        basic_group = QGroupBox("📋 Basic Information")
        basic_layout = QVBoxLayout()
        
        info_html = []
        info_html.append(f"<b>Name:</b> {self.artifact.get('name', 'N/A')}<br>")
        info_html.append(f"<b>Type:</b> {self.artifact.get('type', 'N/A')}<br>")
        info_html.append(f"<b>Path/Location:</b> {self.artifact.get('path', 'N/A')}<br>")
        info_html.append(f"<b>Status:</b> {self.artifact.get('status', 'N/A')}<br>")
        
        if self.artifact.get('size'):
            info_html.append(f"<b>Size:</b> {self.artifact.get('size')}<br>")
        
        if self.artifact.get('date'):
            info_html.append(f"<b>Date/Time:</b> {self.artifact.get('date')}<br>")
        
        if self.artifact.get('owner'):
            info_html.append(f"<b>Owner:</b> {self.artifact.get('owner')}<br>")
        
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setHtml("".join(info_html))
        info_text.setMaximumHeight(200)
        basic_layout.addWidget(info_text)
        
        basic_group.setLayout(basic_layout)
        layout.addWidget(basic_group)
        
        # Hash Information
        if self.artifact.get('hash'):
            hash_group = QGroupBox("🔐 Hash Information")
            hash_layout = QVBoxLayout()
            
            hash_text = QTextEdit()
            hash_text.setReadOnly(True)
            hash_text.setPlainText(self.artifact.get('hash', 'N/A'))
            hash_text.setMaximumHeight(80)
            hash_layout.addWidget(hash_text)
            
            btn_verify = QPushButton("✓ Verify Hash")
            btn_verify.clicked.connect(self._verify_hash)
            hash_layout.addWidget(btn_verify)
            
            hash_group.setLayout(hash_layout)
            layout.addWidget(hash_group)
        
        # Description/Notes
        if self.artifact.get('description') or self.artifact.get('notes'):
            notes_group = QGroupBox("📝 Description / Notes")
            notes_layout = QVBoxLayout()
            
            notes_text = QTextEdit()
            notes_text.setReadOnly(True)
            notes_content = self.artifact.get('description', '') or self.artifact.get('notes', '')
            notes_text.setPlainText(notes_content)
            notes_layout.addWidget(notes_text)
            
            notes_group.setLayout(notes_layout)
            layout.addWidget(notes_group)
        
        layout.addStretch()
        return widget
    
    def _create_timeline_tab(self) -> QWidget:
        """Create timeline events tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info label
        info_label = QLabel(
            f"This artifact appears in <b>{len(self.timeline_events)}</b> timeline event(s)"
        )
        layout.addWidget(info_label)
        
        # Events table
        events_table = QTableWidget(0, 5)
        events_table.setHorizontalHeaderLabels([
            "Timestamp", "Event Type", "Severity", "User", "Description"
        ])
        
        # Populate events
        for event in self.timeline_events:
            row = events_table.rowCount()
            events_table.insertRow(row)
            
            events_table.setItem(row, 0, QTableWidgetItem(str(event.get('timestamp', 'N/A'))))
            events_table.setItem(row, 1, QTableWidgetItem(event.get('event_type', 'N/A')))
            events_table.setItem(row, 2, QTableWidgetItem(event.get('severity', 'N/A')))
            events_table.setItem(row, 3, QTableWidgetItem(event.get('user', 'N/A')))
            events_table.setItem(row, 4, QTableWidgetItem(event.get('description', 'N/A')))
        
        events_table.resizeColumnsToContents()
        layout.addWidget(events_table)
        
        return widget
    
    def _create_technical_tab(self) -> QWidget:
        """Create technical details tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        tech_text = QTextEdit()
        tech_text.setReadOnly(True)
        tech_text.setFontFamily("Courier New")
        
        # Display all artifact data
        tech_content = []
        tech_content.append("=" * 60)
        tech_content.append("TECHNICAL ARTIFACT DETAILS")
        tech_content.append("=" * 60)
        tech_content.append("")
        
        for key, value in self.artifact.items():
            tech_content.append(f"{key}: {value}")
        
        tech_content.append("")
        tech_content.append("=" * 60)
        
        tech_text.setPlainText("\n".join(tech_content))
        layout.addWidget(tech_text)
        
        return widget
    
    def _on_show_timeline(self):
        """Emit signal to show artifact in timeline."""
        self.show_in_timeline.emit(self.artifact)
        self.accept()
    
    def _verify_hash(self):
        """Verify artifact hash (placeholder)."""
        QMessageBox.information(
            self,
            "Hash Verification",
            "Hash verification against known databases (NSRL, VirusTotal) "
            "will be implemented in future version."
        )
    
    def _export_details(self):
        """Export artifact details to file."""
        from PyQt6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Artifact Details",
            f"artifact_{self.artifact.get('name', 'unknown')}.txt",
            "Text Files (*.txt);;JSON Files (*.json);;All Files (*)"
        )
        
        if filename:
            try:
                import json
                
                if filename.endswith('.json'):
                    # Export as JSON
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(self.artifact, f, indent=2, default=str)
                else:
                    # Export as text
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write("=" * 60 + "\n")
                        f.write("ARTIFACT DETAILS\n")
                        f.write("=" * 60 + "\n\n")
                        
                        for key, value in self.artifact.items():
                            f.write(f"{key}: {value}\n")
                        
                        if self.timeline_events:
                            f.write("\n" + "=" * 60 + "\n")
                            f.write(f"TIMELINE EVENTS ({len(self.timeline_events)})\n")
                            f.write("=" * 60 + "\n\n")
                            
                            for i, event in enumerate(self.timeline_events, 1):
                                f.write(f"Event {i}:\n")
                                for k, v in event.items():
                                    f.write(f"  {k}: {v}\n")
                                f.write("\n")
                
                QMessageBox.information(
                    self,
                    "Export Successful",
                    f"Artifact details exported to:\n{filename}"
                )
                
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Export Failed",
                    f"Failed to export details: {e}"
                )


class ArtifactChoiceDialog(QDialog):
    """
    Simple dialog to choose between viewing details or showing in timeline.
    """
    
    def __init__(self, artifact: Dict[str, Any], has_timeline_events: bool = False, parent=None):
        super().__init__(parent)
        self.artifact = artifact
        self.has_timeline_events = has_timeline_events
        self.choice = None  # 'details' or 'timeline'
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI."""
        self.setWindowTitle(f"Artifact #{self.artifact.get('id', '?')}")
        self.setMinimumWidth(400)
        
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel(f"<b>📋 {self.artifact.get('name', 'Unknown')}</b>")
        title.setStyleSheet("font-size: 14pt; padding: 10px;")
        layout.addWidget(title)
        
        # Description
        desc = QLabel("What would you like to do with this artifact?")
        desc.setStyleSheet("padding: 5px 10px;")
        layout.addWidget(desc)
        
        # View Details button
        btn_details = QPushButton("📄 View Details")
        btn_details.setMinimumHeight(40)
        btn_details.clicked.connect(self._choose_details)
        btn_details.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                font-weight: bold;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        layout.addWidget(btn_details)
        
        # Show in Timeline button (only if events exist)
        if self.has_timeline_events:
            btn_timeline = QPushButton("📅 Show in Timeline")
            btn_timeline.setMinimumHeight(40)
            btn_timeline.clicked.connect(self._choose_timeline)
            btn_timeline.setStyleSheet("""
                QPushButton {
                    background-color: #2ecc71;
                    color: white;
                    font-weight: bold;
                    border: none;
                    border-radius: 4px;
                }
                QPushButton:hover {
                    background-color: #27ae60;
                }
            """)
            layout.addWidget(btn_timeline)
        else:
            # Show disabled button with message
            no_events = QLabel("⚠ No timeline events for this artifact")
            no_events.setStyleSheet("color: #999; padding: 10px; text-align: center;")
            no_events.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(no_events)
        
        # Cancel button
        btn_cancel = QPushButton("❌ Cancel")
        btn_cancel.clicked.connect(self.reject)
        layout.addWidget(btn_cancel)
    
    def _choose_details(self):
        """User chose to view details."""
        self.choice = 'details'
        self.accept()
    
    def _choose_timeline(self):
        """User chose to show in timeline."""
        self.choice = 'timeline'
        self.accept()
    
    def get_choice(self) -> Optional[str]:
        """Get user's choice."""
        return self.choice
