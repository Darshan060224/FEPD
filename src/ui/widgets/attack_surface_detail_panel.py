"""
FEPD Attack Surface Detail Panel
=================================

Interactive detail panel that shows artifacts when user clicks on a
category in the Attack Surface treemap.

This transforms the Attack Surface from static visualization into
an interactive forensic control panel.

Clicking a box (e.g., "ProcessExecution") opens this panel with:
- Artifact list table
- Evidence paths (VEOS only, never analyst paths)
- Timestamps
- Anomaly scores
- Severity ratings
- Quick navigation to Files tab, Timeline, ML Analytics
"""

import sys
from typing import List, Dict, Optional
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QFrame, QHeaderView,
    QScrollArea, QLineEdit
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor


class AttackSurfaceDetailPanel(QWidget):
    """
    Detail panel showing artifacts for a selected attack surface category.
    
    Displays:
    - Category name and risk level
    - Total event count
    - Filterable artifact table
    - Navigation buttons
    """
    
    # Navigation signals
    navigate_to_files = pyqtSignal(str)       # Path to highlight in Files tab
    navigate_to_timeline = pyqtSignal(str)    # Filter timeline
    navigate_to_ml = pyqtSignal(str)          # Focus in ML Analytics
    close_requested = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_category = ""
        self.artifacts: List[Dict] = []
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the detail panel UI."""
        self.setStyleSheet("""
            QWidget {
                background: #1a1a2e;
                color: #e0e0e0;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header
        header = self._create_header()
        layout.addWidget(header)
        
        # Summary section
        self.summary_label = QLabel()
        self.summary_label.setStyleSheet("""
            background: #0f1117;
            color: #4ade80;
            padding: 12px 16px;
            font-size: 12px;
            font-family: 'Consolas', monospace;
            border-bottom: 1px solid #2d2d4a;
        """)
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)
        
        # Filter bar
        filter_bar = self._create_filter_bar()
        layout.addWidget(filter_bar)
        
        # Artifact table
        self.table = self._create_table()
        layout.addWidget(self.table)
        
        # Navigation footer
        footer = self._create_footer()
        layout.addWidget(footer)
    
    def _create_header(self) -> QWidget:
        """Create header with category name and close button."""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: #2d2d4a;
                border-bottom: 2px solid #4ade80;
                padding: 12px 16px;
            }
        """)
        
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 12, 16, 12)
        
        self.category_label = QLabel("Artifact Details")
        self.category_label.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #e0e0e0;
        """)
        header_layout.addWidget(self.category_label)
        
        header_layout.addStretch()
        
        close_btn = QPushButton("✕")
        close_btn.setFixedSize(32, 32)
        close_btn.setStyleSheet("""
            QPushButton {
                background: #3d3d5a;
                color: #e0e0e0;
                border: none;
                border-radius: 16px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #ef4444;
            }
        """)
        close_btn.clicked.connect(self.close_requested.emit)
        header_layout.addWidget(close_btn)
        
        return header
    
    def _create_filter_bar(self) -> QWidget:
        """Create filter/search bar."""
        filter_bar = QFrame()
        filter_bar.setStyleSheet("""
            QFrame {
                background: #0f1117;
                padding: 8px 16px;
                border-bottom: 1px solid #2d2d4a;
            }
        """)
        
        filter_layout = QHBoxLayout(filter_bar)
        filter_layout.setContentsMargins(16, 8, 16, 8)
        
        filter_label = QLabel("🔍 Filter:")
        filter_label.setStyleSheet("color: #888;")
        filter_layout.addWidget(filter_label)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Search artifacts...")
        self.filter_input.setStyleSheet("""
            QLineEdit {
                background: #2d2d4a;
                color: #e0e0e0;
                border: 1px solid #3d3d5a;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border: 1px solid #4ade80;
            }
        """)
        self.filter_input.textChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.filter_input, stretch=1)
        
        return filter_bar
    
    def _create_table(self) -> QTableWidget:
        """Create artifact table."""
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels([
            "Name", "Evidence Path", "Modified", "Size", "Anomaly", "Severity"
        ])
        
        table.setStyleSheet("""
            QTableWidget {
                background: #0f1117;
                color: #e0e0e0;
                gridline-color: #2d2d4a;
                border: none;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #1c2535;
            }
            QTableWidget::item:selected {
                background: #2d2d4a;
                color: #4ade80;
            }
            QTableWidget::item:hover {
                background: #1c2535;
            }
            QHeaderView::section {
                background: #1a1a2e;
                color: #888;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #2d2d4a;
                font-weight: bold;
                text-align: left;
            }
        """)
        
        # Column widths
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        
        table.setColumnWidth(0, 180)
        table.setColumnWidth(2, 140)
        table.setColumnWidth(3, 100)
        table.setColumnWidth(4, 80)
        table.setColumnWidth(5, 100)
        
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        
        # Double-click to navigate to Files tab
        table.doubleClicked.connect(self._on_row_double_click)
        
        return table
    
    def _create_footer(self) -> QWidget:
        """Create navigation footer."""
        footer = QFrame()
        footer.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-top: 1px solid #2d2d4a;
                padding: 12px 16px;
            }
        """)
        
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(16, 12, 16, 12)
        
        label = QLabel("Quick Navigation:")
        label.setStyleSheet("color: #888; font-size: 11px;")
        footer_layout.addWidget(label)
        
        footer_layout.addStretch()
        
        # Navigation buttons
        btn_style = """
            QPushButton {
                background: #2d2d4a;
                color: #e0e0e0;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-size: 12px;
            }
            QPushButton:hover {
                background: #3d3d5a;
            }
        """
        
        files_btn = QPushButton("📁 Files Tab")
        files_btn.setStyleSheet(btn_style)
        files_btn.clicked.connect(self._navigate_to_files)
        footer_layout.addWidget(files_btn)
        
        timeline_btn = QPushButton("📅 Timeline")
        timeline_btn.setStyleSheet(btn_style)
        timeline_btn.clicked.connect(self._navigate_to_timeline)
        footer_layout.addWidget(timeline_btn)
        
        ml_btn = QPushButton("🤖 ML Analytics")
        ml_btn.setStyleSheet(btn_style)
        ml_btn.clicked.connect(self._navigate_to_ml)
        footer_layout.addWidget(ml_btn)
        
        return footer
    
    def load_category(self, category_id: str, category_name: str, 
                     artifacts: List[Dict], risk_level: str = "Medium"):
        """
        Load artifacts for a specific category.
        
        Args:
            category_id: Category identifier (e.g., "ProcessExecution")
            category_name: Human-readable name (e.g., "Process Execution")
            artifacts: List of artifact dictionaries with keys:
                - name: Artifact name
                - path: Evidence path (VEOS path only)
                - modified: Timestamp
                - size: File size in bytes
                - anomaly_score: 0.0 to 1.0
                - severity: Low/Medium/High/Critical
            risk_level: Overall risk level for category
        """
        self.current_category = category_id
        self.artifacts = artifacts
        
        # Update header
        self.category_label.setText(f"🎯 {category_name}")
        
        # Update summary
        total_count = len(artifacts)
        high_risk = sum(1 for a in artifacts if a.get('anomaly_score', 0) > 0.7)
        
        summary = (
            f"<b>Artifact Type:</b> {category_name}  |  "
            f"<b>Total Events:</b> {total_count:,}  |  "
            f"<b>Risk Level:</b> {risk_level}  |  "
            f"<b>High Risk Items:</b> {high_risk}"
        )
        self.summary_label.setText(summary)
        
        # Populate table
        self._populate_table(artifacts)
    
    def _populate_table(self, artifacts: List[Dict]):
        """Populate the artifact table."""
        self.table.setRowCount(0)
        
        for artifact in artifacts:
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            # Name
            name = artifact.get('name', 'Unknown')
            self.table.setItem(row, 0, self._create_item(name))
            
            # Evidence Path (VEOS path only)
            path = artifact.get('path', '')
            self.table.setItem(row, 1, self._create_item(path, font_family='Consolas'))
            
            # Modified timestamp
            modified = artifact.get('modified', '')
            if isinstance(modified, datetime):
                modified = modified.strftime('%Y-%m-%d %H:%M:%S')
            self.table.setItem(row, 2, self._create_item(str(modified)))
            
            # Size
            size = artifact.get('size', 0)
            size_str = self._format_size(size)
            self.table.setItem(row, 3, self._create_item(size_str))
            
            # Anomaly score
            anomaly = artifact.get('anomaly_score', 0.0)
            anomaly_item = self._create_item(f"{anomaly:.2f}")
            anomaly_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            # Color code by score
            if anomaly >= 0.8:
                anomaly_item.setForeground(QColor("#ef4444"))  # Red
            elif anomaly >= 0.6:
                anomaly_item.setForeground(QColor("#f59e0b"))  # Orange
            elif anomaly >= 0.4:
                anomaly_item.setForeground(QColor("#eab308"))  # Yellow
            else:
                anomaly_item.setForeground(QColor("#4ade80"))  # Green
            
            self.table.setItem(row, 4, anomaly_item)
            
            # Severity
            severity = artifact.get('severity', 'Low')
            severity_item = self._create_item(severity)
            severity_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            # Color code severity
            if severity == 'Critical':
                severity_item.setForeground(QColor("#7f1d1d"))
                severity_item.setBackground(QColor("#ef4444"))
            elif severity == 'High':
                severity_item.setForeground(QColor("#7c2d12"))
                severity_item.setBackground(QColor("#f59e0b"))
            elif severity == 'Medium':
                severity_item.setForeground(QColor("#713f12"))
                severity_item.setBackground(QColor("#eab308"))
            else:
                severity_item.setForeground(QColor("#14532d"))
                severity_item.setBackground(QColor("#4ade80"))
            
            self.table.setItem(row, 5, severity_item)
    
    def _create_item(self, text: str, font_family: str = None) -> QTableWidgetItem:
        """Create a table item with consistent styling."""
        item = QTableWidgetItem(text)
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Read-only
        
        if font_family:
            font = QFont(font_family, 10)
            item.setFont(font)
        
        return item
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        if size_bytes == 0:
            return "0 B"
        
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        size = float(size_bytes)
        unit_idx = 0
        
        while size >= 1024 and unit_idx < len(units) - 1:
            size /= 1024
            unit_idx += 1
        
        return f"{size:.1f} {units[unit_idx]}"
    
    def _apply_filter(self, text: str):
        """Filter table rows based on search text."""
        text = text.lower()
        
        for row in range(self.table.rowCount()):
            should_show = False
            
            # Search in name and path columns
            for col in [0, 1]:
                item = self.table.item(row, col)
                if item and text in item.text().lower():
                    should_show = True
                    break
            
            self.table.setRowHidden(row, not should_show)
    
    def _on_row_double_click(self, index):
        """Handle double-click on table row."""
        row = index.row()
        path_item = self.table.item(row, 1)
        
        if path_item:
            path = path_item.text()
            self.navigate_to_files.emit(path)
    
    def _navigate_to_files(self):
        """Navigate to Files tab with current selection."""
        current_row = self.table.currentRow()
        if current_row >= 0:
            path_item = self.table.item(current_row, 1)
            if path_item:
                self.navigate_to_files.emit(path_item.text())
    
    def _navigate_to_timeline(self):
        """Filter timeline by current category."""
        self.navigate_to_timeline.emit(self.current_category)
    
    def _navigate_to_ml(self):
        """Focus ML Analytics on current category."""
        self.navigate_to_ml.emit(self.current_category)


if __name__ == '__main__':
    """Test the detail panel."""
    from PyQt6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    panel = AttackSurfaceDetailPanel()
    panel.setWindowTitle("Attack Surface Detail Panel")
    panel.resize(900, 600)
    
    # Sample data
    sample_artifacts = [
        {
            'name': 'powershell.exe',
            'path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'modified': datetime.now(),
            'size': 445952,
            'anomaly_score': 0.89,
            'severity': 'High'
        },
        {
            'name': 'cmd.exe',
            'path': 'C:\\Windows\\System32\\cmd.exe',
            'modified': datetime.now(),
            'size': 289792,
            'anomaly_score': 0.32,
            'severity': 'Low'
        },
        {
            'name': 'evil.exe',
            'path': 'C:\\Temp\\evil.exe',
            'modified': datetime.now(),
            'size': 102400,
            'anomaly_score': 0.95,
            'severity': 'Critical'
        },
    ]
    
    panel.load_category(
        category_id='ProcessExecution',
        category_name='Process Execution',
        artifacts=sample_artifacts,
        risk_level='High'
    )
    
    panel.show()
    sys.exit(app.exec())
