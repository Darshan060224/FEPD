"""
File Details Dialog
===================

Displays comprehensive file metadata and forensic details.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QFormLayout, QFrame, QPushButton, QTextEdit,
    QTabWidget, QWidget, QGroupBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from typing import Optional, Dict, Any
from datetime import datetime

import sys
sys.path.insert(0, str(__file__).replace('\\', '/').rsplit('/src/', 1)[0])
from src.core.virtual_fs import VFSNode, VFSNodeType


class FileDetailsDialog(QDialog):
    """
    Dialog showing comprehensive file details.
    
    Displays:
    - Path and filename
    - Size and type
    - Timestamps (created, modified, accessed)
    - Hashes (SHA-256, MD5)
    - Evidence source
    - Partition info
    - Additional metadata
    """
    
    def __init__(
        self,
        node: VFSNode,
        parent: Optional[QWidget] = None
    ):
        super().__init__(parent)
        self.node = node
        
        self.setWindowTitle(f"Details - {node.name}")
        self.setMinimumSize(500, 400)
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
                color: #e0e0e0;
            }
            QLabel {
                color: #e0e0e0;
            }
            QGroupBox {
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                margin-top: 12px;
                padding-top: 12px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 4px;
                color: #0078d4;
            }
        """)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)
        
        # Header with icon and name
        header = QFrame()
        header_layout = QHBoxLayout(header)
        
        # Icon
        icon_label = QLabel(self._get_icon())
        icon_label.setStyleSheet("font-size: 48px;")
        header_layout.addWidget(icon_label)
        
        # Name and path
        name_layout = QVBoxLayout()
        name_label = QLabel(self.node.name)
        name_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        name_layout.addWidget(name_label)
        
        path_label = QLabel(self.node.path)
        path_label.setStyleSheet("color: #888; font-size: 11px;")
        path_label.setWordWrap(True)
        name_layout.addWidget(path_label)
        
        header_layout.addLayout(name_layout)
        header_layout.addStretch()
        
        layout.addWidget(header)
        
        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background: #3d3d3d;")
        layout.addWidget(sep)
        
        # Tab widget for details
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3d3d3d;
                border-radius: 4px;
            }
            QTabBar::tab {
                background: #2d2d2d;
                color: #888;
                padding: 8px 16px;
                border: 1px solid #3d3d3d;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background: #1e1e1e;
                color: #e0e0e0;
            }
        """)
        
        # General tab
        tabs.addTab(self._create_general_tab(), "General")
        
        # Timestamps tab
        tabs.addTab(self._create_timestamps_tab(), "Timestamps")
        
        # Hashes tab
        tabs.addTab(self._create_hashes_tab(), "Hashes")
        
        # Forensic tab
        tabs.addTab(self._create_forensic_tab(), "Forensic")
        
        layout.addWidget(tabs)
        
        # Close button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background: #0078d4;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 24px;
            }
            QPushButton:hover { background: #1e8ae6; }
        """)
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
    
    def _get_icon(self) -> str:
        """Get icon for node type."""
        icons = {
            VFSNodeType.ROOT: "🖥️",
            VFSNodeType.DISK: "💽",
            VFSNodeType.PARTITION: "📦",
            VFSNodeType.DRIVE: "💾",
            VFSNodeType.FOLDER: "📁",
            VFSNodeType.FILE: "📄",
            VFSNodeType.USER: "👤",
            VFSNodeType.SYSTEM: "⚙️",
            VFSNodeType.SYMLINK: "🔗",
            VFSNodeType.DELETED: "🗑️",
        }
        
        # Check for specific file types
        if self.node.node_type == VFSNodeType.FILE:
            ext = self.node.name.lower().rsplit('.', 1)[-1] if '.' in self.node.name else ''
            if ext in ('pdf',):
                return "📕"
            elif ext in ('jpg', 'jpeg', 'png', 'gif', 'bmp'):
                return "🖼️"
            elif ext in ('mp4', 'avi', 'mkv', 'mov'):
                return "🎬"
            elif ext in ('mp3', 'wav', 'flac'):
                return "🎵"
            elif ext in ('exe', 'dll'):
                return "⚡"
            elif ext in ('zip', 'rar', '7z'):
                return "📦"
            elif ext in ('doc', 'docx'):
                return "📘"
            elif ext in ('xls', 'xlsx'):
                return "📊"
        
        return icons.get(self.node.node_type, "📄")
    
    def _create_general_tab(self) -> QWidget:
        """Create general info tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        form = QFormLayout()
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        # Type
        type_text = self.node.node_type.value.replace('_', ' ').title()
        if self.node.is_deleted:
            type_text += " (Deleted)"
        form.addRow("Type:", self._create_value_label(type_text))
        
        # Size
        if self.node.size > 0:
            size_text = f"{self._format_size(self.node.size)} ({self.node.size:,} bytes)"
        else:
            size_text = "—"
        form.addRow("Size:", self._create_value_label(size_text))
        
        # MIME Type
        if self.node.mime_type:
            form.addRow("MIME Type:", self._create_value_label(self.node.mime_type))
        
        # Inode
        if self.node.inode:
            form.addRow("Inode:", self._create_value_label(str(self.node.inode)))
        
        # Allocation status
        alloc_text = "Allocated" if self.node.is_allocated else "Unallocated"
        form.addRow("Status:", self._create_value_label(alloc_text))
        
        layout.addLayout(form)
        layout.addStretch()
        
        return widget
    
    def _create_timestamps_tab(self) -> QWidget:
        """Create timestamps tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        form = QFormLayout()
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        # Created
        if self.node.created:
            created_text = self._format_datetime(self.node.created)
        else:
            created_text = "—"
        form.addRow("Created:", self._create_value_label(created_text))
        
        # Modified
        if self.node.modified:
            modified_text = self._format_datetime(self.node.modified)
        else:
            modified_text = "—"
        form.addRow("Modified:", self._create_value_label(modified_text))
        
        # Accessed
        if self.node.accessed:
            accessed_text = self._format_datetime(self.node.accessed)
        else:
            accessed_text = "—"
        form.addRow("Accessed:", self._create_value_label(accessed_text))
        
        layout.addLayout(form)
        
        # Timeline visualization
        if any([self.node.created, self.node.modified, self.node.accessed]):
            timeline_group = QGroupBox("Timeline")
            timeline_layout = QVBoxLayout(timeline_group)
            
            times = []
            if self.node.created:
                times.append(("Created", self.node.created))
            if self.node.modified:
                times.append(("Modified", self.node.modified))
            if self.node.accessed:
                times.append(("Accessed", self.node.accessed))
            
            times.sort(key=lambda x: x[1])
            
            for event, time in times:
                label = QLabel(f"  ● {time.strftime('%Y-%m-%d %H:%M:%S')} — {event}")
                label.setStyleSheet("color: #888; font-family: monospace;")
                timeline_layout.addWidget(label)
            
            layout.addWidget(timeline_group)
        
        layout.addStretch()
        
        return widget
    
    def _create_hashes_tab(self) -> QWidget:
        """Create hashes tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        form = QFormLayout()
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        # SHA-256
        if self.node.sha256:
            sha_label = self._create_value_label(self.node.sha256)
            sha_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            sha_label.setStyleSheet("font-family: monospace; color: #4ec9b0;")
            form.addRow("SHA-256:", sha_label)
        else:
            form.addRow("SHA-256:", self._create_value_label("Not computed"))
        
        # MD5
        if self.node.md5:
            md5_label = self._create_value_label(self.node.md5)
            md5_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            md5_label.setStyleSheet("font-family: monospace; color: #4ec9b0;")
            form.addRow("MD5:", md5_label)
        else:
            form.addRow("MD5:", self._create_value_label("Not computed"))
        
        layout.addLayout(form)
        
        # Hash verification note
        note = QLabel(
            "💡 Hash values can be used to verify file integrity\n"
            "    and search for known files in hash databases."
        )
        note.setStyleSheet("color: #888; font-size: 11px; margin-top: 20px;")
        layout.addWidget(note)
        
        layout.addStretch()
        
        return widget
    
    def _create_forensic_tab(self) -> QWidget:
        """Create forensic details tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        form = QFormLayout()
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        # Evidence source
        if self.node.evidence_id:
            form.addRow("Evidence:", self._create_value_label(self.node.evidence_id))
        
        # Partition
        if self.node.partition_info:
            form.addRow("Partition:", self._create_value_label(self.node.partition_info))
        
        # Parent path
        form.addRow("Parent:", self._create_value_label(self.node.parent_path or "/"))
        
        # Full VFS path
        path_label = self._create_value_label(self.node.path)
        path_label.setWordWrap(True)
        form.addRow("VFS Path:", path_label)
        
        layout.addLayout(form)
        
        # Metadata
        if self.node.metadata:
            meta_group = QGroupBox("Additional Metadata")
            meta_layout = QVBoxLayout(meta_group)
            
            meta_text = QTextEdit()
            meta_text.setReadOnly(True)
            meta_text.setPlainText(str(self.node.metadata))
            meta_text.setStyleSheet("""
                QTextEdit {
                    background: #252525;
                    color: #d4d4d4;
                    border: none;
                    font-family: monospace;
                }
            """)
            meta_text.setMaximumHeight(100)
            meta_layout.addWidget(meta_text)
            
            layout.addWidget(meta_group)
        
        layout.addStretch()
        
        return widget
    
    def _create_value_label(self, text: str) -> QLabel:
        """Create a styled value label."""
        label = QLabel(text)
        label.setStyleSheet("color: #d4d4d4;")
        label.setWordWrap(True)
        return label
    
    def _format_size(self, size: int) -> str:
        """Format byte size."""
        size_f = float(size)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_f < 1024:
                return f"{size_f:.1f} {unit}"
            size_f /= 1024
        return f"{size_f:.1f} TB"
    
    def _format_datetime(self, dt: datetime) -> str:
        """Format datetime for display."""
        return dt.strftime("%Y-%m-%d %H:%M:%S")
