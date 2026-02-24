"""
Base Viewer Widget
==================

Abstract base class for all file viewers.
Provides common functionality and interface.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QToolBar,
    QPushButton, QSizePolicy, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon, QFont, QAction
from pathlib import Path
from typing import Optional, Callable
from abc import ABC, abstractmethod


class BaseViewer(QWidget):
    """
    Base class for all file viewers.
    
    Provides:
    - Title bar with filename
    - Toolbar for actions
    - Content area (subclass implements)
    - Close button
    """
    
    # Signals
    closed = pyqtSignal()
    file_opened = pyqtSignal(str)  # Emits file path
    
    def __init__(
        self,
        parent: Optional[QWidget] = None,
        title: str = "File Viewer",
        read_file_func: Optional[Callable[[str, int, int], bytes]] = None
    ):
        """
        Initialize base viewer.
        
        Args:
            parent: Parent widget
            title: Viewer title
            read_file_func: Function to read file bytes from VFS
                           (path, offset, length) -> bytes
        """
        super().__init__(parent)
        
        self.title = title
        self.file_path: Optional[str] = None
        self.file_name: Optional[str] = None
        self.read_file_func = read_file_func
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the viewer UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Title bar
        self._create_title_bar()
        layout.addWidget(self.title_bar)
        
        # Toolbar
        self.toolbar = QToolBar()
        self.toolbar.setStyleSheet("""
            QToolBar {
                background: #2d2d2d;
                border: none;
                padding: 4px;
                spacing: 4px;
            }
            QToolButton {
                background: #3d3d3d;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 4px 8px;
                color: #e0e0e0;
            }
            QToolButton:hover {
                background: #4d4d4d;
                border-color: #0078d4;
            }
        """)
        self._setup_toolbar()
        layout.addWidget(self.toolbar)
        
        # Content area (subclass implements)
        self.content_widget = self._create_content_widget()
        self.content_widget.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding
        )
        layout.addWidget(self.content_widget)
        
        # Status bar
        self.status_bar = QLabel()
        self.status_bar.setStyleSheet("""
            QLabel {
                background: #252525;
                color: #888;
                padding: 4px 8px;
                font-size: 11px;
            }
        """)
        layout.addWidget(self.status_bar)
        
        self.setStyleSheet("""
            BaseViewer {
                background: #1e1e1e;
                border: 1px solid #3d3d3d;
                border-radius: 4px;
            }
        """)
    
    def _create_title_bar(self):
        """Create the title bar."""
        self.title_bar = QFrame()
        self.title_bar.setStyleSheet("""
            QFrame {
                background: #252525;
                border-bottom: 1px solid #3d3d3d;
            }
        """)
        
        layout = QHBoxLayout(self.title_bar)
        layout.setContentsMargins(8, 4, 8, 4)
        
        # Icon and title
        self.title_icon = QLabel("📄")
        self.title_icon.setStyleSheet("font-size: 16px;")
        layout.addWidget(self.title_icon)
        
        self.title_label = QLabel(self.title)
        self.title_label.setStyleSheet("""
            QLabel {
                color: #e0e0e0;
                font-weight: bold;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.title_label)
        
        # Filename (updated when file is opened)
        self.filename_label = QLabel("")
        self.filename_label.setStyleSheet("""
            QLabel {
                color: #888;
                font-size: 11px;
            }
        """)
        layout.addWidget(self.filename_label)
        
        layout.addStretch()
        
        # Close button
        close_btn = QPushButton("✕")
        close_btn.setFixedSize(24, 24)
        close_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: none;
                color: #888;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #e81123;
                color: white;
            }
        """)
        close_btn.clicked.connect(self._on_close)
        layout.addWidget(close_btn)
    
    def _setup_toolbar(self):
        """Set up toolbar actions. Override in subclasses."""
        # Zoom actions (common)
        zoom_in = QAction("🔍+", self)
        zoom_in.setToolTip("Zoom In")
        zoom_in.triggered.connect(self._zoom_in)
        self.toolbar.addAction(zoom_in)
        
        zoom_out = QAction("🔍−", self)
        zoom_out.setToolTip("Zoom Out")
        zoom_out.triggered.connect(self._zoom_out)
        self.toolbar.addAction(zoom_out)
        
        self.toolbar.addSeparator()
    
    @abstractmethod
    def _create_content_widget(self) -> QWidget:
        """Create the main content widget. Must be implemented by subclass."""
        pass
    
    @abstractmethod
    def load_file(self, path: str, data: Optional[bytes] = None) -> bool:
        """
        Load a file for viewing.
        
        Args:
            path: VFS path to file
            data: Optional pre-loaded file data
            
        Returns:
            True if file loaded successfully
        """
        pass
    
    def _on_close(self):
        """Handle close button click."""
        self.closed.emit()
        self.close()
    
    def _zoom_in(self):
        """Zoom in. Override in subclasses."""
        pass
    
    def _zoom_out(self):
        """Zoom out. Override in subclasses."""
        pass
    
    def set_status(self, message: str):
        """Set status bar message."""
        self.status_bar.setText(message)
    
    def set_file_info(self, path: str, name: str):
        """Update file info in title bar."""
        self.file_path = path
        self.file_name = name
        self.filename_label.setText(f" — {name}")
        self.file_opened.emit(path)
    
    def get_supported_extensions(self) -> list:
        """Return list of supported file extensions. Override in subclasses."""
        return []
