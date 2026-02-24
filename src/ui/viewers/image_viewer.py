"""
Image Viewer
============

Read-only image viewer for forensic evidence.
"""

from PyQt6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QScrollArea,
    QSizePolicy, QFrame
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QPixmap, QImage, QAction
from typing import Optional
from pathlib import Path
import io

from .base_viewer import BaseViewer


class ImageViewer(BaseViewer):
    """
    Image viewer for forensic evidence.
    
    Features:
    - Supports common image formats
    - Zoom in/out
    - Fit to window
    - EXIF metadata display
    """
    
    SUPPORTED_EXTENSIONS = [
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
        '.tiff', '.tif', '.webp', '.svg'
    ]
    
    def __init__(self, parent: Optional[QWidget] = None, read_file_func=None):
        # Initialize attributes BEFORE super().__init__() since it calls _create_content_widget()
        self._zoom_factor = 1.0
        self._original_pixmap: Optional[QPixmap] = None
        
        super().__init__(parent, title="Image Viewer", read_file_func=read_file_func)
        self.title_icon.setText("🖼️")
    
    def _create_content_widget(self) -> QWidget:
        """Create image display widget."""
        # Scroll area for panning
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(False)
        self.scroll_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scroll_area.setStyleSheet("""
            QScrollArea {
                background-color: #1e1e1e;
                border: none;
            }
            QScrollBar:vertical, QScrollBar:horizontal {
                background: #2d2d2d;
            }
            QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
                background: #555;
                border-radius: 4px;
            }
        """)
        
        # Image label
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setStyleSheet("background: transparent;")
        self.image_label.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Ignored
        )
        
        self.scroll_area.setWidget(self.image_label)
        
        return self.scroll_area
    
    def _setup_toolbar(self):
        """Add image-specific toolbar actions."""
        super()._setup_toolbar()
        
        # Fit to window
        fit_action = QAction("⊡ Fit", self)
        fit_action.setToolTip("Fit to Window")
        fit_action.triggered.connect(self._fit_to_window)
        self.toolbar.addAction(fit_action)
        
        # Actual size
        actual_action = QAction("1:1", self)
        actual_action.setToolTip("Actual Size")
        actual_action.triggered.connect(self._actual_size)
        self.toolbar.addAction(actual_action)
        
        self.toolbar.addSeparator()
        
        # Rotate
        rotate_left = QAction("↺", self)
        rotate_left.setToolTip("Rotate Left")
        rotate_left.triggered.connect(lambda: self._rotate(-90))
        self.toolbar.addAction(rotate_left)
        
        rotate_right = QAction("↻", self)
        rotate_right.setToolTip("Rotate Right")
        rotate_right.triggered.connect(lambda: self._rotate(90))
        self.toolbar.addAction(rotate_right)
    
    def load_file(self, path: str, data: Optional[bytes] = None) -> bool:
        """Load image file."""
        try:
            name = Path(path).name
            self.set_file_info(path, name)
            
            # Get file data
            if data is None and self.read_file_func:
                data = self.read_file_func(path, 0, -1)
            
            if data is None:
                self.image_label.setText("Error: Could not read file")
                return False
            
            # Load image
            image = QImage()
            if not image.loadFromData(data):
                self.image_label.setText("Error: Could not decode image")
                return False
            
            self._original_pixmap = QPixmap.fromImage(image)
            self._zoom_factor = 1.0
            
            # Display
            self._fit_to_window()
            
            # Update status
            width = self._original_pixmap.width()
            height = self._original_pixmap.height()
            size = len(data)
            
            # Try to get format info
            ext = Path(path).suffix.upper().lstrip('.')
            
            self.set_status(
                f"{width} × {height} pixels | {ext} | {self._format_size(size)} | "
                f"Zoom: {int(self._zoom_factor * 100)}%"
            )
            
            return True
            
        except Exception as e:
            self.image_label.setText(f"Error loading image: {e}")
            return False
    
    def _update_display(self):
        """Update the displayed image with current zoom."""
        if not self._original_pixmap:
            return
        
        # Scale pixmap
        new_size = self._original_pixmap.size() * self._zoom_factor
        scaled = self._original_pixmap.scaled(
            QSize(int(new_size.width()), int(new_size.height())),
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation
        )
        
        self.image_label.setPixmap(scaled)
        self.image_label.resize(scaled.size())
        
        # Update status
        self.set_status(
            f"{self._original_pixmap.width()} × {self._original_pixmap.height()} | "
            f"Zoom: {int(self._zoom_factor * 100)}%"
        )
    
    def _fit_to_window(self):
        """Fit image to window size."""
        if not self._original_pixmap:
            return
        
        # Calculate zoom to fit
        scroll_size = self.scroll_area.viewport().size()
        img_size = self._original_pixmap.size()
        
        zoom_w = scroll_size.width() / img_size.width()
        zoom_h = scroll_size.height() / img_size.height()
        
        self._zoom_factor = min(zoom_w, zoom_h, 1.0)  # Don't upscale
        self._update_display()
    
    def _actual_size(self):
        """Show image at actual size (100%)."""
        self._zoom_factor = 1.0
        self._update_display()
    
    def _zoom_in(self):
        """Zoom in."""
        self._zoom_factor = min(4.0, self._zoom_factor * 1.25)
        self._update_display()
    
    def _zoom_out(self):
        """Zoom out."""
        self._zoom_factor = max(0.1, self._zoom_factor / 1.25)
        self._update_display()
    
    def _rotate(self, degrees: int):
        """Rotate image."""
        if not self._original_pixmap:
            return
        
        from PyQt6.QtGui import QTransform
        
        transform = QTransform()
        transform.rotate(degrees)
        self._original_pixmap = self._original_pixmap.transformed(
            transform, Qt.TransformationMode.SmoothTransformation
        )
        self._update_display()
    
    def _format_size(self, size: int) -> str:
        """Format byte size."""
        size_f = float(size)
        for unit in ['B', 'KB', 'MB']:
            if size_f < 1024:
                return f"{size_f:.1f} {unit}"
            size_f /= 1024
        return f"{size_f:.1f} GB"
    
    def get_supported_extensions(self) -> list:
        return self.SUPPORTED_EXTENSIONS
