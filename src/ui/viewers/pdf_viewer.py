"""
PDF Viewer
==========

Read-only PDF viewer for forensic evidence.
Uses PyMuPDF (fitz) if available, falls back to basic view.
"""

from PyQt6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout, QScrollArea,
    QSpinBox, QPushButton, QSizePolicy
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QPixmap, QImage
from typing import Optional
from pathlib import Path

from .base_viewer import BaseViewer

# Try to import PyMuPDF
try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False


class PDFViewer(BaseViewer):
    """
    PDF viewer for forensic evidence.
    
    Features:
    - Page-by-page viewing
    - Zoom in/out
    - Page navigation
    - Text search (when PyMuPDF available)
    """
    
    SUPPORTED_EXTENSIONS = ['.pdf']
    
    def __init__(self, parent: Optional[QWidget] = None, read_file_func=None):
        # Initialize attributes BEFORE super().__init__() since it calls _create_content_widget()
        self._zoom_factor = 1.0
        self._current_page = 0
        self._total_pages = 0
        self._pdf_doc = None
        self._pdf_data: Optional[bytes] = None
        
        super().__init__(parent, title="PDF Viewer", read_file_func=read_file_func)
        self.title_icon.setText("📕")
    
    def _create_content_widget(self) -> QWidget:
        """Create PDF display widget."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Page display area
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(False)
        self.scroll_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scroll_area.setStyleSheet("""
            QScrollArea {
                background-color: #404040;
                border: none;
            }
        """)
        
        self.page_label = QLabel()
        self.page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.page_label.setStyleSheet("background: white;")
        
        self.scroll_area.setWidget(self.page_label)
        layout.addWidget(self.scroll_area)
        
        # Page navigation bar
        nav_bar = QWidget()
        nav_layout = QHBoxLayout(nav_bar)
        nav_layout.setContentsMargins(8, 4, 8, 4)
        
        # Previous page
        self.prev_btn = QPushButton("◀")
        self.prev_btn.setFixedWidth(40)
        self.prev_btn.clicked.connect(self._prev_page)
        self.prev_btn.setStyleSheet("""
            QPushButton {
                background: #3d3d3d;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 4px;
            }
            QPushButton:hover { background: #4d4d4d; }
            QPushButton:disabled { color: #666; }
        """)
        nav_layout.addWidget(self.prev_btn)
        
        # Page number
        nav_layout.addWidget(QLabel("Page:"))
        self.page_spin = QSpinBox()
        self.page_spin.setRange(1, 1)
        self.page_spin.valueChanged.connect(self._goto_page)
        self.page_spin.setStyleSheet("""
            QSpinBox {
                background: #3d3d3d;
                color: #e0e0e0;
                border: 1px solid #555;
                padding: 2px;
            }
        """)
        nav_layout.addWidget(self.page_spin)
        
        self.total_label = QLabel("/ 1")
        self.total_label.setStyleSheet("color: #e0e0e0;")
        nav_layout.addWidget(self.total_label)
        
        # Next page
        self.next_btn = QPushButton("▶")
        self.next_btn.setFixedWidth(40)
        self.next_btn.clicked.connect(self._next_page)
        self.next_btn.setStyleSheet(self.prev_btn.styleSheet())
        nav_layout.addWidget(self.next_btn)
        
        nav_layout.addStretch()
        
        # Zoom controls
        nav_layout.addWidget(QLabel("Zoom:"))
        zoom_out_btn = QPushButton("−")
        zoom_out_btn.setFixedWidth(30)
        zoom_out_btn.clicked.connect(self._zoom_out)
        zoom_out_btn.setStyleSheet(self.prev_btn.styleSheet())
        nav_layout.addWidget(zoom_out_btn)
        
        self.zoom_label = QLabel("100%")
        self.zoom_label.setStyleSheet("color: #e0e0e0; min-width: 40px;")
        self.zoom_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nav_layout.addWidget(self.zoom_label)
        
        zoom_in_btn = QPushButton("+")
        zoom_in_btn.setFixedWidth(30)
        zoom_in_btn.clicked.connect(self._zoom_in)
        zoom_in_btn.setStyleSheet(self.prev_btn.styleSheet())
        nav_layout.addWidget(zoom_in_btn)
        
        nav_bar.setStyleSheet("background: #252525; border-top: 1px solid #3d3d3d;")
        layout.addWidget(nav_bar)
        
        return container
    
    def load_file(self, path: str, data: Optional[bytes] = None) -> bool:
        """Load PDF file."""
        try:
            name = Path(path).name
            self.set_file_info(path, name)
            
            # Get file data
            if data is None and self.read_file_func:
                data = self.read_file_func(path, 0, -1)
            
            if data is None:
                self.page_label.setText("Error: Could not read file")
                return False
            
            self._pdf_data = data
            
            if not PYMUPDF_AVAILABLE:
                self.page_label.setText(
                    "PDF viewing requires PyMuPDF\n\n"
                    "Install with: pip install PyMuPDF\n\n"
                    f"File: {name}\n"
                    f"Size: {self._format_size(len(data))}"
                )
                self.set_status(f"Size: {self._format_size(len(data))} | PyMuPDF not installed")
                return True
            
            # Open PDF with PyMuPDF
            self._pdf_doc = fitz.open(stream=data, filetype="pdf")
            self._total_pages = len(self._pdf_doc)
            self._current_page = 0
            self._zoom_factor = 1.0
            
            # Update UI
            self.page_spin.setRange(1, self._total_pages)
            self.page_spin.setValue(1)
            self.total_label.setText(f"/ {self._total_pages}")
            
            # Render first page
            self._render_page()
            
            self.set_status(
                f"Pages: {self._total_pages} | Size: {self._format_size(len(data))}"
            )
            
            return True
            
        except Exception as e:
            self.page_label.setText(f"Error loading PDF: {e}")
            return False
    
    def _render_page(self):
        """Render current page."""
        if not PYMUPDF_AVAILABLE or not self._pdf_doc:
            return
        
        try:
            page = self._pdf_doc.load_page(self._current_page)
            
            # Render at zoom level
            mat = fitz.Matrix(self._zoom_factor * 1.5, self._zoom_factor * 1.5)
            pix = page.get_pixmap(matrix=mat)
            
            # Convert to QImage
            img = QImage(
                pix.samples, pix.width, pix.height,
                pix.stride, QImage.Format.Format_RGB888
            )
            
            # Display
            pixmap = QPixmap.fromImage(img)
            self.page_label.setPixmap(pixmap)
            self.page_label.resize(pixmap.size())
            
            # Update zoom label
            self.zoom_label.setText(f"{int(self._zoom_factor * 100)}%")
            
            # Update navigation buttons
            self.prev_btn.setEnabled(self._current_page > 0)
            self.next_btn.setEnabled(self._current_page < self._total_pages - 1)
            
        except Exception as e:
            self.page_label.setText(f"Error rendering page: {e}")
    
    def _prev_page(self):
        """Go to previous page."""
        if self._current_page > 0:
            self._current_page -= 1
            self.page_spin.setValue(self._current_page + 1)
            self._render_page()
    
    def _next_page(self):
        """Go to next page."""
        if self._current_page < self._total_pages - 1:
            self._current_page += 1
            self.page_spin.setValue(self._current_page + 1)
            self._render_page()
    
    def _goto_page(self, page: int):
        """Go to specific page."""
        self._current_page = page - 1
        self._render_page()
    
    def _zoom_in(self):
        """Zoom in."""
        self._zoom_factor = min(3.0, self._zoom_factor * 1.25)
        self._render_page()
    
    def _zoom_out(self):
        """Zoom out."""
        self._zoom_factor = max(0.25, self._zoom_factor / 1.25)
        self._render_page()
    
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
    
    def close(self):
        """Clean up resources."""
        if self._pdf_doc:
            self._pdf_doc.close()
            self._pdf_doc = None
        super().close()
