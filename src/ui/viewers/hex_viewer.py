"""
Hex Viewer
==========

Forensic hex viewer for binary file inspection.
"""

from PyQt6.QtWidgets import (
    QWidget, QPlainTextEdit, QVBoxLayout, QHBoxLayout,
    QLabel, QSpinBox, QCheckBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QTextCharFormat, QColor, QAction
from typing import Optional
from pathlib import Path

from .base_viewer import BaseViewer


class HexViewer(BaseViewer):
    """
    Hex viewer for binary files.
    
    Features:
    - Hex + ASCII side-by-side view
    - Offset display
    - Configurable bytes per line
    - Non-printable character highlighting
    """
    
    def __init__(self, parent: Optional[QWidget] = None, read_file_func=None):
        # Initialize attributes BEFORE super().__init__() since it calls _create_content_widget()
        self._font_size = 11
        self._bytes_per_line = 16
        self._data: Optional[bytes] = None
        self._offset = 0
        self._chunk_size = 16 * 1024  # 16KB per view
        
        super().__init__(parent, title="Hex Viewer", read_file_func=read_file_func)
        self.title_icon.setText("🔢")
    
    def _create_content_widget(self) -> QWidget:
        """Create hex display widget."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Hex display
        self.hex_display = QPlainTextEdit()
        self.hex_display.setReadOnly(True)
        
        # Monospace font
        font = QFont("Consolas", self._font_size)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.hex_display.setFont(font)
        
        self.hex_display.setStyleSheet("""
            QPlainTextEdit {
                background-color: #0d1117;
                color: #c9d1d9;
                border: none;
                selection-background-color: #264f78;
            }
        """)
        
        self.hex_display.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.hex_display)
        
        # Navigation bar
        nav_bar = QWidget()
        nav_layout = QHBoxLayout(nav_bar)
        nav_layout.setContentsMargins(8, 4, 8, 4)
        
        nav_layout.addWidget(QLabel("Offset:"))
        self.offset_spin = QSpinBox()
        self.offset_spin.setRange(0, 0)
        self.offset_spin.setSingleStep(256)
        self.offset_spin.valueChanged.connect(self._goto_offset)
        self.offset_spin.setStyleSheet("""
            QSpinBox {
                background: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                padding: 2px;
            }
        """)
        nav_layout.addWidget(self.offset_spin)
        
        nav_layout.addWidget(QLabel("Bytes/Line:"))
        self.bytes_spin = QSpinBox()
        self.bytes_spin.setRange(8, 32)
        self.bytes_spin.setSingleStep(8)
        self.bytes_spin.setValue(16)
        self.bytes_spin.valueChanged.connect(self._change_bytes_per_line)
        self.bytes_spin.setStyleSheet(self.offset_spin.styleSheet())
        nav_layout.addWidget(self.bytes_spin)
        
        self.show_ascii = QCheckBox("Show ASCII")
        self.show_ascii.setChecked(True)
        self.show_ascii.toggled.connect(self._refresh_display)
        self.show_ascii.setStyleSheet("color: #c9d1d9;")
        nav_layout.addWidget(self.show_ascii)
        
        nav_layout.addStretch()
        
        nav_bar.setStyleSheet("background: #161b22; border-top: 1px solid #30363d;")
        layout.addWidget(nav_bar)
        
        return container
    
    def _setup_toolbar(self):
        """Add hex-specific toolbar actions."""
        super()._setup_toolbar()
        
        # Go to offset
        goto_action = QAction("⏩ Go to", self)
        goto_action.setToolTip("Go to offset")
        goto_action.triggered.connect(self._show_goto_dialog)
        self.toolbar.addAction(goto_action)
    
    def load_file(self, path: str, data: Optional[bytes] = None) -> bool:
        """Load binary file for hex view."""
        try:
            name = Path(path).name
            self.set_file_info(path, name)
            
            # Get file data
            if data is None and self.read_file_func:
                data = self.read_file_func(path, 0, -1)
            
            if data is None:
                self.hex_display.setPlainText("Error: Could not read file")
                return False
            
            self._data = data
            self._offset = 0
            
            # Update offset spinner range
            self.offset_spin.setRange(0, max(0, len(data) - self._chunk_size))
            
            # Display hex
            self._refresh_display()
            
            # Update status
            self.set_status(f"Size: {self._format_size(len(data))} | {len(data):,} bytes")
            
            return True
            
        except Exception as e:
            self.hex_display.setPlainText(f"Error loading file: {e}")
            return False
    
    def _refresh_display(self):
        """Refresh the hex display."""
        if not self._data:
            return
        
        # Get chunk to display
        chunk = self._data[self._offset:self._offset + self._chunk_size]
        
        lines = []
        for i in range(0, len(chunk), self._bytes_per_line):
            row = chunk[i:i + self._bytes_per_line]
            offset = self._offset + i
            
            # Offset column
            line = f"{offset:08X}  "
            
            # Hex bytes
            hex_bytes = []
            for j, b in enumerate(row):
                hex_bytes.append(f"{b:02X}")
                if (j + 1) % 8 == 0:
                    hex_bytes.append("")  # Extra space every 8 bytes
            
            # Pad to full line width
            while len(hex_bytes) < self._bytes_per_line + (self._bytes_per_line // 8):
                hex_bytes.append("  ")
            
            line += " ".join(hex_bytes)
            
            # ASCII column
            if self.show_ascii.isChecked():
                line += "  │"
                for b in row:
                    if 32 <= b <= 126:
                        line += chr(b)
                    else:
                        line += "·"
                line += "│"
            
            lines.append(line)
        
        # Header
        header = "Offset    "
        for i in range(self._bytes_per_line):
            header += f"{i:02X} "
            if (i + 1) % 8 == 0:
                header += " "
        if self.show_ascii.isChecked():
            header += "  │ASCII│"
        
        separator = "─" * len(header)
        
        text = header + "\n" + separator + "\n" + "\n".join(lines)
        self.hex_display.setPlainText(text)
    
    def _goto_offset(self, offset: int):
        """Go to specific offset."""
        self._offset = offset
        self._refresh_display()
    
    def _change_bytes_per_line(self, count: int):
        """Change bytes per line."""
        self._bytes_per_line = count
        self._refresh_display()
    
    def _show_goto_dialog(self):
        """Show go to offset dialog."""
        from PyQt6.QtWidgets import QInputDialog
        
        if not self._data:
            return
        
        offset, ok = QInputDialog.getText(
            self, "Go to Offset",
            "Enter offset (hex or decimal):",
            text=f"0x{self._offset:X}"
        )
        
        if ok and offset:
            try:
                if offset.startswith('0x') or offset.startswith('0X'):
                    new_offset = int(offset, 16)
                else:
                    new_offset = int(offset)
                
                new_offset = max(0, min(new_offset, len(self._data) - 1))
                self._offset = new_offset
                self.offset_spin.setValue(new_offset)
                self._refresh_display()
            except ValueError:
                pass
    
    def _zoom_in(self):
        """Increase font size."""
        self._font_size = min(20, self._font_size + 1)
        font = self.hex_display.font()
        font.setPointSize(self._font_size)
        self.hex_display.setFont(font)
    
    def _zoom_out(self):
        """Decrease font size."""
        self._font_size = max(8, self._font_size - 1)
        font = self.hex_display.font()
        font.setPointSize(self._font_size)
        self.hex_display.setFont(font)
    
    def _format_size(self, size: int) -> str:
        """Format byte size."""
        size_f = float(size)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_f < 1024:
                return f"{size_f:.1f} {unit}"
            size_f /= 1024
        return f"{size_f:.1f} TB"
    
    def get_supported_extensions(self) -> list:
        return ['*']  # Supports all files
