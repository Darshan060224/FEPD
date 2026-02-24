"""
Text Viewer
===========

Read-only text file viewer with syntax highlighting.
"""

from PyQt6.QtWidgets import (
    QWidget, QPlainTextEdit, QVBoxLayout, QComboBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QTextCharFormat, QColor, QSyntaxHighlighter, QTextDocument, QAction
from typing import Optional
from pathlib import Path

from .base_viewer import BaseViewer


class SyntaxHighlighter(QSyntaxHighlighter):
    """Basic syntax highlighter for common file types."""
    
    def __init__(self, document: QTextDocument, file_type: str = "text"):
        super().__init__(document)
        self.file_type = file_type
        self._setup_formats()
    
    def _setup_formats(self):
        """Set up text formats for highlighting."""
        # Keywords
        self.keyword_format = QTextCharFormat()
        self.keyword_format.setForeground(QColor("#569cd6"))
        self.keyword_format.setFontWeight(700)
        
        # Strings
        self.string_format = QTextCharFormat()
        self.string_format.setForeground(QColor("#ce9178"))
        
        # Comments
        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor("#6a9955"))
        
        # Numbers
        self.number_format = QTextCharFormat()
        self.number_format.setForeground(QColor("#b5cea8"))
        
        # Paths/URLs
        self.path_format = QTextCharFormat()
        self.path_format.setForeground(QColor("#4ec9b0"))
    
    def highlightBlock(self, text: str):
        """Apply highlighting to a block of text."""
        if self.file_type in ("log", "txt"):
            self._highlight_log(text)
        elif self.file_type in ("json", "xml", "html"):
            self._highlight_markup(text)
        elif self.file_type in ("py", "python"):
            self._highlight_python(text)
        elif self.file_type in ("ini", "cfg", "conf"):
            self._highlight_config(text)
    
    def _highlight_log(self, text: str):
        """Highlight log file content."""
        import re
        
        # Timestamps
        for match in re.finditer(r'\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}', text):
            self.setFormat(match.start(), match.end() - match.start(), self.number_format)
        
        # Error/Warning keywords
        error_format = QTextCharFormat()
        error_format.setForeground(QColor("#f14c4c"))
        for match in re.finditer(r'\b(ERROR|CRITICAL|FATAL|FAIL)\b', text, re.IGNORECASE):
            self.setFormat(match.start(), match.end() - match.start(), error_format)
        
        warn_format = QTextCharFormat()
        warn_format.setForeground(QColor("#cca700"))
        for match in re.finditer(r'\b(WARNING|WARN)\b', text, re.IGNORECASE):
            self.setFormat(match.start(), match.end() - match.start(), warn_format)
        
        # Paths
        for match in re.finditer(r'[A-Z]:\\[^\s:*?"<>|]+|/[^\s:*?"<>|]+', text):
            self.setFormat(match.start(), match.end() - match.start(), self.path_format)
    
    def _highlight_markup(self, text: str):
        """Highlight JSON/XML/HTML."""
        import re
        
        # Strings
        for match in re.finditer(r'"[^"]*"', text):
            self.setFormat(match.start(), match.end() - match.start(), self.string_format)
        
        # Tags/keys
        for match in re.finditer(r'<[^>]+>|"[^"]+"\s*:', text):
            self.setFormat(match.start(), match.end() - match.start(), self.keyword_format)
    
    def _highlight_python(self, text: str):
        """Highlight Python syntax."""
        import re
        
        keywords = [
            'def', 'class', 'import', 'from', 'if', 'else', 'elif',
            'for', 'while', 'try', 'except', 'finally', 'with', 'as',
            'return', 'yield', 'raise', 'pass', 'break', 'continue',
            'True', 'False', 'None', 'and', 'or', 'not', 'in', 'is'
        ]
        
        for kw in keywords:
            for match in re.finditer(rf'\b{kw}\b', text):
                self.setFormat(match.start(), match.end() - match.start(), self.keyword_format)
        
        # Strings
        for match in re.finditer(r'["\'][^"\']*["\']', text):
            self.setFormat(match.start(), match.end() - match.start(), self.string_format)
        
        # Comments
        for match in re.finditer(r'#.*$', text):
            self.setFormat(match.start(), match.end() - match.start(), self.comment_format)
    
    def _highlight_config(self, text: str):
        """Highlight config files."""
        import re
        
        # Section headers
        for match in re.finditer(r'^\[.*\]', text, re.MULTILINE):
            self.setFormat(match.start(), match.end() - match.start(), self.keyword_format)
        
        # Comments
        for match in re.finditer(r'^[#;].*$', text, re.MULTILINE):
            self.setFormat(match.start(), match.end() - match.start(), self.comment_format)
        
        # Keys
        for match in re.finditer(r'^[^=\s]+(?=\s*=)', text, re.MULTILINE):
            self.setFormat(match.start(), match.end() - match.start(), self.path_format)


class TextViewer(BaseViewer):
    """
    Read-only text file viewer.
    
    Features:
    - Syntax highlighting for common formats
    - Line numbers
    - Search functionality
    - Zoom in/out
    """
    
    SUPPORTED_EXTENSIONS = [
        '.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm',
        '.py', '.js', '.css', '.md', '.ini', '.cfg', '.conf',
        '.bat', '.ps1', '.sh', '.yaml', '.yml', '.sql', '.reg'
    ]
    
    def __init__(self, parent: Optional[QWidget] = None, read_file_func=None):
        # Initialize attributes BEFORE super().__init__() since it calls _create_content_widget()
        self._font_size = 11
        self._highlighter: Optional[SyntaxHighlighter] = None
        
        super().__init__(parent, title="Text Viewer", read_file_func=read_file_func)
        self.title_icon.setText("📝")
    
    def _create_content_widget(self) -> QWidget:
        """Create text editor widget."""
        self.text_edit = QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        
        # Set monospace font
        font = QFont("Consolas", self._font_size)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.text_edit.setFont(font)
        
        # Style
        self.text_edit.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: none;
                selection-background-color: #264f78;
                selection-color: #ffffff;
            }
        """)
        
        # Line wrap
        self.text_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        
        return self.text_edit
    
    def _setup_toolbar(self):
        """Add text-specific toolbar actions."""
        super()._setup_toolbar()
        
        # Word wrap toggle
        wrap_action = QAction("↩ Wrap", self)
        wrap_action.setCheckable(True)
        wrap_action.setToolTip("Toggle Word Wrap")
        wrap_action.toggled.connect(self._toggle_wrap)
        self.toolbar.addAction(wrap_action)
        
        # Encoding selector
        self.toolbar.addSeparator()
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(['utf-8', 'utf-16', 'latin-1', 'cp1252', 'ascii'])
        self.encoding_combo.setStyleSheet("""
            QComboBox {
                background: #3d3d3d;
                color: #e0e0e0;
                border: 1px solid #555;
                padding: 2px 8px;
            }
        """)
        self.encoding_combo.currentTextChanged.connect(self._reload_with_encoding)
        self.toolbar.addWidget(self.encoding_combo)
    
    def load_file(self, path: str, data: Optional[bytes] = None) -> bool:
        """Load text file."""
        try:
            name = Path(path).name
            self.set_file_info(path, name)
            
            # Get file data
            if data is None and self.read_file_func:
                data = self.read_file_func(path, 0, -1)
            
            if data is None:
                self.text_edit.setPlainText("Error: Could not read file")
                return False
            
            # Decode with selected encoding
            encoding = self.encoding_combo.currentText()
            try:
                text = data.decode(encoding, errors='replace')
            except:
                text = data.decode('utf-8', errors='replace')
            
            self.text_edit.setPlainText(text)
            self._current_data = data  # Store for re-encoding
            
            # Set up syntax highlighting
            ext = Path(path).suffix.lower()
            file_type = ext.lstrip('.')
            self._highlighter = SyntaxHighlighter(self.text_edit.document(), file_type)
            
            # Update status
            lines = text.count('\n') + 1
            size = len(data)
            self.set_status(f"Lines: {lines:,} | Size: {self._format_size(size)} | Encoding: {encoding}")
            
            return True
            
        except Exception as e:
            self.text_edit.setPlainText(f"Error loading file: {e}")
            return False
    
    def _toggle_wrap(self, enabled: bool):
        """Toggle word wrap."""
        if enabled:
            self.text_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        else:
            self.text_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    
    def _reload_with_encoding(self, encoding: str):
        """Reload file with different encoding."""
        if hasattr(self, '_current_data') and self._current_data:
            try:
                text = self._current_data.decode(encoding, errors='replace')
                self.text_edit.setPlainText(text)
            except:
                pass
    
    def _zoom_in(self):
        """Increase font size."""
        self._font_size = min(24, self._font_size + 1)
        font = self.text_edit.font()
        font.setPointSize(self._font_size)
        self.text_edit.setFont(font)
    
    def _zoom_out(self):
        """Decrease font size."""
        self._font_size = max(8, self._font_size - 1)
        font = self.text_edit.font()
        font.setPointSize(self._font_size)
        self.text_edit.setFont(font)
    
    def _format_size(self, size: int) -> str:
        """Format byte size for display."""
        size_f = float(size)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_f < 1024:
                return f"{size_f:.1f} {unit}"
            size_f /= 1024
        return f"{size_f:.1f} TB"
    
    def get_supported_extensions(self) -> list:
        return self.SUPPORTED_EXTENSIONS
