"""
FEPD - Enhanced Filesystem Tree Widget
Tree-based directory structure with sorting, metadata, and context menus

Features:
- Hierarchical filesystem view
- Size, Modified Time, Type columns
- Right-click context menus
- Sorting support
- Search/filter capability
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QLineEdit, QPushButton, QLabel, QMenu, QHeaderView
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QAction, QIcon, QColor


class FilesystemTreeWidget(QWidget):
    """
    Enhanced filesystem tree with metadata display.
    """
    
    # Signals
    item_selected = pyqtSignal(dict)  # Emits file/folder metadata
    item_double_clicked = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self._all_items = []  # Store all items for filtering
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Search/Filter bar
        search_layout = QHBoxLayout()
        search_layout.setContentsMargins(5, 5, 5, 5)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search files/folders...")
        self.search_input.textChanged.connect(self._filter_tree)
        search_layout.addWidget(self.search_input)
        
        btn_clear = QPushButton("✖")
        btn_clear.setFixedWidth(30)
        btn_clear.clicked.connect(lambda: self.search_input.clear())
        search_layout.addWidget(btn_clear)
        
        layout.addLayout(search_layout)
        
        # Tree widget with columns
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Size", "Modified", "Type"])
        self.tree.setColumnCount(4)
        self.tree.setSortingEnabled(True)
        self.tree.setAlternatingRowColors(True)
        
        # Configure columns
        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Name
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Size
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Modified
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Type
        
        # Context menu
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_context_menu)
        
        # Selection
        self.tree.itemSelectionChanged.connect(self._on_selection_changed)
        self.tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        
        layout.addWidget(self.tree)
        
        # Status bar
        self.status_label = QLabel("No filesystem loaded")
        self.status_label.setStyleSheet("padding: 3px; color: #888;")
        layout.addWidget(self.status_label)
    
    def populate_from_extracted(self, extracted_dir: Path):
        """
        Populate tree from extracted filesystem directory.
        
        Args:
            extracted_dir: Path to extracted filesystem
        """
        self.tree.clear()
        self._all_items = []
        
        if not extracted_dir.exists():
            self.status_label.setText(f"⚠ Directory not found: {extracted_dir}")
            return
        
        try:
            # Create root item
            root_item = QTreeWidgetItem(self.tree)
            root_item.setText(0, f"💿 {extracted_dir.name}")
            root_item.setExpanded(True)
            
            # Store metadata
            root_data = {
                'path': str(extracted_dir),
                'name': extracted_dir.name,
                'type': 'directory',
                'size': 0,
                'modified': None,
                'is_dir': True
            }
            root_item.setData(0, Qt.ItemDataRole.UserRole, root_data)
            
            # Recursively build tree
            self._build_tree_recursive(extracted_dir, root_item, max_depth=5)
            
            # Update status
            total_items = len(self._all_items)
            self.status_label.setText(f"✓ Loaded {total_items} items")
            self.logger.info(f"Filesystem tree populated with {total_items} items")
            
        except Exception as e:
            self.logger.error(f"Error populating filesystem tree: {e}")
            self.status_label.setText(f"❌ Error: {e}")
    
    def _build_tree_recursive(self, directory: Path, parent_item: QTreeWidgetItem, 
                             current_depth: int = 0, max_depth: int = 5):
        """
        Recursively build tree from directory structure.
        
        Args:
            directory: Current directory path
            parent_item: Parent tree item
            current_depth: Current recursion depth
            max_depth: Maximum depth to traverse
        """
        if current_depth >= max_depth:
            return
        
        try:
            # Get all entries
            entries = []
            for entry in directory.iterdir():
                try:
                    stat = entry.stat()
                    entries.append({
                        'path': entry,
                        'name': entry.name,
                        'is_dir': entry.is_dir(),
                        'size': stat.st_size if entry.is_file() else 0,
                        'modified': datetime.fromtimestamp(stat.st_mtime),
                        'type': 'Directory' if entry.is_dir() else self._get_file_type(entry)
                    })
                except (PermissionError, OSError) as e:
                    self.logger.debug(f"Skipping {entry}: {e}")
                    continue
            
            # Sort: directories first, then by name
            entries.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
            
            # Add to tree
            for entry_data in entries:
                item = QTreeWidgetItem(parent_item)
                
                # Icon and name
                icon = "📁" if entry_data['is_dir'] else self._get_file_icon(entry_data['name'])
                item.setText(0, f"{icon} {entry_data['name']}")
                
                # Size
                if entry_data['is_dir']:
                    item.setText(1, "")
                else:
                    item.setText(1, self._format_size(entry_data['size']))
                
                # Modified time
                if entry_data['modified']:
                    item.setText(2, entry_data['modified'].strftime("%Y-%m-%d %H:%M:%S"))
                
                # Type
                item.setText(3, entry_data['type'])
                
                # Store metadata
                item.setData(0, Qt.ItemDataRole.UserRole, entry_data)
                self._all_items.append((item, entry_data))
                
                # Recurse for directories
                if entry_data['is_dir']:
                    self._build_tree_recursive(
                        entry_data['path'], 
                        item, 
                        current_depth + 1, 
                        max_depth
                    )
        
        except Exception as e:
            self.logger.error(f"Error building tree for {directory}: {e}")
    
    def _get_file_type(self, path: Path) -> str:
        """Determine file type from extension."""
        suffix = path.suffix.lower()
        
        type_map = {
            # Forensic artifacts
            '.evtx': 'Event Log',
            '.evt': 'Event Log',
            '.log': 'Log File',
            '.pf': 'Prefetch',
            '.dat': 'Registry Hive',
            '.reg': 'Registry Export',
            
            # Documents
            '.pdf': 'PDF Document',
            '.doc': 'Word Document',
            '.docx': 'Word Document',
            '.xls': 'Excel Spreadsheet',
            '.xlsx': 'Excel Spreadsheet',
            '.ppt': 'PowerPoint',
            '.pptx': 'PowerPoint',
            '.txt': 'Text File',
            
            # Images
            '.jpg': 'JPEG Image',
            '.jpeg': 'JPEG Image',
            '.png': 'PNG Image',
            '.gif': 'GIF Image',
            '.bmp': 'Bitmap Image',
            
            # Executables
            '.exe': 'Executable',
            '.dll': 'DLL Library',
            '.sys': 'System File',
            
            # Archives
            '.zip': 'ZIP Archive',
            '.rar': 'RAR Archive',
            '.7z': '7-Zip Archive',
            
            # Databases
            '.db': 'Database',
            '.sqlite': 'SQLite Database',
            '.mdb': 'Access Database',
        }
        
        return type_map.get(suffix, 'File')
    
    def _get_file_icon(self, filename: str) -> str:
        """Get emoji icon for file type."""
        suffix = Path(filename).suffix.lower()
        
        icon_map = {
            '.evtx': '📜',
            '.evt': '📜',
            '.log': '📋',
            '.pf': '⚡',
            '.dat': '🗄',
            '.reg': '🗄',
            '.pdf': '📄',
            '.doc': '📝',
            '.docx': '📝',
            '.xls': '📊',
            '.xlsx': '📊',
            '.txt': '📃',
            '.jpg': '🖼',
            '.jpeg': '🖼',
            '.png': '🖼',
            '.gif': '🖼',
            '.exe': '⚙',
            '.dll': '🔧',
            '.sys': '🔧',
            '.zip': '📦',
            '.rar': '📦',
            '.7z': '📦',
            '.db': '💾',
            '.sqlite': '💾',
        }
        
        return icon_map.get(suffix, '📄')
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        size_value: float = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_value < 1024.0:
                return f"{size_value:.1f} {unit}"
            size_value /= 1024.0
        return f"{size_value:.1f} PB"
    
    def _filter_tree(self):
        """Filter tree based on search text."""
        search_text = self.search_input.text().lower()
        
        if not search_text:
            # Show all items
            for item, _ in self._all_items:
                item.setHidden(False)
            self.status_label.setText(f"✓ Showing all {len(self._all_items)} items")
            return
        
        # Hide items that don't match
        visible_count = 0
        for item, data in self._all_items:
            name = data['name'].lower()
            type_str = data['type'].lower()
            
            matches = (search_text in name or search_text in type_str)
            item.setHidden(not matches)
            
            if matches:
                visible_count += 1
                # Expand parent to show matched item
                parent = item.parent()
                while parent:
                    parent.setExpanded(True)
                    parent = parent.parent()
        
        self.status_label.setText(f"🔍 Found {visible_count} matching items")
    
    def _on_selection_changed(self):
        """Handle item selection."""
        selected = self.tree.selectedItems()
        if not selected:
            return
        
        item = selected[0]
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if data:
            self.item_selected.emit(data)
    
    def _on_item_double_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle item double-click."""
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if data:
            self.item_double_clicked.emit(data)
    
    def _show_context_menu(self, position):
        """Show right-click context menu."""
        item = self.tree.itemAt(position)
        if not item:
            return
        
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return
        
        menu = QMenu(self)
        
        # View Details
        action_details = QAction("📋 View Details", self)
        action_details.triggered.connect(lambda: self._show_item_details(data))
        menu.addAction(action_details)
        
        # Copy Path
        action_copy_path = QAction("📎 Copy Path", self)
        action_copy_path.triggered.connect(lambda: self._copy_path(data))
        menu.addAction(action_copy_path)
        
        menu.addSeparator()
        
        if not data['is_dir']:
            # Extract File
            action_extract = QAction("💾 Extract File...", self)
            action_extract.triggered.connect(lambda: self._extract_file(data))
            menu.addAction(action_extract)
            
            # Calculate Hash
            action_hash = QAction("🔐 Calculate Hash", self)
            action_hash.triggered.connect(lambda: self._calculate_hash(data))
            menu.addAction(action_hash)
            
            menu.addSeparator()
        
        # Show in Timeline
        action_timeline = QAction("⏱ Show in Timeline", self)
        action_timeline.triggered.connect(lambda: self._show_in_timeline(data))
        menu.addAction(action_timeline)
        
        # Show menu
        menu.exec(self.tree.viewport().mapToGlobal(position))
    
    def _show_item_details(self, data: dict):
        """Show detailed information popup."""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Details - {data['name']}")
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(dialog)
        
        details_text = QTextEdit()
        details_text.setReadOnly(True)
        
        html = []
        html.append(f"<h2>📋 {data['name']}</h2>")
        html.append(f"<b>Type:</b> {data['type']}<br>")
        html.append(f"<b>Path:</b> {data['path']}<br>")
        
        if not data['is_dir']:
            html.append(f"<b>Size:</b> {self._format_size(data['size'])}<br>")
        
        if data['modified']:
            html.append(f"<b>Modified:</b> {data['modified'].strftime('%Y-%m-%d %H:%M:%S')}<br>")
        
        html.append(f"<b>Is Directory:</b> {'Yes' if data['is_dir'] else 'No'}<br>")
        
        details_text.setHtml("".join(html))
        layout.addWidget(details_text)
        
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dialog.accept)
        layout.addWidget(btn_close)
        
        dialog.exec()
    
    def _copy_path(self, data: dict):
        """Copy file path to clipboard."""
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(str(data['path']))
        self.status_label.setText(f"✓ Copied path to clipboard")
    
    def _extract_file(self, data: dict):
        """Extract file to user-specified location."""
        from PyQt6.QtWidgets import QFileDialog, QMessageBox
        
        # TODO: Implement file extraction
        QMessageBox.information(
            self,
            "Extract File",
            f"File extraction not yet implemented.\n\nSource: {data['path']}"
        )
    
    def _calculate_hash(self, data: dict):
        """Calculate and display file hash."""
        from PyQt6.QtWidgets import QMessageBox
        import hashlib
        
        try:
            # Calculate MD5 and SHA256
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            
            with open(data['path'], 'rb') as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha256.update(chunk)
            
            QMessageBox.information(
                self,
                f"Hash - {data['name']}",
                f"MD5: {md5.hexdigest()}\n\nSHA256: {sha256.hexdigest()}"
            )
        except Exception as e:
            QMessageBox.warning(self, "Hash Error", f"Failed to calculate hash: {e}")
    
    def _show_in_timeline(self, data: dict):
        """Navigate to timeline tab and highlight this file's events."""
        # This will be implemented by parent window
        self.logger.info(f"Show in timeline requested for: {data['name']}")
        # TODO: Emit signal to main window to switch tabs and filter timeline
