# Advanced Features Implementation Guide - Part 2

**FEPD - Forensic Evidence Parser Dashboard**  
**Advanced Features: Artifact Navigation, Workflow Integration & Performance**

---

## 4. 🧭 Artifact Timeline Navigation & Filtering

### Overview
Enhanced artifact tab with clickable counts, detail views, and timeline jump functionality.

### Architecture

```
src/
├── ui/
│   ├── tabs/
│   │   └── artifacts_tab.py        # EXISTING - Enhanced
│   └── dialogs/
│       ├── artifact_details_dialog.py  # NEW - Detailed artifact view
│       └── artifact_filter_dialog.py   # NEW - Advanced filtering
└── utils/
    └── artifact_navigator.py       # NEW - Navigation logic
```

### Implementation

**File: `src/utils/artifact_navigator.py`**
```python
"""
Artifact navigation and filtering utilities
"""

import pandas as pd
import logging
from typing import List, Dict, Optional, Tuple
from datetime import datetime


class ArtifactNavigator:
    """
    Navigate between artifacts and timeline events.
    
    Features:
    - Find artifacts by hash
    - Filter artifacts by type, user, time range
    - Jump from artifact to timeline events
    - Cross-reference artifacts
    """
    
    def __init__(self, artifacts_df: pd.DataFrame, timeline_df: pd.DataFrame):
        """
        Initialize navigator with artifact and timeline data.
        
        Args:
            artifacts_df: DataFrame with artifacts metadata
            timeline_df: DataFrame with timeline events
        """
        self.logger = logging.getLogger(__name__)
        self.artifacts_df = artifacts_df
        self.timeline_df = timeline_df
    
    def find_artifact_timeline_events(self, artifact_path: str) -> pd.DataFrame:
        """
        Find timeline events related to specific artifact.
        
        Args:
            artifact_path: Path to artifact file
        
        Returns:
            DataFrame with related timeline events
        """
        # Look for events that reference this artifact
        related_events = self.timeline_df[
            self.timeline_df['Source'].str.contains(artifact_path, case=False, na=False) |
            self.timeline_df['Description'].str.contains(artifact_path, case=False, na=False)
        ]
        
        return related_events.sort_values('Timestamp')
    
    def filter_artifacts(self, 
                        artifact_types: List[str] = None,
                        hash_value: str = None,
                        time_range: Tuple[datetime, datetime] = None,
                        user_filter: str = None) -> pd.DataFrame:
        """
        Filter artifacts by multiple criteria.
        
        Args:
            artifact_types: List of artifact types to include
            hash_value: Filter by hash (MD5/SHA256)
            time_range: (start_date, end_date) tuple
            user_filter: Filter by user/path substring
        
        Returns:
            Filtered DataFrame
        """
        filtered = self.artifacts_df.copy()
        
        # Filter by type
        if artifact_types:
            filtered = filtered[filtered['Type'].isin(artifact_types)]
        
        # Filter by hash
        if hash_value:
            filtered = filtered[
                (filtered['MD5'].str.contains(hash_value, case=False, na=False)) |
                (filtered['SHA256'].str.contains(hash_value, case=False, na=False))
            ]
        
        # Filter by time range
        if time_range and 'Modified' in filtered.columns:
            start, end = time_range
            filtered['Modified_dt'] = pd.to_datetime(filtered['Modified'], errors='coerce')
            filtered = filtered[
                (filtered['Modified_dt'] >= start) &
                (filtered['Modified_dt'] <= end)
            ]
            filtered = filtered.drop(columns=['Modified_dt'])
        
        # Filter by user/path
        if user_filter:
            filtered = filtered[
                filtered['Path'].str.contains(user_filter, case=False, na=False)
            ]
        
        return filtered
    
    def get_artifact_by_hash(self, hash_value: str) -> Optional[Dict]:
        """
        Find artifact by hash value.
        
        Args:
            hash_value: MD5 or SHA256 hash
        
        Returns:
            Artifact record as dictionary or None
        """
        matches = self.artifacts_df[
            (self.artifacts_df['MD5'] == hash_value) |
            (self.artifacts_df['SHA256'] == hash_value)
        ]
        
        if not matches.empty:
            return matches.iloc[0].to_dict()
        return None
    
    def get_artifact_statistics(self, artifact_type: str = None) -> Dict:
        """
        Get statistics about artifacts.
        
        Args:
            artifact_type: Optional type filter
        
        Returns:
            Dictionary with statistics
        """
        df = self.artifacts_df
        if artifact_type:
            df = df[df['Type'] == artifact_type]
        
        return {
            'total_count': len(df),
            'total_size': df['Size'].sum() if 'Size' in df.columns else 0,
            'unique_hashes': df['SHA256'].nunique() if 'SHA256' in df.columns else 0,
            'types': df['Type'].value_counts().to_dict() if 'Type' in df.columns else {}
        }
```

**File: `src/ui/dialogs/artifact_details_dialog.py`**
```python
"""
Detailed artifact information dialog
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QTextEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QTabWidget, QWidget
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
import pandas as pd


class ArtifactDetailsDialog(QDialog):
    """
    Show detailed information about an artifact.
    
    Features:
    - File metadata
    - Hash values
    - Related timeline events
    - Jump to timeline button
    """
    
    jump_to_timeline = pyqtSignal(pd.DataFrame)  # Emit related events
    
    def __init__(self, artifact_data: dict, related_events: pd.DataFrame = None, parent=None):
        super().__init__(parent)
        self.artifact_data = artifact_data
        self.related_events = related_events
        
        self.setWindowTitle(f"Artifact Details - {artifact_data.get('Name', 'Unknown')}")
        self.setModal(True)
        self.setMinimumSize(800, 600)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout()
        
        # Header
        header = QLabel(f"<h2>📦 {self.artifact_data.get('Name', 'Unknown')}</h2>")
        layout.addWidget(header)
        
        # Tab widget
        tabs = QTabWidget()
        
        # Metadata tab
        metadata_tab = self._create_metadata_tab()
        tabs.addTab(metadata_tab, "📋 Metadata")
        
        # Timeline tab (if events available)
        if self.related_events is not None and not self.related_events.empty:
            timeline_tab = self._create_timeline_tab()
            tabs.addTab(timeline_tab, f"⏱️ Timeline ({len(self.related_events)} events)")
        
        layout.addWidget(tabs)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        if self.related_events is not None and not self.related_events.empty:
            jump_btn = QPushButton("🔗 Jump to Timeline")
            jump_btn.setStyleSheet("""
                QPushButton {
                    background-color: #4A90E2;
                    color: white;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #357ABD;
                }
            """)
            jump_btn.clicked.connect(self._on_jump_to_timeline)
            button_layout.addWidget(jump_btn)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _create_metadata_tab(self) -> QWidget:
        """Create metadata information tab."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Format metadata as HTML
        metadata_html = f"""
        <style>
            table {{ border-collapse: collapse; width: 100%; }}
            th {{ background-color: #2E2E2E; color: white; padding: 8px; text-align: left; }}
            td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
            .label {{ font-weight: bold; color: #4A90E2; }}
        </style>
        <table>
            <tr><td class="label">Path:</td><td>{self.artifact_data.get('Path', 'N/A')}</td></tr>
            <tr><td class="label">Type:</td><td>{self.artifact_data.get('Type', 'N/A')}</td></tr>
            <tr><td class="label">Size:</td><td>{self._format_size(self.artifact_data.get('Size', 0))}</td></tr>
            <tr><td class="label">Modified:</td><td>{self.artifact_data.get('Modified', 'N/A')}</td></tr>
            <tr><td class="label">MD5:</td><td><code>{self.artifact_data.get('MD5', 'N/A')}</code></td></tr>
            <tr><td class="label">SHA256:</td><td><code>{self.artifact_data.get('SHA256', 'N/A')}</code></td></tr>
        </table>
        """
        
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setHtml(metadata_html)
        layout.addWidget(text_edit)
        
        widget.setLayout(layout)
        return widget
    
    def _create_timeline_tab(self) -> QWidget:
        """Create related timeline events tab."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(['Timestamp', 'Event Type', 'Description', 'Classification'])
        table.horizontalHeader().setStretchLastSection(True)
        
        # Populate with related events
        table.setRowCount(len(self.related_events))
        for i, (_, row) in enumerate(self.related_events.iterrows()):
            table.setItem(i, 0, QTableWidgetItem(str(row.get('Timestamp', ''))))
            table.setItem(i, 1, QTableWidgetItem(str(row.get('Event Type', ''))))
            table.setItem(i, 2, QTableWidgetItem(str(row.get('Description', ''))))
            table.setItem(i, 3, QTableWidgetItem(str(row.get('Classification', ''))))
        
        layout.addWidget(table)
        widget.setLayout(layout)
        return widget
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def _on_jump_to_timeline(self):
        """Emit signal to jump to timeline with filtered events."""
        self.jump_to_timeline.emit(self.related_events)
        self.accept()
```

**File: `src/ui/dialogs/artifact_filter_dialog.py`**
```python
"""
Advanced artifact filtering dialog
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QDateEdit, QPushButton,
    QCheckBox, QGroupBox, QFormLayout
)
from PyQt6.QtCore import Qt, QDate
from typing import Dict, List


class ArtifactFilterDialog(QDialog):
    """
    Advanced filtering for artifacts.
    
    Features:
    - Filter by type (checkboxes)
    - Hash search
    - Date range
    - Path/user filter
    """
    
    def __init__(self, available_types: List[str], parent=None):
        super().__init__(parent)
        self.available_types = available_types
        self.filters = {}
        
        self.setWindowTitle("Advanced Artifact Filters")
        self.setModal(True)
        self.setMinimumWidth(500)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout()
        
        # Artifact types
        types_group = QGroupBox("Artifact Types")
        types_layout = QVBoxLayout()
        
        self.type_checkboxes = {}
        for artifact_type in self.available_types:
            cb = QCheckBox(artifact_type)
            cb.setChecked(True)
            self.type_checkboxes[artifact_type] = cb
            types_layout.addWidget(cb)
        
        types_group.setLayout(types_layout)
        layout.addWidget(types_group)
        
        # Hash filter
        hash_layout = QHBoxLayout()
        hash_layout.addWidget(QLabel("Hash (MD5/SHA256):"))
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter hash value...")
        hash_layout.addWidget(self.hash_input)
        layout.addLayout(hash_layout)
        
        # Date range
        date_group = QGroupBox("Date Range")
        date_layout = QFormLayout()
        
        self.start_date = QDateEdit()
        self.start_date.setDate(QDate.currentDate().addYears(-1))
        self.start_date.setCalendarPopup(True)
        
        self.end_date = QDateEdit()
        self.end_date.setDate(QDate.currentDate())
        self.end_date.setCalendarPopup(True)
        
        date_layout.addRow("Start Date:", self.start_date)
        date_layout.addRow("End Date:", self.end_date)
        
        date_group.setLayout(date_layout)
        layout.addWidget(date_group)
        
        # Path filter
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Path/User Filter:"))
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Enter path substring...")
        path_layout.addWidget(self.path_input)
        layout.addLayout(path_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        apply_btn = QPushButton("Apply Filters")
        apply_btn.clicked.connect(self.accept)
        button_layout.addWidget(apply_btn)
        
        reset_btn = QPushButton("Reset")
        reset_btn.clicked.connect(self._reset_filters)
        button_layout.addWidget(reset_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _reset_filters(self):
        """Reset all filters to default."""
        for cb in self.type_checkboxes.values():
            cb.setChecked(True)
        self.hash_input.clear()
        self.path_input.clear()
        self.start_date.setDate(QDate.currentDate().addYears(-1))
        self.end_date.setDate(QDate.currentDate())
    
    def get_filters(self) -> Dict:
        """
        Get selected filters.
        
        Returns:
            Dictionary with filter criteria
        """
        return {
            'types': [t for t, cb in self.type_checkboxes.items() if cb.isChecked()],
            'hash': self.hash_input.text().strip() or None,
            'date_range': (
                self.start_date.date().toPyDate(),
                self.end_date.date().toPyDate()
            ) if self.start_date.date() != self.end_date.date() else None,
            'path': self.path_input.text().strip() or None
        }
```

**Enhance Artifacts Tab (`src/ui/tabs/artifacts_tab.py`):**

```python
# Add to existing ArtifactsTab class

def _setup_ui(self):
    """Enhanced UI with clickable counts."""
    # ... existing code ...
    
    # Make table cells clickable
    self.artifacts_table.cellClicked.connect(self._on_cell_clicked)
    
    # Add filter button
    self.filter_btn = QPushButton("🔍 Advanced Filters")
    self.filter_btn.clicked.connect(self._show_filter_dialog)
    # Add to toolbar

def _on_cell_clicked(self, row: int, column: int):
    """Handle click on artifact count cell."""
    from ..dialogs.artifact_details_dialog import ArtifactDetailsDialog
    from ...utils.artifact_navigator import ArtifactNavigator
    
    # Get artifact data from clicked row
    artifact_name = self.artifacts_table.item(row, 0).text()
    artifact_data = self._get_artifact_data(row)
    
    # Find related timeline events
    navigator = ArtifactNavigator(self.artifacts_df, self.timeline_df)
    related_events = navigator.find_artifact_timeline_events(artifact_data['Path'])
    
    # Show details dialog
    dialog = ArtifactDetailsDialog(artifact_data, related_events, self)
    dialog.jump_to_timeline.connect(self._on_jump_to_timeline)
    dialog.exec()

def _on_jump_to_timeline(self, filtered_events: pd.DataFrame):
    """Jump to timeline tab with filtered events."""
    # Signal parent window to switch to timeline tab with filter
    if self.parent() and hasattr(self.parent(), 'show_filtered_timeline'):
        self.parent().show_filtered_timeline(filtered_events)

def _show_filter_dialog(self):
    """Show advanced filter dialog."""
    from ..dialogs.artifact_filter_dialog import ArtifactFilterDialog
    
    available_types = self.artifacts_df['Type'].unique().tolist()
    dialog = ArtifactFilterDialog(available_types, self)
    
    if dialog.exec():
        filters = dialog.get_filters()
        self._apply_filters(filters)

def _apply_filters(self, filters: Dict):
    """Apply selected filters to artifacts table."""
    from ...utils.artifact_navigator import ArtifactNavigator
    
    navigator = ArtifactNavigator(self.artifacts_df, self.timeline_df)
    filtered_df = navigator.filter_artifacts(
        artifact_types=filters.get('types'),
        hash_value=filters.get('hash'),
        time_range=filters.get('date_range'),
        user_filter=filters.get('path')
    )
    
    self._populate_table(filtered_df)
    self.status_label.setText(f"Showing {len(filtered_df)} of {len(self.artifacts_df)} artifacts")
```

---

## 5. 🗂 Folder Tree & Metadata Viewer (Enhancement)

### Status: **Partially Complete** ✅

Your existing code in `main_window.py` already implements:
- ✅ Virtual folder tree from disk image
- ✅ 2-column layout (tree left, metadata right)
- ✅ File metadata display (name, size, type, timestamps)
- ✅ **RECENTLY FIXED**: Files now display correctly when clicking folders

### Recommended Enhancements

**Add these features to existing implementation:**

```python
# In main_window.py, add to tree widget setup

def _enhance_tree_widget(self):
    """Add advanced tree features."""
    
    # 1. Context menu on right-click
    self.image_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    self.image_tree.customContextMenuRequested.connect(self._show_tree_context_menu)
    
    # 2. Double-click to extract file
    self.image_tree.itemDoubleClicked.connect(self._on_tree_item_double_clicked)
    
    # 3. Search/filter box above tree
    self.tree_search = QLineEdit()
    self.tree_search.setPlaceholderText("🔍 Search files and folders...")
    self.tree_search.textChanged.connect(self._filter_tree_items)

def _show_tree_context_menu(self, position):
    """Show context menu on tree item."""
    from PyQt6.QtWidgets import QMenu
    
    item = self.image_tree.itemAt(position)
    if not item:
        return
    
    menu = QMenu()
    
    # Add actions
    extract_action = menu.addAction("📤 Extract File")
    hash_action = menu.addAction("🔐 Calculate Hash")
    timeline_action = menu.addAction("⏱️ Show in Timeline")
    properties_action = menu.addAction("📋 Properties")
    
    action = menu.exec(self.image_tree.viewport().mapToGlobal(position))
    
    if action == extract_action:
        self._extract_file_from_tree(item)
    elif action == hash_action:
        self._calculate_file_hash(item)
    elif action == timeline_action:
        self._show_file_in_timeline(item)
    elif action == properties_action:
        self._show_file_properties(item)

def _filter_tree_items(self, search_text: str):
    """Filter tree items by search text."""
    # Implement tree filtering logic
    pass

def _calculate_file_hash(self, item):
    """Calculate and display file hash."""
    from PyQt6.QtWidgets import QMessageBox
    import hashlib
    
    item_data = item.data(0, Qt.ItemDataRole.UserRole)
    if item_data and item_data['type'] == 'file':
        # Read file and calculate hash
        # Show in dialog
        pass
```

---

## 6. 🧩 Workflow Integration

### Overview
Seamless case creation and image ingestion workflow from application launch.

### Architecture

```
src/
├── ui/
│   ├── dialogs/
│   │   ├── case_selection_dialog.py   # EXISTING - Enhanced
│   │   └── image_selection_dialog.py  # NEW - Image picker
│   └── main_window.py                  # EXISTING - Enhanced startup
└── utils/
    └── workflow_manager.py             # NEW - Workflow orchestration
```

### Implementation

**File: `src/utils/workflow_manager.py`**
```python
"""
Workflow management for case and image handling
"""

import logging
from pathlib import Path
from typing import Optional, Tuple
from .config import Config


class WorkflowManager:
    """
    Manage application workflow from startup to analysis.
    
    Features:
    - Auto-detect last opened case
    - Prompt for case selection on startup
    - Store image path in config
    - Auto-ingest after case creation
    - Resume previous session
    """
    
    def __init__(self, config: Config):
        """
        Initialize workflow manager.
        
        Args:
            config: Application configuration
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
    
    def get_startup_action(self) -> Tuple[str, Optional[str]]:
        """
        Determine startup action based on config.
        
        Returns:
            Tuple of (action, case_id)
            Actions: 'show_dialog', 'open_last_case', 'create_new'
        """
        # Check if there's a last opened case
        last_case = self.config.get('last_opened_case')
        
        if last_case and self._case_exists(last_case):
            # Ask if user wants to reopen
            return ('open_last_case', last_case)
        
        # Show case selection dialog
        return ('show_dialog', None)
    
    def _case_exists(self, case_id: str) -> bool:
        """Check if case directory exists."""
        case_dir = self.config.get_case_dir(case_id)
        return case_dir.exists()
    
    def store_image_path(self, case_id: str, image_path: str):
        """
        Store image path in case config.
        
        Args:
            case_id: Case identifier
            image_path: Path to disk image
        """
        case_dir = self.config.get_case_dir(case_id)
        config_file = case_dir / 'case_config.json'
        
        import json
        config_data = {}
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                config_data = json.load(f)
        
        config_data['image_path'] = str(image_path)
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        self.logger.info(f"Stored image path for case {case_id}: {image_path}")
    
    def get_image_path(self, case_id: str) -> Optional[str]:
        """
        Get stored image path for case.
        
        Args:
            case_id: Case identifier
        
        Returns:
            Image path or None
        """
        case_dir = self.config.get_case_dir(case_id)
        config_file = case_dir / 'case_config.json'
        
        if not config_file.exists():
            return None
        
        import json
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        
        return config_data.get('image_path')
```

**File: `src/ui/dialogs/image_selection_dialog.py`**
```python
"""
Image selection dialog for case creation
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFileDialog, QLineEdit, QMessageBox
)
from PyQt6.QtCore import Qt
from pathlib import Path


class ImageSelectionDialog(QDialog):
    """
    Dialog for selecting disk image during case creation.
    
    Features:
    - File picker for E01, RAW, DD images
    - Image validation
    - Path display
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_image = None
        
        self.setWindowTitle("Select Disk Image")
        self.setModal(True)
        self.setMinimumWidth(600)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout()
        
        # Header
        header = QLabel(
            "<h2>Select Forensic Disk Image</h2>"
            "<p>Choose an E01, RAW, or DD image file to analyze.</p>"
        )
        header.setWordWrap(True)
        layout.addWidget(header)
        
        # File selection
        file_layout = QHBoxLayout()
        
        self.path_input = QLineEdit()
        self.path_input.setReadOnly(True)
        self.path_input.setPlaceholderText("No image selected...")
        file_layout.addWidget(self.path_input, 1)
        
        browse_btn = QPushButton("📁 Browse...")
        browse_btn.clicked.connect(self._browse_image)
        file_layout.addWidget(browse_btn)
        
        layout.addLayout(file_layout)
        
        # Info label
        self.info_label = QLabel()
        self.info_label.setStyleSheet("color: #888;")
        layout.addWidget(self.info_label)
        
        layout.addStretch()
        
        # Buttons
        button_layout = QHBoxLayout()
        
        ok_btn = QPushButton("✓ Continue")
        ok_btn.setEnabled(False)
        ok_btn.clicked.connect(self.accept)
        self.ok_btn = ok_btn
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        
        button_layout.addStretch()
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(ok_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _browse_image(self):
        """Open file browser for image selection."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Disk Image",
            "",
            "Forensic Images (*.e01 *.E01 *.raw *.RAW *.dd *.DD *.001);;All Files (*.*)"
        )
        
        if file_path:
            self._validate_and_set_image(file_path)
    
    def _validate_and_set_image(self, file_path: str):
        """Validate and set selected image."""
        path = Path(file_path)
        
        if not path.exists():
            QMessageBox.warning(self, "Error", "File does not exist!")
            return
        
        # Basic validation
        size_mb = path.stat().st_size / (1024 * 1024)
        
        self.selected_image = str(path)
        self.path_input.setText(str(path))
        self.info_label.setText(f"✓ Image size: {size_mb:.1f} MB")
        self.ok_btn.setEnabled(True)
    
    def get_selected_image(self) -> Optional[str]:
        """Get selected image path."""
        return self.selected_image
```

**Enhance Main Window Startup (`main_window.py`):**

```python
class MainWindow(QMainWindow):
    
    def __init__(self, config: Config):
        super().__init__()
        self.config = config
        self.workflow_manager = WorkflowManager(config)
        
        # ... existing init ...
        
        # Show case selection on startup
        QTimer.singleShot(100, self._startup_workflow)
    
    def _startup_workflow(self):
        """Execute startup workflow."""
        action, case_id = self.workflow_manager.get_startup_action()
        
        if action == 'open_last_case':
            # Ask to reopen last case
            reply = QMessageBox.question(
                self,
                "Reopen Last Case",
                f"Reopen case '{case_id}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.open_case(case_id)
                return
        
        # Show case selection dialog
        self._show_case_selection()
    
    def _show_case_selection(self):
        """Show case open/create dialog."""
        from .dialogs.case_selection_dialog import CaseSelectionDialog
        
        dialog = CaseSelectionDialog(self.config, self)
        
        if dialog.exec():
            case_id = dialog.get_selected_case()
            is_new = dialog.is_new_case()
            
            if is_new:
                # New case - select image
                self._create_case_with_image(case_id)
            else:
                # Existing case - open directly
                self.open_case(case_id)
    
    def _create_case_with_image(self, case_id: str):
        """Create case and select image."""
        from .dialogs.image_selection_dialog import ImageSelectionDialog
        
        # Show image selection dialog
        image_dialog = ImageSelectionDialog(self)
        
        if image_dialog.exec():
            image_path = image_dialog.get_selected_image()
            
            # Store image path
            self.workflow_manager.store_image_path(case_id, image_path)
            
            # Open case and auto-ingest
            self.open_case(case_id)
            self._auto_ingest_image(image_path)
    
    def _auto_ingest_image(self, image_path: str):
        """Automatically start image ingestion."""
        self.logger.info(f"Auto-ingesting image: {image_path}")
        
        # Switch to ingest tab
        self.tabs.setCurrentIndex(0)  # Ingest tab
        
        # Set image path in ingest tab
        if hasattr(self, 'ingest_tab'):
            self.ingest_tab.set_image_path(image_path)
            
            # Auto-start processing
            QTimer.singleShot(500, self.ingest_tab.start_processing)
```

---

## 7. 🚀 Performance Optimization

### Database Optimization

```python
# In timeline database queries, use indexes

CREATE INDEX idx_timestamp ON timeline_events(timestamp);
CREATE INDEX idx_event_type ON timeline_events(event_type);
CREATE INDEX idx_classification ON timeline_events(classification);

# Use query optimization
df = pd.read_sql_query("""
    SELECT * FROM timeline_events
    WHERE timestamp BETWEEN ? AND ?
    AND event_type IN (?)
    ORDER BY timestamp
    LIMIT 10000
""", conn, params=[start, end, types])
```

### UI Performance

```python
# Use QTableWidget virtualization for large datasets
self.timeline_table.setVerticalScrollMode(
    QAbstractItemView.ScrollMode.ScrollPerPixel
)

# Lazy loading for tree widget
def _load_tree_node_on_demand(self, item):
    """Load child nodes only when expanded."""
    if item.childCount() == 1 and item.child(0).text(0) == "...":
        # Remove placeholder
        item.takeChild(0)
        # Load actual children
        self._load_children(item)

# Pagination for large result sets
self.current_page = 0
self.page_size = 1000

def _load_page(self, page_num: int):
    """Load specific page of results."""
    offset = page_num * self.page_size
    df = self.full_data.iloc[offset:offset + self.page_size]
    self._populate_table(df)
```

### Memory Management

```python
# Clear large DataFrames when not needed
def clear_analysis_cache(self):
    """Clear cached analysis data."""
    if hasattr(self, 'timeline_df'):
        del self.timeline_df
    if hasattr(self, 'artifacts_df'):
        del self.artifacts_df
    
    # Force garbage collection
    import gc
    gc.collect()

# Use chunking for large file processing
def process_large_file(file_path: Path, chunk_size: int = 10000):
    """Process file in chunks to avoid memory issues."""
    for chunk in pd.read_csv(file_path, chunksize=chunk_size):
        process_chunk(chunk)
        yield chunk  # Generator pattern
```

---

## 8. 🧪 Testing Strategy

### Unit Tests

**File: `tests/test_i18n.py`**
```python
import pytest
from src.utils.i18n.translator import Translator

def test_translator_initialization():
    t = Translator()
    assert t.current_language == 'en'
    assert 'en' in t.translations

def test_language_switching():
    t = Translator()
    result = t.set_language('fr')
    assert result == True
    assert t.current_language == 'fr'

def test_translation_retrieval():
    t = Translator()
    title = t.get('report.title')
    assert 'Forensic' in title

def test_parameter_substitution():
    t = Translator()
    text = t.get('report.case_id', case='12345')
    assert '12345' in text
```

### Integration Tests

**File: `tests/test_workflow.py`**
```python
import pytest
from src.utils.workflow_manager import WorkflowManager
from src.utils.config import Config

def test_startup_workflow(tmp_path):
    config = Config(tmp_path)
    manager = WorkflowManager(config)
    
    action, case_id = manager.get_startup_action()
    assert action in ['show_dialog', 'open_last_case']

def test_image_storage(tmp_path):
    config = Config(tmp_path)
    manager = WorkflowManager(config)
    
    case_id = 'test_case'
    image_path = '/path/to/image.e01'
    
    manager.store_image_path(case_id, image_path)
    retrieved = manager.get_image_path(case_id)
    
    assert retrieved == image_path
```

---

## 📦 Summary & Next Steps

### Implementation Priority

1. **Immediate (Week 1)**:
   - ✅ Multilingual PDF reporting (high value, low complexity)
   - ✅ Session save/restore (critical UX improvement)

2. **Short-term (Week 2-3)**:
   - ✅ Event heatmap (powerful visualization)
   - ✅ Artifact navigation enhancements

3. **Medium-term (Week 4-6)**:
   - ✅ Folder tree enhancements
   - ✅ Workflow integration

4. **Ongoing**:
   - ✅ Performance optimization
   - ✅ Testing coverage

### File Checklist

Create these new files:
- [x] `src/utils/i18n/__init__.py`
- [x] `src/utils/i18n/translator.py`
- [x] `src/utils/i18n/report_translator.py`
- [x] `locales/en.json`, `fr.json`, `hi.json`
- [x] `src/utils/session_manager.py`
- [x] `src/ui/dialogs/restore_session_dialog.py`
- [x] `src/ui/dialogs/language_selector_dialog.py`
- [x] `src/visualization/heatmap_generator.py`
- [x] `src/visualization/heatmap_widget.py`
- [x] `src/ui/tabs/heatmap_tab.py`
- [x] `src/utils/artifact_navigator.py`
- [x] `src/ui/dialogs/artifact_details_dialog.py`
- [x] `src/ui/dialogs/artifact_filter_dialog.py`
- [x] `src/utils/workflow_manager.py`
- [x] `src/ui/dialogs/image_selection_dialog.py`

### Dependencies to Install

```bash
pip install seaborn matplotlib pillow
```

### Integration Steps

1. Import new modules in main_window.py
2. Add new tabs to QTabWidget
3. Connect signals between components
4. Update menu bar with new actions
5. Test each feature independently
6. Run integration tests

---

**🎉 All features documented! Ready to implement!**
