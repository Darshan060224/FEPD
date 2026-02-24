# FEPD UI Integration Guide

## Quick Start

This guide shows how to integrate the new comprehensive UI components into `main_window.py`.

---

## Step 1: Update Imports

Add to `src/ui/main_window.py`:

```python
from src.ui.ingest_wizard import ImageIngestWizard
from src.ui.artifacts_tab import ArtifactsTab
from src.ui.timeline_tab import TimelineTab
from src.ui.report_tab import ReportTab
```

---

## Step 2: Replace Tab Creation Methods

### Before (Placeholder):
```python
def _create_ingest_tab(self):
    tab = QWidget()
    layout = QVBoxLayout(tab)
    
    btn_ingest = QPushButton("📁 Ingest Disk Image")
    btn_ingest.setMinimumHeight(50)
    btn_ingest.clicked.connect(self._ingest_image)
    btn_ingest.setEnabled(False)  # Disabled until case opened
    
    layout.addWidget(btn_ingest)
    layout.addStretch()
    return tab
```

### After (Integrated):
```python
def _create_ingest_tab(self):
    # Create wizard button/launcher
    tab = QWidget()
    layout = QVBoxLayout(tab)
    
    # Ingest queue section
    queue_group = QGroupBox("📥 Ingest Queue")
    queue_layout = QVBoxLayout()
    
    # Button to launch wizard
    self.btn_launch_wizard = QPushButton("➕ Add Disk Image to Queue")
    self.btn_launch_wizard.setMinimumHeight(40)
    self.btn_launch_wizard.setEnabled(False)  # Disabled until case opened
    self.btn_launch_wizard.clicked.connect(self._launch_ingest_wizard)
    queue_layout.addWidget(self.btn_launch_wizard)
    
    # Queue table (for multiple images)
    self.tbl_ingest_queue = QTableWidget()
    self.tbl_ingest_queue.setColumnCount(5)
    self.tbl_ingest_queue.setHorizontalHeaderLabels([
        "Image File", "Format", "Status", "Progress", "Actions"
    ])
    queue_layout.addWidget(self.tbl_ingest_queue)
    
    queue_group.setLayout(queue_layout)
    layout.addWidget(queue_group)
    
    return tab

def _launch_ingest_wizard(self):
    """Launch the image ingest wizard."""
    wizard = ImageIngestWizard(self)
    
    if wizard.exec() == QDialog.DialogCode.Accepted:
        # Get configuration
        config = wizard.get_ingestion_config()
        
        # Add to ingest queue and start processing
        self._add_to_ingest_queue(config)
        self._start_ingestion(config)
```

---

### Artifacts Tab

### Before (Placeholder):
```python
def _create_artifacts_tab(self):
    tab = QWidget()
    layout = QVBoxLayout(tab)
    
    self.artifact_table = QTableWidget()
    self.artifact_table.setColumnCount(5)
    self.artifact_table.setHorizontalHeaderLabels([
        "Type", "Path", "Size", "Hash", "Status"
    ])
    
    layout.addWidget(self.artifact_table)
    return tab
```

### After (Integrated):
```python
def _create_artifacts_tab(self):
    # Create comprehensive artifacts browser
    self.artifacts_tab = ArtifactsTab(self)
    
    # Connect signals
    self.artifacts_tab.artifact_selected.connect(self._on_artifact_selected)
    
    return self.artifacts_tab
```

---

### Timeline Tab

### Before (Placeholder):
```python
def _create_timeline_tab(self):
    tab = QWidget()
    layout = QVBoxLayout(tab)
    
    lbl = QLabel("Timeline visualization placeholder")
    layout.addWidget(lbl)
    layout.addStretch()
    
    return tab
```

### After (Integrated):
```python
def _create_timeline_tab(self):
    # Create timeline visualization
    self.timeline_tab = TimelineTab(self)
    return self.timeline_tab
```

---

### Report Tab

### Before (Placeholder):
```python
def _create_report_tab(self):
    tab = QWidget()
    layout = QVBoxLayout(tab)
    
    btn_generate = QPushButton("📄 Generate PDF Report")
    btn_generate.setMinimumHeight(50)
    btn_generate.clicked.connect(self._generate_report)
    
    layout.addWidget(btn_generate)
    layout.addStretch()
    return tab
```

### After (Integrated):
```python
def _create_report_tab(self):
    # Create report generator
    self.report_tab = ReportTab(self)
    
    # Connect signals
    self.report_tab.report_generated.connect(self._on_report_generated)
    
    return self.report_tab
```

---

## Step 3: Connect Ingestion to Pipeline

Add these methods to `MainWindow`:

```python
def _add_to_ingest_queue(self, config: Dict[str, Any]):
    """Add image to ingest queue table."""
    row = self.tbl_ingest_queue.rowCount()
    self.tbl_ingest_queue.insertRow(row)
    
    # Image file
    self.tbl_ingest_queue.setItem(row, 0, QTableWidgetItem(config['image_path']))
    
    # Format
    self.tbl_ingest_queue.setItem(row, 1, QTableWidgetItem(config.get('format', 'Unknown')))
    
    # Status
    self.tbl_ingest_queue.setItem(row, 2, QTableWidgetItem("⏳ Pending"))
    
    # Progress bar
    progress = QProgressBar()
    self.tbl_ingest_queue.setCellWidget(row, 3, progress)
    
    # Actions button
    btn_cancel = QPushButton("❌ Cancel")
    self.tbl_ingest_queue.setCellWidget(row, 4, btn_cancel)

def _start_ingestion(self, config: Dict[str, Any]):
    """Start ingestion process using FEPDPipeline."""
    from src.modules.pipeline import FEPDPipeline
    
    # Create pipeline
    pipeline = FEPDPipeline(
        case_name=self.current_case_name,
        workspace=Path(self.current_case_path)
    )
    
    # Configure based on wizard settings
    pipeline_config = {
        'image_path': config['image_path'],
        'timezone': config['timezone'],
        'verify_hash': config['options']['verify_hash'],
        'read_only': config['options']['read_only'],
        'carve_files': config['options']['carve_files'],
        'modules': config['selected_modules']
    }
    
    # TODO: Run pipeline in background thread
    # Connect progress signals to update queue table
    # On completion, load artifacts into artifacts tab
```

---

## Step 4: Load Artifacts After Ingestion

```python
def _on_ingestion_complete(self, artifacts: List[Dict]):
    """Called when ingestion completes."""
    # Load into artifacts tab
    self.artifacts_tab.load_artifacts(artifacts)
    
    # Generate timeline events
    timeline_events = self._artifacts_to_timeline_events(artifacts)
    self.timeline_tab.load_timeline_events(timeline_events)
    
    # Update status bar
    self.statusBar().showMessage(f"Loaded {len(artifacts):,} artifacts", 5000)
    
    # Switch to artifacts tab
    self.tabs.setCurrentIndex(1)  # Artifacts tab

def _artifacts_to_timeline_events(self, artifacts: List[Dict]) -> List[Dict]:
    """Convert artifacts to timeline events."""
    events = []
    
    for artifact in artifacts:
        if 'timestamp' in artifact and artifact['timestamp']:
            events.append({
                'timestamp': artifact['timestamp'],
                'category': artifact.get('type', 'Unknown'),
                'name': artifact.get('name', 'Unknown'),
                'description': artifact.get('path', '')
            })
    
    return sorted(events, key=lambda e: e['timestamp'])
```

---

## Step 5: Connect Tagging to Report

```python
def _on_artifact_selected(self, artifact: Dict):
    """Handle artifact selection in artifacts tab."""
    # Could update timeline to highlight corresponding event
    pass

def _update_report_with_tagged(self):
    """Update report tab with tagged artifacts."""
    # Get tagged artifacts from artifacts tab
    tagged = []
    
    # Scan artifacts tab table for tagged items
    for row in range(self.artifacts_tab.tbl_artifacts.rowCount()):
        tag_widget = self.artifacts_tab.tbl_artifacts.cellWidget(row, 0)
        if tag_widget and tag_widget.isChecked():
            artifact = {
                'type': self.artifacts_tab.tbl_artifacts.item(row, 1).text(),
                'name': self.artifacts_tab.tbl_artifacts.item(row, 2).text(),
                'path': self.artifacts_tab.tbl_artifacts.item(row, 3).text(),
                'timestamp': self.artifacts_tab.tbl_artifacts.item(row, 4).text(),
            }
            tagged.append(artifact)
    
    # Load into report tab
    self.report_tab.load_tagged_artifacts(tagged)
```

---

## Step 6: Enable Tabs When Case Opened

Update `_new_case` and `_open_case`:

```python
def _new_case(self):
    # ... existing code ...
    
    # Enable ingest button
    self.btn_launch_wizard.setEnabled(True)
    
    # Update status
    self.statusBar().showMessage(f"Case '{case_name}' created", 5000)
```

---

## Step 7: Auto-Update Report Tab

Add to `_create_report_tab`:

```python
def _create_report_tab(self):
    self.report_tab = ReportTab(self)
    self.report_tab.report_generated.connect(self._on_report_generated)
    
    # Auto-update when tab changes
    self.tabs.currentChanged.connect(self._on_tab_changed)
    
    return self.report_tab

def _on_tab_changed(self, index: int):
    """Handle tab change."""
    if index == 3:  # Report tab
        # Auto-load tagged artifacts
        self._update_report_with_tagged()
```

---

## Step 8: Add Required Dependencies

Update `requirements.txt`:

```
PyQt6>=6.6.0
PyQt6-WebEngine>=6.6.0
python-registry>=1.3.1
pytsk3>=20231007
reportlab>=4.0.0
python-docx>=1.1.0
Pillow>=10.0.0
```

Install:
```bash
pip install -r requirements.txt
```

---

## Complete Integration Example

Here's a minimal working example:

```python
# src/ui/main_window.py

from PyQt6.QtWidgets import QMainWindow, QTabWidget, QMessageBox
from PyQt6.QtCore import Qt
from src.ui.ingest_wizard import ImageIngestWizard
from src.ui.artifacts_tab import ArtifactsTab
from src.ui.timeline_tab import TimelineTab
from src.ui.report_tab import ReportTab

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FEPD - Forensic Evidence Processing Dashboard")
        self.setGeometry(100, 100, 1600, 900)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_ingest_tab(), "📁 Image Ingest")
        self.tabs.addTab(self._create_artifacts_tab(), "🔍 Artifacts")
        self.tabs.addTab(self._create_timeline_tab(), "📊 Timeline")
        self.tabs.addTab(self._create_report_tab(), "📄 Report")
        
        self.setCentralWidget(self.tabs)
    
    def _create_ingest_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        btn = QPushButton("➕ Add Disk Image")
        btn.clicked.connect(self._launch_wizard)
        layout.addWidget(btn)
        
        return tab
    
    def _create_artifacts_tab(self):
        self.artifacts_tab = ArtifactsTab(self)
        return self.artifacts_tab
    
    def _create_timeline_tab(self):
        self.timeline_tab = TimelineTab(self)
        return self.timeline_tab
    
    def _create_report_tab(self):
        self.report_tab = ReportTab(self)
        return self.report_tab
    
    def _launch_wizard(self):
        wizard = ImageIngestWizard(self)
        if wizard.exec() == QDialog.DialogCode.Accepted:
            config = wizard.get_ingestion_config()
            self._start_ingestion(config)
```

---

## Testing

After integration:

1. **Launch Application**:
   ```bash
   python main.py
   ```

2. **Create New Case**: File → New Case

3. **Test Ingest Wizard**:
   - Click "Add Disk Image"
   - Drag-drop or browse for image
   - Configure timezone and options
   - Select modules
   - Verify wizard completes

4. **Test Artifacts Tab**:
   - Load sample artifacts
   - Test filtering (search, dropdowns, checkboxes)
   - Test sorting (click columns)
   - Test tagging (click tag column)
   - Test preview pane (select artifact)

5. **Test Timeline Tab**:
   - Load sample events
   - Test zoom (buttons, mouse wheel)
   - Test pan (drag)
   - Test category filtering
   - Test event click

6. **Test Report Tab**:
   - Fill in case metadata
   - Verify tagged artifacts appear
   - Select evidence items
   - Generate preview
   - Generate report (all formats)

---

## Troubleshooting

### Issue: Wizard doesn't launch
**Solution**: Check that case is opened first (wizard requires active case)

### Issue: No artifacts displayed
**Solution**: Verify pipeline results are being passed to `artifacts_tab.load_artifacts()`

### Issue: Timeline is empty
**Solution**: Ensure artifacts have timestamp fields and conversion is working

### Issue: Report preview blank
**Solution**: Check that PyQt6-WebEngine is installed correctly

### Issue: Export fails
**Solution**: Verify reportlab/python-docx are installed for PDF/DOCX export

---

## Next Steps

1. ✅ All UI components implemented
2. ⏳ Integrate with main_window.py (this guide)
3. ⏳ Connect to backend pipeline
4. ⏳ Test with real forensic images
5. ⏳ Implement actual report generation
6. ⏳ Add hex viewer integration
7. ⏳ Performance optimization

---

## Questions?

Check `docs/UI_IMPLEMENTATION_SUMMARY.md` for detailed component documentation.
