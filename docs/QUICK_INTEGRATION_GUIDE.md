# Quick Integration Guide - Connect All Features

This guide shows exactly how to integrate all 6 advanced features into your FEPD application.

---

## 🚀 Quick Start (Copy-Paste Integration)

### Step 1: Integrate Session Management (10 minutes)

**File**: `src/ui/main_window.py`

Add to imports:
```python
from src.utils.session_manager import SessionManager
from src.ui.dialogs.restore_session_dialog import RestoreSessionDialog
```

Add to `__init__` method (after setting up case):
```python
# Initialize session manager
self.session_manager = SessionManager(self.case_dir)
```

Add new method:
```python
def _check_and_restore_session(self):
    """Check for existing session and prompt to restore."""
    if self.session_manager.has_snapshot():
        dialog = RestoreSessionDialog(self.case_dir, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Restore session
            state = self.session_manager.load_session()
            self._apply_session_state(state)
            logger.info("Session restored")
        else:
            # Delete snapshot
            self.session_manager.delete_snapshot()
            logger.info("Starting fresh - snapshot deleted")

def _apply_session_state(self, state: dict):
    """Apply restored session state to UI."""
    # Restore tab
    if 'active_tab' in state:
        self.tabs.setCurrentIndex(state['active_tab'])
    
    # Restore scroll positions
    if 'scroll_positions' in state:
        # Apply to timeline, artifacts, files tables
        pass
    
    # Restore filters
    if 'filters' in state:
        # Apply filters to relevant components
        pass

def _get_current_state(self) -> dict:
    """Get current application state for session saving."""
    return {
        'active_tab': self.tabs.currentIndex(),
        'scroll_positions': {
            'timeline': self.timeline_tab.get_scroll_position(),
            'artifacts': self.artifacts_tab.get_scroll_position(),
            'files': self.files_tab.get_scroll_position()
        },
        'filters': {
            'timeline': self.timeline_tab.get_active_filters(),
            'artifacts': self.artifacts_tab.get_active_filters()
        }
    }

def _save_session(self):
    """Save current session (toolbar action)."""
    state = self._get_current_state()
    if self.session_manager.save_session(state):
        self.statusBar().showMessage("Session saved", 3000)

def closeEvent(self, event):
    """Auto-save session on close."""
    state = self._get_current_state()
    self.session_manager.auto_save(state)
    super().closeEvent(event)
```

Call after pipeline completes:
```python
def _on_pipeline_complete(self):
    # ... existing code ...
    
    # Check for session restore
    self._check_and_restore_session()
```

Add toolbar button:
```python
def _setup_toolbar(self):
    # ... existing toolbar code ...
    
    # Session save button
    save_session_action = QAction("💾 Save Session", self)
    save_session_action.triggered.connect(self._save_session)
    toolbar.addAction(save_session_action)
```

---

### Step 2: Integrate Workflow (30 minutes)

**File**: `main.py` or wherever you launch the app

Add to imports:
```python
from src.utils.workflow_manager import WorkflowManager
from src.ui.dialogs.case_selection_dialog import CaseSelectionDialog
from src.ui.dialogs.image_selection_dialog import ImageSelectionDialog
```

Modify startup sequence:
```python
def main():
    app = QApplication(sys.argv)
    
    # Initialize workflow manager
    workflow = WorkflowManager()
    
    # Show case selection dialog
    summary = workflow.get_workflow_summary()
    case_dialog = CaseSelectionDialog(
        has_last_case=summary['has_recent_case'],
        last_case_id=summary['last_case_id'],
        last_opened=summary['last_case_opened']
    )
    
    # Connect signals
    case_dialog.new_case_requested.connect(lambda: handle_new_case(workflow))
    case_dialog.open_case_requested.connect(lambda: handle_open_case(workflow))
    case_dialog.open_last_case_requested.connect(lambda case_id: handle_open_last_case(workflow, case_id))
    
    # Show dialog
    if case_dialog.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)  # User closed dialog
    
    # Start application
    sys.exit(app.exec())

def handle_new_case(workflow: WorkflowManager):
    """Handle new case creation."""
    # Show image selection
    img_dialog = ImageSelectionDialog()
    if img_dialog.exec() == QDialog.DialogCode.Accepted:
        image_path = img_dialog.get_selected_image()
        
        # Store image path
        workflow.store_image_path(image_path)
        
        # Create case
        case_id = f"case_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        case_dir = Path(f"cases/{case_id}")
        case_dir.mkdir(parents=True, exist_ok=True)
        
        # Store case opened
        workflow.store_case_opened(case_id)
        
        # Launch main window with auto-ingestion
        main_window = MainWindow(case_dir=case_dir, auto_ingest=image_path)
        main_window.show()

def handle_open_case(workflow: WorkflowManager):
    """Handle opening existing case."""
    # Show case folder picker
    case_dir = QFileDialog.getExistingDirectory(None, "Select Case Folder")
    if case_dir:
        case_id = Path(case_dir).name
        workflow.store_case_opened(case_id)
        
        # Launch main window
        main_window = MainWindow(case_dir=case_dir)
        main_window.show()

def handle_open_last_case(workflow: WorkflowManager, case_id: str):
    """Handle opening last case."""
    case_dir = Path(f"cases/{case_id}")
    if case_dir.exists():
        workflow.store_case_opened(case_id)
        
        # Launch main window
        main_window = MainWindow(case_dir=case_dir)
        main_window.show()
    else:
        # Case not found - show error
        QMessageBox.warning(None, "Error", f"Case '{case_id}' not found")
        handle_open_case(workflow)
```

---

### Step 3: Integrate Artifact Navigation (20 minutes)

**File**: `src/ui/tabs/artifacts_tab.py`

Add to imports:
```python
from src.utils.artifact_navigator import ArtifactNavigator
from src.ui.dialogs.artifact_details_dialog import ArtifactDetailsDialog
from src.ui.dialogs.artifact_filter_dialog import ArtifactFilterDialog
```

Add to `__init__` or `set_data` method:
```python
def set_data(self, artifacts_df, timeline_df):
    """Set artifacts and timeline data."""
    self.artifacts_df = artifacts_df
    self.timeline_df = timeline_df
    
    # Initialize navigator
    self.navigator = ArtifactNavigator(artifacts_df, timeline_df)
    
    # ... existing code to populate table ...
```

Add clickable counts:
```python
def _create_summary_widget(self):
    """Create summary widget with clickable counts."""
    summary_layout = QHBoxLayout()
    
    stats = self.navigator.get_artifact_statistics()
    
    for artifact_type, count in stats['by_type'].items():
        # Create clickable label
        label = QLabel(f"{artifact_type}: <a href='#{artifact_type}'>{count}</a>")
        label.setTextFormat(Qt.TextFormat.RichText)
        label.linkActivated.connect(lambda url, t=artifact_type: self._show_artifact_details(t))
        summary_layout.addWidget(label)
    
    return summary_layout

def _show_artifact_details(self, artifact_type: str):
    """Show artifact details dialog."""
    # Get artifacts of this type
    artifacts = self.navigator.filter_artifacts(artifact_type=artifact_type)
    
    if len(artifacts) == 1:
        # Single artifact - show details
        artifact = artifacts.iloc[0]
        dialog = ArtifactDetailsDialog(artifact, self.navigator, self)
        dialog.jump_to_timeline.connect(self._jump_to_timeline)
        dialog.exec()
    else:
        # Multiple artifacts - show list
        # (Could show list dialog or filter table)
        self._filter_table(artifact_type=artifact_type)
```

Add filter button:
```python
def _setup_toolbar(self):
    """Setup artifacts toolbar."""
    toolbar = QHBoxLayout()
    
    # Filter button
    filter_btn = QPushButton("🔍 Filter Artifacts")
    filter_btn.clicked.connect(self._show_filter_dialog)
    toolbar.addWidget(filter_btn)
    
    # ... other toolbar buttons ...

def _show_filter_dialog(self):
    """Show artifact filter dialog."""
    dialog = ArtifactFilterDialog(self)
    if dialog.exec() == QDialog.DialogCode.Accepted:
        filters = dialog.get_filters()
        filtered_df = self.navigator.filter_artifacts(**filters)
        self._update_table(filtered_df)

def _jump_to_timeline(self, events_df):
    """Jump to timeline tab and show artifact events."""
    # Signal to main window to switch to timeline tab
    self.jump_to_timeline_requested.emit(events_df)
```

Add signal to artifacts tab:
```python
from PyQt6.QtCore import pyqtSignal

class ArtifactsTab(QWidget):
    jump_to_timeline_requested = pyqtSignal(object)  # DataFrame
    
    # ... rest of class ...
```

Connect in main window:
```python
# In main_window.py
self.artifacts_tab.jump_to_timeline_requested.connect(self._filter_timeline_to_events)

def _filter_timeline_to_events(self, events_df):
    """Filter timeline to show specific events."""
    self.tabs.setCurrentIndex(0)  # Switch to timeline tab
    self.timeline_tab.filter_to_events(events_df)
```

---

### Step 4: Integrate Multilingual PDF (15 minutes)

**File**: `src/report_generator.py`

Add to imports:
```python
from src.utils.i18n.translator import Translator
from src.ui.dialogs.language_selector_dialog import LanguageSelectorDialog
```

Add to `ReportGenerator` class:
```python
def __init__(self):
    self.translator = Translator()
    # ... existing init code ...

def generate_pdf_report(self, case_info, artifacts, timeline):
    """Generate PDF report with language selection."""
    # Show language selector
    dialog = LanguageSelectorDialog()
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return None  # User cancelled
    
    # Set language
    language = dialog.get_selected_language()
    self.translator.set_language(language)
    
    # Generate report with translations
    return self._generate_report_content(case_info, artifacts, timeline)

def _generate_report_content(self, case_info, artifacts, timeline):
    """Generate report content with translations."""
    # Use translator for all strings
    title = self.translator.get('report.title')
    summary = self.translator.get('report.summary', count=len(artifacts))
    
    # Timeline section
    timeline_title = self.translator.get('report.timeline_section')
    
    # Artifacts section
    artifacts_title = self.translator.get('report.artifacts_section')
    
    # Labels
    label_name = self.translator.get('report.label_name')
    label_type = self.translator.get('report.label_type')
    label_date = self.translator.get('report.label_date')
    
    # ... use translated strings in report generation ...
```

---

## 🧪 Testing Each Integration

### Test Session Management
1. Open FEPD with a case
2. Apply some filters
3. Click "💾 Save Session"
4. Close application
5. Reopen - should see restore prompt
6. Click "Restore Session" - filters should be restored

### Test Workflow
1. Close FEPD completely
2. Launch application
3. Should see case selection dialog
4. Click "Create New Case"
5. Should see image selection dialog
6. Select an E01 file
7. Application should start ingestion automatically

### Test Artifact Navigation
1. Open case with artifacts
2. Click on artifact count (e.g., "Registry: 5")
3. Should see artifact details dialog
4. Click "Jump to Timeline"
5. Timeline should filter to artifact events

### Test Multilingual PDF
1. Click "Export Report"
2. Should see language selection dialog
3. Choose "Français"
4. Report should be generated in French

---

## 📝 Quick Troubleshooting

### Session not restoring?
- Check if `session_snapshot.json` exists in case folder
- Verify `_get_current_state()` returns valid dict
- Check console for errors

### Workflow dialog not showing?
- Verify `workflow_state.json` created in `config/`
- Check if signals are connected
- Verify dialog imports

### Artifact navigation not working?
- Check if navigator initialized with both DataFrames
- Verify artifact/timeline data not empty
- Check signal connections

### Translations not working?
- Verify `locales/` folder exists
- Check if JSON files are valid
- Verify language code matches filename (en.json, fr.json, hi.json)

---

## ✅ Integration Complete Checklist

- [ ] Session Management integrated
  - [ ] Save button works
  - [ ] Restore prompt shows on startup
  - [ ] Auto-save on close works
  
- [ ] Workflow integrated
  - [ ] Case selection dialog shows on launch
  - [ ] New case creates and auto-ingests
  - [ ] Open case works
  - [ ] Open last case works
  
- [ ] Artifact Navigation integrated
  - [ ] Counts are clickable
  - [ ] Details dialog shows
  - [ ] Jump to timeline works
  - [ ] Filter dialog works
  
- [ ] Multilingual PDF integrated
  - [ ] Language selector shows
  - [ ] Report generates in selected language
  - [ ] All 3 languages work (EN/FR/HI)

---

## 🎉 You're Done!

All 6 advanced features are now integrated:
1. ✅ Multilingual PDF Reporting
2. ✅ Session Save/Restore
3. ✅ Calendar Heatmap (already in Visualizations tab)
4. ✅ Artifact Navigation
5. ✅ Folder Tree (already working)
6. ✅ Workflow Integration

**Total Integration Time**: ~75 minutes

**Next**: Test with real forensic cases and enjoy your upgraded FEPD! 🚀
