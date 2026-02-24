# Advanced Features - Quick Start Guide

**FEPD - Forensic Evidence Parser Dashboard**  
**Get Started with Advanced Features in 30 Minutes**

---

## 🚀 Quick Implementation Roadmap

### Phase 1: Multilingual PDF Reports (30 minutes)

**Step 1: Create i18n structure**
```bash
cd src/utils
mkdir i18n
cd i18n
```

**Step 2: Copy files from documentation**
- Copy `translator.py` from Part 1 → `src/utils/i18n/translator.py`
- Copy `report_translator.py` → `src/utils/i18n/report_translator.py`
- Copy `__init__.py` → `src/utils/i18n/__init__.py`

**Step 3: Create language packs**
```bash
cd ../../../locales  # Go to project root/locales
```
- Copy `en.json`, `fr.json`, `hi.json` from documentation

**Step 4: Test translation**
```python
# Test in Python console
from src.utils.i18n.translator import Translator

t = Translator()
print(t.get('report.title'))  # Should print "Forensic Analysis Report"

t.set_language('fr')
print(t.get('report.title'))  # Should print "Rapport d'Analyse Forensique"
```

**Step 5: Integrate with report generator**
In `src/utils/report_generator.py`:
```python
# Add at top
from .i18n.translator import Translator
from .i18n.report_translator import ReportTranslator

# In __init__ method
def __init__(self, case_dir: str, case_id: str, language: str = 'en'):
    self.translator = Translator()
    self.translator.set_language(language)
    self.report_translator = ReportTranslator(self.translator)
    # ... rest of existing code
```

**✅ Test**: Generate a French report and verify translated headers!

---

### Phase 2: Session Save/Restore (45 minutes)

**Step 1: Create session manager**
```bash
cd src/utils
```
- Copy `session_manager.py` from documentation

**Step 2: Create restore dialog**
```bash
cd ../ui/dialogs
```
- Copy `restore_session_dialog.py` from documentation

**Step 3: Add to main window**
In `src/ui/main_window.py`:
```python
# Add import
from ..utils.session_manager import SessionManager
from .dialogs.restore_session_dialog import RestoreSessionDialog

# In __init__
self.session_manager = None

# Add save session button to toolbar
def _setup_toolbar(self):
    # ... existing toolbar code ...
    
    save_session_action = QAction("💾 Save Session", self)
    save_session_action.triggered.connect(self._on_save_session_clicked)
    self.toolbar.addAction(save_session_action)

# Add method
def _on_save_session_clicked(self):
    self.save_current_session()
    QMessageBox.information(self, "Session Saved", 
        "Your analysis session has been saved!")
```

**Step 4: Implement save/restore logic**
Copy methods from Part 2:
- `save_current_session()`
- `_restore_session()`
- `_start_fresh_analysis()`
- Update `open_case()` to check for snapshots

**✅ Test**: Save session → Close app → Reopen → Should show restore dialog!

---

### Phase 3: Event Heatmap (60 minutes)

**Step 1: Install dependencies**
```bash
pip install seaborn matplotlib
```

**Step 2: Create heatmap module**
```bash
cd src/visualization
```
- Copy `heatmap_generator.py` from documentation
- Copy `heatmap_widget.py` from documentation

**Step 3: Create heatmap tab**
```bash
cd ../ui/tabs
```
- Copy `heatmap_tab.py` from documentation

**Step 4: Add to main window**
In `src/ui/main_window.py`:
```python
# Add import
from .tabs.heatmap_tab import HeatmapTab

# In __init__, after other tabs
self.heatmap_tab = HeatmapTab(self)
self.tabs.addTab(self.heatmap_tab, "📅 Heatmap")

# In _on_pipeline_finished, add
self.heatmap_tab.load_timeline(classified_df)
```

**✅ Test**: Run analysis → Check Heatmap tab → Should show calendar visualization!

---

### Phase 4: Artifact Navigation (45 minutes)

**Step 1: Create navigator utility**
```bash
cd src/utils
```
- Copy `artifact_navigator.py` from documentation

**Step 2: Create dialogs**
```bash
cd ../ui/dialogs
```
- Copy `artifact_details_dialog.py` from documentation
- Copy `artifact_filter_dialog.py` from documentation

**Step 3: Enhance artifacts tab**
In `src/ui/tabs/artifacts_tab.py`:
```python
# Add to _setup_ui
self.artifacts_table.cellClicked.connect(self._on_cell_clicked)

# Add filter button
filter_btn = QPushButton("🔍 Advanced Filters")
filter_btn.clicked.connect(self._show_filter_dialog)

# Add methods from documentation:
# - _on_cell_clicked()
# - _show_filter_dialog()
# - _apply_filters()
# - _on_jump_to_timeline()
```

**✅ Test**: Click artifact count → Should show details dialog with timeline!

---

### Phase 5: Workflow Integration (30 minutes)

**Step 1: Create workflow manager**
```bash
cd src/utils
```
- Copy `workflow_manager.py` from documentation

**Step 2: Create image selection dialog**
```bash
cd ../ui/dialogs
```
- Copy `image_selection_dialog.py` from documentation

**Step 3: Add startup workflow to main window**
In `src/ui/main_window.py`:
```python
# Add import
from ..utils.workflow_manager import WorkflowManager

# In __init__
self.workflow_manager = WorkflowManager(self.config)

# Add startup trigger
QTimer.singleShot(100, self._startup_workflow)

# Add methods from documentation:
# - _startup_workflow()
# - _show_case_selection()
# - _create_case_with_image()
# - _auto_ingest_image()
```

**✅ Test**: Launch app → Should show case selection immediately!

---

## 📝 Implementation Checklist

Use this checklist to track your progress:

### Core Features
- [ ] Multilingual PDF reporting
  - [ ] Translation engine working
  - [ ] Language packs created (EN, FR, HI)
  - [ ] Report generator integrated
  - [ ] Language selector dialog
  - [ ] Test PDF export in multiple languages

- [ ] Session save/restore
  - [ ] SessionManager created
  - [ ] Save button in toolbar
  - [ ] Restore dialog implemented
  - [ ] Filter state preservation
  - [ ] UI state preservation
  - [ ] Test save → reopen → restore

- [ ] Event heatmap
  - [ ] Heatmap generator implemented
  - [ ] Widget with matplotlib canvas
  - [ ] Tab added to main window
  - [ ] Click-to-filter working
  - [ ] Test with real timeline data

- [ ] Artifact navigation
  - [ ] Navigator utility created
  - [ ] Details dialog working
  - [ ] Filter dialog implemented
  - [ ] Jump to timeline functional
  - [ ] Test with various artifacts

- [ ] Workflow integration
  - [ ] Startup case selection
  - [ ] Image selection dialog
  - [ ] Auto-ingest working
  - [ ] Config storage
  - [ ] Test end-to-end workflow

### Enhancements
- [ ] Folder tree context menu
- [ ] File hash calculation
- [ ] Export heatmap image
- [ ] Artifact statistics panel
- [ ] Performance optimization
- [ ] Error handling
- [ ] Logging enhancements

---

## 🐛 Troubleshooting

### Common Issues

**1. Import errors for i18n modules**
```python
# Make sure __init__.py exists in src/utils/i18n/
# Add this to src/utils/i18n/__init__.py:
from .translator import Translator
from .report_translator import ReportTranslator
__all__ = ['Translator', 'ReportTranslator']
```

**2. Matplotlib not showing in PyQt6**
```bash
pip install PyQt6 matplotlib
# Use FigureCanvasQTAgg, not FigureCanvas
```

**3. Session file not found**
```python
# Check case directory structure:
cases/
└── case1/
    └── session_snapshot.json  # Should be here
```

**4. Language packs not loading**
```python
# Verify locale directory exists
# Check JSON syntax with: python -m json.tool locales/en.json
```

---

## 🎯 Testing Each Feature

### Test Multilingual Reports
```python
# In Python console or test script
from src.utils.report_generator import ReportGenerator

# English
gen_en = ReportGenerator('cases/case1', 'case1', language='en')
gen_en.generate_report(timeline_df, artifacts)

# French  
gen_fr = ReportGenerator('cases/case1', 'case1', language='fr')
gen_fr.generate_report(timeline_df, artifacts)

# Check PDFs have different language headers
```

### Test Session Restore
```bash
# 1. Open case, apply filters, scroll timeline
# 2. Click "Save Session"
# 3. Close application
# 4. Reopen application
# 5. Should show restore dialog
# 6. Click "Restore Session"
# 7. Verify filters and scroll position restored
```

### Test Heatmap
```bash
# 1. Open case with timeline data
# 2. Go to Heatmap tab
# 3. Should see calendar-style heatmap
# 4. Click on a colored cell
# 5. Timeline should filter to that time slice
```

### Test Artifact Navigation
```bash
# 1. Go to Artifacts tab
# 2. Click on any artifact row
# 3. Should show details dialog
# 4. Click "Jump to Timeline"
# 5. Should switch to Timeline tab with filtered events
```

---

## 📚 Code Snippets

### Quick Add Language Support to Any String

```python
# Instead of hardcoded strings:
title = "Forensic Analysis Report"

# Use translator:
from src.utils.i18n.translator import Translator
t = Translator()
t.set_language('fr')
title = t.get('report.title')
```

### Quick Save Session State

```python
# In any method where state changes
def apply_filter(self, filter_value):
    # ... apply filter logic ...
    
    # Auto-save session
    if hasattr(self, 'session_manager'):
        self.save_current_session()
```

### Quick Add Heatmap to Custom Tab

```python
from src.visualization.heatmap_widget import HeatmapWidget

# In your tab __init__
self.heatmap = HeatmapWidget()
layout.addWidget(self.heatmap)

# Load data
self.heatmap.load_data(your_timeline_df)
```

---

## 🎉 Success Metrics

Your implementation is successful when:

✅ **Multilingual**: Can export reports in EN, FR, HI with correct translations  
✅ **Session**: Can save → close → reopen → restore with all filters intact  
✅ **Heatmap**: Clicking heatmap cell filters timeline to that hour  
✅ **Navigation**: Clicking artifact jumps to related timeline events  
✅ **Workflow**: New users see case selection on launch  

---

## 📞 Next Steps

1. **Start with Phase 1** (Multilingual) - easiest win
2. **Move to Phase 2** (Session) - highest user impact
3. **Add Phase 3** (Heatmap) - great visualization
4. **Complete Phase 4-5** when ready

**Need help?** Check the detailed documentation in:
- `ADVANCED_FEATURES_IMPLEMENTATION.md` (Part 1)
- `ADVANCED_FEATURES_PART2.md` (Part 2)

---

**Happy Coding! 🚀**
