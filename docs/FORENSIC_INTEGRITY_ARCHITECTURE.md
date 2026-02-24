# FEPD Forensic Integrity Architecture

## Overview

FEPD enforces a critical forensic principle: **The investigator must NEVER see analyzer-side paths.**

This document describes the architectural changes that turn FEPD into a **Forensic Operating System** rather than a tool wrapper.

## Core Principle

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                     FEPD FORENSIC INTEGRITY CONTRACT                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  "FEPD SHALL NEVER expose analyzer-side filesystem paths to the             ║
║   investigator.                                                             ║
║                                                                              ║
║   All visible paths SHALL be reconstructed from evidence metadata only.     ║
║                                                                              ║
║   Any leakage SHALL be treated as a forensic integrity breach."             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## Two Realities

| Layer       | Example Path                                    | Must be visible? |
|-------------|------------------------------------------------|------------------|
| **Analyzer** | `C:\FEPD\cases\cs-01\extracted\...`           | ❌ **NEVER**     |
| **Evidence** | `C:\Windows\System32\config\SAM`               | ✅ **ALWAYS**    |

The user must **never** see:
- `cases/`
- `extracted_data/`
- `partition_0/`
- `/mnt/`
- Any local disk path containing FEPD workspace
- Any temporary folder
- Any debug storage location

**If it appears → Integrity Violation**

---

## New Components

### 1. Path Sanitizer (`src/core/path_sanitizer.py`)

The firewall against path leakage.

```python
from src.core.path_sanitizer import safe_path, is_safe_path

# Before ANY UI output:
safe_display_path = safe_path(internal_path, component="files_tab")
```

Features:
- Pattern matching for analyzer paths (`cases/`, `extracted`, `partition_`, `/mnt/`)
- Evidence path extraction from internal paths
- Severity classification (CRITICAL, HIGH, MEDIUM, LOW)
- Chain of Custody logging of blocked attempts
- `ForensicIntegrityError` exception for leak attempts

### 2. Background Workers (`src/core/background_workers.py`)

Keeps UI responsive during heavy forensic I/O.

```python
from src.core.background_workers import get_task_manager, TaskType

manager = get_task_manager()
task_id = manager.start_mount(image_path, case_path)
manager.task_completed.connect(on_mount_complete)
```

Architecture:
```
[ UI Thread ]
     |
     |  (signals only, no blocking)
     v
[ Worker Engine ]
     |
     |  (forensic I/O)
     v
[ Evidence Backend ]
```

Workers available:
- `MountImageWorker` - Open forensic images
- `BuildVFSWorker` - Build Virtual Evidence File System
- `ExtractArtifactsWorker` - Extract forensic artifacts
- `ParseEventsWorker` - Parse extracted artifacts
- `HashFileWorker` - Compute file hashes

### 3. Progress Indicators (`src/ui/widgets/progress_indicators.py`)

Visual feedback without blocking.

```python
from src.ui.widgets.progress_indicators import ForensicProgressDialog

dialog = ForensicProgressDialog(self, "Mounting Evidence")
dialog.show()
dialog.set_progress(50, "Scanning partitions...")
```

Components:
- `ForensicProgressDialog` - Modal progress with cancel
- `SpinnerWidget` - Animated spinner
- `ProgressOverlay` - Semi-transparent overlay
- `StatusBarProgress` - Status bar integration

---

## Integration Points

### Files Tab (`src/ui/files_tab.py`)

All path displays sanitized:

```python
# Breadcrumb navigation
windows_path = sanitize_display_path(windows_path, "breadcrumb")

# Details panel
display_path = sanitize_display_path(display_path, "details_panel")
```

### Forensic Terminal (`src/ui/widgets/forensic_terminal.py`)

All output sanitized:

```python
def _append_output(self, text: str, color_key: str = 'output'):
    # FORENSIC INTEGRITY: Sanitize ALL terminal output
    text = sanitize_terminal_output(text)
    # ... display ...
```

Terminal commands:
- `pwd` returns evidence path: `C:\Users\LoneWolf\Desktop`
- NOT analyzer path: `/cases/case1/vefs/partition3/Users/LoneWolf/Desktop`

### Blocked Analyzer Path Alert

If an analyzer path tries to surface:

```
[INTEGRITY ALERT]
Analyzer path exposure attempt blocked.
Evidence integrity preserved.
```

Logged as:
```
COC_EVENT: PATH_SANITIZATION_BLOCKED
```

---

## Why This Matters

### 1. Court Admissibility
Evidence integrity is paramount. If analyzer paths leak:
- It suggests evidence may have been modified
- Chain of custody is questioned
- Defense can challenge findings

### 2. Investigator Focus
The investigator should see the victim's filesystem, not FEPD internals:
- "What files were on the suspect's Desktop?"
- NOT "Where did FEPD extract those files?"

### 3. True Forensic OS
FEPD becomes a window INTO the evidence, not a wrapper AROUND it:
- Files Tab = Victim's File Explorer
- Terminal = Victim's CMD prompt
- All paths = Evidence locations

---

## Testing

Run the path sanitizer tests:

```bash
python src/core/path_sanitizer.py
```

Expected output:
```
Test Results:
----------------------------------------------------------------------
✓ [BLOCKED ] cases/cs-01/vefs/p3/Users/LoneWolf/Desktop/file.txt
   → Sanitized to: C:\Users\LoneWolf\Desktop\file.txt
✓ [ALLOWED ] C:\Windows\System32\config\SAM
```

---

## Enforcement Checklist

Before ANY path is displayed:

- [ ] Files Tab breadcrumb → `sanitize_display_path()`
- [ ] Files Tab details panel → `sanitize_display_path()`
- [ ] Terminal output → `sanitize_terminal_output()`
- [ ] Reports → `safe_path()`
- [ ] Exports → `safe_path()`
- [ ] Logs shown to user → `safe_path()`
- [ ] Right-click details → `sanitize_display_path()`
- [ ] Search results → `safe_path()`

---

## Files Modified

1. **New Files:**
   - `src/core/path_sanitizer.py` - Path sanitization engine
   - `src/core/background_workers.py` - Background task system
   - `src/ui/widgets/progress_indicators.py` - Progress UI components

2. **Updated Files:**
   - `src/ui/files_tab.py` - Added sanitization to breadcrumb and details
   - `src/ui/widgets/forensic_terminal.py` - Added output sanitization

---

## What This Enables

With these changes, FEPD becomes:

1. **Event-driven** - UI never freezes
2. **Forensically sound** - No path leakage
3. **Court-grade** - Integrity maintained
4. **Enterprise-ready** - Handles terabyte images

This is how EnCase, FTK, Autopsy, and X-Ways operate.

**You are not building a tool. You are building a forensic operating system.**
