# Interactive Attack Surface Map

## Overview

The Attack Surface Map is now a **fully interactive forensic control panel** that transforms from static visualization into an actionable intelligence system.

## Visual Design

```
┌─────────────────────────────────────────────┐
│ 🔴 ProcessExecution (96)                    │
│   High-risk active behavior                 │
│                                              │
│ 🟠 RegistryPersistence (23) 🟡 FileDrop (47)│
│   Persistence clues         Malware drops   │
│                                              │
│ 🟢 WindowsEvent (22,441)                     │
│   Telemetry / OS activity                   │
└─────────────────────────────────────────────┘
```

## Interactive Features

### 1. Click → Detail Panel Opens

**User Action**: Click any artifact category box (e.g., "ProcessExecution")

**System Response**:
- Detail panel slides in from right
- Shows complete artifact list for that category
- Displays interactive table with:
  - **Name**: Artifact identifier
  - **Evidence Path**: VEOS path (never analyst path)
  - **Modified**: Timestamp
  - **Size**: File size (human-readable)
  - **Anomaly Score**: 0.00-1.00 (color-coded)
  - **Severity**: Low/Medium/High/Critical (color-coded)

### 2. Detail Panel Features

#### Artifact Table
- **Sortable columns**: Click headers to sort
- **Color-coded scores**:
  - 🟢 Green: 0.0-0.4 (Low risk)
  - 🟡 Yellow: 0.4-0.6 (Medium risk)
  - 🟠 Orange: 0.6-0.8 (High risk)
  - 🔴 Red: 0.8-1.0 (Critical risk)

#### Search/Filter
- Real-time filtering of artifacts
- Searches in Name and Path columns
- Type to narrow down results instantly

#### Navigation Buttons
- **📁 Files Tab**: Jump to artifact in Files view
- **📅 Timeline**: Filter timeline by category
- **🤖 ML Analytics**: Focus ML analysis on category

### 3. Double-Click → Navigate

**User Action**: Double-click any row in artifact table

**System Response**:
- Switches to Files tab
- Highlights the selected artifact
- Shows full file metadata

### 4. Color Coding by Risk

Each category box is colored by mean anomaly score:

| Color | Range | Meaning |
|-------|-------|---------|
| Gray | 0.0-0.3 | Normal activity |
| Orange | 0.3-0.5 | Suspicious patterns |
| Red | 0.5-0.7 | High risk indicators |
| Dark Red | 0.7-1.0 | Critical threats |

## Forensic Workflow

### Traditional Approach (Static)
```
Analyst sees chart → Writes notes → Manually searches files
```

### FEPD Approach (Interactive)
```
Click category → See artifacts → Navigate to evidence → Take action
```

## Example Usage Scenarios

### Scenario 1: Investigating Process Execution

1. **See**: Red "ProcessExecution" box with 96 events
2. **Click**: Box opens detail panel
3. **Observe**: Table shows powershell.exe with anomaly score 0.89
4. **Action**: Double-click → Jumps to Files tab
5. **Analyze**: View full process metadata, timeline, ML analysis

### Scenario 2: Registry Persistence Hunt

1. **See**: Orange "RegistryPersistence" box with 23 events
2. **Click**: Opens detail panel
3. **Filter**: Type "Run" in search box
4. **Find**: HKCU\Software\...\Run\Backdoor (score 0.91)
5. **Navigate**: Click "📅 Timeline" to see when it was created
6. **Correlate**: Timeline shows persistence added during incident window

### Scenario 3: Network Activity Analysis

1. **See**: Purple "NetworkActivity" box with 312 events
2. **Click**: Opens artifacts
3. **Sort**: Click "Anomaly" column to sort by risk
4. **Identify**: C2 connection to 185.142.x.x:443 (score 0.93)
5. **Investigate**: Navigate to ML Analytics for UEBA correlation

## Technical Details

### Box Sizing Algorithm

```
weighted_size = log(count + 1) × severity_factor × (1 + anomaly_factor)
```

- **log(count + 1)**: Logarithmic scaling prevents large categories from dominating
- **severity_factor**: Category importance (ProcessExecution=1.8, WindowsEvent=1.2)
- **anomaly_factor**: 1.0 to 2.0 based on mean anomaly score

### Artifact Extraction

When category is clicked, system:
1. Filters events dataframe by category keywords
2. Extracts up to 100 most relevant artifacts
3. Computes severity from anomaly scores
4. Formats timestamps, sizes for display
5. Loads into detail panel table

### Navigation Integration

Detail panel emits Qt signals that parent tabs can connect to:

```python
navigate_to_files = pyqtSignal(str)      # Path to highlight
navigate_to_timeline = pyqtSignal(str)   # Category filter
navigate_to_ml = pyqtSignal(str)         # ML focus
```

## Path Integrity (CRITICAL)

**NEVER expose analyst-side paths in detail panel.**

✅ **Correct** (Evidence path):
```
C:\Users\Admin\AppData\Roaming\evil.exe
```

❌ **WRONG** (Analyst path - breach of forensic integrity):
```
/home/analyst/cases/investigation/evidence/Users/Admin/evil.exe
```

The detail panel **only shows VEOS paths** extracted from evidence.

## Performance Considerations

- Table limited to 100 artifacts per category (configurable)
- Search filtering is client-side (instant)
- Detail panel lazy-loads (only when category clicked)
- No impact on treemap rendering performance

## Future Enhancements

- [ ] Export artifact list to CSV
- [ ] Bulk actions (tag multiple artifacts)
- [ ] In-panel timeline preview
- [ ] Risk explanation tooltips
- [ ] Category comparison mode
- [ ] Artifact clustering within categories

## Testing

Test the interactive features:

```bash
python test_attack_surface_interactive.py
```

This launches the Attack Surface Map with sample data. Click boxes, explore artifacts, test navigation.

## Integration

To use in your tab:

```python
from ui.visualizations.attack_surface_map import AttackSurfaceMapWidget

# Create widget
attack_surface = AttackSurfaceMapWidget()

# Connect navigation signals
attack_surface.navigate_to_files.connect(self._handle_file_navigation)
attack_surface.navigate_to_timeline.connect(self._handle_timeline_filter)
attack_surface.navigate_to_ml.connect(self._handle_ml_focus)

# Load data
attack_surface.load_events(events_dataframe)
```

## Summary

The Attack Surface Map now provides:

✅ **Interactive exploration** - Click to drill down  
✅ **Instant artifact access** - No manual searching  
✅ **Cross-tab navigation** - Seamless workflow  
✅ **Forensic integrity** - Evidence paths only  
✅ **Risk visualization** - Color-coded priorities  
✅ **Actionable intelligence** - From pattern to evidence to action  

This is what transforms FEPD from a viewer into a **forensic intelligence system**.
