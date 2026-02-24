# FEPD OS - Forensic Operating System Architecture

## 🎯 Vision: "A Time-Frozen OS Built From Evidence"

FEPD is no longer just a "tool that shows extracted artifacts." It's now a **Virtual Operating System reconstructed from evidence** where every tab (Files, Terminal, ML, Timeline, Visualizations) behaves as if the dead system is alive again, but in read-only forensic mode.

---

## 🧱 Core Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    FEPD OS Architecture                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   FEPDOSOrchestrator                     │   │
│  │  (src/core/fepd_os_integration.py)                      │   │
│  └───────────────┬───────────────┬─────────────────────────┘   │
│                  │               │                              │
│    ┌─────────────▼──┐  ┌────────▼────────┐  ┌──────────────┐  │
│    │     VEOS       │  │  Evidence CMD   │  │  ML Engine   │  │
│    │  (veos.py)     │  │ (evidence_cmd)  │  │(forensic_ml) │  │
│    └───────┬────────┘  └────────┬────────┘  └──────┬───────┘  │
│            │                    │                   │          │
│            └────────────┬───────┴───────────────────┘          │
│                         │                                       │
│            ┌────────────▼────────────┐                         │
│            │  Evidence Database       │                         │
│            │  (SQLite / VFS)          │                         │
│            └─────────────────────────┘                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 New Files Created

| File | Purpose |
|------|---------|
| `src/core/veos.py` | Virtual Evidence OS core - drives, users, paths |
| `src/core/evidence_cmd.py` | Evidence CMD terminal with blocking |
| `src/ml/forensic_ml_engine.py` | ML with meaningful scores & explanations |
| `src/visualization/investigative_visualizations.py` | Heatmaps, graphs, treemaps |
| `src/core/fepd_os_integration.py` | Orchestrator that ties everything together |

---

## 1️⃣ VEOS (Virtual Evidence OS)

**Location:** `src/core/veos.py`

### Purpose
Parses disk images and rebuilds the file system as it appeared to the victim.

### Key Classes

```python
@dataclass
class VEOSFile:
    display_path: str      # C:\Users\Alice\Desktop\note.txt
    internal_path: str     # cases/corp-leak/Evidence/note.txt  
    physical_path: str     # Actual disk path
    size: int
    is_dir: bool
    timestamps: Dict       # created, modified, accessed
    metadata: Dict         # permissions, owner, hash

@dataclass  
class VEOSDrive:
    letter: str            # C, D, E
    label: str             # "Local Disk"
    fs_type: str           # NTFS, ext4
    total_size: int
    used_size: int
    users: List[VEOSUserProfile]

@dataclass
class VEOSUserProfile:
    username: str          # Alice
    sid: str               # S-1-5-21-...
    home_path: str         # C:\Users\Alice
    is_admin: bool
```

### Path Sanitization

**NEVER shows:**
- `cases/...`
- `Evidence/...`
- `tmp/...`
- Internal Python paths

**ALWAYS shows:**
- `C:\Users\Alice\Desktop\note.txt`
- `/home/bob/documents/file.txt`

```python
sanitizer = VEOSPathSanitizer("windows", "C:\\")
display = sanitizer.sanitize("cases/corp-leak/Evidence/Users/Alice/file.txt")
# Returns: "C:\Users\Alice\file.txt"
```

---

## 2️⃣ Evidence CMD

**Location:** `src/core/evidence_cmd.py`

### Prompt Format
```
fepd:corp-leak[Alice]$ dir C:\Users
fepd:corp-leak[SYSTEM]$ type C:\Windows\System32\config\SAM
```

### Supported Commands (Read-Only)

| Windows | Unix | Description |
|---------|------|-------------|
| `dir` | `ls` | List directory |
| `cd` | `cd` | Change directory |
| `type` | `cat` | View file contents |
| `tree` | `tree` | Directory tree |
| `whoami` | `whoami` | Current user |
| `hostname` | `hostname` | Machine name |
| `systeminfo` | `uname` | System information |
| `find` | `find`/`grep` | Search files/content |

### Blocked Commands (Mutation Prevention)

```
⛔ FORENSIC BLOCK: 'del' would modify evidence
────────────────────────────────────────────────
This terminal operates in READ-ONLY forensic mode.
Mutating commands are blocked to preserve evidence integrity.

Command: del malware.exe
Reason:  File deletion would destroy evidence
Status:  BLOCKED - Evidence preserved

💡 Tip: Use 'find malware.exe' to locate instead
```

**Blocked:** `del`, `copy`, `move`, `format`, `rm`, `mv`, `cp`, `chmod`, `chown`, `sudo`, `mkfs`, etc.

---

## 3️⃣ Forensic ML Engine

**Location:** `src/ml/forensic_ml_engine.py`

### Problem Solved
Before: "Anomaly Score: 1.000" with "Unknown, Unknown, Unknown"
After: Meaningful relative scores with forensic explanations

### Score Ranges

| Score | Severity | Meaning |
|-------|----------|---------|
| 0.0-0.3 | Normal | Baseline activity |
| 0.3-0.6 | Suspicious | Worth investigating |
| 0.6-0.85 | High Risk | Likely malicious |
| 0.85-1.0 | Critical | Active threat indicator |

### Explanations

The ML engine provides reasons like:
- "Rare execution time (03:42 AM)"
- "New binary not seen before"
- "User context switch: SYSTEM → Alice"
- "Encoded/obfuscated command detected"
- "Rapid succession of events (100+/min)"
- "Known attack tool pattern"

### Usage

```python
from src.ml.forensic_ml_engine import ForensicMLEngine

engine = ForensicMLEngine("cases/corp-leak")
engine.train(events_df)

results = engine.analyze(events_df)
# Results include: anomaly_score, severity, explanations
```

---

## 4️⃣ Investigative Visualizations

**Location:** `src/visualization/investigative_visualizations.py`

### 🔥 Activity Heatmap
Time vs activity density. Shows when events occurred with intensity.

```python
heatmap = ActivityHeatmap(events_df)
fig = heatmap.generate_day_hour_heatmap()
```

### 🧬 User Behavior Graph
Who did what. Network graph of users and their actions.

```python
graph = UserBehaviorGraph(events_df)
fig = graph.generate()
```

### 🧭 Attack Path Flow
From entry to impact. Shows attack stages and progression.

```python
flow = AttackPathFlow(events_df)
fig = flow.generate()
```

### 🧱 Artifact Treemap
Distribution like a crypto heatmap.
- Each block = artifact cluster
- Color = severity
- Size = volume

```python
treemap = ArtifactTreemap(events_df)
fig = treemap.generate()
```

---

## 5️⃣ Integration Layer

**Location:** `src/core/fepd_os_integration.py`

### Quick Start

```python
from src.core.fepd_os_integration import initialize_fepd_os

# Initialize for a case
os = initialize_fepd_os("cases/corp-leak")

# Check status
print(os.get_status())
# {
#     'case_name': 'corp-leak',
#     'platform': 'windows',
#     'drive_count': 2,
#     'user_count': 3,
#     'veos_initialized': True,
#     'cmd_initialized': True,
#     'ml_initialized': True
# }

# List files (evidence-native paths only!)
files = os.list_directory("C:\\Users\\Alice\\Desktop")
for f in files:
    print(f.display_path)  # Never shows cases/...

# Execute commands in Evidence CMD
output = os.execute_command("dir C:\\Users")
print(output)

# Run ML analysis
results = os.analyze_ml()
print(results[['anomaly_score', 'severity', 'explanations']].head())

# Generate visualizations
figures = os.generate_visualizations(results)
figures['day_hour_heatmap'].savefig('heatmap.png')

# Get forensic report
report = os.get_forensic_report(results, top_n=10)
print(report)
```

---

## 🔄 UI Integration Points

### Files Tab (`src/ui/files_tab_v2.py`)

Replace current path display with VEOS:
```python
from src.core.fepd_os_integration import get_orchestrator, sanitize_display_path

# When displaying paths
path_label.setText(sanitize_display_path(file.internal_path))

# When listing directories  
files = get_orchestrator().list_directory("C:\\Users")
```

### Terminal Widget

Replace current shell with Evidence CMD:
```python
from src.core.fepd_os_integration import get_orchestrator

cmd = get_orchestrator().cmd
prompt = cmd.prompt  # fepd:corp-leak[Alice]$
output = cmd.execute("dir C:\\")
```

### ML Tab (`src/ui/tabs/ml_analytics_tab.py`)

Use the new Forensic ML Engine:
```python
from src.core.fepd_os_integration import get_orchestrator

engine = get_orchestrator().ml_engine
results = engine.analyze(events_df)
# Now has meaningful scores and explanations
```

### Visualizations Tab (`src/ui/tabs/visualizations_tab.py`)

Add investigative visualizations:
```python
from src.visualization.investigative_visualizations import (
    ActivityHeatmap, UserBehaviorGraph, AttackPathFlow, ArtifactTreemap
)

# Create heatmap
heatmap = ActivityHeatmap(events_df)
fig = heatmap.generate_day_hour_heatmap()

# Embed in PyQt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
canvas = FigureCanvasQTAgg(fig)
layout.addWidget(canvas)
```

---

## ✅ What's Changed

| Before | After |
|--------|-------|
| Paths showed `cases/corp-leak/Evidence/...` | Paths show `C:\Users\Alice\...` |
| Terminal was basic shell | Terminal is Evidence CMD with blocking |
| ML always showed 1.000 | ML shows 0.0-1.0 with explanations |
| Visualizations were generic charts | Visualizations are investigative maps |
| FEPD was a "viewer" | FEPD is a "Forensic Operating System" |

---

## 🚀 Future Enhancements

1. **Live VFS mounting** - Mount evidence as read-only filesystem
2. **Process reconstruction** - Show running processes at time of capture
3. **Network visualization** - Map connections and data flows
4. **Automated IOC detection** - Flag known malicious indicators
5. **Report generation** - One-click forensic report export

---

## 📝 Dependencies

```bash
pip install pandas numpy matplotlib squarify networkx
```

Optional but recommended:
```bash
pip install pytsk3 pyewf  # For disk image parsing
```

---

*FEPD OS - Making the dead system come alive for investigation.*
