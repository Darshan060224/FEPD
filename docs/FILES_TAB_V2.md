# FEPD Files Tab v2 - Forensic Operating System View

## Overview

The Files Tab has been upgraded to be a **Forensic Operating System View** that communicates four truths at all times:

1. **You are browsing evidence**, not your host system
2. **Everything is read-only** & court-safe
3. **Every file is traceable** (hash, partition, source image)
4. **This view is linked to the terminal** (same virtual path)

## Core Promise

> "I am walking inside the suspect's machine. I can touch everything. But nothing I do can destroy evidence. And every action is accountable."

---

## Features Implemented

### 1. 🔗 Clickable Breadcrumb Navigation

**Location:** Top of Files Tab, below status banner

**Display:**
```
🖥️ Evidence Root ▸ 💽 Disk0 ▸ 📦 Partition1 ▸ ⚙️ Windows ▸ 🔧 System32 ▸ 🗝️ config
```

**Behavior:**
- Each segment is a clickable button
- Click any segment to navigate directly to that path
- Icons indicate folder type:
  - 💽 Disk level
  - 📦 Partition level
  - ⚙️ Windows folder
  - 👤 User profile
  - 📁 Regular folder

**Code Location:** `ClickableBreadcrumb` class in `files_tab_v2.py`

---

### 2. 🔒 Forensic Status Banner

**Location:** Top of Files Tab (always visible)

**Display:**
```
┌────────────────────────────────────────────────────────────────────────────┐
│ 🧪 Evidence Source: LoneWolf.E01 + E02    🔒 Mode: READ-ONLY              │
│                                           🧬 Integrity: SHA-256 Verified   │
│ 🗂️ Virtual Filesystem mounted from forensic image (NOT your host system)  │
└────────────────────────────────────────────────────────────────────────────┘
```

**Elements:**
- **Evidence Source:** Shows which forensic images are loaded
- **READ-ONLY Badge:** Prominent green badge indicating forensic mode
- **Integrity Status:** SHA-256 verification status
- **CoC Status:** Chain of Custody active indicator

**Code Location:** `ForensicStatusBanner` class

---

### 3. 📋 Evidence Identity Card (Details Panel)

**Location:** Right side panel (280-380px width)

**Display:**
```
┌─────────────────────────────────────────────┐
│                    🗝️                       │
│                   SAM                        │
│             Registry Hive                    │
│        🔒 READ-ONLY EVIDENCE                 │
│                                             │
│ ─────── 📋 FILE PROPERTIES ────────         │
│ Size:      32 KB (32,768 bytes)             │
│ Created:   2025-01-02 09:12:44              │
│ Modified:  2026-01-09 18:02:11              │
│ Accessed:  2026-01-10 10:41:03              │
│                                             │
│ ─────── 🔐 FORENSIC IDENTITY ──────         │
│ SHA-256:   9a3c...f82e                      │
│ Partition: 💽 Disk0 ▸ 📦 Partition1         │
│ Source:    LoneWolf.E01                     │
│ Path:      Disk0 ▸ Windows ▸ System32       │
│                                             │
│ ────── 🏷️ ARTIFACT CLASSIFICATION ─────    │
│ Type:      Registry - Credentials           │
│ Risk Tags: [Credentials] [Authentication]   │
└─────────────────────────────────────────────┘
```

**Code Location:** `EvidenceIdentityCard` class

---

### 4. 🎨 Color-Coded File Types

**Color Coding:**
| Color | File Types | Meaning |
|-------|-----------|---------|
| 🟠 Orange | `.exe`, `.dll`, `.sys`, `.ps1`, `.bat` | Executables (potential threat) |
| 🟣 Purple | `SAM`, `SYSTEM`, `SOFTWARE`, `.dat` | Registry hives (system config) |
| 🔵 Blue | `.evtx`, `.evt`, `.log`, `.etl` | Event logs (audit trail) |
| 🟡 Amber | `.pst`, `.ost`, `.eml`, `.msg` | Email files |
| 🔴 Red | Flagged files | Suspicious/flagged by ML |
| 🟢 Green | `.doc`, `.pdf`, `.txt` | Documents |
| 🔷 Teal | `.zip`, `.rar`, `.7z` | Archives |
| 🔵 Cyan | `.jpg`, `.png`, `.gif` | Images |

**Code Location:** `FILE_TYPE_COLORS` constant

---

### 5. 🔄 Terminal ↔ Files Tab Sync

**Bidirectional Synchronization:**

**Files Tab → Terminal:**
- Navigating in Files tab updates terminal's current directory
- User profile detection updates terminal prompt
- Double-clicking folder emits `cd <path>` to terminal

**Terminal → Files Tab:**
- `cd /Windows/System32` in terminal navigates Files tab
- Sync indicator shows "🔗 Terminal Synced"

**Visual Indicators:**
- Green "🔗 Terminal Synced" badge when in sync
- Yellow "🔄 Syncing..." during navigation
- Gold "👤 JohnDoe" badge when viewing user profile

**Code Location:** `sync_from_terminal()`, `terminal_command` signal

---

### 6. ⛔ Blocked Operations

**Blocked Actions:**
- Delete (Del key)
- Permanent Delete (Shift+Del)
- Rename (F2)
- Cut (Ctrl+X)
- Paste (Ctrl+V)
- New Folder
- Move
- Save

**Warning Dialog:**
```
┌───────────────────────────────────────────────────────────────────────┐
│           🚫 [READ-ONLY FORENSIC MODE]                                │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   This action would MODIFY EVIDENCE and is BLOCKED.                   │
│                                                                       │
│   FEPD operates in strict forensic mode to preserve:                  │
│                                                                       │
│     ✓ Evidence integrity and hash values                              │
│     ✓ Chain-of-custody compliance                                     │
│     ✓ Court admissibility standards                                   │
│     ✓ Forensic soundness                                              │
│                                                                       │
│   ⚠️  Attempt has been LOGGED in Chain of Custody.                    │
│                                                                       │
│   💡 TIP: Use "Export to Workspace" to create a working copy.         │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

**All attempts logged to Chain of Custody.**

---

## Context Menu (Right-Click)

### Allowed Forensic Operations:
```
📄 Open (Viewer)
─────────────────
🔢 Hex View
🔤 Strings Extract
🔐 Calculate Hash
─────────────────
📤 Export Copy
─────────────────
📅 Show in Timeline
🔍 Find Related Artifacts
─────────────────
ℹ️ Properties
━━ ⛔ BLOCKED (Read-Only) ━━
🚫 Delete
🚫 Rename
🚫 Move
🚫 Copy Here
🚫 New Folder
─────────────────
🔒 All actions logged to CoC
```

---

## Artifact Classification

**Automatic Detection:**
| File | Classification | Risk Tags |
|------|---------------|-----------|
| `SAM` | Registry - Credentials | [Credentials] [Authentication] |
| `NTUSER.DAT` | Registry - User Settings | [User Profile] [Persistence] |
| `Security.evtx` | Event Log - Security Audit | [Authentication] [Audit Trail] |
| `*.pf` | Prefetch - Execution Evidence | [Execution] [Timeline] |
| `*.exe` | Executable - Binary | [Executable] |
| `*.ps1` | Executable - Scripting | [Scripting] [PowerShell] |

---

## Integration

### From Python Code:
```python
from src.ui.files_tab_v2 import ForensicFilesTab, EvidenceIdentityCard

# Create Files Tab
files_tab = ForensicFilesTab(
    vfs=virtual_filesystem,
    read_file_func=read_func,
    coc_logger=chain_of_custody_logger
)

# Connect signals
files_tab.path_changed.connect(on_path_changed)
files_tab.terminal_command.connect(execute_in_terminal)
files_tab.write_blocked.connect(on_write_attempt)

# Set evidence source
files_tab.set_evidence_source("LoneWolf.E01 + E02 + E03")
```

---

## Files Changed

| File | Changes |
|------|---------|
| `src/ui/files_tab_v2.py` | **NEW** - Complete forensic file explorer implementation |
| `src/ui/main_window.py` | Import v2, add terminal sync setup |
| `test_files_tab_v2.py` | Component tests |

---

## Testing

Run the test suite:
```bash
python test_files_tab_v2.py
```

Expected output:
```
[1/6] Testing imports... ✅
[2/6] Testing forensic constants... ✅
[3/6] Testing breadcrumb path parsing... ✅
[4/6] Testing file type detection... ✅
[5/6] Testing user context detection... ✅
[6/6] Testing artifact classification... ✅

ALL FORENSIC FILES TAB v2 TESTS PASSED ✅
```

---

## Design Philosophy

The Files Tab is designed to feel like:

> "I am inside the suspect's disk, but nothing I do can ever damage it."

Every visual element reinforces:
- 🔒 **Safety**: Read-only mode is always visible
- 📍 **Traceability**: Every file shows its forensic identity
- ⚖️ **Court-readiness**: All actions are logged
- 🔗 **Consistency**: Terminal and Files tab stay in sync
