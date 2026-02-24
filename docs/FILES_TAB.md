# FEPD Files Tab - Forensic File Explorer

## Overview

The Files Tab provides a **Windows "This PC" style** file explorer specifically designed for forensic evidence browsing. It displays a merged virtual filesystem tree from all ingested evidence images with **100% read-only protection**.

## Key Features

### 🔒 Write-Block Protection
- **All modify operations are blocked**: Delete, Rename, Cut, Paste
- Visual indicator: `🔒 WRITE-BLOCKED` badge in header
- Blocked shortcuts show forensic warning message
- All block events logged to Chain of Custody

### 📁 Filesystem Tree
- Hierarchical view: Disk → Partition → Folders → Files
- Node types with icons:
  - 💿 **DISK** - Physical disk (e.g., "Disk0 (500GB Samsung SSD)")
  - 📀 **PARTITION** - Disk partition (e.g., "Partition1 - NTFS (C:)")
  - 📁 **FOLDER** - Directory
  - 📄 **FILE** - Regular file
  - 👤 **USER** - User profile folder
  - ⚙️ **SYSTEM** - System folder (Windows, System32)
  - 🗑️ **DELETED** - Recovered deleted file
  - 🔗 **SYMLINK** - Symbolic link

### 🧭 Breadcrumb Navigation
- Shows current path with visual segments
- User profile folders highlighted with 👤 icon
- Syncs with terminal current directory

### 👤 User Profile Detection
Automatically detects when browsing user profile folders:
- Windows: `/Users/Administrator`, `/Users/JohnDoe`
- Linux: `/home/user`
- macOS: `/Users/username`

The current user context is shown in the breadcrumb bar and emitted via signals.

### ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+H` | Open file in Hex Viewer |
| `Ctrl+T` | Open file in Text Viewer |
| `Ctrl+Shift+S` | Extract printable strings |
| `Ctrl+I` | Show file details dialog |
| `Ctrl+E` | Export file to workspace |
| `Enter` | Open selected file/expand folder |
| `Delete` | **BLOCKED** - Forensic warning |
| `Ctrl+X` | **BLOCKED** - Forensic warning |
| `F2` | **BLOCKED** - Forensic warning |
| `Ctrl+V` | **BLOCKED** - Forensic warning |

### 📋 Right-Click Context Menu

**For Files:**
- 📄 Open - Open with appropriate viewer
- 📝 View as Text - Open in text viewer
- 🔢 Hex View - Open in hex viewer
- 🔤 Extract Strings - ASCII/Unicode string extraction
- ℹ️ Details - Show file metadata
- 🔐 Compute Hash - Calculate SHA-256
- 📤 Export to Workspace - Save copy to workspace

**For All Items:**
- 🔒 Write Operations Blocked - Disabled indicator

## Signal Integration

The Files Tab emits signals for integration with other components:

```python
class FilesTab(QWidget):
    # Emitted when a node is selected
    node_selected = pyqtSignal(object)  # VFSNode
    
    # Emitted when path changes (for terminal sync)
    path_changed = pyqtSignal(str)
    
    # Emitted when user context changes
    user_context_changed = pyqtSignal(str)  # username or empty
    
    # Emitted when terminal command should execute
    terminal_command = pyqtSignal(str)
    
    # Emitted when write operation was blocked
    write_blocked = pyqtSignal(str)  # action name
```

### Terminal Integration Example

```python
# Connect Files Tab to Terminal
files_tab.path_changed.connect(terminal.sync_path)
files_tab.user_context_changed.connect(terminal.update_prompt_user)
files_tab.terminal_command.connect(terminal.execute_command)
```

## Strings Extraction

The "Extract Strings" feature performs forensic string analysis:
- Extracts ASCII strings (minimum 4 characters)
- Extracts Unicode strings (UTF-16 LE)
- Deduplicates and sorts by length
- Opens results in Text Viewer
- Logs extraction to Chain of Custody

## Chain of Custody Logging

All actions are logged with details:

```
FILE_SELECTED: {path, type, user_context}
FILE_OPENED: {path, name, size, hash}
FILE_EXPORTED: {source_path, export_path, hash}
STRINGS_EXTRACTION_STARTED: {path, name, size}
STRINGS_EXTRACTION_COMPLETE: {path, strings_found, ascii_count, unicode_count}
KEYBOARD_SHORTCUTS_INITIALIZED: {blocked_operations, forensic_shortcuts}
TERMINAL_PATH_SYNC: {terminal_path, found}
```

## Usage

```python
from src.ui.files_tab import FilesTab
from src.core.virtual_fs import VirtualFilesystem

# Create Files Tab with VFS
vfs = VirtualFilesystem("evidence.db")
files_tab = FilesTab(
    vfs=vfs,
    coc_logger=lambda action, details: log_coc(action, details),
    read_file_func=lambda path, offset, length: read_from_evidence(path, offset, length)
)

# Connect signals
files_tab.write_blocked.connect(lambda action: 
    print(f"⚠️ Write blocked: {action}")
)
```

## Demo

Run the demo to see all features in action:

```powershell
python demo_files_tab.py
```

## Architecture

```
FilesTab
├── Header Bar
│   ├── 🖥️ "This Case" title
│   ├── Statistics label (files/folders/size)
│   └── 🔒 WRITE-BLOCKED indicator
├── Breadcrumb Bar
│   ├── 📁 Path icon
│   ├── Breadcrumb path segments
│   └── 👤 User context indicator
├── Main Splitter
│   ├── Tree View (VFSTreeModel)
│   │   ├── Lazy-loading children
│   │   ├── Custom icons by node type
│   │   └── Context menu integration
│   └── Details Panel
│       ├── File preview icon
│       ├── Metadata display
│       └── Hash information
└── Keyboard Shortcuts (write-blocked)
```

## Security Guarantees

1. **No modification possible** - All write operations blocked at keyboard and context menu level
2. **Evidence integrity** - Files are never modified, only exported to workspace
3. **Full audit trail** - Every action logged to Chain of Custody
4. **Read-only file access** - Uses `read_file_func` callback, never direct file access
5. **Hash verification** - SHA-256 displayed for integrity checking
