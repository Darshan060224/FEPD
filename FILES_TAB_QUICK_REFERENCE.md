# FEPD Files Tab - Quick Reference Guide

## 🚀 Getting Started

### 1. Opening the Files Tab

The Files Tab automatically appears as the 2nd tab in the FEPD main window:

```
┌─────────────────────────────────────────┐
│ [Case] [Ingest] [📁 Files] [Artifacts] │
│                    ▲                    │
│                    └─── Click here      │
└─────────────────────────────────────────┘
```

### 2. First Time Setup

The Files Tab requires:
- ✅ An active case (created via "New Case" or "Open Case")
- ✅ An ingested disk image (via the Ingest tab)
- ✅ VFS populated (happens automatically during ingest)

---

## 📂 Navigation

### Tree Navigation (Left Panel)

```
📁 This PC
├── 💾 C:
│   ├── 📁 Users
│   │   ├── 👤 Alice
│   │   └── 👤 Bob
│   ├── 📁 Windows
│   └── 📁 Program Files
└── 💾 D:
```

**Actions:**
- **Single Click** → Load contents in center panel
- **Double Click** → Expand/collapse folder

### Breadcrumb Navigation (Top Bar)

```
📁  This PC  ›  C:  ›  Users  ›  Alice  ›  Downloads
    └───┬───┘   └┬┘   └──┬──┘   └──┬──┘   └────┬────┘
        └─────────────────┴──────────┴──────────┴─────
                   Click any segment to jump
```

### Toolbar Buttons

```
[←]  Back       Alt+Left
[→]  Forward    Alt+Right
[↑]  Up Level   Alt+Up
```

---

## 🔍 Browsing Files

### Center Panel (File List)

```
┌──────────────────────────────────────────────────┐
│ Icon │ Name         │ Size    │ Type  │ Modified │
├──────┼──────────────┼─────────┼───────┼──────────┤
│  📁  │ Documents    │ —       │Folder │2024-01-15│
│  📄  │ notes.txt    │ 1.2 KB  │Text   │2024-01-20│
│  ⚡  │ chrome.exe   │ 2.1 MB  │Exe    │2024-01-10│
│  🖼️  │ photo.jpg    │ 340 KB  │JPEG   │2024-02-01│
└──────┴──────────────┴─────────┴───────┴──────────┘
```

**Actions:**
- **Single Click** → Show details in right panel
- **Double Click** → Open file in viewer (or navigate into folder)
- **Right Click** → Context menu

### Details Panel (Right Side)

```
┌─────────────────────────┐
│     📄 notes.txt        │
│     Text Document       │
├─────────────────────────┤
│ Size:     1,234 bytes   │
│ Modified: 2024-01-20    │
│ Created:  2024-01-15    │
│ SHA-256:  abc123...     │
│ Location: /C:/Users/... │
├─────────────────────────┤
│ [Compute SHA-256]       │
├─────────────────────────┤
│ Preview:                │
│ ┌─────────────────────┐ │
│ │ This is the first...│ │
│ │ line of the file... │ │
│ └─────────────────────┘ │
└─────────────────────────┘
```

---

## 🔎 Search & Filter

### Search Box

Type in the search box at the top right:

```
┌──────────────────────┐
│ 🔍 Search files...   │
└──────────────────────┘
```

**Examples:**
- `report` → Find all files containing "report"
- `*.pdf` → Find all PDF files
- `2024` → Find files with "2024" in name

### Filter Dropdown

```
┌─────────────┐
│ All Files   │  ← Click to filter by type
├─────────────┤
│ Images      │
│ Documents   │
│ Executables │
│ Archives    │
└─────────────┘
```

### Sort Options

```
┌─────────────┐
│ Name ↑      │
│ Name ↓      │
│ Size ↑      │
│ Size ↓      │
│ Date ↑      │
│ Date ↓      │
└─────────────┘
```

---

## 📄 Opening Files

### Automatic Viewer Selection

FEPD automatically selects the best viewer based on file type:

| File Type | Viewer | Extensions |
|-----------|--------|------------|
| **Text** | Text Viewer | `.txt`, `.log`, `.csv`, `.json` |
| **Hex** | Hex Viewer | All files (fallback) |
| **Images** | Image Viewer | `.jpg`, `.png`, `.gif`, `.bmp` |
| **PDF** | PDF Viewer | `.pdf` |
| **Video** | Video Viewer | `.mp4`, `.avi`, `.mkv` |

### Manual Viewer Selection

Right-click → Choose viewer:

```
┌─────────────────────────┐
│ 📄 Open (Safe Viewer)   │
├─────────────────────────┤
│ 📝 Text View            │
│ 🔢 Hex View             │
│ 🔤 Strings Extract      │
│ 🔐 Compute SHA-256      │
└─────────────────────────┘
```

---

## ⌨️ Keyboard Shortcuts

### Navigation
| Shortcut | Action |
|----------|--------|
| `Alt+Left` | Navigate back |
| `Alt+Right` | Navigate forward |
| `Alt+Up` | Go up one level |
| `Backspace` | Go up one level |

### File Operations
| Shortcut | Action |
|----------|--------|
| `Ctrl+H` | Open in Hex Viewer |
| `Ctrl+T` | Open in Text Viewer |
| `Ctrl+I` | Show properties |
| `Ctrl+E` | Export to workspace |
| `Return` | Open selected item |
| `F5` | Refresh view |

### Blocked (Read-Only)
| Shortcut | Action | Status |
|----------|--------|--------|
| `Delete` | Delete file | ⛔ BLOCKED |
| `Ctrl+X` | Cut file | ⛔ BLOCKED |
| `F2` | Rename file | ⛔ BLOCKED |
| `Ctrl+V` | Paste file | ⛔ BLOCKED |

---

## 🖱️ Context Menu (Right-Click)

### On Folders

```
┌──────────────────────┐
│ 📂 Open Folder       │
│ ℹ️ Properties         │
├──────────────────────┤
│ ━━ ⛔ BLOCKED ━━     │
│ 🚫 Delete (blocked)  │
│ 🚫 Rename (blocked)  │
└──────────────────────┘
```

### On Files

```
┌──────────────────────────┐
│ 📄 Open (Safe Viewer)    │
├──────────────────────────┤
│ 📝 Text View             │
│ 🔢 Hex View              │
│ 🔤 Strings Extract       │
│ 🔐 Compute SHA-256       │
├──────────────────────────┤
│ ℹ️ Properties             │
│ 📅 Jump to Timeline      │
│ 📤 Export to Workspace   │
├──────────────────────────┤
│ ━━ ⛔ BLOCKED ━━         │
│ 🚫 Delete (blocked)      │
│ 🚫 Rename (blocked)      │
│ 🚫 Cut (blocked)         │
│ 🚫 Edit (blocked)        │
├──────────────────────────┤
│ 🔒 All actions logged    │
└──────────────────────────┘
```

---

## 🔐 Forensic Features

### Read-Only Mode

**ALL write operations are blocked:**
- ❌ Cannot delete files
- ❌ Cannot rename files
- ❌ Cannot modify files
- ❌ Cannot move files
- ❌ Cannot create new files

**Safe operations:**
- ✅ View files
- ✅ Compute hashes
- ✅ Extract strings
- ✅ Export to workspace (creates copy)

### Chain of Custody Logging

Every action is logged:

```
[2024-01-15 10:30:45] FILE_VIEWED
  Path: /C:/Users/Alice/Documents/evidence.pdf
  User: investigator_jones
  Action: opened_in_pdf_viewer
  Hash: abc123def456...

[2024-01-15 10:32:10] FILE_EXPORTED
  Path: /C:/Users/Alice/Documents/evidence.pdf
  Destination: C:/Cases/CASE001/workspace/evidence.pdf
  Hash: abc123def456...
  User: investigator_jones
```

### Hash Computation

**Compute SHA-256/MD5 for any file:**

1. Right-click file → "🔐 Compute SHA-256"
2. Or click "Compute SHA-256" in details panel
3. Hash appears in details panel and is logged

**Uses:**
- Evidence verification
- Duplicate detection
- Court presentation

---

## 📤 Exporting Files

### Why Export?

Since all files are **read-only**, you must export to:
- Make edits or annotations
- Create reports
- Share files with team

### How to Export

1. Right-click file → "📤 Export to Workspace"
2. Choose destination
3. File is **copied** (original remains unchanged)
4. Export is logged to Chain of Custody

---

## 🔄 Terminal Sync

### Bidirectional Integration

**Files Tab → Terminal:**
- Navigate in Files Tab → Terminal's `pwd` changes

**Terminal → Files Tab:**
- Type `cd /C:/Users/Alice` → Files Tab navigates to that folder

### Example

```
Files Tab:  Navigate to /C:/Windows
            │
            ▼
Terminal:   pwd → /C:/Windows

Terminal:   cd /C:/Users
            │
            ▼
Files Tab:  Automatically navigates to /C:/Users
```

---

## ⚠️ Troubleshooting

### "No files visible in Files Tab"

**Possible causes:**
1. No case is loaded → Open or create a case
2. No image ingested → Go to Ingest tab and load a disk image
3. VFS not populated → Wait for ingest to complete

### "File viewer shows 'File reading not available'"

**Solution:**
- The image must be mounted
- Check that `read_file_func` is connected
- Verify disk image is accessible

### "Search returns no results"

**Check:**
- Search is case-insensitive
- Wildcard syntax: `*.pdf` not `pdf`
- Try browsing manually to verify files exist

---

## 🎯 Best Practices

### 1. Always Verify Hashes
- Compute SHA-256 for critical evidence
- Compare with original disk image hash
- Log all hash computations

### 2. Use Export for Working Copies
- Never attempt to modify evidence directly
- Export files to workspace for analysis
- Document all exports in case notes

### 3. Navigate Methodically
- Use breadcrumb for quick jumps
- Use tree for hierarchical browsing
- Use search for specific files

### 4. Check Chain of Custody
- Review CoC logs regularly
- Ensure all accesses are documented
- Export CoC logs for court

---

## 📊 Status Indicators

### Bottom Status Bar

```
┌────────────────────────────────────────────┐
│ 📊 4 folders, 12 files      🔒 Read-Only   │
└────────────────────────────────────────────┘
```

### File Icons by Type

| Icon | Type | Examples |
|------|------|----------|
| 📁 | Folder | Directories |
| 📄 | Generic File | Unknown types |
| ⚡ | Executable | `.exe`, `.dll` |
| 📘 | Document | `.pdf`, `.docx` |
| 🖼️ | Image | `.jpg`, `.png` |
| 📦 | Archive | `.zip`, `.rar` |
| 💿 | Forensic | `.e01`, `.mem` |
| 🗑️ | Deleted | MFT-marked deleted |

---

## 🆘 Support

### Documentation
- `FILES_TAB_IMPLEMENTATION.md` - Full implementation details
- `FILES_TAB_ARCHITECTURE.txt` - Architecture diagrams

### Source Code
- `src/ui/files_tab.py` - Main Files Tab UI
- `src/controllers/files_controller.py` - Controller logic
- `src/core/file_navigator.py` - Navigation engine

### Contact
For issues or questions, check the main FEPD documentation or consult the development team.

---

**Version:** 1.0  
**Last Updated:** 2026-03-08  
**Status:** Production-Ready ✅
