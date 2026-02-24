# FEPD UI/UX Quick Visual Reference

## 🎨 UI Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  FEPD - Forensic Evidence Processing Dashboard                 │
│  ┌───────┬──────────┬─────────┬────────┐                       │
│  │📁Ingest│🔍Artifacts│📊Timeline│📄Report│                       │
│  └───────┴──────────┴─────────┴────────┘                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  TAB CONTENT AREA (see layouts below)                          │
│                                                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 1️⃣ Image Ingest Wizard Layout

### Page 1: Image Selection
```
┌─────────────────────────────────────┐
│  Select Disk Image                  │
├─────────────────────────────────────┤
│  ┌───────────────────────────────┐  │
│  │     📦                        │  │
│  │  Drag & Drop Image Here       │  │
│  │  or click Browse button       │  │
│  │                               │  │
│  │  [gray border → blue on hover]│  │
│  └───────────────────────────────┘  │
│                                     │
│  Or: [Browse...] button             │
│                                     │
│  Selected: case_image.E01           │
│  Size: 2.5 GB | Format: E01         │
│                                     │
│           [← Back]  [Next →]        │
└─────────────────────────────────────┘
```

### Page 2: Timezone & Options
```
┌─────────────────────────────────────┐
│  Timezone & Options                 │
├─────────────────────────────────────┤
│  Timezone: [UTC ▼]                  │
│                                     │
│  Acquisition Options:               │
│  ☑ Verify image hash on load        │
│  ☑ Enforce read-only mode           │
│  ☑ Search for orphan files          │
│  ☐ Carve deleted files (slow)       │
│                                     │
│  Evidence Metadata:                 │
│  Evidence #: [EVID-2025-001]        │
│  Examiner:   [John Doe]             │
│  Notes:      [text area...]         │
│                                     │
│         [← Back]  [Next →]          │
└─────────────────────────────────────┘
```

### Page 3: Ingest Modules
```
┌─────────────────────────────────────┐
│  Select Analysis Modules            │
├─────────────────────────────────────┤
│  [✓ All] [⭐ Recommended] [✗ None]  │
│                                     │
│  Core:                              │
│  ☑ File System Analysis             │
│  ☑ Hash Lookup (NSRL)               │
│  ☑ Registry Parser                  │
│  ☑ MFT Parser                       │
│                                     │
│  Internet:                          │
│  ☑ Browser History                  │
│                                     │
│  Communication:                     │
│  ☑ Email Parser                     │
│  ☐ Chat & Messaging                 │
│                                     │
│  [+ 6 more categories...]           │
│                                     │
│         [← Back]  [Next →]          │
└─────────────────────────────────────┘
```

### Page 4: Progress
```
┌─────────────────────────────────────┐
│  Ingestion Progress                 │
├─────────────────────────────────────┤
│  Status: Processing MFT...          │
│  [████████░░░░░░░░░] 45%            │
│                                     │
│  ┌──────────┬────────┬──────────┐   │
│  │ Module   │ Status │ Progress │   │
│  ├──────────┼────────┼──────────┤   │
│  │Filesystem│ ✅ Done│ [█████] │   │
│  │Registry  │ ✅ Done│ [█████] │   │
│  │MFT       │🔄 Run  │ [███░░] │   │
│  │Browser   │⏳ Pend │ [░░░░░] │   │
│  └──────────┴────────┴──────────┘   │
│                                     │
│  Log:                               │
│  ┌───────────────────────────────┐  │
│  │ [12:34:56] Starting MFT...    │  │
│  │ [12:35:10] Found 12,456 files │  │
│  │ [auto-scroll to bottom]       │  │
│  └───────────────────────────────┘  │
│                                     │
│         [← Back]  [❌ Cancel]       │
└─────────────────────────────────────┘
```

---

## 2️⃣ Artifacts Browser Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  🔍 Artifacts Browser                                               │
├────────────┬───────────────────────────────────┬─────────────────────┤
│ TREE (20%) │      TABLE (50%)                  │  PREVIEW (30%)     │
│            │                                   │                    │
│ 💾 Data    │  🔎 Filters                       │  📋 Details        │
│   Sources  │  Search: [text box...]  [✗]      │                    │
│            │  Type:[All▼] Status:[All▼]       │  Name: file.jpg    │
│ 🔍 Results │  Size:[Any▼] ⭐Tagged ☐Hide Known│  Type: Image       │
│   📁File   │  [🔄 Reset Filters]               │  Path: /pics/...   │
│     System │                                   │  Size: 2.5 MB      │
│     ├─All  │  ┌──┬────┬──────┬──────┬─────┐  │                    │
│     ├─Del  │  │📌│Type│Name  │Path  │Date │  │  ⏰ Timestamps     │
│     └─Carve│  ├──┼────┼──────┼──────┼─────┤  │  Mod: 2025-01-15   │
│   🔐Reg    │  │☑│📄│pic.jpg│/doc│11:22│  │  Acc: 2025-01-15   │
│     ├─Auto │  │☐│📐│sys.dll│/win│10:15│  │  Crt: 2025-01-10   │
│     ├─USB  │  │☑│🌐│page.html│/tmp│09:30│ │                    │
│     └─Recent│  │[alternating colors]        │  │  🔐 Hashes         │
│   🌐Web    │  │[sortable columns]          │  │  MD5: abc123...    │
│   💬Comm   │  │[color-coded status]        │  │  SHA256: def456... │
│   📸Media  │  └──┴────┴──────┴──────┴─────┘  │                    │
│            │                                   │  👁️ Preview        │
│ ⭐ Tagged  │  Context Menu (right-click):      │  ┌──────────────┐  │
│   Items    │  ⭐ Tag | 💾 Export | 🔍 Hex     │  │ [text/hex]   │  │
│            │  📋 Copy Hash | 📋 Copy Path     │  │ [content]    │  │
│ 🔍 Hash    │                                   │  └──────────────┘  │
│   Matches  │  Loaded 1,234 artifacts           │                    │
│            │  [📤 Export Filtered Results...] │  [⭐ Tag Notable]  │
│ 📊 Stats   │                                   │  [💾 Export...]   │
│ Total:1234 │                                   │  [🔍 Hex View]    │
│ Filtered:56│                                   │                    │
│ Tagged: 12 │                                   │                    │
└────────────┴───────────────────────────────────┴─────────────────────┘
```

**Color Legend**:
- 🟢 Green cells = Active files
- 🔴 Red cells = Deleted files
- 🟡 Yellow cells = Carved files
- 🟣 Purple cells = Encrypted files

---

## 3️⃣ Timeline Visualization Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  📊 Timeline Visualization                                          │
├─────────────────────────────────────────────────────────────────────┤
│  Select Categories:                                                 │
│  ☑Media ☑Email ☑Web ☑FileSystem ☑Registry ☑Chat ☑Docs             │
│  [✓ All] [✗ None]                                                  │
│                                                                     │
│  Zoom: [🔍 In] [🔍 Out] [🔄 Reset]       [📤 Export Timeline...]  │
├─────────────────────────────────────────────────────────────────────┤
│  📊 Timeline Chart                                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                             │   │
│  │ Media     │ ●●●  [heatmap]  ●●●●●                         │   │
│  │ Email     │ ●  ●●●●●●  ●                                  │   │
│  │ Web       │ [█████heat]  ●●●●  ●                          │   │
│  │ File Sys  │ ●●●●●●●●●●●●●●●●●●●●                         │   │
│  │ Registry  │ ●  ●  ●                                       │   │
│  │ Chat      │ ●●●●●●●●●●                                    │   │
│  │           │                                               │   │
│  │           ├───┬───────┬───────┬───────┬───────┬──────┤   │   │
│  │         Jan-01  Jan-15  Feb-01  Feb-15  Mar-01  Mar-15 │   │
│  │                                                             │   │
│  │  [Drag to pan] [Mouse wheel to zoom]                       │   │
│  │  [Click dot to see details]                                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Loaded 5,432 events | Range: 2025-01-01 to 2025-03-15            │
├─────────────────────────────────────────────────────────────────────┤
│  📋 Event Details                                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Time:     2025-02-15 14:23:45                               │   │
│  │ Category: Email                                             │   │
│  │ Name:     Important Message.eml                             │   │
│  │ Description: Email from suspect to victim                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

**Features**:
- Heatmap automatically appears in dense areas (red gradient)
- Zoom in → heatmap breaks into individual dots
- Drag left/right to pan through time
- Mouse wheel to zoom in/out

---

## 4️⃣ Report Generation Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  📄 Report Generation                                               │
├──────────────────────────────────┬──────────────────────────────────┤
│  CONFIG (50%)                    │  PREVIEW (50%)                   │
│                                  │                                  │
│  📋 Case Metadata                │  👁️ Report Preview               │
│  ┌────────────────────────────┐ │  ┌────────────────────────────┐ │
│  │ Case #:  [CASE-2025-001]   │ │  │ Forensic Examination Report│ │
│  │ Examiner:[John Doe]        │ │  │ ───────────────────────────│ │
│  │ Org:     [Digital Forensics│ │  │                            │ │
│  │          Lab]              │ │  │ Case Information           │ │
│  │ Start:   [📅 2025-01-15]   │ │  │ Case #: CASE-2025-001      │ │
│  │ End:     [📅 2025-01-20]   │ │  │ Examiner: John Doe         │ │
│  │ Victim:  [Jane Smith]      │ │  │ ...                        │ │
│  │ Summary: [text area...]    │ │  │                            │ │
│  └────────────────────────────┘ │  │ Evidence Items:            │ │
│                                  │  │ [table preview...]         │ │
│  ⭐ Evidence Selection            │  │                            │ │
│  [✓ Select All] [✗ Deselect]    │  │ Chain of Custody:          │ │
│  ┌──┬────┬────────┬─────┬────┐ │  │ [log preview...]           │ │
│  │☑│Type│Name    │Path │Date│ │  │                            │ │
│  ├──┼────┼────────┼─────┼────┤ │  │ Findings:                  │ │
│  │☑│Img │pic.jpg │/doc │1/15│ │  │ [findings preview...]      │ │
│  │☑│Doc │report  │/usr │1/16│ │  │                            │ │
│  │☐│Web │cache   │/tmp │1/17│ │  └────────────────────────────┘ │
│  └──┴────┴────────┴─────┴────┘ │                                  │
│  12 artifacts selected           │  [🔄 Refresh Preview]            │
│                                  │  Preview generated successfully  │
│  ⚙️ Report Options               │                                  │
│  Format:   [PDF ▼]              │                                  │
│  Template: [Detailed Report ▼]  │                                  │
│                                  │                                  │
│  Include in Report:              │                                  │
│  ☑ Chain-of-Custody Log          │                                  │
│  ☑ Cryptographic Hashes          │                                  │
│  ☑ Screenshots and Thumbnails    │                                  │
│  ☐ Timeline Visualization        │                                  │
│  ☑ Statistical Summary           │                                  │
│                                  │                                  │
│  Page Options:                   │                                  │
│  ☑ Page Numbers                  │                                  │
│  ☑ Headers and Footers           │                                  │
│  ☐ Watermark (Draft/Confidential)│                                  │
│                                  │                                  │
└──────────────────────────────────┴──────────────────────────────────┤
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  [████████████░░░░░░░░░] 65% Generating report...          │    │
│  │  [📄 Generate Report]  [📁 Choose Save Location...]        │    │
│  │  Report will be saved to: C:\Cases\CASE-2025-001\report.pdf│    │
│  └────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🎨 Color Scheme (Dark Indigo Theme)

```
Background:     #2c2c2c (Dark Gray)
Panel BG:       #3a3a3a (Lighter Gray)
Border:         #555555 (Medium Gray)
Text:           #eeeeee (Off-White)
Primary:        #3498db (Blue)
Success:        #2ecc71 (Green)
Warning:        #f1c40f (Yellow)
Danger:         #e74c3c (Red)
Accent:         #9b59b6 (Purple)

Status Colors:
  Active:       #2ecc71 (Green) @ 50% alpha
  Deleted:      #e74c3c (Red) @ 50% alpha
  Carved:       #f1c40f (Yellow) @ 50% alpha
  Encrypted:    #9b59b6 (Purple) @ 50% alpha
```

---

## 📱 Icons Used

```
Emoji Icons (Unicode):
  📁 Folder/Ingest
  🔍 Search/Artifacts
  📊 Timeline/Charts
  📄 Report/Document
  📦 Package/Upload
  📋 Clipboard/Details
  📌 Pin/Tag
  ⭐ Star/Notable
  💾 Save/Export
  🔐 Registry/Security
  🌐 Web/Browser
  📧 Email
  💬 Chat
  🖼️ Image
  📝 Document
  ⚙️ Settings
  ✅ Complete
  ❌ Error/Cancel
  ⏳ Pending
  🔄 Running/Refresh
  🔍 Zoom
  📤 Export
  👁️ Preview
  ⏰ Time
```

---

## 🎯 Key Interactions

### Drag & Drop
```
State 1 (Normal):
┌───────────────┐
│   📦          │  Border: gray (#7f8c8d)
│ Drop Here     │  BG: transparent
└───────────────┘

State 2 (Hover):
┌───────────────┐
│   📦          │  Border: blue (#3498db) ← changes on hover
│ Drop Here     │  BG: blue @ 10% alpha
└───────────────┘

State 3 (Dropped):
┌───────────────┐
│   ✅          │  Shows filename
│ case_img.E01  │  Shows size & format
│ 2.5 GB | E01  │
└───────────────┘
```

### Filter Updates
```
User types "email" in search box
        ↓
Real-time filtering (instant update)
        ↓
Table updates: 1,234 → 23 artifacts
        ↓
Statistics update: "Filtered: 23"
```

### Timeline Interaction
```
Normal View (zoomed out):
  [████████████] ← Heatmap (red gradient)
        ↓ zoom in (mouse wheel)
  [● ● ● ● ●] ← Individual dots
        ↓ click dot
  Detail pane shows event info
```

---

## 📐 Responsive Layout

### Artifacts Tab Splitter Proportions
```
┌──────┬─────────────────────┬───────────┐
│ 20%  │        50%          │    30%    │
│ Tree │       Table         │  Preview  │
└──────┴─────────────────────┴───────────┘

User can drag splitter handles to adjust:
   ↕                    ↕
Minimum width: 200px for tree, 300px for preview
```

### Timeline Tab Splitter Proportions
```
┌───────────────────────────────────────┐
│             600px                     │
│           Timeline                    │
├───────────────────────────────────────┤
│             200px                     │
│          Event Details                │
└───────────────────────────────────────┘

Vertical split can be adjusted
          ↔
```

---

## 🚀 UI Flow Diagram

```
Start FEPD
    ↓
Create/Open Case
    ↓
[📁 Ingest Tab]
    ↓ Launch Wizard
  Step 1: Select image (drag-drop or browse)
    ↓
  Step 2: Configure timezone & options
    ↓
  Step 3: Select analysis modules
    ↓
  Step 4: Monitor progress
    ↓
Ingestion Complete
    ↓
[🔍 Artifacts Tab]
    ↓ Auto-load artifacts
  Browse categories
  Apply filters
  Preview artifacts
  Tag notable items
    ↓
[📊 Timeline Tab]
    ↓ View events
  Zoom/pan timeline
  Filter by category
  Click events for details
    ↓
[📄 Report Tab]
    ↓ Generate report
  Fill case metadata
  Select evidence
  Choose format
  Generate & export
    ↓
Report Saved!
```

---

## 💡 Tooltips & Help Text

### Ingest Wizard
- **Verify hash**: "Calculate and verify cryptographic hash to ensure image integrity"
- **Read-only mode**: "Prevent any modifications to evidence (forensically sound)"
- **Orphan files**: "Search for files not listed in filesystem (carved)"
- **File carving**: "Recover deleted files from unallocated space (time-intensive)"

### Artifacts Tab
- **Tagged Only**: "Show only artifacts marked as notable"
- **Hide Known**: "Hide files matching NSRL known-good hashes"
- **Type filter**: "Filter by artifact category (Files, Registry, Web, etc.)"
- **Status filter**: "Filter by file status (Active, Deleted, Carved, Encrypted)"

### Timeline Tab
- **Zoom**: "Use mouse wheel or buttons to zoom in/out"
- **Pan**: "Click and drag to move through time"
- **Heatmap**: "Dense areas shown as red gradient; zoom to see individual events"

### Report Tab
- **CoC Log**: "Include complete chain-of-custody documentation"
- **Hashes**: "Include MD5 and SHA-256 hashes for all evidence"
- **Watermark**: "Add 'DRAFT' or 'CONFIDENTIAL' watermark to pages"

---

## 📏 Size Guidelines

### Minimum Window Size
- Width: 1200px
- Height: 700px
- Optimal: 1600x900 (16:9 aspect ratio)

### Button Heights
- Normal: 30-35px
- Large (Generate Report): 40-50px
- Icon buttons: 25-30px

### Font Sizes
- Headers: 14-16px bold
- Body text: 11-12px
- Small text (stats): 10-11px
- Table text: 11px

### Table Row Heights
- Normal rows: 30-35px
- Header row: 35-40px

---

This visual reference provides a quick understanding of the UI layout and interactions!
