# 🎯 Evidence Type Selection - Visual Demo

## What You'll See in the UI

### Step 1: Create New Case
When you click "Create New Case", you'll see this dialog:

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                  Create New Forensic Case                   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Please provide the following information to create a new case.
All fields are required for proper case management and chain
of custody.

Case ID*:         [CASE-2026-001_____________]

Case Name*:       [Financial Fraud Invest___]

Investigator*:    [John Doe__________________]


┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃              Evidence Type Selection                        ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                              ┃
┃  ☐ This evidence is a multi-part forensic image            ┃
┃     (e.g., E01, E02, E03...)                                ┃
┃                                                              ┃
┃  📄 Single File Mode: You can upload exactly one file      ┃
┃     (.img, .dd, .mem, .dmp, .raw, .aff, .log, .zip)        ┃
┃                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                     Evidence Files                           ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                              ┃
┃  [ 📂 Browse for Evidence File(s)... ]                      ┃
┃                                                              ┃
┃  ┌────────────────────────────────────────────────────────┐ ┃
┃  │ No evidence selected                                   │ ┃
┃  │                                                         │ ┃
┃  │                                                         │ ┃
┃  └────────────────────────────────────────────────────────┘ ┃
┃                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


           [ Cancel ]      [ Create Case ]
```

---

### Step 2A: Single File Mode (Default)

**Scenario:** Analyst has a memory dump file

1. Leave checkbox **UNCHECKED**
2. Click "Browse for Evidence File..."
3. Select: `suspect_laptop_memory.dmp`

**Result:**

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                     Evidence Files                           ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                              ┃
┃  [ 📂 Browse for Evidence File... ]                         ┃
┃                                                              ┃
┃  ┌────────────────────────────────────────────────────────┐ ┃
┃  │ ✓ Single file evidence detected:                      │ ┃
┃  │   File: suspect_laptop_memory.dmp                     │ ┃
┃  │   Format: MEMORY                                       │ ┃
┃  │   Size: 8192.00 MB                                     │ ┃
┃  │   Status: READY                                        │ ┃
┃  └────────────────────────────────────────────────────────┘ ┃
┃                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

✅ **Green background** = Valid!  
✅ "Create Case" button is **ENABLED**

---

### Step 2B: Multi-Part Mode

**Scenario:** Analyst has LoneWolf E01 split into 9 parts

1. **CHECK** the box: "This evidence is a multi-part forensic image"

**UI Updates:**

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃              Evidence Type Selection                        ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                              ┃
┃  ☑ This evidence is a multi-part forensic image            ┃  ← CHECKED!
┃     (e.g., E01, E02, E03...)                                ┃
┃                                                              ┃
┃  📦 Multi-Part Mode: You can upload multiple segments       ┃  ← NEW
┃     (E01, E02, ...). FEPD will validate the sequence        ┃
┃     and ensure all parts are present.                       ┃
┃                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                     Evidence Files                           ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                              ┃
┃  [ 📂 Browse for Evidence Parts... ]                        ┃  ← Changed!
┃                                                              ┃
┃  ┌────────────────────────────────────────────────────────┐ ┃
┃  │ No evidence selected                                   │ ┃
┃  └────────────────────────────────────────────────────────┘ ┃
┃                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

2. Click "Browse for Evidence Parts..."
3. File dialog opens: **Select ALL 9 files**

```
┌─────────────────────────────────────────────────────────────┐
│ Select All Evidence Parts (E01, E02, ...)                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  📁 C:\Evidence\                                            │
│                                                              │
│  📄 LoneWolf.E01  ◄─────────────┐                          │
│  📄 LoneWolf.E02                 │                          │
│  📄 LoneWolf.E03                 │  Ctrl+Click              │
│  📄 LoneWolf.E04                 │  or                      │
│  📄 LoneWolf.E05  ◄──────────────┤  Shift+Click             │
│  📄 LoneWolf.E06                 │  to select all           │
│  📄 LoneWolf.E07                 │                          │
│  📄 LoneWolf.E08                 │                          │
│  📄 LoneWolf.E09  ◄─────────────┘                          │
│                                                              │
│  Selected: 9 files                                          │
│                                                              │
│                          [ Open ]  [ Cancel ]               │
└─────────────────────────────────────────────────────────────┘
```

4. Click "Open"

**Result - Valid Multi-Part Set:**

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                     Evidence Files                           ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                              ┃
┃  [ 📂 Browse for Evidence Parts... ]                        ┃
┃                                                              ┃
┃  ┌────────────────────────────────────────────────────────┐ ┃
┃  │ ✓ Detected multi-part forensic image:                 │ ┃
┃  │   Base name: LoneWolf                                  │ ┃
┃  │   Parts: .E01 → .E09                                   │ ┃
┃  │   Total size: 14.60 GB                                 │ ┃
┃  │   Status: COMPLETE                                     │ ┃
┃  └────────────────────────────────────────────────────────┘ ┃
┃                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

✅ **Green background** = Valid!  
✅ All parts detected  
✅ Sequence is complete  
✅ "Create Case" button is **ENABLED**

---

### Step 2C: Error Case - Incomplete Set

**Scenario:** Analyst accidentally skips E05

Selected files: E01, E02, E03, E04, E06, E07, E08, E09

**Result:**

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                     Evidence Files                           ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                              ┃
┃  [ 📂 Browse for Evidence Parts... ]                        ┃
┃                                                              ┃
┃  ┌────────────────────────────────────────────────────────┐ ┃
┃  │ ❌ Incomplete evidence set:                            │ ┃
┃  │   Base name: LoneWolf                                  │ ┃
┃  │   Missing: 5                                           │ ┃
┃  │                                                         │ ┃
┃  │ Forensic integrity requires ALL segments.              │ ┃
┃  │ Please provide the missing parts.                      │ ┃
┃  └────────────────────────────────────────────────────────┘ ┃
┃                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

❌ **Red background** = Invalid!  
❌ Missing part detected  
❌ "Create Case" button is **DISABLED**

**Fix:** Go back and add LoneWolf.E05

---

### Step 2D: Error Case - Multiple Files in Single Mode

**Scenario:** Analyst selects 2 files but forgets to check the checkbox

Selected: `evidence1.img`, `evidence2.img`
Checkbox: ☐ UNCHECKED (Single Mode)

**Result:**

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                     Evidence Files                           ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                              ┃
┃  [ 📂 Browse for Evidence File... ]                         ┃
┃                                                              ┃
┃  ┌────────────────────────────────────────────────────────┐ ┃
┃  │ ❌ Invalid Evidence:                                   │ ┃
┃  │ You selected multiple files.                           │ ┃
┃  │                                                         │ ┃
┃  │ Enable 'Multi-part forensic image' to upload           │ ┃
┃  │ split disks (E01, E02, ...).                           │ ┃
┃  └────────────────────────────────────────────────────────┘ ┃
┃                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

❌ **Red background** = Invalid!  
❌ Error message with clear fix  
❌ "Create Case" button is **DISABLED**

**Fix:** Check the multi-part checkbox

---

## Real-World Examples

### Example 1: Memory Forensics

**Evidence:** `suspect_laptop_2026-01-11.mem`

**Steps:**
1. ☐ Leave checkbox unchecked (Single Mode)
2. Browse → Select memory dump file
3. ✅ See validation: "Single file evidence detected"
4. Click "Create Case"

**Use Case:** 
- Windows memory dump analysis
- Malware analysis from memory
- Live system capture

---

### Example 2: EnCase E01 Disk Image

**Evidence:** Corporate laptop split into 15 parts

```
CompanyLaptop.E01
CompanyLaptop.E02
CompanyLaptop.E03
...
CompanyLaptop.E15
```

**Steps:**
1. ☑ Check "Multi-part forensic image"
2. Browse → Select ALL 15 files (Ctrl+A)
3. ✅ See validation: "Detected multi-part forensic image: E01 → E15"
4. Click "Create Case"

**Use Case:**
- Full disk forensic analysis
- Corporate data breach investigation
- Evidence from FTK Imager, EnCase

---

### Example 3: Large Server Image (L01 format)

**Evidence:** Linux server - 50 GB split into L01 segments

```
WebServer.L01
WebServer.L02
WebServer.L03
WebServer.L04
```

**Steps:**
1. ☑ Check "Multi-part forensic image"
2. Browse → Select all L01 files
3. ✅ See validation: "Parts: .L01 → .L04"
4. Click "Create Case"

**Use Case:**
- Server breach investigation
- Logical disk analysis
- Database forensics

---

## After Case Creation

Once created, **you never see the parts again!**

### FEPD OS View:

```bash
fepd:Case_LoneWolf$ mount
/volumes/system  → LoneWolf (mounted)
/volumes/data    → LoneWolf (mounted)

fepd:Case_LoneWolf$ ls /volumes/system
/Windows
/Users
/Program Files
...

# You work with it as ONE unified disk!
```

### Behind the Scenes:

```
FEPD automatically:
✓ Mounts E01 as primary
✓ Reads E02-E09 automatically when needed
✓ Presents unified file system
✓ Handles segment transitions transparently
✓ Maintains chain of custody for ALL parts
```

---

## Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Select multiple files | `Ctrl+Click` (individual) |
| Select range | `Shift+Click` (range) |
| Select all in folder | `Ctrl+A` |
| Toggle checkbox | `Space` (when focused) |
| Create case | `Alt+C` or `Enter` |

---

## Color Coding

| Color | Meaning | Action |
|-------|---------|--------|
| 🟢 Green | Valid evidence - ready to ingest | Can create case |
| 🔴 Red | Invalid - errors detected | Fix errors first |
| ⚪ Gray | No selection yet | Select evidence |

---

## Tips for Analysts

### ✅ DO:
- ✅ Select ALL parts of a multi-part image
- ✅ Verify sequence is complete before creating case
- ✅ Use descriptive case IDs
- ✅ Double-check file selection

### ❌ DON'T:
- ❌ Mix different evidence sets in one case
- ❌ Skip parts thinking FEPD will "figure it out"
- ❌ Use multi-part mode for single files
- ❌ Ignore red error messages

---

## Common Patterns You'll See

### Pattern 1: E01 (EnCase)
```
Evidence.E01, Evidence.E02, Evidence.E03...
```

### Pattern 2: L01 (Logical)
```
Evidence.L01, Evidence.L02, Evidence.L03...
```

### Pattern 3: Numbered
```
Evidence.001, Evidence.002, Evidence.003...
```

All patterns work the same way - just check the box and select all parts!

---

This visual guide shows exactly what you'll see when using the Evidence Type Selection feature. The UI is designed to be **intuitive, clear, and error-proof**.
