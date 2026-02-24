# FEPD Case Management Workflows

## Visual Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     FEPD APPLICATION START                       │
│                                                                  │
│              Status: No Active Case (Inactive Mode)              │
│                   Ingest Image: DISABLED ❌                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  User Decision  │
                    └─────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
              ▼                               ▼
     ┌────────────────┐              ┌────────────────┐
     │   NEW CASE     │              │   OPEN CASE    │
     └────────────────┘              └────────────────┘
              │                               │
              │                               │
              ▼                               ▼
```

---

## NEW CASE Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: Ask for Case ID                                         │
│ ┌─────────────────────────────────────────────────────────┐    │
│ │ Enter Case ID (identity anchor):                         │    │
│ │ [2025-CYBER-001____________________________] [OK] [Cancel]│    │
│ └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Validate Case ID                                        │
│ • Must be alphanumeric + underscores/hyphens only               │
│ • Must not already exist in /cases/                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Create /cases/2025-CYBER-001/                          │
│                                                                  │
│ cases/                                                           │
│ └── 2025-CYBER-001/        ← NEW FOLDER CREATED                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 4: Create Placeholder CSV Files (0 bytes)                  │
│                                                                  │
│ 2025-CYBER-001/                                                 │
│ ├── normalized_events.csv      (0 bytes) ✅                    │
│ └── classified_events.csv      (0 bytes) ✅                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 5: Create Empty Chain of Custody Log                       │
│                                                                  │
│ 2025-CYBER-001/                                                 │
│ └── chain_of_custody.log       (0 bytes) ✅                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 6: Write Case Metadata JSON                                │
│                                                                  │
│ case_metadata.json:                                             │
│ {                                                                │
│   "case_id": "2025-CYBER-001",                                  │
│   "created_timestamp": "2025-11-07T13:27:55.447309",           │
│   "timezone_mode": "UTC",                                        │
│   "theme_preference": "dark_indigo",                            │
│   "examiner": "John Doe",                                        │
│   "status": "active",                                            │
│   "version": "1.0.0"                                             │
│ }                                                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 7: Create Subdirectories                                   │
│                                                                  │
│ 2025-CYBER-001/                                                 │
│ ├── artifacts/              ✅ (empty, ready for evidence)     │
│ └── report/                 ✅ (empty, ready for reports)      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 8: Enable Workspace Mode                                   │
│                                                                  │
│ • current_case = "2025-CYBER-001"                               │
│ • case_workspace = Path("cases/2025-CYBER-001")                │
│ • Ingest Image button: ENABLED ✅                               │
│ • Status bar: "📂 Active Case: 2025-CYBER-001"                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ ✅ SUCCESS: Case Created                                         │
│                                                                  │
│ "Case '2025-CYBER-001' created successfully!                    │
│  Workspace: cases/2025-CYBER-001                                │
│  You can now ingest forensic images."                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
        [USER CAN NOW INGEST DISK IMAGES] 🚀
```

---

## OPEN CASE Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: List All Cases in /cases/                               │
│                                                                  │
│ Scanning: cases/                                                 │
│ ├── 2025-CYBER-001/       ✅ Found                              │
│ ├── 2024-HOMICIDE-042/    ✅ Found                              │
│ └── TEST-CASE-123/        ✅ Found                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Show Case Selection Dialog                              │
│ ┌─────────────────────────────────────────────────────────┐    │
│ │ 🔍 Select case to restore:                               │    │
│ │                                                           │    │
│ │ ┌───────────────────────────────────────────────────┐   │    │
│ │ │ 2025-CYBER-001 [Timeline, CoC, 45 Artifacts]      │   │    │
│ │ │   Created: 2025-11-07                              │   │    │
│ │ ├───────────────────────────────────────────────────┤   │    │
│ │ │ 2024-HOMICIDE-042 [Timeline, Normalized, CoC, ... │   │    │
│ │ │   Created: 2024-08-15                              │   │    │
│ │ ├───────────────────────────────────────────────────┤   │    │
│ │ │ TEST-CASE-123 [Empty]                             │   │    │
│ │ │   Created: 2025-11-05                              │   │    │
│ │ └───────────────────────────────────────────────────┘   │    │
│ │                                                           │    │
│ │                                [Open]  [Cancel]           │    │
│ └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Load normalized_events.csv                              │
│                                                                  │
│ Reading: cases/2025-CYBER-001/normalized_events.csv            │
│ Events: 1,247 rows                                              │
│ ✅ Stored in memory for correlation analysis                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 4: Load classified_events.csv → Timeline                   │
│                                                                  │
│ Reading: cases/2025-CYBER-001/classified_events.csv            │
│ Events: 1,247 rows                                              │
│ ✅ Populating timeline table...                                 │
│                                                                  │
│ Timeline Table:                                                  │
│ ┌────────────────────┬──────────┬────────────┬──────────────┐  │
│ │ Timestamp          │ Type     │ Event      │ Description  │  │
│ ├────────────────────┼──────────┼────────────┼──────────────┤  │
│ │ 2025-11-01 14:23:01│ Registry │ Key Modify │ ...          │  │
│ │ 2025-11-01 14:24:15│ EVTX     │ Logon      │ User: admin  │  │
│ │ ...                │ ...      │ ...        │ ...          │  │
│ └────────────────────┴──────────┴────────────┴──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 5: Load chain_of_custody.log → Validate Integrity          │
│                                                                  │
│ Reading: cases/2025-CYBER-001/chain_of_custody.log             │
│ Entries: 45 audit logs                                          │
│                                                                  │
│ Validating hash chain:                                           │
│ Entry 1: hash = abc123...                                       │
│ Entry 2: previous_hash = abc123... ✅ MATCH                     │
│ Entry 3: previous_hash = def456... ✅ MATCH                     │
│ ...                                                              │
│ Entry 45: previous_hash = xyz789... ✅ MATCH                    │
│                                                                  │
│ ✅ Chain of Custody integrity VERIFIED                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 6: Load case_metadata.json → Restore UI State              │
│                                                                  │
│ Reading: cases/2025-CYBER-001/case_metadata.json               │
│                                                                  │
│ Metadata:                                                        │
│ • Case ID: 2025-CYBER-001                                       │
│ • Created: 2025-11-07T13:27:55.447309                          │
│ • Timezone: UTC                                                  │
│ • Theme: dark_indigo                                             │
│ • Examiner: John Doe                                             │
│ • Status: active                                                 │
│                                                                  │
│ ✅ UI state restored from metadata                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 7: Rebuild UI with Restored Data                           │
│                                                                  │
│ • Timeline tab: 1,247 events loaded ✅                          │
│ • Artifacts tab: 45 artifacts loaded ✅                         │
│ • Filters: Restored from ui_filters.json ✅                     │
│ • Workspace mode: ENABLED ✅                                     │
│ • Window title: "FEPD - 2025-CYBER-001" ✅                      │
│ • Status bar: "📂 Active Case: 2025-CYBER-001" ✅               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ ✅ SUCCESS: Case Opened                                          │
│                                                                  │
│ "Case '2025-CYBER-001' loaded successfully!                     │
│  Forensic workspace restored to exact previous state."          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
    [EXACT FORENSIC UNIVERSE RESTORED] 🎯
    [READY FOR PEER REVIEW / ANALYSIS] 🔍
```

---

## Comparison: NEW vs OPEN

```
┌─────────────────────┬────────────────────┬─────────────────────┐
│     OPERATION       │     NEW CASE       │     OPEN CASE       │
├─────────────────────┼────────────────────┼─────────────────────┤
│ Purpose             │ Start new          │ Restore previous    │
│                     │ investigation      │ workspace           │
├─────────────────────┼────────────────────┼─────────────────────┤
│ Creates Files       │ ✅ Empty workspace │ ❌ Uses existing    │
├─────────────────────┼────────────────────┼─────────────────────┤
│ Loads Data          │ ❌ Nothing to load │ ✅ All case data    │
├─────────────────────┼────────────────────┼─────────────────────┤
│ Timeline            │ Empty              │ Full (1,247 events) │
├─────────────────────┼────────────────────┼─────────────────────┤
│ Artifacts           │ 0                  │ 45                  │
├─────────────────────┼────────────────────┼─────────────────────┤
│ CoC Entries         │ 0                  │ 45 (validated)      │
├─────────────────────┼────────────────────┼─────────────────────┤
│ Workspace Mode      │ ENABLED            │ ENABLED             │
├─────────────────────┼────────────────────┼─────────────────────┤
│ Ingest Image Button │ ✅ Ready           │ ✅ Ready            │
├─────────────────────┼────────────────────┼─────────────────────┤
│ Use Case            │ New evidence       │ Peer review, QA     │
└─────────────────────┴────────────────────┴─────────────────────┘
```

---

## State Machine

```
                    ┌──────────────────┐
                    │   FEPD STARTS    │
                    │  (No Active Case)│
                    └────────┬─────────┘
                             │
                     Ingest: DISABLED ❌
                             │
         ┌───────────────────┴───────────────────┐
         │                                       │
    [New Case]                              [Open Case]
         │                                       │
         ▼                                       ▼
┌────────────────────┐              ┌────────────────────┐
│  CREATE WORKSPACE  │              │  LOAD WORKSPACE    │
│                    │              │                    │
│ • Make folder      │              │ • Load CSVs        │
│ • Make placeholders│              │ • Load CoC         │
│ • Write metadata   │              │ • Load metadata    │
│ • Enable workspace │              │ • Enable workspace │
└────────┬───────────┘              └────────┬───────────┘
         │                                   │
         └───────────────┬───────────────────┘
                         │
                         ▼
              ┌────────────────────┐
              │  ACTIVE WORKSPACE  │
              │                    │
              │ Ingest: ENABLED ✅ │
              └────────────────────┘
                         │
                         ▼
              [User can process evidence]
```

---

## Error States

### NEW CASE Errors

```
Input: "2025/CYBER/001"
       ↓
[❌ INVALID] → Contains invalid characters (/)
       ↓
Show error dialog → User tries again
```

```
Input: "EXISTING-CASE"
       ↓
Check: cases/EXISTING-CASE/ exists
       ↓
[❌ DUPLICATE] → Case already exists
       ↓
Show error dialog → User tries different ID
```

### OPEN CASE Errors

```
Select: "CORRUPTED-CASE"
       ↓
Load: chain_of_custody.log
       ↓
Validate hash chain
       ↓
[❌ BROKEN CHAIN] → Hash mismatch detected
       ↓
Show warning dialog → User proceeds with caution
```

```
Select: "MISSING-FILES-CASE"
       ↓
Check: normalized_events.csv (missing)
       ↓
[⚠️ WARNING] → Some files missing
       ↓
Load what's available → Show partial workspace
```

---

## Summary Flow

```
START
  │
  ├─→ NEW CASE
  │     ├─ Validate ID
  │     ├─ Create folder structure
  │     ├─ Create placeholders
  │     ├─ Write metadata
  │     └─ ENABLE workspace → [READY FOR INGESTION]
  │
  └─→ OPEN CASE
        ├─ List available cases
        ├─ User selects case
        ├─ Load CSVs (timeline data)
        ├─ Load & validate CoC
        ├─ Load metadata (UI state)
        ├─ Rebuild UI
        └─ ENABLE workspace → [READY FOR REVIEW]
```

Both paths lead to: **ACTIVE WORKSPACE MODE** 🚀
