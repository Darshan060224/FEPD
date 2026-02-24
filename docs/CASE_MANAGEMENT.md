# FEPD Case Management System

## Overview

The FEPD Case Management System provides complete forensic workspace control through two primary operations:
- **NEW CASE**: Creates a controlled mini-filesystem for a new investigation
- **OPEN CASE**: Restores the exact previous forensic universe for peer review

## NEW CASE - How It Works

When the examiner clicks **New Case**, the system creates a complete isolated workspace:

### Process Flow

1. **Ask for Case ID**
   - The Case ID becomes the **identity anchor** of the investigation
   - Must contain only letters, numbers, underscores, and hyphens
   - Cannot duplicate an existing case

2. **Create `/cases/{Case_ID}/` folder**
   - Creates isolated directory for this investigation
   - Example: `/cases/2025-CYBER-001/`

3. **Create zero-length placeholder CSV files**
   ```
   /cases/{Case_ID}/normalized_events.csv       (0 bytes)
   /cases/{Case_ID}/classified_events.csv       (0 bytes)
   ```
   - These files will be populated during evidence processing

4. **Create empty `chain_of_custody.log`**
   ```
   /cases/{Case_ID}/chain_of_custody.log        (0 bytes)
   ```
   - Cryptographic hash chain for forensic integrity

5. **Write `case_metadata.json`**
   ```json
   {
     "case_id": "2025-CYBER-001",
     "created_timestamp": "2025-11-07T13:27:55.447309",
     "timezone_mode": "UTC",
     "theme_preference": "dark_indigo",
     "examiner": "John Doe",
     "status": "active",
     "version": "1.0.0"
   }
   ```

6. **Enable "Ingest Image" button (Active Workspace Mode)**
   - UI switches to active workspace state
   - Evidence ingestion now permitted
   - Status bar shows: `📂 Active Case: 2025-CYBER-001`

### Result

A **controlled mini-filesystem** for the investigation:

```
/cases/2025-CYBER-001/
├── normalized_events.csv       (placeholder)
├── classified_events.csv       (placeholder)
├── chain_of_custody.log        (empty)
├── case_metadata.json          (metadata)
├── artifacts/                  (subdirectory)
└── report/                     (subdirectory)
```

---

## OPEN CASE - How It Works

When the examiner clicks **Open Case**, the system restores the complete forensic workspace state.

### Process Flow

1. **List all folders inside `/cases/`**
   - Scans for existing case directories
   - Shows case status indicators:
     - `[Timeline, Normalized, CoC, 45 Artifacts]`
     - Creation timestamp
     - Case metadata

2. **User selects a case**
   - Interactive dialog with case details
   - Shows what data is available in each case

3. **Load `normalized_events.csv` → Restore timeline data**
   - Reads normalized forensic events
   - Stores in memory for correlation analysis

4. **Load `classified_events.csv` → Restore event classes**
   - Reads classified timeline events
   - Populates timeline table in UI
   - Shows all evidence with classifications

5. **Load `chain_of_custody.log` → Show all hash entries**
   - Reads complete audit trail
   - **Validates hash chain integrity**
   - Warns if chain is broken (evidence tampering detection)

6. **Load `case_metadata.json` → Restore UI state**
   - Restores timezone mode (UTC/Local)
   - Restores theme preference
   - Restores examiner information
   - Loads creation timestamp

7. **Rebuild UI using restored data**
   - Populates timeline table
   - Populates artifacts table
   - Applies saved filters
   - Restores window state
   - Enables workspace mode

### Result

The **exact previous forensic universe** is restored:
- ✅ All timeline events displayed
- ✅ All artifacts visible
- ✅ Chain of Custody validated
- ✅ UI state restored (filters, timezone, theme)
- ✅ Ready for peer review

This is **NOT just opening a folder** — it's reconstructing the entire forensic workspace at the exact state the previous examiner left it.

---

## File Structure

### Case Directory Layout

```
/cases/{Case_ID}/
│
├── normalized_events.csv          # Normalized forensic events
├── classified_events.csv          # Classified timeline events  
├── chain_of_custody.log           # Cryptographic audit trail
├── case_metadata.json             # Case configuration & UI state
├── ui_filters.json                # Saved UI filter state (optional)
│
├── artifacts/                     # Extracted evidence
│   ├── evtx/
│   ├── registry/
│   ├── prefetch/
│   ├── browser/
│   └── mft/
│
└── report/                        # Generated reports
    └── FINAL_REPORT.pdf
```

### Metadata Schema

**`case_metadata.json`:**
```json
{
  "case_id": "string",             // Unique case identifier
  "created_timestamp": "ISO8601",  // Case creation time
  "timezone_mode": "UTC|Local",    // Timestamp display mode
  "theme_preference": "string",    // UI theme setting
  "examiner": "string",            // Primary examiner name
  "status": "active|closed",       // Case status
  "version": "string"              // FEPD version
}
```

---

## Workspace States

### Inactive Workspace
- **No active case**
- "Ingest Image" button **DISABLED**
- Status bar: `"No active case - Create or Open a case to begin"`

### Active Workspace
- **Case is open** (NEW or OPEN)
- "Ingest Image" button **ENABLED**
- Status bar: `📂 Active Case: {Case_ID}`
- All forensic operations permitted

---

## Use Cases

### Scenario 1: Starting New Investigation
```
1. Click "File → New Case"
2. Enter Case ID: "2025-INCIDENT-042"
3. ✅ Case created with empty workspace
4. ✅ Ingest Image button enabled
5. Ingest forensic disk image (E01/RAW)
6. Process artifacts
7. Generate timeline
8. Generate report
```

### Scenario 2: Peer Review
```
1. Click "File → Open Case"
2. Select case: "2025-INCIDENT-042 [Timeline, CoC, 127 Artifacts]"
3. ✅ Complete workspace restored
4. ✅ Timeline shows 1,247 events
5. ✅ Artifacts table shows 127 files
6. ✅ Chain of Custody validated (45 entries)
7. Review findings
8. Add additional analysis
9. Generate supplemental report
```

### Scenario 3: Quality Assurance
```
1. Open case from colleague
2. Verify Chain of Custody integrity
3. Review timeline for completeness
4. Validate artifact extraction
5. Check report accuracy
6. Sign off on analysis
```

---

## Chain of Custody Integrity

When opening a case, the system **validates** the cryptographic hash chain:

### Valid Chain
```
Entry 1: hash = abc123...
Entry 2: previous_hash = abc123... ✅ MATCH
Entry 3: previous_hash = def456... ✅ MATCH
```
**Result**: ✅ Chain intact - No tampering detected

### Broken Chain
```
Entry 1: hash = abc123...
Entry 2: previous_hash = WRONG!!! ❌ MISMATCH
```
**Result**: ⚠️ Warning dialog - Evidence handling compromised

---

## Error Handling

### Invalid Case ID
```
Error: "Case ID must contain only letters, numbers, underscores, and hyphens."
```

### Duplicate Case
```
Error: "Case ID 'XYZ' already exists. Please choose a different ID or open the existing case."
```

### Missing Case Files
```
Warning: "Some case files are missing. Workspace may be incomplete."
```

### CoC Integrity Failure
```
Warning: "Chain of Custody integrity check failed! Hash chain may be broken."
```

---

## API Reference

### `_new_case()`
Creates new forensic case with complete workspace initialization.

**Process:**
1. Prompt for Case ID
2. Validate Case ID format
3. Create case folder structure
4. Create placeholder CSV files
5. Create empty CoC log
6. Write metadata JSON
7. Enable workspace mode

### `_open_case()`
Opens existing case and restores complete workspace state.

**Process:**
1. List available cases
2. Show case selection dialog
3. Load case data
4. Validate CoC integrity
5. Restore UI state
6. Enable workspace mode

### `_load_case_data(case_id, case_path)`
Loads complete case data and rebuilds UI.

**Restores:**
- Timeline events (classified_events.csv)
- Normalized data (normalized_events.csv)
- Chain of Custody (chain_of_custody.log)
- UI state (case_metadata.json)
- Artifacts (artifacts/ directory)
- Reports (report/ directory)

### `_set_workspace_active(active)`
Enables/disables workspace mode.

**When Active:**
- Ingest Image button enabled
- Case-related actions available
- Status bar shows active case

**When Inactive:**
- Ingest Image button disabled
- Must create/open case first

---

## Testing

Run the case management test suite:

```bash
python tests/test_case_management.py
```

**Tests:**
- ✅ New Case creation
- ✅ Placeholder file generation
- ✅ Metadata JSON structure
- ✅ Case listing and detection
- ✅ Metadata loading
- ✅ Workspace restoration

---

## Best Practices

1. **Use descriptive Case IDs**: `2025-CYBER-001`, `HOMICIDE-2024-0042`
2. **Validate CoC on every case open**: Check for integrity warnings
3. **Never manually edit case files**: Use FEPD interface only
4. **Back up cases regularly**: `/cases/` directory contains all evidence
5. **Document examiner changes**: Each examiner logs actions in CoC

---

## Forensic Compliance

This case management system ensures:
- ✅ **Evidence Isolation**: Each case has separate controlled workspace
- ✅ **Audit Trail**: Complete Chain of Custody with cryptographic hashing
- ✅ **Reproducibility**: Exact workspace state restoration for peer review
- ✅ **Integrity Validation**: Automatic detection of evidence tampering
- ✅ **Legal Admissibility**: Forensically sound evidence handling

---

## Summary

| Feature | NEW CASE | OPEN CASE |
|---------|----------|-----------|
| **Purpose** | Start new investigation | Restore previous workspace |
| **Creates** | Empty workspace | N/A |
| **Loads** | Nothing | Complete case data |
| **Enables** | Workspace mode | Workspace mode |
| **Result** | Ready for ingestion | Ready for review |
| **Use Case** | New evidence | Peer review, QA |
