# FEPD Evidence Ingestion & Processing Orchestrator

## Implementation Complete ✅

This document describes the forensic-grade evidence ingestion system that was implemented for FEPD.

---

## Architecture Overview

### Core Components

1. **Evidence Upload Dialog** (`src/ui/dialogs/evidence_upload_dialog.py`)
   - Evidence Type selection (Disk/Memory)
   - Multi-part E01 mode toggle
   - Drag-and-drop support
   - Real-time validation

2. **Evidence Orchestrator** (`src/core/evidence_orchestrator.py`)
   - Complete pipeline coordination
   - Chain of Custody automation
   - Hash computation
   - Workspace management

3. **Chain of Custody** (`src/core/chain_of_custody.py`)
   - Blockchain-style tamper-evident logging
   - Expanded action types for pipeline phases

4. **Forensic Shell** (`src/fepd_os/shell.py`)
   - New `status` command for pipeline state
   - Enhanced evidence detection

---

## Upload UI Logic (Phase 1)

### Evidence Type Selection

```
Evidence Type:
[●] Disk Image (E01 / E02+ / DD / RAW / AFF)
[ ] Memory Image (MEM / DMP / RAW)

Options:
[ ] Multi-part E01 evidence (E01 + E02 + ...)
```

### Validation Rules

| Condition | Behavior |
|-----------|----------|
| Multi-part unchecked | Allow only 1 file |
| Multi-part checked | Allow multiple E0x files |
| Memory selected | Allow only 1 file |
| Disk + Memory | Allow both |

### E01 Set Validation

- Same base name (LoneWolf.E01…E09)
- No missing segments
- Sequential numbering
- Size > 0
- Readable

Error format:
```
❌ Invalid evidence set:
- Missing LoneWolf.E04
```

---

## Chain of Custody (Phase 3)

### Automatic Logging

For each file:
- Compute SHA256
- Record size
- Record timestamp
- Append CoC entry

### CoC Record Format

```json
{
  "id": 1,
  "timestamp": "2026-01-12T13:00:00+00:00",
  "user": "investigator",
  "action": "EVIDENCE_IMPORTED",
  "details": "CASE=LoneWolf\nFILES=[...]\nHASHCHAINED=true",
  "prev_hash": "abc123...",
  "self_hash": "def456..."
}
```

### Supported Actions

```python
class CoC_Actions:
    # Chain management
    CHAIN_INITIALIZED = "CHAIN_INITIALIZED"
    
    # Case lifecycle
    CASE_CREATED = "CASE_CREATED"
    CASE_ACCESSED = "CASE_ACCESSED"
    CASE_EXPORTED = "CASE_EXPORTED"
    CASE_IMPORTED = "CASE_IMPORTED"
    CASE_ERROR = "CASE_ERROR"
    
    # Evidence handling
    EVIDENCE_IMPORTED = "EVIDENCE_IMPORTED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    EVIDENCE_MOUNTED = "EVIDENCE_MOUNTED"
    EVIDENCE_HASH_VERIFIED = "EVIDENCE_HASH_VERIFIED"
    
    # Pipeline phases
    PIPELINE_STARTED = "PIPELINE_STARTED"
    PIPELINE_STEP_STARTED = "PIPELINE_STEP_STARTED"
    PIPELINE_STEP_COMPLETED = "PIPELINE_STEP_COMPLETED"
    PIPELINE_ERROR = "PIPELINE_ERROR"
    PIPELINE_COMPLETE = "PIPELINE_COMPLETE"
    
    # Analysis
    ML_ANALYSIS_START = "ML_ANALYSIS_START"
    ML_ANALYSIS_COMPLETE = "ML_ANALYSIS_COMPLETE"
    UEBA_ANALYSIS_START = "UEBA_ANALYSIS_START"
    UEBA_ANALYSIS_COMPLETE = "UEBA_ANALYSIS_COMPLETE"
```

---

## Case Workspace Structure (Phase 4)

```
/case/
├── chain_of_custody.log
├── case.json
├── evidence/
│   ├── disk0/          # Mounted disk image
│   └── memory/         # Memory dump
├── artifacts/
│   ├── evtx/
│   ├── registry/
│   ├── mft/
│   ├── prefetch/
│   ├── browser/
│   ├── network/
│   └── mobile/
├── events/
│   └── events.parquet
├── ml/
│   ├── anomalies.json
│   ├── ueba_profiles.json
│   └── findings.json
├── reports/
└── visualizations/
```

---

## Pipeline Phases (Phase 6)

The orchestrator executes these phases automatically:

1. **Validation** - Verify evidence integrity
2. **Hashing** - Compute SHA-256 for all files
3. **Chain of Custody** - Initialize blockchain log
4. **Workspace Setup** - Create case directory structure
5. **Evidence Reconstruction** - Virtual mount (read-only)
6. **Partition Discovery** - Detect disk partitions (disk images only)
6b. **Memory Analysis** - Full forensic memory analysis (memory images only)
7. **Artifact Discovery** - Find forensic artifacts
8. **Artifact Extraction** - Copy to workspace
9. **Parsing** - Parse EVTX, Registry, etc.
10. **Normalization** - Convert to standard schema
11. **Timeline Build** - Create forensic timeline
12. **ML Analysis** - Autoencoder anomaly detection
13. **UEBA** - User behavior profiling
14. **Visualization** - Generate heatmaps, attack surface
15. **Terminal Init** - Initialize forensic shell

Each phase logs to Chain of Custody:
```
PIPELINE_STEP_STARTED
PIPELINE_STEP_COMPLETED
```

---

## Memory Analysis (Phase 6b)

When processing memory dumps (.mem, .dmp, .raw), the orchestrator automatically executes comprehensive memory analysis:

### Extracted Artifacts

| Artifact | Description |
|----------|-------------|
| Processes | Running processes found in memory |
| Network Connections | IP addresses, ports, connections |
| URLs | HTTP/HTTPS URLs extracted from memory |
| Registry Keys | HKEY_* patterns in memory |
| Strings | Printable ASCII strings |

### Memory Analysis Output

```
/case/
├── memory_analysis/
│   ├── memory_analysis.json
│   ├── processes.txt
│   └── network.txt
└── ml/
    └── memory_findings.json
```

### Chain of Custody Actions

```python
MEMORY_ANALYSIS_START = "MEMORY_ANALYSIS_START"
MEMORY_ANALYSIS_COMPLETE = "MEMORY_ANALYSIS_COMPLETE"
MEMORY_PROCESSES_FOUND = "MEMORY_PROCESSES_FOUND"
MEMORY_NETWORK_FOUND = "MEMORY_NETWORK_FOUND"
MEMORY_STRINGS_EXTRACTED = "MEMORY_STRINGS_EXTRACTED"
```

### Terminal Commands

```bash
# Quick memory scan
fepd:case[root]$ memscan

# Analyze specific memory file
fepd:case[root]$ memscan /path/to/memory.mem

# Full deep analysis
fepd:case[root]$ memscan /path/to/memory.mem --full

# Check memory analysis status
fepd:case[root]$ memscan --status
```

---

## Event Schema (Phase 8)

```json
{
  "timestamp": "2026-01-12T13:00:00Z",
  "user": "SYSTEM",
  "host": "WORKSTATION01",
  "artifact_type": "evtx",
  "action": "logon",
  "path": "/Windows/System32/winevt/Logs/Security.evtx",
  "process": "winlogon.exe",
  "network": "192.168.1.100",
  "severity": "info"
}
```

---

## Forensic Terminal Status Command

```
fepd:CaseName[root]$ status

═══════════════════════════════════════════════════════════════
FEPD Case Status: CaseName
═══════════════════════════════════════════════════════════════

  ✔ Evidence verified
  ✔ Artifacts extracted (125 files)
  ✔ Events parsed
  ✔ ML completed
  ✔ UEBA completed
  ✔ Visualizations built

═══════════════════════════════════════════════════════════════

🔒 Case fully processed and ready for investigation

fepd:CaseName[root]$
```

---

## Error Handling (Phase 12)

If ANY step fails:
1. Stop pipeline
2. Log failure to CoC
3. Mark case = ERROR
4. Offer rollback

Rollback:
- Deletes `/case/*` (workspace only)
- Evidence NEVER touched

---

## Security Rules

| Rule | Implementation |
|------|----------------|
| Never modify evidence | Read-only mounting |
| Never overwrite CoC | Append-only log |
| Never skip hashing | Mandatory SHA-256 |
| Never skip validation | Pre-flight checks |
| Always reproducible | Deterministic pipeline |

---

## Test Results

```
============================================================
TEST SUMMARY
============================================================
  ✅ PASSED: Evidence Validator
  ✅ PASSED: Orchestrator Validation
  ✅ PASSED: Chain of Custody
  ✅ PASSED: Workspace Creation
  ✅ PASSED: Hash Computation
  ✅ PASSED: Upload Dialog Validation

Total: 6/6 tests passed
```

---

## Files Created/Modified

### New Files
- `src/core/evidence_orchestrator.py` - Main orchestrator (1500+ lines)
- `src/ui/dialogs/evidence_upload_dialog.py` - Upload dialog (600+ lines)
- `test_evidence_orchestrator.py` - Test suite

### Modified Files
- `src/ui/main_window.py` - Integrated new upload dialog
- `src/core/chain_of_custody.py` - Added new CoC actions
- `src/fepd_os/shell.py` - Added `status` command

---

## Usage

### From GUI
1. Create/Open case
2. Click "Ingest Disk Image" button
3. Select evidence type (Disk/Memory)
4. Enable multi-part if needed
5. Drop or browse for files
6. Click "Upload Evidence"
7. Watch progress dialog
8. Use forensic terminal when ready

### From Terminal
```bash
fepd:case[root]$ detect
fepd:case[root]$ mount --all
fepd:case[root]$ status
```

---

## Constitutional Principles Enforced

1. **Evidence is IMMUTABLE** - All operations read-only
2. **Chain of custody is SACRED** - Every operation logged
3. **ML outputs are EXPLAINABLE** - Evidence links required
4. **UEBA learns 'normal' to detect 'unusual'**
5. **Reproducible & deterministic** - Same input → Same output
6. **Court-defensible** - All findings backed by artifacts

---

*Implementation completed: January 12, 2026*
