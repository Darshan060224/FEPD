# Requirements Specification (SRS)

## FEPD – Forensic Evidence Parser Dashboard

**Software Requirements Specification**

---

## TABLE OF CONTENTS

1. [Functional Requirements](#functional-requirements)
   - Image Ingestion (FR-01 to FR-04)
   - Artifact Discovery (FR-05 to FR-06)
   - Extraction & Hashing (FR-07 to FR-09)
   - Parsing (FR-10 to FR-14)
   - Normalization & Rules (FR-15 to FR-17)
   - Timeline Visualization (FR-18 to FR-20)
   - Reporting (FR-21 to FR-23)
   - Chain of Custody (FR-24 to FR-25)
   - Advanced Search (FR-26 to FR-28)
   - Annotations (FR-29 to FR-30)
   - Case Management (FR-31 to FR-33)
   - UI Features (FR-34 to FR-35)

2. [Non-Functional Requirements](#non-functional-requirements)
   - Performance
   - Security & Forensic Integrity
   - Usability
   - Reliability & Fault Tolerance
   - Maintainability
   - Portability

3. [Data Dictionary](#data-dictionary)

---

## FUNCTIONAL REQUIREMENTS

### A) Image Ingestion

**FR-01: Forensic Image Format Support**
- **Description:** System shall ingest forensic disk images in E01 (Expert Witness Format), RAW (dd), and DD formats.
- **Input:** File path to forensic image
- **Output:** Mounted virtual filesystem handle
- **Priority:** Critical
- **Verification:** Load sample E01, RAW, and DD images successfully

**FR-02: Image Integrity Hashing**
- **Description:** System shall compute SHA-256 cryptographic hash of the entire ingested image.
- **Input:** Forensic image file
- **Output:** 64-character hexadecimal SHA-256 hash
- **Priority:** Critical
- **Verification:** Hash matches known reference hash (NIST NSRL test images)

**FR-03: Chain-of-Custody Entry for Image**
- **Description:** System shall record a chain-of-custody entry with timestamp (UTC), hash value, and image path upon ingestion.
- **Input:** Image hash, timestamp, file path
- **Output:** CoC log entry (append-only)
- **Priority:** Critical
- **Verification:** CoC log contains accurate entry with correct timestamp and hash

**FR-04: Read-Only Image Access**
- **Description:** System shall always open forensic images in read-only mode. No write operations shall be permitted.
- **Input:** Forensic image file
- **Output:** Read-only file handle
- **Priority:** Critical
- **Verification:** Attempt to write to image fails; hash remains unchanged after analysis

---

### B) Artifact Auto Discovery

**FR-05: Automated Windows Artifact Scanning**
- **Description:** System shall auto-scan default Windows artifact paths inside the mounted image, including:
  - `/Windows/System32/winevt/Logs/` (Event Logs)
  - `/Windows/System32/config/` (Registry hives)
  - `/Windows/Prefetch/` (Prefetch files)
  - Browser profile directories (Chrome, Edge, Firefox)
  - `$MFT` (Master File Table)
- **Input:** Mounted forensic image filesystem
- **Output:** List of discovered artifact paths
- **Priority:** High
- **Verification:** Known test image with planted artifacts returns complete list

**FR-06: Automatic Artifact Queuing**
- **Description:** System shall automatically enqueue discovered artifacts for extraction without manual intervention.
- **Input:** Discovered artifact list
- **Output:** Extraction queue
- **Priority:** High
- **Verification:** Queue contains all expected artifacts after discovery

---

### C) Extraction & Hashing

**FR-07: Local Artifact Extraction**
- **Description:** System shall extract discovered artifacts to a local case workspace directory.
- **Input:** Artifact internal path inside image
- **Output:** Extracted file in case workspace
- **Priority:** Critical
- **Verification:** Extracted files match original artifact byte-for-byte

**FR-08: Artifact-Level SHA-256 Hashing**
- **Description:** System shall compute SHA-256 hash for every extracted artifact individually.
- **Input:** Extracted artifact file
- **Output:** SHA-256 hash string
- **Priority:** Critical
- **Verification:** Hash matches reference hash for known artifacts

**FR-09: Artifact Provenance Logging**
- **Description:** System shall store artifact hash, internal image path, extracted path, and extraction timestamp into chain-of-custody log.
- **Input:** Artifact metadata
- **Output:** CoC log entry
- **Priority:** Critical
- **Verification:** CoC log accurately reflects all extracted artifacts

---

### D) Parsing

**FR-10: EVTX Event Log Parsing**
- **Description:** System shall parse Windows Event Log (EVTX) files and extract:
  - Timestamp (TimeCreated)
  - Provider name
  - Event ID
  - Event message/description
  - Computer name
  - User SID (if present)
- **Input:** Extracted .evtx files
- **Output:** Structured event records
- **Priority:** Critical
- **Verification:** Parse Security.evtx and correctly extract EventID 4624 (logon events)

**FR-11: Registry Hive Parsing**
- **Description:** System shall parse Windows Registry hive files (SYSTEM, SOFTWARE, SAM, NTUSER.DAT) and extract:
  - Registry key paths
  - Value names and data
  - Last modified timestamps
- **Input:** Extracted registry hive files
- **Output:** Registry key-value records
- **Priority:** Critical
- **Verification:** Extract Run keys from SOFTWARE hive correctly

**FR-12: Prefetch File Parsing**
- **Description:** System shall parse Windows Prefetch (.pf) files and extract:
  - Executable name
  - Run count
  - Last run timestamp
  - File paths accessed by executable
- **Input:** Extracted .pf files
- **Output:** Prefetch execution records
- **Priority:** High
- **Verification:** Parse CALC.EXE-*.pf and verify run count accuracy

**FR-13: MFT (Master File Table) Parsing**
- **Description:** System shall parse NTFS Master File Table and extract:
  - File paths
  - MACB timestamps (Modified, Accessed, Changed, Birth)
  - File sizes
  - File attributes
- **Input:** Extracted $MFT file
- **Output:** File metadata records with MACB timelines
- **Priority:** High
- **Verification:** Extract timestamps for known files and verify accuracy

**FR-14: Browser History Parsing**
- **Description:** System shall parse browser history databases (Chrome, Edge, Firefox) and extract:
  - URLs visited
  - Visit timestamps
  - Page titles
  - Visit counts
- **Input:** Extracted browser SQLite databases (History, places.sqlite)
- **Output:** Web browsing activity records
- **Priority:** Medium
- **Verification:** Parse Chrome History file and extract known visited URLs

---

### E) Normalization & Rule Engine

**FR-15: Unified Event Schema Normalization**
- **Description:** System shall normalize all parsed outputs into a unified event schema with standardized fields:
  - `event_id` (UUID)
  - `ts_utc` (Timestamp UTC)
  - `ts_local` (Timestamp Local)
  - `artifact_source` (EVTX/REG/PF/MFT/Browser)
  - `artifact_path` (Internal image path)
  - `event_type` (Execution/FileAccess/RegistryModify/etc.)
  - `user_account` (Username if available)
  - `exe_name` (Executable name if applicable)
  - `event_id_native` (Original Event ID for EVTX)
  - `filepath` (File path for file-related events)
  - `macb` (MACB flag for MFT events)
  - `rule_class` (Classification label)
  - `severity` (1-5 score)
  - `description` (Human-readable summary)
  - `raw_data_ref` (Link to full parsed record)
- **Input:** Parsed records from all artifact types
- **Output:** Normalized event table
- **Priority:** Critical
- **Verification:** Records from different artifact types have consistent schema

**FR-16: Deterministic Forensic Classification Rules**
- **Description:** System shall apply deterministic forensic classification rules to assign categories:
  - `USER_ACTIVITY` (normal user operations)
  - `REMOTE_ACCESS` (RDP, SSH, remote desktop connections)
  - `PERSISTENCE` (autostart registry keys, scheduled tasks)
  - `STAGING` (file compression, bulk file copying)
  - `EXFIL_PREP` (network file transfers, external media access)
  - `ANTI_FORENSICS` (log clearing, file deletion, timestomping)
  - `NORMAL` (system maintenance, updates)
- **Input:** Normalized event
- **Output:** Event with assigned `rule_class`
- **Priority:** Critical
- **Verification:** EventID 4624 Type 10 correctly classified as REMOTE_ACCESS

**FR-17: Severity Scoring with Rationale**
- **Description:** System shall assign severity scores (1=low, 5=critical) and provide rationale text explaining classification.
- **Input:** Classified event
- **Output:** Event with `severity` score and `rationale` text
- **Priority:** High
- **Verification:** Event Log clearing (EventID 1102) receives severity 5 with appropriate rationale

---

### F) Timeline Visualization

**FR-18: Vertical Timeline Display**
- **Description:** System shall display normalized events in a vertical timeline view, sorted chronologically by timestamp, with color-coded classification labels.
- **Input:** Classified normalized events
- **Output:** Interactive timeline UI component
- **Priority:** Critical
- **Verification:** Events appear in correct chronological order with appropriate colors

**FR-19: Multi-Criteria Filtering**
- **Description:** System shall allow filtering by:
  - Event class (USER_ACTIVITY, REMOTE_ACCESS, STAGING, etc.)
  - File path (substring match)
  - Timestamp ranges (start date/time to end date/time)
  - Keywords (regex-based search across all fields)
- **Input:** Filter criteria
- **Output:** Filtered event list
- **Priority:** High
- **Verification:** Filter for "powershell" returns only PowerShell-related events

**FR-20: UTC and Local Time Toggle**
- **Description:** System shall support toggling between UTC and Local Time display modes. All timestamps stored internally as UTC.
- **Input:** User timezone preference
- **Output:** Timeline with timestamps in selected timezone
- **Priority:** Medium
- **Verification:** Toggle switch correctly converts UTC to EST and displays appropriately

---

### G) Reporting

**FR-21: HTML/PDF Report Generation**
- **Description:** System shall generate final investigation report in HTML and PDF formats containing:
  - Case summary
  - Image hash
  - Artifact hash table
  - Classification summary (event counts by class)
  - Timeline event table
  - Investigator notes
- **Input:** Classified events, case metadata, notes
- **Output:** HTML and PDF report files
- **Priority:** Critical
- **Verification:** Generated PDF contains all required sections and is readable

**FR-22: Report Integrity Hashing**
- **Description:** System shall compute SHA-256 hash of the final generated report and store it in chain-of-custody log.
- **Input:** Generated report file
- **Output:** Report hash value, CoC entry
- **Priority:** Critical
- **Verification:** Report hash in CoC log matches manually computed hash

**FR-23: Evidence Provenance Embedding**
- **Description:** System shall embed artifact provenance metadata (image hash, artifact hashes, extraction timestamps) and case hash references in the report.
- **Input:** CoC log, artifact metadata
- **Output:** Report with embedded provenance section
- **Priority:** High
- **Verification:** Report contains complete hash table and provenance chain

---

### H) Chain of Custody Logging

**FR-24: Append-Only CoC Log**
- **Description:** System shall maintain an append-only chain-of-custody log recording all operations with:
  - Timestamp (UTC)
  - Operation type (ImageIngested, ArtifactExtracted, ReportGenerated)
  - Hash value (SHA-256)
  - File path or identifier
  - Rationale/reason
- **Input:** Forensic operations
- **Output:** CoC log file (text or structured format)
- **Priority:** Critical
- **Verification:** Log cannot be modified retroactively (append-only enforcement)

**FR-25: CoC Log Export**
- **Description:** System shall support exporting the chain-of-custody log as a standalone text file for archival or legal review.
- **Input:** Export request
- **Output:** CoC log export file
- **Priority:** Medium
- **Verification:** Exported log is complete and human-readable

---

### I) Advanced Search & Filtering

**FR-26: Event ID Filtering**
- **Description:** System shall allow filtering by specific Windows Event IDs (e.g., 4624, 4625, 1102, 4688).
- **Input:** Event ID number(s)
- **Output:** Events matching specified Event IDs
- **Priority:** High
- **Verification:** Filter for EventID 4625 returns only failed logon attempts

**FR-27: Regex-Based Keyword Search**
- **Description:** System shall support regular expression-based keyword search across all normalized event fields.
- **Input:** Regex pattern
- **Output:** Events matching regex pattern
- **Priority:** Medium
- **Verification:** Regex pattern `powershell|cmd` returns events containing either term

**FR-28: File Extension Filtering**
- **Description:** System shall allow filtering by filename extension (e.g., .exe, .dll, .zip, .ps1).
- **Input:** File extension
- **Output:** Events related to files with specified extension
- **Priority:** Medium
- **Verification:** Filter for `.ps1` returns only PowerShell script-related events

---

### J) Notes & Evidence Annotation

**FR-29: Analyst Note Attachment**
- **Description:** System shall allow the analyst to attach notes to any timeline event row for case documentation.
- **Input:** Event ID, note text
- **Output:** Note associated with event, stored in case metadata
- **Priority:** Medium
- **Verification:** Note attached to event persists across application restarts

**FR-30: Note Persistence in Case Directory**
- **Description:** System shall store analyst notes inside the case directory as structured metadata (JSON/YAML).
- **Input:** Notes data
- **Output:** Notes file in case directory
- **Priority:** Medium
- **Verification:** Notes file is human-readable and contains all attached notes

---

### K) Case Export / Sharing

**FR-31: CSV Event Export**
- **Description:** System shall support exporting normalized events to CSV file for external analysis or archival.
- **Input:** Filtered or complete event set
- **Output:** CSV file with all normalized event fields
- **Priority:** Medium
- **Verification:** Exported CSV opens correctly in Excel/LibreOffice Calc

**FR-32: Case Directory Reopening**
- **Description:** System shall support re-opening previous case directories to resume analysis.
- **Input:** Case directory path
- **Output:** Restored session with previous events, notes, filters
- **Priority:** High
- **Verification:** Reopened case shows previously analyzed events without re-parsing

**FR-33: Case Configuration Persistence**
- **Description:** System shall store case configuration (timezone mode, applied filters, last view state) and restore it on reopen.
- **Input:** Case state
- **Output:** Configuration file in case directory
- **Priority:** Low
- **Verification:** Timezone toggle and filters persist across sessions

---

### L) UI Features

**FR-34: Free Layout Mode**
- **Description:** System shall provide a Free Layout Mode where all visualization panels (Timeline, Sankey, Heatmap, Graph, Details) can be repositioned by drag-and-drop.
- **Input:** User layout preference
- **Output:** Rearrangeable UI panels
- **Priority:** Low
- **Verification:** Panels can be dragged and docked in different positions

**FR-35: Dual-Format Report Export**
- **Description:** System shall export the final report in PDF format with embedded SHA-256 evidence metadata, and optionally generate an HTML version for internal review.
- **Input:** Report data
- **Output:** PDF and HTML report files
- **Priority:** High
- **Verification:** Both PDF and HTML reports contain identical information

---

## NON-FUNCTIONAL REQUIREMENTS

### 5.1 Performance Requirements

**NFR-01: Timeline Load Performance**
- **Description:** System shall load 500,000 normalized events into timeline view in ≤ 3 seconds.
- **Measurement:** Stopwatch timing from data load to UI render completion
- **Priority:** High
- **Rationale:** Analysts need responsive interaction during large case analysis

**NFR-02: Normalization & Classification Performance**
- **Description:** System shall normalize and classify 500,000 events in ≤ 10 seconds.
- **Measurement:** Elapsed time from parsed records to classified events
- **Priority:** High
- **Rationale:** Processing speed directly impacts case throughput

**NFR-03: Image Hashing Performance**
- **Description:** System shall compute SHA-256 hash of a 500 GB forensic image in ≤ 15 minutes on standard workstation hardware (SSD, quad-core CPU).
- **Measurement:** Time from hash start to completion
- **Priority:** Medium
- **Rationale:** Hashing is unavoidable but should not bottleneck workflow

---

### 5.2 Security & Forensic Integrity Requirements

**NFR-04: Read-Only Evidence Access**
- **Description:** All evidence access shall be read-only. No write operations shall be permitted on forensic images or extracted artifacts during analysis.
- **Verification:** Code review, write-attempt testing
- **Priority:** Critical
- **Rationale:** Forensic soundness requires evidence immutability

**NFR-05: SHA-256 Hashing Standard**
- **Description:** All hashes shall be computed using SHA-256 algorithm (NIST FIPS 180-4 compliant).
- **Verification:** Algorithm verification, test vector validation
- **Priority:** Critical
- **Rationale:** SHA-256 is industry standard for forensic integrity verification

**NFR-06: Append-Only Chain-of-Custody**
- **Description:** Chain-of-custody log shall be append-only and never overwritten or modified retroactively.
- **Verification:** File permission testing, log manipulation attempts
- **Priority:** Critical
- **Rationale:** CoC log must be tamper-evident for legal admissibility

**NFR-07: Cryptographic Integrity Verification**
- **Description:** System shall detect any evidence tampering via hash mismatch detection and alert the user immediately.
- **Verification:** Intentionally modify artifact file and verify alert
- **Priority:** Critical
- **Rationale:** Integrity violations must be detected before analysis proceeds

---

### 5.3 Usability Requirements

**NFR-08: UTC / Local Time Toggle**
- **Description:** System shall provide UTC / Local Time toggle with default display mode set to UTC.
- **Verification:** UI toggle testing, timestamp conversion validation
- **Priority:** Medium
- **Rationale:** UTC is forensic standard but local time aids human interpretation

**NFR-09: Dark Indigo Theme UI**
- **Description:** System shall use a Dark Indigo color theme to reduce eye strain during extended analysis sessions.
- **Verification:** Visual inspection, contrast ratio testing
- **Priority:** Low
- **Rationale:** Professional forensic tools often use dark themes for comfort

**NFR-10: Minimal Click Workflow**
- **Description:** Main workflow steps (Ingest → Timeline → Report) shall require ≤ 3 clicks each.
- **Verification:** User interaction flow testing
- **Priority:** Medium
- **Rationale:** Reduces cognitive load and speeds up common tasks

**NFR-11: Contextual Help and Tooltips**
- **Description:** System shall provide tooltips and contextual help for forensic terminology (e.g., "MACB timestamps", "Event ID 4624").
- **Verification:** UI review, tooltip coverage testing
- **Priority:** Low
- **Rationale:** Supports junior analysts and reduces training burden

---

### 5.4 Reliability & Fault Tolerance Requirements

**NFR-12: Graceful Parser Error Handling**
- **Description:** On parser error → skip artifact, keep pipeline running, log error to case log. System shall not crash due to single malformed artifact.
- **Verification:** Test with intentionally corrupted artifacts
- **Priority:** High
- **Rationale:** Real-world forensic images often contain corrupted artifacts

**NFR-13: CoC Log Crash Recovery**
- **Description:** On application crash → chain-of-custody log shall not lose last complete entry. Log writes shall be atomic.
- **Verification:** Kill process during operation and verify log integrity
- **Priority:** High
- **Rationale:** Legal evidence trail must survive unexpected failures

**NFR-14: Timezone Consistency**
- **Description:** Internal processing timestamps must also be logged in UTC to avoid timezone confusion during legal proceedings.
- **Verification:** Timestamp format validation in CoC log
- **Priority:** Medium
- **Rationale:** Timezone ambiguity can undermine evidence credibility

---

### 5.5 Maintainability Requirements

**NFR-15: Plug-in Parser Architecture**
- **Description:** All parser modules shall be plug-ins (modular design) to allow easy extension with new artifact types.
- **Verification:** Add new parser module and verify integration without core code changes
- **Priority:** High
- **Rationale:** Forensic artifact formats evolve; system must be extensible

**NFR-16: Editable Rulebook Configuration**
- **Description:** Forensic classification rulebook shall be stored as editable configuration file (YAML/JSON) for easy rule updates.
- **Verification:** Modify rule file and verify classification changes
- **Priority:** Medium
- **Rationale:** Organizations may need custom classification rules

**NFR-17: Code Documentation**
- **Description:** All modules shall have inline code documentation (docstrings) and external API documentation.
- **Verification:** Code review, documentation coverage testing
- **Priority:** Low
- **Rationale:** Facilitates future development and peer review

---

### 5.6 Portability Requirements

**NFR-18: Windows 10/11 Compatibility**
- **Description:** Application shall run offline on Windows 10 and Windows 11 (64-bit) workstations without internet connectivity.
- **Verification:** Installation and execution testing on Windows 10/11
- **Priority:** Critical
- **Rationale:** Primary target platform for government forensic labs

**NFR-19: Standalone Deployment**
- **Description:** System shall be deployable as standalone executable with bundled dependencies (PyInstaller/cx_Freeze).
- **Verification:** Build standalone executable and test on clean Windows installation
- **Priority:** High
- **Rationale:** Simplifies deployment in air-gapped environments

**NFR-20: No External Service Dependencies**
- **Description:** System shall operate without requiring external services, internet connectivity, or cloud APIs.
- **Verification:** Disconnect network and verify full functionality
- **Priority:** Critical
- **Rationale:** Air-gapped lab requirement for classified evidence

---

## DATA DICTIONARY

### Normalized Event Schema

The following table defines the unified schema used to represent all forensic events after normalization:

| Field Name | Data Type | Description / Purpose | Constraints |
|------------|-----------|----------------------|-------------|
| **event_id** | UUID / String | Unique internal ID assigned to every normalized event row | NOT NULL, PRIMARY KEY |
| **ts_utc** | Datetime (ISO 8601 UTC) | Primary timestamp for comparison + ordering in timeline | NOT NULL |
| **ts_local** | Datetime (Local TZ) | Local converted timestamp for UI readability (toggle display) | NOT NULL |
| **artifact_source** | Enum/String | Which artifact this row came from (EVTX / REG / PF / MFT / Browser) | NOT NULL, ENUM |
| **artifact_path** | String (file path) | Exact internal path inside image (provenance) | NOT NULL |
| **event_type** | String | Raw category inside that artifact (e.g., RegKeyModified, ProcessExecution) | NOT NULL |
| **user_account** | String / NULL | Username if available (extracted mainly from EVTX + Registry) | NULLABLE |
| **exe_name** | String / NULL | Executable name if event was execution (from Prefetch + EVTX) | NULLABLE |
| **event_id_native** | String / NULL | Native Event ID (EVTX Event ID number) when available | NULLABLE |
| **filepath** | String / NULL | File path if event is file-related (mostly from MFT) | NULLABLE |
| **macb** | String / NULL | MACB timestamp flag for file events (M/A/C/B as letters) | NULLABLE, ENUM(M,A,C,B) |
| **rule_class** | Enum | Forensic classification (USER_ACTIVITY / REMOTE_ACCESS / STAGING / EXFIL_PREP / ANTI_FORENSICS / NORMAL) | NOT NULL, ENUM |
| **severity** | Integer (1–5) | Forensic severity score (1=low → 5=critical) | NOT NULL, RANGE(1,5) |
| **description** | Text | Human readable summary line used in timeline view | NOT NULL |
| **raw_data_ref** | String / FileRef | Pointer/filename to full raw parsed record for drill-down | NULLABLE |

### MACB Timestamp Flags (MFT Metadata)

| Flag | Meaning | Description |
|------|---------|-------------|
| **M** | Modified | File content was modified |
| **A** | Accessed | File was accessed/read |
| **C** | Changed | File metadata (permissions, attributes) changed |
| **B** | Birth | File creation timestamp (birth time) |

### Classification Enumeration (rule_class)

| Classification | Code | Description | Typical Indicators |
|----------------|------|-------------|-------------------|
| **User Activity** | USER_ACTIVITY | Normal user operations | Explorer.exe, document access, GUI interactions |
| **Remote Access** | REMOTE_ACCESS | Remote desktop connections | EventID 4624 Type 10, RDP, VNC, SSH sessions |
| **Persistence** | PERSISTENCE | Autostart mechanisms | Registry Run keys, Startup folder, Scheduled Tasks |
| **Staging** | STAGING | File collection/compression | WinZip.exe, 7z.exe, bulk file copying to single location |
| **Exfil Preparation** | EXFIL_PREP | Data exfiltration preparation | curl.exe, network share access, external media writes |
| **Anti-Forensics** | ANTI_FORENSICS | Evidence destruction | EventID 1102 (log clearing), file deletion, timestomping |
| **Normal** | NORMAL | System maintenance | Windows Updates, antivirus scans, system processes |

### Severity Scoring Matrix

| Severity | Score | Description | Example Events |
|----------|-------|-------------|----------------|
| **Informational** | 1 | Normal system activity | User login (local console) |
| **Low** | 2 | Potentially suspicious | Multiple failed login attempts |
| **Medium** | 3 | Suspicious behavior | Remote desktop connection from unusual IP |
| **High** | 4 | Likely malicious | Mass file compression before network transfer |
| **Critical** | 5 | Confirmed malicious | Event log clearing, ransomware execution |

### Chain-of-Custody Log Schema

| Field Name | Data Type | Description | Constraints |
|------------|-----------|-------------|-------------|
| **coc_id** | Integer (autoincrement) | Unique identifier for CoC entry | PRIMARY KEY |
| **timestamp_utc** | Datetime (ISO 8601 UTC) | When operation occurred | NOT NULL |
| **event** | String | Operation type (ImageIngested, ArtifactExtracted, ReportGenerated) | NOT NULL |
| **hash_value** | String (64 hex chars) | SHA-256 hash of affected object | NOT NULL |
| **reason** | Text | Explanation of operation | NULLABLE |

---

## REQUIREMENTS TRACEABILITY MATRIX

| Requirement ID | Category | Priority | Verification Method | Status |
|----------------|----------|----------|---------------------|--------|
| FR-01 | Image Ingestion | Critical | Test with E01/RAW/DD samples | ✅ Specified |
| FR-02 | Image Ingestion | Critical | Hash verification against NIST samples | ✅ Specified |
| FR-03 | Image Ingestion | Critical | CoC log inspection | ✅ Specified |
| FR-04 | Image Ingestion | Critical | Write-attempt testing | ✅ Specified |
| FR-05 | Artifact Discovery | High | Test with known artifact paths | ✅ Specified |
| FR-06 | Artifact Discovery | High | Queue verification | ✅ Specified |
| FR-07 | Extraction | Critical | Byte-for-byte comparison | ✅ Specified |
| FR-08 | Extraction | Critical | Hash verification | ✅ Specified |
| FR-09 | Extraction | Critical | CoC log inspection | ✅ Specified |
| FR-10 | Parsing | Critical | Parse Security.evtx successfully | ✅ Specified |
| FR-11 | Parsing | Critical | Extract Registry Run keys | ✅ Specified |
| FR-12 | Parsing | High | Parse Prefetch run counts | ✅ Specified |
| FR-13 | Parsing | High | Extract MFT MACB timestamps | ✅ Specified |
| FR-14 | Parsing | Medium | Parse Chrome History database | ✅ Specified |
| FR-15 | Normalization | Critical | Schema consistency validation | ✅ Specified |
| FR-16 | Classification | Critical | EventID 4624 Type 10 classification | ✅ Specified |
| FR-17 | Classification | High | Severity score validation | ✅ Specified |
| FR-18 | Timeline | Critical | Visual timeline inspection | ✅ Specified |
| FR-19 | Timeline | High | Filter functionality testing | ✅ Specified |
| FR-20 | Timeline | Medium | Timezone toggle verification | ✅ Specified |
| FR-21 | Reporting | Critical | PDF generation and readability | ✅ Specified |
| FR-22 | Reporting | Critical | Report hash verification | ✅ Specified |
| FR-23 | Reporting | High | Provenance section inspection | ✅ Specified |
| FR-24 | CoC Logging | Critical | Append-only enforcement testing | ✅ Specified |
| FR-25 | CoC Logging | Medium | Export functionality testing | ✅ Specified |
| FR-26 | Search | High | Event ID filter testing | ✅ Specified |
| FR-27 | Search | Medium | Regex pattern matching | ✅ Specified |
| FR-28 | Search | Medium | File extension filtering | ✅ Specified |
| FR-29 | Annotations | Medium | Note attachment testing | ✅ Specified |
| FR-30 | Annotations | Medium | Note persistence verification | ✅ Specified |
| FR-31 | Case Management | Medium | CSV export testing | ✅ Specified |
| FR-32 | Case Management | High | Case reopening testing | ✅ Specified |
| FR-33 | Case Management | Low | Configuration persistence | ✅ Specified |
| FR-34 | UI Features | Low | Panel drag-and-drop testing | ✅ Specified |
| FR-35 | UI Features | High | Dual-format export verification | ✅ Specified |

---

**Document Version:** 1.0  
**Last Updated:** November 6, 2025  
**Requirements Status:** Complete (35 Functional Requirements, 20 Non-Functional Requirements)
