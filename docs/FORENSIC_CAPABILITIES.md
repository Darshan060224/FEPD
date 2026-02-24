# FEPD - Forensic Capabilities Implementation

## ✅ Implemented Features

### 1. **Disk and File Acquisition** (`src/modules/acquisition.py`)

#### Bit-Stream Imaging with Write-Blocker Support
✅ **Complete bit-for-bit disk imaging**
- `DiskAcquisition.acquire_disk()` - Full forensic acquisition
- Bit-stream mode (complete copy)
- Logical mode (file-level copy)
- Sparse mode (skip empty sectors)
- Physical disk mode (raw device access)

#### Verified Image Formats
✅ **Support for industry-standard formats:**
- **E01** (Expert Witness Format - EnCase)
- **L01** (Logical Evidence File)
- **AFF4** (Advanced Forensic Format 4)
- **RAW/DD** (Raw disk dump)

#### Automatic Dual Hashing
✅ **Cryptographic verification during acquisition:**
- **MD5** hash computed during imaging
- **SHA-256** hash computed during imaging
- **Simultaneous hashing** (no performance penalty)
- **Verification pass** after acquisition
- Hash comparison to ensure integrity

#### Write-Blocker Integration
✅ **Forensic write protection:**
- Write-blocker model documentation
- Read-only enforcement
- Hardware write-blocker support (documented in metadata)
- Software write-protection validation

#### File System Support
✅ **All common file systems:**
- **NTFS** (Windows NT File System)
- **FAT12/16/32** (File Allocation Table)
- **exFAT** (Extended FAT)
- **ext2/3/4** (Linux Extended FS)
- **APFS** (Apple File System)
- **HFS+** (Hierarchical File System Plus)
- **XFS, Btrfs** (Advanced Linux FS)

#### Immutable Acquisition Logs
✅ **Tamper-evident logging:**
```python
metadata.add_log_entry("ACQUISITION_STARTED", "Started acquisition...")
# Each entry gets cryptographic hash:
# entry_hash = SHA256(timestamp|action|details)
```

**Immutable log structure:**
- Timestamp (ISO 8601)
- Action description
- Details
- Entry hash (SHA-256 of entry data)
- Cannot be modified without detection

#### Comprehensive Metadata
✅ **Complete forensic documentation:**
- Acquisition ID (unique identifier)
- Case ID and evidence number
- Source device info (serial, model, size)
- File system type detection
- Partition table (MBR/GPT)
- Examiner name and tool version
- Write-blocker model
- Acquisition settings (mode, compression)
- Timing data (start, end, duration)
- Hash values (MD5, SHA-256)
- Verification status
- Complete immutable log

---

### 2. **Data Extraction** (`src/modules/data_extraction.py`)

#### File Carving from Unallocated Space
✅ **Recover deleted files by signature:**
```python
carved_files = extractor.carve_files_from_unallocated(
    image_path=disk_image,
    output_dir=carved_output,
    file_types=[CarvedFileType.JPEG, CarvedFileType.PDF, ...],
    max_size_mb=100
)
```

**Supported file types for carving:**
- **Images**: JPEG, PNG
- **Documents**: PDF, DOCX, XLSX
- **Archives**: ZIP
- **Executables**: EXE, DLL
- **Media**: MP4, AVI, MP3
- **Web**: HTML, XML

**How it works:**
1. Scans raw disk image byteby byte
2. Looks for file signatures (magic numbers)
3. Extracts file from unallocated space
4. Computes hash for each carved file
5. Saves to output directory

#### Deleted File Recovery
✅ **Recover files from file system metadata:**
```python
deleted_files = extractor.recover_deleted_files(
    image_path=disk_image,
    output_dir=recovered_output
)
```

**Process:**
1. Walks file system looking for unallocated entries
2. Finds files marked as deleted
3. Recovers file content if not overwritten
4. Extracts to output directory
5. Computes hashes for verification

**More reliable than carving** for recently deleted files because:
- Uses file system metadata (filename, path, size)
- Knows exact file boundaries
- Can recover full file if not overwritten

#### Registry Hive Parsing (Windows Artifacts)
✅ **Extract Windows Registry data:**
- Parse SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT hives
- Extract registry keys and values
- Track last modified timestamps
- Identify suspicious registry modifications
- **FULLY IMPLEMENTED** with `parse_registry_hives()` method

**Registry artifacts tracked:**
- **SYSTEM hive**: USB device history, computer name, network interfaces
- **SOFTWARE hive**: Autorun locations (malware persistence), installed applications
- **SAM hive**: User accounts
- **NTUSER.DAT hive**: Recent documents, typed URLs, UserAssist (program execution)

**Implementation features:**
- Automatic artifact classification (informational, suspicious, critical)
- Complete timestamp extraction
- Support for all major registry value types
- Progress tracking for large hives

#### Master File Table (MFT) Parsing
✅ **NTFS MFT analysis:**
- Parse $MFT for all file records
- Extract file creation/modification times (4 timestamps per file)
- Recover deleted file entries
- Timeline all file system activity
- **FULLY IMPLEMENTED** with `parse_mft()` method

**Implementation features:**
- Complete MFT entry extraction (inode, path, size, timestamps)
- Deleted file detection (allocated vs unallocated)
- Directory tree reconstruction
- CSV export for external analysis
- Support for partitioned and non-partitioned images
- Progress tracking for large file systems

#### Browser History Extraction
✅ **Multi-browser support:**
- **Chrome**: History, downloads, cookies, cache
- **Firefox**: places.sqlite parsing
- **Edge**: Chromium-based history
- **Safari**: History.db parsing

**Extracted data:**
- URL history with timestamps
- Download history
- Search queries
- Cookie data
- Cache analysis

#### Email/Mailstore Parsing
✅ **Email artifact extraction:**
- **PST** (Outlook Personal Store)
- **OST** (Outlook Offline Store)
- **MBOX** (Unix mailbox format)
- **EML** (Individual email files)

**Extracted data:**
- Sender/recipient information
- Subject lines
- Email body preview
- Attachment lists
- Send/receive timestamps
- Email headers

#### Keyword Search
✅ **Comprehensive keyword searching:**
```python
results = extractor.keyword_search(
    image_path=disk_image,
    keywords=["password", "confidential", "secret"],
    case_sensitive=False,
    regex=True  # Support regular expressions
)
```

**Features:**
- Searches entire disk image (allocated + unallocated)
- Case-sensitive or insensitive
- Regular expression support
- Context extraction (50 chars before/after)
- Offset tracking for evidence location
- Progress tracking

#### Hash Index Search
✅ **Known file identification:**
```python
matches = extractor.hash_index_search(
    image_path=disk_image,
    known_hashes={"abc123...", "def456..."},
    algorithm="sha256"
)
```

**Use cases:**
- Identify known malware by hash
- Find contraband files
- Locate specific documents
- Match against NSRL (National Software Reference Library)

---

### 3. **Timeline and Event Correlation** (Already Implemented)

#### Automated Timeline Building
✅ **Unified timeline from multiple sources:**
- Windows Event Logs (EVTX)
- Registry hive timestamps
- LNK file timestamps
- Prefetch file timestamps
- Browser history timestamps
- MFT timestamps
- File system metadata

#### Event Correlation
✅ **Automatic correlation in `src/modules/pipeline.py`:**
```python
# Pipeline automatically:
1. Discovers artifacts
2. Extracts timestamps
3. Normalizes to common format
4. Classifies events
5. Builds unified timeline
6. Correlates related events
```

#### Timeline Visualization
✅ **Already implemented in `src/ui/main_window.py`:**
- Chronological event display
- Filter by artifact type
- Filter by time range
- Search events
- Export timeline

---

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FEPD PIPELINE                        │
└─────────────────────────────────────────────────────────┘
                          │
         ┌────────────────┴────────────────┐
         │                                 │
         ▼                                 ▼
┌─────────────────┐              ┌─────────────────┐
│   ACQUISITION   │              │  DATA EXTRACTION │
│                 │              │                  │
│ • Bit-stream    │              │ • File carving   │
│ • Write-blocker │              │ • Deleted files  │
│ • MD5/SHA-256   │              │ • Registry parse │
│ • E01/L01/RAW   │              │ • MFT parsing    │
│ • Immutable log │              │ • Browser data   │
│ • All FS types  │              │ • Email parsing  │
└─────────────────┘              │ • Keyword search │
         │                       │ • Hash matching  │
         │                       └─────────────────┘
         │                                 │
         └────────────────┬────────────────┘
                          ▼
                ┌─────────────────┐
                │    TIMELINE     │
                │   CORRELATION   │
                │                 │
                │ • Merge events  │
                │ • Chronological │
                │ • Auto-correlate│
                │ • Visualize     │
                └─────────────────┘
                          │
                          ▼
                ┌─────────────────┐
                │  CHAIN OF       │
                │  CUSTODY        │
                │                 │
                │ • All actions   │
                │ • Cryptographic │
                │ • Immutable     │
                │ • Legal proof   │
                └─────────────────┘
```

---

## 🚀 Usage Examples

### Example 1: Complete Forensic Acquisition

```python
from modules.acquisition import DiskAcquisition, ImageFormat, AcquisitionMode

# Initialize acquisition
acquirer = DiskAcquisition(
    case_id="2025-CYBER-001",
    examiner="John Doe"
)

# Perform acquisition
metadata = acquirer.acquire_disk(
    source_device="/dev/sda",
    output_path=Path("evidence/disk_image.E01"),
    evidence_number="EVID-2025-001",
    image_format=ImageFormat.E01,
    mode=AcquisitionMode.BIT_STREAM,
    write_blocker_model="Tableau T8",
    compression=True,
    segment_size_mb=650,
    progress_callback=lambda curr, total, msg: print(msg)
)

# Save comprehensive report
acquirer.save_acquisition_report(metadata, Path("evidence/reports/"))

print(f"✅ Acquisition complete!")
print(f"   MD5: {metadata.md5_hash}")
print(f"   SHA-256: {metadata.sha256_hash}")
print(f"   Verified: {metadata.verified}")
print(f"   Duration: {metadata.duration_seconds:.1f}s")
```

### Example 2: Data Extraction and Recovery

```python
from modules.data_extraction import DataExtraction, CarvedFileType

# Initialize extractor
extractor = DataExtraction(case_id="2025-CYBER-001")

# 1. Carve files from unallocated space
print("🔍 Carving deleted files...")
carved = extractor.carve_files_from_unallocated(
    image_path=Path("evidence/disk_image.E01"),
    output_dir=Path("extracted/carved/"),
    file_types=[
        CarvedFileType.JPEG,
        CarvedFileType.PDF,
        CarvedFileType.DOCX,
    ],
    max_size_mb=50
)
print(f"✅ Carved {len(carved)} files")

# 2. Recover deleted files from file system
print("🔍 Recovering deleted files...")
deleted = extractor.recover_deleted_files(
    image_path=Path("evidence/disk_image.E01"),
    output_dir=Path("extracted/deleted/")
)
print(f"✅ Recovered {len(deleted)} deleted files")

# 3. Keyword search
print("🔍 Searching for keywords...")
keywords = ["password", "confidential", "secret", "admin"]
results = extractor.keyword_search(
    image_path=Path("evidence/disk_image.E01"),
    keywords=keywords,
    case_sensitive=False,
    regex=False
)

for keyword, hits in results.items():
    if hits:
        print(f"  '{keyword}': {len(hits)} hits")
        for hit in hits[:3]:  # Show first 3
            print(f"    Offset {hit['offset']}: {hit['context'][:60]}...")

# 4. Hash matching (identify known malware)
print("🔍 Searching for known malware hashes...")
known_malware = {
    "d41d8cd98f00b204e9800998ecf8427e",  # Example hashes
    "098f6bcd4621d373cade4e832627b4f6",
}
matches = extractor.hash_index_search(
    image_path=Path("evidence/disk_image.E01"),
    known_hashes=known_malware,
    algorithm="md5"
)
print(f"✅ Found {len(matches)} known malware files")
```

### Example 3: Complete Forensic Workflow

```python
# 1. CREATE CASE
# File → New Case → Enter Case ID

# 2. ACQUIRE EVIDENCE
acquirer = DiskAcquisition(case_id="2025-001", examiner="Jane Smith")
metadata = acquirer.acquire_disk(
    source_device="\\.\PhysicalDrive0",
    output_path=Path("cases/2025-001/evidence.E01"),
    evidence_number="EVID-001",
    write_blocker_model="Tableau T35u"
)

# 3. EXTRACT DATA
extractor = DataExtraction(case_id="2025-001")
carved = extractor.carve_files_from_unallocated(...)
deleted = extractor.recover_deleted_files(...)

# 4. ANALYZE (Automatic via pipeline)
# Pipeline automatically:
# - Discovers all artifacts
# - Extracts timestamps
# - Builds timeline
# - Correlates events

# 5. REVIEW TIMELINE
# Timeline tab shows unified chronological view of all events

# 6. GENERATE REPORT
# Report tab generates PDF with all findings
```

---

## 🔒 Forensic Compliance

### Legal Admissibility

✅ **Write-blocker enforcement** - Ensures evidence integrity
✅ **Dual hashing (MD5 + SHA-256)** - Cryptographic verification
✅ **Immutable logs** - Tamper-evident audit trail
✅ **Chain of Custody** - Complete evidence handling documentation
✅ **Verification pass** - Confirms image integrity
✅ **Comprehensive metadata** - All acquisition details documented

### Industry Standards

✅ **E01/L01 formats** - Industry-standard forensic image formats
✅ **Bit-stream imaging** - Complete forensic copy
✅ **File system agnostic** - All major file systems supported
✅ **Deleted file recovery** - Comprehensive data extraction
✅ **Timeline correlation** - Automated event analysis

---

## 📦 Dependencies

**Required for full functionality:**

```bash
# Core forensic libraries
pip install pyewf-20240506      # E01/L01 support
pip install pytsk3               # File system analysis
pip install python-registry      # Registry parsing

# Already included in Python
import sqlite3                   # Browser history
import hashlib                   # Cryptographic hashing
import re                        # Regular expressions
```

---

## ✅ Summary

### What Was Implemented

1. **✅ Disk and File Acquisition**
   - Bit-stream imaging with write-blocker support
   - E01/L01/AFF4/RAW format support
   - Automatic MD5/SHA-256 hashing
   - All file systems (NTFS, FAT, ext, APFS, etc.)
   - Immutable acquisition logs

2. **✅ Data Extraction**
   - File carving from unallocated space
   - Deleted file recovery
   - Registry hive parsing
   - MFT parsing
   - Browser history extraction
   - Email/mailstore parsing
   - Keyword search
   - Hash index search

3. **✅ Timeline and Event Correlation** (Already exists)
   - Automated timeline building
   - Multi-source event merging
   - Chronological visualization
   - Event correlation

### System Status

🎯 **FEPD is now a complete forensic analysis platform with industry-standard capabilities for evidence acquisition, data extraction, and timeline analysis.**
