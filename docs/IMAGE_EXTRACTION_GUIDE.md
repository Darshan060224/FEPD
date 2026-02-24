# Disk Image Artifact Extraction - Complete Guide

## Overview

FEPD now supports forensically-sound extraction of artifacts from E01 (Expert Witness) and raw DD disk images. This feature enables automated, read-only extraction of Windows artifacts while maintaining chain of custody through cryptographic hashing and detailed logging.

---

## 🎯 Key Features

### Forensic Safety
- ✅ **Read-only access**: No modifications to evidence
- ✅ **Hash verification**: MD5/SHA256 for image and artifacts
- ✅ **Chain of custody**: Detailed extraction logs
- ✅ **MACB timestamps**: Preserves file system metadata
- ✅ **Court-admissible**: Follows forensic best practices

### Supported Formats
- ✅ **E01 (Expert Witness)**: EnCase format with segmentation support
- ✅ **Raw DD images**: Bitstream copies (.dd, .raw, .img)
- ✅ **NTFS**: Full support for Windows NTFS
- ✅ **FAT12/16/32**: DOS/Windows FAT filesystems
- ✅ **EXT2/3/4**: Linux filesystems (basic support)

### Artifact Categories
- ✅ **Event Logs**: Application, Security, System, PowerShell
- ✅ **Registry Hives**: SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT
- ✅ **User Registry**: NTUSER.DAT, UsrClass.dat
- ✅ **Browser History**: Chrome, Edge, Firefox
- ✅ **Prefetch Files**: Application execution history
- ✅ **Master File Table**: Complete NTFS file metadata

---

## 📦 Installation

### Required Libraries

```bash
# Install via pip
pip install pytsk3  # The Sleuth Kit
pip install pyewf   # E01 support (requires libewf)
```

### Windows Installation

**pytsk3**:
1. Download wheel from: https://github.com/py4n6/pytsk/releases
2. Install: `pip install pytsk3-<version>-cp3xx-win_amd64.whl`

**pyewf**:
1. Download libewf DLLs from: https://github.com/libyal/libewf/releases
2. Extract to `Python\Lib\site-packages\` or add to PATH
3. Install: `pip install pyewf`

### Linux Installation

```bash
# Ubuntu/Debian
sudo apt-get install libtsk-dev libewf-dev
pip install pytsk3 pyewf

# Fedora/RHEL
sudo dnf install libtsk-devel libewf-devel
pip install pytsk3 pyewf
```

### Verify Installation

```python
import pytsk3
import pyewf

print("pytsk3 version:", pytsk3.TSK_VERSION_STR)
print("pyewf available:", pyewf is not None)
```

---

## 🚀 Quick Start

### Automated Extraction (Recommended)

```python
from src.modules.artifact_extractor import extract_artifacts_from_image

# Extract all artifacts automatically
results = extract_artifacts_from_image(
    image_path="evidence/case123.E01",
    output_dir="extracted_artifacts/case123",
    verify_hash=True
)

print(f"Success: {results['success']}")
print(f"Extracted {len(results['artifacts'])} artifact groups")
print(f"Image MD5: {results['image_metadata']['hash']}")
```

**Output Directory Structure**:
```
extracted_artifacts/case123/
├── extraction_log.json          # Detailed metadata
├── extraction_log.csv            # Quick reference
├── partition_0/
│   ├── EventLogs/
│   │   ├── Application.evtx
│   │   ├── Security.evtx
│   │   └── System.evtx
│   ├── Registry/
│   │   ├── SYSTEM
│   │   ├── SOFTWARE
│   │   ├── SAM
│   │   └── SECURITY
│   ├── Prefetch/
│   │   ├── APP1.pf
│   │   └── APP2.pf
│   ├── MFT/
│   │   └── $MFT
│   └── Users/
│       ├── JohnDoe/
│       │   ├── NTUSER.DAT
│       │   ├── UsrClass.dat
│       │   └── BrowserHistory/
│       │       ├── Chrome_History
│       │       ├── Edge_History
│       │       └── Firefox_default_places.sqlite
│       └── JaneSmith/
│           └── ...
```

### Manual Extraction (Fine-Grained Control)

```python
from pathlib import Path
from src.modules.image_handler import DiskImageHandler

# Open disk image
with DiskImageHandler("case.E01", verify_hash=True) as handler:
    # Get image metadata
    print(f"Type: {handler.image_type}")      # 'ewf' or 'raw'
    print(f"Size: {handler.image_size:,} bytes")
    print(f"MD5: {handler.image_hash}")
    
    # Enumerate partitions
    partitions = handler.enumerate_partitions()
    
    # Open NTFS filesystem
    fs_info = handler.open_filesystem(partition_index=0)
    
    # Extract specific file
    metadata = handler.extract_file(
        fs_info=fs_info,
        path="/Windows/System32/config/SYSTEM",
        output_path=Path("output/SYSTEM"),
        calculate_hash=True
    )
    
    print(f"Extracted: {metadata['source_path']}")
    print(f"MD5: {metadata['md5']}")
    print(f"SHA256: {metadata['sha256']}")
```

---

## 🔍 Detailed Usage

### Opening Disk Images

#### E01 Images (Expert Witness / EnCase)

```python
from src.modules.image_handler import DiskImageHandler

# Single E01 file
handler = DiskImageHandler("case.E01", verify_hash=True)
handler.open_image()

# Segmented E01 (E01, E02, E03...)
# Automatically detects all segments
handler = DiskImageHandler("case.E01", verify_hash=True)
handler.open_image()  # Opens all segments

# Image metadata
print(f"Size: {handler.image_size:,} bytes")
print(f"Type: {handler.image_type}")  # 'ewf'
print(f"Stored MD5: {handler.image_hash}")  # From E01 metadata
```

**E01 Features**:
- Supports compression (automatic)
- Hash stored in metadata (verified on open)
- Segmentation support (E01, E02, E03...)
- CRC verification

#### Raw DD Images

```python
# Raw bitstream copy
handler = DiskImageHandler("case.dd", verify_hash=True)
handler.open_image()

# Hash calculated on open (if verify_hash=True)
print(f"Calculated MD5: {handler.image_hash}")
```

**Raw Image Features**:
- Simple byte stream
- No metadata
- Hash calculated on load
- Faster than E01 (no decompression)

### Partition Enumeration

```python
# List all partitions
partitions = handler.enumerate_partitions()

for i, partition in enumerate(partitions):
    print(f"Partition {i}:")
    print(f"  Description: {partition['description']}")
    print(f"  Type: {partition['type']}")  # ntfs, fat32, etc.
    print(f"  Start: sector {partition['start']}")
    print(f"  Size: {partition['length'] * 512:,} bytes")
```

**Example Output**:
```
Partition 0:
  Description: NTFS / exFAT (0x07)
  Type: ntfs
  Start: sector 2048
  Size: 536,870,912,000 bytes
```

### Filesystem Operations

```python
# Open filesystem on partition
fs_info = handler.open_filesystem(partition_index=0)

# List directory contents
entries = handler.list_directory(fs_info, "/Windows/System32")

for entry in entries:
    print(f"{entry['type']}: {entry['name']} ({entry['size']:,} bytes)")
```

**Example Output**:
```
dir: winevt (0 bytes)
file: cmd.exe (289,792 bytes)
file: notepad.exe (225,280 bytes)
```

### File Extraction

```python
# Extract single file
metadata = handler.extract_file(
    fs_info=fs_info,
    path="/Windows/System32/config/SYSTEM",
    output_path=Path("output/SYSTEM"),
    calculate_hash=True
)

# Metadata includes:
print(metadata)
{
    'source_path': '/Windows/System32/config/SYSTEM',
    'output_path': 'output/SYSTEM',
    'size': 12582912,
    'md5': 'a1b2c3d4e5f6...',
    'sha256': 'f6e5d4c3b2a1...',
    'extracted_at': '2025-11-07T14:30:45',
    'mtime': 1699372800,  # Modified time
    'atime': 1699372800,  # Access time
    'ctime': 1699372800,  # Change time
    'crtime': 1699372800  # Creation time
}
```

### File Search

```python
# Find files by name (recursive)
found_paths = handler.find_file(
    fs_info=fs_info,
    filename="NTUSER.DAT",
    start_path="/Users"
)

for path in found_paths:
    print(f"Found: {path}")
```

**Example Output**:
```
Found: /Users/JohnDoe/NTUSER.DAT
Found: /Users/JaneSmith/NTUSER.DAT
Found: /Users/Admin/NTUSER.DAT
```

---

## 📂 Artifact Extraction

### Event Logs (EVTX)

```python
# Default locations
event_log_paths = [
    '/Windows/System32/winevt/Logs/Application.evtx',
    '/Windows/System32/winevt/Logs/Security.evtx',
    '/Windows/System32/winevt/Logs/System.evtx',
    '/Windows/System32/winevt/Logs/Setup.evtx',
    '/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx',
]

for path in event_log_paths:
    output_file = Path("output/EventLogs") / Path(path).name
    handler.extract_file(fs_info, path, output_file)
```

### Registry Hives

```python
# System-wide hives
registry_paths = [
    '/Windows/System32/config/SYSTEM',
    '/Windows/System32/config/SOFTWARE',
    '/Windows/System32/config/SAM',
    '/Windows/System32/config/SECURITY',
    '/Windows/System32/config/DEFAULT',
]

for path in registry_paths:
    # Extract hive
    handler.extract_file(
        fs_info, path, 
        Path("output/Registry") / Path(path).name
    )
    
    # Extract transaction logs
    handler.extract_file(
        fs_info, f"{path}.LOG1",
        Path("output/Registry") / f"{Path(path).name}.LOG1"
    )
```

**User Registry**:
```python
# Find all user directories
entries = handler.list_directory(fs_info, "/Users")

for entry in entries:
    if entry['type'] == 'dir' and entry['name'] not in ['Public', 'Default']:
        # Extract NTUSER.DAT
        ntuser_path = f"/Users/{entry['name']}/NTUSER.DAT"
        output_file = Path(f"output/Users/{entry['name']}/NTUSER.DAT")
        handler.extract_file(fs_info, ntuser_path, output_file)
        
        # Extract UsrClass.dat
        usrclass_path = f"/Users/{entry['name']}/AppData/Local/Microsoft/Windows/UsrClass.dat"
        output_file = Path(f"output/Users/{entry['name']}/UsrClass.dat")
        handler.extract_file(fs_info, usrclass_path, output_file)
```

### Browser History

**Chrome**:
```python
chrome_history = "/Users/JohnDoe/AppData/Local/Google/Chrome/User Data/Default/History"
handler.extract_file(fs_info, chrome_history, Path("output/Chrome_History"))

# Also extract Cookies
chrome_cookies = "/Users/JohnDoe/AppData/Local/Google/Chrome/User Data/Default/Cookies"
handler.extract_file(fs_info, chrome_cookies, Path("output/Chrome_Cookies"))
```

**Edge**:
```python
edge_history = "/Users/JohnDoe/AppData/Local/Microsoft/Edge/User Data/Default/History"
handler.extract_file(fs_info, edge_history, Path("output/Edge_History"))
```

**Firefox**:
```python
# Find Firefox profiles
firefox_profiles = handler.list_directory(
    fs_info,
    "/Users/JohnDoe/AppData/Roaming/Mozilla/Firefox/Profiles"
)

for profile in firefox_profiles:
    if profile['type'] == 'dir':
        places_path = f"/Users/JohnDoe/AppData/Roaming/Mozilla/Firefox/Profiles/{profile['name']}/places.sqlite"
        output_file = Path(f"output/Firefox_{profile['name']}_places.sqlite")
        handler.extract_file(fs_info, places_path, output_file)
```

### Prefetch Files

```python
# List all prefetch files
prefetch_entries = handler.list_directory(fs_info, "/Windows/Prefetch")

for entry in prefetch_entries:
    if entry['name'].endswith('.pf'):
        path = f"/Windows/Prefetch/{entry['name']}"
        output_file = Path("output/Prefetch") / entry['name']
        handler.extract_file(fs_info, path, output_file)
```

### Master File Table ($MFT)

```python
# Extract complete MFT
handler.extract_file(
    fs_info,
    path="/$MFT",
    output_path=Path("output/$MFT"),
    calculate_hash=True
)
```

---

## 🔐 Forensic Best Practices

### 1. Read-Only Access

**Always** use read-only mode:
```python
# DiskImageHandler is read-only by design
handler = DiskImageHandler("case.E01", verify_hash=True)
# No write operations possible - evidence is safe
```

### 2. Hash Verification

**Always** verify and calculate hashes:
```python
# Verify image hash
handler = DiskImageHandler("case.E01", verify_hash=True)
handler.open_image()
print(f"Image MD5: {handler.image_hash}")

# Calculate artifact hashes
metadata = handler.extract_file(
    fs_info, path, output_file,
    calculate_hash=True  # MD5 and SHA256
)
print(f"Artifact MD5: {metadata['md5']}")
print(f"Artifact SHA256: {metadata['sha256']}")
```

### 3. Chain of Custody

**Always** maintain extraction logs:
```python
# Automatic logging with ArtifactExtractor
results = extract_artifacts_from_image("case.E01", "output")

# Logs saved to:
# - output/extraction_log.json (detailed)
# - output/extraction_log.csv (spreadsheet)
```

**Log Contents**:
- Source path in image
- Output path on filesystem
- File size
- MD5 hash
- SHA256 hash
- Extraction timestamp
- MACB timestamps (Modified, Accessed, Changed, Birth)

### 4. Documentation

**Always** document your process:
```python
log_entry = {
    'case_number': 'CASE-2025-001',
    'examiner': 'John Doe',
    'timestamp': '2025-11-07T14:30:45',
    'tool': 'FEPD v1.0',
    'action': 'Extract SYSTEM hive',
    'source_image': 'case.E01',
    'source_image_md5': 'abc123...',
    'extracted_file': 'SYSTEM',
    'extracted_file_md5': 'def456...',
}
```

### 5. Reproducibility

**Always** use standard tools:
- pytsk3 (The Sleuth Kit) - Widely accepted
- pyewf (libewf) - EnCase format standard
- hashlib (Python stdlib) - Standard hashing

Anyone can reproduce your results using the same tools.

---

## 🛠️ Integration with FEPD

### With Existing Parsers

```python
# 1. Extract artifacts
results = extract_artifacts_from_image("case.E01", "output")

# 2. Parse with FEPD parsers
from src.modules.data_extraction import parse_registry_hives, parse_mft

# Parse extracted registry
registry_results = parse_registry_hives(
    image_path="output/partition_0/Registry/SYSTEM",
    output_dir=Path("parsed_results")
)

# Parse extracted MFT
mft_results = parse_mft(
    image_path="output/partition_0/MFT/$MFT",
    output_dir=Path("parsed_results")
)
```

### With UI/Pipeline

```python
# Integration point in FEPDPipeline
from src.modules.artifact_extractor import ArtifactExtractor

def ingest_disk_image(image_path, case_workspace):
    # 1. Extract artifacts
    extractor = ArtifactExtractor(
        image_path=image_path,
        output_dir=case_workspace / "extracted_artifacts",
        verify_hash=True
    )
    
    results = extractor.extract_all_artifacts()
    
    # 2. Parse extracted artifacts
    # (Use existing FEPD parsers)
    
    # 3. Load into database
    # (Use existing FEPD data loading)
    
    return results
```

---

## ⚡ Performance Optimization

### Selective Extraction

```python
# Extract only needed artifacts (faster)
handler = DiskImageHandler("case.E01", verify_hash=True)
handler.open_image()
fs_info = handler.open_filesystem(0)

# Only extract Security event log
handler.extract_file(
    fs_info,
    "/Windows/System32/winevt/Logs/Security.evtx",
    Path("output/Security.evtx")
)

handler.close()
```

### Chunked Reading

```python
# DiskImageHandler automatically uses chunked reading
# Default chunk size: 1 MB
# No action needed - automatic optimization
```

### Parallel Processing

```python
from multiprocessing import Pool

def extract_from_partition(partition_index):
    handler = DiskImageHandler("case.E01", verify_hash=True)
    handler.open_image()
    fs_info = handler.open_filesystem(partition_index)
    
    # Extract artifacts from this partition
    # ...
    
    handler.close()

# Process all partitions in parallel
partitions = [0, 1, 2]  # Partition indices
with Pool(processes=4) as pool:
    pool.map(extract_from_partition, partitions)
```

---

## 🐛 Troubleshooting

### Issue: "pytsk3 not available"

**Solution**:
```bash
# Install pytsk3
pip install pytsk3

# Windows: Download wheel from
# https://github.com/py4n6/pytsk/releases
pip install pytsk3-<version>-cp3xx-win_amd64.whl
```

### Issue: "pyewf not available"

**Solution**:
```bash
# Install libewf first
# Download from: https://github.com/libyal/libewf/releases

# Windows: Place DLLs in Python\Lib\site-packages\
# Linux: sudo apt-get install libewf-dev

pip install pyewf
```

### Issue: "Failed to open image"

**Possible Causes**:
1. File doesn't exist
2. Wrong format (not E01 or DD)
3. Corrupted image
4. Missing segments (E02, E03...)

**Solution**:
```python
# Check file exists
from pathlib import Path
if not Path("case.E01").exists():
    print("File not found!")

# Try raw format
handler = DiskImageHandler("case.dd", verify_hash=True)
```

### Issue: "No partitions found"

**Possible Causes**:
1. Raw filesystem (no partition table)
2. Unsupported partition scheme

**Solution**:
```python
# Try accessing partition 0 directly
fs_info = handler.open_filesystem(0)
```

### Issue: "Hash mismatch"

**Possible Causes**:
1. Image corrupted
2. Image modified
3. Transmission error

**Solution**:
```
DO NOT PROCEED!
Evidence integrity is compromised.
Re-acquire image from source.
```

### Issue: "Permission denied"

**Solution**:
```bash
# Windows: Run as Administrator
# Linux: Use sudo
sudo python extract_artifacts.py case.E01 output
```

### Issue: "Out of memory"

**Solution**:
```python
# Already optimized - uses chunked reading
# If still having issues:
# 1. Extract fewer artifacts at once
# 2. Increase system RAM
# 3. Use 64-bit Python
```

---

## 📊 Extraction Log Format

### JSON Format (extraction_log.json)

```json
{
  "extraction_summary": {
    "image_path": "case.E01",
    "output_dir": "output",
    "start_time": "2025-11-07T14:00:00",
    "end_time": "2025-11-07T14:15:32",
    "success": true,
    "image_metadata": {
      "type": "ewf",
      "size": 536870912000,
      "hash": "a1b2c3d4e5f6..."
    },
    "artifacts": {
      "event_logs": {"count": 6},
      "registry_hives": {"count": 5},
      "user_JohnDoe_ntuser": {"md5": "abc..."}
    }
  },
  "extracted_artifacts": [
    {
      "source_path": "/Windows/System32/config/SYSTEM",
      "output_path": "output/SYSTEM",
      "size": 12582912,
      "md5": "a1b2c3d4e5f6...",
      "sha256": "f6e5d4c3b2a1...",
      "extracted_at": "2025-11-07T14:05:23",
      "mtime": 1699372800,
      "atime": 1699372800,
      "ctime": 1699372800,
      "crtime": 1699372800
    }
  ],
  "chain_of_custody": {
    "image_hash": "a1b2c3d4e5f6...",
    "extraction_time": "2025-11-07T14:00:00",
    "tool": "FEPD Artifact Extractor",
    "verify_hash": true
  }
}
```

### CSV Format (extraction_log.csv)

```csv
Source Path,Output Path,Size,MD5,SHA256,Extracted At
"/Windows/System32/config/SYSTEM","output/SYSTEM",12582912,"a1b2c3d4...","f6e5d4c3...","2025-11-07T14:05:23"
```

---

## 📚 Additional Resources

### Official Documentation
- **The Sleuth Kit**: https://www.sleuthkit.org/
- **libewf (EnCase)**: https://github.com/libyal/libewf
- **pytsk3**: https://github.com/py4n6/pytsk
- **NIST Digital Forensics**: https://www.nist.gov/forensics

### Forensic Standards
- **SWGDE Best Practices**: https://www.swgde.org/
- **ISO 27037**: Digital evidence identification
- **ACPO Guidelines**: UK computer forensics principles

### Related FEPD Documentation
- `REGISTRY_IMPLEMENTATION.md` - Registry parsing
- `MFT_IMPLEMENTATION.md` - MFT analysis
- `TESTING_GUIDE.md` - Testing procedures
- `UI_IMPLEMENTATION_SUMMARY.md` - GUI features

---

## ✅ Summary

FEPD's disk image extraction feature provides:

- ✅ Forensically-sound artifact extraction
- ✅ Support for E01 and raw images
- ✅ Automated hash verification
- ✅ Comprehensive chain of custody
- ✅ Court-admissible documentation
- ✅ Integration with existing parsers
- ✅ Professional workflow automation

All operations maintain evidence integrity through read-only access, cryptographic hashing, and detailed logging suitable for legal proceedings.
