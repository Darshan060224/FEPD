# FEPD Quick Reference - Registry & MFT Parsing

## Quick Import

```python
from pathlib import Path
from modules.data_extraction import DataExtraction, CarvedFileType
```

---

## 1. Registry Hive Parsing - Quick Start

### Basic Usage

```python
# Initialize
extractor = DataExtraction(case_id="CASE-001")

# Define hive paths
hives = {
    "SYSTEM": Path("evidence/Windows/System32/config/SYSTEM"),
    "SOFTWARE": Path("evidence/Windows/System32/config/SOFTWARE"),
    "NTUSER.DAT": Path("evidence/Users/Username/NTUSER.DAT"),
}

# Parse
artifacts = extractor.parse_registry_hives(hives)
print(f"Found {len(artifacts)} artifacts")
```

### Filter High-Priority Artifacts

```python
# Find autorun entries (malware persistence)
autoruns = [a for a in artifacts if 'Run' in a.key_path]

# Find suspicious artifacts
suspicious = [a for a in artifacts if a.significance == 'suspicious']

# Find critical artifacts
critical = [a for a in artifacts if a.significance == 'critical']

# Print summary
for artifact in suspicious:
    print(f"{artifact.hive} | {artifact.key_path}")
    print(f"  {artifact.value_name} = {artifact.value_data}")
```

### Common Registry Locations

```python
# Hive extraction from disk image (conceptual)
registry_locations = {
    "SYSTEM":     "C:/Windows/System32/config/SYSTEM",
    "SOFTWARE":   "C:/Windows/System32/config/SOFTWARE",
    "SAM":        "C:/Windows/System32/config/SAM",
    "SECURITY":   "C:/Windows/System32/config/SECURITY",
    "NTUSER.DAT": "C:/Users/{USERNAME}/NTUSER.DAT",
}
```

---

## 2. MFT Parsing - Quick Start

### Basic Usage

```python
# Initialize
extractor = DataExtraction(case_id="CASE-001")

# Parse MFT
entries = extractor.parse_mft(
    image_path=Path("evidence/disk.E01"),
    output_csv=Path("analysis/mft.csv")  # Optional CSV export
)

print(f"Parsed {len(entries)} MFT entries")
```

### Find Deleted Files

```python
# Filter deleted files
deleted = [e for e in entries if not e['allocated']]
print(f"Found {len(deleted)} deleted files")

# Show deleted files
for entry in deleted[:10]:
    print(f"✗ {entry['file_path']}")
    print(f"  Size: {entry['size']:,} bytes")
    print(f"  Modified: {entry['modified']}")
```

### Timeline Analysis

```python
# Get recently modified files
recent = sorted(
    [e for e in entries if e['modified']],
    key=lambda x: x['modified'],
    reverse=True
)[:20]

print("Recently Modified Files:")
for entry in recent:
    status = "✓" if entry['allocated'] else "✗ DELETED"
    print(f"{status} {entry['file_path']}")
    print(f"  {entry['modified']}")
```

### Find Large Files

```python
# Find files over 100MB
large = [e for e in entries if e['size'] > 100_000_000]
large.sort(key=lambda x: x['size'], reverse=True)

print("Large Files (>100MB):")
for entry in large[:10]:
    print(f"{entry['file_path']}: {entry['size']:,} bytes")
```

### Search by Extension

```python
# Find all executables
exes = [e for e in entries if e['file_name'].endswith('.exe')]

# Find all documents
docs = [e for e in entries if e['file_name'].endswith(('.docx', '.pdf', '.xlsx'))]

# Find suspicious temp executables
suspicious = [
    e for e in entries 
    if e['file_name'].endswith('.exe') and 'Temp' in e['file_path']
]

print(f"Suspicious executables: {len(suspicious)}")
```

---

## 3. Combined Workflow

### Complete Investigation

```python
from modules.data_extraction import DataExtraction
from pathlib import Path

# Initialize
extractor = DataExtraction(case_id="2025-CYBER-001")

# ============================================================================
# STEP 1: Parse MFT (File System Timeline)
# ============================================================================
print("Parsing MFT...")
mft_entries = extractor.parse_mft(
    image_path=Path("evidence/disk.E01"),
    output_csv=Path("analysis/mft_timeline.csv")
)
print(f"✅ {len(mft_entries)} MFT entries")

# Find suspicious executables in temp folders
suspicious_files = [
    e for e in mft_entries 
    if e['file_name'].endswith('.exe') and 'Temp' in e['file_path']
]
print(f"🔍 {len(suspicious_files)} suspicious executables")

# ============================================================================
# STEP 2: Parse Registry (User Activity)
# ============================================================================
print("\nParsing registry...")
registry_artifacts = extractor.parse_registry_hives({
    "SYSTEM": Path("evidence/hives/SYSTEM"),
    "SOFTWARE": Path("evidence/hives/SOFTWARE"),
    "NTUSER.DAT": Path("evidence/hives/NTUSER.DAT"),
})
print(f"✅ {len(registry_artifacts)} registry artifacts")

# Find autorun entries (malware persistence)
autoruns = [a for a in registry_artifacts if 'Run' in a.key_path]
print(f"🚨 {len(autoruns)} autorun entries")

# ============================================================================
# STEP 3: Recover Deleted Files
# ============================================================================
print("\nRecovering deleted files...")
deleted_files = extractor.recover_deleted_files(
    image_path=Path("evidence/disk.E01"),
    output_dir=Path("evidence/recovered/")
)
print(f"✅ {len(deleted_files)} deleted files recovered")

# ============================================================================
# STEP 4: File Carving
# ============================================================================
print("\nCarving files from unallocated space...")
carved_files = extractor.carve_files_from_unallocated(
    image_path=Path("evidence/disk.E01"),
    output_dir=Path("evidence/carved/"),
    file_types=[CarvedFileType.JPEG, CarvedFileType.PDF, CarvedFileType.DOCX]
)
print(f"✅ {len(carved_files)} files carved")

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "="*70)
print("INVESTIGATION SUMMARY")
print("="*70)
print(f"MFT entries:           {len(mft_entries):,}")
print(f"Suspicious files:      {len(suspicious_files)}")
print(f"Registry artifacts:    {len(registry_artifacts)}")
print(f"Autorun entries:       {len(autoruns)} 🚨")
print(f"Deleted files:         {len(deleted_files)}")
print(f"Carved files:          {len(carved_files)}")
print("="*70)
```

---

## 4. Artifact Structure Reference

### RegistryArtifact

```python
@dataclass
class RegistryArtifact:
    hive: str              # "SYSTEM", "SOFTWARE", "SAM", "NTUSER.DAT"
    key_path: str          # Full registry key path
    value_name: str        # Registry value name
    value_data: Any        # Registry value data
    value_type: str        # "REG_SZ", "REG_DWORD", etc.
    last_modified: datetime | None
    significance: str      # "informational", "suspicious", "critical"
```

### MFT Entry Dictionary

```python
{
    "inode": 12345,                              # MFT record number
    "file_name": "document.docx",                # File name only
    "file_path": "/Users/John/document.docx",    # Full path
    "size": 524288,                              # Bytes
    "allocated": True,                           # False if deleted
    "is_directory": False,                       # True for folders
    "created": datetime(...),                    # Created timestamp
    "modified": datetime(...),                   # Modified timestamp
    "accessed": datetime(...),                   # Accessed timestamp
    "mft_modified": datetime(...)                # MFT entry modified
}
```

---

## 5. Performance Tips

### Registry Parsing
- Parse all hives at once for better performance
- Focus analysis on suspicious/critical artifacts first
- Use progress callback for large hives

### MFT Parsing
- Enable CSV export to reduce memory usage
- Use CSV for external analysis (Excel, pandas)
- Filter results in Python before processing
- Progress callback shows parsing progress

---

## 6. Error Handling

### Check Dependencies

```python
extractor = DataExtraction(case_id="CASE-001")

if not extractor.has_registry:
    print("⚠️ python-registry not available")
    print("Install: pip install python-registry")

if not extractor.has_pytsk3:
    print("⚠️ pytsk3 not available")
    print("Install: pip install pytsk3")
```

### Handle Missing Hives

```python
# Check if hive exists before parsing
hive_paths = {}

for hive_name, hive_path in potential_hives.items():
    if hive_path.exists():
        hive_paths[hive_name] = hive_path
    else:
        print(f"⚠️ Hive not found: {hive_path}")

if hive_paths:
    artifacts = extractor.parse_registry_hives(hive_paths)
```

---

## 7. Export and Analysis

### Export MFT to CSV

```python
# CSV automatically created if output_csv specified
mft_entries = extractor.parse_mft(
    image_path=Path("disk.E01"),
    output_csv=Path("mft_export.csv")  # Creates CSV
)
```

### Analyze with Pandas

```python
import pandas as pd

# Load MFT CSV
df = pd.read_csv("mft_export.csv")

# Convert timestamps
df['modified'] = pd.to_datetime(df['modified'])
df['created'] = pd.to_datetime(df['created'])

# Filter deleted files
deleted = df[df['allocated'] == False]

# Find large files
large = df[df['size'] > 100_000_000].sort_values('size', ascending=False)

# Timeline analysis
recent = df.sort_values('modified', ascending=False).head(50)

# Export filtered results
deleted.to_csv("deleted_files.csv", index=False)
```

---

## 8. Common Use Cases

### Use Case 1: Find Malware Persistence

```python
# Parse SOFTWARE hive
artifacts = extractor.parse_registry_hives({
    "SOFTWARE": Path("hives/SOFTWARE")
})

# Find autorun entries
autoruns = [a for a in artifacts if 'Run' in a.key_path]

for entry in autoruns:
    print(f"🚨 Autorun: {entry.value_name}")
    print(f"   Command: {entry.value_data}")
    print(f"   Modified: {entry.last_modified}")
```

### Use Case 2: Track User Activity

```python
# Parse NTUSER.DAT
artifacts = extractor.parse_registry_hives({
    "NTUSER": Path("hives/NTUSER.DAT")
})

# Find recent documents
recent_docs = [
    a for a in artifacts 
    if 'RecentDocs' in a.key_path
]

# Find typed URLs
urls = [
    a for a in artifacts 
    if 'TypedURLs' in a.key_path
]
```

### Use Case 3: Find Recently Deleted Files

```python
# Parse MFT
entries = extractor.parse_mft(Path("disk.E01"))

# Find recently deleted files
from datetime import datetime, timedelta
recent_cutoff = datetime.now() - timedelta(days=7)

recently_deleted = [
    e for e in entries
    if not e['allocated'] 
    and e['modified'] 
    and e['modified'] > recent_cutoff
]

print(f"Files deleted in last 7 days: {len(recently_deleted)}")
```

### Use Case 4: USB Device History

```python
# Parse SYSTEM hive
artifacts = extractor.parse_registry_hives({
    "SYSTEM": Path("hives/SYSTEM")
})

# Find USB devices
usb_devices = [
    a for a in artifacts 
    if 'USBSTOR' in a.key_path
]

print(f"USB devices connected: {len(usb_devices)}")
for device in usb_devices:
    print(f"  • {device.value_data}")
    print(f"    Last seen: {device.last_modified}")
```

---

## Summary

✅ **Registry Parsing**: `extractor.parse_registry_hives(hive_paths)`
✅ **MFT Parsing**: `extractor.parse_mft(image_path, output_csv)`

Both methods are fully implemented and production-ready for forensic investigations.
