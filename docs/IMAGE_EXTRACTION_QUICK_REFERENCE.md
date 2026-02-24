```python
"""
Quick Reference: Disk Image Artifact Extraction

Forensically-sound extraction of artifacts from E01/DD disk images.
All operations are read-only to preserve evidence integrity.
"""

from pathlib import Path
from src.modules.image_handler import DiskImageHandler
from src.modules.artifact_extractor import extract_artifacts_from_image

# =============================================================================
# BASIC USAGE - Automated Extraction
# =============================================================================

# Extract all artifacts automatically (recommended)
results = extract_artifacts_from_image(
    image_path="evidence/case123.E01",
    output_dir="extracted_artifacts/case123",
    verify_hash=True  # Verify image hash and calculate artifact hashes
)

print(f"Success: {results['success']}")
print(f"Extracted {len(results['artifacts'])} artifact groups")
print(f"Image MD5: {results['image_metadata']['hash']}")

# Results include:
# - Event logs (Application, Security, System, PowerShell)
# - Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT)
# - User registry (NTUSER.DAT, UsrClass.dat)
# - Browser history (Chrome, Edge, Firefox)
# - Prefetch files (*.pf)
# - Master File Table ($MFT)

# Extraction log saved to:
# - extracted_artifacts/case123/extraction_log.json (detailed metadata)
# - extracted_artifacts/case123/extraction_log.csv (quick reference)


# =============================================================================
# MANUAL EXTRACTION - Fine-Grained Control
# =============================================================================

# Open disk image (E01 or raw DD)
with DiskImageHandler("evidence/case.E01", verify_hash=True) as handler:
    # Image metadata
    print(f"Image type: {handler.image_type}")  # 'ewf' or 'raw'
    print(f"Image size: {handler.image_size:,} bytes")
    print(f"Image MD5: {handler.image_hash}")
    
    # Enumerate partitions
    partitions = handler.enumerate_partitions()
    for i, part in enumerate(partitions):
        print(f"Partition {i}: {part['description']} "
              f"({part['type']}, {part['length']*512:,} bytes)")
    
    # Open NTFS filesystem on partition 0
    fs_info = handler.open_filesystem(partition_index=0)
    
    # Extract specific file
    metadata = handler.extract_file(
        fs_info=fs_info,
        path="/Windows/System32/config/SYSTEM",
        output_path=Path("extracted/SYSTEM"),
        calculate_hash=True
    )
    
    print(f"Extracted: {metadata['source_path']}")
    print(f"Size: {metadata['size']:,} bytes")
    print(f"MD5: {metadata['md5']}")
    print(f"SHA256: {metadata['sha256']}")
    
    # List directory contents
    entries = handler.list_directory(fs_info, "/Windows/System32/winevt/Logs")
    for entry in entries:
        print(f"{entry['type']}: {entry['name']} ({entry['size']:,} bytes)")
    
    # Search for files by name (recursive)
    found = handler.find_file(fs_info, "NTUSER.DAT", start_path="/Users")
    for path in found:
        print(f"Found: {path}")


# =============================================================================
# E01 IMAGE HANDLING
# =============================================================================

# E01 images (Expert Witness Format / EnCase)
# Supports segmented images (E01, E02, E03...)

handler = DiskImageHandler("case.E01", verify_hash=True)
handler.open_image()

# Hash verification (automatic with E01)
# - Reads MD5 from E01 metadata
# - Verifies image integrity
print(f"E01 stored MD5: {handler.image_hash}")

# Manual hash calculation (for raw images)
image_md5 = handler._calculate_image_hash(algorithm='md5')
image_sha256 = handler._calculate_image_hash(algorithm='sha256')

handler.close()


# =============================================================================
# RAW IMAGE HANDLING
# =============================================================================

# Raw DD images (no metadata, simple byte stream)

handler = DiskImageHandler("case.dd", verify_hash=True)
handler.open_image()

# Hash calculated automatically on open (if verify_hash=True)
print(f"Raw image MD5: {handler.image_hash}")

handler.close()


# =============================================================================
# ARTIFACT EXTRACTION - Specific Categories
# =============================================================================

# Event Logs (EVTX)
from src.modules.artifact_extractor import ArtifactExtractor

extractor = ArtifactExtractor("case.E01", Path("output"), verify_hash=True)
handler = DiskImageHandler("case.E01", verify_hash=True)
handler.open_image()
fs_info = handler.open_filesystem(0)

# Extract all event logs
event_log_paths = [
    '/Windows/System32/winevt/Logs/Application.evtx',
    '/Windows/System32/winevt/Logs/Security.evtx',
    '/Windows/System32/winevt/Logs/System.evtx',
]

for path in event_log_paths:
    output_file = Path("output/EventLogs") / Path(path).name
    metadata = handler.extract_file(fs_info, path, output_file)
    if metadata:
        print(f"Extracted: {path} -> MD5: {metadata['md5']}")

handler.close()


# Registry Hives
registry_paths = [
    '/Windows/System32/config/SYSTEM',
    '/Windows/System32/config/SOFTWARE',
    '/Windows/System32/config/SAM',
    '/Windows/System32/config/SECURITY',
]

# Also extract transaction logs (.LOG1, .LOG2)
for path in registry_paths:
    # Extract hive
    handler.extract_file(fs_info, path, Path("output/Registry") / Path(path).name)
    # Extract LOG1
    handler.extract_file(fs_info, f"{path}.LOG1", Path("output/Registry") / f"{Path(path).name}.LOG1")
    # Extract LOG2
    handler.extract_file(fs_info, f"{path}.LOG2", Path("output/Registry") / f"{Path(path).name}.LOG2")


# User Registry (NTUSER.DAT)
# Find all user directories
entries = handler.list_directory(fs_info, "/Users")
for entry in entries:
    if entry['type'] == 'dir' and entry['name'] not in ['Public', 'Default']:
        ntuser_path = f"/Users/{entry['name']}/NTUSER.DAT"
        output_file = Path(f"output/Users/{entry['name']}/NTUSER.DAT")
        handler.extract_file(fs_info, ntuser_path, output_file)


# Browser History (Chrome)
chrome_history = "/Users/JohnDoe/AppData/Local/Google/Chrome/User Data/Default/History"
handler.extract_file(fs_info, chrome_history, Path("output/Chrome_History"))

# Browser History (Edge)
edge_history = "/Users/JohnDoe/AppData/Local/Microsoft/Edge/User Data/Default/History"
handler.extract_file(fs_info, edge_history, Path("output/Edge_History"))

# Browser History (Firefox)
# Need to find profile directory first
firefox_profiles = handler.list_directory(
    fs_info, 
    "/Users/JohnDoe/AppData/Roaming/Mozilla/Firefox/Profiles"
)
for profile in firefox_profiles:
    if profile['type'] == 'dir':
        places_path = f"/Users/JohnDoe/AppData/Roaming/Mozilla/Firefox/Profiles/{profile['name']}/places.sqlite"
        handler.extract_file(fs_info, places_path, Path(f"output/Firefox_{profile['name']}_places.sqlite"))


# Prefetch Files
prefetch_entries = handler.list_directory(fs_info, "/Windows/Prefetch")
for entry in prefetch_entries:
    if entry['name'].endswith('.pf'):
        path = f"/Windows/Prefetch/{entry['name']}"
        handler.extract_file(fs_info, path, Path("output/Prefetch") / entry['name'])


# Master File Table ($MFT)
handler.extract_file(fs_info, "/$MFT", Path("output/$MFT"))


# =============================================================================
# FORENSIC BEST PRACTICES
# =============================================================================

# 1. ALWAYS use read-only mode (automatic with DiskImageHandler)
# 2. ALWAYS verify hashes (set verify_hash=True)
# 3. ALWAYS log all actions (automatic with ArtifactExtractor)
# 4. NEVER mount images with write access
# 5. ALWAYS document tool versions and timestamps

# Chain of Custody logging
# All extraction operations are logged with:
# - Source path in image
# - Output path on filesystem
# - File size
# - MD5 hash
# - SHA256 hash
# - Extraction timestamp

# Example extraction log entry:
log_entry = {
    'source_path': '/Windows/System32/config/SYSTEM',
    'output_path': 'extracted/SYSTEM',
    'size': 12582912,
    'md5': 'a1b2c3d4e5f6...',
    'sha256': 'f6e5d4c3b2a1...',
    'extracted_at': '2025-11-07T14:30:45',
    'mtime': 1699372800,  # MACB times
    'atime': 1699372800,
    'ctime': 1699372800,
    'crtime': 1699372800,
}

# Logs saved to:
# - extraction_log.json (detailed JSON)
# - extraction_log.csv (CSV for spreadsheets)


# =============================================================================
# ERROR HANDLING
# =============================================================================

try:
    handler = DiskImageHandler("case.E01", verify_hash=True)
    
    if not handler.open_image():
        raise RuntimeError("Failed to open image")
    
    partitions = handler.enumerate_partitions()
    
    if not partitions:
        raise RuntimeError("No partitions found")
    
    fs_info = handler.open_filesystem(0)
    
    if not fs_info:
        raise RuntimeError("Failed to open filesystem")
    
    # Extract artifact
    metadata = handler.extract_file(
        fs_info, 
        "/Windows/System32/config/SYSTEM",
        Path("output/SYSTEM")
    )
    
    if not metadata:
        print("Artifact not found or extraction failed")
    else:
        print(f"Success: MD5={metadata['md5']}")
        
except Exception as e:
    print(f"Error: {e}")
    
finally:
    if handler:
        handler.close()


# =============================================================================
# INTEGRATION WITH EXISTING PARSERS
# =============================================================================

# After extraction, use existing FEPD parsers

from src.modules.data_extraction import parse_registry_hives, parse_mft

# Parse extracted registry hives
registry_results = parse_registry_hives(
    image_path="extracted/SYSTEM",  # Use extracted file
    output_dir=Path("parsed_results")
)

# Parse extracted MFT
mft_results = parse_mft(
    image_path="extracted/$MFT",
    output_dir=Path("parsed_results")
)


# =============================================================================
# PERFORMANCE TIPS
# =============================================================================

# 1. Extract only needed artifacts (use manual extraction)
# 2. Use chunk reading for large files (automatic in DiskImageHandler)
# 3. Skip hash calculation for speed (set verify_hash=False) - NOT RECOMMENDED
# 4. Process partitions in parallel (use multiprocessing)

# Example: Parallel partition processing
from multiprocessing import Pool

def process_partition(partition_index):
    handler = DiskImageHandler("case.E01", verify_hash=True)
    handler.open_image()
    fs_info = handler.open_filesystem(partition_index)
    
    # Extract artifacts from this partition
    # ...
    
    handler.close()

# Process all partitions in parallel
with Pool(processes=4) as pool:
    pool.map(process_partition, range(len(partitions)))


# =============================================================================
# TROUBLESHOOTING
# =============================================================================

# Issue: "pytsk3 not available"
# Solution: Install pytsk3
#   pip install pytsk3
#   Windows: Download wheel from https://github.com/py4n6/pytsk/releases

# Issue: "pyewf not available"
# Solution: Install pyewf and libewf
#   1. Download libewf DLLs from https://github.com/libyal/libewf/releases
#   2. Place in Python\Lib\site-packages\ or add to PATH
#   3. pip install pyewf

# Issue: "Failed to open image"
# Solution: Check file exists, format is correct (E01 or DD)

# Issue: "No partitions found"
# Solution: May be raw filesystem (no partition table)
#   Try accessing partition 0 directly

# Issue: "Failed to open filesystem"
# Solution: Check partition type (must be NTFS/FAT)
#   Only NTFS/FAT are fully supported

# Issue: Hash mismatch
# Solution: Image may be corrupted or modified
#   DO NOT proceed - evidence integrity compromised

# Issue: Permission denied
# Solution: Run as administrator (Windows) or use sudo (Linux)

# Issue: Out of memory
# Solution: Process smaller chunks, use streaming
#   DiskImageHandler automatically uses chunked reading


# =============================================================================
# SUPPORTED IMAGE FORMATS
# =============================================================================

# E01 (Expert Witness / EnCase)
# - Single file: case.E01
# - Segmented: case.E01, case.E02, case.E03...
# - Compressed: Yes (automatic)
# - Hash verification: Yes (from metadata)

# DD/RAW (Bitstream copy)
# - Extensions: .dd, .raw, .img, .001
# - Compressed: No
# - Hash verification: Calculated on open

# Supported filesystems:
# - NTFS (Windows)
# - FAT12/FAT16/FAT32
# - exFAT (limited)
# - EXT2/EXT3/EXT4 (Linux)

# NOT supported:
# - VMDK (use conversion tools)
# - VHD/VHDX (use conversion tools)
# - AFF (use conversion tools)


# =============================================================================
# COMMAND LINE USAGE
# =============================================================================

# Via Python script
python extract_artifacts.py case.E01 output_dir --verify-hash

# Via FEPD GUI
# 1. Launch FEPD
# 2. Image Ingest tab
# 3. Drag-drop E01 file
# 4. Select "Extract Artifacts" module
# 5. Click "Start Ingestion"
# 6. Artifacts saved to case workspace


# =============================================================================
# LEGAL & COURT ADMISSIBILITY
# =============================================================================

# This implementation follows forensic best practices:
#
# 1. Read-only access: No modifications to evidence
# 2. Hash verification: Proves integrity (MD5, SHA256)
# 3. Detailed logging: Chain of custody documentation
# 4. Timestamps: MACB times preserved
# 5. Tool provenance: Open-source, peer-reviewed libraries
#    - pytsk3: The Sleuth Kit (widely accepted)
#    - pyewf: libewf (EnCase format standard)
# 6. Reproducibility: Anyone can verify using same tools
#
# All actions are logged with:
# - Tool name and version
# - Timestamps
# - Hashes of source image
# - Hashes of extracted artifacts
# - Complete file paths
#
# Logs suitable for:
# - Court evidence exhibits
# - Expert witness testimony
# - Peer review
# - Audit trails

"""
