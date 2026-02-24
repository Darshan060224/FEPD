# Android/Mobile Image Support

## Issue Identified

The E01 image `tracy-phone-2012-07-15-final.E01` is an **Android phone forensic image** (likely YAFFS2 or ext4 filesystem). The current FEPD system cannot process it because:

1. **TSK (The Sleuth Kit) Cannot Identify Filesystem**
   ```
   ERROR - Failed to open filesystem: Cannot determine file system type
   ```
   - This occurs on both partitions detected in the image
   - TSK expects Windows (NTFS/FAT32) or Linux (ext2/ext3/ext4) filesystems
   - Android uses specialized mobile filesystems (YAFFS2, F2FS, ext4 with Android-specific metadata)

2. **Previous Fallback Bug (FIXED)**
   - **Bug**: When extraction failed, system incorrectly fell back to scanning `C:\Users\darsh\Downloads` (host directory)
   - **Fix**: Now keeps temp mount point for potential raw file carving
   - **Files Modified**: 
     - [main_window.py](../src/ui/main_window.py) lines 1107-1124 (E01 extraction)
     - [main_window.py](../src/ui/main_window.py) lines 1138-1142 (RAW extraction)

## Current Status

### ✅ Fixed
- Mount point fallback bug (no longer searches Downloads folder)
- Better error handling for unsupported filesystems
- Keeps temp mount point for raw carving attempts

### ⚠️ Still Not Supported
- **Android filesystem parsing** (YAFFS2, F2FS)
- **Mobile-specific artifacts** (SMS databases, call logs, app data)
- **Raw data carving** from unparseable filesystems

## Solutions

### Option 1: Pre-Extract with Mobile Forensic Tools (RECOMMENDED)
Use specialized Android forensic tools to extract the image first:

1. **Autopsy** with Android Analyzer module
   ```bash
   # Open tracy-phone-2012-07-15-final.E01 in Autopsy
   # Export artifacts to: cases/bKJBSzCC/extracted_data/
   ```

2. **Android Debug Bridge (ADB)** for logical extraction
   ```bash
   # If image was from live device
   adb pull /data/data/ extracted_data/
   ```

3. **Physical Extraction Tools**
   - Cellebrite UFED
   - Oxygen Forensics
   - XRY (MSAB)

### Option 2: Add Android Support to FEPD (Future Enhancement)

**Required Libraries:**
```python
# Add to requirements.txt
pytsk3>=3.0.0  # Already installed
pyewf>=20201230  # Already installed
yaffs2utils  # For YAFFS2 filesystem support (Android 2.x)
python-magic  # Better file type detection
adb-shell>=0.4.0  # ADB protocol for logical extraction
```

**Implementation Steps:**

1. **Filesystem Detection Enhancement**
   ```python
   # src/modules/image_handler.py
   def _detect_android_filesystem(self, partition_idx):
       """Detect Android-specific filesystems."""
       # Check for YAFFS2 magic bytes
       # Check for ext4 with Android metadata
       # Return filesystem type
   ```

2. **Android Artifact Discovery**
   ```python
   # src/modules/discovery.py
   ANDROID_ARTIFACT_PATHS = {
       'sms': ['data/data/com.android.providers.telephony/databases/mmssms.db'],
       'contacts': ['data/data/com.android.providers.contacts/databases/contacts2.db'],
       'call_logs': ['data/data/com.android.providers.contacts/databases/calllog.db'],
       'browser': ['data/data/com.android.browser/databases/browser2.db'],
       'apps': ['data/data/*/databases/*.db'],
   }
   ```

3. **SQLite Parser for Mobile Databases**
   ```python
   # src/parsers/android_parser.py
   class AndroidSMSParser:
       def parse(self, db_path):
           # Parse mmssms.db
           # Extract SMS/MMS records
           # Return normalized events
   ```

### Option 3: Raw File Carving (Limited Success)

For images where filesystem is unreadable, use file carving:

```python
# Future: Add file carving support
from src.modules.file_carver import FileCarver

carver = FileCarver(image_path)
carved_files = carver.carve_files(
    signatures=['sqlite', 'jpeg', 'xml'],
    output_dir='cases/bKJBSzCC/carved_data'
)
```

**Tools for Manual Carving:**
- **Foremost**: `foremost -i tracy-phone-2012-07-15-final.E01 -o carved_output/`
- **Photorec**: GUI tool for file carving
- **Scalpel**: Fast file carving with custom signatures

## Workaround for Current Image

**Step 1: Extract with Autopsy**
1. Open Autopsy (free, open-source)
2. Create new case: "Tracy Phone Analysis"
3. Add data source: `tracy-phone-2012-07-15-final.E01`
4. Let Autopsy parse Android filesystem
5. Export artifacts:
   - Right-click "Data Sources" → Export File
   - Select: SMS, Contacts, Call Logs, Browser History
   - Export to: `C:\Users\darsh\Desktop\FEPD\cases\bKJBSzCC\extracted_data\`

**Step 2: Process in FEPD**
1. Open FEPD with case `bKJBSzCC`
2. Manually import extracted artifacts:
   ```python
   # Python console in FEPD
   from src.parsers.android_parser import AndroidSMSParser
   parser = AndroidSMSParser()
   events = parser.parse('cases/bKJBSzCC/extracted_data/mmssms.db')
   ```

**Step 3: Visualize Timeline**
1. FEPD will normalize events to timeline format
2. Use Timeline tab for visualization
3. Use ML Analytics for behavior analysis

## Error Messages Decoded

### "Cannot determine file system type"
- **Cause**: TSK cannot recognize Android filesystem
- **Solution**: Use Option 1 (pre-extract) or Option 2 (add Android support)

### "Mount point contains ... items" but "NO ARTIFACTS DISCOVERED"
- **Cause**: Files extracted but not in expected Windows paths
- **Solution**: Discovery module needs Android artifact paths

### "Returning empty artifact list"
- **Cause**: No Windows registry/EVTX/MFT files found
- **Solution**: Normal for non-Windows images - need Android parsers

## Testing Android Support (Future)

```python
# tests/test_android_image.py
def test_android_e01_parsing():
    """Test Android E01 image parsing."""
    handler = DiskImageHandler('tracy-phone-2012-07-15-final.E01')
    assert handler.open_image()
    
    # Should detect Android filesystem
    partitions = handler.enumerate_partitions()
    assert any(p['fs_type'] == 'YAFFS2' or p['fs_type'] == 'EXT4' 
               for p in partitions)
    
    # Should extract Android artifacts
    discovery = ArtifactDiscovery()
    artifacts = discovery.discover_android(mount_point)
    assert len(artifacts) > 0
    assert any(a.artifact_type == ArtifactType.SMS for a in artifacts)
```

## References

- **Android Filesystem Structure**: https://source.android.com/devices/architecture
- **YAFFS2 Specification**: https://yaffs.net/documents/yaffs2-specification
- **Mobile Forensics Best Practices**: NIST SP 800-101
- **Autopsy Android Analyzer**: https://www.autopsy.com/docs/

## Estimated Development Effort

| Feature | Effort | Priority |
|---------|--------|----------|
| Android filesystem detection | 2-3 days | High |
| SMS/Contacts parsing | 3-4 days | High |
| App data extraction | 5-7 days | Medium |
| YAFFS2 support | 7-10 days | Low (use Autopsy) |
| **Total** | **17-24 days** | - |

**Recommendation**: Use Autopsy for Android images (Option 1) until Android support is built into FEPD.
