# Evidence Type Selection - Quick Reference

## For Analysts

### Single File Mode (Default)

**When to use:**
- Memory dumps (.mem, .dmp)
- Single disk images (.img, .dd, .raw)
- Log files (.log)
- Archive files (.zip)

**How to use:**
1. Leave checkbox **UNTICKED**
2. Click "Browse for Evidence File..."
3. Select **ONE** file only
4. Click "Create Case"

**Error:** If you select multiple files, you'll see:
```
❌ You selected multiple files.
Enable 'Multi-part forensic image' to upload split disks.
```

---

### Multi-Part Mode

**When to use:**
- EnCase E01 format (LoneWolf.E01, LoneWolf.E02, ...)
- Logical Evidence Files (Evidence.L01, Evidence.L02, ...)
- Any split forensic image requiring all parts

**How to use:**
1. **CHECK** the box: "This evidence is a multi-part forensic image"
2. Click "Browse for Evidence Parts..."
3. Select **ALL** parts (Ctrl+Click or Shift+Click)
4. System validates the set
5. If complete, click "Create Case"

**Success:** You'll see:
```
✓ Detected multi-part forensic image:
  Base name: LoneWolf
  Parts: E01 → E09
  Total size: 14.6 GB
  Status: COMPLETE
```

**Error:** If parts are missing:
```
❌ Incomplete evidence set:
Missing: LoneWolf.E05

Forensic integrity requires ALL segments.
Please provide the missing part.
```

---

## For Developers

### Quick Integration

```python
from src.modules.evidence_validator import get_evidence_validator
from pathlib import Path

# Initialize validator
validator = get_evidence_validator()

# Case 1: Validate single file
files = [Path("memory.dmp")]
is_valid, evidence, error = validator.validate_evidence(
    files, 
    is_multipart_mode=False
)

# Case 2: Validate multi-part
files = [Path(f"LoneWolf.E{i:02d}") for i in range(1, 10)]
is_valid, evidence, error = validator.validate_evidence(
    files,
    is_multipart_mode=True
)

# Get summary
if is_valid:
    summary = validator.format_evidence_summary(evidence)
    print(summary)
```

### Evidence Object Usage

```python
# Access evidence properties
evidence.id                 # "LoneWolf"
evidence.type              # EvidenceType.MULTI_PART_DISK
evidence.format            # EvidenceFormat.E01_MULTI
evidence.total_parts       # 9
evidence.total_size_bytes  # 15663104000
evidence.is_complete       # True

# Get paths
primary = evidence.get_primary_path()    # LoneWolf.E01
all_paths = evidence.get_all_paths()     # All 9 parts

# Serialize
data = evidence.to_dict()  # For JSON storage
```

---

## Supported Patterns

### E01 Format
```
LoneWolf.E01 ─┐
LoneWolf.E02  ├─→ Base: "LoneWolf", Type: E01
LoneWolf.E03 ─┘
```

### L01 Format
```
Evidence.L01 ─┐
Evidence.L02  ├─→ Base: "Evidence", Type: L01
Evidence.L03 ─┘
```

### Numbered Format
```
Image.001 ─┐
Image.002  ├─→ Base: "Image", Type: 001
Image.003 ─┘
```

---

## Common Issues

### Issue 1: Selected multiple files in single mode
**Error:** "You selected multiple files..."
**Fix:** Check the multi-part checkbox first

### Issue 2: Missing parts in sequence
**Error:** "Incomplete evidence set: Missing E05"
**Fix:** Locate and include the missing part(s)

### Issue 3: Mixed base names
**Error:** "Could not detect multi-part naming pattern"
**Fix:** Ensure all parts have the same base name (LoneWolf.E01, LoneWolf.E02, NOT LoneWolf.E01, Evidence.E02)

### Issue 4: Wrong starting number
**Error:** "Sequence should start at 1..."
**Fix:** E01/L01 formats must start at 01, not 00 or 02

---

## Keyboard Shortcuts

**Multi-file selection:**
- `Ctrl+Click` - Select individual files
- `Shift+Click` - Select range
- `Ctrl+A` - Select all in directory

---

## File Size Warnings

| Size | Warning |
|------|---------|
| < 5 GB | No warning |
| 5 GB - 50 GB | "May take several minutes..." |
| > 50 GB | "May take over an hour..." |

---

## Chain of Custody

Every evidence ingestion logs:
- ✅ Evidence type (single vs multi-part)
- ✅ File paths (all parts for multi-part)
- ✅ SHA-256 hash (primary file)
- ✅ Timestamp
- ✅ Analyst name
- ✅ Case ID

Stored in: `cases/<case_id>/metadata/evidence.json`

---

## Testing

### Run Tests
```bash
python test_evidence_validator.py
```

### Expected Output
```
✓ Single file validation passed
✓ E01 Pattern detected: LoneWolf
✓ L01 Pattern detected: Evidence
✓ Complete sequence validated
✓ Incomplete sequence detected correctly
✓ Multi-part validation working
```

---

## Need Help?

Check full documentation: [EVIDENCE_TYPE_SELECTION.md](EVIDENCE_TYPE_SELECTION.md)

For issues: Review error messages - they include specific fix instructions.
