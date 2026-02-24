# FEPD FORENSIC SECURITY AUDIT - COMPREHENSIVE ANALYSIS
**Date:** 2026-01-11  
**Auditor:** Internal Forensic Architect & Auditor  
**Status:** CRITICAL ISSUES IDENTIFIED

---

## CRITICAL FINDINGS

### [CRITICAL-001] : CaseManager._calculate_file_hash()

**Problem:**  
Hash calculation is performed SYNCHRONOUSLY in main thread during case creation.

**Impact:**  
For large evidence files (10+ GB), the entire UI freezes for minutes. No progress feedback. User cannot cancel. Appears as application hang.

**Exploit Scenario:**  
1. Attacker provides malformed 100GB E01 file
2. User attempts case creation
3. Application hangs for 15+ minutes
4. User force-kills process
5. Corrupted case directory remains
6. Evidence integrity state unknown

**Fix:**  
```python
# In HashCalculationThread.run()
def run(self):
    try:
        # CURRENT: Calls case_manager.create_case() which blocks
        # This already calculates hash synchronously
        
        # FIX: Move hash calculation to this background thread
        primary_path = str(self.evidence_obj.get_primary_path())
        
        # Calculate hash HERE with progress reporting
        hash_value = self._calculate_hash_with_progress(primary_path)
        
        # Then create case with pre-computed hash
        case_metadata = self.case_manager.create_case_with_hash(
            self.case_id,
            self.case_name,
            self.investigator,
            primary_path,
            precomputed_hash=hash_value
        )
```

**Test:**  
1. Create case with 20GB E01 file
2. Verify UI remains responsive
3. Verify progress updates every second
4. Verify hash matches independent calculation
5. Verify cancellation works mid-hash

**Severity:** CRITICAL  
**Court Impact:** Case creation failure = evidence rejection

---

### [CRITICAL-002] : Evidence Validator Hash Duplication

**Problem:**  
Evidence validator calculates hash during validation. CaseManager re-calculates SAME hash during case creation. **Double hashing = 2x time waste.**

**Impact:**  
12.62 GB LoneWolf evidence is hashed TWICE:
- Once in `validate_multipart_files()` → stores in `EvidenceSegment.sha256_hash`
- Again in `create_case()` → re-reads entire file

**Exploit Scenario:**  
1. User validates 50GB multi-part E01 set (10 minutes)
2. User clicks "Create Case"
3. System re-hashes primary file (another 8 minutes)
4. Total: 18 minutes for what should be 10

**Fix:**  
```python
# In case_creation_dialog.py
def _create_case(self):
    # ...
    
    # CURRENT: Pass path, case_manager re-hashes
    # case_manager.create_case(..., image_path)
    
    # FIX: Pass pre-computed hash from validation
    if self.evidence_object and self.evidence_object.parts:
        primary_hash = self.evidence_object.parts[0].sha256_hash
        
        self.case_manager.create_case(
            case_id,
            case_name,
            investigator,
            primary_path,
            precomputed_hash=primary_hash  # NEW PARAMETER
        )
```

**Test:**  
1. Validate 20GB E01 file (record hash time)
2. Create case
3. Verify NO re-hashing occurs
4. Verify case.json contains correct hash
5. Total time should be ~hash_time, not 2x

**Severity:** CRITICAL  
**Court Impact:** Analyst frustration → errors → case dismissal

---

### [CRITICAL-003] : ML Predictions Not Bound to Case

**Problem:**  
`MLIntegrityManager` stores predictions in case directory, but `record_prediction()` is never called by actual ML code.

**Impact:**  
ML predictions exist in memory, displayed in UI, but **never persisted with hash bindings**.

**Exploit Scenario:**  
1. Analyst runs malware detection on `backdoor.exe`
2. ML predicts "malicious" with 95% confidence
3. Analyst closes FEPD
4. Attacker replaces `backdoor.exe` with clean file (same name)
5. Analyst reopens case
6. No ML prediction exists → re-runs model
7. Model says "benign" (different file)
8. Defense attorney: "Which file did you analyze?"

**Fix:**  
```python
# In src/ml/inference_pipeline.py or wherever ML runs
from src.core.ml_integrity import MLIntegrityManager

class InferencePipeline:
    def __init__(self, case_id, case_path, ...):
        self.ml_integrity = MLIntegrityManager(case_path)
    
    def process_evidence(self, evidence_path):
        # Calculate hash BEFORE analysis
        artifact_hash = hashlib.sha256(open(evidence_path, 'rb').read()).hexdigest()
        
        # Run ML model
        prediction = self.model.predict(...)
        
        # CRITICAL: Bind prediction to hash
        self.ml_integrity.record_prediction(
            artifact_path=str(evidence_path),
            artifact_sha256=artifact_hash,
            model_name="malware_detector_v1",
            model_version="1.0.0",
            prediction=prediction['category'],
            confidence=prediction['confidence']
        )
```

**Test:**  
1. Run ML on artifact
2. Verify `ml_predictions.json` created
3. Replace artifact with different file
4. Run `verify_all_predictions()`
5. Verify integrity failure detected

**Severity:** CRITICAL  
**Court Impact:** ML evidence inadmissible without hash binding

---

## HIGH FINDINGS

### [HIGH-001] : Case Manager Silent Corruption

**Problem:**  
If `_calculate_file_hash()` fails mid-hash (disk error, permission denied), exception propagates but case directory already created.

**Impact:**  
Partial case state on disk. `case.json` not created but `cases/CASE-001/` exists.

**Fix:**  
```python
def create_case(self, case_id, case_name, investigator, image_path):
    # ... validation ...
    
    case_dir = self.base_cases_dir / case_id
    if case_dir.exists():
        raise ValueError(f"Case '{case_id}' already exists")
    
    try:
        # Create case directory
        case_dir.mkdir(parents=True)
        artifacts_dir = case_dir / "artifacts"
        artifacts_dir.mkdir()
        
        # Calculate hash (can fail)
        image_hash = self._calculate_file_hash(str(image_path))
        
        # Create metadata
        case_metadata = {...}
        
        # Save case.json
        case_json_path = case_dir / "case.json"
        with open(case_json_path, 'w') as f:
            json.dump(case_metadata, f, indent=4)
        
        # Initialize chain of custody
        self._init_chain_of_custody(case_dir, case_metadata)
        
        return case_metadata
    
    except Exception as e:
        # CLEANUP ON FAILURE
        if case_dir.exists():
            import shutil
            shutil.rmtree(case_dir)
            logger.error(f"Case creation failed, cleaned up: {case_dir}")
        raise
```

**Severity:** HIGH

---

### [HIGH-002] : Evidence Registry Race Condition

**Problem:**  
`EvidenceRegistry._load_registry()` and `._save_registry()` are not atomic. Two concurrent case creations could corrupt registry.

**Impact:**  
```json
# Thread 1 loads
{"evidence": {"hash1": {"case_id": "CASE-001"}}}

# Thread 2 loads (same state)
{"evidence": {"hash1": {"case_id": "CASE-001"}}}

# Thread 1 adds hash2, saves
{"evidence": {"hash1": ..., "hash2": {"case_id": "CASE-002"}}}

# Thread 2 adds hash3, saves (OVERWRITES thread 1's write!)
{"evidence": {"hash1": ..., "hash3": {"case_id": "CASE-003"}}}
# hash2 LOST!
```

**Fix:**  
```python
import fcntl  # Unix file locking
import msvcrt # Windows file locking
import platform

class EvidenceRegistry:
    def _save_registry(self, registry):
        """Save registry with file locking."""
        try:
            with open(self.registry_file, 'r+') as f:
                # Acquire exclusive lock
                if platform.system() == 'Windows':
                    msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                
                # Re-read to get latest state
                f.seek(0)
                current = json.load(f)
                
                # Merge changes
                current["evidence"].update(registry["evidence"])
                
                # Write back
                f.seek(0)
                f.truncate()
                json.dump(current, f, indent=2)
                
                # Release lock automatically on close
        except Exception as e:
            logger.error(f"Failed to save registry: {e}")
```

**Severity:** HIGH  
**Court Impact:** Duplicate evidence undetected → case contamination

---

### [HIGH-003] : ML Predictions Lack Model Reproducibility

**Problem:**  
`MLPrediction` stores `model_name` and `model_version` as strings. No actual model binary hash or weights checksum.

**Impact:**  
Cannot prove that `malware_detector_v1` used in 2025 is same model as `malware_detector_v1` used in 2026.

**Fix:**  
```python
@dataclass
class MLPrediction:
    artifact_path: str
    artifact_sha256: str
    model_name: str
    model_version: str
    model_sha256: str  # NEW: Hash of model weights file
    model_path: str    # NEW: Path to model binary
    prediction: str
    confidence: float
    predicted_at: str
    metadata: Dict[str, Any]
    
    def verify_model_integrity(self, current_model_path: Path) -> bool:
        """Verify model hasn't been modified since prediction."""
        import hashlib
        current_hash = hashlib.sha256(open(current_model_path, 'rb').read()).hexdigest()
        return current_hash == self.model_sha256
```

**Severity:** HIGH  
**Court Impact:** Model tampering undetectable → ML evidence rejected

---

## MEDIUM FINDINGS

### [MEDIUM-001] : Audit Logger Not Integrated with ML Pipeline

**Problem:**  
`ForensicAuditLogger` exists but ML code doesn't call it.

**Fix:**  
In every ML module:
```python
from src.core.forensic_audit_logger import ForensicAuditLogger

self.audit_logger = ForensicAuditLogger(case_dir)

# After each prediction
self.audit_logger.log_ml_prediction(
    artifact_path=...,
    artifact_hash=...,
    model_name=...,
    prediction=...,
    confidence=...,
    user=investigator,
    case_id=case_id
)
```

**Severity:** MEDIUM

---

### [MEDIUM-002] : No Verification of E01 Part Sequence

**Problem:**  
`validate_multipart_files()` checks for numeric sequence gaps, but doesn't verify E01 CRCs or segment linking.

**Impact:**  
Could accept:
- `LoneWolf.E01`, `LoneWolf.E02`, `OtherEvidence.E03` (wrong base name)
- Corrupted E01 parts with valid names

**Fix:**  
Read E01 header from each part, verify:
- Segment number matches filename
- Total segments count is consistent
- CRC-32 checksums match
- Evidence UUID is same across all parts

**Severity:** MEDIUM

---

### [MEDIUM-003] : Memory Dump Analysis Lacks Format Detection

**Problem:**  
`MemoryAnalyzer` assumes raw memory dump. No Volatility profile detection, no format validation.

**Impact:**  
Cannot differentiate:
- Windows memory dump
- Linux memory dump
- Android memory dump
- Corrupted file

**Fix:**  
```python
def detect_memory_format(file_path: Path) -> str:
    with open(file_path, 'rb') as f:
        header = f.read(4096)
    
    # Windows crash dump
    if header.startswith(b'PAGEDUMP'):
        return 'windows_crash_dump'
    
    # Linux core dump
    if header.startswith(b'\x7fELF'):
        return 'linux_core_dump'
    
    # LiME format
    if b'EMiL' in header[:256]:
        return 'lime_dump'
    
    # Raw memory (no header)
    return 'raw_memory'
```

**Severity:** MEDIUM

---

## LOW FINDINGS

### [LOW-001] : FEPD Terminal Commands Not Sandboxed

**Problem:**  
Shell commands execute arbitrary Python code. No command whitelisting.

**Severity:** LOW (FEPD is not a multi-tenant system)

---

## DESIGN FLAWS

### [DESIGN-001] : ML Training on Case Data

**Problem:**  
No explicit prevention of training ML models on case evidence.

**Fix:**  
Add to all ML training scripts:
```python
TRAINING_DATA_DIR = Path("training_data/")  # SEPARATE FROM CASES
CASE_DATA_DIR = Path("cases/")  # READ-ONLY FOR INFERENCE

def train_model(data_source):
    if CASE_DATA_DIR in Path(data_source).parents:
        raise SecurityError(
            "CONSTITUTIONAL VIOLATION: Cannot train on case data!\n"
            "Training must use separate, labeled datasets only."
        )
```

**Severity:** CRITICAL (Constitutional Violation)

---

## MISSING FEATURES

### [MISSING-001] : No Android/iOS Mobile Image Support

**Problem:**  
FEPD cannot parse:
- Android `.ab` backups
- iOS `.ipsw` images
- Mobile SQLite databases (contacts, SMS, call logs)

**Impact:**  
Blind spot for mobile forensics cases.

---

### [MISSING-002] : No Cloud Artifact Parsers

**Problem:**  
No support for:
- AWS CloudTrail logs
- Azure AD sign-in logs
- Google Workspace audit logs
- Office 365 mailbox exports

**Impact:**  
Cloud-native attacks invisible.

---

### [MISSING-003] : No File Carving for Deleted Files

**Problem:**  
FEPD extracts files from filesystem but doesn't carve unallocated space.

**Impact:**  
Deleted evidence not recovered.

---

## SUMMARY

### Critical Issues: 3
1. Synchronous hash calculation (UI freeze)
2. Double hashing (performance)
3. ML predictions not persisted

### High Issues: 3
1. Case creation corruption
2. Registry race condition
3. ML model reproducibility

### Medium Issues: 3
1. Audit logger not integrated
2. E01 part verification incomplete
3. Memory dump format detection missing

### Design Flaws: 1
1. No training data isolation enforcement

### Missing Features: 3
1. Mobile image support
2. Cloud artifact parsing
3. File carving

---

## RECOMMENDED PRIORITY

**Immediate (This Week):**
1. Fix CRITICAL-001 (hash calculation async)
2. Fix CRITICAL-002 (eliminate double hashing)
3. Fix CRITICAL-003 (bind ML predictions)

**Next Sprint:**
1. Fix HIGH-001, HIGH-002, HIGH-003
2. Add DESIGN-001 enforcement

**Backlog:**
1. MEDIUM issues
2. Mobile/cloud support
3. File carving

---

**Audit Complete**  
**Status:** FEPD is not court-ready until CRITICAL issues resolved  
**Re-audit Required:** After fixes implemented
