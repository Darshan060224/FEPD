# FEPD Security & Forensic Soundness Audit Report

**Audit Date:** 2026-03-06  
**Auditor:** Automated Static Analysis (GitHub Copilot)  
**Scope:** Full codebase at `c:\Users\darsh\Desktop\FEPD`  
**Classification:** CONFIDENTIAL — Attorney Work Product

---

## Executive Summary

The FEPD codebase demonstrates **strong forensic design principles** — hash-chained chain-of-custody, read-only evidence enforcement, path sanitization, and ML prediction binding. However, several **Critical and High severity security vulnerabilities** exist that could undermine court admissibility if exploited or challenged by opposing counsel.

**Overall Court-Defensibility Assessment: CONDITIONAL PASS**  
The system is defensible *if* the Critical and High issues below are remediated. In its current state, a skilled defense attorney could challenge the integrity of ML model loading (arbitrary code execution via pickle) and timestamp consistency (mixed UTC/local time).

---

## 1. SECURITY VULNERABILITIES

### CRITICAL Severity

#### SEC-CRIT-001: Arbitrary Code Execution via Pickle Deserialization
**Risk:** An attacker who can substitute a `.pkl` model file can achieve full remote code execution.  
**Files:**
- [src/analysis/forensic_ml_analyzer.py](src/analysis/forensic_ml_analyzer.py#L44) — `pickle.load(f)` for malware model
- [src/analysis/forensic_ml_analyzer.py](src/analysis/forensic_ml_analyzer.py#L51) — `pickle.load(f)` for malware scaler
- [src/analysis/forensic_ml_analyzer.py](src/analysis/forensic_ml_analyzer.py#L58) — `pickle.load(f)` for network model
- [src/analysis/forensic_ml_analyzer.py](src/analysis/forensic_ml_analyzer.py#L65) — `pickle.load(f)` for network scaler
- [src/ml/models/isolation_forest_model.py](src/ml/models/isolation_forest_model.py#L258) — `pickle.load(f)` in `IsolationForestModel.load()`

**Attack Vector:** Replace `.pkl` file in `models/` directory → arbitrary Python code executes on next case load.  
**Impact:** Full system compromise, evidence tampering, chain-of-custody destruction.

**Recommended Fix:**
```python
# Option A: Use safetensors/ONNX for model serialization (preferred)
# Option B: Verify model file hash before loading
import hashlib
def safe_load_model(path, expected_hash):
    with open(path, 'rb') as f:
        data = f.read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_hash:
        raise SecurityError(f"Model file tampered: {path}")
    return pickle.loads(data)  # Only after hash verification

# Option C: Use sklearn's joblib with restricted unpickling
```

---

#### SEC-CRIT-002: Command Injection via `os.system()` with User-Influenced Paths
**Risk:** `os.system()` passes strings to the shell, enabling command injection if paths contain shell metacharacters.  
**Files:**
- [src/ui/tabs/case_details_tab.py](src/ui/tabs/case_details_tab.py#L372) — `os.system(f'open "{coc_log_path}"')`
- [src/ui/tabs/case_details_tab.py](src/ui/tabs/case_details_tab.py#L374) — `os.system(f'xdg-open "{coc_log_path}"')`
- [src/ui/tabs/case_details_tab.py](src/ui/tabs/case_details_tab.py#L395) — `os.system(f'open "{self.case_path}"')`
- [src/ui/tabs/case_details_tab.py](src/ui/tabs/case_details_tab.py#L397) — `os.system(f'xdg-open "{self.case_path}"')`
- [scripts/demo_fepd_os.py](scripts/demo_fepd_os.py#L117) — `os.system(f"{sys.executable} create_demo_case.py")`

**Attack Vector:** A case path containing `"; rm -rf / #` would execute arbitrary commands.  
**Impact:** Host system compromise.

**Recommended Fix:**
```python
# Replace os.system() with subprocess.run() without shell=True
import subprocess, shlex
subprocess.run(['xdg-open', str(coc_log_path)])  # Already done correctly elsewhere
```

---

### HIGH Severity

#### SEC-HIGH-001: Case ID Path Traversal — No Sanitization
**Risk:** `case_id` from user input is used directly in path construction with no validation against directory traversal.  
**File:** [src/core/case_manager.py](src/core/case_manager.py#L112)  
```python
case_dir = self.base_cases_dir / case_id  # case_id = "../../etc" → escapes cases/
case_dir.mkdir(parents=True)              # parents=True makes it worse
```

**Attack Vector:** User enters case ID `../../malicious_dir` → writes outside `cases/` directory.  
**Impact:** Arbitrary directory creation, potential overwrite of system files.

**Recommended Fix:**
```python
import re
if not re.match(r'^[A-Za-z0-9_\-]+$', case_id):
    raise ValueError("Case ID contains invalid characters")
# Also verify resolved path stays within base_cases_dir:
case_dir = (self.base_cases_dir / case_id).resolve()
if not str(case_dir).startswith(str(self.base_cases_dir.resolve())):
    raise ValueError("Case ID would escape cases directory")
```

---

#### SEC-HIGH-002: SQLite `check_same_thread=False` Without Locking
**Risk:** SQLite with `check_same_thread=False` allows multi-threaded access but SQLite itself is not thread-safe for write operations without proper serialization.  
**Files:**
- [src/core/virtual_fs.py](src/core/virtual_fs.py#L139) — VFS database
- [src/modules/db_manager.py](src/modules/db_manager.py#L382) — Main database with `isolation_level=None` (autocommit)
- [src/modules/search_engine.py](src/modules/search_engine.py#L461) — Search FTS database

**Impact:** Database corruption under concurrent access, potential loss of forensic data.

**Recommended Fix:**
```python
# Use threading.Lock() for all write operations, or
# Use connection-per-thread pattern with thread-local storage
import threading
_local = threading.local()
def get_connection():
    if not hasattr(_local, 'conn'):
        _local.conn = sqlite3.connect(str(db_path))
    return _local.conn
```

---

#### SEC-HIGH-003: Temp File Without Guaranteed Cleanup
**Risk:** Temp mount directory created with `mkdtemp()` may not be cleaned up on crash or exception.  
**Files:**
- [src/ui/main_window.py](src/ui/main_window.py#L1962) — `tempfile.mkdtemp(prefix="fepd_mount_")` — cleanup in `finally` at L2171/L2188 exists but uses `ignore_errors=True`
- [src/ui/viewers/video_viewer.py](src/ui/viewers/video_viewer.py#L197) — `tempfile.mkstemp()` — cleanup only in `close()`, not `__del__`

**Impact:** Evidence remnants left in system temp directories; recoverable by unauthorized parties.

**Recommended Fix:**
```python
# Use context managers for automatic cleanup
with tempfile.TemporaryDirectory(prefix="fepd_mount_") as temp_mount:
    # ... work with temp_mount ...
# Auto-cleaned even on exception

# For video viewer, add __del__ backup:
def __del__(self):
    self.close()
```

---

### MEDIUM Severity

#### SEC-MED-001: No `secrets` Module Usage — All Randomness via `random`/`numpy.random`
**Risk:** Python's `random` module is cryptographically insecure. While most current usage is in demo/visualization data generation, any future use for tokens, IDs, or security-relevant values would be vulnerable.  
**Files:** 30+ uses of `np.random.*` across:
- [src/ml/ml_anomaly_detector.py](src/ml/ml_anomaly_detector.py#L573)
- [src/ml/ueba_profiler.py](src/ml/ueba_profiler.py#L853-L858)
- [src/visualization/heatmap_widget.py](src/visualization/heatmap_widget.py#L256)
- Multiple test files

**Current Impact:** Low (used for demo data and ML, not security).  
**Potential Impact:** High if used for session tokens or evidence IDs.

**Recommended Fix:** Add `import secrets` for any security-relevant random generation. Document that `random`/`numpy.random` are only for non-security contexts.

---

#### SEC-MED-002: No `.env` File or Secret Management
**Risk:** No `.env.example` or `.env` file exists. API keys (VirusTotal, OTX) are collected via UI dialog ([src/ui/dialogs/custom_dialogs.py](src/ui/dialogs/custom_dialogs.py#L445)) but storage/persistence mechanism is unclear.  
**Impact:** Potential for credentials to be stored insecurely in config files or case metadata.

**Recommended Fix:** Create `.env.example` with placeholder keys; use `python-dotenv` or OS keyring for secret storage.

---

### LOW Severity

#### SEC-LOW-001: `eval()`/`exec()` Usage
**Finding:** All 20+ instances of `eval()`/`exec()` are **Qt dialog `.exec()` calls** (e.g., `dialog.exec()`, `menu.exec()`). These are NOT Python's `eval()`/`exec()` builtins.  
**Risk:** NONE. These are safe Qt method calls.

#### SEC-LOW-002: SQL Injection
**Finding:** SQL queries at [src/fepd_os/indexer.py](src/fepd_os/indexer.py#L48) and [src/fepd_os/shell.py](src/fepd_os/shell.py#L492) correctly use parameterized queries (`?` placeholders).  
**Risk:** NONE found. SQL usage appears safe.

#### SEC-LOW-003: No `shell=True` in subprocess calls
**Finding:** All `subprocess.run()` calls use list arguments without `shell=True`.  
**Risk:** NONE. This is correct practice.

---

## 2. FORENSIC SOUNDNESS VIOLATIONS

### CRITICAL Forensic Issues

#### FOR-CRIT-001: Inconsistent Timestamp Standards — Mixed UTC and Local Time
**Risk:** Mixing `datetime.now()` (local time) and `datetime.now(timezone.utc)` (UTC) creates ambiguous forensic timelines. A defense attorney can challenge any timeline reconstruction that mixes time zones.

**UTC (Correct):**
- [src/core/chain_of_custody.py](src/core/chain_of_custody.py#L55) — `datetime.now(timezone.utc).isoformat()` ✅
- [src/utils/chain_of_custody.py](src/utils/chain_of_custody.py#L90) — `datetime.now(timezone.utc).isoformat()` ✅
- [src/core/ml_integrity.py](src/core/ml_integrity.py#L82) — `datetime.now(timezone.utc).isoformat()` ✅
- [src/core/evidence_registry.py](src/core/evidence_registry.py#L108) — `datetime.now(timezone.utc).isoformat()` ✅

**Local Time (INCORRECT for forensics):**
- [src/core/integrity.py](src/core/integrity.py#L127) — `datetime.now().isoformat()` ❌
- [src/core/integrity.py](src/core/integrity.py#L184) — `datetime.now().isoformat()` ❌
- [src/core/integrity.py](src/core/integrity.py#L230) — `datetime.now().strftime(...)` ❌
- [src/core/case_manager.py](src/core/case_manager.py#L63) — `datetime.now().isoformat()` ❌
- [src/core/case_manager.py](src/core/case_manager.py#L140) — `datetime.now().isoformat()` ❌
- [src/core/path_sanitizer.py](src/core/path_sanitizer.py#L394) — `datetime.now().isoformat()` ❌
- [src/core/training_state.py](src/core/training_state.py#L72) — `datetime.now().isoformat()` ❌
- [src/core/forensic_data_importer.py](src/core/forensic_data_importer.py#L54) — `datetime.now().isoformat()` ❌

**Impact:** Timeline inconsistencies between chain-of-custody entries (UTC) and integrity records (local time). In a case spanning time zone changes (DST), timestamps become ambiguous.

**Recommended Fix:**
```python
# Replace ALL datetime.now() with datetime.now(timezone.utc)
from datetime import datetime, timezone
timestamp = datetime.now(timezone.utc).isoformat()
```

---

#### FOR-CRIT-002: No Post-Analysis Integrity Verification
**Risk:** Evidence is hashed on upload (`register_evidence`) and can be verified on demand (`verify_integrity`), but **no automatic post-analysis hash verification** exists. The system does not re-hash evidence after analysis completes to prove evidence was not modified during processing.

**What exists:**
- Pre-analysis hash: [src/core/integrity.py](src/core/integrity.py#L100) — `register_evidence()` calculates SHA-256 on upload ✅
- On-demand verify: [src/core/integrity.py](src/core/integrity.py#L149) — `verify_integrity()` can be called manually ✅
- Read-only enforcement: [src/core/integrity.py](src/core/integrity.py#L267) — `_make_readonly()` sets file permissions ✅

**What's missing:**
- No automatic `verify_integrity()` call after pipeline completes
- No "analysis complete — evidence verified unchanged" chain-of-custody entry
- No final hash comparison in the pipeline completion flow

**Impact:** Cannot prove to court that evidence was unmodified throughout analysis. Opposing counsel: *"Can you prove the evidence wasn't altered between upload and report generation?"*

**Recommended Fix:**
```python
# In the pipeline completion handler:
def on_pipeline_complete(case_path, evidence_path):
    mgr = IntegrityManager(case_path)
    verified = mgr.verify_integrity(evidence_path)
    chain.append(user, "POST_ANALYSIS_VERIFY", 
                 f"Evidence integrity {'CONFIRMED' if verified else 'FAILED'}")
```

---

### HIGH Forensic Issues

#### FOR-HIGH-001: Chain of Custody Log File Not Protected Against Direct Editing
**Risk:** The chain-of-custody log at `chain_of_custody.log` is a plain text JSONL file. While it uses hash chaining (each entry hashes the previous), the file itself has no filesystem-level write protection. An attacker with file access could rewrite the entire chain with valid hashes.

**Files:**
- [src/core/chain_of_custody.py](src/core/chain_of_custody.py#L50) — File-based append-only log
- [src/utils/chain_of_custody.py](src/utils/chain_of_custody.py#L103) — File append

**Mitigating Factor:** The hash-chaining design means selective edits are detected. But full chain rewrite with recomputed hashes is possible.

**Impact:** Tamper detection is present but not tamper-proof. A sophisticated actor could rewrite the entire log.

**Recommended Fix:**
1. Set log file to append-only at OS level (`chattr +a` on Linux)
2. Periodically export chain hash to external/independent storage
3. Add digital signature (HMAC) using a key stored separately from the log

---

#### FOR-HIGH-002: Non-Deterministic Analysis Components
**Risk:** ML analysis uses non-seeded random operations, meaning the same evidence analyzed twice may produce different results.

**Files with non-deterministic behavior:**
- [src/ml/ml_anomaly_detector.py](src/ml/ml_anomaly_detector.py#L573) — `np.random.choice` for centroid initialization
- IsolationForest models inherently have randomness

**Impact:** Results are not perfectly reproducible. Opposing counsel: *"Running the same analysis twice gives different answers — how can we trust either?"*

**Recommended Fix:**
```python
# Set fixed random seed for reproducibility
np.random.seed(42)  # Or use RandomState per-analysis
# Document that seed is fixed and record it in chain of custody
```

---

#### FOR-HIGH-003: Evidence Registry is Case-Global — Cross-Case Information Leakage
**Risk:** The evidence registry at [src/core/evidence_registry.py](src/core/evidence_registry.py) uses a single `.evidence_registry.json` file shared across ALL cases. This means:
1. Opening Case A reveals that the same evidence exists in Case B (via `check_duplicate`)
2. No case isolation for metadata

**Impact:** Cross-case information leakage. In multi-client forensic labs, this violates case isolation.

**Recommended Fix:** Add access controls or use per-case isolation flags. The duplicate check should return only "duplicate exists" without revealing the other case ID unless authorized.

---

### MEDIUM Forensic Issues

#### FOR-MED-001: Read-Only Enforcement is Permission-Based Only
**Risk:** Evidence immutability relies on filesystem permissions (chmod). A user running as root/admin can bypass this trivially.

**Files:**
- [src/core/integrity.py](src/core/integrity.py#L267-L279) — `_make_readonly()` uses `chmod`
- [src/modules/image_ingestion.py](src/modules/image_ingestion.py#L312) — Windows `attrib +R`

**Impact:** Admins can modify evidence despite "read-only" protection.

**Recommended Fix:** Defense-in-depth: combine permissions + hash verification + chain-of-custody logging of any permission changes. Document that physical evidence copies should be maintained independently.

---

#### FOR-MED-002: Pickle-Based ML Models Not Hash-Verified Before Loading
**Risk:** Even though `ml_integrity.py` exists to bind predictions to artifact hashes, the ML models themselves are loaded via `pickle.load()` without verifying the model file hash. A tampered model could produce biased results.

**Files:**
- [src/core/ml_integrity.py](src/core/ml_integrity.py) — Tracks prediction↔artifact binding ✅
- [src/analysis/forensic_ml_analyzer.py](src/analysis/forensic_ml_analyzer.py#L44) — Loads model without hash check ❌

**Impact:** Model substitution could bias analysis results without detection.

---

#### FOR-MED-003: Chain of Custody Verification Mutates Entry During Check
**Risk:** In [src/utils/chain_of_custody.py](src/utils/chain_of_custody.py#L171), `verify_chain()` does `stored_hash = entry.pop('entry_hash')` which modifies the entry dictionary in-place during verification. If the same entries list is used elsewhere, this causes data corruption.

**Impact:** Subtle bug that could cause verification to fail on second call or corrupt in-memory state.

**Recommended Fix:**
```python
entry_copy = entry.copy()
stored_hash = entry_copy.pop('entry_hash')
computed_hash = self._compute_entry_hash(entry_copy)
```

---

### LOW Forensic Issues

#### FOR-LOW-001: `uuid4()` for Case IDs
**Finding:** [src/ui/tabs/case_tab.py](src/ui/tabs/case_tab.py#L356) uses `uuid4()` for case IDs in some flows. UUID4 is random-based and not forensically meaningful.  
**Impact:** Low. Users can override with meaningful case IDs.

#### FOR-LOW-002: Demo/Test Data Uses Random Generation
**Finding:** Visualization and test modules generate random demo data. This is appropriate for non-production code.  
**Impact:** None in production.

---

## 3. POSITIVE FINDINGS (Strengths)

| Feature | Assessment | Location |
|---------|-----------|----------|
| Hash-chained chain of custody | **Excellent** — blockchain-like append-only ledger with hash linking | [src/core/chain_of_custody.py](src/core/chain_of_custody.py) |
| Chain verification | **Excellent** — full chain integrity verification with break detection | [src/core/chain_of_custody.py](src/core/chain_of_custody.py#L153) |
| Path sanitizer | **Excellent** — prevents host filesystem path leakage to UI | [src/core/path_sanitizer.py](src/core/path_sanitizer.py) |
| Read-only terminal guard | **Excellent** — comprehensive command blocking for evidence immutability | [src/terminal/security/read_only_guard.py](src/terminal/security/read_only_guard.py) |
| Command injection prevention | **Excellent** — PATH_TRAVERSAL_PATTERNS, INJECTION_PATTERNS detection | [src/terminal/security/command_validator.py](src/terminal/security/command_validator.py) |
| Training/inference mode isolation | **Good** — hard boundaries between training and inference | [src/core/training_state.py](src/core/training_state.py) |
| ML prediction binding | **Good** — predictions tied to artifact SHA-256 | [src/core/ml_integrity.py](src/core/ml_integrity.py) |
| Parameterized SQL queries | **Good** — no SQL injection found | Throughout |
| No `shell=True` subprocess | **Good** — all subprocess calls use list arguments | Throughout |
| Evidence hashing on upload | **Good** — SHA-256 on registration | [src/core/integrity.py](src/core/integrity.py#L100) |
| Duplicate evidence detection | **Good** — prevents accidentally importing same evidence twice | [src/core/evidence_registry.py](src/core/evidence_registry.py) |

---

## 4. REMEDIATION PRIORITY

| Priority | ID | Issue | Effort |
|----------|-----|-------|--------|
| 🔴 P0 | SEC-CRIT-001 | Pickle deserialization → hash-verify before load | 2-4 hours |
| 🔴 P0 | SEC-CRIT-002 | `os.system()` → `subprocess.run()` list form | 1 hour |
| 🔴 P0 | FOR-CRIT-001 | `datetime.now()` → `datetime.now(timezone.utc)` everywhere | 2 hours |
| 🔴 P0 | FOR-CRIT-002 | Add post-analysis integrity verification | 3-4 hours |
| 🟠 P1 | SEC-HIGH-001 | Case ID path traversal sanitization | 1 hour |
| 🟠 P1 | SEC-HIGH-002 | SQLite thread safety | 4-6 hours |
| 🟠 P1 | FOR-HIGH-001 | Chain-of-custody filesystem protection | 2 hours |
| 🟠 P1 | FOR-HIGH-002 | Fixed random seeds for ML reproducibility | 2 hours |
| 🟠 P1 | FOR-HIGH-003 | Cross-case evidence registry isolation | 3 hours |
| 🟡 P2 | SEC-HIGH-003 | Temp file cleanup guarantees | 2 hours |
| 🟡 P2 | FOR-MED-003 | `entry.pop()` mutation in verify_chain | 15 min |
| 🟢 P3 | SEC-MED-001 | Secrets module documentation | 30 min |
| 🟢 P3 | SEC-MED-002 | `.env.example` for secret management | 1 hour |

---

## 5. COURT-DEFENSIBILITY ASSESSMENT

### Can this system produce court-admissible evidence?

**YES, with caveats.** The architecture demonstrates forensic awareness that exceeds most open-source DFIR tools:

✅ **Strengths for court:**
- Hash-chained audit trail (tamper-evident)
- Evidence immutability enforcement (multi-layer)
- Path sanitization (prevents analyst information leakage)
- SHA-256 evidence hashing at ingestion

❌ **Weaknesses a defense attorney would exploit:**
1. *"The timestamps disagree — integrity records use local time while chain of custody uses UTC. Which clock do we trust?"* (FOR-CRIT-001)
2. *"No one verified the evidence was unchanged after analysis. The hash was only checked at upload."* (FOR-CRIT-002)
3. *"The ML models could have been replaced with malicious ones — they're loaded without verification."* (SEC-CRIT-001)
4. *"Running the analysis twice gives different results."* (FOR-HIGH-002)

### Verdict

**Fix the 4 P0 issues and this system becomes strongly defensible.** The forensic architecture is fundamentally sound — these are implementation gaps, not design flaws.

---

*End of Security & Forensic Soundness Audit Report*
