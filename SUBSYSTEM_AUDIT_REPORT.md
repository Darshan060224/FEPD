# FEPD Subsystem Audit Report

**Generated:** 2025-01-XX  
**Scope:** Terminal System (`src/terminal/`), Visualization Engine (`src/visualization/`), FEPD-OS (`src/fepd_os/`)  
**Auditor:** Automated Code Audit  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Critical Issues](#2-critical-issues)
3. [Major Issues](#3-major-issues)
4. [Minor Issues](#4-minor-issues)
5. [Terminal System Analysis](#5-terminal-system-analysis)
6. [Visualization Engine Analysis](#6-visualization-engine-analysis)
7. [FEPD-OS Analysis](#7-fepd-os-analysis)
8. [Completeness Assessment](#8-completeness-assessment)
9. [Integration Assessment](#9-integration-assessment)
10. [File Inventory](#10-file-inventory)

---

## 1. Executive Summary

The FEPD codebase across three subsystems totals **~11,700 lines** of Python across **60 files**. The architecture is well-conceived: a constitutional forensic operating system with immutable evidence, chain-of-custody logging, OS-adaptive terminal emulation, and ML-explainable intelligence. However, several **import-breaking bugs** exist that prevent module loading, and there are integration seams between the three subsystems that introduce runtime failure risks.

| Severity | Count |
|----------|-------|
| CRITICAL | 3     |
| MAJOR    | 5     |
| MINOR    | 9     |

**Overall Grade: B-** — Strong architecture, solid individual modules, but import/integration issues would cause failures at load time.

---

## 2. Critical Issues

### CRIT-01: `commands/__init__.py` — All 15 Re-exports Reference Non-Existent Names

**File:** `src/terminal/commands/__init__.py` (Lines 8–22)  
**Severity:** CRITICAL — Module load crashes with `ImportError`

The `__init__.py` imports `handle_ls`, `handle_cd`, `handle_pwd`, etc. from submodules, but every command module exports `<name>_command` functions instead:

| `__init__.py` imports | Actual function name |
|---|---|
| `handle_ls` | `ls_command` |
| `handle_cd` | `cd_command` |
| `handle_pwd` | `pwd_command` |
| `handle_cat` | `cat_command` |
| `handle_tree` | `tree_command` |
| `handle_hash` | `hash_command` |
| `handle_hexdump` | `hexdump_command` |
| `handle_strings` | `strings_command` |
| `handle_find` | `find_command` |
| `handle_grep` | `grep_command` |
| `handle_timeline` | `timeline_command` |
| `handle_score` | `score_command` |
| `handle_explain` | `explain_command` |
| `handle_artifacts` | `artifacts_command` |
| `handle_connections` | `connections_command` |

**Impact:** `from src.terminal.commands import handle_ls` will crash. However, `terminal_engine.py` imports directly (`from ..commands.ls import ls_command`) so the terminal engine itself works. Any code importing via the package `__init__.py` will fail.

**Fix:**
```python
from .ls import ls_command as handle_ls
# ... or rename all imports to match actual function names
```

---

### CRIT-02: `intelligence/__init__.py` — Exports `ArtifactMatch` but Class Is Named `CorrelationResult`

**File:** `src/terminal/intelligence/__init__.py` (Line 9)  
**Severity:** CRITICAL — `ImportError` when importing `ArtifactMatch`

```python
from .artifact_correlator import ArtifactCorrelator, ArtifactMatch  # ArtifactMatch doesn't exist
```

The actual class in `artifact_correlator.py` is `CorrelationResult` (line 31). There is no `ArtifactMatch` anywhere in the file.

**Impact:** `from src.terminal.intelligence import ArtifactMatch` crashes. If no consumer code imports via the package init, this is latent. If any does, it fails at load time.

**Fix:**
```python
from .artifact_correlator import ArtifactCorrelator, CorrelationResult as ArtifactMatch
# ... or rename the __all__ entry
```

---

### CRIT-03: `shell.py` — References `self.coc_logger` but Never Assigns It

**File:** `src/fepd_os/shell.py` (Lines 1088-1092)  
**Severity:** CRITICAL — `AttributeError` at runtime during report generation

In `cmd_report()`:
```python
if self.coc_logger:
    self.coc_logger.log(...)
```

But `FEPDShellEngine.__init__()` never creates a `self.coc_logger` attribute. It creates `self.audit` (an `AuditLogger` instance) and uses `ChainLogger` locally in other methods (e.g., `cmd_verify_coc`), but there is no `self.coc_logger` attribute.

**Impact:** If `cmd_report()` succeeds generating the report text and reaches the CoC logging block, it will raise `AttributeError: 'FEPDShellEngine' object has no attribute 'coc_logger'`. The `if self.coc_logger:` check will itself crash (not just evaluate to False) because the attribute doesn't exist.

**Fix:** Add `self.coc_logger = None` to `__init__()`, and initialize it in `mount_case()`:
```python
self.coc_logger = ChainLogger(case_path) if case_path else None
```

---

## 3. Major Issues

### MAJ-01: All 7 Visualization Chart Modules Use Absolute `src.*` Imports

**Files:** All files in `src/visualization/charts/`  
**Severity:** MAJOR — Breaks when project is run as installed package or from different CWD

Every chart module uses:
```python
from src.visualization.engine.data_processor import DataProcessor, ForensicEvent
from src.visualization.engine.visualization_engine import ACCENT_COLORS, apply_dark_theme
```

This only works when running from the project root with `src` as a package on `sys.path`. If the project is ever installed via pip, run as a module (`python -m`), or invoked from a different working directory, all chart imports fail.

**Affected files:**
- `artifact_distribution.py`
- `attack_surface_chart.py`
- `connections_graph.py`
- `heatmap_chart.py`
- `severity_chart.py`
- `timeline_chart.py`
- `user_activity_chart.py`

**Fix:** Use relative imports:
```python
from ..engine.data_processor import DataProcessor, ForensicEvent
from ..engine.visualization_engine import ACCENT_COLORS, apply_dark_theme
```

---

### MAJ-02: `shell.py` Cross-Package Relative Imports — Fragile Dependency Chain

**File:** `src/fepd_os/shell.py` (Lines 39-40)  
**Severity:** MAJOR

```python
from ..core.chain_of_custody import ChainLogger, CoC_Actions
from ..core.case_transfer import export_case, import_case
```

These files exist (`src/core/chain_of_custody.py` and `src/core/case_transfer.py`) and export the expected symbols. However:

1. `case_transfer.py` defines `export_case` and `import_case` as **both module-level functions AND class methods**. The module-level functions (used by shell.py) exist but the `import_case` function signature takes `(bundle_path: str, cases_dir: str)` while the class method takes `(self, cases_dir)`. This is correct but confusing.

2. The `evidence_shell.py` file does NOT import from `..core.*` — only `shell.py` does. This is correct.

**Risk:** Fragile cross-package relative imports. If `src/core/__init__.py` doesn't exist or is misconfigured, these break.

---

### MAJ-03: `shell.py` — `cmd_memscan()` Uses Absolute Import `src.modules.memory_analyzer`

**File:** `src/fepd_os/shell.py` (Lines ~790, ~1195)  
**Severity:** MAJOR — Mixed import styles

```python
from src.modules.memory_analyzer import MemoryAnalyzer
```

This appears in `cmd_memscan()` fallback and `cmd_ps()` / `cmd_netstat()`. It uses absolute `src.*` import style while the rest of `shell.py` uses relative imports (`from ..core.*`). This will break under the same conditions as MAJ-01.

---

### MAJ-04: `shell.py` — `cmd_report()` Uses Import `..reporting.forensic_report_generator`

**File:** `src/fepd_os/shell.py` (Line ~1040)  

```python
from ..reporting.forensic_report_generator import ForensicReportGenerator
```

This requires `src/reporting/forensic_report_generator.py` to exist. If it doesn't (not verified in this audit scope), the import inside `cmd_report()` will raise `ImportError`. The exception is caught but produces a degraded error message.

---

### MAJ-05: VFS `_node_at()` Is a Private API Used Extensively

**Files:** `src/fepd_os/shell.py` (Lines ~440, ~485, ~520), `src/terminal/commands/cd.py`  
**Severity:** MAJOR — Encapsulation violation, fragile coupling

Multiple consumers call `self.vfs._node_at(path)` directly:
- `cmd_cd()` in shell.py
- `_tree_recursive()` in shell.py
- `cd_command()` in terminal commands

The `VirtualFilesystem` class exposes `list_dir()` and `stat()` as public API, but `_node_at()` (prefixed with `_`) is private. If VFS internals change (e.g., switching from tree-based to flat index), all callers break.

**Fix:** Expose a public `exists(path) -> bool` and `is_dir(path) -> bool` method on `VirtualFilesystem`.

---

## 4. Minor Issues

### MIN-01: `heatmap_widget.py` — Matplotlib Backend Import Path Varies

**File:** `src/visualization/heatmap_widget.py`

```python
from matplotlib.backends.backend_qt import NavigationToolbar2QT
```

This import path varies between matplotlib versions. Some versions use `backend_qtagg` or `backend_qt5agg`. May cause `ImportError` on certain matplotlib versions.

---

### MIN-02: `evidence_shell.py` — `_cmd_cat()` Returns Placeholder Text Instead of Actual Content

**File:** `src/fepd_os/evidence_shell.py` (Lines ~710-715)

```python
return f"[File: {target}]\n[Content preview would be shown here from evidence storage]"
```

The `_cmd_cat()` method in the Evidence OS Shell never reads actual file content. It checks metadata for a `real_path` key but then just returns a placeholder. By contrast, the FEPD-mode `cmd_cat()` in `shell.py` actually opens and returns file contents.

---

### MIN-03: `evidence_shell.py` — `_cmd_dir_windows()` Uses Current Time Instead of Evidence Time

**File:** `src/fepd_os/evidence_shell.py` (Lines ~490-510)

```python
date_str = datetime.now().strftime('%m/%d/%Y  %I:%M %p')
```

Windows DIR output should show file timestamps from evidence metadata, not `datetime.now()`. This is misleading in a forensic context where timestamps are evidence.

---

### MIN-04: `evidence_shell.py` — `_cmd_head()` / `_cmd_tail()` Are Trivial Wrappers

**File:** `src/fepd_os/evidence_shell.py` (Lines ~720-725)

```python
def _cmd_head(self, args, full_cmd):
    return self._cmd_cat(args, full_cmd) + "\n...(truncated)"

def _cmd_tail(self, args, full_cmd):
    return "...(earlier content)\n" + self._cmd_cat(args, full_cmd)
```

These don't implement actual head/tail behavior (line count selection via `-n`). They just prepend/append text to the full cat output.

---

### MIN-05: `vfs.py` — `_build_tree()` Marks All Leaf Nodes as Files

**File:** `src/fepd_os/vfs.py` (Lines ~42-49)

```python
for i, part in enumerate(parts):
    if part not in node.children:
        is_dir = i != len(parts) - 1
        node.children[part] = VNode(part, is_dir=is_dir)
    node = node.children[part]
node.is_dir = False  # Final node always set to file
```

The last `node.is_dir = False` unconditionally marks the final path component as a file. If a directory path is stored in the DB without trailing content (e.g., `Users/Admin/`), it will be incorrectly marked as a file. This works for files but breaks for empty directories in the index.

---

### MIN-06: `shell.py` — Bare `except:` in `_tree_recursive()`

**File:** `src/fepd_os/shell.py` (Line ~525)

```python
except:
    pass
```

Bare `except` catches `BaseException` including `KeyboardInterrupt` and `SystemExit`. Should be `except Exception:`.

---

### MIN-07: `audit.py` — Silently Swallows All Database Errors

**File:** `src/fepd_os/audit.py`

```python
except Exception:
    pass  # Don't crash on audit failure
```

While not crashing on audit failure is reasonable, completely swallowing errors means audit failures are invisible. Should at minimum log to stderr.

---

### MIN-08: `indexer.py` — Opens and Closes DB Connection Per Operation

**File:** `src/fepd_os/indexer.py` (Lines ~20-38)

`add_file_record()` calls `sqlite3.connect()`, executes one INSERT, then `conn.close()`. In bulk indexing scenarios this is extremely inefficient (no connection reuse, no batching, fsync per commit).

---

### MIN-09: `shell.py` — `cmd_cd()` Doesn't Resolve Relative Paths

**File:** `src/fepd_os/shell.py` (Lines ~440-448)

```python
def cmd_cd(self, args):
    ...
    path = args[0]
    node = self.vfs._node_at(path)
    ...
    self.cwd = path
```

The FEPD-mode `cmd_cd()` sets `self.cwd = path` without resolving relative paths against the current CWD. If the user types `cd subfolder`, `self.cwd` becomes `"subfolder"` instead of `/current/path/subfolder`. The Evidence OS Shell's `_cmd_cd()` handles this correctly with `os.path.join(self._cwd, norm_target)`.

---

## 5. Terminal System Analysis

### Architecture
The terminal follows a clean pipeline architecture:
```
Input → Parser → Validator → Logger → Dispatcher → Command Handler → Output
```

### Code Quality
- **Parser** (`command_parser.py`, 168 lines): Robust tokenization with shlex fallback, pipe/redirect support. Well-tested structure.
- **Dispatcher** (`command_dispatcher.py`, 197 lines): Clean registry pattern with alias support and pipe chain execution.
- **Session** (`session_manager.py`, 184 lines): Complete history management, prompt generation, serializable snapshots.
- **Engine** (`terminal_engine.py`, 511 lines): Orchestrates all components. Registers 20+ commands with rich built-in help. Has autocomplete for VFS paths.

### Command Correctness with VFS
All 15 commands correctly operate against the VFS abstraction:
- `ls`, `cd`, `tree`, `find` use `vfs.list_dir()`, `vfs.stat()`, `vfs._node_at()`
- `cat`, `hash`, `hexdump`, `strings` use `vfs.read_file()` or metadata
- `score`, `explain` use ML bridge
- `timeline`, `connections` query SQLite DB tables

### Security
- **ReadOnlyGuard** (187 lines): Blocks 6 categories of mutating commands (delete, create, move, copy, edit, system). Detects redirects.
- **CommandValidator** (152 lines): Validates arguments, detects path traversal and injection patterns. Issues warnings (not blocks) for injection — this appears intentional to allow forensic paths containing special characters.

### Chain of Custody
- **CoCLogger** (237 lines): Hash-chained audit log using SHA-256. Creates `terminal_audit` table in SQLite. Has `verify_chain()` to detect tampering. Well-designed for legal admissibility.

---

## 6. Visualization Engine Analysis

### Architecture
```
Events → DataProcessor → VisualizationEngine → Chart Modules → FigureCanvas
                                                    ↕
                                          VisualizationController (MVC)
```

### Data Processing
- **DataProcessor** (362 lines): Excellent data normalization layer. Maps 50+ column aliases to canonical names. Provides aggregation helpers: hourly/daily counts, user-hour matrix, category distribution. Handles None/missing values gracefully.
- **ForensicEvent** dataclass: Clean canonical format with timestamp, type, severity, user, source, details, numeric_value.

### Engine
- **VisualizationEngine** (351 lines): 
  - LRU figure cache (8 slots) prevents redundant rendering
  - `_ChartWorker` QThread for async chart generation — prevents UI freeze
  - Dark theme with forensic-appropriate color palette
  - Export to PNG/PDF/SVG with high DPI
  - Thread-safe signal-slot pattern via PyQt6

### Chart Modules (7 total)
All chart modules are functional and produce matplotlib figures:
1. **Timeline** — Line chart with peak annotation
2. **Heatmap** — Hour×date activity density
3. **Severity** — Horizontal bar chart with color coding
4. **Artifact Distribution** — Pie/donut chart
5. **User Activity** — User×hour heatmap with off-hours highlighting
6. **Connections Graph** — NetworkX entity graph with fallback bar chart
7. **Attack Surface** — Multi-panel: port risk, connections, attack vectors

### Visualization Correctness
- Charts correctly consume `ForensicEvent` data from the processor
- Graceful fallbacks when optional dependencies (networkx, squarify, seaborn) are missing
- Dark theme consistently applied
- All figures are non-interactive (static renders) embedded in PyQt6

### Thread Safety
- Chart generation runs on `_ChartWorker` QThread — UI stays responsive
- Signal-slot mechanism for result delivery
- Figure cache is accessed from the main thread only (thread-safe by design)

---

## 7. FEPD-OS Analysis

### Architecture
```
CLI Entry (prompt_toolkit REPL)
    → FEPDShellEngine (main dispatcher, 2426 lines)
        → CaseContextManager (case registry)
        → VirtualFilesystem (evidence tree from SQLite)
        → EvidenceOSShell (OS-native command emulation, 1114 lines)
            → EvidenceOSDetector (OS type detection from file paths)
        → AuditLogger (SQLite audit trail)
        → MLBridge (deterministic scoring)
        → ChainLogger (blockchain CoC)
```

### OS Detection & Emulation
- **EvidenceOSDetector** (evidence_os.py, 566 lines): Multi-strategy detection using weighted scoring across 5 OS types (Windows, Linux, macOS, Android, iOS). Detects by file path patterns (registry hives, /etc/, .app, .dex).
- **EvidenceOSShell** (evidence_shell.py, 1114 lines): Full OS-native command sets:
  - Windows: 20+ commands (dir, type, ipconfig, systeminfo, ver, findstr, where, set, path)
  - Linux: 25+ commands (ls, cat, head, tail, grep, find, stat, wc, uname, id, ifconfig)
  - macOS: Linux commands + sw_vers, system_profiler, mdls
- **Mutation blocking**: `is_mutating_command()` checks against comprehensive sets of OS-specific dangerous commands (40+ per OS). Also detects write patterns (`>`, `>>`, `-rf`, `--force`).

### FEPDShellEngine (shell.py, 2426 lines)
The main shell engine is the largest single file. It implements:
- **Case management**: `cmd_cases`, `cmd_create_case`, `cmd_use` with case mounting
- **Dual-mode command dispatch**: Native OS mode routes to EvidenceOSShell; FEPD mode routes to `cmd_*` handlers
- **Virtual system reconstruction**: `cmd_ps`, `cmd_netstat`, `cmd_sessions`, `cmd_services`, `cmd_startup` — all from SQLite artifact tables
- **UEBA**: `cmd_ueba` with build/status/anomalies/user-profile subcommands
- **Memory analysis**: `cmd_memscan` with orchestrator integration and fallback
- **Report generation**: `cmd_report` with court-admissible format
- **Chain of custody**: `cmd_verify_coc`, `cmd_export_case`, `cmd_import_case`

### FEPD-OS Correctness
- VFS tree construction from SQLite is correct but has the empty-directory edge case (MIN-05)
- OS detection scoring is well-designed with weighted heuristics
- Mutation blocking is comprehensive with 40+ commands per OS
- The dual-mode dispatch (native OS vs FEPD commands) works correctly:
  - Native OS commands go to `EvidenceOSShell.execute()`
  - FEPD commands go to `cmd_*` methods via `getattr`
  - Unknown commands fall back to Evidence OS Shell

### Key Design Issue: Two Parallel Command Systems
There are effectively **two complete command implementations**:
1. `src/terminal/commands/` — Used by `TerminalEngine` (PyQt6 GUI terminal)
2. `src/fepd_os/evidence_shell.py` + `shell.py` — Used by `FEPDShellEngine` (CLI REPL)

These are **not integrated**. The terminal commands use VFS's `list_dir()`/`stat()`, while the evidence shell builds its own `_file_tree` dict from SQLite. This means:
- Bug fixes must be applied in two places
- Behavioral differences between GUI terminal and CLI terminal
- The evidence shell's `_cmd_cat()` returns placeholders while the terminal's `cat_command()` actually returns file content

---

## 8. Completeness Assessment

### Terminal System — 95% Complete
| Component | Status | Notes |
|-----------|--------|-------|
| Command Parser | ✅ Complete | Pipes, quotes, redirects |
| Command Dispatcher | ✅ Complete | Registry, aliases, pipe chains |
| Session Manager | ✅ Complete | History, snapshots |
| Security (ReadOnly) | ✅ Complete | 6 blocked categories |
| Security (Validator) | ✅ Complete | Path traversal, injection |
| Chain of Custody | ✅ Complete | Hash-chained audit |
| Terminal Widget (UI) | ✅ Complete | PyQt6, history, autocomplete |
| Commands (15) | ✅ Complete | All VFS-integrated |
| Intelligence | ✅ Complete | Timeline, correlator, ML explainer |
| Package `__init__.py` | ❌ Broken | Wrong export names (CRIT-01, CRIT-02) |

### Visualization Engine — 90% Complete
| Component | Status | Notes |
|-----------|--------|-------|
| Data Processor | ✅ Complete | 50+ column aliases |
| Visualization Engine | ✅ Complete | Cache, threads, export |
| Controller | ✅ Complete | MVC pattern |
| Charts (7) | ✅ Complete | All chart types |
| Heatmap Generator | ✅ Complete | Standalone + widget |
| Investigative Viz (4) | ✅ Complete | Heatmap, graph, flow, treemap |
| Import consistency | ❌ Broken | Absolute imports (MAJ-01) |

### FEPD-OS — 85% Complete
| Component | Status | Notes |
|-----------|--------|-------|
| Case Management | ✅ Complete | Registry sync, creation |
| VFS | ✅ Functional | Edge case with empty dirs |
| OS Detection | ✅ Complete | 5 OS types, weighted scoring |
| OS Shell Emulation | ✅ Complete | 60+ commands across 3 OS types |
| Mutation Blocking | ✅ Complete | 120+ blocked commands |
| Audit Logging | ✅ Functional | Silent error swallowing |
| ML Bridge | ✅ Functional | Deterministic stub |
| Indexer | ✅ Functional | No batching |
| Shell Engine | ⚠️ Mostly | Missing `coc_logger` attr (CRIT-03) |
| Memory Analysis | ⚠️ Partial | Depends on optional modules |
| Report Generation | ⚠️ Partial | Depends on optional module + CRIT-03 |

---

## 9. Integration Assessment

### Terminal ↔ Visualization
**Integration: WEAK**
- No direct integration. The terminal produces text output; the visualization engine consumes event data from SQLite.
- They share the same SQLite case database schema, but there is no coordination protocol.
- The `VisualizationController` could be extended to consume terminal command results, but currently doesn't.

### Terminal ↔ FEPD-OS
**Integration: PARALLEL (NOT INTEGRATED)**
- Both implement the same forensic commands (ls, cd, cat, etc.) independently.
- Terminal uses `VirtualFilesystem` (VNode tree); FEPD-OS uses its own `_file_tree` dict.
- Terminal has richer command output (color-coded, Windows-style formatting); FEPD-OS has OS-native emulation.
- There is no shared command handler base class.

### Visualization ↔ FEPD-OS
**Integration: WEAK**
- FEPD-OS `cmd_status()` checks for visualization output files but doesn't generate them.
- No mechanism for the shell to trigger visualization generation.

### Cross-Cutting Integration Points
| Shared Resource | Terminal | FEPD-OS | Visualization |
|---|---|---|---|
| SQLite case DB | ✅ Reads | ✅ Reads/Creates | ✅ Reads |
| VFS (VNode) | ✅ Uses | Uses own tree | ❌ |
| ML Bridge | ✅ Uses | ✅ Uses | ❌ |
| Chain of Custody | ✅ CoCLogger | ✅ ChainLogger | ❌ |
| Evidence Detection | ❌ | ✅ EvidenceOSDetector | ❌ |

---

## 10. File Inventory

### Terminal System (`src/terminal/`)

| File | Lines | Purpose |
|------|-------|---------|
| `__init__.py` | 43 | Package init with exports |
| `core/__init__.py` | 4 | Core subpackage |
| `core/terminal_engine.py` | 511 | Central command pipeline |
| `core/command_parser.py` | 168 | Input tokenization |
| `core/command_dispatcher.py` | 197 | Command registry & dispatch |
| `core/session_manager.py` | 184 | Session & history management |
| `commands/__init__.py` | 40 | ❌ BROKEN — wrong names |
| `commands/ls.py` | 202 | Directory listing |
| `commands/cd.py` | 129 | Change directory |
| `commands/cat.py` | 128 | File content display |
| `commands/pwd.py` | 32 | Print working directory |
| `commands/find.py` | 131 | File search |
| `commands/grep.py` | 135 | Text search |
| `commands/hash.py` | 114 | Cryptographic hashing |
| `commands/hexdump.py` | 128 | Hex dump |
| `commands/strings.py` | 126 | String extraction |
| `commands/tree.py` | 125 | Directory tree |
| `commands/artifacts.py` | 148 | Artifact cross-reference |
| `commands/connections.py` | 104 | Network connection analysis |
| `commands/explain.py` | 211 | ML explainability |
| `commands/score.py` | 170 | Risk scoring |
| `commands/timeline.py` | 177 | MACB timeline |
| `intelligence/__init__.py` | 19 | ❌ BROKEN — wrong class name |
| `intelligence/artifact_correlator.py` | 231 | Artifact correlation |
| `intelligence/ml_explainer.py` | 208 | Court-explainable ML |
| `intelligence/timeline_engine.py` | 194 | Timeline aggregation |
| `logging/__init__.py` | 4 | Logging subpackage |
| `logging/coc_logger.py` | 237 | Chain of custody audit |
| `security/__init__.py` | 4 | Security subpackage |
| `security/read_only_guard.py` | 187 | Evidence immutability |
| `security/command_validator.py` | 152 | Pre-execution validation |
| `ui/__init__.py` | 4 | UI subpackage |
| `ui/terminal_widget.py` | 365 | PyQt6 terminal widget |

**Terminal Subtotal: ~4,232 lines across 33 files**

### Visualization Engine (`src/visualization/`)

| File | Lines | Purpose |
|------|-------|---------|
| `__init__.py` | 14 | Package init |
| `heatmap_generator.py` | 233 | Standalone heatmap generator |
| `heatmap_widget.py` | 227 | PyQt6 heatmap widget |
| `investigative_visualizations.py` | 837 | 4 advanced forensic visualizations |
| `charts/__init__.py` | 14 | Charts subpackage |
| `charts/artifact_distribution.py` | ~64 | Pie/donut chart |
| `charts/attack_surface_chart.py` | ~160 | Multi-panel attack surface |
| `charts/connections_graph.py` | ~140 | Entity relationship graph |
| `charts/heatmap_chart.py` | ~83 | Activity heatmap |
| `charts/severity_chart.py` | ~60 | Severity bar chart |
| `charts/timeline_chart.py` | ~80 | Timeline line chart |
| `charts/user_activity_chart.py` | ~72 | User activity heatmap |
| `engine/__init__.py` | 4 | Engine subpackage |
| `engine/data_processor.py` | 362 | Data normalization |
| `engine/visualization_engine.py` | 351 | Chart factory & caching |
| `ui/__init__.py` | 4 | UI subpackage |
| `ui/visualization_controller.py` | 155 | MVC controller |

**Visualization Subtotal: ~2,860 lines across 17 files**

### FEPD-OS (`src/fepd_os/`)

| File | Lines | Purpose |
|------|-------|---------|
| `__init__.py` | 4 | Package init |
| `audit.py` | 41 | SQLite audit logger |
| `case_context.py` | 316 | Case management & registry |
| `cli_entry.py` | 30 | CLI entry point (REPL) |
| `evidence_os.py` | 566 | OS detection & mutation blocking |
| `evidence_shell.py` | 1114 | OS-native shell emulation |
| `indexer.py` | 49 | Evidence file indexer |
| `ml_bridge.py` | 25 | Deterministic ML scoring stub |
| `shell.py` | 2426 | Main shell engine |
| `vfs.py` | 84 | Virtual filesystem |

**FEPD-OS Subtotal: ~4,655 lines across 10 files**

---

### Grand Total: ~11,747 lines across 60 files

---

## Recommendations (Priority Order)

1. **Fix CRIT-01**: Update `commands/__init__.py` to use correct function names
2. **Fix CRIT-02**: Update `intelligence/__init__.py` to export `CorrelationResult`
3. **Fix CRIT-03**: Add `self.coc_logger = None` to `FEPDShellEngine.__init__()`
4. **Fix MAJ-01**: Convert all chart module imports to relative imports
5. **Fix MAJ-05**: Add public `exists()` and `is_dir()` to `VirtualFilesystem`
6. **Consolidate**: Consider unifying the two parallel command systems (terminal commands vs evidence shell) around a shared command handler interface
7. **Fix MIN-03**: Use evidence timestamps in DIR output instead of `datetime.now()`
8. **Fix MIN-06**: Replace bare `except:` with `except Exception:`
9. **Fix MIN-09**: Resolve relative paths in FEPD-mode `cmd_cd()`

---

*End of Audit Report*
