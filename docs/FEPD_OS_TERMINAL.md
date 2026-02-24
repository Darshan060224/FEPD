# FEPD Forensic Operating System Terminal

## Overview

The FEPD Terminal is a **read-only forensic shell** that lets analysts walk inside evidence safely. It provides a terminal interface bound to case contexts, operating on unified artifact indexes rather than raw disk images.

## Architecture

```
Evidence (E01/DD/IMG/DMG/PCAP/MEM)
        ↓ (read-only)
Artifact Extractors
        ↓
Unified Artifact Index (SQLite)
        ↓
Virtual Filesystem + Timeline Graph
        ↓
FEPD Shell Engine
        ↓
ML Bridge + Explainability
```

The shell **never touches raw evidence** after indexing.

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Launch Terminal

```bash
python src/fepd_os/cli_entry.py
```

### 3. Create and Mount a Case

```
fepd:global$ create_case corp-leak
case corp-leak created

fepd:global$ use case corp-leak
[Context switched to case: corp-leak]

fepd:corp-leak$ 
```

### 4. Index Evidence (Python API)

```python
from src.fepd_os.case_context import CaseContextManager
from src.fepd_os.indexer import EvidenceIndexer

cc = CaseContextManager('.')  # workspace root
cc.create_case('corp-leak')
idx = EvidenceIndexer(cc.case_db_path('corp-leak'))

# Add file records from evidence
idx.add_file_record(
    'data/cases/case010/Users/bob/Desktop/report.docx',
    origin='E01',
    owner='bob'
)
idx.add_file_record(
    'data/cases/case010/Users/bob/Desktop/payload.exe',
    origin='E01',
    owner='bob'
)
```

### 5. Navigate Evidence

```
fepd:corp-leak$ users
alice
bob

fepd:corp-leak$ use bob
[Context switched to user: bob]

fepd:corp-leak[bob]$ ls Desktop
report.docx
payload.exe [0.93]

fepd:corp-leak[bob]$ explain payload.exe
SCORE: 0.93
REASONS: executable file type, suspicious filename, outlier entropy/behavior model

fepd:corp-leak[bob]$ hash payload.exe
a3f2b8c9d1e0f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2
```

## Prompt Format

```
fepd:<case_name>[<user>]$
```

- **No case selected**: `fepd:global$`
- **Case selected**: `fepd:corp-leak$`
- **User context active**: `fepd:corp-leak[bob]$`

**Rules:**
- No implicit default user
- User context appears **only after** `use <user>`
- Every command is audit-logged
- All operations are **read-only**

## Command Reference

### Navigation

| Command | Description |
|---------|-------------|
| `ls [path]` | List directory contents with ML scores |
| `cd <path>` | Change virtual directory |
| `pwd` | Print working directory |
| `tree [path]` | Show directory tree (3 levels) |
| `find <name>` | Find files by name pattern |

### Inspection

| Command | Description |
|---------|-------------|
| `stat <item>` | Show file metadata (size, hash, owner, ML score) |
| `cat <file>` | View file content (viewer only, max 100KB) |
| `hash <file>` | Display SHA-256 hash |
| `hexdump <file>` | Hex viewer (first 256 bytes) |
| `strings <file>` | Extract printable strings (min 4 chars) |

### Timeline & Search

| Command | Description |
|---------|-------------|
| `timeline` | Show recent events (50 most recent) |
| `search <keyword>` | Search files by keyword |

### ML Intelligence

| Command | Description |
|---------|-------------|
| `score <item>` | Get ML risk score (0.0-1.0) |
| `explain <item>` | Show anomaly explanation with reasons |

### Case Control

| Command | Description |
|---------|-------------|
| `cases` | List all available cases |
| `create_case <name>` | Create new case index |
| `use case <name>` | Switch to case context |
| `users` | List users in current case |
| `use <user>` | Switch to user context |
| `exit_user` | Clear user context |

### Help & Exit

| Command | Description |
|---------|-------------|
| `help` | Show command reference |
| `quit` / `exit` | Leave terminal |

## Immutability Rules

The FEPD Terminal is **100% read-only**. The following commands are **BLOCKED**:

- `rm`, `mv`, `cp`, `touch` - Evidence modification denied
- `vi`, `nano` - No editors allowed
- `>` redirection - No file writes
- Any state-changing operations

**Attempt:**
```
fepd:corp-leak[bob]$ rm payload.exe
```

**Response:**
```
[DENIED] Evidence is immutable.
FEPD Terminal is read-only by design.
Use 'export' to copy data outside the case.
```

## Audit Logging

Every command is logged to the case database for **court defensibility**:

**Logged fields:**
- Timestamp (UTC ISO format)
- Case name
- User context
- Command
- Arguments
- Result hash (SHA-256 of output)

**Query audit logs:**

```python
import sqlite3
conn = sqlite3.connect('data/indexes/corp-leak.db')
cur = conn.cursor()
cur.execute("SELECT ts, user_context, command, args FROM audit_logs ORDER BY ts DESC LIMIT 10")
for row in cur.fetchall():
    print(row)
conn.close()
```

## ML Explainability

The ML Bridge provides **deterministic, explainable scoring**:

```
fepd:corp-leak[bob]$ explain payload.exe
SCORE: 0.93
REASONS: executable file type, suspicious filename, outlier entropy/behavior model
```

**Scoring factors:**
- File type (executables flagged)
- Filename patterns (suspicious keywords)
- Entropy analysis (compressed/packed files)
- Behavioral model (off-hours creation, network activity)

Scores range from **0.0 (benign)** to **1.0 (high risk)**.

## Virtual Filesystem

The VFS maps the artifact index to a familiar tree structure:

```
/
├── Users/
│   ├── alice/
│   │   ├── Desktop/
│   │   ├── Documents/
│   ├── bob/
│   │   ├── Desktop/
│   │   │   ├── report.docx
│   │   │   └── payload.exe [0.93]
├── System/
├── Network/
├── Memory/
```

**Key features:**
- Backed by index, not raw disk
- Cross-evidence correlation
- Timeline-aware navigation
- ML scores attached to artifacts

## Database Schema

Each case has a SQLite index with:

**`files` table:**
- `id`, `path`, `origin`, `owner`, `size`, `created`, `modified`, `hash`, `ml_score`, `ml_explain`

**`users` table:**
- `name`

**`events` table:**
- `id`, `ts`, `type`, `details`

**`audit_logs` table:**
- `id`, `ts`, `case_name`, `user_context`, `command`, `args`, `result_hash`

## Analyst Experience

> "I am inside the system, but I am a ghost.  
> I can see everything.  
> I can change nothing.  
> Every answer is evidence-backed.  
> Every anomaly is explained."

This is not just a UI feature.  
**This is your Forensic Operating System.**

## Integration with FEPD UI

Add a dedicated tab to the main UI:

```
[ Overview ] [ Timeline ] [ Artifacts ] [ ML ] [ 🖥 FEPD Terminal ]
```

The terminal provides:
- Command history (↑ ↓ navigation)
- Tab autocomplete
- Color-coded risk scores
- Copy/export output
- Jump-to-artifact links
- Timeline anchors

## Future Enhancements

- [ ] `trace <item>` - Show artifact provenance chain
- [ ] `graph <item>` - Visualize relationships
- [ ] `compare user1 user2` - Side-by-side analysis
- [ ] `export <item>` - Extract artifacts for external tools
- [ ] `report` - Generate terminal session report
- [ ] `rewind <time>` - Navigate timeline
- [ ] Network correlation commands
- [ ] Memory analysis integration
- [ ] Cross-case pivot queries

## Safety Guarantees

✅ **No evidence modification** - All operations are read-only  
✅ **Full audit trail** - Every action logged with cryptographic hash  
✅ **Explainable ML** - No black-box decisions  
✅ **Chain of custody** - Origin tracking for every artifact  
✅ **Court-defensible** - Complete command history with timestamps

---

**FEPD Terminal** - Walk inside evidence. Leave no trace. Explain everything.
