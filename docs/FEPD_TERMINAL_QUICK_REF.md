# FEPD Terminal - Quick Reference Card

## 🚀 Quick Start

```bash
# Launch terminal
python src/fepd_os/cli_entry.py

# Create demo case
python create_demo_case.py
```

## 📋 Common Workflows

### Initial Setup
```
fepd:global$ create_case corp-leak
fepd:global$ use case corp-leak
fepd:corp-leak$ 
```

### User Investigation
```
fepd:corp-leak$ users
alice
bob

fepd:corp-leak$ use bob
fepd:corp-leak[bob]$ tree Desktop
Desktop
├── report.docx
├── payload.exe [0.93]
└── exfil_tool.py [0.78]

fepd:corp-leak[bob]$ explain payload.exe
SCORE: 0.93
REASONS: executable file type, suspicious filename, outlier entropy
```

### Timeline Analysis
```
fepd:corp-leak$ timeline
2025-12-15T23:45:00Z | FILE_DELETED | exfil_tool.py removed
2025-12-15T23:00:00Z | NETWORK_CONN | Large data transfer detected
2025-12-15T22:40:30Z | FILE_ACCESS | credentials.txt read by payload.exe
```

### File Inspection
```
fepd:corp-leak[bob]$ ls Desktop
report.docx
payload.exe [0.93]

fepd:corp-leak[bob]$ stat payload.exe
path: Users/bob/Desktop/payload.exe
owner: bob
size: 45056
hash: a3f2b8c9d1e0f7a6b5c4d3e2f1a0b9c8...
ml_score: 0.93

fepd:corp-leak[bob]$ hash payload.exe
a3f2b8c9d1e0f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2
```

### Search Operations
```
fepd:corp-leak$ find payload
Users/bob/Desktop/payload.exe

fepd:corp-leak$ search exe
Users/bob/Desktop/payload.exe
Users/bob/Downloads/tor-browser.exe
System/Windows/System32/cmd.exe
```

### Context Switching
```
fepd:corp-leak[bob]$ exit_user
[user context cleared]

fepd:corp-leak$ use alice
[Context switched to user: alice]

fepd:corp-leak[alice]$ ls Desktop
budget.xlsx
```

## 🎯 Key Commands at a Glance

| Category | Commands |
|----------|----------|
| **Navigation** | `ls`, `cd`, `pwd`, `tree`, `find` |
| **Inspection** | `stat`, `cat`, `hash`, `hexdump`, `strings` |
| **Timeline** | `timeline` |
| **Search** | `search`, `find` |
| **ML** | `score`, `explain` |
| **Case** | `cases`, `create_case`, `use case` |
| **User** | `users`, `use`, `exit_user` |
| **Help** | `help` |

## 🔒 Immutability Enforcement

### ❌ Blocked Commands
```
fepd:corp-leak$ rm payload.exe
[DENIED] Evidence is immutable.
FEPD Terminal is read-only by design.
Use 'export' to copy data outside the case.
```

All write operations are **automatically blocked**:
- `rm`, `mv`, `cp`, `touch`
- `vi`, `nano`, `emacs`
- File redirection (`>`)
- Any state modification

## 📊 ML Risk Scores

Scores range from **0.0** (benign) to **1.0** (high risk):

```
file.txt       [0.12]  ⚪ Low risk
script.ps1     [0.56]  🟡 Medium risk
payload.exe    [0.93]  🔴 High risk
```

### Score Explanations
```
fepd:corp-leak$ explain payload.exe
SCORE: 0.93
REASONS: 
  - executable file type
  - suspicious filename
  - outlier entropy/behavior model
```

## 🔍 Advanced Examples

### Cross-User Comparison
```
fepd:corp-leak$ use alice
fepd:corp-leak[alice]$ ls Desktop
budget.xlsx
strategy.pdf

fepd:corp-leak[alice]$ exit_user
fepd:corp-leak$ use bob
fepd:corp-leak[bob]$ ls Desktop
payload.exe [0.93]
exfil_tool.py [0.78]
```

### Deep Inspection
```
fepd:corp-leak$ stat Users/bob/Desktop/payload.exe
fepd:corp-leak$ hash Users/bob/Desktop/payload.exe
fepd:corp-leak$ hexdump Users/bob/Desktop/payload.exe
fepd:corp-leak$ strings Users/bob/Desktop/payload.exe | grep -i http
```

### Directory Tree
```
fepd:corp-leak$ tree Users
Users
├── alice
│   ├── Desktop
│   │   └── budget.xlsx
│   ├── Documents
│   │   └── strategy.pdf
│   └── Downloads
│       └── meeting_notes.docx
└── bob
    ├── Desktop
    │   ├── payload.exe
    │   └── report.docx
    └── Documents
        └── credentials.txt
```

## 📝 Audit Trail

Every command is logged:

```python
import sqlite3
conn = sqlite3.connect('data/indexes/corp-leak.db')
cur = conn.cursor()
cur.execute("SELECT ts, user_context, command, args FROM audit_logs ORDER BY ts DESC")
for row in cur.fetchall():
    print(f"{row[0]} | {row[1]} | {row[2]} {row[3]}")
```

**Example output:**
```
2026-01-10T15:30:45Z | bob | ls | Desktop
2026-01-10T15:30:12Z | bob | explain | payload.exe
2026-01-10T15:29:58Z |     | use | bob
2026-01-10T15:29:45Z |     | users |
```

## 🎨 Prompt Anatomy

```
fepd:<case_name>[<user>]$
     \_________/ \____/
         |          |
    Case context   User context
                   (optional)
```

**Examples:**
- `fepd:global$` - No case selected
- `fepd:corp-leak$` - Case selected, no user
- `fepd:corp-leak[bob]$` - Case + user context

## 💡 Pro Tips

1. **Tab Completion** - Use Tab to autocomplete commands
2. **History** - Use ↑ ↓ arrows for command history
3. **Help** - Type `help` for full command reference
4. **Exit** - Type `quit` or `exit` to leave terminal

## 🔗 Integration

### CLI Mode
```bash
python src/fepd_os/cli_entry.py
```

### Python API
```python
from src.fepd_os.shell import FEPDShellEngine

engine = FEPDShellEngine('.')
engine.dispatch('create_case test')
engine.dispatch('use case test')
result = engine.dispatch('ls /')
print(result)
```

### UI Integration
```python
from ui.fepd_terminal_widget import FEPDTerminalWidget

# Add to PyQt6 UI
terminal = FEPDTerminalWidget(workspace_root='.')
tabs.addTab(terminal, "🖥 FEPD Terminal")
```

## 🚨 Safety Guarantees

✅ **Read-only** - Zero evidence modification risk  
✅ **Audited** - Every command logged with cryptographic hash  
✅ **Explainable** - No ML black boxes  
✅ **Chain of custody** - Origin tracking for all artifacts  
✅ **Court-defensible** - Complete provenance trail

---

**FEPD Terminal** - Your forensic ghost shell. See everything. Change nothing.
