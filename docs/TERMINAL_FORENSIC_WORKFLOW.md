# FEPD Terminal - Forensic Workflow Guide

## 🎯 Core Principle

**The FEPD Terminal is a forensic-safe clone of the suspect system's native shell.**

Every command operates ONLY on forensic evidence. The analyst's operating system is never touched.

---

## 🔒 Forensic Integrity Rules

1. ✅ **READ-ONLY MODE**: All write commands are blocked
2. ✅ **EVIDENCE PATHS ONLY**: No analyst filesystem paths are exposed  
3. ✅ **CHAIN OF CUSTODY**: All actions are logged
4. ✅ **CASE ISOLATION**: Terminal is inactive until a case is loaded
5. ✅ **EXPLICIT MOUNTING**: Evidence must be manually mounted (no auto-mount)

---

## 📋 Terminal Startup Behavior

### Initial State
```
╔════════════════════════════════════════════════════════════════════════╗
║                     FEPD Forensic Evidence Terminal                   ║
╚════════════════════════════════════════════════════════════════════════╝

⚖️  All data shown is from forensic evidence only.
🔒 All commands operate in READ-ONLY mode.
🛡️  Evidence integrity protection is active.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Getting Started:
  cases              List available forensic cases
  use case <name>    Load a case for investigation
  help               Show available commands

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

C:\>
```

**Prompt Format (No Evidence)**: `C:\>`  
**Filesystem**: Empty until evidence is mounted

---

## 🗂️ Workflow: Loading a Case

### Step 1: List Available Cases
```cmd
C:\> cases

Available Forensic Cases:
  1. corp-leak        Corporate Data Leak Investigation
  2. malware-2024     Ransomware Incident Analysis
  3. insider-threat   Employee Misconduct Case
```

### Step 2: Load a Case
```cmd
C:\> use case corp-leak

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Case Loaded - Evidence Metadata Detected
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Evidence System: DESKTOP-ABC123
OS Version:      Windows 10 Pro Build 19045
User Context:    alice.johnson
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  Evidence NOT mounted - File system is currently EMPTY.

To access evidence files:
  1. detect              → Scan for evidence images (.E01/.DD/.IMG/.MEM)
  2. mount <index|file>  → Mount evidence in READ-ONLY mode

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

C:\>
```

**Important**: Evidence is NOT auto-mounted. The filesystem remains empty.

---

## 📂 Workflow: Mounting Evidence

### Attempting File Commands Before Mount
```cmd
C:\> dir

Evidence not mounted. File system is empty.

To mount evidence:
  1. detect          → Scan for evidence images
  2. mount <index>   → Mount evidence in READ-ONLY mode

C:\>
```

### Step 3: Detect Evidence Images
```cmd
C:\> detect

Scanning case directory for evidence files...

Detected Evidence Files:
  Index  Type  Size        Hash (SHA256)                              Path
  -----  ----  ----------  -----------------------------------------  ------------------
  1      E01   4.2 GB      a3f5e8...                                  suspect-laptop.E01
  2      DD    1.8 GB      b7c2d9...                                  usb-drive.dd
  3      MEM   8.0 GB      f1e4a7...                                  memory-dump.mem

Use: mount <index> or mount <filename>

C:\>
```

### Step 4: Mount Evidence
```cmd
C:\> mount 1

Mounting: suspect-laptop.E01
Validating integrity...
Computing hash...
Mounting as READ-ONLY...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Evidence Mounted Successfully
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
File:          suspect-laptop.E01
Mounted as:    C:\
Mode:          READ-ONLY
Integrity:     Protected ✓
Hash:          a3f5e8d2b1c4f7a9...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

C:\>
```

---

## 💻 Available Commands (After Mount)

### Directory Navigation
```cmd
C:\> dir
 Volume in drive C is EVIDENCE
 Volume Serial Number is FEPD-2026

 Directory of C:\

01/15/2024  02:30 PM    <DIR>          Users
01/15/2024  02:30 PM    <DIR>          Windows
01/15/2024  02:30 PM    <DIR>          Program Files
               0 File(s)              0 bytes
               3 Dir(s)   [EVIDENCE - Read Only]

C:\> cd Users\alice.johnson\Desktop

C:\Users\alice.johnson\Desktop>
```

### File Operations (READ-ONLY)
```cmd
C:\Users\alice.johnson\Desktop> type confidential.txt
[File contents displayed here...]

C:\Users\alice.johnson\Desktop> tree /f
Folder PATH listing
Volume serial number is FEPD-2026
C:\USERS\ALICE.JOHNSON\DESKTOP
│   confidential.txt
│   report.docx
│
└───Screenshots
        screenshot1.png
        screenshot2.png

C:\Users\alice.johnson\Desktop> find "password" *.txt
Searching for "password" in evidence...
Use "search password" for FEPD full-text search.
```

### Windows-Like Commands
- `dir` - List directory contents
- `cd <path>` - Change directory
- `tree` - Show directory tree
- `type <file>` - Display file contents
- `more <file>` - Page through file
- `find <pattern>` - Search in files
- `where <pattern>` - Locate files
- `cls` - Clear screen
- `pwd` - Show current path
- `echo <text>` - Display text

---

## ⛔ Blocked Commands

All write operations are blocked to preserve evidence integrity:

```cmd
C:\Users\alice.johnson\Desktop> del confidential.txt

⛔ Write operation blocked – Evidence integrity preserved.

Command: del
Reason:  'del' is a write command that would modify evidence

All write operations are disabled in forensic mode.
Evidence must remain unmodified to maintain chain of custody.

C:\Users\alice.johnson\Desktop>
```

### Blocked Command Categories
- **File Modifications**: `del`, `copy`, `move`, `rename`, `mkdir`, `rmdir`
- **Permission Changes**: `icacls`, `cacls`, `takeown`, `attrib`
- **System Modifications**: `format`, `diskpart`, `chkdsk`, `reg`
- **Network Modifications**: `netsh`, `route`
- **Process Control**: `taskkill`, `shutdown`, `sc`, `net`
- **Scripting**: `powershell`, `cmd`, `wscript`

---

## 🔍 FEPD Forensic Commands

Beyond Windows commands, FEPD provides forensic-specific commands:

```cmd
# Search across all evidence
C:\> search "password"

# View timeline of events
C:\> timeline

# Show anomalies detected by ML
C:\> anomalies

# Display IOC matches
C:\> iocs

# Generate forensic report
C:\> forensic_report

# View UEBA behavioral analysis
C:\> ueba

# Memory analysis
C:\> memscan

# Chain of custody audit
C:\> chain
```

---

## 🛡️ Path Protection

**CRITICAL**: The terminal NEVER exposes analyst filesystem paths.

All paths displayed are **evidence-native paths** only:

✅ **Correct**: `C:\Users\Alice\Desktop\malware.exe`  
❌ **NEVER**: `C:\Analyst\FEPD\cases\corp-leak\evidence\...`

Any attempt to expose analyst paths is blocked and logged as an integrity violation.

---

## 📊 Example Investigation Session

```cmd
C:\> cases
Available Forensic Cases:
  1. insider-threat

C:\> use case insider-threat
✓ Case Loaded: insider-threat

C:\> detect
Detected Evidence Files:
  1  E01  2.5 GB  employee-laptop.E01

C:\> mount 1
✓ Evidence mounted as C:\
✓ Read-only mode active

C:\> cd Users\john.doe\Downloads

C:\Users\john.doe\Downloads> dir
 Directory of C:\Users\john.doe\Downloads

01/20/2024  03:45 PM         2,456,789 company-data.zip
01/20/2024  04:12 PM           892,145 transfer.exe
               2 File(s)      3,348,934 bytes

C:\Users\john.doe\Downloads> search "confidential"
Searching evidence for: confidential
Found 47 matches across 12 files

C:\Users\john.doe\Downloads> timeline
Showing activity timeline for evidence...
[Timeline visualization]

C:\Users\john.doe\Downloads> forensic_report
Generating comprehensive forensic report...
✓ Report saved: reports/insider-threat-2024.pdf
```

---

## 📝 Summary

1. **Terminal starts empty** - No case loaded
2. **Load case** - `use case <name>`
3. **Case loaded but NO auto-mount** - Filesystem remains empty
4. **Detect evidence** - `detect` to scan for images
5. **Mount evidence** - `mount <index>` to make files accessible
6. **Investigate** - Use Windows commands and FEPD tools
7. **All operations are READ-ONLY** - Write commands blocked
8. **Evidence paths only** - Analyst paths never exposed

This workflow ensures **forensic integrity** at every step while providing a familiar Windows CMD experience.
