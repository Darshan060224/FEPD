# FEPD OS - Investigator Quick Reference Card

**Version:** 1.0 Constitutional Release  
**Prompt:** `fepd:<case>[<user>]$`

---

## 🚀 Getting Started (30 seconds)

```bash
# 1. Create case
fepd:global[unknown]$ create_case MyCase

# 2. Switch to case
fepd:global[unknown]$ use case MyCase

# 3. Auto-detect evidence
fepd:MyCase[unknown]$ detect

# 4. Mount evidence
fepd:MyCase[unknown]$ mount /path/to/evidence.e01

# 5. Start investigating
fepd:MyCase[unknown]$ ls /
```

---

## 📁 Navigation (Like Linux)

```bash
ls              # List files
ls /Windows     # List specific directory
cd /Users       # Change directory
pwd             # Show current directory
tree            # Show directory tree
find malware    # Find files by name
```

---

## 🔍 Inspection (Read-Only)

```bash
stat file.exe           # Show metadata (size, dates, hash)
cat config.txt          # View text file
hash suspicious.dll     # SHA-256 hash
hexdump payload.bin     # Hex view
strings backdoor.exe    # Extract printable strings
```

---

## ⏱️ Timeline Analysis

```bash
timeline                        # Last 50 events
timeline --user jdoe            # Filter by user
timeline --process cmd.exe      # Filter by process
timeline --type evtx            # Filter by artifact type
timeline --limit 100            # Show 100 events
```

---

## 🔎 Search

```bash
search malware                  # Search all files
search *.dll --memory           # Search memory dumps only
search NTUSER.DAT --registry    # Search registry hives only
search Security.evtx --evtx     # Search event logs only
```

---

## 💻 Virtual System Reconstruction

```bash
ps              # Process list (from Prefetch, Memory, EVTX)
netstat         # Network connections (from Memory, Browser)
sessions        # User logon/logoff events (from EVTX)
services        # Windows services (from Registry)
startup         # Persistence mechanisms (from Registry)
users           # List all users
```

---

## 🧠 UEBA (Behavior Analytics)

```bash
# Step 1: Build baseline (do this ONCE per case)
ueba build

# Step 2: Check status
ueba status

# Step 3: Detect anomalies
ueba anomalies

# Step 4: Profile specific user
ueba user jdoe
```

**What UEBA Detects:**
- Off-hours activity (e.g., 3 AM logins)
- Unusual process executions
- New file access patterns
- Behavioral deviations from baseline

---

## 🤖 ML Intelligence

```bash
score malware.exe       # Get risk score (0.0 = safe, 1.0 = critical)
explain malware.exe     # Why is this risky? (with evidence)
```

**Example Output:**
```
[ML Score: 0.94] Critical anomaly

Anomaly detected: Malicious persistence
Evidence:
  - Registry Run key: HKCU\...\Run\malware.exe
  - Prefetch: MALWARE.EXE-A3F5B8C2.pf
  - Off-hours execution: 2025-01-22 03:16
Confidence: 0.94
Recommendation: Remove persistence, isolate system
```

---

## 💾 Evidence Management

```bash
# Auto-detect evidence files
detect

# Mount evidence (read-only)
mount /evidence/disk01.e01
mount --all

# Verify integrity
validate /evidence/disk01.e01
```

**Supported Evidence:**
- E01, DD, RAW (disk images)
- MEM, DMP (memory dumps)
- EVTX (event logs)
- Registry hives (NTUSER.DAT, SYSTEM, SOFTWARE, SAM, SECURITY)
- Prefetch (*.pf)

---

## 🗂️ Case Management

```bash
cases                   # List all cases
create_case LoneWolf    # Create new case
use case LoneWolf       # Switch to case
use administrator       # Switch user context
exit_user               # Clear user context
```

---

## ⚠️ What You CANNOT Do (By Design)

```bash
rm file.txt         # ❌ DENIED - Evidence is immutable
mv old.txt new.txt  # ❌ DENIED - Evidence is immutable
cp file.txt backup  # ❌ DENIED - Evidence is immutable
vi file.txt         # ❌ DENIED - Evidence is immutable
```

**Why?** All operations are read-only to preserve evidence integrity and chain of custody.

---

## 🎯 Common Investigation Workflows

### Workflow 1: Quick Triage (5 minutes)
```bash
create_case Triage01
use case Triage01
detect
mount --all
timeline
ueba build
ueba anomalies
```

### Workflow 2: User Behavior Analysis
```bash
use case MyCase
users                       # Identify users
use suspicious_user         # Set context
sessions                    # Check logon times
ueba user suspicious_user   # Behavioral profile
timeline --user suspicious_user
```

### Workflow 3: Malware Hunt
```bash
search *.exe
search *.dll --memory
startup                     # Check persistence
ps                          # Check processes
score /path/to/suspicious.exe
explain /path/to/suspicious.exe
```

### Workflow 4: Lateral Movement Detection
```bash
sessions                    # Look for unusual logons
timeline --type evtx        # Check Security.evtx
netstat                     # Check network activity
ueba anomalies              # Detect unusual behavior
```

---

## 🏆 Best Practices

1. **Always build UEBA baseline first**
   ```bash
   ueba build
   ```

2. **Use filters to reduce noise**
   ```bash
   timeline --user admin --process powershell.exe
   ```

3. **Validate evidence before analysis**
   ```bash
   detect
   validate /evidence/disk01.e01
   ```

4. **Switch user context for focused analysis**
   ```bash
   use administrator
   timeline
   ```

5. **Combine commands for comprehensive view**
   ```bash
   ps
   startup
   netstat
   ueba anomalies
   ```

---

## 🆘 Troubleshooting

### No timeline events?
```bash
[No timeline events]
[HINT] Evidence may need ingestion. Check if artifacts were extracted.
```
**Solution:** Mount evidence first, then wait for ingestion.

### No process data?
```bash
[No process data available]
[HINT] Process reconstruction requires Prefetch files (.pf)
[HINT] Run: search *.pf
```
**Solution:** Ensure Prefetch files are extracted from evidence.

### UEBA not trained?
```bash
[ERROR] UEBA baseline not built
[HINT] Run: ueba build
```
**Solution:** Build baseline first (needs >50 events).

### No case selected?
```bash
No case selected.
[HINT] Run: use case <name>
[HINT] Or: create_case <name>
```
**Solution:** Create or select a case first.

---

## 🔑 Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Tab` | Command completion |
| `Ctrl+C` | Cancel current command |
| `↑` / `↓` | Command history |
| `Ctrl+L` | Clear screen |

---

## 📊 Understanding ML Scores

| Score | Risk Level | Meaning |
|-------|-----------|---------|
| 0.0 - 0.3 | Low | Normal behavior, low suspicion |
| 0.3 - 0.6 | Medium | Slightly unusual, monitor |
| 0.6 - 0.8 | High | Unusual behavior, investigate |
| 0.8 - 1.0 | Critical | Highly anomalous, immediate action |

---

## 📖 More Help

```bash
help        # Full command reference
```

---

## 🎓 Pro Tips

1. **Pipe-like workflow**: Use sequential commands
   ```bash
   users
   use suspicious_user
   timeline --user suspicious_user
   ueba user suspicious_user
   ```

2. **Context matters**: Set user context for better filtering
   ```bash
   use administrator
   timeline        # Now filtered to administrator
   ```

3. **UEBA is your friend**: It learns normal, detects unusual
   ```bash
   ueba build      # Do this early
   ueba anomalies  # Check periodically
   ```

4. **ML scores guide priorities**: Start with highest scores
   ```bash
   score file1.exe     # 0.94 - investigate first
   score file2.exe     # 0.12 - low priority
   ```

5. **Timeline + UEBA = Complete picture**
   ```bash
   timeline --user attacker
   ueba user attacker
   ```

---

## 📞 Quick Reference Summary

**Must-Run Commands:**
1. `create_case <name>` or `use case <name>`
2. `detect` (find evidence)
3. `mount <path>` (mount evidence)
4. `ueba build` (build baseline)
5. `ueba anomalies` (detect threats)

**Investigation Trinity:**
- `timeline` - What happened?
- `ps / netstat / sessions` - System state reconstruction
- `ueba anomalies` - What's unusual?

**Evidence Trinity:**
- `detect` - Find it
- `mount` - Access it (read-only)
- `validate` - Verify it

---

**Remember:** 
- 🔒 All operations are read-only
- 📝 Chain of custody is automatic
- 🧠 ML is explainable, not a black box
- ⚖️ Court-defensible by design

**Motto:** *If the GUI disappears, the investigation continues.*

---

**Print this card and keep it near your workstation!**
