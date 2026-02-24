# Memory Dump Analysis in FEPD

## Overview

FEPD now supports native analysis of memory dump files (.mem, .dmp, .raw) without requiring external tools like Volatility. The system automatically detects memory dumps and routes them to the memory analyzer instead of the disk image handler.

## Supported Formats

- `.mem` - Raw memory dumps
- `.dmp` - Windows memory dumps
- `.raw` - Raw memory captures
- `.dump` - Generic memory dumps
- `.memory` - Memory snapshot files

## How It Works

When you load a memory dump file in FEPD:

1. **Auto-Detection**: The system detects the file extension and identifies it as a memory dump
2. **Pattern-Based Analysis**: Uses regex patterns to extract artifacts from raw memory
3. **Quick Scan**: Analyzes the first 500MB for rapid triage (~13 seconds)
4. **Artifact Storage**: Results are stored in `case_workspace/memory_analysis/`
5. **Database Integration**: Artifacts are indexed for FEPD Terminal commands

## What Gets Extracted

### Processes
- Pattern: `[\x20-\x7E]{4,64}\.exe\x00`
- Searches ±64 bytes for PID
- Example: `notepad.exe`, `chrome.exe`, `Zyklon.exe`

### Network Connections
- Pattern: `(?:\d{1,3}\.){3}\d{1,3}`
- Validates octets (0-255)
- Searches ±16 bytes for ports
- Example: `127.0.0.1`, `52.173.134.133`

### URLs
- Pattern: `https?://[^\x00\x20]{4,256}`
- Extracts HTTP/HTTPS URLs
- Example: `https://malware.com/payload`

### Registry Keys
- Pattern: `HKEY_[A-Z_]+\\[^\x00]{4,256}`
- Finds Windows registry references
- Example: `HKEY_LOCAL_MACHINE\Software\Malware`

### Strings
- Extracts printable ASCII strings (min 8 characters)
- Useful for finding file paths, commands, etc.

## Usage

### Method 1: Case Creation (Automatic)

1. **Create New Case** → Select memory dump file
2. **Automatic Analysis**: FEPD detects the file type and runs quick scan
3. **View Results**: Check `memory_analysis/` directory or use Terminal

### Method 2: FEPD Terminal (Manual)

```bash
# Quick scan (first 500MB, ~13 seconds)
fepd:case[user]$ memscan /path/to/memdump.mem

# Full analysis (complete dump, 5-10 minutes)
fepd:case[user]$ memscan /path/to/memdump.mem --full

# Auto-detect from database
fepd:case[user]$ memscan
```

### Method 3: Terminal Commands

After analysis, use standard commands to view artifacts:

```bash
# View processes from memory
fepd:case[user]$ ps
# Shows processes from both EVTX logs AND memory dump

# View network connections
fepd:case[user]$ netstat
# Shows IPs from browser history, logs, AND memory dump

# View all artifacts
fepd:case[user]$ ls memory_analysis/
```

## Output Files

### Quick Scan
```
case_workspace/
  memory_analysis/
    quick_scan_results.json     # Processes, IPs, basic artifacts
    memory_artifacts.json        # Database for Terminal commands
```

### Full Analysis
```
case_workspace/
  memory_analysis/
    full_analysis_TIMESTAMP.json    # Complete artifact dump
    full_analysis_TIMESTAMP.txt     # Human-readable report
    memory_artifacts.json           # Updated database
```

## Performance

| Dump Size | Quick Scan | Full Analysis |
|-----------|-----------|---------------|
| 4 GB      | ~13 sec   | ~2 min        |
| 8 GB      | ~13 sec   | ~4 min        |
| 16 GB     | ~13 sec   | ~8 min        |

**Note**: Quick scan only analyzes first 500MB regardless of file size.

## Example Output

### Quick Scan
```
FEPD Memory Dump Analyzer
File: memdump.mem
Mode: Quick Scan
Size: 16.72 GB

Processes Found: 238
  - notepad.exe
  - Zyklon.exe (MALWARE DETECTED)
  - chrome.exe
  - explorer.exe
  ... and 234 more

Network IPs: 194
  - 127.0.0.1 (localhost)
  - 52.173.134.133 (Azure Cloud)
  - 23.210.66.93 (Suspicious)
  ... and 191 more

Analysis saved to: cases/bn/memory_analysis/
```

### Malware Detection

The system automatically flags suspicious process names:
- `zyklon.exe` → Known RAT malware
- `keylogger.exe` → Keylogging tool
- `rat.exe` → Remote Access Trojan
- `backdoor.exe` → Backdoor malware
- `trojan.exe` → Trojan horse

## Integration with FEPD Terminal

Memory artifacts are automatically integrated with Terminal commands:

### `ps` Command
Shows processes from:
1. Windows Event Logs (EVTX)
2. Prefetch files (.pf)
3. **Memory dump** (if analyzed)

### `netstat` Command
Shows network connections from:
1. Browser history databases
2. Windows Firewall logs
3. **Memory dump** (if analyzed)

### `grep` Command
Search memory strings:
```bash
fepd:case[user]$ grep "malware" memory_analysis/
```

## Constitutional Compliance

Memory analysis maintains FEPD's constitutional principles:

### Read-Only
- Never modifies original .mem file
- All analysis is non-destructive

### Explainable
- Pattern-based extraction (not AI/ML)
- Every artifact has source pattern documented
- Human-verifiable results

### Reproducible
- Same input → same output (deterministic)
- No random sampling or heuristics
- Results can be reproduced by other tools

### Chain of Custody
- SHA-256 hash calculated at case creation
- All operations logged to CoC
- Timestamps for every analysis

## Troubleshooting

### "No artifacts discovered"
**Cause**: File treated as disk image instead of memory dump
**Solution**: Rename file with `.mem` extension

### "Analysis takes too long"
**Cause**: Full analysis mode on large dump
**Solution**: Use quick scan first, then `--full` if needed

### "Malware not detected"
**Cause**: Process name obfuscated or packed
**Solution**: Use `strings` command to search memory manually

### "Database not found"
**Cause**: Memory dump not analyzed yet
**Solution**: Run `memscan` command first

## API Usage

### Python Integration

```python
from src.modules.memory_analyzer import MemoryAnalyzer

# Create analyzer
analyzer = MemoryAnalyzer("/path/to/memdump.mem")

# Quick scan
results = analyzer.quick_scan()
print(f"Found {len(results['processes'])} processes")

# Full analysis
output_dir = Path("output")
analyzer.full_analysis(output_dir)
```

### Direct Script

```bash
# CLI mode
python src/modules/memory_analyzer.py memdump.mem --quick
python src/modules/memory_analyzer.py memdump.mem --full --output results/
```

## Limitations

### Not Supported (Requires Volatility)
- Process tree reconstruction
- DLL/module enumeration
- Kernel driver analysis
- Memory carving (executable extraction)
- Volatility profiles

### Supported (Native FEPD)
- Process name extraction
- Network IP addresses
- URL discovery
- Registry key references
- String extraction
- Basic malware indicators

## Best Practices

### 1. Triage Workflow
```bash
# Step 1: Quick scan
memscan /path/to/dump.mem

# Step 2: Review processes
ps | grep -E "exe|dll"

# Step 3: Check network
netstat | grep -v "127.0.0.1"

# Step 4: If malware found → full analysis
memscan --full
```

### 2. Malware Investigation
```bash
# Find suspicious processes
ps | grep -iE "keylog|rat|backdoor|trojan|zyklon"

# Find C2 IPs (exclude common)
netstat | grep -vE "127.0.0.1|10\.|192.168\.|172\.(1[6-9]|2[0-9]|3[01])\."

# Search for URLs
cat memory_analysis/*.json | grep "http"
```

### 3. Performance Optimization
- Use **quick scan** for triage (13 seconds)
- Use **full analysis** only when needed (5-10 minutes)
- Run full analysis overnight for large (16GB+) dumps

## Future Enhancements

Planned features:
- Process tree reconstruction (native)
- DLL enumeration (without Volatility)
- Memory carving for executables
- Timeline integration (memory events)
- YARA rule scanning
- Automated IoC extraction

## See Also

- [Memory Analysis Implementation](MEMORY_ANALYSIS_IMPLEMENTATION.md) - Technical details
- [Constitutional FEPD OS](CONSTITUTIONAL_FEPD_OS.md) - Terminal architecture
- [FEPD Terminal Guide](FEPD_TERMINAL_GUIDE.md) - Command reference
