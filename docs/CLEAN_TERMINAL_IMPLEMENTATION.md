# FEPD OS Clean Terminal Implementation ✓

## Objective
Make FEPD feel like a **native forensic operating system**, not an application.

The terminal shows **only**:
```
fepd:<case_name>[<user>]$ _
```

Nothing else. No banners. No warnings. No hints.

---

## Changes Implemented

### 1. Terminal Widget (`ui/fepd_terminal_widget.py`)

**Removed:**
- ❌ Welcome banner with ASCII art
- ❌ "Type 'help' for commands" hint
- ❌ "All operations are READ-ONLY" warning
- ❌ `[ERROR]` prefix on exceptions
- ❌ Verbose messages on quit/exit

**Changed:**
```python
def __init__(...):
    # No welcome banner - clean shell experience
    self.init_ui()

def clear_output(self):
    # Just clear - no re-printing welcome
    self.output_area.clear()

def execute_command(self):
    # Minimal error display
    except Exception as e:
        self.output_area.append(str(e))  # No [ERROR] prefix
```

### 2. Shell Engine (`src/fepd_os/shell.py`)

**Error Messages - Before vs After:**

| Before | After |
|--------|-------|
| `[ERROR] No case selected.\n[HINT] Run: use case <name>` | `use_case: no active case` |
| `usage: cat <path>` | `cat: missing path` |
| `[Unknown command: xyz]` | `xyz: command not found` |
| `[Context switched to case: X]` | *(silent - prompt changes)* |
| `[No evidence detected]\n[HINT] Copy files...` | `detect: no evidence found` |

**Modified Methods:**
- `_ensure_case_bound()` - Minimal error
- `dispatch()` - No [ERROR] prefix, shell-like "command not found"
- `cmd_use()` - Silent (prompt reflects change)
- `cmd_exit_user()` - Silent
- All `cmd_*` usage errors - Minimal format: `command: error`

**Specific Cleanups:**
```python
# Before:
return (
    "[ERROR] No search pattern provided\n"
    "[HINT] Usage: search <pattern> [--memory|--registry|--evtx]"
)

# After:
return "search: missing pattern"
```

---

## Terminal Experience

### On Startup
```
fepd:global[unknown]$ _
```
That's it. Nothing else.

### During Use
```
fepd:global[unknown]$ create_case LoneWolf_Investigation
case LoneWolf_Investigation created
fepd:global[unknown]$ use case LoneWolf_Investigation
fepd:LoneWolf_Investigation[unknown]$ use user root
fepd:LoneWolf_Investigation[root]$ ls
artifacts/
memory/
registry/
timeline.db
fepd:LoneWolf_Investigation[root]$ cd memory
fepd:LoneWolf_Investigation[root]$ cat dump.mem
cat: missing path
fepd:LoneWolf_Investigation[root]$ _
```

**Notice:**
- ✓ Context switches are **silent** - prompt changes speak for themselves
- ✓ Errors are **inline and minimal** - `command: reason`
- ✓ No `[HINT]`, `[INFO]`, `[NOTE]`, `[NEXT]` clutter
- ✓ Feels like SSH into the evidence

---

## Behavioral Rules

### Prompt Rendering
```python
def _prompt(self) -> str:
    case = self.cc.current_case or 'global'
    user = f"[{self.cc.active_user}]" if self.cc.active_user else '[unknown]'
    return f"fepd:{case}{user}$ "
```

### Error Format
```python
# Command errors
return "command: error_reason"

# Not found
return "command: no such file"

# Missing argument
return "command: missing argument"
```

### Silent Operations
Commands that change state (use case, use user, exit_user) return `''` and let the **prompt change** communicate the result.

---

## Testing

Run these to verify:
```bash
python test_clean_terminal.py    # Unit tests
python demo_clean_terminal.py    # Visual demo
```

**Expected Output:**
```
fepd:LoneWolf_Investigation[root]$ _
```

Clean. Minimal. **Native OS feel.**

---

## Result

The user now experiences FEPD as:

> **"You are inside the seized system."**

Not:
> ~~"You are using a forensic tool to view a system."~~

This is the constitutional FEPD experience:
- **Terminal-first** - No GUI required
- **Evidence-immutable** - Clear, no warnings needed
- **Intelligence-driven** - Quiet until you ask (help command)

---

## Files Modified

1. `ui/fepd_terminal_widget.py` - Removed banners, minimal errors
2. `src/fepd_os/shell.py` - Shell-like error messages, silent context switches
3. `test_clean_terminal.py` - Tests verify minimal behavior
4. `demo_clean_terminal.py` - Visual demonstration

---

## Before & After Comparison

### Before (Cluttered):
```
╔══════════════════════════════════════════════════════════════╗
║         FEPD FORENSIC OPERATING SYSTEM TERMINAL             ║
║              Read-Only Evidence Navigation                   ║
╚══════════════════════════════════════════════════════════════╝

Type 'help' for commands.
Type 'create_case <name>' to start, or 'use case <name>' to load.
All operations are READ-ONLY and AUDIT-LOGGED.

fepd:global[unknown]$ ls
[ERROR] No case selected.
[HINT] Run: use case <name>
[HINT] Or: create_case <name>
fepd:global[unknown]$ _
```

### After (Clean):
```
fepd:global[unknown]$ ls
use_case: no active case
fepd:global[unknown]$ _
```

**Difference:** 
- 8 lines of banners → 0 lines
- Verbose 3-line error → 1-line inline error
- Feels like an app → **Feels like an OS**

---

**Status: ✅ Complete**

The FEPD terminal is now a clean, minimal, native-feeling forensic operating system shell.
