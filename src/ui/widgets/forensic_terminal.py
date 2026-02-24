"""
FEPD Forensic Terminal - Windows CMD-Style Forensic Shell

This terminal emulates a Windows Command Prompt experience but operates
EXCLUSIVELY on forensic evidence, not the host operating system.

Key Features:
- Windows CMD syntax (dir, cd, tree, type, find, where, attrib, etc.)
- 100% read-only - ALL write commands are blocked
- Works on Virtual Filesystem mapped to evidence
- Court-safe forensic protection
- Proper prompt: fepd:<case>[<user>]$

FORENSIC INTEGRITY CONTRACT:
- Terminal NEVER exposes analyzer-side paths
- All paths shown are evidence paths only
- Any analyzer path leak is treated as integrity breach

Copyright (c) 2026 FEPD Development Team
"""

from PyQt6.QtWidgets import QPlainTextEdit, QWidget, QVBoxLayout
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import (
    QFont, QTextCursor, QColor, QTextCharFormat, 
    QKeyEvent, QMouseEvent, QPalette, QTextOption
)
import sys
import os
import fnmatch
import logging
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from pathlib import Path
import json
from datetime import datetime
from typing import Optional, List, Tuple, Dict

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from src.fepd_os.shell import FEPDShellEngine
from src.core.path_sanitizer import safe_path, is_safe_path, get_sanitizer, ForensicIntegrityError


# ============================================================================
# CONSTANTS - Forensic Terminal Configuration
# ============================================================================

# Terminal display constants
MAX_TREE_DEPTH: int = 5
MAX_DIR_ITEMS: int = 50
MAX_OUTPUT_LINES: int = 1000
CURSOR_WIDTH: int = 8
FONT_SIZE: int = 11
FONT_FAMILY: str = "Consolas"

# Terminal colors (Windows CMD authentic)
COLOR_BACKGROUND: str = "#0c0c0c"
COLOR_TEXT: str = "#cccccc"
COLOR_PROMPT: str = "#cccccc"
COLOR_ERROR: str = "#c50f1f"
COLOR_WARNING: str = "#c19c00"
COLOR_SUCCESS: str = "#13a10e"
COLOR_INFO: str = "#3b78ff"
COLOR_SELECTION_BG: str = "#ffffff"
COLOR_SELECTION_FG: str = "#0c0c0c"

# Auto-complete settings
AUTO_COMPLETE_MIN_CHARS: int = 2
AUTO_COMPLETE_MAX_SUGGESTIONS: int = 10

# Command history
MAX_HISTORY_SIZE: int = 1000

# Auto-mount settings
AUTO_MOUNT_ENABLED: bool = True
AUTO_MOUNT_TIMEOUT_MS: int = 2000
AUTO_MOUNT_RETRY_COUNT: int = 3

# Export settings
DEFAULT_EXPORT_FORMAT: str = 'txt'
EXPORT_TIMESTAMP_FORMAT: str = '%Y%m%d_%H%M%S'


# ============================================================================
# FORENSIC PATH PROTECTION
# ============================================================================

def sanitize_terminal_output(text: str) -> str:
    """
    Sanitize terminal output to prevent analyzer path exposure.
    
    This is the terminal's firewall against path leakage.
    """
    sanitizer = get_sanitizer()
    
    # Check if any line contains analyzer paths
    lines = text.split('\n')
    sanitized_lines = []
    
    for line in lines:
        if sanitizer.is_analyzer_path(line):
            # Try to extract evidence path
            evidence_path = sanitizer._extract_evidence_path(line)
            if evidence_path:
                sanitized_lines.append(evidence_path)
            else:
                # Block the line entirely
                sanitized_lines.append("[INTEGRITY ALERT] Analyzer path exposure blocked.")
        else:
            sanitized_lines.append(line)
    
    return '\n'.join(sanitized_lines)


# ============================================================================
# Windows Command Classification System
# ============================================================================

# Commands that WRITE/MODIFY - Always blocked
WRITE_COMMANDS = {
    # File operations
    'del', 'erase', 'copy', 'move', 'ren', 'rename', 'xcopy', 'robocopy',
    'mkdir', 'md', 'rmdir', 'rd', 'mklink',
    
    # Permission changes
    'icacls', 'cacls', 'takeown', 'cipher',
    
    # System modification
    'format', 'diskpart', 'chkdsk', 'defrag', 'sfc', 'dism',
    'bcdedit', 'bootcfg', 'bootrec',
    
    # Registry modification
    'reg', 'regedit', 'regedt32',
    
    # Network modification
    'netsh', 'route',
    
    # Service/process modification
    'sc', 'net', 'taskkill', 'shutdown', 'logoff',
    
    # Scripting that could modify
    'powershell', 'pwsh', 'cmd', 'cscript', 'wscript', 'mshta',
    
    # Editors
    'notepad', 'edit', 'edlin',
    
    # Archive operations
    'compact', 'expand', 'makecab',
    
    # Linux equivalents (blocked too)
    'rm', 'mv', 'cp', 'touch', 'chmod', 'chown', 'sudo', 'su',
    'nano', 'vi', 'vim', 'emacs', 'dd', 'mkfs', 'mount', 'umount',
}

# Commands that are READ-ONLY - Allowed
READ_COMMANDS = {
    # Directory listing
    'dir', 'tree',
    
    # File viewing
    'type', 'more',
    
    # Navigation
    'cd', 'chdir', 'pushd', 'popd',
    
    # Search
    'find', 'findstr', 'where',
    
    # File comparison
    'fc', 'comp',
    
    # Information display
    'echo', 'date', 'time', 'ver', 'vol', 'label', 'title',
    
    # System info (read-only)
    'hostname', 'whoami', 'set', 'path', 'systeminfo',
    'ipconfig', 'netstat', 'nslookup', 'ping', 'tracert', 'pathping',
    'arp', 'getmac', 'nbtstat', 'attrib',
    
    # Help
    'help', 'cls', 'color', 'mode', 'prompt',
    
    # Verification/hash
    'certutil', 'verify',
    
    # Linux equivalents (allowed)
    'ls', 'cat', 'head', 'tail', 'less', 'grep', 'file',
    'stat', 'pwd', 'history', 'clear', 'wc',
}

# Internal FEPD commands
FEPD_COMMANDS = {
    'cases', 'use', 'users', 'timeline', 'anomalies', 'iocs',
    'export', 'chain', 'score', 'explain', 'create_case',
    'ingest', 'search', 'hash', 'forensic_report',
    'help', 'hint', 'exit', 'quit', 'version', 'status', 'info',
    'cng', 'memscan', 'ps', 'netstat', 'sessions', 'services',
    'startup', 'ueba', 'detect', 'mount', 'validate', 'exit_user',
    'osinfo',  # Evidence OS information
}

# Patterns that indicate write intent
WRITE_PATTERNS = ['>', '>>', '-rf', '-f', '/f', '/q']


class WindowsForensicEngine:
    """
    Virtual Windows Command Engine operating on forensic evidence.
    
    This engine simulates Windows CMD behavior but operates ONLY
    on the Virtual Filesystem (VFS) which is mapped to evidence.
    
    The host operating system is NEVER touched.
    """
    
    def __init__(self, shell_engine: FEPDShellEngine) -> None:
        self.shell = shell_engine
        self.cwd: str = 'C:\\'
        self.env_vars: Dict[str, str] = {
            'COMPUTERNAME': 'EVIDENCE-PC',
            'USERNAME': 'Investigator',
            'SYSTEMROOT': 'C:\\Windows',
            'TEMP': 'C:\\Users\\Temp',
        }
        self._mounting: bool = False
        self._last_mount_error: Optional[str] = None
    
    def _check_vfs_ready(self) -> Optional[str]:
        """
        Check if VFS is ready for file commands.
        
        Returns:
            None if VFS is ready, or an appropriate error message.
        """
        # Check if a case is loaded
        if not self.shell.cc.current_case:
            return """No case loaded.

To begin investigation:
  1. cases           → List available cases
  2. use case <name> → Load a case
"""
        
        # Case is loaded but VFS not available (evidence not mounted)
        if not self.shell.vfs:
            return """Evidence not mounted. File system is empty.

To mount evidence:
  1. detect          → Scan for evidence images
  2. mount <index>   → Mount evidence in READ-ONLY mode
"""
        
        return None  # VFS is ready
    
    def classify_command(self, command: str) -> Tuple[str, bool, str]:
        """
        Classify a command as read-only, blocked, or unknown.
        
        Returns: (category, is_blocked, reason)
        """
        if not command.strip():
            return ('empty', False, '')
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        
        # Remove path if present
        if '\\' in cmd or '/' in cmd:
            cmd = os.path.basename(cmd).lower()
        
        # Remove extension
        for ext in ['.exe', '.com', '.bat', '.cmd']:
            if cmd.endswith(ext):
                cmd = cmd[:-len(ext)]
        
        # Check for write patterns
        for pattern in WRITE_PATTERNS:
            if pattern in command and cmd not in ['echo', 'find', 'findstr']:
                return ('write', True, f"Pattern '{pattern}' indicates write operation")
        
        # Check if blocked (write command)
        if cmd in WRITE_COMMANDS:
            return ('write', True, f"'{cmd}' is a write command that would modify evidence")
        
        # Check if it's a FEPD internal command
        if cmd in FEPD_COMMANDS:
            return ('fepd', False, '')
        
        # Check if it's a known read command
        if cmd in READ_COMMANDS:
            return ('read', False, '')
        
        return ('unknown', False, '')
    
    def execute(self, command: str) -> Optional[str]:
        """Execute a Windows-style command on the evidence VFS."""
        if not command.strip():
            return ''
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        handlers = {
            'dir': self._cmd_dir,
            'cd': self._cmd_cd,
            'chdir': self._cmd_cd,
            'tree': self._cmd_tree,
            'type': self._cmd_type,
            'more': self._cmd_type,
            'find': self._cmd_find,
            'findstr': self._cmd_findstr,
            'where': self._cmd_where,
            'fc': self._cmd_fc,
            'echo': self._cmd_echo,
            'cls': self._cmd_cls,
            'ver': self._cmd_ver,
            'vol': self._cmd_vol,
            'date': self._cmd_date,
            'time': self._cmd_time,
            'hostname': self._cmd_hostname,
            'whoami': self._cmd_whoami,
            'set': self._cmd_set,
            'path': self._cmd_path,
            'systeminfo': self._cmd_systeminfo,
            'ipconfig': self._cmd_ipconfig,
            'netstat': self._cmd_netstat,
            'help': self._cmd_help,
            'certutil': self._cmd_certutil,
            'attrib': self._cmd_attrib,
            # Linux commands mapped
            'ls': self._cmd_dir,
            'cat': self._cmd_type,
            'pwd': self._cmd_pwd,
            'clear': self._cmd_cls,
        }
        
        if cmd in handlers:
            try:
                return handlers[cmd](args, command)
            except Exception as e:
                return f"Error executing '{cmd}': {str(e)}"
        
        return None  # Signal to use FEPD engine
    
    def _format_windows_path(self, vfs_path: str) -> str:
        """Convert VFS path to Windows-style evidence path with sanitization."""
        if vfs_path.startswith('/'):
            windows_path = 'C:' + vfs_path.replace('/', '\\')
        else:
            windows_path = vfs_path
        
        # FORENSIC INTEGRITY: Ensure no analyzer paths leak
        try:
            return safe_path(windows_path, "terminal")
        except ForensicIntegrityError:
            return "[PATH PROTECTED]"
    
    def _parse_vfs_path(self, windows_path: str) -> str:
        """Convert Windows-style path to VFS path."""
        path = windows_path
        if len(path) >= 2 and path[1] == ':':
            path = path[2:]
        path = path.replace('\\', '/')
        if not path.startswith('/'):
            path = '/' + path
        return path
    
    def _cmd_dir(self, args: List[str], full_cmd: str) -> str:
        """Simulate Windows DIR command."""
        show_all = '/a' in full_cmd.lower()
        bare = '/b' in full_cmd.lower()
        
        target = self.shell.cwd
        for arg in args:
            if not arg.startswith('/') and not arg.startswith('-'):
                target = self._parse_vfs_path(arg)
                break
        
        try:
            vfs_error = self._check_vfs_ready()
            if vfs_error:
                return vfs_error
            
            items = self.shell.vfs.list_dir(target)
            
            if bare:
                return '\n'.join(items)
            
            output = []
            output.append(" Volume in drive C is EVIDENCE")
            output.append(" Volume Serial Number is FEPD-2026")
            output.append("")
            output.append(f" Directory of {self._format_windows_path(target)}")
            output.append("")
            
            total_files = 0
            total_dirs = 0
            total_size = 0
            
            if target != '/':
                output.append(f"{datetime.now().strftime('%m/%d/%Y  %I:%M %p')}    <DIR>          .")
                output.append(f"{datetime.now().strftime('%m/%d/%Y  %I:%M %p')}    <DIR>          ..")
                total_dirs += 2
            
            for name in items:
                item_path = os.path.join(target, name).replace('\\', '/')
                try:
                    meta = self.shell.vfs.stat(item_path)
                    is_dir = meta.get('is_dir', False) if meta else False
                    size = meta.get('size', 0) if meta else 0
                    mtime = meta.get('mtime', datetime.now().isoformat()) if meta else None
                    
                    try:
                        if isinstance(mtime, str):
                            dt = datetime.fromisoformat(mtime.replace('Z', '+00:00'))
                        else:
                            dt = datetime.now()
                    except:
                        dt = datetime.now()
                    
                    date_str = dt.strftime('%m/%d/%Y  %I:%M %p')
                    
                    if is_dir:
                        output.append(f"{date_str}    <DIR>          {name}")
                        total_dirs += 1
                    else:
                        output.append(f"{date_str}    {size:>14,} {name}")
                        total_files += 1
                        total_size += size
                except:
                    output.append(f"{datetime.now().strftime('%m/%d/%Y  %I:%M %p')}                   {name}")
                    total_files += 1
            
            output.append(f"               {total_files} File(s)  {total_size:>14,} bytes")
            output.append(f"               {total_dirs} Dir(s)   [EVIDENCE - Read Only]")
            
            return '\n'.join(output)
            
        except FileNotFoundError:
            return f"The system cannot find the path specified.\n{self._format_windows_path(target)}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _cmd_cd(self, args: List[str], full_cmd: str) -> str:
        """Simulate Windows CD command."""
        if not args:
            return self._format_windows_path(self.shell.cwd)
        
        target = args[0]
        
        if target == '..':
            new_path = os.path.dirname(self.shell.cwd.rstrip('/'))
            if not new_path:
                new_path = '/'
            self.shell.cwd = new_path
            return ''
        
        if target in ('\\', '/'):
            self.shell.cwd = '/'
            return ''
        
        vfs_path = self._parse_vfs_path(target)
        
        if not vfs_path.startswith('/'):
            vfs_path = os.path.join(self.shell.cwd, vfs_path).replace('\\', '/')
        
        try:
            vfs_error = self._check_vfs_ready()
            if vfs_error:
                return vfs_error
            
            node = self.shell.vfs._node_at(vfs_path)
            if not node:
                return "The system cannot find the path specified."
            if not node.is_dir:
                return "The directory name is invalid."
            
            self.shell.cwd = vfs_path
            return ''
            
        except:
            return "The system cannot find the path specified."
    
    def _cmd_pwd(self, args: List[str], full_cmd: str) -> str:
        """Show current working directory - evidence path only."""
        # FORENSIC INTEGRITY: Return evidence path, never analyzer path
        return self._format_windows_path(self.shell.cwd)
    
    def _cmd_tree(self, args: List[str], full_cmd: str) -> str:
        """Simulate Windows TREE command."""
        target = self.shell.cwd
        for arg in args:
            if not arg.startswith('/'):
                target = self._parse_vfs_path(arg)
                break
        
        try:
            vfs_error = self._check_vfs_ready()
            if vfs_error:
                return vfs_error
            
            output = []
            output.append("Folder PATH listing for volume EVIDENCE")
            output.append("Volume serial number is FEPD-2026")
            output.append(self._format_windows_path(target))
            
            self._tree_recursive(target, output, '', 0)
            
            return '\n'.join(output)
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _tree_recursive(self, path: str, output: List[str], prefix: str, depth: int) -> None:
        """Recursively build tree output with configurable depth."""
        if depth > MAX_TREE_DEPTH:
            return
        try:
            items = self.shell.vfs.list_dir(path)
            for i, name in enumerate(items[:MAX_DIR_ITEMS]):  # Limit items
                is_last_item = (i == len(items[:50]) - 1)
                connector = '└───' if is_last_item else '├───'
                output.append(f"{prefix}{connector}{name}")
                
                item_path = os.path.join(path, name).replace('\\', '/')
                try:
                    meta = self.shell.vfs.stat(item_path)
                    if meta and meta.get('is_dir'):
                        new_prefix = prefix + ('    ' if is_last_item else '│   ')
                        self._tree_recursive(item_path, output, new_prefix, depth + 1)
                except:
                    pass
        except:
            pass
    
    def _cmd_type(self, args: List[str], full_cmd: str) -> str:
        """Simulate Windows TYPE command."""
        if not args:
            return "The syntax of the command is incorrect."
        
        target = args[0]
        vfs_path = self._parse_vfs_path(target)
        
        if not vfs_path.startswith('/'):
            vfs_path = os.path.join(self.shell.cwd, vfs_path).replace('\\', '/')
        
        try:
            vfs_error = self._check_vfs_ready()
            if vfs_error:
                return vfs_error
            
            meta = self.shell.vfs.stat(vfs_path)
            if not meta:
                return "The system cannot find the file specified."
            
            if meta.get('is_dir'):
                return "Access is denied."
            
            real_path = meta.get('path')
            if not real_path or not os.path.exists(real_path):
                return "[File data not available in evidence image]"
            
            with open(real_path, 'rb') as f:
                data = f.read(100 * 1024)
            
            try:
                return data.decode('utf-8', errors='replace')
            except:
                import binascii
                return "[Binary file]\n" + binascii.hexlify(data[:256]).decode('ascii') + '...'
                
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _cmd_find(self, args: List[str], full_cmd: str) -> str:
        """Simulate Windows FIND command."""
        if not args:
            return 'FIND: Parameter format not correct'
        
        search_term = None
        for arg in args:
            if arg.startswith('"') and arg.endswith('"'):
                search_term = arg[1:-1]
                break
            elif not arg.startswith('/'):
                search_term = arg
        
        if not search_term:
            search_term = args[0]
        
        return f'Searching for "{search_term}" in evidence...\nUse "search {search_term}" for FEPD full-text search.'
    
    def _cmd_findstr(self, args: List[str], full_cmd: str) -> str:
        """Simulate Windows FINDSTR command."""
        if not args:
            return "FINDSTR: Argument missing"
        return f'Pattern: {args[0]}\nUse "search {args[0]}" for FEPD forensic search.'
    
    def _cmd_where(self, args: List[str], full_cmd: str) -> str:
        """Simulate Windows WHERE command."""
        if not args:
            return "ERROR: A search pattern is required."
        
        pattern = args[0]
        
        try:
            vfs_error = self._check_vfs_ready()
            if vfs_error:
                return vfs_error
            
            results = []
            self._search_recursive('/', pattern, results)
            
            if results:
                return '\n'.join([self._format_windows_path(p) for p in results[:20]])
            else:
                return "INFO: Could not find files for the given pattern(s)."
                
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _search_recursive(self, path: str, pattern: str, results: List[str], max_results: int = 20):
        """Recursively search for files matching pattern."""
        if len(results) >= max_results:
            return
        
        try:
            items = self.shell.vfs.list_dir(path)
            for name in items:
                if len(results) >= max_results:
                    return
                
                item_path = os.path.join(path, name).replace('\\', '/')
                
                if fnmatch.fnmatch(name.lower(), pattern.lower()):
                    results.append(item_path)
                
                try:
                    meta = self.shell.vfs.stat(item_path)
                    if meta and meta.get('is_dir'):
                        self._search_recursive(item_path, pattern, results, max_results)
                except:
                    pass
        except:
            pass
    
    def _cmd_fc(self, args: List[str], full_cmd: str) -> str:
        return "FC: Use 'hash <file1>' and 'hash <file2>' to compare file hashes."
    
    def _cmd_echo(self, args: List[str], full_cmd: str) -> str:
        if not args:
            return "ECHO is on."
        return ' '.join(args)
    
    def _cmd_cls(self, args: List[str], full_cmd: str) -> str:
        return '__CLS__'
    
    def _cmd_ver(self, args: List[str], full_cmd: str) -> str:
        """Show OS version from evidence."""
        if self.shell.evidence_os_context:
            ctx = self.shell.evidence_os_context
            return f"\n{ctx.os_version}\n"
        return "\n[No evidence loaded - load a case first]\n"
    
    def _cmd_vol(self, args: List[str], full_cmd: str) -> str:
        """Show volume info from evidence."""
        if not self.shell.cc.current_case:
            return "[No evidence loaded]"
        return """ Volume in drive C has no label.
 Volume Serial Number is FEPD-EVID
"""
    
    def _cmd_date(self, args: List[str], full_cmd: str) -> str:
        """Show date from evidence timeline - last event timestamp."""
        if not self.shell.cc.current_case:
            return "[No evidence loaded]"
        
        # Try to get last event timestamp from evidence
        try:
            case_path = self.shell.cc.get_case_path(self.shell.cc.current_case)
            events_file = os.path.join(case_path, 'classified_events.csv')
            if os.path.exists(events_file):
                import csv
                with open(events_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    last_timestamp = None
                    for row in reader:
                        ts = row.get('timestamp', row.get('Timestamp', ''))
                        if ts:
                            last_timestamp = ts
                    if last_timestamp:
                        return f"Evidence timestamp: {last_timestamp}"
            return "[No timeline data in evidence]"
        except:
            return "[Could not read evidence timeline]"
    
    def _cmd_time(self, args: List[str], full_cmd: str) -> str:
        """Show time from evidence - last event time."""
        return self._cmd_date(args, full_cmd)
    
    def _cmd_hostname(self, args: List[str], full_cmd: str) -> str:
        """Show hostname from evidence."""
        if self.shell.evidence_os_context:
            return self.shell.evidence_os_context.hostname
        return "[No evidence loaded]"
    
    def _cmd_whoami(self, args: List[str], full_cmd: str) -> str:
        """Show user from evidence."""
        if self.shell.evidence_os_context:
            ctx = self.shell.evidence_os_context
            hostname = ctx.hostname.lower() if ctx.hostname else 'evidence'
            username = ctx.username if ctx.username else 'user'
            return f"{hostname}\\{username}"
        return "[No evidence loaded]"
    
    def _cmd_set(self, args: List[str], full_cmd: str) -> str:
        """Show environment variables from evidence."""
        if not self.shell.cc.current_case:
            return "[No evidence loaded]"
        
        # Get from evidence OS context
        if self.shell.evidence_os_context:
            ctx = self.shell.evidence_os_context
            env = {
                'COMPUTERNAME': ctx.hostname or 'UNKNOWN',
                'USERNAME': ctx.username or 'UNKNOWN',
                'USERDOMAIN': ctx.domain or ctx.hostname or 'WORKGROUP',
                'SYSTEMROOT': ctx.system_root or 'C:\\Windows',
                'USERPROFILE': ctx.home_path or 'C:\\Users\\User',
            }
            if args:
                var = args[0].upper()
                return env.get(var, f"Environment variable {var} not defined")
            return '\n'.join(f"{k}={v}" for k, v in sorted(env.items()))
        return "[No evidence OS data]"
    
    def _cmd_path(self, args: List[str], full_cmd: str) -> str:
        """Show PATH from evidence."""
        if not self.shell.cc.current_case:
            return "[No evidence loaded]"
        return "PATH=C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem"
    
    def _cmd_systeminfo(self, args: List[str], full_cmd: str) -> str:
        """Show system info from evidence."""
        if not self.shell.evidence_os_context:
            return "[No evidence loaded - use 'use case <name>' first]"
        
        ctx = self.shell.evidence_os_context
        return f"""
Host Name:                 {ctx.hostname or 'UNKNOWN'}
OS Name:                   {ctx.os_version or 'UNKNOWN'}
System Type:               {ctx.architecture or 'x64-based PC'}
Domain:                    {ctx.domain or 'WORKGROUP'}
Registered Owner:          {ctx.username or 'UNKNOWN'}
"""
    
    def _cmd_ipconfig(self, args: List[str], full_cmd: str) -> str:
        """Show IP config from evidence - parsed from registry/network artifacts."""
        if not self.shell.cc.current_case:
            return "[No evidence loaded]"
        
        # Try to find network artifacts in case data
        try:
            case_path = self.shell.cc.get_case_path(self.shell.cc.current_case)
            
            # Check for parsed network data
            network_file = os.path.join(case_path, 'artifacts', 'network_config.json')
            if os.path.exists(network_file):
                with open(network_file, 'r') as f:
                    data = json.load(f)
                    return self._format_ipconfig(data)
            
            # Check for registry artifacts with network info
            registry_dir = os.path.join(case_path, 'artifacts', 'registry')
            if os.path.exists(registry_dir):
                # Look for network interface info
                return "[Network config found - parsing registry data...]"
            
            return "[No network configuration found in evidence]"
        except Exception as e:
            return f"[Could not read network data from evidence]"
    
    def _format_ipconfig(self, data: dict) -> str:
        """Format network config data as ipconfig output."""
        output = ["", "Windows IP Configuration", ""]
        for iface, config in data.items():
            output.append(f"Ethernet adapter {iface}:")
            output.append("")
            output.append(f"   IPv4 Address. . . . . . . . . . . : {config.get('ip', 'N/A')}")
            output.append(f"   Subnet Mask . . . . . . . . . . . : {config.get('mask', 'N/A')}")
            output.append(f"   Default Gateway . . . . . . . . . : {config.get('gateway', 'N/A')}")
            output.append("")
        return '\n'.join(output)
    
    def _cmd_netstat(self, args: List[str], full_cmd: str) -> str:
        """Show network connections from evidence - parsed from artifacts."""
        if not self.shell.cc.current_case:
            return "[No evidence loaded]"
        
        # Try to find network connection artifacts
        try:
            case_path = self.shell.cc.get_case_path(self.shell.cc.current_case)
            
            # Check for timeline events with network connections
            events_file = os.path.join(case_path, 'classified_events.csv')
            if os.path.exists(events_file):
                import csv
                connections = []
                with open(events_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        event_type = row.get('event_type', row.get('EventType', '')).lower()
                        desc = row.get('description', row.get('Description', ''))
                        
                        if 'network' in event_type or 'connection' in event_type:
                            connections.append(desc[:60])
                        elif 'remote' in desc.lower() or 'tcp' in desc.lower():
                            connections.append(desc[:60])
                
                if connections:
                    output = ["", "Active Connections [FROM EVIDENCE]", ""]
                    output.append("  Proto  Local Address          Foreign Address        State")
                    for conn in connections[:10]:  # Limit to 10
                        output.append(f"  {conn}")
                    return '\n'.join(output)
            
            return "[No network connection data found in evidence]"
        except:
            return "[Could not read network data from evidence]"
    
    def _cmd_help(self, args: List[str], full_cmd: str) -> str:
        return """For more information on a specific command, type HELP command-name

ATTRIB      Displays file attributes.
CD          Displays or changes the current directory.
CLS         Clears the screen.
DIR         Displays a list of files and subdirectories.
FIND        Searches for a text string in a file.
FINDSTR     Searches for strings in files.
HELP        Provides Help information for Windows commands.
TREE        Graphically displays the directory structure.
TYPE        Displays the contents of a text file.
VER         Displays the Windows version.
WHERE       Displays the location of files that match a search pattern.

Special commands: cases, use case <name>, users, timeline, search <term>
"""
    
    def _cmd_certutil(self, args: List[str], full_cmd: str) -> str:
        if '-hashfile' in args:
            for i, arg in enumerate(args):
                if arg == '-hashfile' and i + 1 < len(args):
                    return f"Use 'hash {args[i+1]}' for file hash verification."
        return "CertUtil: Use 'hash <filename>' for hash verification."
    
    def _cmd_attrib(self, args: List[str], full_cmd: str) -> str:
        """Read-only attrib - just show attributes."""
        if not args:
            return "Displays file attributes.\nNote: Modification is blocked in forensic mode."
        
        target = args[-1]
        vfs_path = self._parse_vfs_path(target)
        
        if not vfs_path.startswith('/'):
            vfs_path = os.path.join(self.shell.cwd, vfs_path).replace('\\', '/')
        
        try:
            vfs_error = self._check_vfs_ready()
            if vfs_error:
                return vfs_error
            
            meta = self.shell.vfs.stat(vfs_path)
            if not meta:
                return f"File not found - {target}"
            
            attrs = "R"  # Always read-only in forensic mode
            return f"     {attrs}           {self._format_windows_path(vfs_path)}"
            
        except Exception as e:
            return f"Error: {str(e)}"
    
    def auto_mount_evidence(self) -> Tuple[bool, str]:
        """Automatically mount evidence when case is loaded.
        
        Returns:
            (success, message): Tuple of success status and user message
        """
        if self._mounting:
            return False, "⏳ Mount operation already in progress..."
        
        self._mounting = True
        
        try:
            # Check if case is loaded
            if not self.shell.cc.current_case:
                self._mounting = False
                return False, "❌ No case loaded. Cannot auto-mount."
            
            # Check if VFS already mounted
            if self.shell.vfs:
                self._mounting = False
                return True, "✅ Evidence already mounted and ready."
            
            # Attempt to detect and mount evidence
            # This simulates: detect → mount 0
            
            # First, try to find evidence in case directory
            case_path = self.shell.cc.get_case_path(self.shell.cc.current_case)
            if not case_path:
                self._mounting = False
                return False, "❌ Case path not found."
            
            # Ensure case_path is a Path object
            case_path = Path(case_path)
            if not case_path.exists():
                self._mounting = False
                return False, "❌ Case path not found."
            
            # Look for evidence database or VEOS
            evidence_db = case_path / "evidence.db"
            vfs_db = case_path / "vfs.db"
            
            if evidence_db.exists() or vfs_db.exists():
                # Evidence database exists, VEOS should auto-initialize
                # This will be handled by the VFS injection from main_window
                self._mounting = False
                return True, "⏳ Evidence detected. Waiting for VFS initialization..."
            
            # No evidence found
            self._mounting = False
            self._last_mount_error = "No evidence images detected in case directory."
            return False, f"⚠️  {self._last_mount_error}\n\n" + \
                   "💡 To mount evidence:\n" + \
                   "   1. Go to Image Ingest tab\n" + \
                   "   2. Click 'Add Evidence Image'\n" + \
                   "   3. Select your .e01/.dd/.raw file\n" + \
                   "   4. Wait for ingestion to complete\n"
            
        except Exception as e:
            self._mounting = False
            self._last_mount_error = str(e)
            return False, f"❌ Auto-mount failed: {str(e)}"
        finally:
            self._mounting = False


# ============================================================================
# Main Terminal Widget
# ============================================================================

class ForensicTerminal(QPlainTextEdit):
    """
    Windows CMD-style forensic terminal.
    
    Operates EXCLUSIVELY on forensic evidence.
    All commands are read-only.
    Write operations are blocked with forensic warnings.
    """
    
    command_executed = pyqtSignal(str, str)
    case_changed = pyqtSignal(str)
    
    def __init__(self, workspace_root: str = '.', parent: Optional[QWidget] = None):
        super().__init__(parent)
        
        self.workspace_root: str = workspace_root
        self.engine: FEPDShellEngine = FEPDShellEngine(workspace_root)
        self.win_engine: WindowsForensicEngine = WindowsForensicEngine(self.engine)
        
        self.prompt_position: int = 0
        self.command_history: List[str] = []
        self.history_index: int = -1
        self.current_input: str = ""
        self._auto_complete_suggestions: List[str] = []
        self._auto_complete_index: int = -1
        self._session_log: List[str] = []
        self._case_loaded: bool = False
        self._vfs_ready: bool = False
        
        self._setup_appearance()
        self._setup_behavior()
        self._show_banner()
        self._print_prompt()
    
    def _setup_appearance(self) -> None:
        """Configure Windows CMD-style appearance with constants."""
        # Use classic Windows CMD font
        font = QFont(FONT_FAMILY, FONT_SIZE)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        
        # Authentic Windows CMD colors (black background, light gray text)
        self.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT};
                border: none;
                padding: 4px 8px;
                selection-background-color: {COLOR_SELECTION_BG};
                selection-color: {COLOR_SELECTION_FG};
            }}
        """)
        
        self.setWordWrapMode(QTextOption.WrapMode.NoWrap)
        self.setCursorWidth(CURSOR_WIDTH)
        
        # Windows CMD authentic colors
        self.colors = {
            'prompt': QColor(COLOR_PROMPT),
            'command': QColor(COLOR_TEXT),
            'output': QColor(COLOR_TEXT),
            'error': QColor(COLOR_ERROR),
            'warning': QColor(COLOR_WARNING),
            'success': QColor(COLOR_SUCCESS),
            'info': QColor('#cccccc'),        # Same as normal
            'blocked': QColor('#c50f1f'),     # Red
            'path': QColor('#cccccc'),        # Same as normal
        }
    
    def _setup_behavior(self):
        self.setReadOnly(False)
        self.setUndoRedoEnabled(False)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    
    def _show_banner(self):
        """Show startup banner - evidence-focused with clear forensic context."""
        banner = """╔════════════════════════════════════════════════════════════════════════╗
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
"""
        cursor = self.textCursor()
        fmt = QTextCharFormat()
        fmt.setForeground(self.colors['output'])
        cursor.insertText(banner, fmt)
        self.setTextCursor(cursor)
    
    def _show_evidence_os_banner(self):
        """Show Evidence OS detection when case loaded - DO NOT auto-mount."""
        if not self.engine.evidence_os_context:
            return
        
        ctx = self.engine.evidence_os_context
        # Show evidence details but NO auto-mount
        cursor = self.textCursor()
        fmt = QTextCharFormat()
        fmt.setForeground(self.colors['success'])
        
        banner = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Case Loaded - Evidence Metadata Detected
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Evidence System: {ctx.hostname or 'Unknown'}
OS Version:      {ctx.os_version or 'Unknown'}
User Context:    {ctx.username or 'Unknown'}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  Evidence NOT mounted - File system is currently EMPTY.

To access evidence files:
  1. detect              → Scan for evidence images (.E01/.DD/.IMG/.MEM)
  2. mount <index|file>  → Mount evidence in READ-ONLY mode

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        cursor.insertText(banner, fmt)
        self.setTextCursor(cursor)

    def _auto_mount_evidence(self):
        """
        DO NOT auto-mount evidence when case is loaded.
        
        This method is now disabled per forensic workflow requirements.
        User must explicitly run 'detect' and 'mount' commands.
        """
        # DISABLED: No automatic mounting
        # User must explicitly:
        # 1. Run 'detect' to find evidence
        # 2. Run 'mount <evidence>' to mount it
        pass

    def _get_prompt(self) -> str:
        r"""
        Get prompt - shows C:\> when no evidence mounted, evidence path when mounted.
        
        Before mount: C:\>
        After mount:  C:\Users\Alice\Desktop>
        """
        # Check if case is loaded
        if not self.engine.cc.current_case:
            return "C:\\>"
        
        # Check if VFS is mounted
        if not self.engine.vfs:
            # Case loaded but no evidence mounted
            return "C:\\>"
        
        # VFS is mounted - show evidence-native path
        cwd = self.engine.cwd if hasattr(self.engine, 'cwd') else '/'
        
        # Convert VFS path to Windows path
        if cwd.startswith('/This PC/'):
            # /This PC/C:/Users/John -> C:\Users\John
            parts = cwd.split('/')
            if len(parts) >= 3 and ':' in parts[2]:
                drive = parts[2]
                if len(parts) > 3:
                    win_path = drive + '\\' + '\\'.join(parts[3:])
                else:
                    win_path = drive + '\\'
            else:
                win_path = 'C:\\'
        elif cwd == '/':
            win_path = 'C:\\'
        else:
            # Fallback
            win_path = 'C:' + cwd.replace('/', '\\')
        
        return f"{win_path}>"
    
    def _print_prompt(self):
        prompt = self._get_prompt()
        
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.setTextCursor(cursor)
        
        fmt = QTextCharFormat()
        fmt.setForeground(self.colors['prompt'])
        fmt.setFontWeight(700)
        cursor.insertText(prompt, fmt)
        
        fmt = QTextCharFormat()
        fmt.setForeground(self.colors['command'])
        fmt.setFontWeight(400)
        cursor.setCharFormat(fmt)
        
        self.prompt_position = cursor.position()
        self.ensureCursorVisible()
    
    def _log_blocked_command(self, command: str, reason: str):
        """Log a blocked command to chain of custody."""
        try:
            if self.engine.cc.current_case:
                from src.core.chain_of_custody import ChainLogger, CoC_Actions
                case_path = self.engine.cc.get_case_path(self.engine.cc.current_case)
                chain = ChainLogger(case_path)
                chain.log(
                    user="investigator",
                    action=CoC_Actions.COMMAND_BLOCKED,
                    details=f"Blocked: {command} | Reason: {reason}"
                )
        except Exception:
            pass  # Logging is best-effort
    
    def _get_current_command(self) -> str:
        text = self.toPlainText()
        if self.prompt_position <= len(text):
            return text[self.prompt_position:]
        return ""
    
    def _set_current_command(self, text: str):
        cursor = self.textCursor()
        cursor.setPosition(self.prompt_position)
        cursor.movePosition(QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()
        cursor.insertText(text)
        self.setTextCursor(cursor)
    
    def _get_auto_complete_suggestions(self, partial_cmd: str) -> List[str]:
        """Get auto-complete suggestions for partial command.
        
        Args:
            partial_cmd: Partial command or path
            
        Returns:
            List of matching suggestions
        """
        if len(partial_cmd) < AUTO_COMPLETE_MIN_CHARS:
            return []
        
        suggestions: List[str] = []
        
        # Check if it's a path (contains / or \)
        if '/' in partial_cmd or '\\' in partial_cmd:
            # Path auto-complete
            try:
                if self.win_engine and self.win_engine.shell.vfs:
                    # Parse directory and partial filename
                    if '\\' in partial_cmd:
                        parts = partial_cmd.rsplit('\\', 1)
                    else:
                        parts = partial_cmd.rsplit('/', 1)
                    
                    if len(parts) == 2:
                        dir_path, partial_name = parts
                    else:
                        dir_path = self.win_engine.shell.cwd
                        partial_name = parts[0]
                    
                    # Convert to VFS path
                    vfs_path = self.win_engine._parse_vfs_path(dir_path or '.')
                    
                    # List directory
                    items = self.win_engine.shell.vfs.list_dir(vfs_path)
                    
                    # Filter by partial name
                    matches = [item for item in items if item.lower().startswith(partial_name.lower())]
                    suggestions = matches[:AUTO_COMPLETE_MAX_SUGGESTIONS]
            except:
                pass
        else:
            # Command auto-complete
            all_commands = list(READ_COMMANDS) + list(FEPD_COMMANDS)
            matches = [cmd for cmd in all_commands if cmd.startswith(partial_cmd.lower())]
            suggestions = sorted(matches)[:AUTO_COMPLETE_MAX_SUGGESTIONS]
        
        return suggestions
    
    def _apply_auto_complete(self) -> None:
        """Apply auto-complete suggestion to current input."""
        if not self._auto_complete_suggestions:
            return
        
        if self._auto_complete_index >= len(self._auto_complete_suggestions):
            self._auto_complete_index = 0
        
        suggestion = self._auto_complete_suggestions[self._auto_complete_index]
        
        # Replace current partial command with suggestion
        current_cmd = self._get_current_command()
        
        # Find the part to replace
        if ' ' in current_cmd:
            # Replace last word (path/argument)
            parts = current_cmd.rsplit(' ', 1)
            new_cmd = parts[0] + ' ' + suggestion
        else:
            # Replace entire command
            new_cmd = suggestion
        
        self._set_current_command(new_cmd)
        
        # Move to next suggestion for next Tab press
        self._auto_complete_index += 1
    
    def _append_output(self, text: str, color_key: str = 'output'):
        if not text:
            return
        
        # FORENSIC INTEGRITY: Sanitize ALL terminal output
        # This is the firewall against analyzer path exposure
        text = sanitize_terminal_output(text)
        
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        
        doc_text = self.toPlainText()
        if doc_text and not doc_text.endswith('\n'):
            cursor.insertText('\n')
        
        fmt = QTextCharFormat()
        fmt.setForeground(self.colors.get(color_key, self.colors['output']))
        cursor.insertText(text, fmt)
        
        if not text.endswith('\n'):
            cursor.insertText('\n')
        
        self.setTextCursor(cursor)
        self.ensureCursorVisible()
    
    def _show_blocked_warning(self, command: str, reason: str):
        """Show forensic-safe write operation blocked message."""
        cmd_name = command.split()[0] if command else 'unknown'
        
        warning = f"""⛔ Write operation blocked – Evidence integrity preserved.

Command: {cmd_name}
Reason:  {reason}

All write operations are disabled in forensic mode.
Evidence must remain unmodified to maintain chain of custody.
"""
        self._append_output(warning, 'blocked')
    
    def _show_unknown_command(self, command: str):
        cmd_name = command.split()[0] if command else 'unknown'
        # Authentic Windows CMD error message
        msg = f"'{cmd_name}' is not recognized as an internal or external command,\noperable program or batch file."
        self._append_output(msg, 'error')
    
    def _execute_command(self, command: str):
        """Execute command with Evidence OS emulation and FEPD commands."""
        command = command.strip()
        if not command:
            return
        
        # LOG: Command received
        logging.info(f"Terminal executing command: {command}")
        
        if command and (not self.command_history or self.command_history[-1] != command):
            self.command_history.append(command)
        self.history_index = -1
        self.current_input = ""
        
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText('\n')
        self.setTextCursor(cursor)
        
        # Get base command name for routing
        cmd_lower = command.lower().split()[0] if command else ''
        
        # Check if this is a FEPD internal command - always route to FEPD dispatcher
        is_fepd_command = cmd_lower in FEPD_COMMANDS
        
        # Classify command for write-blocking
        category, is_blocked, reason = self.win_engine.classify_command(command)
        logging.debug(f"Command classification: category={category}, is_fepd={is_fepd_command}, blocked={is_blocked}")
        
        # Handle blocked commands
        if is_blocked:
            logging.warning(f"Command blocked: {command} - Reason: {reason}")
            self._show_blocked_warning(command, reason)
            self._log_blocked_command(command, reason)
            self._print_prompt()
            return
        
        # Handle special commands first
        if cmd_lower in ('cls', 'clear'):
            logging.debug(f"Executing clear command")
            self.clear()
            self._print_prompt()
            return
        
        if cmd_lower in ('exit', 'quit'):
            logging.debug(f"Exit command received (ignored)")
            self._append_output("Use window close button to exit FEPD.", 'info')
            self._print_prompt()
            return
        
        # If NOT a FEPD command and we have Evidence OS Shell active, use native OS emulation
        if not is_fepd_command and self.engine.evidence_shell and self.engine.native_os_mode:
            logging.info(f"Routing to Evidence OS Shell: {command}")
            result, was_blocked = self.engine.evidence_shell.execute(command)
            
            if was_blocked:
                logging.warning(f"Evidence shell blocked command: {command}")
                self._append_output(result, 'blocked')
                self._print_prompt()
                self.command_executed.emit(command, result)
                return
            
            if result == '__CLEAR__':
                logging.debug("Evidence shell returned __CLEAR__")
                self.clear()
                self._print_prompt()
                return
            
            # If we got a result (even "command not found"), show it
            if result:
                logging.debug(f"Evidence shell output: {result[:100]}...")
                self._append_output(result, 'output')
                self._print_prompt()
                self.command_executed.emit(command, result)
                return
        
        # Try Windows engine for legacy support (when no evidence shell)
        if not is_fepd_command and category == 'read':
            logging.info(f"Routing to Windows engine: {command}")
            result = self.win_engine.execute(command)
            
            if result == '__CLS__':
                logging.debug("Windows engine returned __CLS__")
                self.clear()
                self._print_prompt()
                return
            
            if result is not None:
                logging.debug(f"Windows engine output: {result[:100]}...")
                self._append_output(result, 'output')
                self._print_prompt()
                self.command_executed.emit(command, result)
                return
        
        # Pass to FEPD engine for internal commands
        try:
            logging.info(f"Routing to FEPD engine: {command}")
            result = self.engine.dispatch(command)
            
            if result:
                logging.debug(f"FEPD engine output: {result[:100]}...")
                color_key = 'output'
                result_lower = result.lower()
                
                if any(x in result_lower for x in ['error', 'failed', 'not found', 'invalid']):
                    color_key = 'error'
                elif any(x in result for x in ['✓', '✔', 'success', '[ok]']):
                    color_key = 'success'
                elif any(x in result_lower for x in ['warning', '⚠']):
                    color_key = 'warning'
                
                self._append_output(result, color_key)
            
            self.command_executed.emit(command, result or "")
            logging.info(f"Command executed successfully: {command}")
            
            # When case is loaded, show Evidence OS banner and auto-mount evidence
            if 'use case' in cmd_lower:
                logging.info(f"Case loaded via command: {command}")
                if self.engine.cc.current_case:
                    self.case_changed.emit(self.engine.cc.current_case)
                    # Show Evidence OS detection info
                    if self.engine.evidence_os_context:
                        self._show_evidence_os_banner()
                    
                    # Auto-detect and auto-mount evidence
                    self._auto_mount_evidence()
            
        except Exception as e:
            error_msg = str(e)
            logging.error(f"Command execution error: {command} - {error_msg}")
            if 'not recognized' in error_msg.lower() or 'unknown' in error_msg.lower():
                self._show_unknown_command(command)
            else:
                self._append_output(f"Error: {error_msg}", 'error')
        
        self._print_prompt()
    
    # ========================================================================
    # Keyboard Event Handling
    # ========================================================================
    
    def keyPressEvent(self, event: QKeyEvent):
        cursor = self.textCursor()
        key = event.key()
        modifiers = event.modifiers()
        
        # Handle Tab key for auto-complete
        if key == Qt.Key.Key_Tab:
            current_cmd = self._get_current_command()
            if current_cmd:
                if not self._auto_complete_suggestions:
                    # First Tab - get suggestions
                    self._auto_complete_suggestions = self._get_auto_complete_suggestions(current_cmd)
                    self._auto_complete_index = 0
                
                if self._auto_complete_suggestions:
                    self._apply_auto_complete()
            return
        else:
            # Reset auto-complete on any other key
            self._auto_complete_suggestions = []
            self._auto_complete_index = -1
        
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            command = self._get_current_command()
            logging.debug(f"Key press Enter - executing command: {command}")
            self._execute_command(command)
            return
        
        if key == Qt.Key.Key_C and modifiers & Qt.KeyboardModifier.ControlModifier:
            self._append_output("^C", 'warning')
            self._print_prompt()
            return
        
        if key == Qt.Key.Key_L and modifiers & Qt.KeyboardModifier.ControlModifier:
            self.clear()
            self._print_prompt()
            return
        
        if key == Qt.Key.Key_A and modifiers & Qt.KeyboardModifier.ControlModifier:
            cursor.setPosition(self.prompt_position)
            self.setTextCursor(cursor)
            return
        
        if key == Qt.Key.Key_E and modifiers & Qt.KeyboardModifier.ControlModifier:
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.setTextCursor(cursor)
            return
        
        if key == Qt.Key.Key_U and modifiers & Qt.KeyboardModifier.ControlModifier:
            self._set_current_command("")
            return
        
        if key == Qt.Key.Key_Up:
            if self.command_history:
                if self.history_index == -1:
                    self.current_input = self._get_current_command()
                if self.history_index < len(self.command_history) - 1:
                    self.history_index += 1
                    self._set_current_command(self.command_history[-(self.history_index + 1)])
            return
        
        if key == Qt.Key.Key_Down:
            if self.history_index > 0:
                self.history_index -= 1
                self._set_current_command(self.command_history[-(self.history_index + 1)])
            elif self.history_index == 0:
                self.history_index = -1
                self._set_current_command(self.current_input)
            return
        
        if key == Qt.Key.Key_Home:
            cursor.setPosition(self.prompt_position)
            self.setTextCursor(cursor)
            return
        
        if key == Qt.Key.Key_End:
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.setTextCursor(cursor)
            return
        
        if key == Qt.Key.Key_Left:
            if cursor.position() <= self.prompt_position:
                return
            super().keyPressEvent(event)
            return
        
        if key == Qt.Key.Key_Backspace:
            if cursor.position() <= self.prompt_position:
                return
            super().keyPressEvent(event)
            return
        
        if key == Qt.Key.Key_Delete:
            if cursor.position() < self.prompt_position:
                return
            super().keyPressEvent(event)
            return
        
        if key == Qt.Key.Key_Tab:
            return
        
        if cursor.position() < self.prompt_position:
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.setTextCursor(cursor)
        
        super().keyPressEvent(event)
    
    def mousePressEvent(self, event: QMouseEvent):
        super().mousePressEvent(event)
        cursor = self.textCursor()
        if cursor.position() < self.prompt_position:
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.setTextCursor(cursor)
    
    def insertFromMimeData(self, source):
        cursor = self.textCursor()
        if cursor.position() < self.prompt_position:
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.setTextCursor(cursor)
        
        text = source.text()
        if text:
            lines = text.split('\n')
            for i, line in enumerate(lines):
                if i == 0:
                    cursor.insertText(line)
                else:
                    self._execute_command(self._get_current_command())
                    self._set_current_command(line)
    
    # ========================================================================
    # Public API
    # ========================================================================
    
    def execute(self, command: str):
        """Execute a command programmatically (from external calls)."""
        logging.info(f"Terminal.execute() called with command: {command}")
        self._set_current_command(command)
        self._execute_command(command)
    
    def load_case(self, case_name: str) -> None:
        """Load case with auto-mount functionality.
        
        Args:
            case_name: Name of the case to load
        """
        # Mark case as loaded
        self._case_loaded = True
        
        # Execute the use case command
        self.execute(f"use case {case_name}")
        
        # Show loading indicator
        if AUTO_MOUNT_ENABLED:
            self._append_output("\n⏳ Initializing evidence filesystem...", 'info')
            
            # Use QTimer to allow UI to update
            QTimer.singleShot(100, self._attempt_auto_mount)
    
    def _attempt_auto_mount(self) -> None:
        """Attempt to auto-mount evidence with retry logic."""
        if not self.win_engine:
            return
        
        # Try auto-mount
        success, message = self.win_engine.auto_mount_evidence()
        
        # Display result
        if success:
            self._append_output(message, 'success')
            self._vfs_ready = True
        else:
            self._append_output(message, 'warning')
            self._vfs_ready = False
        
        # Print new prompt
        self._print_prompt()
    
    def inject_vfs(self, vfs) -> None:
        """Inject VFS and notify user.
        
        Called by main_window after VFS is fully initialized.
        
        Args:
            vfs: Virtual filesystem instance
        """
        if self.win_engine:
            self.win_engine.shell.vfs = vfs
            self._vfs_ready = True
            
            # Show success message
            self._append_output("\n✅ Evidence filesystem mounted successfully!", 'success')
            self._append_output(f"📁 Working directory: {self.win_engine.cwd}", 'info')
            self._append_output("\n💡 Tip: Type 'dir' to list files, 'cd <folder>' to navigate", 'info')
            self._print_prompt()
    
    def get_engine(self) -> FEPDShellEngine:
        return self.engine
    
    def print_message(self, message: str, color_key: str = 'info') -> None:
        self._append_output(message, color_key)
        self._print_prompt()
    
    def export_session(self, filepath: Optional[str] = None) -> bool:
        """Export terminal session to file.
        
        Args:
            filepath: Path to save file (auto-generated if None)
            
        Returns:
            True if export successful
        """
        try:
            # Generate filename if not provided
            if not filepath:
                timestamp = datetime.now().strftime(EXPORT_TIMESTAMP_FORMAT)
                case_name = "unknown"
                if self.engine and self.engine.cc.current_case:
                    case_name = self.engine.cc.current_case
                filepath = f"fepd_session_{case_name}_{timestamp}.{DEFAULT_EXPORT_FORMAT}"
            
            # Get all terminal text
            session_text = self.toPlainText()
            
            # Write to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write("FEPD Forensic Terminal Session Log\n")
                f.write("="*60 + "\n")
                f.write(f"Exported: {datetime.now().isoformat()}\n")
                if self.engine and self.engine.cc.current_case:
                    f.write(f"Case: {self.engine.cc.current_case}\n")
                f.write("="*60 + "\n\n")
                f.write(session_text)
            
            self._append_output(f"\n✅ Session exported to: {filepath}", 'success')
            return True
            
        except Exception as e:
            self._append_output(f"\n❌ Export failed: {str(e)}", 'error')
            return False
    
    def get_command_history(self) -> List[str]:
        """Get command history for export or analysis.
        
        Returns:
            List of executed commands
        """
        return self.command_history.copy()
    
    def clear_with_banner(self) -> None:
        """Clear terminal and show banner again."""
        self.clear()
        self._show_banner()
        self._print_prompt()


class ForensicTerminalWidget(QWidget):
    """Widget wrapper for ForensicTerminal with enhanced functionality."""
    
    def __init__(self, workspace_root: str = '.', parent: Optional[QWidget] = None):
        super().__init__(parent)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        self.terminal = ForensicTerminal(workspace_root, self)
        layout.addWidget(self.terminal)
        
        self.command_executed = self.terminal.command_executed
        self.case_changed = self.terminal.case_changed
    
    def execute(self, command: str) -> None:
        """Execute a command in the terminal."""
        self.terminal.execute(command)
    
    def load_case(self, case_name: str) -> None:
        """Load a case with auto-mount."""
        self.terminal.load_case(case_name)
    
    def inject_vfs(self, vfs) -> None:
        """Inject VFS after it's initialized."""
        self.terminal.inject_vfs(vfs)
    
    def export_session(self, filepath: Optional[str] = None) -> bool:
        """Export terminal session to file."""
        return self.terminal.export_session(filepath)
    
    def clear(self) -> None:
        """Clear terminal screen."""
        self.terminal.clear_with_banner()
    
    def focusInEvent(self, event) -> None:
        """Focus terminal when widget receives focus."""
        super().focusInEvent(event)
        self.terminal.setFocus()
    
    def get_engine(self):
        """Get the FEPD shell engine."""
        return self.terminal.get_engine()
    
    def is_ready(self) -> bool:
        """Check if terminal is ready (case loaded and VFS mounted)."""
        return self.terminal._case_loaded and self.terminal._vfs_ready
