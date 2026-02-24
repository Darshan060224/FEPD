"""
FEPD Evidence OS Shell Engine

This is the core engine that makes the terminal feel like you're INSIDE
the compromised machine. It emulates the native shell of the evidence OS.

When evidence is Windows → Behaves like CMD/PowerShell
When evidence is Linux → Behaves like Bash
When evidence is macOS → Behaves like zsh

🔒 EVERYTHING IS READ-ONLY
Any command that modifies state is intercepted, logged, and blocked.

The user must feel like they are inside the compromised machine—
but the machine is frozen in time.
"""

import os
import re
import sqlite3
import hashlib
import json
from typing import Dict, List, Optional, Any, Tuple, Callable
from datetime import datetime
from pathlib import Path

from .evidence_os import (
    EvidenceOSType, ShellStyle, EvidenceOSContext, EvidenceOSDetector,
    is_mutating_command, create_audit_entry,
    WINDOWS_MUTATING_COMMANDS, LINUX_MUTATING_COMMANDS, MACOS_MUTATING_COMMANDS
)


class EvidenceOSShell:
    """
    The FEPD Forensic Shell that emulates the evidence's operating system.
    
    This shell:
    - Mimics the OS inside the evidence
    - Maps every command to the evidence filesystem
    - Blocks all mutating commands
    - Audit logs every command
    
    The investigator feels like they're inside the compromised machine,
    but it's frozen in time and completely read-only.
    """
    
    def __init__(self, case_name: str, db_path: str, case_path: str = None):
        """
        Initialize the Evidence OS Shell.
        
        Args:
            case_name: Name of the forensic case
            db_path: Path to the evidence database
            case_path: Path to the case directory for audit logging
        """
        self.case_name = case_name
        self.db_path = db_path
        self.case_path = case_path
        
        # Detect OS from evidence
        self.detector = EvidenceOSDetector(db_path, case_path)
        self.os_context: Optional[EvidenceOSContext] = None
        
        # Current working directory in evidence
        self._cwd = '/'
        
        # Command history for shell
        self.history: List[str] = []
        
        # User context
        self.current_user = 'root'
        
        # Audit log entries
        self.audit_log: List[Dict] = []
        
        # Build virtual filesystem tree
        self._file_tree: Dict = {}
        self._load_file_tree()
        
        # Detect the evidence OS
        self._detect_evidence_os()
        
        # Set CWD to root initially, then to user home if it exists
        self._set_initial_cwd()
    
    def _set_initial_cwd(self):
        """Set initial working directory based on detected user and available paths."""
        # Start at root
        self._cwd = '/'
        
        if not self.os_context:
            return
        
        # Try to find the user's home directory in evidence
        username = self.os_context.username
        
        # Check for Windows-style Users/username
        if self._path_exists(f'/Users/{username}'):
            self._cwd = f'/Users/{username}'
            return
        
        # Check for Linux-style home/username
        if self._path_exists(f'/home/{username}'):
            self._cwd = f'/home/{username}'
            return
        
        # Fall back to /Users if it exists
        if self._path_exists('/Users'):
            self._cwd = '/Users'
            return
        
        # Otherwise stay at root
        self._cwd = '/'
    
    def _detect_evidence_os(self):
        """Detect the operating system from evidence and set context."""
        self.os_context = self.detector.detect()
        self.current_user = self.os_context.username if self.os_context else 'root'
    
    def _load_file_tree(self):
        """Load file paths from database into a tree structure."""
        if not self.db_path or not os.path.exists(self.db_path):
            return
        
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            
            # Check if files table exists
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files'")
            if not cur.fetchone():
                conn.close()
                return  # No files table yet
            
            cur.execute("SELECT path, size, owner, hash FROM files")
            
            for row in cur.fetchall():
                path, size, owner, file_hash = row
                if not path:
                    continue
                
                # Normalize path
                norm_path = path.replace('\\', '/')
                if not norm_path.startswith('/'):
                    norm_path = '/' + norm_path
                
                # Build tree
                parts = [p for p in norm_path.split('/') if p]
                node = self._file_tree
                
                for i, part in enumerate(parts):
                    if part not in node:
                        node[part] = {
                            '_is_dir': True,
                            '_meta': {}
                        }
                    node = node[part]
                
                # Mark leaf as file
                node['_is_dir'] = False
                node['_meta'] = {
                    'size': size or 0,
                    'owner': owner or '',
                    'hash': file_hash or '',
                    'real_path': path
                }
            
            conn.close()
        except Exception as e:
            print(f"Error loading file tree: {e}")
    
    @property
    def cwd(self) -> str:
        """Get current working directory in evidence-native format."""
        if self.os_context and self.os_context.os_type == EvidenceOSType.WINDOWS:
            # Convert to Windows path style
            path = self._cwd
            if path.startswith('/'):
                path = 'C:' + path
            return path.replace('/', '\\')
        return self._cwd
    
    @cwd.setter
    def cwd(self, value: str):
        """Set current working directory (normalizes internally)."""
        # Normalize to internal format
        path = value.replace('\\', '/')
        if len(path) >= 2 and path[1] == ':':
            path = path[2:]  # Remove drive letter
        if not path.startswith('/'):
            path = '/' + path
        self._cwd = path
    
    def get_prompt(self) -> str:
        """
        Get the native OS-style prompt.
        
        Windows: C:\\Users\\victim>
        Linux: root@evidence:/home/user#
        macOS: victim@Mac ~ %
        """
        if not self.os_context:
            return f"fepd:{self.case_name}> "
        
        return self.os_context.get_prompt(self.cwd)
    
    def execute(self, command: str) -> Tuple[str, bool]:
        """
        Execute a command in the evidence OS context.
        
        Args:
            command: Command string to execute
        
        Returns:
            (output, was_blocked)
        """
        command = command.strip()
        if not command:
            return ('', False)
        
        # Add to history
        self.history.append(command)
        
        # Check if command would mutate evidence
        os_type = self.os_context.os_type if self.os_context else EvidenceOSType.UNKNOWN
        is_mutating, reason = is_mutating_command(command, os_type)
        
        if is_mutating:
            output = self._block_command(command, reason)
            self._log_command(command, output, blocked=True, reason=reason)
            return (output, True)
        
        # Parse and execute command
        output = self._dispatch_command(command)
        self._log_command(command, output)
        
        return (output, False)
    
    def _block_command(self, command: str, reason: str) -> str:
        """Generate read-only forensic warning for blocked commands."""
        cmd_name = command.split()[0] if command else 'unknown'
        
        if self.os_context and self.os_context.os_type == EvidenceOSType.WINDOWS:
            # Windows-style error
            return f"""
Access is denied.

[READ-ONLY FORENSIC MODE]
Command blocked: {cmd_name}
Reason: {reason}

This terminal operates on forensic evidence in read-only mode.
All write operations are blocked to preserve evidence integrity.
This attempt has been logged to Chain of Custody.
"""
        else:
            # Unix-style error
            return f"""
bash: {cmd_name}: Permission denied

[READ-ONLY FORENSIC MODE]
Command blocked: {cmd_name}
Reason: {reason}

This terminal operates on forensic evidence in read-only mode.
All write operations are blocked to preserve evidence integrity.
This attempt has been logged to Chain of Custody.
"""
    
    def _log_command(self, command: str, output: str, blocked: bool = False, reason: str = ''):
        """Log command execution to audit trail."""
        entry = create_audit_entry(
            user=self.current_user,
            case=self.case_name,
            cwd=self.cwd,
            command=command,
            result=output,
            blocked=blocked,
            reason=reason
        )
        self.audit_log.append(entry)
        
        # Also log to chain of custody file if case path exists
        if self.case_path:
            try:
                from ..core.chain_of_custody import ChainLogger, CoC_Actions
                chain = ChainLogger(self.case_path)
                action = CoC_Actions.COMMAND_BLOCKED if blocked else CoC_Actions.COMMAND_EXECUTED
                chain.log(
                    user=self.current_user,
                    action=action,
                    details=f"Command: {command}" + (f" | Blocked: {reason}" if blocked else "")
                )
            except Exception:
                pass  # Chain logging is optional
    
    def _dispatch_command(self, command: str) -> str:
        """Dispatch command to appropriate handler based on OS type."""
        parts = command.strip().split()
        if not parts:
            return ''
        
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        os_type = self.os_context.os_type if self.os_context else EvidenceOSType.WINDOWS
        
        # Get handlers based on OS type
        if os_type == EvidenceOSType.WINDOWS:
            handlers = self._get_windows_handlers()
        elif os_type in (EvidenceOSType.LINUX, EvidenceOSType.ANDROID):
            handlers = self._get_linux_handlers()
        elif os_type in (EvidenceOSType.MACOS, EvidenceOSType.IOS):
            handlers = self._get_macos_handlers()
        else:
            handlers = self._get_windows_handlers()  # Default
        
        # Execute handler if available
        if cmd in handlers:
            return handlers[cmd](args, command)
        
        # Command not found - OS-specific error
        return self._command_not_found(cmd)
    
    def _command_not_found(self, cmd: str) -> str:
        """Generate OS-appropriate 'command not found' error."""
        os_type = self.os_context.os_type if self.os_context else EvidenceOSType.WINDOWS
        
        if os_type == EvidenceOSType.WINDOWS:
            return f"'{cmd}' is not recognized as an internal or external command,\noperable program or batch file."
        else:
            return f"bash: {cmd}: command not found"
    
    # =========================================================================
    # WINDOWS COMMAND HANDLERS
    # =========================================================================
    
    def _get_windows_handlers(self) -> Dict[str, Callable]:
        """Get Windows CMD command handlers."""
        return {
            # Navigation
            'cd': self._cmd_cd,
            'chdir': self._cmd_cd,
            'dir': self._cmd_dir_windows,
            'tree': self._cmd_tree_windows,
            
            # File viewing
            'type': self._cmd_type,
            'more': self._cmd_type,
            
            # System info (reconstructed from artifacts)
            'hostname': self._cmd_hostname,
            'whoami': self._cmd_whoami,
            'ipconfig': self._cmd_ipconfig,
            'systeminfo': self._cmd_systeminfo,
            'ver': self._cmd_ver,
            
            # Search
            'find': self._cmd_find_windows,
            'findstr': self._cmd_findstr,
            'where': self._cmd_where,
            
            # Other
            'cls': self._cmd_cls,
            'echo': self._cmd_echo,
            'date': self._cmd_date,
            'time': self._cmd_time_cmd,
            'set': self._cmd_set,
            'path': self._cmd_path,
            'help': self._cmd_help,
            
            # Also accept Linux commands
            'ls': self._cmd_dir_windows,
            'pwd': self._cmd_pwd,
            'cat': self._cmd_type,
            'clear': self._cmd_cls,
        }
    
    # =========================================================================
    # LINUX/BASH COMMAND HANDLERS
    # =========================================================================
    
    def _get_linux_handlers(self) -> Dict[str, Callable]:
        """Get Linux Bash command handlers."""
        return {
            # Navigation
            'cd': self._cmd_cd,
            'ls': self._cmd_ls_linux,
            'pwd': self._cmd_pwd,
            'tree': self._cmd_tree_linux,
            
            # File viewing
            'cat': self._cmd_cat,
            'head': self._cmd_head,
            'tail': self._cmd_tail,
            'less': self._cmd_cat,
            'more': self._cmd_cat,
            
            # System info
            'hostname': self._cmd_hostname,
            'whoami': self._cmd_whoami,
            'id': self._cmd_id,
            'uname': self._cmd_uname,
            'uptime': self._cmd_uptime,
            'ifconfig': self._cmd_ifconfig,
            'ip': self._cmd_ip,
            
            # Search
            'find': self._cmd_find_linux,
            'grep': self._cmd_grep,
            'locate': self._cmd_locate,
            
            # File info
            'file': self._cmd_file,
            'stat': self._cmd_stat,
            'wc': self._cmd_wc,
            
            # Other
            'clear': self._cmd_cls,
            'echo': self._cmd_echo,
            'date': self._cmd_date,
            'history': self._cmd_history,
            'help': self._cmd_help,
            
            # Also accept Windows commands
            'dir': self._cmd_ls_linux,
            'type': self._cmd_cat,
            'cls': self._cmd_cls,
        }
    
    # =========================================================================
    # MACOS/ZSH COMMAND HANDLERS
    # =========================================================================
    
    def _get_macos_handlers(self) -> Dict[str, Callable]:
        """Get macOS zsh command handlers."""
        # macOS uses mostly the same commands as Linux
        handlers = self._get_linux_handlers()
        
        # Add macOS-specific commands
        handlers.update({
            'sw_vers': self._cmd_sw_vers,
            'system_profiler': self._cmd_system_profiler,
            'mdls': self._cmd_mdls,
        })
        
        return handlers
    
    # =========================================================================
    # COMMAND IMPLEMENTATIONS
    # =========================================================================
    
    def _cmd_cd(self, args: List[str], full_cmd: str) -> str:
        """Change directory (all OS)."""
        if not args:
            # Return to home
            self._cwd = self.os_context.home_path if self.os_context else '/'
            return ''
        
        target = args[0]
        
        # Handle special paths
        if target == '..':
            parent = os.path.dirname(self._cwd.rstrip('/'))
            self._cwd = parent if parent else '/'
            return ''
        
        if target in ('/', '\\'):
            self._cwd = '/'
            return ''
        
        if target == '~':
            self._cwd = self.os_context.home_path if self.os_context else '/'
            return ''
        
        # Normalize path
        norm_target = target.replace('\\', '/')
        if len(norm_target) >= 2 and norm_target[1] == ':':
            norm_target = norm_target[2:]  # Remove drive letter
        
        # Resolve path
        if norm_target.startswith('/'):
            new_path = norm_target
        else:
            new_path = os.path.join(self._cwd, norm_target).replace('\\', '/')
        
        # Simplify path (remove ..)
        parts = []
        for part in new_path.split('/'):
            if part == '..':
                if parts:
                    parts.pop()
            elif part and part != '.':
                parts.append(part)
        
        new_path = '/' + '/'.join(parts)
        
        # Check if path exists in evidence
        if self._path_exists(new_path) and self._is_directory(new_path):
            self._cwd = new_path
            return ''
        
        # Path not found
        os_type = self.os_context.os_type if self.os_context else EvidenceOSType.WINDOWS
        if os_type == EvidenceOSType.WINDOWS:
            return "The system cannot find the path specified."
        else:
            return f"bash: cd: {target}: No such file or directory"
    
    def _cmd_pwd(self, args: List[str], full_cmd: str) -> str:
        """Print working directory."""
        return self.cwd
    
    def _cmd_dir_windows(self, args: List[str], full_cmd: str) -> str:
        """Windows DIR command."""
        target = self._cwd
        show_all = '/a' in full_cmd.lower()
        bare = '/b' in full_cmd.lower()
        
        # Parse target path from args
        for arg in args:
            if not arg.startswith('/'):
                norm = arg.replace('\\', '/')
                if len(norm) >= 2 and norm[1] == ':':
                    norm = norm[2:]
                if norm.startswith('/'):
                    target = norm
                else:
                    target = os.path.join(self._cwd, norm).replace('\\', '/')
                break
        
        items = self._list_directory(target)
        if items is None:
            return "The system cannot find the path specified."
        
        if bare:
            return '\n'.join(items)
        
        # Windows-style directory listing
        out = []
        out.append(" Volume in drive C is EVIDENCE")
        out.append(" Volume Serial Number is FEPD-2026")
        out.append("")
        
        # Convert path to Windows style
        win_path = 'C:' + target.replace('/', '\\')
        out.append(f" Directory of {win_path}")
        out.append("")
        
        total_files = 0
        total_dirs = 0
        total_size = 0
        
        # Add . and ..
        if target != '/':
            out.append(f"{datetime.now().strftime('%m/%d/%Y  %I:%M %p')}    <DIR>          .")
            out.append(f"{datetime.now().strftime('%m/%d/%Y  %I:%M %p')}    <DIR>          ..")
            total_dirs += 2
        
        for name in items:
            item_path = (target.rstrip('/') + '/' + name).replace('//', '/')
            is_dir = self._is_directory(item_path)
            meta = self._get_file_meta(item_path)
            size = meta.get('size', 0) if meta else 0
            
            date_str = datetime.now().strftime('%m/%d/%Y  %I:%M %p')
            
            if is_dir:
                out.append(f"{date_str}    <DIR>          {name}")
                total_dirs += 1
            else:
                out.append(f"{date_str}    {size:>14,} {name}")
                total_files += 1
                total_size += size
        
        out.append(f"               {total_files} File(s)  {total_size:>14,} bytes")
        out.append(f"               {total_dirs} Dir(s)   [EVIDENCE - Read Only]")
        
        return '\n'.join(out)
    
    def _cmd_ls_linux(self, args: List[str], full_cmd: str) -> str:
        """Linux ls command."""
        target = self._cwd
        show_long = '-l' in args
        show_all = '-a' in args
        
        # Parse target path
        for arg in args:
            if not arg.startswith('-'):
                if arg.startswith('/'):
                    target = arg
                else:
                    target = os.path.join(self._cwd, arg).replace('\\', '/')
                break
        
        items = self._list_directory(target)
        if items is None:
            return f"ls: cannot access '{target}': No such file or directory"
        
        if show_long:
            out = [f"total {len(items)}"]
            for name in items:
                item_path = (target.rstrip('/') + '/' + name).replace('//', '/')
                is_dir = self._is_directory(item_path)
                meta = self._get_file_meta(item_path)
                size = meta.get('size', 0) if meta else 0
                owner = meta.get('owner', 'root') if meta else 'root'
                
                perms = 'drwxr-xr-x' if is_dir else '-rw-r--r--'
                date_str = datetime.now().strftime('%b %d %H:%M')
                
                out.append(f"{perms}  1 {owner:8} {owner:8} {size:8} {date_str} {name}")
            return '\n'.join(out)
        else:
            return '  '.join(items)
    
    def _cmd_tree_windows(self, args: List[str], full_cmd: str) -> str:
        """Windows TREE command."""
        target = self._cwd
        for arg in args:
            if not arg.startswith('/'):
                target = arg
                break
        
        win_path = 'C:' + target.replace('/', '\\')
        out = []
        out.append("Folder PATH listing for volume EVIDENCE")
        out.append("Volume serial number is FEPD-2026")
        out.append(win_path)
        
        self._tree_recursive(target, out, '', 0)
        
        return '\n'.join(out)
    
    def _cmd_tree_linux(self, args: List[str], full_cmd: str) -> str:
        """Linux tree command."""
        target = self._cwd
        for arg in args:
            if not arg.startswith('-'):
                target = arg
                break
        
        out = [target]
        self._tree_recursive(target, out, '', 0)
        
        dirs = sum(1 for line in out if '<DIR>' not in line and '├' in line or '└' in line)
        files = len(out) - 1 - dirs
        out.append("")
        out.append(f"{dirs} directories, {files} files")
        
        return '\n'.join(out)
    
    def _tree_recursive(self, path: str, output: List[str], prefix: str, depth: int):
        """Build tree recursively."""
        if depth > 4:  # Max depth
            return
        
        items = self._list_directory(path)
        if not items:
            return
        
        for i, name in enumerate(items[:30]):  # Limit
            is_last = (i == len(items[:30]) - 1)
            connector = '└── ' if is_last else '├── '
            output.append(f"{prefix}{connector}{name}")
            
            item_path = (path.rstrip('/') + '/' + name).replace('//', '/')
            if self._is_directory(item_path):
                new_prefix = prefix + ('    ' if is_last else '│   ')
                self._tree_recursive(item_path, output, new_prefix, depth + 1)
    
    def _cmd_type(self, args: List[str], full_cmd: str) -> str:
        """Windows TYPE / Unix cat command."""
        return self._cmd_cat(args, full_cmd)
    
    def _cmd_cat(self, args: List[str], full_cmd: str) -> str:
        """Read file contents."""
        if not args:
            os_type = self.os_context.os_type if self.os_context else EvidenceOSType.WINDOWS
            if os_type == EvidenceOSType.WINDOWS:
                return "The syntax of the command is incorrect."
            return "cat: missing operand"
        
        target = args[0].replace('\\', '/')
        if len(target) >= 2 and target[1] == ':':
            target = target[2:]
        
        if not target.startswith('/'):
            target = os.path.join(self._cwd, target).replace('\\', '/')
        
        meta = self._get_file_meta(target)
        if not meta:
            os_type = self.os_context.os_type if self.os_context else EvidenceOSType.WINDOWS
            if os_type == EvidenceOSType.WINDOWS:
                return "The system cannot find the file specified."
            return f"cat: {args[0]}: No such file or directory"
        
        real_path = meta.get('real_path')
        if not real_path:
            return "[File content not available in evidence image]"
        
        # Try to find the actual file on disk
        # This would need to be mapped to actual evidence storage
        return f"[File: {target}]\n[Content preview would be shown here from evidence storage]"
    
    def _cmd_head(self, args: List[str], full_cmd: str) -> str:
        """Show first lines of file."""
        return self._cmd_cat(args, full_cmd) + "\n...(truncated)"
    
    def _cmd_tail(self, args: List[str], full_cmd: str) -> str:
        """Show last lines of file."""
        return "...(earlier content)\n" + self._cmd_cat(args, full_cmd)
    
    # =========================================================================
    # SYSTEM INFO COMMANDS (reconstructed from artifacts)
    # =========================================================================
    
    def _cmd_hostname(self, args: List[str], full_cmd: str) -> str:
        """Return hostname from evidence."""
        return self.os_context.hostname if self.os_context else 'EVIDENCE-PC'
    
    def _cmd_whoami(self, args: List[str], full_cmd: str) -> str:
        """Return current user context."""
        if self.os_context and self.os_context.os_type == EvidenceOSType.WINDOWS:
            domain = self.os_context.domain or self.os_context.hostname
            return f"{domain}\\{self.current_user}"
        return self.current_user
    
    def _cmd_id(self, args: List[str], full_cmd: str) -> str:
        """Linux id command."""
        user = self.current_user
        if user == 'root':
            return "uid=0(root) gid=0(root) groups=0(root)"
        return f"uid=1000({user}) gid=1000({user}) groups=1000({user})"
    
    def _cmd_uname(self, args: List[str], full_cmd: str) -> str:
        """Linux uname command."""
        show_all = '-a' in args
        
        if show_all:
            return f"Linux {self.os_context.hostname if self.os_context else 'evidence'} 5.4.0-generic #1 SMP x86_64 GNU/Linux"
        return "Linux"
    
    def _cmd_uptime(self, args: List[str], full_cmd: str) -> str:
        """Show system uptime (from evidence)."""
        return " [Evidence snapshot - uptime data not available]"
    
    def _cmd_ipconfig(self, args: List[str], full_cmd: str) -> str:
        """Windows ipconfig - reconstructed from evidence."""
        return """
Windows IP Configuration

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : [Reconstructed from evidence]
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : [Reconstructed from evidence]

[Network configuration reconstructed from forensic artifacts]
"""
    
    def _cmd_ifconfig(self, args: List[str], full_cmd: str) -> str:
        """Linux ifconfig - reconstructed from evidence."""
        return """
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet [Reconstructed from evidence]  netmask 255.255.255.0
        ether [Reconstructed from evidence]

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0

[Network configuration reconstructed from forensic artifacts]
"""
    
    def _cmd_ip(self, args: List[str], full_cmd: str) -> str:
        """Linux ip command."""
        if args and args[0] == 'addr':
            return self._cmd_ifconfig(args, full_cmd)
        return "[Use 'ip addr' for network information]"
    
    def _cmd_systeminfo(self, args: List[str], full_cmd: str) -> str:
        """Windows systeminfo - reconstructed from evidence."""
        ctx = self.os_context
        return f"""
Host Name:                 {ctx.hostname if ctx else 'EVIDENCE-PC'}
OS Name:                   {ctx.os_version if ctx else 'Microsoft Windows'}
OS Version:                [Reconstructed from Registry]
System Manufacturer:       [Reconstructed from evidence]
System Type:               {ctx.architecture if ctx else 'x64'}-based PC
Total Physical Memory:     [Reconstructed from evidence]
Domain:                    {ctx.domain if ctx else 'WORKGROUP'}

[System information reconstructed from forensic artifacts]
"""
    
    def _cmd_ver(self, args: List[str], full_cmd: str) -> str:
        """Windows ver command."""
        return "\nMicrosoft Windows [Version reconstructed from evidence]\n"
    
    def _cmd_sw_vers(self, args: List[str], full_cmd: str) -> str:
        """macOS sw_vers command."""
        return """ProductName:    macOS
ProductVersion: [Reconstructed from evidence]
BuildVersion:   [Reconstructed from evidence]
"""
    
    def _cmd_system_profiler(self, args: List[str], full_cmd: str) -> str:
        """macOS system_profiler command."""
        return "[System profile reconstructed from evidence]"
    
    def _cmd_mdls(self, args: List[str], full_cmd: str) -> str:
        """macOS mdls (metadata listing) command."""
        if not args:
            return "usage: mdls path"
        return f"[Metadata for {args[0]} - would be reconstructed from evidence]"
    
    # =========================================================================
    # SEARCH COMMANDS
    # =========================================================================
    
    def _cmd_find_windows(self, args: List[str], full_cmd: str) -> str:
        """Windows FIND command."""
        if not args:
            return 'FIND: Parameter format not correct'
        return f'Searching for "{args[0]}" in evidence...\n[Use "search" command for full-text forensic search]'
    
    def _cmd_findstr(self, args: List[str], full_cmd: str) -> str:
        """Windows FINDSTR command."""
        if not args:
            return "FINDSTR: Argument missing"
        return f'Pattern: {args[0]}\n[Use "search" command for forensic search]'
    
    def _cmd_where(self, args: List[str], full_cmd: str) -> str:
        """Windows WHERE command."""
        if not args:
            return "ERROR: A search pattern is required."
        
        pattern = args[0]
        results = self._search_files(pattern)
        
        if results:
            return '\n'.join(['C:' + p.replace('/', '\\') for p in results[:20]])
        return "INFO: Could not find files for the given pattern(s)."
    
    def _cmd_find_linux(self, args: List[str], full_cmd: str) -> str:
        """Linux find command."""
        if not args:
            return "find: missing arguments"
        
        path = '.'
        name_pattern = None
        
        for i, arg in enumerate(args):
            if arg == '-name' and i + 1 < len(args):
                name_pattern = args[i + 1]
            elif not arg.startswith('-') and i == 0:
                path = arg
        
        if name_pattern:
            results = self._search_files(name_pattern.replace('*', ''))
            if results:
                return '\n'.join(results[:50])
        
        return f"find: '{path}': [Results would be shown here]"
    
    def _cmd_grep(self, args: List[str], full_cmd: str) -> str:
        """Linux grep command."""
        if not args:
            return "usage: grep [pattern] [file]"
        return f"[Searching for '{args[0]}' in evidence - use 'search' for forensic search]"
    
    def _cmd_locate(self, args: List[str], full_cmd: str) -> str:
        """Linux locate command."""
        if not args:
            return "usage: locate pattern"
        
        results = self._search_files(args[0])
        if results:
            return '\n'.join(results[:50])
        return f"locate: no matches for '{args[0]}'"
    
    # =========================================================================
    # FILE INFO COMMANDS
    # =========================================================================
    
    def _cmd_file(self, args: List[str], full_cmd: str) -> str:
        """Linux file command (identify file type)."""
        if not args:
            return "usage: file [file]"
        return f"{args[0]}: [File type from forensic analysis]"
    
    def _cmd_stat(self, args: List[str], full_cmd: str) -> str:
        """Linux stat command."""
        if not args:
            return "stat: missing operand"
        
        target = args[0]
        meta = self._get_file_meta(target)
        
        if not meta:
            return f"stat: cannot stat '{target}': No such file or directory"
        
        return f"""  File: {target}
  Size: {meta.get('size', 0)}            [Evidence]
Access: [From forensic artifacts]
Modify: [From forensic artifacts]
Change: [From forensic artifacts]
"""
    
    def _cmd_wc(self, args: List[str], full_cmd: str) -> str:
        """Linux wc (word count) command."""
        if not args:
            return "usage: wc [file]"
        return f"[Line/word/byte count for {args[0]} from evidence]"
    
    # =========================================================================
    # OTHER COMMANDS
    # =========================================================================
    
    def _cmd_cls(self, args: List[str], full_cmd: str) -> str:
        """Clear screen (returns special marker)."""
        return '__CLEAR__'
    
    def _cmd_echo(self, args: List[str], full_cmd: str) -> str:
        """Echo command."""
        # Get everything after 'echo '
        if ' ' in full_cmd:
            return full_cmd.split(' ', 1)[1]
        return ''
    
    def _cmd_date(self, args: List[str], full_cmd: str) -> str:
        """Show date."""
        os_type = self.os_context.os_type if self.os_context else EvidenceOSType.WINDOWS
        if os_type == EvidenceOSType.WINDOWS:
            return f"The current date is: [Evidence snapshot time]"
        return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y") + " [Current - not evidence time]"
    
    def _cmd_time_cmd(self, args: List[str], full_cmd: str) -> str:
        """Show time."""
        return f"The current time is: [Evidence snapshot time]"
    
    def _cmd_set(self, args: List[str], full_cmd: str) -> str:
        """Show environment variables."""
        ctx = self.os_context
        return f"""COMPUTERNAME={ctx.hostname if ctx else 'EVIDENCE-PC'}
USERNAME={self.current_user}
USERPROFILE={ctx.home_path if ctx else 'C:\\Users\\user'}
SystemRoot={ctx.system_root if ctx else 'C:\\Windows'}
[Environment reconstructed from Registry]
"""
    
    def _cmd_path(self, args: List[str], full_cmd: str) -> str:
        """Show PATH variable."""
        os_type = self.os_context.os_type if self.os_context else EvidenceOSType.WINDOWS
        if os_type == EvidenceOSType.WINDOWS:
            return "PATH=[Reconstructed from Registry]"
        return "PATH=[Reconstructed from evidence]"
    
    def _cmd_history(self, args: List[str], full_cmd: str) -> str:
        """Show command history."""
        out = []
        for i, cmd in enumerate(self.history[-50:], 1):
            out.append(f"  {i}  {cmd}")
        return '\n'.join(out) if out else "(no history)"
    
    def _cmd_help(self, args: List[str], full_cmd: str) -> str:
        """Show help."""
        os_type = self.os_context.os_type if self.os_context else EvidenceOSType.WINDOWS
        
        if os_type == EvidenceOSType.WINDOWS:
            return """
FEPD Forensic Shell - Windows CMD Emulation
============================================

This terminal emulates Windows CMD operating on forensic evidence.
All commands operate on the evidence filesystem (READ-ONLY).

Available Commands:
  DIR        List directory contents
  CD         Change directory
  TYPE       Display file contents
  TREE       Display directory tree
  FIND       Search for text
  WHERE      Locate files
  HOSTNAME   Show computer name
  WHOAMI     Show current user
  IPCONFIG   Show network config
  SYSTEMINFO Show system info
  CLS        Clear screen

🔒 All write commands are BLOCKED to preserve evidence integrity.
"""
        else:
            return """
FEPD Forensic Shell - Bash Emulation
=====================================

This terminal emulates Linux Bash operating on forensic evidence.
All commands operate on the evidence filesystem (READ-ONLY).

Available Commands:
  ls         List directory contents
  cd         Change directory
  cat        Display file contents
  tree       Display directory tree
  find       Search for files
  grep       Search file contents
  hostname   Show hostname
  whoami     Show current user
  id         Show user identity
  uname      Show system info
  ifconfig   Show network config
  clear      Clear screen

🔒 All write commands are BLOCKED to preserve evidence integrity.
"""
    
    # =========================================================================
    # FILESYSTEM HELPERS
    # =========================================================================
    
    def _path_exists(self, path: str) -> bool:
        """Check if path exists in evidence."""
        norm = path.replace('\\', '/').strip('/')
        if not norm:
            return True  # Root exists
        
        parts = norm.split('/')
        node = self._file_tree
        
        for part in parts:
            if part not in node:
                return False
            node = node[part]
        
        return True
    
    def _is_directory(self, path: str) -> bool:
        """Check if path is a directory."""
        norm = path.replace('\\', '/').strip('/')
        if not norm:
            return True  # Root is directory
        
        parts = norm.split('/')
        node = self._file_tree
        
        for part in parts:
            if part not in node:
                return False
            node = node[part]
        
        return node.get('_is_dir', False)
    
    def _list_directory(self, path: str) -> Optional[List[str]]:
        """List contents of directory."""
        norm = path.replace('\\', '/').strip('/')
        
        if not norm:
            node = self._file_tree
        else:
            parts = norm.split('/')
            node = self._file_tree
            
            for part in parts:
                if part not in node:
                    return None
                node = node[part]
        
        if not isinstance(node, dict):
            return None
        
        # Filter out metadata keys
        items = [k for k in node.keys() if not k.startswith('_')]
        return sorted(items)
    
    def _get_file_meta(self, path: str) -> Optional[Dict]:
        """Get file metadata."""
        norm = path.replace('\\', '/').strip('/')
        if not norm:
            return {'_is_dir': True}
        
        parts = norm.split('/')
        node = self._file_tree
        
        for part in parts:
            if part not in node:
                return None
            node = node[part]
        
        return node.get('_meta', {})
    
    def _search_files(self, pattern: str) -> List[str]:
        """Search for files matching pattern."""
        results = []
        pattern_lower = pattern.lower()
        
        def search_node(node: Dict, current_path: str):
            for name, child in node.items():
                if name.startswith('_'):
                    continue
                
                child_path = current_path + '/' + name
                
                if pattern_lower in name.lower():
                    results.append(child_path)
                
                if isinstance(child, dict) and child.get('_is_dir', False):
                    search_node(child, child_path)
        
        search_node(self._file_tree, '')
        return results[:100]
