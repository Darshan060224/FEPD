"""
FEPD Evidence CMD - Virtual Operating System Terminal
======================================================

This module provides the terminal interface that makes the user feel like
they are inside the compromised machine's command line.

The terminal:
- Uses the VEOS layer for all operations
- Maps every command to evidence, not host OS
- Blocks all mutating commands
- Logs every action to Chain of Custody
- Shows evidence-native prompt: fepd:<case>[<user>]$

The user experience is:
"I am typing commands in the dead machine's own terminal,
but it's frozen in time and I cannot modify anything."

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import os
import re
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Callable, Any
from pathlib import Path
import logging

from ..core.veos import (
    VirtualEvidenceOS, VEOSFile, OSPlatform,
    get_veos, set_veos, create_veos
)

logger = logging.getLogger(__name__)


# ============================================================================
# MUTATING COMMANDS (BLOCKED)
# ============================================================================

WINDOWS_MUTATING_COMMANDS = {
    'del', 'erase', 'rd', 'rmdir', 'rm', 'copy', 'xcopy', 'robocopy',
    'move', 'ren', 'rename', 'md', 'mkdir', 'format', 'attrib',
    'reg', 'regedit', 'net', 'sc', 'schtasks', 'runas', 'powershell',
    'cmd', 'start', 'shutdown', 'restart', 'logoff', 'taskkill',
    'wmic', 'bcdedit', 'diskpart', 'cacls', 'icacls', 'takeown',
    'cipher', 'compact', 'fsutil'
}

UNIX_MUTATING_COMMANDS = {
    'rm', 'rmdir', 'mv', 'cp', 'ln', 'chmod', 'chown', 'chgrp',
    'mkdir', 'touch', 'dd', 'mkfs', 'mount', 'umount', 'fdisk',
    'parted', 'apt', 'apt-get', 'yum', 'dnf', 'pacman', 'brew',
    'pip', 'npm', 'systemctl', 'service', 'kill', 'pkill', 'killall',
    'reboot', 'shutdown', 'halt', 'poweroff', 'init', 'crontab',
    'useradd', 'userdel', 'usermod', 'groupadd', 'passwd', 'su', 'sudo'
}


def is_mutating_command(command: str, platform: OSPlatform) -> Tuple[bool, str]:
    """
    Check if a command would modify evidence.
    
    Args:
        command: The command string
        platform: Target platform
        
    Returns:
        (is_mutating, reason)
    """
    if not command:
        return False, ""
    
    cmd = command.split()[0].lower()
    
    # Check platform-specific mutating commands
    if platform == OSPlatform.WINDOWS:
        mutating = WINDOWS_MUTATING_COMMANDS
    else:
        mutating = UNIX_MUTATING_COMMANDS
    
    if cmd in mutating:
        return True, f"'{cmd}' modifies filesystem"
    
    # Check for redirect operators
    if '>' in command or '>>' in command:
        return True, "Output redirection would create/modify files"
    
    # Check for pipe to tee
    if '| tee' in command:
        return True, "Pipe to tee would create files"
    
    return False, ""


# ============================================================================
# EVIDENCE CMD - The Virtual Terminal
# ============================================================================

class EvidenceCMD:
    """
    Evidence CMD - The terminal that makes the dead system come alive.
    
    Features:
    - Evidence-native prompt: fepd:<case>[<user>]$
    - Maps all commands to VEOS (not host OS)
    - Blocks mutating commands with forensic warnings
    - Supports Windows and Unix commands based on evidence platform
    - All operations logged to Chain of Custody
    """
    
    def __init__(self, veos: VirtualEvidenceOS, case_name: str = "CASE"):
        """
        Initialize Evidence CMD.
        
        Args:
            veos: The Virtual Evidence OS instance
            case_name: Name of the forensic case
        """
        self.veos = veos
        self.case_name = case_name
        self.history: List[str] = []
        self.audit_log: List[Dict] = []
        
        # Current user context (from VEOS)
        self._current_user = "Investigator"
        if veos.users:
            self._current_user = next(iter(veos.users.keys()))
    
    @property
    def prompt(self) -> str:
        """
        Get the evidence-native prompt.
        
        Format: fepd:<case>[<user>]$
        
        Example: fepd:LoneWolf[Alice]$
        """
        cwd = self.veos.cwd
        user = self._current_user
        return f"fepd:{self.case_name}[{user}]$ "
    
    @property
    def platform(self) -> OSPlatform:
        """Get the evidence platform."""
        return self.veos.platform
    
    @property
    def cwd(self) -> str:
        """Get current working directory in display format."""
        return self.veos.cwd
    
    def execute(self, command: str) -> Tuple[str, bool]:
        """
        Execute a command in the evidence context.
        
        Args:
            command: The command to execute
            
        Returns:
            (output, was_blocked)
        """
        command = command.strip()
        if not command:
            return '', False
        
        # Add to history
        self.history.append(command)
        
        # Check if mutating
        is_mut, reason = is_mutating_command(command, self.platform)
        
        if is_mut:
            output = self._block_command(command, reason)
            self._log_command(command, output, blocked=True, reason=reason)
            return output, True
        
        # Parse and execute
        output = self._dispatch(command)
        self._log_command(command, output)
        return output, False
    
    def _block_command(self, command: str, reason: str) -> str:
        """Generate the forensic block message."""
        cmd_name = command.split()[0]
        
        return f"""
╔══════════════════════════════════════════════════════════════════════════╗
║  🚫 [BLOCKED] This command would modify evidence.                         ║
║                                                                           ║
║  Command: {cmd_name:<60} ║
║  Reason:  {reason:<60} ║
║                                                                           ║
║  ✓ Evidence integrity preserved                                           ║
║  ✓ Hash values unchanged                                                  ║
║  ✓ Attempt logged to Chain of Custody                                     ║
║                                                                           ║
║  💡 TIP: Use read-only commands like dir, type, cat, ls, tree             ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
    
    def _log_command(self, command: str, output: str, 
                     blocked: bool = False, reason: str = ""):
        """Log command to audit trail."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'user': self._current_user,
            'case': self.case_name,
            'cwd': self.cwd,
            'command': command,
            'blocked': blocked,
            'reason': reason,
            'output_length': len(output)
        }
        self.audit_log.append(entry)
        
        # Log to file if case path available
        if self.veos.case_path:
            try:
                log_file = self.veos.case_path / "terminal_audit.log"
                with open(log_file, 'a', encoding='utf-8') as f:
                    action = "BLOCKED" if blocked else "EXECUTED"
                    f.write(f"[{entry['timestamp']}] [{action}] {command}\n")
            except Exception as e:
                logger.warning(f"Could not write to audit log: {e}")
    
    def _dispatch(self, command: str) -> str:
        """Dispatch command to appropriate handler."""
        parts = command.strip().split()
        if not parts:
            return ''
        
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Get handlers for platform
        handlers = self._get_handlers()
        
        if cmd in handlers:
            return handlers[cmd](args, command)
        
        # Command not found
        return self._command_not_found(cmd)
    
    def _get_handlers(self) -> Dict[str, Callable]:
        """Get command handlers based on platform."""
        # Common handlers
        handlers = {
            # Navigation
            'cd': self._cmd_cd,
            'pwd': self._cmd_pwd,
            
            # Clear
            'cls': self._cmd_clear,
            'clear': self._cmd_clear,
            
            # Echo/Print
            'echo': self._cmd_echo,
            
            # Help
            'help': self._cmd_help,
            '?': self._cmd_help,
            
            # History
            'history': self._cmd_history,
            
            # System info
            'whoami': self._cmd_whoami,
            'hostname': self._cmd_hostname,
        }
        
        # Platform-specific handlers
        if self.platform == OSPlatform.WINDOWS:
            handlers.update({
                'dir': self._cmd_dir,
                'tree': self._cmd_tree,
                'type': self._cmd_type,
                'more': self._cmd_type,
                'find': self._cmd_find,
                'findstr': self._cmd_findstr,
                'where': self._cmd_where,
                'attrib': self._cmd_attrib_ro,
                'ver': self._cmd_ver,
                'systeminfo': self._cmd_systeminfo,
                'ipconfig': self._cmd_ipconfig,
                'net': self._cmd_net_ro,
                # Also accept Unix commands
                'ls': self._cmd_dir,
                'cat': self._cmd_type,
            })
        else:
            handlers.update({
                'ls': self._cmd_ls,
                'tree': self._cmd_tree_unix,
                'cat': self._cmd_cat,
                'head': self._cmd_head,
                'tail': self._cmd_tail,
                'find': self._cmd_find_unix,
                'grep': self._cmd_grep,
                'file': self._cmd_file,
                'stat': self._cmd_stat,
                'uname': self._cmd_uname,
                'id': self._cmd_id,
                # Also accept Windows commands
                'dir': self._cmd_ls,
                'type': self._cmd_cat,
            })
        
        return handlers
    
    def _command_not_found(self, cmd: str) -> str:
        """Return 'command not found' error."""
        if self.platform == OSPlatform.WINDOWS:
            return f"'{cmd}' is not recognized as an internal or external command,\noperable program or batch file."
        return f"bash: {cmd}: command not found"
    
    # =========================================================================
    # COMMAND IMPLEMENTATIONS
    # =========================================================================
    
    def _cmd_cd(self, args: List[str], full_cmd: str) -> str:
        """Change directory."""
        if not args:
            # Go to user home
            if self._current_user in self.veos.users:
                home = self.veos.users[self._current_user].home_path
                self.veos.cwd = home
            return ''
        
        target = args[0]
        
        # Handle special paths
        if target == '..':
            current = self.veos._cwd
            parent = os.path.dirname(current.rstrip('/'))
            self.veos._cwd = parent if parent else '/'
            return ''
        
        if target in ('/', '\\'):
            self.veos._cwd = '/'
            return ''
        
        if target == '~':
            if self._current_user in self.veos.users:
                home = self.veos.users[self._current_user].home_path
                self.veos.cwd = home
            return ''
        
        # Normalize and resolve path
        norm = target.replace('\\', '/')
        
        # Remove drive letter if present
        if len(norm) >= 2 and norm[1] == ':':
            norm = norm[2:]
        
        # Resolve relative vs absolute
        if norm.startswith('/'):
            new_path = norm
        else:
            new_path = (self.veos._cwd.rstrip('/') + '/' + norm).replace('//', '/')
        
        # Simplify (handle ..)
        parts = []
        for p in new_path.split('/'):
            if p == '..':
                if parts:
                    parts.pop()
            elif p and p != '.':
                parts.append(p)
        
        new_path = '/' + '/'.join(parts)
        
        # Check if exists and is directory
        if self.veos.path_exists(new_path) and self.veos.is_directory(new_path):
            self.veos._cwd = new_path
            return ''
        
        # Error
        if self.platform == OSPlatform.WINDOWS:
            return "The system cannot find the path specified."
        return f"bash: cd: {target}: No such file or directory"
    
    def _cmd_pwd(self, args: List[str], full_cmd: str) -> str:
        """Print working directory."""
        return self.cwd
    
    def _cmd_dir(self, args: List[str], full_cmd: str) -> str:
        """Windows DIR command."""
        target = self.veos._cwd
        bare = '/b' in full_cmd.lower()
        wide = '/w' in full_cmd.lower()
        
        # Parse target from args
        for arg in args:
            if not arg.startswith('/'):
                norm = arg.replace('\\', '/')
                if len(norm) >= 2 and norm[1] == ':':
                    norm = norm[2:]
                if norm.startswith('/'):
                    target = norm
                else:
                    target = (self.veos._cwd.rstrip('/') + '/' + norm).replace('//', '/')
                break
        
        # List directory
        items = self.veos.list_dir(target)
        
        if bare:
            return '\n'.join(f.name for f in items)
        
        # Windows-style output
        out = []
        out.append(" Volume in drive C is EVIDENCE")
        out.append(" Volume Serial Number is FEPD-2026")
        out.append("")
        
        # Display path
        display_path = self.veos.path_sanitizer.sanitize(target)
        out.append(f" Directory of {display_path}")
        out.append("")
        
        total_files = 0
        total_dirs = 0
        total_size = 0
        
        # Add . and ..
        if target != '/':
            now = datetime.now().strftime('%m/%d/%Y  %I:%M %p')
            out.append(f"{now}    <DIR>          .")
            out.append(f"{now}    <DIR>          ..")
            total_dirs += 2
        
        for item in items:
            date_str = item.modified.strftime('%m/%d/%Y  %I:%M %p') if item.modified else datetime.now().strftime('%m/%d/%Y  %I:%M %p')
            
            if item.is_directory:
                out.append(f"{date_str}    <DIR>          {item.name}")
                total_dirs += 1
            else:
                out.append(f"{date_str}    {item.size:>14,} {item.name}")
                total_files += 1
                total_size += item.size
        
        out.append(f"               {total_files} File(s)  {total_size:>14,} bytes")
        out.append(f"               {total_dirs} Dir(s)   [EVIDENCE - Read Only]")
        
        return '\n'.join(out)
    
    def _cmd_ls(self, args: List[str], full_cmd: str) -> str:
        """Unix ls command."""
        target = self.veos._cwd
        long_format = '-l' in args
        show_all = '-a' in args
        human_readable = '-h' in args
        
        # Parse target
        for arg in args:
            if not arg.startswith('-'):
                if arg.startswith('/'):
                    target = arg
                else:
                    target = (self.veos._cwd.rstrip('/') + '/' + arg).replace('//', '/')
                break
        
        items = self.veos.list_dir(target)
        
        if long_format:
            out = [f"total {len(items)}"]
            for item in items:
                perms = 'drwxr-xr-x' if item.is_directory else '-rw-r--r--'
                owner = item.owner or 'root'
                size = item.size
                
                if human_readable and size > 1024:
                    if size > 1024 * 1024 * 1024:
                        size_str = f"{size / (1024*1024*1024):.1f}G"
                    elif size > 1024 * 1024:
                        size_str = f"{size / (1024*1024):.1f}M"
                    else:
                        size_str = f"{size / 1024:.1f}K"
                else:
                    size_str = str(size)
                
                date_str = item.modified.strftime('%b %d %H:%M') if item.modified else datetime.now().strftime('%b %d %H:%M')
                
                out.append(f"{perms}  1 {owner:8} {owner:8} {size_str:>8} {date_str} {item.name}")
            return '\n'.join(out)
        
        return '  '.join(item.name for item in items)
    
    def _cmd_tree(self, args: List[str], full_cmd: str) -> str:
        """Windows TREE command."""
        target = self.veos._cwd
        for arg in args:
            if not arg.startswith('/'):
                target = arg
                break
        
        display_path = self.veos.path_sanitizer.sanitize(target)
        out = []
        out.append("Folder PATH listing for volume EVIDENCE")
        out.append("Volume serial number is FEPD-2026")
        out.append(display_path)
        
        self._tree_recursive(target, out, '', 0)
        
        return '\n'.join(out)
    
    def _cmd_tree_unix(self, args: List[str], full_cmd: str) -> str:
        """Unix tree command."""
        target = self.veos._cwd
        for arg in args:
            if not arg.startswith('-'):
                target = arg
                break
        
        out = [self.veos.path_sanitizer.sanitize(target)]
        dir_count, file_count = self._tree_recursive(target, out, '', 0)
        
        out.append(f"\n{dir_count} directories, {file_count} files")
        return '\n'.join(out)
    
    def _tree_recursive(self, path: str, output: List[str], prefix: str, depth: int) -> Tuple[int, int]:
        """Build tree recursively."""
        dir_count = 0
        file_count = 0
        
        if depth > 4:  # Max depth
            return dir_count, file_count
        
        items = self.veos.list_dir(path)
        items = items[:30]  # Limit for performance
        
        for i, item in enumerate(items):
            is_last = (i == len(items) - 1)
            connector = '└── ' if is_last else '├── '
            output.append(f"{prefix}{connector}{item.name}")
            
            if item.is_directory:
                dir_count += 1
                new_prefix = prefix + ('    ' if is_last else '│   ')
                sub_dirs, sub_files = self._tree_recursive(
                    item.internal_path, output, new_prefix, depth + 1
                )
                dir_count += sub_dirs
                file_count += sub_files
            else:
                file_count += 1
        
        return dir_count, file_count
    
    def _cmd_type(self, args: List[str], full_cmd: str) -> str:
        """Windows TYPE command."""
        return self._cmd_cat(args, full_cmd)
    
    def _cmd_cat(self, args: List[str], full_cmd: str) -> str:
        """Read file contents."""
        if not args:
            if self.platform == OSPlatform.WINDOWS:
                return "The syntax of the command is incorrect."
            return "cat: missing operand"
        
        target = args[0].replace('\\', '/')
        if len(target) >= 2 and target[1] == ':':
            target = target[2:]
        
        if not target.startswith('/'):
            target = (self.veos._cwd.rstrip('/') + '/' + target).replace('//', '/')
        
        vfile = self.veos.get_file(target)
        if not vfile:
            if self.platform == OSPlatform.WINDOWS:
                return "The system cannot find the file specified."
            return f"cat: {args[0]}: No such file or directory"
        
        # Try to read content
        content = self.veos.read_file(target)
        if content:
            try:
                return content.decode('utf-8', errors='replace')
            except:
                return f"[Binary file - {len(content)} bytes]"
        
        return f"[File: {vfile.display_path}]\n[Size: {vfile.size} bytes]\n[Content not available in current evidence extraction]"
    
    def _cmd_head(self, args: List[str], full_cmd: str) -> str:
        """Show first lines of file."""
        content = self._cmd_cat(args, full_cmd)
        lines = content.split('\n')[:10]
        return '\n'.join(lines) + "\n...(truncated)"
    
    def _cmd_tail(self, args: List[str], full_cmd: str) -> str:
        """Show last lines of file."""
        content = self._cmd_cat(args, full_cmd)
        lines = content.split('\n')[-10:]
        return "...(earlier content)\n" + '\n'.join(lines)
    
    def _cmd_find(self, args: List[str], full_cmd: str) -> str:
        """Windows FIND command (search in file)."""
        return "[Use FINDSTR for pattern searching in evidence files]"
    
    def _cmd_findstr(self, args: List[str], full_cmd: str) -> str:
        """Windows FINDSTR command."""
        if not args:
            return "FINDSTR: No search strings"
        
        pattern = args[0]
        results = []
        for vfile in self.veos.search(pattern):
            results.append(vfile.display_path)
        
        if results:
            return '\n'.join(results[:50])
        return f"FINDSTR: '{pattern}' not found"
    
    def _cmd_find_unix(self, args: List[str], full_cmd: str) -> str:
        """Unix find command."""
        target = self.veos._cwd
        name_pattern = None
        
        for i, arg in enumerate(args):
            if arg == '-name' and i + 1 < len(args):
                name_pattern = args[i + 1].strip("'\"").replace('*', '')
            elif not arg.startswith('-'):
                target = arg
        
        if not name_pattern:
            # List all files
            results = []
            for vfile in self.veos.search('', target):
                results.append(vfile.display_path)
            return '\n'.join(results[:100])
        
        # Search for pattern
        results = []
        for vfile in self.veos.search(name_pattern, target):
            results.append(vfile.display_path)
        
        return '\n'.join(results[:100]) if results else ""
    
    def _cmd_grep(self, args: List[str], full_cmd: str) -> str:
        """Unix grep command."""
        if not args:
            return "Usage: grep PATTERN [FILE]"
        
        pattern = args[0]
        results = []
        for vfile in self.veos.search(pattern):
            results.append(vfile.display_path)
        
        return '\n'.join(results[:50]) if results else ""
    
    def _cmd_where(self, args: List[str], full_cmd: str) -> str:
        """Windows WHERE command."""
        if not args:
            return "WHERE: Argument not specified"
        
        pattern = args[0]
        results = []
        for vfile in self.veos.search(pattern):
            if pattern.lower() in vfile.name.lower():
                results.append(vfile.display_path)
        
        return '\n'.join(results[:20]) if results else f"INFO: Could not find \"{pattern}\"."
    
    def _cmd_file(self, args: List[str], full_cmd: str) -> str:
        """Unix file command."""
        if not args:
            return "Usage: file FILE"
        
        target = args[0].replace('\\', '/')
        if not target.startswith('/'):
            target = (self.veos._cwd.rstrip('/') + '/' + target).replace('//', '/')
        
        vfile = self.veos.get_file(target)
        if not vfile:
            return f"file: {args[0]}: No such file or directory"
        
        mime = vfile.mime_type or "application/octet-stream"
        return f"{vfile.display_path}: {mime}"
    
    def _cmd_stat(self, args: List[str], full_cmd: str) -> str:
        """Unix stat command."""
        if not args:
            return "Usage: stat FILE"
        
        target = args[0].replace('\\', '/')
        if not target.startswith('/'):
            target = (self.veos._cwd.rstrip('/') + '/' + target).replace('//', '/')
        
        vfile = self.veos.get_file(target)
        if not vfile:
            return f"stat: {args[0]}: No such file or directory"
        
        return f"""  File: {vfile.display_path}
  Size: {vfile.size}         {vfile.mime_type or 'regular file'}
Access: {vfile.accessed.isoformat() if vfile.accessed else 'Unknown'}
Modify: {vfile.modified.isoformat() if vfile.modified else 'Unknown'}
Change: {vfile.created.isoformat() if vfile.created else 'Unknown'}
 Owner: {vfile.owner or 'Unknown'}
  Hash: {vfile.sha256 or 'Not computed'}"""
    
    def _cmd_attrib_ro(self, args: List[str], full_cmd: str) -> str:
        """Windows ATTRIB (read-only mode)."""
        target = self.veos._cwd
        for arg in args:
            if not arg.startswith('/') and not arg.startswith('+') and not arg.startswith('-'):
                target = arg
                break
        
        items = self.veos.list_dir(target)
        out = []
        for item in items:
            attrs = "A" if not item.is_directory else "D"
            if item.is_deleted:
                attrs += "H"
            out.append(f"     {attrs:6} {item.display_path}")
        
        return '\n'.join(out) if out else ""
    
    def _cmd_net_ro(self, args: List[str], full_cmd: str) -> str:
        """Windows NET (read-only views only)."""
        if not args:
            return "[Use 'net user' or 'net localgroup' for user information]"
        
        subcmd = args[0].lower()
        
        if subcmd == 'user':
            # Show users from VEOS
            out = ["User accounts for \\\\EVIDENCE", "-" * 40]
            for user in self.veos.users:
                out.append(user)
            return '\n'.join(out)
        
        if subcmd == 'localgroup':
            return "[Local group information reconstructed from SAM database]"
        
        return f"[NET {subcmd.upper()} information not available in evidence]"
    
    def _cmd_clear(self, args: List[str], full_cmd: str) -> str:
        """Clear screen (returns escape code or empty)."""
        return '\033[2J\033[H'  # ANSI clear
    
    def _cmd_echo(self, args: List[str], full_cmd: str) -> str:
        """Echo text."""
        if not args:
            return "ECHO is on."
        return ' '.join(args)
    
    def _cmd_whoami(self, args: List[str], full_cmd: str) -> str:
        """Show current user."""
        if self.platform == OSPlatform.WINDOWS:
            hostname = self.veos.hostname or 'EVIDENCE'
            return f"{hostname}\\{self._current_user}"
        return self._current_user
    
    def _cmd_hostname(self, args: List[str], full_cmd: str) -> str:
        """Show hostname."""
        return self.veos.hostname or 'EVIDENCE-PC'
    
    def _cmd_ver(self, args: List[str], full_cmd: str) -> str:
        """Windows VER command."""
        version = self.veos.os_version or "Windows [Reconstructed from Evidence]"
        return f"\nMicrosoft {version}\n"
    
    def _cmd_systeminfo(self, args: List[str], full_cmd: str) -> str:
        """Windows SYSTEMINFO command."""
        info = self.veos.get_system_info()
        return f"""
Host Name:                 {info.get('hostname', 'EVIDENCE-PC')}
OS Name:                   {info.get('os_version', 'Microsoft Windows')}
System Type:               x64-based PC
Total Users:               {len(info.get('users', []))}
Drives:                    {', '.join(info.get('drives', ['C:']))}
Total Files in Evidence:   {info.get('total_files', 0)}

[System information reconstructed from forensic artifacts]
[Evidence Sources: {', '.join(info.get('evidence_sources', ['Unknown']))}]
"""
    
    def _cmd_ipconfig(self, args: List[str], full_cmd: str) -> str:
        """Windows IPCONFIG command."""
        return """
Windows IP Configuration

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : [Reconstructed from evidence]
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : [Reconstructed from evidence]

[Network configuration reconstructed from forensic artifacts]
"""
    
    def _cmd_uname(self, args: List[str], full_cmd: str) -> str:
        """Unix uname command."""
        show_all = '-a' in args
        hostname = self.veos.hostname or 'evidence'
        
        if show_all:
            return f"Linux {hostname} 5.4.0-generic #1 SMP x86_64 GNU/Linux"
        return "Linux"
    
    def _cmd_id(self, args: List[str], full_cmd: str) -> str:
        """Unix id command."""
        user = self._current_user
        if user == 'root':
            return "uid=0(root) gid=0(root) groups=0(root)"
        return f"uid=1000({user}) gid=1000({user}) groups=1000({user})"
    
    def _cmd_help(self, args: List[str], full_cmd: str) -> str:
        """Show help."""
        if self.platform == OSPlatform.WINDOWS:
            return """
FEPD Evidence CMD - Forensic Terminal
=====================================

Available commands (read-only):
  dir         List directory contents
  cd          Change directory
  tree        Display directory tree
  type/more   Display file contents
  find/where  Search for files
  attrib      Display file attributes
  whoami      Display current user
  hostname    Display computer name
  systeminfo  Display system information
  ipconfig    Display network configuration
  cls         Clear screen
  help        Show this help

⚠️  All write operations are blocked to preserve evidence.
"""
        return """
FEPD Evidence Shell - Forensic Terminal
=======================================

Available commands (read-only):
  ls          List directory contents
  cd          Change directory
  pwd         Print working directory
  tree        Display directory tree
  cat/head/tail  Display file contents
  find        Search for files
  grep        Search file contents
  stat        Display file information
  file        Identify file type
  whoami      Display current user
  hostname    Display computer name
  uname       Display system information
  id          Display user ID
  clear       Clear screen
  help        Show this help

⚠️  All write operations are blocked to preserve evidence.
"""
    
    def _cmd_history(self, args: List[str], full_cmd: str) -> str:
        """Show command history."""
        out = []
        for i, cmd in enumerate(self.history, 1):
            out.append(f"  {i:4}  {cmd}")
        return '\n'.join(out)
    
    def switch_user(self, username: str) -> bool:
        """Switch user context (for investigation)."""
        if username in self.veos.users:
            self._current_user = username
            # Change to user's home directory
            home = self.veos.users[username].home_path
            if home:
                self.veos.cwd = home
            return True
        return False
    
    def get_available_users(self) -> List[str]:
        """Get list of users available in evidence."""
        return list(self.veos.users.keys())
