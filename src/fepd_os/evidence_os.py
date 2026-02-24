"""
FEPD Evidence OS Detection and Emulation Engine

This module detects the operating system type from forensic evidence and
provides the context needed to emulate the evidence's native shell experience.

When you load a Windows image → Terminal feels like CMD/PowerShell
When you load a Linux image → Terminal feels like Bash
When you load a macOS image → Terminal feels like zsh

Constitutional Principles:
- Everything is READ-ONLY
- Any mutating command is intercepted, logged, and BLOCKED
- The user must feel like they're INSIDE the compromised machine
- But the machine is frozen in time
"""

import os
import re
import sqlite3
import json
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass


class EvidenceOSType(Enum):
    """Detected operating system types from forensic evidence."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class ShellStyle(Enum):
    """Shell emulation styles."""
    CMD = "cmd"           # Windows Command Prompt
    POWERSHELL = "powershell"  # Windows PowerShell
    BASH = "bash"         # Linux/macOS Bash
    ZSH = "zsh"           # macOS zsh
    SH = "sh"             # Generic Unix shell


@dataclass
class EvidenceOSContext:
    """Context about the evidence's operating system."""
    os_type: EvidenceOSType
    shell_style: ShellStyle
    hostname: str
    username: str
    home_path: str
    system_root: str
    computer_name: str
    os_version: str
    architecture: str
    domain: str
    
    def get_prompt(self, cwd: str = None) -> str:
        """Generate native OS-style prompt."""
        if self.os_type == EvidenceOSType.WINDOWS:
            # Windows style: C:\Users\victim>
            path = cwd or self.home_path
            return f"{path}>"
        
        elif self.os_type == EvidenceOSType.LINUX:
            # Linux style: root@evidence:/home/user#
            path = cwd or self.home_path
            # Convert to Unix-style path
            if path.startswith('C:'):
                path = path[2:].replace('\\', '/')
            user = self.username or 'root'
            host = self.hostname or 'evidence'
            suffix = '#' if user == 'root' else '$'
            return f"{user}@{host}:{path}{suffix} "
        
        elif self.os_type == EvidenceOSType.MACOS:
            # macOS zsh style: victim@Macbook ~ %
            path = cwd or self.home_path
            # Collapse home path to ~
            if path.startswith(f'/Users/{self.username}'):
                path = '~' + path[len(f'/Users/{self.username}'):]
            elif path == f'/Users/{self.username}':
                path = '~'
            user = self.username or 'root'
            host = self.hostname or 'Mac'
            suffix = '#' if user == 'root' else '%'
            return f"{user}@{host} {path} {suffix} "
        
        else:
            # Generic fallback
            return f"fepd:{self.hostname}> "


class EvidenceOSDetector:
    """
    Detects the operating system from forensic evidence artifacts.
    
    Uses multiple detection strategies:
    1. File system structure analysis
    2. Registry hive presence (Windows)
    3. Configuration files (/etc/os-release for Linux)
    4. plist files (macOS)
    5. User profile paths
    6. Event log structures
    """
    
    def __init__(self, db_path: str = None, case_path: str = None):
        """
        Initialize detector with evidence database or case path.
        
        Args:
            db_path: Path to the evidence SQLite database
            case_path: Path to the case directory
        """
        self.db_path = db_path
        self.case_path = case_path
        self._file_paths: List[str] = []
        self._loaded = False
    
    def _load_file_paths(self) -> List[str]:
        """Load all file paths from evidence database."""
        if self._loaded:
            return self._file_paths
            
        if self.db_path and os.path.exists(self.db_path):
            try:
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute("SELECT path FROM files")
                self._file_paths = [row[0] for row in cur.fetchall() if row[0]]
                conn.close()
                self._loaded = True
            except Exception:
                pass
        
        return self._file_paths
    
    def detect(self) -> EvidenceOSContext:
        """
        Detect the operating system from evidence.
        
        Returns:
            EvidenceOSContext with detected OS information
        """
        paths = self._load_file_paths()
        
        # Try detection methods in order of reliability
        os_type = self._detect_os_type(paths)
        hostname = self._detect_hostname(paths, os_type)
        username = self._detect_primary_user(paths, os_type)
        home_path = self._detect_home_path(paths, os_type, username)
        system_root = self._detect_system_root(os_type)
        computer_name = hostname
        os_version = self._detect_os_version(paths, os_type)
        architecture = self._detect_architecture(paths, os_type)
        domain = self._detect_domain(paths, os_type)
        shell_style = self._get_shell_style(os_type)
        
        return EvidenceOSContext(
            os_type=os_type,
            shell_style=shell_style,
            hostname=hostname,
            username=username,
            home_path=home_path,
            system_root=system_root,
            computer_name=computer_name,
            os_version=os_version,
            architecture=architecture,
            domain=domain
        )
    
    def _detect_os_type(self, paths: List[str]) -> EvidenceOSType:
        """Detect OS type from file structure."""
        if not paths:
            return EvidenceOSType.UNKNOWN
        
        # Normalize paths for comparison
        normalized = [p.lower().replace('\\', '/') for p in paths]
        
        # Windows indicators (strongest signals first)
        windows_indicators = [
            'windows/system32',
            'users/default',
            'program files',
            'programdata',
            'ntuser.dat',
            '.evtx',
            'system32/config',
            'appdata/local',
            'appdata/roaming',
        ]
        
        # Linux indicators
        linux_indicators = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/os-release',
            '/home/',
            '/var/log/syslog',
            '/var/log/auth.log',
            '/usr/bin/',
            '/usr/lib/',
            '/etc/fstab',
        ]
        
        # macOS indicators
        macos_indicators = [
            '/users/',
            '/library/',
            '/applications/',
            '/system/library/',
            '.plist',
            '/private/var/',
            '/cores/',
            'library/preferences',
        ]
        
        # Android indicators
        android_indicators = [
            '/data/data/',
            '/system/app/',
            '/system/framework/',
            'com.android.',
            '/sdcard/',
            'build.prop',
        ]
        
        # iOS indicators
        ios_indicators = [
            '/private/var/mobile/',
            '/var/mobile/applications/',
            '/applications/mobilesafari.app',
            'consolidated.db',
        ]
        
        # Score each OS type
        scores = {
            EvidenceOSType.WINDOWS: 0,
            EvidenceOSType.LINUX: 0,
            EvidenceOSType.MACOS: 0,
            EvidenceOSType.ANDROID: 0,
            EvidenceOSType.IOS: 0,
        }
        
        for path in normalized[:1000]:  # Sample first 1000 for performance
            for indicator in windows_indicators:
                if indicator in path:
                    scores[EvidenceOSType.WINDOWS] += 1
            for indicator in linux_indicators:
                if indicator in path:
                    scores[EvidenceOSType.LINUX] += 1
            for indicator in macos_indicators:
                if indicator in path:
                    scores[EvidenceOSType.MACOS] += 1
            for indicator in android_indicators:
                if indicator in path:
                    scores[EvidenceOSType.ANDROID] += 1
            for indicator in ios_indicators:
                if indicator in path:
                    scores[EvidenceOSType.IOS] += 1
        
        # Return highest scoring OS
        max_score = max(scores.values())
        if max_score == 0:
            return EvidenceOSType.UNKNOWN
        
        for os_type, score in scores.items():
            if score == max_score:
                return os_type
        
        return EvidenceOSType.UNKNOWN
    
    def _detect_hostname(self, paths: List[str], os_type: EvidenceOSType) -> str:
        """Detect hostname from evidence artifacts."""
        if not self.db_path or not os.path.exists(self.db_path):
            return 'EVIDENCE-PC'
        
        # Try to find hostname in file contents or metadata
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            
            # Check if we have a hostname stored in metadata
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'")
            if cur.fetchone():
                cur.execute("SELECT value FROM metadata WHERE key='hostname'")
                result = cur.fetchone()
                if result:
                    conn.close()
                    return result[0]
            
            conn.close()
        except Exception:
            pass
        
        # Generate hostname based on OS type
        if os_type == EvidenceOSType.WINDOWS:
            return 'EVIDENCE-PC'
        elif os_type == EvidenceOSType.LINUX:
            return 'evidence'
        elif os_type == EvidenceOSType.MACOS:
            return 'Evidence-Mac'
        elif os_type == EvidenceOSType.ANDROID:
            return 'android-device'
        elif os_type == EvidenceOSType.IOS:
            return 'iPhone'
        
        return 'evidence'
    
    def _detect_primary_user(self, paths: List[str], os_type: EvidenceOSType) -> str:
        """Detect primary user from evidence paths."""
        users = set()
        
        for path in paths:
            normalized = path.replace('\\', '/')
            
            if os_type == EvidenceOSType.WINDOWS:
                # Match C:\Users\Username or Users\Username
                match = re.search(r'(?:^|/)Users/([^/]+)', normalized, re.IGNORECASE)
                if match:
                    user = match.group(1)
                    # Exclude system users
                    if user.lower() not in ('public', 'default', 'default user', 
                                           'all users', 'defaultapppool'):
                        users.add(user)
            
            elif os_type in (EvidenceOSType.LINUX, EvidenceOSType.MACOS):
                # Match /home/username or /Users/username
                match = re.search(r'/(?:home|Users)/([^/]+)', normalized, re.IGNORECASE)
                if match:
                    user = match.group(1)
                    if user.lower() not in ('shared', 'guest'):
                        users.add(user)
        
        if users:
            # Return first user found (could enhance to pick most active)
            return list(users)[0]
        
        return 'user' if os_type != EvidenceOSType.LINUX else 'root'
    
    def _detect_home_path(self, paths: List[str], os_type: EvidenceOSType, username: str) -> str:
        """Get home directory path for the detected OS."""
        if os_type == EvidenceOSType.WINDOWS:
            return f"C:\\Users\\{username}"
        elif os_type == EvidenceOSType.LINUX:
            if username == 'root':
                return '/root'
            return f"/home/{username}"
        elif os_type == EvidenceOSType.MACOS:
            return f"/Users/{username}"
        elif os_type == EvidenceOSType.ANDROID:
            return '/sdcard'
        elif os_type == EvidenceOSType.IOS:
            return '/private/var/mobile'
        
        return '/'
    
    def _detect_system_root(self, os_type: EvidenceOSType) -> str:
        """Get system root path for the detected OS."""
        if os_type == EvidenceOSType.WINDOWS:
            return 'C:\\Windows'
        elif os_type in (EvidenceOSType.LINUX, EvidenceOSType.ANDROID):
            return '/'
        elif os_type == EvidenceOSType.MACOS:
            return '/System'
        elif os_type == EvidenceOSType.IOS:
            return '/System'
        return '/'
    
    def _detect_os_version(self, paths: List[str], os_type: EvidenceOSType) -> str:
        """Detect OS version from evidence."""
        # Would be enhanced to read from registry/config files
        if os_type == EvidenceOSType.WINDOWS:
            return 'Windows 10/11'
        elif os_type == EvidenceOSType.LINUX:
            return 'Linux'
        elif os_type == EvidenceOSType.MACOS:
            return 'macOS'
        return 'Unknown'
    
    def _detect_architecture(self, paths: List[str], os_type: EvidenceOSType) -> str:
        """Detect CPU architecture from evidence."""
        normalized = [p.lower() for p in paths[:500]]
        
        # Check for 64-bit indicators
        for path in normalized:
            if 'program files (x86)' in path or 'syswow64' in path:
                return 'x64'
            if 'lib64' in path or 'x86_64' in path:
                return 'x64'
        
        return 'x64'  # Default assumption
    
    def _detect_domain(self, paths: List[str], os_type: EvidenceOSType) -> str:
        """Detect domain membership from evidence."""
        # Would be enhanced to read from registry
        return ''
    
    def _get_shell_style(self, os_type: EvidenceOSType) -> ShellStyle:
        """Get appropriate shell style for OS type."""
        if os_type == EvidenceOSType.WINDOWS:
            return ShellStyle.CMD
        elif os_type == EvidenceOSType.LINUX:
            return ShellStyle.BASH
        elif os_type == EvidenceOSType.MACOS:
            return ShellStyle.ZSH
        else:
            return ShellStyle.SH


# ============================================================================
# MUTATING COMMANDS - Must be blocked and logged
# ============================================================================

WINDOWS_MUTATING_COMMANDS = {
    # File operations
    'del', 'erase', 'copy', 'xcopy', 'robocopy', 'move', 'ren', 'rename',
    'mkdir', 'md', 'rmdir', 'rd', 'mklink',
    
    # Permission/security
    'icacls', 'cacls', 'takeown', 'cipher', 'attrib',
    
    # Disk operations
    'format', 'diskpart', 'chkdsk', 'defrag', 'sfc', 'dism',
    'bcdedit', 'bootcfg', 'bootrec', 'mountvol', 'label',
    
    # Registry
    'reg', 'regedit', 'regedt32',
    
    # Network config
    'netsh', 'route', 'arp',
    
    # Service/process
    'sc', 'net', 'taskkill', 'tskill', 'shutdown', 'logoff',
    
    # Scripting (can modify)
    'powershell', 'pwsh', 'cmd', 'cscript', 'wscript', 'mshta',
    
    # Editors
    'notepad', 'edit', 'edlin', 'notepad++', 'code',
}

LINUX_MUTATING_COMMANDS = {
    # File operations
    'rm', 'mv', 'cp', 'ln', 'mkdir', 'rmdir', 'touch', 'truncate',
    
    # Permission
    'chmod', 'chown', 'chgrp', 'setfacl',
    
    # Disk operations
    'mkfs', 'mount', 'umount', 'fdisk', 'parted', 'dd', 'sync',
    
    # Package management
    'apt', 'apt-get', 'dpkg', 'yum', 'dnf', 'rpm', 'pacman', 'pip',
    
    # Service/process
    'kill', 'killall', 'pkill', 'shutdown', 'reboot', 'systemctl',
    'service', 'init', 'telinit',
    
    # User management
    'useradd', 'userdel', 'usermod', 'groupadd', 'passwd',
    
    # Privileged
    'sudo', 'su',
    
    # Editors
    'nano', 'vi', 'vim', 'emacs', 'ed', 'sed', 'awk',
}

MACOS_MUTATING_COMMANDS = LINUX_MUTATING_COMMANDS | {
    # macOS specific
    'dscl', 'dseditgroup', 'tmutil', 'diskutil', 'hdiutil',
    'defaults', 'pmset', 'nvram', 'bless', 'csrutil',
    'open', 'osascript',
}

# Patterns that indicate write intent in any OS
WRITE_PATTERNS = [
    '>', '>>', 
    '-rf', '-f', '--force',
    '/f', '/q', '/y',
    '-w', '--write',
    '-o', '--output',
]


def is_mutating_command(command: str, os_type: EvidenceOSType) -> Tuple[bool, str]:
    """
    Check if a command would modify evidence.
    
    Returns:
        (is_mutating, reason)
    """
    if not command.strip():
        return (False, '')
    
    parts = command.strip().split()
    cmd = parts[0].lower()
    
    # Remove path components
    if '/' in cmd or '\\' in cmd:
        cmd = os.path.basename(cmd).lower()
    
    # Remove extension
    for ext in ['.exe', '.com', '.bat', '.cmd', '.sh', '.py']:
        if cmd.endswith(ext):
            cmd = cmd[:-len(ext)]
    
    # Check for write patterns in the full command
    for pattern in WRITE_PATTERNS:
        if pattern in command:
            # Exclude legitimate uses like 'grep pattern'
            if cmd not in ('echo', 'find', 'grep', 'findstr'):
                return (True, f"Pattern '{pattern}' indicates write operation")
    
    # Check against OS-specific mutating commands
    mutating_set = set()
    
    if os_type == EvidenceOSType.WINDOWS:
        mutating_set = WINDOWS_MUTATING_COMMANDS
    elif os_type in (EvidenceOSType.LINUX, EvidenceOSType.ANDROID):
        mutating_set = LINUX_MUTATING_COMMANDS
    elif os_type in (EvidenceOSType.MACOS, EvidenceOSType.IOS):
        mutating_set = MACOS_MUTATING_COMMANDS
    else:
        # For unknown OS, combine all
        mutating_set = WINDOWS_MUTATING_COMMANDS | LINUX_MUTATING_COMMANDS
    
    if cmd in mutating_set:
        return (True, f"'{cmd}' would modify evidence")
    
    return (False, '')


# ============================================================================
# Audit Logging for Command Execution
# ============================================================================

def create_audit_entry(
    user: str,
    case: str,
    cwd: str,
    command: str,
    result: str,
    blocked: bool = False,
    reason: str = ''
) -> Dict[str, Any]:
    """
    Create an audit log entry for command execution.
    
    Returns a dict suitable for JSON serialization and chain of custody.
    """
    return {
        "time": datetime.utcnow().isoformat() + 'Z',
        "user": user,
        "case": case,
        "cwd": cwd,
        "command": command,
        "result": "BLOCKED" if blocked else "OK",
        "blocked_reason": reason if blocked else "",
        "result_preview": result[:200] if result and not blocked else ""
    }
