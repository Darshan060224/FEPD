"""
FEPD Virtual Evidence Operating System (VEOS)
==============================================

The VEOS layer transforms FEPD from "a tool that shows extracted artifacts" 
into "a virtual operating system reconstructed from evidence."

Every tab (Files, Terminal, ML, Timeline, Visualizations) behaves as if 
the dead system is alive again, but in read-only forensic mode.

Think of FEPD as: A time-frozen OS built from evidence.

Key Features:
- Evidence-native virtual OS layer
- Path sanitization (never show cases/... evidence/... tmp/...)
- Partition parsing (NTFS/FAT/APFS/EXT)
- Drive reconstruction (C:, D:)
- User folder reconstruction (C:\\Users\\Alice)
- System folder reconstruction (Windows, Program Files)

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import os
import json
import sqlite3
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Generator
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


logger = logging.getLogger(__name__)


# ============================================================================
# VEOS CONSTANTS
# ============================================================================

class OSPlatform(Enum):
    """Detected operating system platform."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class PartitionType(Enum):
    """Filesystem partition types."""
    NTFS = "NTFS"
    FAT32 = "FAT32"
    FAT16 = "FAT16"
    EXFAT = "exFAT"
    EXT4 = "ext4"
    EXT3 = "ext3"
    EXT2 = "ext2"
    APFS = "APFS"
    HFS_PLUS = "HFS+"
    UNKNOWN = "Unknown"


# Common Windows system folders for detection
WINDOWS_SYSTEM_FOLDERS = {
    'windows', 'program files', 'program files (x86)', 'users',
    'programdata', 'recovery', 'system volume information',
    '$recycle.bin', 'boot', 'perflogs', 'temp', 'tmp'
}

# Common Linux system folders
LINUX_SYSTEM_FOLDERS = {
    'bin', 'boot', 'dev', 'etc', 'home', 'lib', 'lib64',
    'media', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin',
    'srv', 'sys', 'tmp', 'usr', 'var'
}

# Common macOS system folders
MACOS_SYSTEM_FOLDERS = {
    'applications', 'library', 'system', 'users', 'volumes',
    'private', 'cores', 'opt', 'usr', 'var', 'bin', 'sbin'
}

# Path patterns that should NEVER be shown to users (internal paths)
FORBIDDEN_PATH_PATTERNS = [
    'cases/',
    'evidence/',
    '/tmp/',
    '\\tmp\\',
    'extracted/',
    'staging/',
    'workspace/',
    '__pycache__',
    '.git/',
    'data/cases/',
    'data/workspace/'
]


# ============================================================================
# VEOS FILE ENTRY
# ============================================================================

@dataclass
class VEOSFile:
    """
    Represents a file in the Virtual Evidence OS.
    
    Stores both the evidence-native display path (what the user sees)
    and the actual physical path (hidden from user, used for reading).
    """
    # Display path - what the user sees (e.g., "C:\\Users\\Alice\\Desktop\\note.txt")
    display_path: str
    
    # Normalized internal path (e.g., "/Disk0/C/Users/Alice/Desktop/note.txt")
    internal_path: str
    
    # Physical path on disk - NEVER shown to user
    physical_path: Optional[str] = None
    
    # Filesystem metadata
    partition: Optional[str] = None  # e.g., "C:", "/dev/sda1"
    filesystem_type: PartitionType = PartitionType.UNKNOWN
    inode: Optional[int] = None
    offset: Optional[int] = None
    
    # File metadata
    name: str = ""
    size: int = 0
    is_directory: bool = False
    is_deleted: bool = False
    is_allocated: bool = True
    
    # Timestamps
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    accessed: Optional[datetime] = None
    
    # Hashes
    sha256: Optional[str] = None
    md5: Optional[str] = None
    
    # Evidence tracking
    evidence_source: Optional[str] = None  # Source image (e.g., "LoneWolf.E01")
    
    # Additional metadata
    mime_type: Optional[str] = None
    owner: Optional[str] = None
    permissions: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "display_path": self.display_path,
            "partition": self.partition,
            "inode": self.inode,
            "offset": self.offset,
            "name": self.name,
            "size": self.size,
            "is_directory": self.is_directory,
            "is_deleted": self.is_deleted,
            "sha256": self.sha256,
            "md5": self.md5,
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "accessed": self.accessed.isoformat() if self.accessed else None,
            "evidence_source": self.evidence_source,
            "owner": self.owner,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VEOSFile':
        """Create from dictionary."""
        return cls(
            display_path=data.get("display_path", ""),
            internal_path=data.get("internal_path", data.get("display_path", "")),
            physical_path=data.get("physical_path"),
            partition=data.get("partition"),
            filesystem_type=PartitionType(data.get("filesystem_type", "Unknown")),
            inode=data.get("inode"),
            offset=data.get("offset"),
            name=data.get("name", ""),
            size=data.get("size", 0),
            is_directory=data.get("is_directory", False),
            is_deleted=data.get("is_deleted", False),
            is_allocated=data.get("is_allocated", True),
            created=datetime.fromisoformat(data["created"]) if data.get("created") else None,
            modified=datetime.fromisoformat(data["modified"]) if data.get("modified") else None,
            accessed=datetime.fromisoformat(data["accessed"]) if data.get("accessed") else None,
            sha256=data.get("sha256"),
            md5=data.get("md5"),
            evidence_source=data.get("evidence_source"),
            mime_type=data.get("mime_type"),
            owner=data.get("owner"),
            permissions=data.get("permissions"),
            metadata=data.get("metadata", {})
        )


# ============================================================================
# VEOS USER PROFILE
# ============================================================================

@dataclass
class VEOSUserProfile:
    """Represents a user profile in the VEOS."""
    username: str
    sid: Optional[str] = None  # Windows SID
    uid: Optional[int] = None  # Unix UID
    home_path: str = ""  # Display path to home folder
    profile_type: str = "local"  # local, domain, service
    
    # Well-known folders
    desktop_path: Optional[str] = None
    documents_path: Optional[str] = None
    downloads_path: Optional[str] = None
    appdata_path: Optional[str] = None
    appdata_local_path: Optional[str] = None
    
    # Profile metadata
    last_login: Optional[datetime] = None
    is_admin: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# VEOS DRIVE
# ============================================================================

@dataclass
class VEOSDrive:
    """Represents a drive/volume in the VEOS."""
    letter: str  # e.g., "C", "D" (Windows) or mount point (Linux/Mac)
    label: Optional[str] = None  # Volume label
    filesystem: PartitionType = PartitionType.UNKNOWN
    total_size: int = 0
    used_size: int = 0
    free_size: int = 0
    serial_number: Optional[str] = None
    is_system_drive: bool = False
    partition_offset: Optional[int] = None
    partition_index: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# PATH SANITIZER
# ============================================================================

class VEOSPathSanitizer:
    """
    Path sanitizer that ensures only evidence-native paths are shown.
    
    NEVER shows:
    - cases/...
    - Evidence/...
    - tmp/...
    - extracted/...
    - Any physical host system path
    
    ALWAYS shows:
    - C:\\Users\\Alice\\Desktop\\note.txt
    - /home/alice/documents/file.txt
    - Native OS-style paths
    """
    
    def __init__(self, platform: OSPlatform = OSPlatform.WINDOWS):
        self.platform = platform
        self._path_cache: Dict[str, str] = {}
    
    def sanitize(self, path: str) -> str:
        """
        Sanitize a path to show only evidence-native format.
        
        Args:
            path: Raw path (may contain physical/internal paths)
            
        Returns:
            Sanitized evidence-native path
        """
        if not path:
            return ""
        
        # Check cache
        if path in self._path_cache:
            return self._path_cache[path]
        
        sanitized = self._do_sanitize(path)
        self._path_cache[path] = sanitized
        return sanitized
    
    def _do_sanitize(self, path: str) -> str:
        """Internal sanitization logic."""
        # Normalize path separators
        normalized = path.replace('\\', '/')
        
        # Check for forbidden patterns and strip them
        for pattern in FORBIDDEN_PATH_PATTERNS:
            if pattern.replace('\\', '/') in normalized.lower():
                # Find the evidence-native portion after the forbidden pattern
                idx = normalized.lower().find(pattern.replace('\\', '/'))
                if idx != -1:
                    # Find the next component after the pattern
                    rest = normalized[idx + len(pattern):]
                    if rest:
                        normalized = rest
        
        # Strip physical path prefixes like /tmp/fepd_123456/
        parts = normalized.split('/')
        for i, part in enumerate(parts):
            # Look for drive indicators or known root folders
            if ':' in part or part.lower() in WINDOWS_SYSTEM_FOLDERS | LINUX_SYSTEM_FOLDERS | MACOS_SYSTEM_FOLDERS:
                normalized = '/'.join(parts[i:])
                break
            # Look for Disk0, Partition0 patterns
            if part.lower().startswith('disk') or part.lower().startswith('partition'):
                # Skip to next meaningful part
                continue
        
        # Format for target platform
        if self.platform == OSPlatform.WINDOWS:
            return self._format_windows_path(normalized)
        elif self.platform in (OSPlatform.LINUX, OSPlatform.ANDROID):
            return self._format_linux_path(normalized)
        elif self.platform in (OSPlatform.MACOS, OSPlatform.IOS):
            return self._format_macos_path(normalized)
        
        return normalized
    
    def _format_windows_path(self, path: str) -> str:
        """Format path as Windows-style."""
        # Normalize separators
        path = path.replace('/', '\\')
        
        # Ensure drive letter format
        if path.startswith('\\') and len(path) > 1:
            # Check if this looks like a Windows path
            parts = path.strip('\\').split('\\')
            if parts:
                first = parts[0].lower()
                # Check for known Windows folders at root
                if first in {'users', 'windows', 'program files', 'program files (x86)', 'programdata'}:
                    path = 'C:' + path
                elif len(first) == 1 and first.isalpha():
                    # Likely a drive letter
                    path = first.upper() + ':' + '\\'.join(parts[1:])
        
        # Ensure proper drive letter format
        if len(path) >= 2 and path[1] != ':' and path[0].isalpha():
            if path.lower().startswith('c\\') or path.lower().startswith('d\\'):
                path = path[0].upper() + ':' + path[1:]
        
        # Clean up double backslashes
        while '\\\\' in path:
            path = path.replace('\\\\', '\\')
        
        return path
    
    def _format_linux_path(self, path: str) -> str:
        """Format path as Linux-style."""
        path = path.replace('\\', '/')
        if not path.startswith('/'):
            path = '/' + path
        while '//' in path:
            path = path.replace('//', '/')
        return path
    
    def _format_macos_path(self, path: str) -> str:
        """Format path as macOS-style."""
        return self._format_linux_path(path)
    
    def is_safe_to_display(self, path: str) -> bool:
        """Check if a path is safe to display to the user."""
        normalized = path.replace('\\', '/').lower()
        
        for pattern in FORBIDDEN_PATH_PATTERNS:
            if pattern.replace('\\', '/').lower() in normalized:
                return False
        
        return True


# ============================================================================
# VIRTUAL EVIDENCE OPERATING SYSTEM (VEOS)
# ============================================================================

class VirtualEvidenceOS:
    """
    The Virtual Evidence Operating System.
    
    Reconstructs a complete operating system view from forensic evidence.
    Provides unified access for:
    - Files Tab (Explorer-like browsing)
    - Terminal (Evidence CMD/Bash)
    - ML Analysis (normalized events)
    - Timeline (temporal navigation)
    - Visualizations (investigative maps)
    
    The user experience is:
    "I am inside the suspect's computer, but it's frozen in time
    and I cannot modify anything."
    """
    
    def __init__(self, case_path: Path, db_path: Optional[Path] = None):
        """
        Initialize the VEOS.
        
        Args:
            case_path: Path to the case directory
            db_path: Path to the SQLite database (optional)
        """
        self.case_path = Path(case_path)
        self.db_path = db_path or (self.case_path / "evidence.db")
        
        # Detected platform
        self.platform: OSPlatform = OSPlatform.UNKNOWN
        
        # Path sanitizer
        self.path_sanitizer = VEOSPathSanitizer()
        
        # Evidence metadata
        self.hostname: Optional[str] = None
        self.os_version: Optional[str] = None
        self.computer_name: Optional[str] = None
        
        # Drives and partitions
        self.drives: Dict[str, VEOSDrive] = {}  # "C" -> VEOSDrive
        
        # User profiles
        self.users: Dict[str, VEOSUserProfile] = {}  # "Alice" -> VEOSUserProfile
        
        # File index (display_path -> VEOSFile)
        self._file_index: Dict[str, VEOSFile] = {}
        
        # Directory structure cache
        self._dir_cache: Dict[str, List[str]] = {}
        
        # Current working directory (for terminal)
        self._cwd: str = "/"
        
        # Evidence source images
        self.evidence_sources: List[str] = []
        
        # Initialize database
        self._conn: Optional[sqlite3.Connection] = None
        
        # Initialize the system
        self._initialize()
    
    def _initialize(self):
        """Initialize the VEOS from evidence."""
        logger.info(f"Initializing VEOS from {self.case_path}")
        
        # Load from database if exists
        if self.db_path.exists():
            self._load_from_database()
        
        # Detect platform
        self._detect_platform()
        
        # Update path sanitizer platform
        self.path_sanitizer.platform = self.platform
        
        # Detect drives
        self._detect_drives()
        
        # Detect users
        self._detect_users()
        
        # Set initial CWD
        self._set_initial_cwd()
        
        logger.info(f"VEOS initialized: {self.platform.value}, {len(self.drives)} drives, {len(self.users)} users")
    
    def _load_from_database(self):
        """Load file structure from evidence database."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            
            # Check for files table
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files'")
            if not cur.fetchone():
                conn.close()
                return
            
            # Load files
            cur.execute("""
                SELECT path, size, owner, hash, created, modified, accessed,
                       mime_type, is_directory
                FROM files
            """)
            
            for row in cur.fetchall():
                path = row['path']
                if not path:
                    continue
                
                # Create VEOS file entry
                vfile = VEOSFile(
                    display_path=self._to_display_path(path),
                    internal_path=self._normalize_internal_path(path),
                    name=os.path.basename(path),
                    size=row['size'] or 0,
                    owner=row['owner'],
                    sha256=row['hash'],
                    is_directory=bool(row['is_directory']) if row['is_directory'] is not None else path.endswith('/'),
                    mime_type=row['mime_type']
                )
                
                # Parse timestamps
                for ts_field, attr in [('created', 'created'), ('modified', 'modified'), ('accessed', 'accessed')]:
                    if row[ts_field]:
                        try:
                            setattr(vfile, attr, datetime.fromisoformat(row[ts_field]))
                        except (ValueError, TypeError):
                            pass
                
                self._file_index[vfile.internal_path] = vfile
            
            conn.close()
            logger.info(f"Loaded {len(self._file_index)} files from database")
            
        except Exception as e:
            logger.error(f"Error loading from database: {e}")
    
    def _normalize_internal_path(self, path: str) -> str:
        """Normalize a path to internal format (forward slashes, lowercase drive)."""
        # Convert to forward slashes
        path = path.replace('\\', '/')
        
        # Ensure starts with /
        if not path.startswith('/'):
            path = '/' + path
        
        # Clean up double slashes
        while '//' in path:
            path = path.replace('//', '/')
        
        return path
    
    def _to_display_path(self, internal_path: str) -> str:
        """Convert internal path to display path based on platform."""
        return self.path_sanitizer.sanitize(internal_path)
    
    def _detect_platform(self):
        """Detect the operating system from evidence files."""
        # Look for Windows indicators
        windows_indicators = ['/windows/', '/users/', '/program files/', 'ntuser.dat', '.evtx']
        linux_indicators = ['/etc/', '/home/', '/var/', '/proc/', '.bash_history']
        macos_indicators = ['/library/', '/applications/', '.ds_store', '/private/']
        
        windows_score = 0
        linux_score = 0
        macos_score = 0
        
        for path in list(self._file_index.keys())[:1000]:  # Sample first 1000 files
            path_lower = path.lower()
            
            for indicator in windows_indicators:
                if indicator in path_lower:
                    windows_score += 1
            
            for indicator in linux_indicators:
                if indicator in path_lower:
                    linux_score += 1
            
            for indicator in macos_indicators:
                if indicator in path_lower:
                    macos_score += 1
        
        # Determine platform
        max_score = max(windows_score, linux_score, macos_score)
        if max_score == 0:
            self.platform = OSPlatform.UNKNOWN
        elif windows_score == max_score:
            self.platform = OSPlatform.WINDOWS
        elif macos_score == max_score:
            self.platform = OSPlatform.MACOS
        else:
            self.platform = OSPlatform.LINUX
        
        logger.info(f"Detected platform: {self.platform.value} (W:{windows_score} L:{linux_score} M:{macos_score})")
    
    def _detect_drives(self):
        """Detect drives/volumes from evidence."""
        # Look for drive letters in Windows paths
        drive_letters = set()
        
        for path in self._file_index.keys():
            # Check for Windows drive letter pattern
            if len(path) >= 3:
                if path[1] == ':' or (path[0] == '/' and path[2] == ':'):
                    letter = path[0] if path[1] == ':' else path[1]
                    if letter.isalpha():
                        drive_letters.add(letter.upper())
        
        # Create drive entries
        for letter in drive_letters:
            self.drives[letter] = VEOSDrive(
                letter=letter,
                filesystem=PartitionType.NTFS,  # Assume NTFS for Windows
                is_system_drive=(letter == 'C')
            )
        
        # If no drives found but we have files, create a default C: drive
        if not self.drives and self._file_index:
            self.drives['C'] = VEOSDrive(
                letter='C',
                filesystem=PartitionType.NTFS,
                is_system_drive=True
            )
        
        logger.info(f"Detected drives: {list(self.drives.keys())}")
    
    def _detect_users(self):
        """Detect user profiles from evidence."""
        # Look for user folders
        user_paths = set()
        
        for path in self._file_index.keys():
            path_lower = path.lower()
            
            # Windows: /Users/username/
            if '/users/' in path_lower:
                parts = path.split('/')
                for i, part in enumerate(parts):
                    if part.lower() == 'users' and i + 1 < len(parts):
                        username = parts[i + 1]
                        if username.lower() not in {'public', 'default', 'default user', 'all users'}:
                            user_paths.add(username)
            
            # Linux/Mac: /home/username/
            if '/home/' in path_lower:
                parts = path.split('/')
                for i, part in enumerate(parts):
                    if part.lower() == 'home' and i + 1 < len(parts):
                        username = parts[i + 1]
                        user_paths.add(username)
        
        # Create user profiles
        for username in user_paths:
            if self.platform == OSPlatform.WINDOWS:
                home_path = f"C:\\Users\\{username}"
            else:
                home_path = f"/home/{username}"
            
            profile = VEOSUserProfile(
                username=username,
                home_path=home_path
            )
            
            # Set well-known folders for Windows
            if self.platform == OSPlatform.WINDOWS:
                profile.desktop_path = f"{home_path}\\Desktop"
                profile.documents_path = f"{home_path}\\Documents"
                profile.downloads_path = f"{home_path}\\Downloads"
                profile.appdata_path = f"{home_path}\\AppData\\Roaming"
                profile.appdata_local_path = f"{home_path}\\AppData\\Local"
            
            self.users[username] = profile
        
        logger.info(f"Detected users: {list(self.users.keys())}")
    
    def _set_initial_cwd(self):
        """Set initial working directory."""
        # Try to set to first user's home directory
        if self.users:
            first_user = next(iter(self.users.values()))
            if self.platform == OSPlatform.WINDOWS:
                self._cwd = first_user.home_path.replace('\\', '/')
            else:
                self._cwd = first_user.home_path
        elif self.platform == OSPlatform.WINDOWS:
            self._cwd = "C:/"
        else:
            self._cwd = "/"
    
    @property
    def cwd(self) -> str:
        """Get current working directory in display format."""
        return self._to_display_path(self._cwd)
    
    @cwd.setter
    def cwd(self, value: str):
        """Set current working directory."""
        self._cwd = self._normalize_internal_path(value)
    
    def list_dir(self, path: str = None) -> List[VEOSFile]:
        """
        List directory contents.
        
        Args:
            path: Directory path (defaults to CWD)
            
        Returns:
            List of VEOSFile entries
        """
        if path is None:
            path = self._cwd
        
        path = self._normalize_internal_path(path)
        
        # Find all files in this directory
        results = []
        seen_names = set()
        
        for internal_path, vfile in self._file_index.items():
            # Check if file is directly in this directory
            parent = os.path.dirname(internal_path)
            if parent == path.rstrip('/'):
                name = vfile.name or os.path.basename(internal_path)
                if name not in seen_names:
                    seen_names.add(name)
                    results.append(vfile)
            # Check for subdirectories
            elif internal_path.startswith(path.rstrip('/') + '/'):
                rest = internal_path[len(path.rstrip('/')) + 1:]
                if '/' in rest:
                    subdir = rest.split('/')[0]
                    if subdir and subdir not in seen_names:
                        seen_names.add(subdir)
                        # Create a directory entry
                        dir_entry = VEOSFile(
                            display_path=self._to_display_path(path.rstrip('/') + '/' + subdir),
                            internal_path=path.rstrip('/') + '/' + subdir,
                            name=subdir,
                            is_directory=True
                        )
                        results.append(dir_entry)
        
        # Sort: directories first, then alphabetically
        results.sort(key=lambda f: (not f.is_directory, f.name.lower()))
        
        return results
    
    def get_file(self, path: str) -> Optional[VEOSFile]:
        """
        Get a specific file by path.
        
        Args:
            path: File path (display or internal format)
            
        Returns:
            VEOSFile or None if not found
        """
        internal = self._normalize_internal_path(path)
        return self._file_index.get(internal)
    
    def path_exists(self, path: str) -> bool:
        """Check if a path exists in the VEOS."""
        internal = self._normalize_internal_path(path)
        
        # Check exact match
        if internal in self._file_index:
            return True
        
        # Check if it's a directory (has children)
        prefix = internal.rstrip('/') + '/'
        for p in self._file_index.keys():
            if p.startswith(prefix):
                return True
        
        return False
    
    def is_directory(self, path: str) -> bool:
        """Check if path is a directory."""
        internal = self._normalize_internal_path(path)
        
        # Check if file entry says it's a directory
        if internal in self._file_index:
            return self._file_index[internal].is_directory
        
        # Check if there are children
        prefix = internal.rstrip('/') + '/'
        for p in self._file_index.keys():
            if p.startswith(prefix):
                return True
        
        return False
    
    def read_file(self, path: str) -> Optional[bytes]:
        """
        Read file contents.
        
        Args:
            path: File path
            
        Returns:
            File contents as bytes, or None if not readable
        """
        vfile = self.get_file(path)
        if not vfile:
            return None
        
        # If we have a physical path, read from there
        if vfile.physical_path and os.path.exists(vfile.physical_path):
            try:
                with open(vfile.physical_path, 'rb') as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Error reading file {path}: {e}")
                return None
        
        return None
    
    def search(self, query: str, path: str = None, 
               include_deleted: bool = False) -> Generator[VEOSFile, None, None]:
        """
        Search for files matching a query.
        
        Args:
            query: Search query (filename pattern or content)
            path: Limit search to this path
            include_deleted: Include deleted files
            
        Yields:
            Matching VEOSFile entries
        """
        query_lower = query.lower()
        search_path = self._normalize_internal_path(path) if path else None
        
        for internal_path, vfile in self._file_index.items():
            # Skip deleted if not requested
            if vfile.is_deleted and not include_deleted:
                continue
            
            # Check path constraint
            if search_path and not internal_path.startswith(search_path):
                continue
            
            # Check name match
            if query_lower in vfile.name.lower():
                yield vfile
    
    def get_drive_structure(self) -> Dict[str, Any]:
        """
        Get the drive structure for UI display.
        
        Returns structure like:
        {
            "C:": {
                "label": "Local Disk",
                "filesystem": "NTFS",
                "children": ["Users", "Windows", "Program Files"]
            }
        }
        """
        structure = {}
        
        for letter, drive in self.drives.items():
            # Get top-level folders for this drive
            if self.platform == OSPlatform.WINDOWS:
                drive_path = f"/{letter}:/"
            else:
                drive_path = "/"
            
            children = []
            seen = set()
            
            for path in self._file_index.keys():
                if path.startswith(drive_path):
                    rest = path[len(drive_path):]
                    if '/' in rest:
                        top_folder = rest.split('/')[0]
                    else:
                        top_folder = rest
                    
                    if top_folder and top_folder not in seen:
                        seen.add(top_folder)
                        children.append(top_folder)
            
            structure[f"{letter}:"] = {
                "label": drive.label or "Local Disk",
                "filesystem": drive.filesystem.value,
                "is_system": drive.is_system_drive,
                "children": sorted(children)
            }
        
        return structure
    
    def get_user_folders(self, username: str) -> Dict[str, str]:
        """Get well-known folders for a user."""
        if username not in self.users:
            return {}
        
        profile = self.users[username]
        return {
            "home": profile.home_path,
            "desktop": profile.desktop_path,
            "documents": profile.documents_path,
            "downloads": profile.downloads_path,
            "appdata": profile.appdata_path,
            "appdata_local": profile.appdata_local_path
        }
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information for display."""
        return {
            "platform": self.platform.value,
            "hostname": self.hostname,
            "os_version": self.os_version,
            "computer_name": self.computer_name,
            "drives": list(self.drives.keys()),
            "users": list(self.users.keys()),
            "total_files": len(self._file_index),
            "evidence_sources": self.evidence_sources
        }
    
    def add_file(self, vfile: VEOSFile):
        """Add a file to the VEOS index."""
        self._file_index[vfile.internal_path] = vfile
        
        # Clear directory cache
        self._dir_cache.clear()
    
    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None


# ============================================================================
# VEOS BUILDER - Creates VEOS from evidence images
# ============================================================================

class VEOSBuilder:
    """
    Builds a Virtual Evidence OS from evidence images.
    
    This class handles:
    - Parsing evidence images (E01, DD, etc.)
    - Extracting filesystem structure
    - Creating the VEOS database
    """
    
    def __init__(self, case_path: Path):
        self.case_path = Path(case_path)
        self.veos: Optional[VirtualEvidenceOS] = None
    
    def build_from_image(self, image_path: Path, 
                         progress_callback: Optional[callable] = None) -> VirtualEvidenceOS:
        """
        Build VEOS from an evidence image.
        
        Args:
            image_path: Path to evidence image
            progress_callback: Optional callback for progress updates
            
        Returns:
            Initialized VirtualEvidenceOS
        """
        logger.info(f"Building VEOS from {image_path}")
        
        # Create VEOS instance
        self.veos = VirtualEvidenceOS(self.case_path)
        self.veos.evidence_sources.append(str(image_path.name))
        
        # TODO: Parse image using pytsk3/pyewf
        # For now, scan extracted files
        
        extracted_dir = self.case_path / "Evidence"
        if extracted_dir.exists():
            self._scan_extracted_files(extracted_dir, progress_callback)
        
        return self.veos
    
    def build_from_extracted(self, extracted_path: Path,
                            progress_callback: Optional[callable] = None) -> VirtualEvidenceOS:
        """
        Build VEOS from already-extracted files.
        
        Args:
            extracted_path: Path to extracted evidence
            progress_callback: Optional callback
            
        Returns:
            Initialized VirtualEvidenceOS
        """
        logger.info(f"Building VEOS from extracted files: {extracted_path}")
        
        # Create VEOS instance
        self.veos = VirtualEvidenceOS(self.case_path)
        
        self._scan_extracted_files(extracted_path, progress_callback)
        
        return self.veos
    
    def _scan_extracted_files(self, root_path: Path, 
                              progress_callback: Optional[callable] = None):
        """Scan extracted files and add to VEOS."""
        total_files = sum(1 for _ in root_path.rglob('*'))
        processed = 0
        
        for file_path in root_path.rglob('*'):
            try:
                # Get relative path from extraction root
                rel_path = file_path.relative_to(root_path)
                
                # Convert to evidence-native path
                internal_path = '/' + str(rel_path).replace('\\', '/')
                
                # Create VEOS file entry
                vfile = VEOSFile(
                    display_path=self.veos._to_display_path(internal_path),
                    internal_path=internal_path,
                    physical_path=str(file_path),
                    name=file_path.name,
                    size=file_path.stat().st_size if file_path.is_file() else 0,
                    is_directory=file_path.is_dir()
                )
                
                # Get timestamps
                stat = file_path.stat()
                vfile.modified = datetime.fromtimestamp(stat.st_mtime)
                vfile.accessed = datetime.fromtimestamp(stat.st_atime)
                vfile.created = datetime.fromtimestamp(stat.st_ctime)
                
                self.veos.add_file(vfile)
                
                processed += 1
                if progress_callback and processed % 100 == 0:
                    progress_callback(int(processed / total_files * 100), 
                                    f"Processing: {file_path.name}")
                
            except Exception as e:
                logger.warning(f"Error processing {file_path}: {e}")
                continue
        
        # Re-initialize to detect platform, drives, users
        self.veos._detect_platform()
        self.veos.path_sanitizer.platform = self.veos.platform
        self.veos._detect_drives()
        self.veos._detect_users()
        self.veos._set_initial_cwd()
        
        logger.info(f"Scanned {processed} files")


# ============================================================================
# SINGLETON ACCESSOR
# ============================================================================

_current_veos: Optional[VirtualEvidenceOS] = None


def get_veos() -> Optional[VirtualEvidenceOS]:
    """Get the current VEOS instance."""
    return _current_veos


def set_veos(veos: VirtualEvidenceOS):
    """Set the current VEOS instance."""
    global _current_veos
    _current_veos = veos


def create_veos(case_path: Path, db_path: Optional[Path] = None) -> VirtualEvidenceOS:
    """Create and set a new VEOS instance."""
    global _current_veos
    _current_veos = VirtualEvidenceOS(case_path, db_path)
    return _current_veos
