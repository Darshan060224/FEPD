"""
FEPD File Entry Model
=====================

UI-facing data model for file/folder entries displayed in the Files Tab.
Decouples the SQLite-backed VFSNode from the presentation layer.

Usage:
    entry = FileEntry.from_vfs_node(node)
    print(entry.display_size)   # "2.1 MB"
    print(entry.display_type)   # "PDF Document"
    print(entry.icon)           # "📕"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any

# Avoid circular import — VFSNode is only needed at runtime for conversion
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from src.core.virtual_fs import VFSNode


# ============================================================================
# FILE TYPE MAPPINGS
# ============================================================================

# Extension → human-readable type name
_EXT_TYPE_MAP: Dict[str, str] = {
    # Documents
    "pdf": "PDF Document",
    "doc": "Word Document", "docx": "Word Document",
    "xls": "Excel Spreadsheet", "xlsx": "Excel Spreadsheet",
    "ppt": "PowerPoint", "pptx": "PowerPoint",
    "odt": "OpenDocument Text", "ods": "OpenDocument Sheet",
    "rtf": "Rich Text File", "txt": "Text File",
    "csv": "CSV File", "md": "Markdown File",
    # Images
    "jpg": "JPEG Image", "jpeg": "JPEG Image",
    "png": "PNG Image", "gif": "GIF Image",
    "bmp": "Bitmap Image", "ico": "Icon File",
    "tiff": "TIFF Image", "tif": "TIFF Image",
    "webp": "WebP Image", "svg": "SVG Image",
    # Audio / Video
    "mp3": "MP3 Audio", "wav": "WAV Audio",
    "flac": "FLAC Audio", "ogg": "OGG Audio",
    "aac": "AAC Audio", "m4a": "M4A Audio", "wma": "WMA Audio",
    "mp4": "MP4 Video", "avi": "AVI Video",
    "mkv": "MKV Video", "mov": "QuickTime Video",
    "wmv": "WMV Video", "webm": "WebM Video", "flv": "FLV Video",
    # Executables / System
    "exe": "Executable", "dll": "Dynamic Library",
    "sys": "System File", "com": "COM Executable",
    "bat": "Batch Script", "cmd": "Command Script",
    "msi": "Installer Package", "ps1": "PowerShell Script",
    "sh": "Shell Script", "py": "Python Script",
    "js": "JavaScript File", "java": "Java Source",
    # Archives
    "zip": "ZIP Archive", "rar": "RAR Archive",
    "7z": "7-Zip Archive", "tar": "TAR Archive",
    "gz": "GZIP Archive", "bz2": "BZIP2 Archive",
    "xz": "XZ Archive", "cab": "Cabinet Archive",
    # Web
    "html": "HTML File", "htm": "HTML File",
    "xml": "XML File", "json": "JSON File",
    "yaml": "YAML File", "yml": "YAML File",
    "css": "CSS Stylesheet",
    # Databases
    "db": "Database File", "sqlite": "SQLite Database",
    "sqlite3": "SQLite Database", "mdb": "Access Database",
    "accdb": "Access Database",
    # Forensic-specific
    "pst": "Outlook Personal Folders",
    "ost": "Outlook Offline Folders",
    "eml": "Email Message", "msg": "Outlook Message",
    "mbox": "Mailbox Archive",
    "evtx": "Windows Event Log", "evt": "Legacy Event Log",
    "etl": "Event Trace Log",
    "e01": "EnCase Image", "l01": "EnCase Logical",
    "dd": "Raw Disk Image", "raw": "Raw Image",
    "pcap": "Network Capture", "pcapng": "Network Capture",
    "lnk": "Windows Shortcut", "pf": "Prefetch File",
    "reg": "Registry Export", "hiv": "Registry Hive",
    "mem": "Memory Dump", "dmp": "Crash Dump",
    "vmem": "Virtual Memory",
    # Config
    "ini": "INI Config", "cfg": "Config File",
    "conf": "Config File", "log": "Log File",
}

# Extension → emoji icon
_EXT_ICON_MAP: Dict[str, str] = {
    "pdf": "📕",
    "jpg": "🖼️", "jpeg": "🖼️", "png": "🖼️", "gif": "🖼️",
    "bmp": "🖼️", "ico": "🖼️", "tiff": "🖼️", "tif": "🖼️", "webp": "🖼️",
    "mp4": "🎬", "avi": "🎬", "mkv": "🎬", "mov": "🎬", "wmv": "🎬",
    "mp3": "🎵", "wav": "🎵", "flac": "🎵", "ogg": "🎵", "aac": "🎵",
    "exe": "⚡", "dll": "⚡", "sys": "⚡", "com": "⚡",
    "bat": "⚡", "cmd": "⚡", "msi": "⚡",
    "zip": "📦", "rar": "📦", "7z": "📦", "tar": "📦",
    "gz": "📦", "bz2": "📦", "xz": "📦", "cab": "📦",
    "doc": "📘", "docx": "📘", "odt": "📘", "rtf": "📘",
    "xls": "📊", "xlsx": "📊", "ods": "📊", "csv": "📊",
    "ppt": "📽️", "pptx": "📽️", "odp": "📽️",
    "txt": "📝", "log": "📝", "md": "📝", "cfg": "📝", "ini": "📝",
    "html": "🌐", "htm": "🌐", "xml": "🌐", "json": "🌐",
    "py": "💻", "js": "💻", "java": "💻", "cpp": "💻", "c": "💻",
    "db": "🗃️", "sqlite": "🗃️", "sqlite3": "🗃️",
    "pst": "📧", "ost": "📧",
    "eml": "✉️", "msg": "✉️", "mbox": "✉️",
    "lnk": "🔗", "dat": "🔗",
    "reg": "🗝️", "hiv": "🗝️",
    "evtx": "📋", "evt": "📋", "etl": "📋",
    "e01": "💿", "l01": "💿", "dd": "💿", "raw": "💿",
    "mem": "🧠", "dmp": "🧠", "vmem": "🧠",
    "pcap": "🌐", "pcapng": "🌐",
}

# Directory-type icons keyed by node_type string
_DIR_ICON_MAP: Dict[str, str] = {
    "root": "🖥️",
    "disk": "💽",
    "partition": "📦",
    "drive": "💾",
    "folder": "📁",
    "user": "👤",
    "system": "⚙️",
    "symlink": "🔗",
    "deleted": "🗑️",
}

# Special folder name overrides
_SPECIAL_FOLDER_ICONS: Dict[str, str] = {
    "desktop": "🖥️",
    "documents": "📄",
    "downloads": "📥",
    "pictures": "🖼️",
    "music": "🎵",
    "videos": "🎬",
    "appdata": "📁",
    "$recycle.bin": "🗑️",
    "system volume information": "⚙️",
    "windows": "⚙️",
    "program files": "📂",
    "program files (x86)": "📂",
    "programdata": "📂",
}


# ============================================================================
# FILE ENTRY DATACLASS
# ============================================================================

@dataclass
class FileEntry:
    """
    Lightweight, UI-facing representation of a file or folder.

    This is the *only* model the UI reads from — it never touches VFSNode
    directly, keeping the view layer decoupled from the data layer.
    """

    # Identity
    name: str
    path: str
    parent_path: str

    # Classification
    node_type: str              # VFSNodeType.value string ("file", "folder", …)
    is_directory: bool

    # Metrics
    size: int = 0

    # Timestamps
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    accessed: Optional[datetime] = None

    # Hashes
    sha256: Optional[str] = None
    md5: Optional[str] = None

    # Type info
    mime_type: Optional[str] = None
    extension: str = ""

    # Forensic provenance
    evidence_id: Optional[str] = None
    partition_info: Optional[str] = None
    inode: Optional[int] = None
    is_deleted: bool = False
    is_allocated: bool = True

    # Extra metadata bag
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Derived / display helpers
    # ------------------------------------------------------------------

    @property
    def icon(self) -> str:
        """Return an emoji icon suitable for UI display."""
        name_lower = self.name.lower()

        # Special folder icons
        if self.is_directory:
            if name_lower in _SPECIAL_FOLDER_ICONS:
                return _SPECIAL_FOLDER_ICONS[name_lower]
            return _DIR_ICON_MAP.get(self.node_type, "📁")

        # File icon by extension
        return _EXT_ICON_MAP.get(self.extension, "📄")

    @property
    def display_type(self) -> str:
        """Human-readable type label for the table column."""
        if self.is_directory:
            type_names = {
                "root": "This PC",
                "disk": "Disk Image",
                "partition": "Partition",
                "drive": "Drive",
                "folder": "Folder",
                "user": "User Profile",
                "system": "System Folder",
                "symlink": "Symbolic Link",
                "deleted": "Deleted",
            }
            return type_names.get(self.node_type, "Folder")

        if self.mime_type:
            return self.mime_type.split("/")[-1].title()

        return _EXT_TYPE_MAP.get(self.extension, f"{self.extension.upper()} File" if self.extension else "File")

    @property
    def display_size(self) -> str:
        """Human-readable size string (empty for directories)."""
        if self.is_directory or self.size == 0:
            return ""
        return _format_size(self.size)

    @property
    def display_modified(self) -> str:
        """Formatted modification timestamp for the table."""
        if self.modified:
            return self.modified.strftime("%Y-%m-%d %H:%M")
        return ""

    @property
    def display_created(self) -> str:
        if self.created:
            return self.created.strftime("%A, %B %d, %Y, %I:%M %p")
        return "—"

    @property
    def display_accessed(self) -> str:
        if self.accessed:
            return self.accessed.strftime("%A, %B %d, %Y, %I:%M %p")
        return "—"

    @property
    def display_modified_full(self) -> str:
        if self.modified:
            return self.modified.strftime("%A, %B %d, %Y, %I:%M %p")
        return "—"

    @property
    def sort_key(self) -> tuple:
        """Sort key: directories first, then alphabetical (case-insensitive)."""
        return (0 if self.is_directory else 1, self.name.lower())

    @property
    def is_suspicious(self) -> bool:
        """Quick heuristic flag for forensic highlighting."""
        name_lower = self.name.lower()
        # Double extensions
        if name_lower.count(".") >= 2:
            return True
        # Executable in user folders
        if self.extension in ("exe", "dll", "bat", "cmd", "ps1", "vbs", "scr"):
            path_lower = self.path.lower()
            if "/downloads/" in path_lower or "/desktop/" in path_lower or "/documents/" in path_lower:
                return True
        return False

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_vfs_node(cls, node: "VFSNode") -> "FileEntry":
        """
        Convert a VFSNode (data-layer object) to a FileEntry (UI model).
        """
        ext = ""
        if "." in node.name:
            ext = node.name.rsplit(".", 1)[-1].lower()

        return cls(
            name=node.name,
            path=node.path,
            parent_path=node.parent_path,
            node_type=node.node_type.value,
            is_directory=node.is_directory,
            size=node.size,
            created=node.created,
            modified=node.modified,
            accessed=node.accessed,
            sha256=node.sha256,
            md5=node.md5,
            mime_type=node.mime_type,
            extension=ext,
            evidence_id=node.evidence_id,
            partition_info=node.partition_info,
            inode=node.inode,
            is_deleted=node.is_deleted,
            is_allocated=node.is_allocated,
            metadata=node.metadata or {},
        )


# ============================================================================
# UTILITY
# ============================================================================

def _format_size(size: int) -> str:
    """Format byte size to human-readable string."""
    size_f = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if size_f < 1024:
            if unit == "B":
                return f"{int(size_f)} {unit}"
            return f"{size_f:.1f} {unit}"
        size_f /= 1024
    return f"{size_f:.1f} TB"
