"""
FEPD Virtual Filesystem (VFS) Database
=======================================

SQLite-backed virtual filesystem that reconstructs evidence image contents.
Provides the single source of truth for both UI Files tab and Terminal navigation.

Architecture:
    E01/DD/IMG → ImageHandler (pytsk3) → VFS Builder → virtual_fs table → UI/Terminal
"""

import sqlite3
import hashlib
import mimetypes
from pathlib import Path, PurePosixPath
from typing import Optional, List, Dict, Any, Generator, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import os


class VFSNodeType(Enum):
    """Types of nodes in the virtual filesystem."""
    ROOT = "root"           # Case root
    DISK = "disk"           # Physical disk
    PARTITION = "partition" # Disk partition
    DRIVE = "drive"         # Drive letter (C:, D:)
    FOLDER = "folder"       # Directory
    FILE = "file"           # Regular file
    USER = "user"           # User profile folder
    SYSTEM = "system"       # System folder (Windows, Program Files)
    SYMLINK = "symlink"     # Symbolic link
    DELETED = "deleted"     # Deleted/recovered file


@dataclass
class VFSNode:
    """Represents a node in the virtual filesystem."""
    id: int
    path: str                               # Full path: /Disk0/C:/Users/Alice/file.txt
    name: str                               # Filename: file.txt
    parent_path: str                        # Parent path: /Disk0/C:/Users/Alice
    node_type: VFSNodeType                  # Type of node
    size: int = 0                           # File size in bytes
    created: Optional[datetime] = None      # Creation time
    modified: Optional[datetime] = None     # Modification time
    accessed: Optional[datetime] = None     # Access time
    sha256: Optional[str] = None            # SHA-256 hash
    md5: Optional[str] = None               # MD5 hash (legacy support)
    mime_type: Optional[str] = None         # MIME type
    evidence_id: Optional[str] = None       # Source evidence file
    partition_info: Optional[str] = None    # Partition details (NTFS, ext4, etc.)
    inode: Optional[int] = None             # Original inode number
    is_deleted: bool = False                # Whether file was deleted
    is_allocated: bool = True               # Whether file is allocated
    metadata: Dict[str, Any] = field(default_factory=dict)  # Extra metadata
    
    @property
    def is_directory(self) -> bool:
        """Check if node is a directory-like type."""
        return self.node_type in (
            VFSNodeType.ROOT, VFSNodeType.DISK, VFSNodeType.PARTITION,
            VFSNodeType.DRIVE, VFSNodeType.FOLDER, VFSNodeType.USER,
            VFSNodeType.SYSTEM
        )
    
    @property
    def icon_name(self) -> str:
        """Get icon name for UI display."""
        icons = {
            VFSNodeType.ROOT: "computer",
            VFSNodeType.DISK: "harddisk",
            VFSNodeType.PARTITION: "partition",
            VFSNodeType.DRIVE: "drive",
            VFSNodeType.FOLDER: "folder",
            VFSNodeType.FILE: "file",
            VFSNodeType.USER: "user",
            VFSNodeType.SYSTEM: "system_folder",
            VFSNodeType.SYMLINK: "symlink",
            VFSNodeType.DELETED: "deleted_file",
        }
        return icons.get(self.node_type, "file")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "path": self.path,
            "name": self.name,
            "parent_path": self.parent_path,
            "node_type": self.node_type.value,
            "size": self.size,
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "accessed": self.accessed.isoformat() if self.accessed else None,
            "sha256": self.sha256,
            "md5": self.md5,
            "mime_type": self.mime_type,
            "evidence_id": self.evidence_id,
            "partition_info": self.partition_info,
            "inode": self.inode,
            "is_deleted": self.is_deleted,
            "is_allocated": self.is_allocated,
            "metadata": self.metadata,
        }


class VirtualFilesystem:
    """
    SQLite-backed virtual filesystem for forensic evidence.
    
    Provides:
    - Tree structure for all evidence images
    - Path-based navigation (matching terminal)
    - File metadata and hashing
    - Search capabilities
    - Chain of custody integration
    """
    
    SCHEMA_VERSION = 1
    
    def __init__(self, case_db_path: Path):
        """
        Initialize VFS with case database.
        
        Args:
            case_db_path: Path to case SQLite database
        """
        self.db_path = Path(case_db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._init_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            # Enable foreign keys
            self._conn.execute("PRAGMA foreign_keys = ON")
        return self._conn
    
    def _init_database(self):
        """Initialize database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Create virtual_fs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS virtual_fs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                parent_path TEXT,
                node_type TEXT NOT NULL,
                size INTEGER DEFAULT 0,
                created TEXT,
                modified TEXT,
                accessed TEXT,
                sha256 TEXT,
                md5 TEXT,
                mime_type TEXT,
                evidence_id TEXT,
                partition_info TEXT,
                inode INTEGER,
                is_deleted INTEGER DEFAULT 0,
                is_allocated INTEGER DEFAULT 1,
                metadata TEXT,
                indexed_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for fast lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vfs_parent ON virtual_fs(parent_path)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vfs_type ON virtual_fs(node_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vfs_name ON virtual_fs(name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vfs_evidence ON virtual_fs(evidence_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vfs_sha256 ON virtual_fs(sha256)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vfs_deleted ON virtual_fs(is_deleted)")
        
        # Create VFS metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vfs_metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        
        # Set schema version
        cursor.execute(
            "INSERT OR REPLACE INTO vfs_metadata (key, value) VALUES (?, ?)",
            ("schema_version", str(self.SCHEMA_VERSION))
        )
        
        conn.commit()
    
    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
    
    # =========================================================================
    # NODE OPERATIONS
    # =========================================================================
    
    def add_node(self, node: VFSNode) -> int:
        """
        Add a node to the VFS.
        
        Args:
            node: VFSNode to add
            
        Returns:
            Node ID
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO virtual_fs (
                path, name, parent_path, node_type, size,
                created, modified, accessed, sha256, md5,
                mime_type, evidence_id, partition_info, inode,
                is_deleted, is_allocated, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            node.path,
            node.name,
            node.parent_path,
            node.node_type.value,
            node.size,
            node.created.isoformat() if node.created else None,
            node.modified.isoformat() if node.modified else None,
            node.accessed.isoformat() if node.accessed else None,
            node.sha256,
            node.md5,
            node.mime_type,
            node.evidence_id,
            node.partition_info,
            node.inode,
            1 if node.is_deleted else 0,
            1 if node.is_allocated else 0,
            json.dumps(node.metadata) if node.metadata else None,
        ))
        
        conn.commit()
        return cursor.lastrowid
    
    def update_hash(self, path: str, sha256: str = None, md5: str = None) -> bool:
        """
        Update hash values for a node.
        
        Args:
            path: VFS path of the node
            sha256: SHA-256 hash (hex string)
            md5: MD5 hash (hex string)
            
        Returns:
            True if node was found and updated
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        updates = []
        params = []
        if sha256 is not None:
            updates.append("sha256 = ?")
            params.append(sha256)
        if md5 is not None:
            updates.append("md5 = ?")
            params.append(md5)
        
        if not updates:
            return False
        
        params.append(path)
        sql = f"UPDATE virtual_fs SET {', '.join(updates)} WHERE path = ?"
        cursor.execute(sql, params)
        conn.commit()
        return cursor.rowcount > 0
    
    def add_nodes_batch(self, nodes: List[VFSNode]) -> int:
        """
        Add multiple nodes in a batch transaction.
        
        Args:
            nodes: List of VFSNode objects
            
        Returns:
            Number of nodes added
        """
        if not nodes:
            return 0
            
        conn = self._get_connection()
        cursor = conn.cursor()
        
        data = [
            (
                node.path,
                node.name,
                node.parent_path,
                node.node_type.value,
                node.size,
                node.created.isoformat() if node.created else None,
                node.modified.isoformat() if node.modified else None,
                node.accessed.isoformat() if node.accessed else None,
                node.sha256,
                node.md5,
                node.mime_type,
                node.evidence_id,
                node.partition_info,
                node.inode,
                1 if node.is_deleted else 0,
                1 if node.is_allocated else 0,
                json.dumps(node.metadata) if node.metadata else None,
            )
            for node in nodes
        ]
        
        cursor.executemany("""
            INSERT OR REPLACE INTO virtual_fs (
                path, name, parent_path, node_type, size,
                created, modified, accessed, sha256, md5,
                mime_type, evidence_id, partition_info, inode,
                is_deleted, is_allocated, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, data)
        
        conn.commit()
        return len(data)
    
    def get_node(self, path: str) -> Optional[VFSNode]:
        """
        Get a node by path.
        
        Args:
            path: Full VFS path
            
        Returns:
            VFSNode or None
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM virtual_fs WHERE path = ?", (path,))
        row = cursor.fetchone()
        
        if row:
            return self._row_to_node(row)
        return None
    
    def get_node_by_id(self, node_id: int) -> Optional[VFSNode]:
        """Get node by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM virtual_fs WHERE id = ?", (node_id,))
        row = cursor.fetchone()
        
        if row:
            return self._row_to_node(row)
        return None
    
    def get_children(self, parent_path: str) -> List[VFSNode]:
        """
        Get all children of a path.
        
        Args:
            parent_path: Parent path
            
        Returns:
            List of child nodes
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM virtual_fs WHERE parent_path = ? ORDER BY node_type, name",
            (parent_path,)
        )
        
        return [self._row_to_node(row) for row in cursor.fetchall()]
    
    def get_root_nodes(self) -> List[VFSNode]:
        """Get top-level nodes (disks/evidence roots)."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Root nodes have parent_path as '', NULL, or '/'
        cursor.execute(
            "SELECT * FROM virtual_fs WHERE parent_path = '' OR parent_path IS NULL OR parent_path = '/' ORDER BY name"
        )
        
        return [self._row_to_node(row) for row in cursor.fetchall()]
    
    def delete_node(self, path: str, recursive: bool = True):
        """
        Delete a node from VFS.
        
        Args:
            path: Path to delete
            recursive: If True, delete all children too
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        if recursive:
            # Delete all nodes under this path
            cursor.execute(
                "DELETE FROM virtual_fs WHERE path = ? OR path LIKE ?",
                (path, f"{path}/%")
            )
        else:
            cursor.execute("DELETE FROM virtual_fs WHERE path = ?", (path,))
        
        conn.commit()
    
    def clear_evidence(self, evidence_id: str):
        """Remove all nodes from a specific evidence file."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "DELETE FROM virtual_fs WHERE evidence_id = ?",
            (evidence_id,)
        )
        conn.commit()
    
    def clear_all(self):
        """Clear entire VFS."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM virtual_fs")
        conn.commit()
    
    # =========================================================================
    # SEARCH & QUERY
    # =========================================================================
    
    def search(
        self,
        query: str,
        node_type: Optional[VFSNodeType] = None,
        include_deleted: bool = False,
        limit: int = 1000
    ) -> List[VFSNode]:
        """
        Search for nodes by name pattern.
        
        Args:
            query: Search pattern (supports wildcards: *, ?)
            node_type: Filter by node type
            include_deleted: Include deleted files
            limit: Maximum results
            
        Returns:
            List of matching nodes
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Convert wildcards to SQL LIKE pattern
        pattern = query.replace("*", "%").replace("?", "_")
        
        sql = "SELECT * FROM virtual_fs WHERE name LIKE ?"
        params = [pattern]
        
        if node_type:
            sql += " AND node_type = ?"
            params.append(node_type.value)
        
        if not include_deleted:
            sql += " AND is_deleted = 0"
        
        sql += f" ORDER BY name LIMIT {limit}"
        
        cursor.execute(sql, params)
        return [self._row_to_node(row) for row in cursor.fetchall()]
    
    def search_by_extension(
        self,
        extension: str,
        include_deleted: bool = False,
        limit: int = 1000
    ) -> List[VFSNode]:
        """Search for files by extension."""
        if not extension.startswith("."):
            extension = f".{extension}"
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        sql = """
            SELECT * FROM virtual_fs 
            WHERE node_type = 'file' 
            AND name LIKE ?
        """
        if not include_deleted:
            sql += " AND is_deleted = 0"
        sql += f" LIMIT {limit}"
        
        cursor.execute(sql, (f"%{extension}",))
        return [self._row_to_node(row) for row in cursor.fetchall()]
    
    def search_by_hash(self, hash_value: str) -> List[VFSNode]:
        """Find files by SHA-256 or MD5 hash."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM virtual_fs WHERE sha256 = ? OR md5 = ?",
            (hash_value, hash_value)
        )
        return [self._row_to_node(row) for row in cursor.fetchall()]
    
    def find_user_folders(self, disk_path: str = None) -> List[VFSNode]:
        """Find all user profile folders."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        sql = "SELECT * FROM virtual_fs WHERE node_type = 'user'"
        if disk_path:
            sql += f" AND path LIKE '{disk_path}%'"
        sql += " ORDER BY path"
        
        cursor.execute(sql)
        return [self._row_to_node(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get VFS statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        stats = {}
        
        # Total counts
        cursor.execute("SELECT COUNT(*) FROM virtual_fs")
        stats["total_nodes"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM virtual_fs WHERE node_type = 'file'")
        stats["total_files"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM virtual_fs WHERE node_type = 'folder'")
        stats["total_folders"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM virtual_fs WHERE is_deleted = 1")
        stats["deleted_files"] = cursor.fetchone()[0]
        
        # Size stats
        cursor.execute("SELECT SUM(size) FROM virtual_fs WHERE node_type = 'file'")
        stats["total_size"] = cursor.fetchone()[0] or 0
        
        # Evidence sources
        cursor.execute("SELECT DISTINCT evidence_id FROM virtual_fs WHERE evidence_id IS NOT NULL")
        stats["evidence_sources"] = [row[0] for row in cursor.fetchall()]
        
        # File type breakdown
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN name LIKE '%.pdf' THEN 'PDF'
                    WHEN name LIKE '%.doc%' THEN 'Document'
                    WHEN name LIKE '%.xls%' THEN 'Spreadsheet'
                    WHEN name LIKE '%.jpg' OR name LIKE '%.jpeg' OR name LIKE '%.png' OR name LIKE '%.gif' THEN 'Image'
                    WHEN name LIKE '%.mp4' OR name LIKE '%.avi' OR name LIKE '%.mkv' THEN 'Video'
                    WHEN name LIKE '%.mp3' OR name LIKE '%.wav' OR name LIKE '%.flac' THEN 'Audio'
                    WHEN name LIKE '%.exe' OR name LIKE '%.dll' THEN 'Executable'
                    WHEN name LIKE '%.zip' OR name LIKE '%.rar' OR name LIKE '%.7z' THEN 'Archive'
                    ELSE 'Other'
                END as category,
                COUNT(*) as count
            FROM virtual_fs 
            WHERE node_type = 'file'
            GROUP BY category
        """)
        stats["file_types"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        return stats
    
    # =========================================================================
    # TREE WALKING
    # =========================================================================
    
    def walk(
        self,
        start_path: str = "",
        include_files: bool = True,
        include_deleted: bool = False
    ) -> Generator[Tuple[str, List[VFSNode], List[VFSNode]], None, None]:
        """
        Walk the VFS tree (like os.walk).
        
        Yields:
            Tuples of (current_path, directories, files)
        """
        def _walk_recursive(path: str):
            children = self.get_children(path)
            
            dirs = []
            files = []
            
            for child in children:
                if not include_deleted and child.is_deleted:
                    continue
                    
                if child.is_directory:
                    dirs.append(child)
                elif include_files:
                    files.append(child)
            
            yield (path, dirs, files)
            
            for d in dirs:
                yield from _walk_recursive(d.path)
        
        yield from _walk_recursive(start_path)
    
    def get_path_tree(self, path: str, max_depth: int = 3) -> Dict[str, Any]:
        """
        Get tree structure as nested dict.
        
        Args:
            path: Starting path
            max_depth: Maximum depth to traverse
            
        Returns:
            Nested dictionary representing tree
        """
        node = self.get_node(path)
        if not node:
            return {}
        
        def _build_tree(n: VFSNode, depth: int) -> Dict[str, Any]:
            result = {
                "name": n.name,
                "path": n.path,
                "type": n.node_type.value,
                "size": n.size,
            }
            
            if depth < max_depth and n.is_directory:
                children = self.get_children(n.path)
                result["children"] = [
                    _build_tree(child, depth + 1)
                    for child in children
                ]
            
            return result
        
        return _build_tree(node, 0)
    
    # =========================================================================
    # HELPERS
    # =========================================================================
    
    def _row_to_node(self, row: sqlite3.Row) -> VFSNode:
        """Convert database row to VFSNode."""
        metadata = {}
        if row["metadata"]:
            try:
                metadata = json.loads(row["metadata"])
            except:
                pass
        
        created = None
        modified = None
        accessed = None
        
        if row["created"]:
            try:
                created = datetime.fromisoformat(row["created"])
            except:
                pass
        if row["modified"]:
            try:
                modified = datetime.fromisoformat(row["modified"])
            except:
                pass
        if row["accessed"]:
            try:
                accessed = datetime.fromisoformat(row["accessed"])
            except:
                pass
        
        return VFSNode(
            id=row["id"],
            path=row["path"],
            name=row["name"],
            parent_path=row["parent_path"] or "",
            node_type=VFSNodeType(row["node_type"]),
            size=row["size"] or 0,
            created=created,
            modified=modified,
            accessed=accessed,
            sha256=row["sha256"],
            md5=row["md5"],
            mime_type=row["mime_type"],
            evidence_id=row["evidence_id"],
            partition_info=row["partition_info"],
            inode=row["inode"],
            is_deleted=bool(row["is_deleted"]),
            is_allocated=bool(row["is_allocated"]),
            metadata=metadata,
        )
    
    @staticmethod
    def normalize_path(path: str) -> str:
        """
        Normalize path for VFS.
        
        Converts Windows paths to forward slashes, handles drive letters.
        """
        # Convert backslashes
        path = path.replace("\\", "/")
        
        # Remove trailing slashes
        path = path.rstrip("/")
        
        # Ensure starts with /
        if path and not path.startswith("/"):
            path = "/" + path
        
        return path or "/"
    
    @staticmethod
    def get_parent_path(path: str) -> str:
        """Get parent path from a path."""
        path = VirtualFilesystem.normalize_path(path)
        if path == "/" or not path:
            return ""
        
        parts = path.rsplit("/", 1)
        return parts[0] if len(parts) > 1 else ""
    
    @staticmethod
    def get_name(path: str) -> str:
        """Get name from path."""
        path = VirtualFilesystem.normalize_path(path)
        if path == "/":
            return "/"
        return path.rsplit("/", 1)[-1]
    
    @staticmethod
    def guess_mime_type(filename: str) -> str:
        """Guess MIME type from filename."""
        mime, _ = mimetypes.guess_type(filename)
        return mime or "application/octet-stream"


# Convenience functions for creating common node types
def create_root_node(case_name: str, evidence_id: str = None) -> VFSNode:
    """Create case root node."""
    return VFSNode(
        id=0,
        path="/",
        name=case_name,
        parent_path="",
        node_type=VFSNodeType.ROOT,
        evidence_id=evidence_id,
    )


def create_disk_node(
    disk_name: str,
    disk_info: str = None,
    evidence_id: str = None
) -> VFSNode:
    """Create disk node."""
    path = f"/{disk_name}"
    return VFSNode(
        id=0,
        path=path,
        name=disk_name,
        parent_path="",
        node_type=VFSNodeType.DISK,
        evidence_id=evidence_id,
        partition_info=disk_info,
    )


def create_drive_node(
    parent_disk: str,
    drive_letter: str,
    partition_info: str = None,
    evidence_id: str = None
) -> VFSNode:
    """Create drive letter node (C:, D:, etc.)."""
    letter = drive_letter.rstrip(":").upper()
    path = f"/{parent_disk}/{letter}:"
    return VFSNode(
        id=0,
        path=path,
        name=f"{letter}:",
        parent_path=f"/{parent_disk}",
        node_type=VFSNodeType.DRIVE,
        evidence_id=evidence_id,
        partition_info=partition_info,
    )


def create_folder_node(
    parent_path: str,
    name: str,
    evidence_id: str = None,
    is_user: bool = False,
    is_system: bool = False
) -> VFSNode:
    """Create folder node."""
    parent = VirtualFilesystem.normalize_path(parent_path)
    path = f"{parent}/{name}"
    
    node_type = VFSNodeType.FOLDER
    if is_user:
        node_type = VFSNodeType.USER
    elif is_system:
        node_type = VFSNodeType.SYSTEM
    
    return VFSNode(
        id=0,
        path=path,
        name=name,
        parent_path=parent,
        node_type=node_type,
        evidence_id=evidence_id,
    )


def create_file_node(
    parent_path: str,
    name: str,
    size: int = 0,
    modified: datetime = None,
    sha256: str = None,
    evidence_id: str = None,
    is_deleted: bool = False
) -> VFSNode:
    """Create file node."""
    parent = VirtualFilesystem.normalize_path(parent_path)
    path = f"{parent}/{name}"
    
    return VFSNode(
        id=0,
        path=path,
        name=name,
        parent_path=parent,
        node_type=VFSNodeType.DELETED if is_deleted else VFSNodeType.FILE,
        size=size,
        modified=modified,
        sha256=sha256,
        mime_type=VirtualFilesystem.guess_mime_type(name),
        evidence_id=evidence_id,
        is_deleted=is_deleted,
    )
