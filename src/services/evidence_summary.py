"""
FEPD Evidence Summary Service
==============================

Generates a comprehensive forensic overview immediately after evidence
ingestion.  Queries the VFS SQLite database to produce:

  • Evidence metadata (image size, filesystem, partitions)
  • File category counts (images, videos, documents, executables, archives)
  • Important folder detection and file counts
  • User account discovery
  • Last-activity timestamps
  • Disk-usage breakdown by category
  • Most-active folder ranking

All operations are **read-only** — no evidence is modified.

Usage::

    from src.services.evidence_summary import EvidenceSummaryService, EvidenceSummary

    svc = EvidenceSummaryService(vfs)
    summary = svc.generate(evidence)
    print(summary.total_files, summary.category_counts)

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── File-category extension map ───────────────────────────────────────────

_CATEGORY_EXTENSIONS: Dict[str, set] = {
    "Images": {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
        ".ico", ".webp", ".svg", ".raw", ".cr2", ".nef", ".heic",
    },
    "Videos": {
        ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
        ".mpg", ".mpeg", ".m4v", ".3gp", ".ts",
    },
    "Documents": {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".txt", ".rtf", ".odt", ".ods", ".odp", ".csv", ".tsv",
        ".md", ".tex", ".epub", ".pages", ".numbers", ".key",
    },
    "Executables": {
        ".exe", ".dll", ".sys", ".ocx", ".scr", ".drv", ".msi",
        ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".com",
    },
    "Archives": {
        ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".tar",
        ".cab", ".iso", ".dmg", ".img",
    },
    "Audio": {
        ".mp3", ".wav", ".flac", ".ogg", ".aac", ".wma", ".m4a",
        ".opus", ".mid", ".midi",
    },
    "Databases": {
        ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".dbf",
    },
    "Email": {
        ".pst", ".ost", ".eml", ".msg", ".mbox",
    },
}

# Reverse map: extension → category
_EXT_TO_CATEGORY: Dict[str, str] = {}
for _cat, _exts in _CATEGORY_EXTENSIONS.items():
    for _e in _exts:
        _EXT_TO_CATEGORY[_e] = _cat

# Known important directories (case-insensitive matching)
_IMPORTANT_FOLDERS = {
    "users", "windows", "program files", "program files (x86)",
    "programdata", "documents", "downloads", "desktop",
    "pictures", "videos", "music", "appdata",
    "documents and settings", "temp", "tmp",
    "home", "root", "var", "etc", "usr", "opt",
    "recycle.bin", "$recycle.bin",
}


# ── Data classes ──────────────────────────────────────────────────────────

@dataclass
class UserAccount:
    """Detected user account."""
    username: str
    home_path: str
    file_count: int = 0
    folder_size: int = 0
    last_activity: Optional[str] = None


@dataclass
class ImportantFolder:
    """A forensically-important directory."""
    name: str
    path: str
    file_count: int = 0
    total_size: int = 0


@dataclass
class FolderActivity:
    """Folder ranked by recent modification activity."""
    name: str
    path: str
    modified_count: int = 0
    latest_modified: Optional[str] = None


@dataclass
class EvidenceSummary:
    """Complete evidence overview produced after ingestion."""

    # ── Evidence metadata ──
    image_name: str = ""
    image_size: int = 0
    image_size_display: str = ""
    sha256: str = ""
    filesystem: str = ""
    partition_count: int = 0
    mount_points: List[str] = field(default_factory=list)
    os_detected: str = ""

    # ── Counts ──
    total_files: int = 0
    total_folders: int = 0
    total_deleted: int = 0

    # ── Categories ──
    category_counts: Dict[str, int] = field(default_factory=dict)
    category_sizes: Dict[str, int] = field(default_factory=dict)

    # ── Users ──
    user_accounts: List[UserAccount] = field(default_factory=list)

    # ── Important folders ──
    important_folders: List[ImportantFolder] = field(default_factory=list)

    # ── Activity ──
    last_file_created: Optional[str] = None
    last_file_modified: Optional[str] = None
    last_file_accessed: Optional[str] = None

    # ── Top active folders ──
    most_active_folders: List[FolderActivity] = field(default_factory=list)

    # ── Quick alerts ──
    alerts: List[Dict[str, Any]] = field(default_factory=list)

    # ── Disk usage (for chart) ──
    disk_usage_pct: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for signal emission / JSON export."""
        return {
            "image_name": self.image_name,
            "image_size": self.image_size,
            "image_size_display": self.image_size_display,
            "sha256": self.sha256,
            "filesystem": self.filesystem,
            "partition_count": self.partition_count,
            "mount_points": self.mount_points,
            "os_detected": self.os_detected,
            "total_files": self.total_files,
            "total_folders": self.total_folders,
            "total_deleted": self.total_deleted,
            "category_counts": self.category_counts,
            "category_sizes": self.category_sizes,
            "user_accounts": [
                {"username": u.username, "home_path": u.home_path,
                 "file_count": u.file_count, "folder_size": u.folder_size,
                 "last_activity": u.last_activity}
                for u in self.user_accounts
            ],
            "important_folders": [
                {"name": f.name, "path": f.path,
                 "file_count": f.file_count, "total_size": f.total_size}
                for f in self.important_folders
            ],
            "last_file_created": self.last_file_created,
            "last_file_modified": self.last_file_modified,
            "last_file_accessed": self.last_file_accessed,
            "most_active_folders": [
                {"name": f.name, "path": f.path,
                 "modified_count": f.modified_count,
                 "latest_modified": f.latest_modified}
                for f in self.most_active_folders
            ],
            "alerts": self.alerts,
            "disk_usage_pct": self.disk_usage_pct,
        }


# ── Service ───────────────────────────────────────────────────────────────

class EvidenceSummaryService:
    """
    Generates an ``EvidenceSummary`` from the VFS database.

    Parameters
    ----------
    vfs : VirtualFilesystem
        The populated virtual filesystem.
    """

    def __init__(self, vfs: Any):
        self._vfs = vfs

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def generate(
        self,
        image_name: str = "",
        image_size: int = 0,
        sha256: str = "",
        filesystem: str = "",
        partitions: Optional[list] = None,
    ) -> EvidenceSummary:
        """
        Collect all statistics and return a populated ``EvidenceSummary``.
        """
        summary = EvidenceSummary(
            image_name=image_name,
            image_size=image_size,
            image_size_display=self._human_size(image_size),
            sha256=sha256,
            filesystem=filesystem,
        )

        if partitions:
            summary.partition_count = len(partitions)
            summary.mount_points = [
                getattr(p, "mount_point", "") for p in partitions if getattr(p, "mount_point", "")
            ]

        conn = self._conn()
        if conn is None:
            return summary

        try:
            self._collect_counts(conn, summary)
            self._collect_categories(conn, summary)
            self._collect_users(conn, summary)
            self._collect_important_folders(conn, summary)
            self._collect_last_activity(conn, summary)
            self._collect_active_folders(conn, summary)
            self._detect_os(conn, summary)
            self._compute_disk_usage(summary)
        except Exception as exc:
            logger.error("Evidence summary generation error: %s", exc, exc_info=True)

        return summary

    # ------------------------------------------------------------------
    # Internal collectors
    # ------------------------------------------------------------------

    def _conn(self) -> Optional[sqlite3.Connection]:
        """Get a read-only SQLite connection from the VFS."""
        try:
            return self._vfs._get_connection()
        except Exception:
            return None

    def _collect_counts(self, conn: sqlite3.Connection, s: EvidenceSummary) -> None:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM virtual_fs WHERE node_type = 'file'")
        s.total_files = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM virtual_fs WHERE node_type IN ('folder','drive','partition')")
        s.total_folders = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM virtual_fs WHERE is_deleted = 1")
        s.total_deleted = cur.fetchone()[0]

    def _collect_categories(self, conn: sqlite3.Connection, s: EvidenceSummary) -> None:
        """Count files by extension category via a single full scan."""
        cur = conn.cursor()
        cur.execute(
            "SELECT name, size FROM virtual_fs WHERE node_type = 'file' AND is_deleted = 0"
        )
        counts: Dict[str, int] = {}
        sizes: Dict[str, int] = {}
        other_count = 0
        other_size = 0

        for row in cur:
            name = row[0] or ""
            size = row[1] or 0
            dot = name.rfind(".")
            if dot >= 0:
                ext = name[dot:].lower()
                cat = _EXT_TO_CATEGORY.get(ext)
            else:
                cat = None

            if cat:
                counts[cat] = counts.get(cat, 0) + 1
                sizes[cat] = sizes.get(cat, 0) + size
            else:
                other_count += 1
                other_size += size

        counts["Other"] = other_count
        sizes["Other"] = other_size
        s.category_counts = counts
        s.category_sizes = sizes

    def _collect_users(self, conn: sqlite3.Connection, s: EvidenceSummary) -> None:
        """Detect user accounts from VFS USER nodes or /Users/ paths."""
        cur = conn.cursor()

        # First try USER node type
        cur.execute("SELECT path, name FROM virtual_fs WHERE node_type = 'user' ORDER BY name")
        user_rows = cur.fetchall()

        if not user_rows:
            # Fallback: look for children of paths ending in /Users
            cur.execute(
                "SELECT path, name FROM virtual_fs "
                "WHERE parent_path LIKE '%/Users' AND node_type IN ('folder','user') "
                "ORDER BY name"
            )
            user_rows = cur.fetchall()

        skip = {"public", "default", "default user", "all users", ".", ".."}
        for row in user_rows:
            uname = row[1]
            if uname.lower() in skip:
                continue
            upath = row[0]

            # Count files under this user path
            cur.execute(
                "SELECT COUNT(*), COALESCE(SUM(size),0) FROM virtual_fs "
                "WHERE path LIKE ? AND node_type = 'file'",
                (f"{upath}/%",),
            )
            fc, fs = cur.fetchone()

            # Latest modified
            cur.execute(
                "SELECT MAX(modified) FROM virtual_fs WHERE path LIKE ? AND modified IS NOT NULL",
                (f"{upath}/%",),
            )
            last_mod = cur.fetchone()[0]

            s.user_accounts.append(UserAccount(
                username=uname,
                home_path=upath,
                file_count=fc,
                folder_size=fs,
                last_activity=last_mod,
            ))

    def _collect_important_folders(self, conn: sqlite3.Connection, s: EvidenceSummary) -> None:
        """Find known-important directories."""
        cur = conn.cursor()
        cur.execute(
            "SELECT path, name FROM virtual_fs "
            "WHERE node_type IN ('folder','drive','system') ORDER BY path"
        )
        for row in cur:
            fname = row[1]
            fpath = row[0]
            if fname.lower() in _IMPORTANT_FOLDERS:
                # Count children files
                cur2 = conn.cursor()
                cur2.execute(
                    "SELECT COUNT(*), COALESCE(SUM(size),0) FROM virtual_fs "
                    "WHERE path LIKE ? AND node_type = 'file'",
                    (f"{fpath}/%",),
                )
                fc, fs = cur2.fetchone()
                s.important_folders.append(ImportantFolder(
                    name=fname, path=fpath, file_count=fc, total_size=fs,
                ))

        # De-duplicate by name (keep deepest path for each name)
        seen: Dict[str, ImportantFolder] = {}
        for f in s.important_folders:
            key = f.name.lower()
            if key not in seen or f.file_count > seen[key].file_count:
                seen[key] = f
        s.important_folders = sorted(seen.values(), key=lambda x: x.name.lower())

    def _collect_last_activity(self, conn: sqlite3.Connection, s: EvidenceSummary) -> None:
        """Find the most recent filesystem timestamps."""
        cur = conn.cursor()
        cur.execute("SELECT MAX(created) FROM virtual_fs WHERE created IS NOT NULL")
        row = cur.fetchone()
        s.last_file_created = row[0] if row else None

        cur.execute("SELECT MAX(modified) FROM virtual_fs WHERE modified IS NOT NULL")
        row = cur.fetchone()
        s.last_file_modified = row[0] if row else None

        cur.execute("SELECT MAX(accessed) FROM virtual_fs WHERE accessed IS NOT NULL")
        row = cur.fetchone()
        s.last_file_accessed = row[0] if row else None

    def _collect_active_folders(self, conn: sqlite3.Connection, s: EvidenceSummary) -> None:
        """Rank folders by number of recently-modified files."""
        cur = conn.cursor()
        cur.execute(
            "SELECT parent_path, COUNT(*) as cnt, MAX(modified) as latest "
            "FROM virtual_fs "
            "WHERE node_type = 'file' AND modified IS NOT NULL "
            "GROUP BY parent_path "
            "ORDER BY cnt DESC "
            "LIMIT 10"
        )
        for row in cur:
            ppath = row[0] or ""
            name = PurePosixPath(ppath).name if ppath else ""
            s.most_active_folders.append(FolderActivity(
                name=name or ppath,
                path=ppath,
                modified_count=row[1],
                latest_modified=row[2],
            ))

    def _detect_os(self, conn: sqlite3.Connection, s: EvidenceSummary) -> None:
        """Heuristic OS detection from filesystem layout."""
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM virtual_fs WHERE name = 'Windows' AND node_type IN ('folder','system')"
        )
        if cur.fetchone()[0] > 0:
            s.os_detected = "Windows"
            # Try to narrow down version
            cur.execute(
                "SELECT COUNT(*) FROM virtual_fs WHERE path LIKE '%/Windows/System32/ntoskrnl.exe'"
            )
            return

        cur.execute(
            "SELECT COUNT(*) FROM virtual_fs WHERE name = 'etc' AND node_type = 'folder'"
        )
        if cur.fetchone()[0] > 0:
            s.os_detected = "Linux / Unix"
            return

        cur.execute(
            "SELECT COUNT(*) FROM virtual_fs WHERE name = 'Applications' AND node_type = 'folder'"
        )
        if cur.fetchone()[0] > 0:
            s.os_detected = "macOS"
            return

        s.os_detected = "Unknown"

    def _compute_disk_usage(self, s: EvidenceSummary) -> None:
        """Compute percentage of total size per category (for pie chart)."""
        total = sum(s.category_sizes.values()) or 1
        s.disk_usage_pct = {
            cat: round(sz / total * 100, 1)
            for cat, sz in sorted(
                s.category_sizes.items(), key=lambda x: x[1], reverse=True,
            )
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _human_size(size: int) -> str:
        """Format bytes into human-readable string."""
        if size <= 0:
            return "0 B"
        s = float(size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(s) < 1024:
                return f"{s:.1f} {unit}"
            s /= 1024
        return f"{s:.1f} PB"
