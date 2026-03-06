"""
FEPD Evidence Filesystem Adapter
=================================

Low-level bridge between forensic disk images (E01 / RAW / DD) and the
FEPD browsing layer.  Handles:

    • Opening images via pyewf / pytsk3
    • Listing directory entries at a given path
    • Reading file bytes (for preview, hash, export)
    • Extracting metadata (timestamps, inodes)

This module is STRICTLY READ-ONLY — no writes, renames, or deletions.

Architecture:
    evidence_fs.py  (this)
        ↓
    pytsk3  /  pyewf
        ↓
    Raw disk image  (E01 / DD / RAW)

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional imports — graceful fallback when forensic libs are not installed
# ---------------------------------------------------------------------------

try:
    import pytsk3
    HAS_PYTSK3 = True
except ImportError:
    pytsk3 = None  # type: ignore[assignment]
    HAS_PYTSK3 = False

try:
    import pyewf
    HAS_PYEWF = True
except ImportError:
    pyewf = None  # type: ignore[assignment]
    HAS_PYEWF = False


# ============================================================================
# Data structures
# ============================================================================

@dataclass
class EvidenceDirEntry:
    """
    One file or folder returned by a directory listing.

    This is the *raw* entry from the forensic image, before it enters the
    VFS database.  EvidenceFS → VFS Builder → FileEntry for the UI.
    """
    name: str
    path: str
    is_directory: bool
    size: int = 0
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    accessed: Optional[datetime] = None
    inode: Optional[int] = None
    is_deleted: bool = False
    is_allocated: bool = True

    @property
    def display_name(self) -> str:
        return self.name


# ============================================================================
# pyewf → pytsk3 bridge (EWF image as pytsk3 Img_Info)
# ============================================================================

class _EWFImgInfo(pytsk3.Img_Info if HAS_PYTSK3 else object):  # type: ignore[misc]
    """Wraps a pyewf handle so pytsk3 can treat it as a raw image."""

    def __init__(self, ewf_handle):
        self._handle = ewf_handle
        if HAS_PYTSK3:
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._handle.close()

    def read(self, offset: int, size: int) -> bytes:
        self._handle.seek(offset)
        return self._handle.read(size)

    def get_size(self) -> int:
        return self._handle.get_media_size()


# ============================================================================
# Evidence Filesystem Adapter
# ============================================================================

class EvidenceFS:
    """
    Read-only filesystem adapter for forensic disk images.

    Usage::

        efs = EvidenceFS()
        efs.open("evidence.E01")
        entries = efs.list_dir("/Users/Alice/Documents")
        data = efs.read_file("/Users/Alice/notes.txt", offset=0, length=-1)
        efs.close()

    Thread safety: a single instance must not be shared across threads.
    Create one per worker if background reads are needed.
    """

    def __init__(self) -> None:
        self._img_info: Optional[object] = None
        self._fs_info: Optional[object] = None
        self._ewf_handle: Optional[object] = None
        self._raw_fh = None
        self._image_path: Optional[str] = None
        self._opened = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self, image_path: str, partition_offset: int = 0) -> None:
        """
        Open a forensic image and mount its filesystem.

        Args:
            image_path:       Path to .E01 / .dd / .raw image file.
            partition_offset: Byte offset of the partition to mount
                              (0 for "whole-disk" or single-partition images).
        """
        self.close()
        self._image_path = image_path
        ext = os.path.splitext(image_path)[1].lower()

        # --- EWF (E01, Ex01, L01) ----------------------------------------
        if ext in (".e01", ".ex01", ".l01") and HAS_PYEWF and HAS_PYTSK3:
            filenames = pyewf.glob(image_path)
            handle = pyewf.handle()
            handle.open(filenames)
            self._ewf_handle = handle
            self._img_info = _EWFImgInfo(handle)
            self._fs_info = pytsk3.FS_Info(self._img_info, offset=partition_offset)

        # --- RAW / DD via pytsk3 ------------------------------------------
        elif HAS_PYTSK3:
            self._img_info = pytsk3.Img_Info(image_path)
            self._fs_info = pytsk3.FS_Info(self._img_info, offset=partition_offset)

        # --- Fallback: plain file I/O (very limited) ----------------------
        else:
            self._raw_fh = open(image_path, "rb")
            logger.warning("pytsk3/pyewf not available — limited to raw byte access")

        self._opened = True
        logger.info("EvidenceFS opened: %s (offset=%d)", image_path, partition_offset)

    def close(self) -> None:
        """Release all resources."""
        try:
            if self._ewf_handle:
                self._ewf_handle.close()
            if self._raw_fh:
                self._raw_fh.close()
        except Exception as exc:
            logger.debug("Close error: %s", exc)
        finally:
            self._img_info = None
            self._fs_info = None
            self._ewf_handle = None
            self._raw_fh = None
            self._opened = False

    @property
    def is_open(self) -> bool:
        return self._opened

    # ------------------------------------------------------------------
    # Directory listing
    # ------------------------------------------------------------------

    def list_dir(self, path: str = "/") -> List[EvidenceDirEntry]:
        """
        List directory entries at *path*.

        Returns folders first (sorted A-Z), then files (sorted A-Z),
        exactly like a native file manager.
        """
        if not self._opened or not self._fs_info:
            return []

        try:
            directory = self._fs_info.open_dir(path=path)
        except Exception as exc:
            logger.error("Cannot open directory '%s': %s", path, exc)
            return []

        folders: List[EvidenceDirEntry] = []
        files: List[EvidenceDirEntry] = []

        for entry in directory:
            name = entry.info.name.name
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")

            # Skip VFS meta-entries
            if name in (".", "..", "$OrphanFiles"):
                continue

            is_dir = False
            size = 0
            inode = None
            created = modified = accessed = None
            is_deleted = False
            is_allocated = True

            try:
                meta = entry.info.meta
                if meta:
                    is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                    size = int(meta.size) if meta.size else 0
                    inode = int(meta.addr) if meta.addr else None

                    if meta.crtime:
                        created = datetime.utcfromtimestamp(meta.crtime)
                    if meta.mtime:
                        modified = datetime.utcfromtimestamp(meta.mtime)
                    if meta.atime:
                        accessed = datetime.utcfromtimestamp(meta.atime)

                    # Flags
                    if hasattr(meta, "flags"):
                        is_allocated = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
                        is_deleted = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
                else:
                    # Fallback: check name type
                    name_obj = entry.info.name
                    if name_obj and hasattr(name_obj, "type"):
                        is_dir = name_obj.type == pytsk3.TSK_FS_NAME_TYPE_DIR
            except Exception:
                pass

            child_path = path.rstrip("/") + "/" + name

            de = EvidenceDirEntry(
                name=name,
                path=child_path,
                is_directory=is_dir,
                size=size,
                created=created,
                modified=modified,
                accessed=accessed,
                inode=inode,
                is_deleted=is_deleted,
                is_allocated=is_allocated,
            )

            if is_dir:
                folders.append(de)
            else:
                files.append(de)

        folders.sort(key=lambda e: e.name.lower())
        files.sort(key=lambda e: e.name.lower())
        return folders + files

    # ------------------------------------------------------------------
    # File reading
    # ------------------------------------------------------------------

    def read_file(self, path: str, offset: int = 0, length: int = -1) -> Optional[bytes]:
        """
        Read bytes from a file inside the evidence image.

        Args:
            path:   Filesystem path inside the image (e.g. ``/Users/Alice/notes.txt``).
            offset: Byte offset to start reading from.
            length: Number of bytes to read (``-1`` = entire file).

        Returns:
            ``bytes`` or ``None`` on error.
        """
        if not self._opened or not self._fs_info:
            return None

        try:
            file_obj = self._fs_info.open(path)
            meta = file_obj.info.meta
            total = int(meta.size) if meta and meta.size else 0

            if length < 0:
                length = total - offset

            length = min(length, total - offset)
            if length <= 0:
                return b""

            return file_obj.read_random(offset, length)

        except Exception as exc:
            logger.error("read_file('%s') failed: %s", path, exc)
            return None

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    def stat(self, path: str) -> Optional[EvidenceDirEntry]:
        """
        Return metadata for a single path (like ``os.stat``).
        """
        if not self._opened or not self._fs_info:
            return None

        try:
            file_obj = self._fs_info.open(path)
            meta = file_obj.info.meta
            name_obj = file_obj.info.name

            name = ""
            if name_obj and name_obj.name:
                name = name_obj.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")

            is_dir = False
            size = 0
            inode = None
            created = modified = accessed = None

            if meta:
                is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                size = int(meta.size) if meta.size else 0
                inode = int(meta.addr) if meta.addr else None
                if meta.crtime:
                    created = datetime.utcfromtimestamp(meta.crtime)
                if meta.mtime:
                    modified = datetime.utcfromtimestamp(meta.mtime)
                if meta.atime:
                    accessed = datetime.utcfromtimestamp(meta.atime)

            return EvidenceDirEntry(
                name=name,
                path=path,
                is_directory=is_dir,
                size=size,
                created=created,
                modified=modified,
                accessed=accessed,
                inode=inode,
            )
        except Exception as exc:
            logger.error("stat('%s') failed: %s", path, exc)
            return None

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def exists(self, path: str) -> bool:
        """Check if a path exists in the image."""
        return self.stat(path) is not None

    def is_dir(self, path: str) -> bool:
        """Check if *path* is a directory."""
        s = self.stat(path)
        return s.is_directory if s else False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __repr__(self) -> str:
        status = "open" if self._opened else "closed"
        return f"<EvidenceFS [{status}] {self._image_path or ''}>"
