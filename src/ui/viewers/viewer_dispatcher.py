"""
FEPD Viewer Dispatcher
======================

Centralised routing of files to the appropriate viewer widget based
on file extension, MIME type, and magic-byte detection.

Usage::

    dispatcher = ViewerDispatcher(read_file_func=my_read)
    viewer     = dispatcher.open(path="/Evidence/doc.pdf", data=raw_bytes)

The dispatcher never modifies evidence — all viewers are strictly
read-only.
"""

from __future__ import annotations

import logging
from pathlib import PurePosixPath
from typing import Optional, Callable, Dict, Set

from PyQt6.QtWidgets import QWidget

from .base_viewer import BaseViewer
from .text_viewer import TextViewer
from .hex_viewer import HexViewer
from .image_viewer import ImageViewer
from .pdf_viewer import PDFViewer
from .video_viewer import VideoViewer

logger = logging.getLogger(__name__)

# ── Extension → viewer type mapping ──────────────────────────────────────

_TEXT_EXTS: Set[str] = {
    ".txt", ".log", ".csv", ".tsv", ".json", ".xml", ".html", ".htm",
    ".css", ".js", ".py", ".java", ".c", ".cpp", ".h", ".hpp", ".cs",
    ".rb", ".go", ".rs", ".swift", ".kt", ".sh", ".bat", ".ps1",
    ".cmd", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".toml", ".md",
    ".rst", ".sql", ".php", ".pl", ".r", ".m", ".vbs", ".reg",
}

_IMAGE_EXTS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif",
    ".ico", ".webp", ".svg",
}

_PDF_EXTS: Set[str] = {".pdf"}

_VIDEO_EXTS: Set[str] = {
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
    ".mpg", ".mpeg", ".m4v", ".3gp",
}

_AUDIO_EXTS: Set[str] = {
    ".mp3", ".wav", ".flac", ".ogg", ".aac", ".wma", ".m4a",
}

# Magic bytes for fallback detection (first N bytes → type)
_MAGIC_MAP: Dict[bytes, str] = {
    b"%PDF":          "pdf",
    b"\x89PNG":       "image",
    b"\xff\xd8\xff":  "image",
    b"GIF8":          "image",
    b"BM":            "image",
    b"MZ":            "pe",
    b"PK\x03\x04":   "archive",
}


class ViewerDispatcher:
    """
    Create and return the correct viewer widget for a given file.

    Parameters
    ----------
    read_file_func : callable, optional
        ``(path, offset, length) -> bytes`` used by viewers to stream
        evidence data from the VFS / disk image.
    """

    def __init__(
        self,
        read_file_func: Optional[Callable[[str, int, int], bytes]] = None,
    ):
        self._read = read_file_func

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def viewer_type(self, path: str, header: bytes = b"") -> str:
        """
        Determine viewer type string for *path*.

        Returns one of: ``"text"``, ``"image"``, ``"pdf"``, ``"video"``,
        ``"audio"``, ``"pe"``, ``"archive"``, ``"hex"`` (fallback).
        """
        ext = PurePosixPath(path).suffix.lower()

        if ext in _TEXT_EXTS:
            return "text"
        if ext in _IMAGE_EXTS:
            return "image"
        if ext in _PDF_EXTS:
            return "pdf"
        if ext in _VIDEO_EXTS:
            return "video"
        if ext in _AUDIO_EXTS:
            return "audio"
        if ext in {".exe", ".dll", ".sys", ".ocx", ".scr", ".drv"}:
            return "pe"
        if ext in {".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".tar"}:
            return "archive"

        # Fallback: magic bytes
        if header:
            for sig, vtype in _MAGIC_MAP.items():
                if header[:len(sig)] == sig:
                    return vtype

        return "hex"

    def open(
        self,
        path: str,
        data: Optional[bytes] = None,
        parent: Optional[QWidget] = None,
    ) -> BaseViewer:
        """
        Return a viewer widget loaded with the file at *path*.

        If *data* is ``None`` and ``read_file_func`` was provided,
        the dispatcher will read the first 8 KB to detect the type and
        pass the function through to the viewer.
        """
        header = (data or b"")[:16]
        if not header and self._read:
            try:
                header = self._read(path, 0, 16)
            except Exception:
                header = b""

        vtype = self.viewer_type(path, header)
        name = PurePosixPath(path).name

        if vtype == "text":
            viewer = TextViewer(parent=parent, read_file_func=self._read)
        elif vtype == "image":
            viewer = ImageViewer(parent=parent, read_file_func=self._read)
        elif vtype == "pdf":
            viewer = PDFViewer(parent=parent, read_file_func=self._read)
        elif vtype == "video":
            viewer = VideoViewer(parent=parent, read_file_func=self._read)
        else:
            # hex fallback for pe, archive, audio, unknown
            viewer = HexViewer(parent=parent, read_file_func=self._read)

        try:
            viewer.open_file(path)
        except Exception as exc:
            logger.warning("Viewer failed to open %s: %s", path, exc)

        return viewer
