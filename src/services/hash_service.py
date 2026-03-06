"""
FEPD Hash Service
=================

Provides asynchronous, cached SHA-256 / MD5 hashing for forensic evidence files.
Runs hash computations in a background ``QThread`` worker so the UI stays
responsive during large-file hashing.

Usage:
    svc = HashService(read_file_func)
    svc.hash_computed.connect(on_hash_ready)
    svc.compute_hash("/This PC/C:/Users/Evidence/malware.exe", file_size=42000)

The service caches results in memory and, optionally, writes them back to
the VFS database.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional, Callable, Dict, Tuple

from PyQt6.QtCore import QObject, QThread, pyqtSignal

logger = logging.getLogger(__name__)

# 64 KB read chunks (matches existing HASH_BUFFER_SIZE in files_tab.py)
_CHUNK_SIZE = 65536


# ============================================================================
# Worker thread
# ============================================================================

class _HashWorker(QThread):
    """Background worker that computes SHA-256 + MD5 for a single file."""

    finished = pyqtSignal(str, str, str)      # path, sha256, md5
    error = pyqtSignal(str, str)              # path, error_message
    progress = pyqtSignal(str, int)           # path, percent (0-100)

    def __init__(
        self,
        path: str,
        file_size: int,
        read_file_func: Callable[[str, int, int], Optional[bytes]],
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)
        self._path = path
        self._file_size = file_size
        self._read_file = read_file_func

    def run(self):
        try:
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            offset = 0
            size = self._file_size or 0

            while offset < size:
                chunk_len = min(_CHUNK_SIZE, size - offset)
                data = self._read_file(self._path, offset, chunk_len)
                if not data:
                    break
                sha256.update(data)
                md5.update(data)
                offset += len(data)

                if size > 0:
                    pct = int((offset / size) * 100)
                    self.progress.emit(self._path, pct)

            self.finished.emit(self._path, sha256.hexdigest(), md5.hexdigest())

        except Exception as exc:
            logger.error(f"Hash worker error for {self._path}: {exc}")
            self.error.emit(self._path, str(exc))


# ============================================================================
# Service
# ============================================================================

class HashService(QObject):
    """
    Lazy, cached hashing service.

    * Hashes only when explicitly requested (not at ingest time).
    * Results are cached in-memory so subsequent requests are instant.
    * Emits Qt signals for async UI integration.
    """

    # Public signals
    hash_computed = pyqtSignal(str, str, str)   # path, sha256, md5
    hash_error = pyqtSignal(str, str)           # path, error_message
    hash_progress = pyqtSignal(str, int)        # path, percent

    def __init__(
        self,
        read_file_func: Optional[Callable[[str, int, int], Optional[bytes]]] = None,
        vfs=None,
        parent: Optional[QObject] = None,
    ):
        """
        Args:
            read_file_func: Callable(path, offset, length) → bytes
            vfs: Optional VirtualFilesystem to write hashes back to the DB.
        """
        super().__init__(parent)
        self._read_file = read_file_func
        self._vfs = vfs
        self._cache: Dict[str, Tuple[str, str]] = {}  # path → (sha256, md5)
        self._active_workers: Dict[str, _HashWorker] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_read_file_func(self, func: Callable[[str, int, int], Optional[bytes]]):
        """Hot-swap the read function (e.g. when an image is loaded later)."""
        self._read_file = func

    def get_cached(self, path: str) -> Optional[Tuple[str, str]]:
        """Return (sha256, md5) from cache, or None."""
        return self._cache.get(path)

    def compute_hash(self, path: str, file_size: int) -> None:
        """
        Request an async hash computation.

        If the hash is already cached, emits ``hash_computed`` immediately.
        If a worker is already running for this path, the request is ignored.
        """
        # Cache hit
        if path in self._cache:
            sha, md = self._cache[path]
            self.hash_computed.emit(path, sha, md)
            return

        # Already running
        if path in self._active_workers:
            return

        # No read function available
        if not self._read_file:
            self.hash_error.emit(path, "File reading not available.")
            return

        # Spin up worker
        worker = _HashWorker(path, file_size, self._read_file, self)
        worker.finished.connect(self._on_worker_finished)
        worker.error.connect(self._on_worker_error)
        worker.progress.connect(self.hash_progress)
        self._active_workers[path] = worker
        worker.start()

    def compute_hash_sync(self, path: str, file_size: int) -> Optional[Tuple[str, str]]:
        """
        Synchronous hash computation (blocks the calling thread).
        Useful for export / verification workflows.
        """
        if path in self._cache:
            return self._cache[path]

        if not self._read_file:
            return None

        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        offset = 0
        size = file_size or 0

        try:
            while offset < size:
                chunk_len = min(_CHUNK_SIZE, size - offset)
                data = self._read_file(path, offset, chunk_len)
                if not data:
                    break
                sha256.update(data)
                md5.update(data)
                offset += len(data)

            result = (sha256.hexdigest(), md5.hexdigest())
            self._cache[path] = result
            return result
        except Exception as exc:
            logger.error(f"Sync hash failed for {path}: {exc}")
            return None

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_worker_finished(self, path: str, sha256: str, md5: str):
        self._cache[path] = (sha256, md5)
        self._active_workers.pop(path, None)

        # Optionally write back to VFS DB
        if self._vfs:
            try:
                self._vfs.update_hash(path, sha256=sha256, md5=md5)
            except Exception:
                pass  # Non-critical; cache is still valid

        self.hash_computed.emit(path, sha256, md5)

    def _on_worker_error(self, path: str, message: str):
        self._active_workers.pop(path, None)
        self.hash_error.emit(path, message)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cancel_all(self):
        """Cancel all running hash workers."""
        for worker in list(self._active_workers.values()):
            worker.quit()
            worker.wait(1000)
        self._active_workers.clear()
