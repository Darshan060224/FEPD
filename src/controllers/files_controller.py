"""
FEPD Files Controller
=====================

Central orchestrator for the forensic file browser.  Sits between the
UI layer (``FilesTab``) and the data layer (``VirtualFilesystem``).

Owns:
    • FileNavigator   — path traversal & history
    • HashService     — async / cached hashing
    • PreviewService  — viewer routing & quick-preview generation

Provides a single public API surface that the UI calls — the UI never
touches ``VirtualFilesystem`` directly.

Forensic safety:
    • Every user-facing action is checked against an allow-list.
    • Write / modify / delete requests are blocked and logged.
    • All allowed actions are recorded via the CoC logger.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Callable, Dict, List, Any

from PyQt6.QtCore import QObject, pyqtSignal

from src.core.virtual_fs import VirtualFilesystem, VFSNode
from src.core.file_navigator import FileNavigator
from src.models.file_entry import FileEntry
from src.services.hash_service import HashService
from src.services.preview_service import PreviewService

logger = logging.getLogger(__name__)


# ============================================================================
# FORENSIC WRITE-BLOCK
# ============================================================================

_BLOCKED_ACTIONS = frozenset({
    "delete", "remove", "rename", "move", "cut",
    "modify", "edit", "write", "save", "create",
})

_BLOCK_MESSAGE = (
    "[BLOCKED] This action would modify evidence.\n"
    "FEPD operates in strict READ-ONLY mode.\n"
    "Use 'Export to Workspace' to create a working copy."
)


# ============================================================================
# FILES CONTROLLER
# ============================================================================

class FilesController(QObject):
    """
    Mediator between the Files Tab UI and the data/service layer.

    Signals emitted by this controller are the **only** signals the UI
    should connect to for navigation, preview, and hashing.
    """

    # ------------------------------------------------------------------
    # Signals (UI connects to these)
    # ------------------------------------------------------------------
    directory_loaded = pyqtSignal(list)             # list[FileEntry]
    file_selected = pyqtSignal(object)              # FileEntry
    path_changed = pyqtSignal(str)                  # current path
    navigation_state_changed = pyqtSignal(bool, bool)  # can_back, can_fwd
    user_context_changed = pyqtSignal(str)          # username or ""

    preview_ready = pyqtSignal(dict)                # preview data dict
    hash_computed = pyqtSignal(str, str, str)        # path, sha256, md5
    hash_progress = pyqtSignal(str, int)            # path, percent
    hash_error = pyqtSignal(str, str)               # path, error

    write_blocked = pyqtSignal(str)                 # blocked action name
    status_message = pyqtSignal(str)                # transient status text
    coc_logged = pyqtSignal(str, dict)              # action, details

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------

    def __init__(
        self,
        vfs: VirtualFilesystem,
        read_file_func: Optional[Callable[[str, int, int], Optional[bytes]]] = None,
        coc_logger: Optional[Callable[[str, Dict], None]] = None,
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)

        self._vfs = vfs
        self._read_file = read_file_func
        self._coc_logger = coc_logger
        self._selected_entry: Optional[FileEntry] = None

        # Sub-components
        self._navigator = FileNavigator(vfs, parent=self)
        self._hash_service = HashService(read_file_func, vfs=vfs, parent=self)
        self._preview_service = PreviewService(read_file_func)

        # Wire navigator signals → controller signals
        self._navigator.path_changed.connect(self.path_changed)
        self._navigator.directory_loaded.connect(self.directory_loaded)
        self._navigator.navigation_state_changed.connect(self.navigation_state_changed)
        self._navigator.user_context_changed.connect(self.user_context_changed)

        # Wire hash service
        self._hash_service.hash_computed.connect(self.hash_computed)
        self._hash_service.hash_progress.connect(self.hash_progress)
        self._hash_service.hash_error.connect(self.hash_error)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def navigator(self) -> FileNavigator:
        return self._navigator

    @property
    def current_path(self) -> str:
        return self._navigator.current_path

    @property
    def current_user(self) -> Optional[str]:
        return self._navigator.current_user

    @property
    def selected_entry(self) -> Optional[FileEntry]:
        return self._selected_entry

    # ------------------------------------------------------------------
    # Read-file pipeline
    # ------------------------------------------------------------------

    def set_read_file_func(self, func: Callable[[str, int, int], Optional[bytes]]):
        """Hot-wire the read-file function after image load."""
        self._read_file = func
        self._hash_service.set_read_file_func(func)
        self._preview_service.set_read_file_func(func)

    def read_file(self, path: str, offset: int, length: int) -> Optional[bytes]:
        """Direct access to the read pipeline (for viewers)."""
        if self._read_file:
            return self._read_file(path, offset, length)
        return None

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def open_folder(self, path: str) -> List[FileEntry]:
        """Navigate into *path* and return sorted children."""
        self._log_coc("DIRECTORY_ENTERED", {"path": path})
        self.status_message.emit(f"Opening {path.rsplit('/', 1)[-1]}…")
        return self._navigator.navigate_to(path)

    def go_back(self) -> Optional[List[FileEntry]]:
        result = self._navigator.go_back()
        if result is not None:
            self._log_coc("NAVIGATE_BACK", {"path": self.current_path})
        return result

    def go_forward(self) -> Optional[List[FileEntry]]:
        result = self._navigator.go_forward()
        if result is not None:
            self._log_coc("NAVIGATE_FORWARD", {"path": self.current_path})
        return result

    def go_up(self) -> Optional[List[FileEntry]]:
        result = self._navigator.go_up()
        if result is not None:
            self._log_coc("NAVIGATE_UP", {"path": self.current_path})
        return result

    def go_root(self) -> List[FileEntry]:
        self._log_coc("NAVIGATE_ROOT", {})
        return self._navigator.go_root()

    def refresh_current(self) -> List[FileEntry]:
        """Re-list the current directory."""
        return self._navigator.navigate_to(self.current_path, add_to_history=False)

    # ------------------------------------------------------------------
    # File selection
    # ------------------------------------------------------------------

    def select_file(self, entry: FileEntry) -> None:
        """
        Called when the user clicks a file in the contents table.
        Triggers preview generation and emits ``file_selected``.
        """
        self._selected_entry = entry
        self.file_selected.emit(entry)

        self._log_coc("FILE_SELECTED", {
            "path": entry.path,
            "type": entry.node_type,
            "size": entry.size,
        })

        # Generate quick preview (async-safe — blocks only very briefly)
        preview = self._preview_service.generate_quick_preview(
            entry.path,
            entry.size,
        )
        if preview:
            self.preview_ready.emit(preview)

    # ------------------------------------------------------------------
    # Double-click dispatch
    # ------------------------------------------------------------------

    def handle_double_click(self, entry: FileEntry) -> str:
        """
        Dispatch a double-click on *entry*.

        Returns:
          ``"navigated"`` if entry is a folder.
          ``"<viewer_type>"`` (e.g. "hex") if it's a file to open.
        """
        if entry.is_directory:
            self.open_folder(entry.path)
            return "navigated"

        viewer = self._preview_service.detect_viewer_type(entry.name, entry.mime_type)
        self._log_coc("FILE_OPENED", {
            "path": entry.path,
            "viewer": viewer,
            "size": entry.size,
        })
        return viewer

    # ------------------------------------------------------------------
    # Viewer type helper
    # ------------------------------------------------------------------

    def get_viewer_type(self, entry: FileEntry) -> str:
        """Return the canonical viewer type for *entry*."""
        # Read first 16 bytes for magic-byte detection (critical for carved files)
        header = None
        if self._read_file and not entry.is_directory:
            try:
                header = self._read_file(entry.path, 0, 16)
            except Exception:
                pass
        return self._preview_service.detect_viewer_type(
            entry.name, entry.mime_type, header_bytes=header,
        )

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def compute_hash(self, path: str, file_size: int) -> None:
        """Request async hash computation for *path*."""
        self._log_coc("HASH_REQUESTED", {"path": path, "size": file_size})
        self._hash_service.compute_hash(path, file_size)

    def get_cached_hash(self, path: str):
        """Return cached (sha256, md5) or None."""
        return self._hash_service.get_cached(path)

    # ------------------------------------------------------------------
    # Export (read-only copy)
    # ------------------------------------------------------------------

    def export_file(self, entry: FileEntry, destination: Path) -> bool:
        """
        Export evidence file to analyst workspace (creates a copy).
        Returns True on success.
        """
        if not self._read_file:
            return False

        try:
            data = self._read_file(entry.path, 0, -1)
            if not data:
                return False

            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)

            self._log_coc("FILE_EXPORTED", {
                "source": entry.path,
                "destination": str(destination),
                "size": len(data),
                "sha256": entry.sha256,
            })
            return True
        except Exception as exc:
            logger.error(f"Export failed for {entry.path}: {exc}")
            return False

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(self, query: str, limit: int = 200) -> List[FileEntry]:
        """Search VFS by name pattern and return FileEntry list."""
        nodes = self._vfs.search(f"*{query}*", limit=limit)
        entries = [FileEntry.from_vfs_node(n) for n in nodes]
        self._log_coc("SEARCH_EXECUTED", {"query": query, "results": len(entries)})
        return sorted(entries, key=lambda e: e.sort_key)

    # ------------------------------------------------------------------
    # VFS statistics
    # ------------------------------------------------------------------

    def get_statistics(self) -> Dict[str, Any]:
        return self._vfs.get_statistics()

    # ------------------------------------------------------------------
    # Write-blocking
    # ------------------------------------------------------------------

    def attempt_write(self, action: str) -> bool:
        """
        Called by the UI when the user attempts a write action.

        Always returns ``False`` and emits ``write_blocked``.
        """
        self.write_blocked.emit(action)
        self._log_coc("WRITE_BLOCKED", {"action": action})
        return False

    # ------------------------------------------------------------------
    # Terminal sync
    # ------------------------------------------------------------------

    def sync_from_terminal(self, terminal_path: str) -> bool:
        """
        Synchronise the file browser to the terminal's ``cd`` path.
        Returns True if the path was found in the VFS.
        """
        terminal_path = terminal_path.replace("\\", "/")
        node = self._vfs.get_node(terminal_path)
        if node:
            self._navigator.navigate_to(terminal_path)
            self._log_coc("TERMINAL_SYNC", {"path": terminal_path})
            return True
        return False

    # ------------------------------------------------------------------
    # Chain of Custody
    # ------------------------------------------------------------------

    def _log_coc(self, action: str, details: Dict):
        if self._coc_logger:
            try:
                self._coc_logger(action, details)
            except Exception as exc:
                logger.warning(f"CoC logging failed: {exc}")
        self.coc_logged.emit(action, details)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup(self):
        self._hash_service.cancel_all()
