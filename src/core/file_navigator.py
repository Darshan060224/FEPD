"""
FEPD File Navigator — Navigation Engine
========================================

Manages path traversal, back/forward history, and directory listing
for the forensic file browser.  Never modifies evidence — read-only
traversal with full Chain of Custody logging.

Architecture:
    FileNavigator
        ├── current_path        (state)
        ├── history stack       (back / forward)
        ├── list_directory()    (folders-first, sorted)
        ├── navigate_to()       (push history, emit signal)
        ├── go_back / go_forward / go_up / go_root
        └── VirtualFilesystem   (data source)
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import List, Optional, Callable, Dict

from PyQt6.QtCore import QObject, pyqtSignal

from src.core.virtual_fs import VirtualFilesystem, VFSNode
from src.models.file_entry import FileEntry

logger = logging.getLogger(__name__)

# Maximum number of entries kept in the back/forward history
_HISTORY_MAX = 100

# Maximum number of directory listings cached
_DIR_CACHE_MAX = 50


class FileNavigator(QObject):
    """
    Core navigation engine for the Files Tab.

    Responsibilities:
      • Track ``current_path``
      • Maintain back / forward history stacks
      • List directory contents (folders first, alphabetically sorted)
      • Emit Qt signals so the UI layer can react

    This class is *stateless* with respect to the UI — it does not reference
    any widget.  Communication is entirely via signals.
    """

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------
    path_changed = pyqtSignal(str)                    # new current path
    directory_loaded = pyqtSignal(list)                # list[FileEntry]
    navigation_state_changed = pyqtSignal(bool, bool)  # can_go_back, can_go_forward
    user_context_changed = pyqtSignal(str)             # detected user name or ""

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------

    def __init__(self, vfs: VirtualFilesystem, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._vfs = vfs
        self._current_path: str = "/"
        self._back_stack: List[str] = []
        self._forward_stack: List[str] = []
        self._current_user: Optional[str] = None
        self._dir_cache: OrderedDict[str, List[FileEntry]] = OrderedDict()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def current_path(self) -> str:
        return self._current_path

    @property
    def current_user(self) -> Optional[str]:
        return self._current_user

    @property
    def can_go_back(self) -> bool:
        return len(self._back_stack) > 0

    @property
    def can_go_forward(self) -> bool:
        return len(self._forward_stack) > 0

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def navigate_to(self, path: str, *, add_to_history: bool = True) -> List[FileEntry]:
        """
        Navigate to *path*, load its children, and emit signals.

        Args:
            path: VFS path (e.g. ``/This PC/C:/Users``)
            add_to_history: If True the previous path is pushed onto the
                back-stack (set False for internal go_back/go_forward calls).

        Returns:
            Sorted list of ``FileEntry`` objects for the target directory.
        """
        if add_to_history and self._current_path and self._current_path != path:
            self._back_stack.append(self._current_path)
            if len(self._back_stack) > _HISTORY_MAX:
                self._back_stack.pop(0)
            # Navigating to a new place clears forward history
            self._forward_stack.clear()

        self._current_path = path

        # List children
        entries = self.list_directory(path)

        # Detect user context
        old_user = self._current_user
        self._current_user = self._detect_user_context(path)
        if self._current_user != old_user:
            self.user_context_changed.emit(self._current_user or "")

        # Emit signals
        self.path_changed.emit(path)
        self.directory_loaded.emit(entries)
        self.navigation_state_changed.emit(self.can_go_back, self.can_go_forward)

        return entries

    def go_back(self) -> Optional[List[FileEntry]]:
        """Go to previous path in history."""
        if not self._back_stack:
            return None
        self._forward_stack.append(self._current_path)
        prev_path = self._back_stack.pop()
        return self.navigate_to(prev_path, add_to_history=False)

    def go_forward(self) -> Optional[List[FileEntry]]:
        """Go to next path in history."""
        if not self._forward_stack:
            return None
        self._back_stack.append(self._current_path)
        next_path = self._forward_stack.pop()
        return self.navigate_to(next_path, add_to_history=False)

    def go_up(self) -> Optional[List[FileEntry]]:
        """Navigate one level up."""
        if not self._current_path or self._current_path == "/":
            return None

        parts = self._current_path.strip("/").split("/")
        if len(parts) <= 1:
            return self.navigate_to("/")

        parent_path = "/" + "/".join(parts[:-1])
        return self.navigate_to(parent_path)

    def go_root(self) -> List[FileEntry]:
        """Navigate to the VFS root."""
        return self.navigate_to("/")

    # ------------------------------------------------------------------
    # Directory listing
    # ------------------------------------------------------------------

    def list_directory(self, path: str) -> List[FileEntry]:
        """
        List directory contents with LRU caching and the standard
        file-manager ordering:
          1. Folders first (sorted A-Z, case-insensitive)
          2. Files second  (sorted A-Z, case-insensitive)

        Results are cached (up to ``_DIR_CACHE_MAX`` directories).
        Call ``invalidate_cache()`` when evidence is reloaded.

        Args:
            path: VFS path to list.

        Returns:
            Sorted ``list[FileEntry]``.
        """
        # Check cache first
        if path in self._dir_cache:
            # Move to end (most recently used)
            self._dir_cache.move_to_end(path)
            return self._dir_cache[path]

        try:
            children: List[VFSNode] = self._vfs.get_children(path)
        except Exception as e:
            logger.error(f"Failed to list directory '{path}': {e}")
            return []

        entries = [FileEntry.from_vfs_node(node) for node in children]

        # Separate, sort, merge
        folders = sorted(
            (e for e in entries if e.is_directory),
            key=lambda e: e.name.lower(),
        )
        files = sorted(
            (e for e in entries if not e.is_directory),
            key=lambda e: e.name.lower(),
        )

        result = folders + files

        # Store in cache
        self._dir_cache[path] = result
        if len(self._dir_cache) > _DIR_CACHE_MAX:
            self._dir_cache.popitem(last=False)  # evict oldest

        return result

    def invalidate_cache(self, path: Optional[str] = None) -> None:
        """Clear directory listing cache. If *path* given, only that entry."""
        if path is None:
            self._dir_cache.clear()
        else:
            self._dir_cache.pop(path, None)

    def get_node(self, path: str) -> Optional[VFSNode]:
        """Get the raw VFSNode for *path* (handy for the controller)."""
        return self._vfs.get_node(path)

    # ------------------------------------------------------------------
    # User context detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_user_context(path: str) -> Optional[str]:
        """Detect if the path is within a user profile folder."""
        if not path:
            return None

        path_lower = path.lower()

        # Windows: …/Users/<username>/…
        if "/users/" in path_lower:
            parts = path.split("/")
            try:
                users_idx = next(
                    i for i, p in enumerate(parts) if p.lower() == "users"
                )
                if users_idx + 1 < len(parts):
                    username = parts[users_idx + 1]
                    if username.lower() not in (
                        "public", "default", "default user", "all users",
                    ):
                        return username
            except StopIteration:
                pass

        # Linux / macOS: …/home/<username>/…
        elif "/home/" in path_lower:
            parts = path.split("/")
            try:
                home_idx = next(
                    i for i, p in enumerate(parts) if p.lower() == "home"
                )
                if home_idx + 1 < len(parts):
                    return parts[home_idx + 1]
            except StopIteration:
                pass

        return None
