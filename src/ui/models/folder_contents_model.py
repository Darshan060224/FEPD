"""
FEPD Folder Contents Model
===========================

``QAbstractTableModel`` that backs the **center panel** of the Files Tab.
Displays the children of the currently-selected folder in a sortable table
with columns: Icon, Name, Size, Type, Date Modified, Hash.

The model operates on ``list[FileEntry]`` — it never touches the database
directly.  The ``FilesController`` feeds it data via ``set_entries()``.
"""

from __future__ import annotations

from typing import List, Optional, Any, Dict

from PyQt6.QtCore import (
    QAbstractTableModel, QModelIndex, Qt, QSortFilterProxyModel,
)
from PyQt6.QtGui import QColor, QFont

from src.models.file_entry import FileEntry


# Column definitions
_COL_ICON = 0
_COL_NAME = 1
_COL_SIZE = 2
_COL_TYPE = 3
_COL_MODIFIED = 4
_COL_HASH = 5

_COLUMN_COUNT = 6

_HEADERS = ["", "Name", "Size", "Type", "Date Modified", "SHA-256"]


# ============================================================================
# TABLE MODEL
# ============================================================================

class FolderContentsModel(QAbstractTableModel):
    """
    Flat table of ``FileEntry`` items for the center panel.

    Supports:
      • Column sorting via ``sort()``
      • Lazy hash display (updated externally via ``update_hash``)
      • Strikethrough + muted colour for deleted files
      • Highlight colour for suspicious files
      • Batch loading for large directories (500 entries at a time)
    """

    BATCH_SIZE = 500  # Load this many entries at a time

    def __init__(self, parent=None):
        super().__init__(parent)
        self._entries: List[FileEntry] = []
        self._all_entries: List[FileEntry] = []  # Full dataset (for pagination)
        self._hash_overrides: Dict[str, str] = {}  # path → sha256 (from HashService)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_entries(self, entries: List[FileEntry]) -> None:
        """Replace the entire dataset with batch loading for large sets."""
        self.beginResetModel()
        self._all_entries = list(entries)
        # Load first batch
        self._entries = self._all_entries[:self.BATCH_SIZE]
        self.endResetModel()

    def load_next_batch(self) -> bool:
        """Load the next batch of entries. Returns True if more entries were loaded."""
        current_count = len(self._entries)
        total_count = len(self._all_entries)
        if current_count >= total_count:
            return False

        next_batch_end = min(current_count + self.BATCH_SIZE, total_count)
        self.beginInsertRows(
            QModelIndex(), current_count, next_batch_end - 1
        )
        self._entries = self._all_entries[:next_batch_end]
        self.endInsertRows()
        return next_batch_end < total_count

    @property
    def has_more(self) -> bool:
        """Check if there are more entries to load."""
        return len(self._entries) < len(self._all_entries)

    @property
    def total_count(self) -> int:
        """Total number of entries (including not-yet-loaded)."""
        return len(self._all_entries)

    def get_entry(self, row: int) -> Optional[FileEntry]:
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None

    def get_entry_by_index(self, index: QModelIndex) -> Optional[FileEntry]:
        if index.isValid():
            return self.get_entry(index.row())
        return None

    def update_hash(self, path: str, sha256: str) -> None:
        """Update the displayed hash for *path* (called by HashService)."""
        self._hash_overrides[path] = sha256
        for row, entry in enumerate(self._entries):
            if entry.path == path:
                idx = self.index(row, _COL_HASH)
                self.dataChanged.emit(idx, idx, [Qt.ItemDataRole.DisplayRole])
                break

    def clear(self) -> None:
        self.beginResetModel()
        self._entries.clear()
        self.endResetModel()

    # ------------------------------------------------------------------
    # QAbstractTableModel overrides
    # ------------------------------------------------------------------

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._entries)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return _COLUMN_COUNT

    def headerData(
        self, section: int, orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(_HEADERS):
                return _HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        entry = self._entries[index.row()]
        col = index.column()

        # ----- Display -----
        if role == Qt.ItemDataRole.DisplayRole:
            if col == _COL_ICON:
                return entry.icon
            if col == _COL_NAME:
                return entry.name
            if col == _COL_SIZE:
                return entry.display_size
            if col == _COL_TYPE:
                return entry.display_type
            if col == _COL_MODIFIED:
                return entry.display_modified
            if col == _COL_HASH:
                # Show override, then entry hash, then "—"
                h = self._hash_overrides.get(entry.path) or entry.sha256
                if h:
                    return f"{h[:16]}…"
                return "—"

        # ----- ToolTip -----
        elif role == Qt.ItemDataRole.ToolTipRole:
            if col == _COL_HASH:
                h = self._hash_overrides.get(entry.path) or entry.sha256
                return h or "Not computed"
            if col == _COL_NAME:
                return entry.path
            return None

        # ----- Foreground colour -----
        elif role == Qt.ItemDataRole.ForegroundRole:
            if entry.is_deleted:
                return QColor("#888888")
            if entry.is_suspicious:
                return QColor("#FF6B6B")
            if col == _COL_HASH:
                return QColor("#888888")
            return None

        # ----- Font -----
        elif role == Qt.ItemDataRole.FontRole:
            if entry.is_deleted:
                font = QFont()
                font.setStrikeOut(True)
                return font
            if entry.is_directory:
                font = QFont()
                font.setBold(True)
                return font
            return None

        # ----- UserRole: raw entry -----
        elif role == Qt.ItemDataRole.UserRole:
            return entry

        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        return base

    # ------------------------------------------------------------------
    # Sorting
    # ------------------------------------------------------------------

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder):
        self.layoutAboutToBeChanged.emit()

        reverse = order == Qt.SortOrder.DescendingOrder

        if column == _COL_NAME:
            key = lambda e: (0 if e.is_directory else 1, e.name.lower())
        elif column == _COL_SIZE:
            key = lambda e: (0 if e.is_directory else 1, e.size)
        elif column == _COL_TYPE:
            key = lambda e: (0 if e.is_directory else 1, e.display_type.lower())
        elif column == _COL_MODIFIED:
            key = lambda e: (0 if e.is_directory else 1, e.modified or "")
        elif column == _COL_HASH:
            key = lambda e: (
                0 if e.is_directory else 1,
                self._hash_overrides.get(e.path, e.sha256 or ""),
            )
        else:
            key = lambda e: e.sort_key

        self._entries.sort(key=key, reverse=reverse)
        self.layoutChanged.emit()


# ============================================================================
# SORT-FILTER PROXY (optional convenience wrapper)
# ============================================================================

class FolderContentsProxyModel(QSortFilterProxyModel):
    """
    Optional proxy for filtering (e.g. show only images, only executables).
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._type_filter: Optional[str] = None  # e.g. "image"
        self._show_deleted: bool = True

    def set_type_filter(self, ext_category: Optional[str]):
        self._type_filter = ext_category
        self.invalidateFilter()

    def set_show_deleted(self, show: bool):
        self._show_deleted = show
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if not isinstance(model, FolderContentsModel):
            return True

        entry = model.get_entry(source_row)
        if entry is None:
            return False

        if not self._show_deleted and entry.is_deleted:
            return False

        if self._type_filter:
            if entry.is_directory:
                return True  # always show folders
            if self._type_filter == "images":
                return entry.extension in (
                    "jpg", "jpeg", "png", "gif", "bmp", "ico", "tiff", "tif", "webp",
                )
            if self._type_filter == "documents":
                return entry.extension in (
                    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
                )
            if self._type_filter == "executables":
                return entry.extension in (
                    "exe", "dll", "sys", "com", "bat", "cmd", "msi", "ps1",
                )
            if self._type_filter == "archives":
                return entry.extension in (
                    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab",
                )

        return True
