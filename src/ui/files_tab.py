"""
FEPD Files Tab — Professional 3-Panel Forensic File Explorer
=============================================================

Industry-grade file browser modeled after Windows Explorer / Autopsy / X-Ways.

Layout:
    ┌──────────────────────────────────────────────────────────────────┐
    │  ← → ↑  │  Breadcrumb Path: C:\\Users\\Alice\\Downloads        │
    ├──────────┼──────────────────────────────────┼───────────────────┤
    │ Folder   │ Folder Contents (Center Table)   │ File Info /       │
    │ Tree     │ ────────────────────────────────  │ Preview           │
    │ (Left)   │ 📁 Reports     —      Folder     │ ───────────       │
    │          │ 📄 notes.txt   1.2 KB  Text      │ Size: 1.2 KB     │
    │ C:\\     │ ⚡ chrome.exe  2.1 MB  Exe       │ Modified: …      │
    │ ├ Users  │ 🖼️ image.jpg  340 KB  JPEG      │ SHA-256: …       │
    │ ├ Windows│                                   │ Hex preview      │
    │ …        │                                   │                   │
    └──────────┴──────────────────────────────────┴───────────────────┘

Navigation Flow:
    Click folder in tree/table → FileNavigator.navigate_to()
        → list_directory() (folders first, sorted A-Z)
        → FolderContentsModel.set_entries()
        → BreadcrumbWidget.set_path()
        → Details panel reset

Forensic Safety:
    • 100 % read-only — no modification, deletion, or rename
    • All actions logged to Chain of Custody
    • Write attempts blocked with clear messaging
    • Complete path synchronisation with FEPD Terminal

Architecture:
    FilesTab (UI)
        │
    FilesController (orchestrator)
        │
    FileNavigator (path traversal + history)
        │
    VirtualFilesystem (SQLite VFS database)
        │
    EvidenceFS (pytsk3 / pyewf low-level reads)

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTreeView, QTableView, QFrame, QLabel,
    QMenu, QMessageBox, QLineEdit, QPushButton,
    QAbstractItemView, QHeaderView, QApplication, QFileDialog,
    QComboBox,
)
from PyQt6.QtCore import (
    Qt, QAbstractItemModel, QModelIndex, pyqtSignal,
    QSize, QTimer, QSortFilterProxyModel,
)
from PyQt6.QtGui import (
    QColor, QFont, QAction, QShortcut, QKeySequence, QPixmap,
)

import sys
sys.path.insert(0, str(__file__).replace("\\", "/").rsplit("/src/", 1)[0])

from src.core.virtual_fs import VirtualFilesystem, VFSNode, VFSNodeType
from src.core.path_sanitizer import safe_path, ForensicIntegrityError
from src.controllers.files_controller import FilesController
from src.models.file_entry import FileEntry
from src.ui.models.folder_contents_model import FolderContentsModel
from src.ui.widgets.breadcrumb_widget import BreadcrumbWidget

logger = logging.getLogger(__name__)


# ============================================================================
# PATH SANITIZATION
# ============================================================================

def _sanitize(path: str, component: str = "files_tab") -> str:
    try:
        return safe_path(path, component)
    except ForensicIntegrityError:
        return "[PATH PROTECTED]"


# ============================================================================
# CONSTANTS
# ============================================================================

WRITE_BLOCK_MESSAGE = (
    "FEPD operates in strict READ-ONLY mode.\n\n"
    "Evidence integrity, chain-of-custody compliance, "
    "and court admissibility require that no modifications "
    "are made to evidence files.\n\n"
    "Use 'Export to Workspace' to create a working copy."
)

WRITE_ACTIONS_BLOCKED = frozenset({
    "delete", "remove", "rename", "move", "cut",
    "modify", "edit", "write", "save", "create",
})

# Tree column widths
_TREE_W_NAME = 260
_TREE_W_SIZE = 80
_TREE_W_TYPE = 100
_TREE_W_MOD = 130

# Perf constants
SEARCH_DEBOUNCE_MS = 300
MAX_STRINGS_DISPLAY = 5000
MAX_FILE_SIZE_STRINGS = 10 * 1024 * 1024
MIN_STRING_LENGTH = 4
HASH_BUFFER_SIZE = 65536


def _block_write(parent: QWidget, action: str = "operation") -> bool:
    QMessageBox.warning(parent, "Forensic Write Block", WRITE_BLOCK_MESSAGE)
    return False


# ============================================================================
# VFS TREE MODEL (left panel)
# ============================================================================

class _VFSTreeModel(QAbstractItemModel):
    """
    Qt item model that exposes the VFS hierarchy in a QTreeView.
    Lazy-loads children on demand for large images.
    """

    def __init__(self, vfs: VirtualFilesystem, parent=None):
        super().__init__(parent)
        self._vfs = vfs
        self._roots: List[VFSNode] = []
        self._children: Dict[str, List[VFSNode]] = {}
        self._cache: Dict[str, VFSNode] = {}
        self.refresh()

    # -- data refresh -------------------------------------------------------

    def refresh(self):
        self.beginResetModel()
        self._roots = self._vfs.get_root_nodes()
        self._children.clear()
        self._cache.clear()
        for n in self._roots:
            self._cache[n.path] = n
        self.endResetModel()

    def _get_children(self, parent_path: str) -> List[VFSNode]:
        if parent_path not in self._children:
            kids = self._vfs.get_children(parent_path)
            self._children[parent_path] = kids
            for k in kids:
                self._cache[k.path] = k
        return self._children[parent_path]

    # -- QAbstractItemModel overrides ----------------------------------------

    def rowCount(self, parent=QModelIndex()):
        if not parent.isValid():
            return len(self._roots)
        node: VFSNode = parent.internalPointer()
        return len(self._get_children(node.path)) if node.is_directory else 0

    def columnCount(self, parent=QModelIndex()):
        return 1  # tree shows only Name column

    def index(self, row, column, parent=QModelIndex()):
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        if not parent.isValid():
            if row < len(self._roots):
                return self.createIndex(row, column, self._roots[row])
        else:
            kids = self._get_children(parent.internalPointer().path)
            if row < len(kids):
                return self.createIndex(row, column, kids[row])
        return QModelIndex()

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()
        node: VFSNode = index.internalPointer()
        if not node.parent_path:
            return QModelIndex()
        pnode = self._cache.get(node.parent_path) or self._vfs.get_node(node.parent_path)
        if not pnode:
            return QModelIndex()
        self._cache[pnode.path] = pnode
        if not pnode.parent_path:
            for i, r in enumerate(self._roots):
                if r.path == pnode.path:
                    return self.createIndex(i, 0, pnode)
            return QModelIndex()
        gp_kids = self._get_children(pnode.parent_path)
        for i, k in enumerate(gp_kids):
            if k.path == pnode.path:
                return self.createIndex(i, 0, pnode)
        return QModelIndex()

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        node: VFSNode = index.internalPointer()
        if role == Qt.ItemDataRole.DisplayRole:
            return f"{self._icon(node)}  {node.name}"
        if role == Qt.ItemDataRole.ToolTipRole:
            return node.path
        if role == Qt.ItemDataRole.UserRole:
            return node
        if role == Qt.ItemDataRole.ForegroundRole:
            if node.is_deleted:
                return QColor("#888")
            if node.node_type == VFSNodeType.SYSTEM:
                return QColor("#888")
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return "Navigation"
        return None

    def hasChildren(self, parent=QModelIndex()):
        if not parent.isValid():
            return bool(self._roots)
        return parent.internalPointer().is_directory

    def canFetchMore(self, parent):
        if not parent.isValid():
            return False
        node = parent.internalPointer()
        return node.is_directory and node.path not in self._children

    def fetchMore(self, parent):
        if parent.isValid():
            self._get_children(parent.internalPointer().path)

    # -- helpers ------------------------------------------------------------

    def node_at(self, index: QModelIndex) -> Optional[VFSNode]:
        return index.internalPointer() if index.isValid() else None

    @staticmethod
    def _icon(node: VFSNode) -> str:
        name_lower = node.name.lower()
        _special = {
            "desktop": "🖥️", "documents": "📄", "downloads": "📥",
            "pictures": "🖼️", "music": "🎵", "videos": "🎬",
            "$recycle.bin": "🗑️", "system volume information": "⚙️",
            "windows": "⚙️", "program files": "📂", "program files (x86)": "📂",
        }
        if name_lower in _special:
            return _special[name_lower]
        _type = {
            VFSNodeType.ROOT: "🖥️", VFSNodeType.DISK: "💽",
            VFSNodeType.PARTITION: "📦", VFSNodeType.DRIVE: "💾",
            VFSNodeType.FOLDER: "📁", VFSNodeType.FILE: "📄",
            VFSNodeType.USER: "👤", VFSNodeType.SYSTEM: "⚙️",
            VFSNodeType.SYMLINK: "🔗", VFSNodeType.DELETED: "🗑️",
        }
        if node.node_type == VFSNodeType.FILE:
            ext = name_lower.rsplit(".", 1)[-1] if "." in name_lower else ""
            _ext = {
                "pdf": "📕", "exe": "⚡", "dll": "⚡",
                "zip": "📦", "rar": "📦", "7z": "📦",
                "jpg": "🖼️", "jpeg": "🖼️", "png": "🖼️", "gif": "🖼️",
                "mp4": "🎬", "avi": "🎬", "mkv": "🎬",
                "mp3": "🎵", "wav": "🎵",
                "doc": "📘", "docx": "📘", "xls": "📊", "xlsx": "📊",
                "pst": "📧", "ost": "📧", "eml": "✉️",
                "evtx": "📋", "reg": "🗝️", "lnk": "🔗",
                "e01": "💿", "mem": "🧠", "dmp": "🧠",
                "py": "💻", "js": "💻", "txt": "📝", "log": "📝",
                "db": "🗃️", "sqlite": "🗃️",
            }
            return _ext.get(ext, "📄")
        return _type.get(node.node_type, "📄")


# ============================================================================
# DETAILS / PREVIEW PANEL (right panel)
# ============================================================================

class _DetailsPanel(QFrame):
    """Right-side panel showing file metadata + quick preview."""

    hash_requested = pyqtSignal(str, int)   # path, size

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("_DetailsPanel { background: #252525; border-left: 1px solid #3d3d3d; }")
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(6)

        self._icon = QLabel("📁")
        self._icon.setStyleSheet("font-size: 48px;")
        self._icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self._icon)

        self._name = QLabel("Select a file")
        self._name.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        self._name.setStyleSheet("color: #e0e0e0;")
        self._name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._name.setWordWrap(True)
        lay.addWidget(self._name)

        self._type = QLabel("")
        self._type.setStyleSheet("color: #888; font-size: 11px;")
        self._type.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self._type)

        lay.addSpacing(10)

        # Properties
        self._props: Dict[str, QLabel] = {}
        for key in ("Size", "Created", "Modified", "Accessed", "Location",
                     "SHA-256", "MD5", "MIME Type", "Evidence", "Partition", "Inode"):
            row = QHBoxLayout()
            lbl = QLabel(f"{key}:")
            lbl.setStyleSheet("color: #888; font-size: 11px; min-width: 65px;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
            val = QLabel("—")
            val.setStyleSheet("color: #d4d4d4; font-size: 11px;")
            val.setWordWrap(True)
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            row.addWidget(lbl)
            row.addWidget(val, 1)
            lay.addLayout(row)
            self._props[key] = val

        lay.addSpacing(8)

        # Hash button
        self._btn_hash = QPushButton("Compute SHA-256")
        self._btn_hash.setStyleSheet(
            "QPushButton { background: #1565c0; color: white; font-weight: bold; "
            "padding: 6px 12px; border-radius: 4px; font-size: 11px; }"
            "QPushButton:hover { background: #1976d2; }"
        )
        self._btn_hash.clicked.connect(self._req_hash)
        lay.addWidget(self._btn_hash)

        lay.addSpacing(8)

        # Quick preview area
        self._preview_title = QLabel("Preview")
        self._preview_title.setStyleSheet("color: #888; font-size: 11px; font-weight: bold;")
        lay.addWidget(self._preview_title)

        self._preview = QLabel("")
        self._preview.setStyleSheet(
            "background: #1e1e1e; color: #c0c0c0; font-family: 'Consolas', monospace; "
            "font-size: 10px; padding: 6px; border: 1px solid #333; border-radius: 3px;"
        )
        self._preview.setWordWrap(True)
        self._preview.setMinimumHeight(80)
        self._preview.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self._preview, 1)

        # Activities section — shows forensic artifact correlation
        self._activities_title = QLabel("Activities")
        self._activities_title.setStyleSheet("color: #888; font-size: 11px; font-weight: bold;")
        lay.addWidget(self._activities_title)

        self._activities = QLabel("")
        self._activities.setStyleSheet(
            "background: #1e1e1e; color: #c0c0c0; font-family: 'Consolas', monospace; "
            "font-size: 10px; padding: 6px; border: 1px solid #333; border-radius: 3px;"
        )
        self._activities.setWordWrap(True)
        self._activities.setMinimumHeight(60)
        self._activities.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self._activities, 1)

        # MACB Timeline section — timestamp analysis
        self._macb_title = QLabel("MACB Timeline")
        self._macb_title.setStyleSheet("color: #ff9800; font-size: 11px; font-weight: bold;")
        lay.addWidget(self._macb_title)

        self._macb = QLabel("")
        self._macb.setStyleSheet(
            "background: #1a1a1a; color: #c0c0c0; font-family: 'Consolas', monospace; "
            "font-size: 10px; padding: 6px; border: 1px solid #333; border-radius: 3px;"
        )
        self._macb.setWordWrap(True)
        self._macb.setMinimumHeight(50)
        self._macb.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self._macb, 1)

        # File Intelligence section — forensic file analysis
        self._intel_title = QLabel("File Intelligence")
        self._intel_title.setStyleSheet("color: #4fc3f7; font-size: 11px; font-weight: bold;")
        lay.addWidget(self._intel_title)

        self._intel = QLabel("")
        self._intel.setStyleSheet(
            "background: #1a1a2e; color: #c0c0c0; font-family: 'Consolas', monospace; "
            "font-size: 10px; padding: 6px; border: 1px solid #333; border-radius: 3px;"
        )
        self._intel.setWordWrap(True)
        self._intel.setMinimumHeight(50)
        self._intel.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self._intel, 1)

        self._current_path: Optional[str] = None
        self._current_size: int = 0

    # -- public API --

    def show_entry(self, entry: FileEntry) -> None:
        self._current_path = entry.path
        self._current_size = entry.size
        self._icon.setText(entry.icon)
        self._name.setText(entry.name)
        self._type.setText(entry.display_type)
        self._props["Size"].setText(
            f"{entry.display_size}  ({entry.size:,} bytes)" if entry.size else "—"
        )
        self._props["Created"].setText(entry.display_created)
        self._props["Modified"].setText(entry.display_modified_full)
        self._props["Accessed"].setText(entry.display_accessed)
        self._props["Location"].setText(_sanitize(entry.path))
        self._props["SHA-256"].setText(entry.sha256[:24] + "…" if entry.sha256 else "—")
        if entry.sha256:
            self._props["SHA-256"].setToolTip(entry.sha256)
        self._props["MD5"].setText(entry.md5[:24] + "…" if entry.md5 else "—")
        if entry.md5:
            self._props["MD5"].setToolTip(entry.md5)
        self._props["MIME Type"].setText(entry.mime_type or "—")
        self._props["Evidence"].setText(entry.evidence_id or "—")
        self._props["Partition"].setText(entry.partition_info or "—")
        self._props["Inode"].setText(str(entry.inode) if entry.inode else "—")
        self._btn_hash.setVisible(not entry.is_directory)

        # Populate activities from artifact correlation
        self._show_activities(entry)

        # Populate MACB timeline
        self._show_macb(entry)

        # Populate file intelligence
        self._show_intelligence(entry)

    def show_preview(self, preview_data: Dict) -> None:
        ptype = preview_data.get("type", "none")
        data = preview_data.get("data", "")
        if ptype == "text":
            self._preview.setPixmap(QPixmap())  # clear any previous image
            self._preview.setText(data[:2000])
        elif ptype == "hex":
            self._preview.setPixmap(QPixmap())
            self._preview.setText(data[:2000])
        elif ptype == "image_thumb":
            # data is a QPixmap thumbnail from the robust decoder
            if hasattr(data, "isNull") and not data.isNull():
                scaled = data.scaled(
                    self._preview.width() - 12,
                    max(self._preview.height() - 12, 120),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
                self._preview.setPixmap(scaled)
            else:
                # Image decode failed → show hex fallback
                self._preview.setPixmap(QPixmap())
                self._preview.setText("⚠ Image could not be decoded — showing hex:\n\n"
                                       "(Select file and press Ctrl+H for full hex view)")
        elif ptype == "image_bytes":
            # Legacy path: raw bytes — try quick decode for thumbnail
            try:
                from src.ui.viewers.image_viewer import generate_thumbnail
                thumb = generate_thumbnail(data, 200)
                if thumb and not thumb.isNull():
                    scaled = thumb.scaled(
                        self._preview.width() - 12,
                        max(self._preview.height() - 12, 120),
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                    self._preview.setPixmap(scaled)
                else:
                    # Decode failed → hex fallback
                    self._preview.setPixmap(QPixmap())
                    self._preview.setText("⚠ Image could not be decoded — use Ctrl+H for hex view")
            except Exception:
                self._preview.setPixmap(QPixmap())
                self._preview.setText("[Image preview — open in viewer]")
        else:
            self._preview.setPixmap(QPixmap())
            self._preview.setText(str(data) if data else "No preview available")

    def update_hash(self, sha256: str, md5: str) -> None:
        self._props["SHA-256"].setText(sha256[:24] + "…")
        self._props["SHA-256"].setToolTip(f"SHA-256: {sha256}\nMD5: {md5}")
        self._props["MD5"].setText(md5[:24] + "…" if md5 else "—")
        if md5:
            self._props["MD5"].setToolTip(md5)

    def clear(self) -> None:
        self._icon.setText("📁")
        self._name.setText("Select a file")
        self._type.setText("")
        for v in self._props.values():
            v.setText("—")
        self._preview.setPixmap(QPixmap())
        self._preview.setText("")
        self._activities.setText("")
        self._macb.setText("")
        self._intel.setText("")
        self._btn_hash.setVisible(False)
        self._current_path = None

    def _req_hash(self):
        if self._current_path:
            self.hash_requested.emit(self._current_path, self._current_size)

    def _show_activities(self, entry: FileEntry) -> None:
        """Show forensic artifact activities correlated with this file."""
        if entry.is_directory:
            self._activities.setText("")
            return

        activities = []
        name_lower = entry.name.lower()
        ext = entry.extension

        # Timeline artifacts from timestamps
        if entry.created:
            activities.append(f"📅 {entry.display_created[:16]}  File Created  (MFT)")
        if entry.modified:
            activities.append(f"📅 {entry.display_modified_full[:16]}  File Modified  (MFT)")
        if entry.accessed:
            activities.append(f"📅 {entry.display_accessed[:16]}  File Accessed  (MFT)")

        # Execution artifacts for executables
        if ext in ("exe", "dll", "bat", "cmd", "ps1", "msi", "com", "scr", "vbs"):
            activities.append(f"⚡ Executable type: {entry.display_type}")
            path_lower = entry.path.lower()
            if "/prefetch/" in path_lower:
                activities.append("🔄 Referenced in Prefetch (execution evidence)")
            if "/downloads/" in path_lower or "/desktop/" in path_lower:
                activities.append("⚠ Located in user download/desktop area")
            if entry.is_suspicious:
                activities.append("🚨 Flagged as suspicious (double extension or user-area executable)")

        # Deleted file activity
        if entry.is_deleted:
            activities.append("🗑️ File was DELETED (recovered from unallocated)")

        # Registry artifacts
        if ext in ("reg", "hiv"):
            activities.append("🗝️ Registry data — may contain persistence keys")

        # Email artifacts
        if ext in ("pst", "ost", "eml", "msg", "mbox"):
            activities.append("📧 Email artifact — may contain communications")

        # Event log artifacts
        if ext in ("evtx", "evt", "etl"):
            activities.append("📋 Event log — contains system/security events")

        # Browser data
        if "history" in name_lower or "cookies" in name_lower or "cache" in name_lower:
            activities.append("🌐 Browser artifact — web activity evidence")

        # Shortcut (LNK) files
        if ext == "lnk":
            activities.append("🔗 Shortcut file — indicates file/program access")

        # Prefetch files
        if ext == "pf":
            activities.append("🔄 Prefetch file — program execution evidence")

        # Database files
        if ext in ("db", "sqlite", "sqlite3"):
            activities.append("🗃️ Database file — may contain structured evidence")

        if not activities:
            self._activities.setText("No correlated activities found")
        else:
            self._activities.setText("\n".join(activities))

    def _show_macb(self, entry: FileEntry) -> None:
        """Show MACB (Modified/Accessed/Changed/Born) timeline for the file."""
        if entry.is_directory:
            self._macb.setText("")
            return

        lines = []
        macb = ""

        # Modified
        if entry.modified:
            lines.append(f"M  Modified:  {entry.display_modified_full}")
            macb += "M"
        else:
            macb += "."

        # Accessed
        if entry.accessed:
            lines.append(f"A  Accessed:  {entry.display_accessed}")
            macb += "A"
        else:
            macb += "."

        # Changed (use metadata change if available, else modified)
        changed = entry.metadata.get("changed") or entry.metadata.get("mft_modified")
        if changed:
            lines.append(f"C  Changed:   {changed}")
            macb += "C"
        else:
            macb += "."

        # Born (Created)
        if entry.created:
            lines.append(f"B  Created:   {entry.display_created}")
            macb += "B"
        else:
            macb += "."

        # Add MACB flags summary
        lines.insert(0, f"Flags: [{macb}]")

        # Timestamp anomaly detection
        if entry.created and entry.modified:
            try:
                from datetime import datetime
                c = datetime.fromisoformat(str(entry.created))
                m = datetime.fromisoformat(str(entry.modified))
                if m < c:
                    lines.append("⚠ ANOMALY: Modified before Created (timestomping?)")
            except Exception:
                pass

        self._macb.setText("\n".join(lines))

    def _show_intelligence(self, entry: FileEntry) -> None:
        """Show forensic file intelligence for the selected file."""
        if entry.is_directory:
            self._intel.setText("")
            return

        lines = []
        ext = entry.extension.lower() if entry.extension else ""
        lines.append(f"File Type:  {entry.display_type}")
        lines.append(f"Extension:  .{ext}" if ext else "Extension:  (none)")
        lines.append(f"True Type:  {entry.mime_type or 'Unknown'}")

        # ML risk score
        ml_score = entry.metadata.get("ml_score")
        if ml_score is not None and isinstance(ml_score, (int, float)):
            lines.append(f"Risk Score: {ml_score:.2f}")
        else:
            lines.append("Risk Score: —")

        # Source information
        if entry.evidence_id:
            lines.append(f"Source:     {entry.evidence_id}")
        if not entry.is_allocated:
            lines.append("Extracted:  Unallocated space (carved)")
        elif entry.is_deleted:
            lines.append("Extracted:  Deleted file recovery")
        else:
            lines.append("Extracted:  Allocated file")

        # Owner
        owner = entry.metadata.get("owner")
        if owner:
            lines.append(f"Owner:      {owner}")

        # Flags
        flags = []
        if entry.is_suspicious:
            flags.append("Suspicious")
        if entry.is_deleted:
            flags.append("Deleted")
        if ext in ("exe", "dll", "bat", "cmd", "ps1", "vbs", "scr", "com", "msi"):
            flags.append("Executable")
        if ml_score and isinstance(ml_score, (int, float)) and ml_score > 0.7:
            flags.append("High Risk")
        if flags:
            lines.append(f"Flags:      ⚠ {', '.join(flags)}")

        self._intel.setText("\n".join(lines))


# ============================================================================
# FILES TAB (main widget)
# ============================================================================

class FilesTab(QWidget):
    """
    TAB 3: FILES — Professional 3-panel forensic file explorer.

    Panels:
        Left   — Folder hierarchy tree (QTreeView + _VFSTreeModel)
        Center — Contents of selected folder (QTableView + FolderContentsModel)
        Right  — File metadata + preview (_DetailsPanel)

    Navigation Engine:
        All navigation is delegated to ``FilesController`` which owns
        ``FileNavigator``, ``HashService`` and ``PreviewService``.
        The UI never touches VFS directly for navigation.

    Signals:
        file_opened(str, str)       — path, viewer type
        node_selected(object)       — VFSNode / FileEntry
        path_changed(str)           — current path (for terminal sync)
        user_context_changed(str)   — detected user profile name
        terminal_command(str)       — command to execute in terminal
        write_blocked(str)          — blocked write action
    """

    file_opened          = pyqtSignal(str, str)
    node_selected        = pyqtSignal(object)
    path_changed         = pyqtSignal(str)
    user_context_changed = pyqtSignal(str)
    terminal_command     = pyqtSignal(str)
    write_blocked        = pyqtSignal(str)

    def __init__(
        self,
        vfs: VirtualFilesystem,
        read_file_func: Optional[Callable[[str, int, int], bytes]] = None,
        coc_logger: Optional[Callable[[str, Dict], None]] = None,
        parent=None,
    ):
        super().__init__(parent)
        self.vfs = vfs
        self.read_file_func = read_file_func
        self.coc_logger = coc_logger

        # Controller — single orchestrator the UI talks to
        self.controller = FilesController(
            vfs=vfs,
            read_file_func=read_file_func,
            coc_logger=coc_logger,
            parent=self,
        )

        # Models
        self._tree_model = _VFSTreeModel(vfs, parent=self)
        self._contents_model = FolderContentsModel(parent=self)

        self._viewers: Dict[str, Any] = {}
        self._search_timer = QTimer()
        self._search_timer.setSingleShot(True)
        self._search_timer.timeout.connect(self._execute_search)

        self._setup_ui()
        self._connect_signals()
        self._setup_shortcuts()
        self._auto_expand()

    # =====================================================================
    # UI CONSTRUCTION
    # =====================================================================

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Toolbar ──────────────────────────────────────────────────────
        toolbar = QFrame()
        toolbar.setStyleSheet(
            "QFrame { background: #2d2d30; border-bottom: 1px solid #3e3e42; }"
        )
        tb = QHBoxLayout(toolbar)
        tb.setContentsMargins(8, 6, 8, 6)
        tb.setSpacing(4)

        self.btn_back = self._nav_button("←", "Back (Alt+Left)")
        self.btn_fwd  = self._nav_button("→", "Forward (Alt+Right)")
        self.btn_up   = self._nav_button("↑", "Up one level (Alt+Up)")
        self.btn_back.setEnabled(False)
        self.btn_fwd.setEnabled(False)
        tb.addWidget(self.btn_back)
        tb.addWidget(self.btn_fwd)
        tb.addWidget(self.btn_up)

        sep = QLabel("|")
        sep.setStyleSheet("color: #555; padding: 0 4px;")
        tb.addWidget(sep)

        # Breadcrumb widget (clickable segments)
        self.breadcrumb = BreadcrumbWidget()
        tb.addWidget(self.breadcrumb, 1)

        # Search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍 Search files…")
        self.search_box.setFixedWidth(200)
        self.search_box.setStyleSheet(
            "QLineEdit { background: #1e1e1e; border: 1px solid #3e3e42; "
            "border-radius: 2px; padding: 4px 8px; color: #fff; font-size: 12px; }"
            "QLineEdit:focus { border-color: #0078d4; }"
        )
        self.search_box.textChanged.connect(self._on_search_changed)
        self.search_box.returnPressed.connect(self._execute_search)
        tb.addWidget(self.search_box)

        root.addWidget(toolbar)

        # ── Ribbon (sort / stats / filter) ───────────────────────────────
        ribbon = QFrame()
        ribbon.setStyleSheet(
            "QFrame { background: #252526; border-bottom: 1px solid #3e3e42; }"
        )
        rb = QHBoxLayout(ribbon)
        rb.setContentsMargins(12, 4, 12, 4)
        rb.setSpacing(12)

        rb.addWidget(QLabel("Sort:"))
        self.sort_combo = QComboBox()
        self.sort_combo.addItems([
            "Name ↑", "Name ↓", "Size ↑", "Size ↓",
            "Date ↑", "Date ↓", "Type ↑", "Type ↓",
        ])
        self.sort_combo.setStyleSheet(
            "QComboBox { background: #2a2a2a; color: #e0e0e0; border: 1px solid #3e3e42; "
            "border-radius: 2px; padding: 3px 8px; font-size: 11px; }"
        )
        self.sort_combo.currentTextChanged.connect(self._on_sort_changed)
        rb.addWidget(self.sort_combo)

        # Filter combo
        rb.addWidget(QLabel("Filter:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "All Files", "Images", "Documents", "Executables", "Archives",
        ])
        self.filter_combo.setStyleSheet(self.sort_combo.styleSheet())
        self.filter_combo.currentTextChanged.connect(self._on_filter_changed)
        rb.addWidget(self.filter_combo)

        self.stats_label = QLabel("")
        self.stats_label.setStyleSheet("color: #888; font-size: 11px;")
        rb.addWidget(self.stats_label)

        self.loading_label = QLabel("")
        self.loading_label.setStyleSheet("color: #4fc3f7; font-size: 11px; font-weight: bold;")
        self.loading_label.setVisible(False)
        rb.addWidget(self.loading_label)

        rb.addStretch()

        self.user_label = QLabel("")
        self.user_label.setStyleSheet("color: #888; font-size: 11px;")
        rb.addWidget(self.user_label)

        for lbl in rb.parentWidget().findChildren(QLabel):
            if lbl.text() in ("Sort:", "Filter:"):
                lbl.setStyleSheet("color: #888; font-size: 11px;")

        root.addWidget(ribbon)

        # ── 3-Panel Splitter ─────────────────────────────────────────────
        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # LEFT — Folder tree
        tree_frame = QFrame()
        tree_frame.setStyleSheet(
            "QFrame { background: #252526; border-right: 1px solid #3e3e42; }"
        )
        tl = QVBoxLayout(tree_frame)
        tl.setContentsMargins(0, 0, 0, 0)

        self.tree_view = QTreeView()
        self.tree_view.setModel(self._tree_model)
        self.tree_view.setHeaderHidden(False)
        self.tree_view.setAnimated(True)
        self.tree_view.setIndentation(20)
        self.tree_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_view.setStyleSheet(self._tree_style())
        tl.addWidget(self.tree_view)
        main_splitter.addWidget(tree_frame)

        # CENTER — Folder contents table
        center_frame = QFrame()
        center_frame.setStyleSheet("QFrame { background: #1e1e1e; }")
        cl = QVBoxLayout(center_frame)
        cl.setContentsMargins(0, 0, 0, 0)

        self.contents_view = QTableView()
        self.contents_view.setModel(self._contents_model)
        self.contents_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.contents_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.contents_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.contents_view.setSortingEnabled(True)
        self.contents_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.contents_view.verticalHeader().setVisible(False)
        hdr = self.contents_view.horizontalHeader()
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # Name stretches
        hdr.setDefaultSectionSize(90)
        self.contents_view.setStyleSheet(self._table_style())
        cl.addWidget(self.contents_view)
        main_splitter.addWidget(center_frame)

        # RIGHT — Details / preview
        self.details_panel = _DetailsPanel()
        self.details_panel.setMinimumWidth(240)
        self.details_panel.setMaximumWidth(360)
        main_splitter.addWidget(self.details_panel)

        main_splitter.setSizes([220, 500, 280])
        root.addWidget(main_splitter, 1)

        # ── Status bar ───────────────────────────────────────────────────
        status = QFrame()
        status.setStyleSheet(
            "QFrame { background: #2d2d30; border-top: 1px solid #3e3e42; }"
        )
        sb = QHBoxLayout(status)
        sb.setContentsMargins(12, 3, 12, 3)

        self.status_items = QLabel("")
        self.status_items.setStyleSheet("color: #888; font-size: 11px;")
        sb.addWidget(self.status_items)

        # Forensic file statistics
        self.status_deleted = QLabel("")
        self.status_deleted.setStyleSheet("color: #f44336; font-size: 10px;")
        sb.addWidget(self.status_deleted)

        self.status_executables = QLabel("")
        self.status_executables.setStyleSheet("color: #ff9800; font-size: 10px;")
        sb.addWidget(self.status_executables)

        self.status_suspicious = QLabel("")
        self.status_suspicious.setStyleSheet("color: #e91e63; font-size: 10px; font-weight: bold;")
        sb.addWidget(self.status_suspicious)

        sb.addStretch()
        self.status_ro = QLabel("🔒 Evidence is read-only — forensic integrity protected")
        self.status_ro.setStyleSheet("color: #4caf50; font-size: 10px; font-weight: bold;")
        sb.addWidget(self.status_ro)

        root.addWidget(status)

    # =====================================================================
    # SIGNAL WIRING
    # =====================================================================

    def _connect_signals(self):
        # --- Navigation buttons ---
        self.btn_back.clicked.connect(self._on_back)
        self.btn_fwd.clicked.connect(self._on_forward)
        self.btn_up.clicked.connect(self._on_up)

        # --- Tree view ---
        self.tree_view.clicked.connect(self._on_tree_clicked)
        self.tree_view.doubleClicked.connect(self._on_tree_double_clicked)
        self.tree_view.customContextMenuRequested.connect(self._show_tree_ctx_menu)

        # --- Contents view ---
        self.contents_view.clicked.connect(self._on_contents_clicked)
        self.contents_view.doubleClicked.connect(self._on_contents_double_clicked)
        self.contents_view.customContextMenuRequested.connect(self._show_contents_ctx_menu)

        # --- Lazy loading on scroll ---
        vbar = self.contents_view.verticalScrollBar()
        if vbar:
            vbar.valueChanged.connect(self._on_scroll_near_end)

        # --- Breadcrumb ---
        self.breadcrumb.segment_clicked.connect(self._on_breadcrumb_segment)
        self.breadcrumb.path_edited.connect(self._on_breadcrumb_edit)

        # --- Controller signals ---
        self.controller.directory_loaded.connect(self._on_directory_loaded)
        self.controller.file_selected.connect(self._on_file_selected)
        self.controller.path_changed.connect(self._on_path_changed)
        self.controller.navigation_state_changed.connect(self._on_nav_state)
        self.controller.user_context_changed.connect(self._on_user_changed)
        self.controller.preview_ready.connect(self._on_preview_ready)
        self.controller.hash_computed.connect(self._on_hash_computed)
        self.controller.write_blocked.connect(self._on_write_blocked)

        # --- Details panel hash request ---
        self.details_panel.hash_requested.connect(
            lambda p, s: self.controller.compute_hash(p, s)
        )

    # =====================================================================
    # NAVIGATION HANDLERS (delegate to controller)
    # =====================================================================

    def _on_back(self):
        self.controller.go_back()

    def _on_forward(self):
        self.controller.go_forward()

    def _on_up(self):
        self.controller.go_up()

    def _on_breadcrumb_segment(self, path: str):
        self.controller.open_folder(path)

    def _on_breadcrumb_edit(self, path: str):
        self.controller.open_folder(path)

    # --- Tree interactions (LEFT PANEL) ---

    def _on_tree_clicked(self, index: QModelIndex):
        """Single click in tree → load folder contents in center panel."""
        node = self._tree_model.node_at(index)
        if not node:
            return
        if node.is_directory:
            self.controller.open_folder(node.path)
        else:
            entry = FileEntry.from_vfs_node(node)
            self.controller.select_file(entry)

    def _on_tree_double_clicked(self, index: QModelIndex):
        """Double click in tree → expand/collapse AND navigate."""
        node = self._tree_model.node_at(index)
        if not node:
            return
        if node.is_directory:
            if self.tree_view.isExpanded(index):
                self.tree_view.collapse(index)
            else:
                self.tree_view.expand(index)
            self.controller.open_folder(node.path)
            self.terminal_command.emit(f"cd {node.path}")
        else:
            self._open_file_entry(FileEntry.from_vfs_node(node))

    # --- Contents interactions (CENTER PANEL) ---

    def _on_contents_clicked(self, index: QModelIndex):
        """Single click in contents → show details + preview in right panel."""
        entry = self._contents_model.get_entry(index.row())
        if entry:
            self.controller.select_file(entry)

    def _on_contents_double_clicked(self, index: QModelIndex):
        """Double click in contents → folder=navigate, file=open viewer."""
        entry = self._contents_model.get_entry(index.row())
        if not entry:
            return
        result = self.controller.handle_double_click(entry)
        if result == "navigated":
            # Also expand the tree to match
            self._expand_tree_to(entry.path)
            self.terminal_command.emit(f"cd {entry.path}")
        else:
            self._open_file_entry(entry)

    # =====================================================================
    # CONTROLLER SIGNAL HANDLERS
    # =====================================================================

    def _on_directory_loaded(self, entries: List[FileEntry]):
        """Controller loaded a directory → update center panel."""
        self._contents_model.set_entries(entries)
        folders = sum(1 for e in entries if e.is_directory)
        files = len(entries) - folders
        self.stats_label.setText(f"{folders} folders, {files} files")
        total = self._contents_model.total_count
        loaded = self._contents_model.rowCount()
        if total > loaded:
            self.status_items.setText(f"{loaded} of {total} items loaded")
        else:
            self.status_items.setText(f"{total} items")

        # Forensic file statistics
        _exe_exts = {"exe", "dll", "bat", "cmd", "ps1", "vbs", "scr", "com", "msi"}
        deleted = sum(1 for e in entries if e.is_deleted)
        execs = sum(1 for e in entries if not e.is_directory and e.extension in _exe_exts)
        suspicious = sum(1 for e in entries if e.is_suspicious)

        self.status_deleted.setText(f"🗑️ {deleted} deleted" if deleted else "")
        self.status_executables.setText(f"⚡ {execs} executables" if execs else "")
        self.status_suspicious.setText(f"🚨 {suspicious} suspicious" if suspicious else "")

        self.details_panel.clear()

    def _on_scroll_near_end(self, value: int):
        """Load more entries when scroll nears the bottom."""
        vbar = self.contents_view.verticalScrollBar()
        if vbar and value >= vbar.maximum() - 50:
            if self._contents_model.load_next_batch():
                total = self._contents_model.total_count
                loaded = self._contents_model.rowCount()
                if total > loaded:
                    self.status_items.setText(f"{loaded} of {total} items loaded")
                else:
                    self.status_items.setText(f"{total} items")

    def _on_path_changed(self, path: str):
        """Controller path changed → update breadcrumb + emit signal."""
        self.breadcrumb.set_path(path)
        self.path_changed.emit(path)

    def _on_nav_state(self, can_back: bool, can_fwd: bool):
        self.btn_back.setEnabled(can_back)
        self.btn_fwd.setEnabled(can_fwd)

    def _on_user_changed(self, username: str):
        if username:
            self.user_label.setText(f"👤 {username}")
            self.user_label.setVisible(True)
        else:
            self.user_label.setText("")
            self.user_label.setVisible(False)
        self.user_context_changed.emit(username)

    def _on_preview_ready(self, preview: dict):
        self.details_panel.show_preview(preview)

    def _on_hash_computed(self, path: str, sha256: str, md5: str):
        self._contents_model.update_hash(path, sha256)
        self.details_panel.update_hash(sha256, md5)

    def _on_write_blocked(self, action: str):
        self.write_blocked.emit(action)
        _block_write(self, action)

    # =====================================================================
    # FILE SELECTION + PREVIEW
    # =====================================================================

    def _on_file_selected(self, entry: FileEntry):
        """Show entry details in right panel."""
        self.details_panel.show_entry(entry)
        self.node_selected.emit(entry)

    # =====================================================================
    # FILE OPENING (viewers)
    # =====================================================================

    def _open_file_entry(self, entry: FileEntry):
        """Open a file with the correct viewer."""
        viewer_type = self.controller.get_viewer_type(entry)
        try:
            from src.ui.viewers import (
                TextViewer, HexViewer, ImageViewer, PDFViewer, VideoViewer,
            )
            viewers = {
                "text": TextViewer, "hex": HexViewer,
                "image": ImageViewer, "pdf": PDFViewer, "video": VideoViewer,
            }
            ViewerClass = viewers.get(viewer_type, TextViewer)
            viewer = ViewerClass(read_file_func=self.read_file_func)

            data = None
            if self.read_file_func:
                try:
                    data = self.read_file_func(entry.path, 0, -1)
                except Exception as exc:
                    logger.error("Read failed: %s", exc)

            viewer.load_file(entry.path, data)
            viewer.setWindowTitle(f"{entry.name} — FEPD Viewer")
            viewer.resize(800, 600)
            viewer.show()
            self._viewers[entry.path] = viewer
            self.file_opened.emit(entry.path, viewer_type)

        except ImportError:
            QMessageBox.information(
                self, "Viewer Not Available",
                f"No viewer found for type '{viewer_type}'.\n"
                "Open in hex viewer instead.",
            )

    # =====================================================================
    # CONTEXT MENUS
    # =====================================================================

    def _show_tree_ctx_menu(self, pos):
        idx = self.tree_view.indexAt(pos)
        node = self._tree_model.node_at(idx)
        if node:
            self._show_ctx_menu(
                FileEntry.from_vfs_node(node),
                self.tree_view.viewport().mapToGlobal(pos),
            )

    def _show_contents_ctx_menu(self, pos):
        idx = self.contents_view.indexAt(pos)
        entry = self._contents_model.get_entry(idx.row()) if idx.isValid() else None
        if entry:
            self._show_ctx_menu(entry, self.contents_view.viewport().mapToGlobal(pos))

    def _show_ctx_menu(self, entry: FileEntry, global_pos):
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background: #252525; color: #e0e0e0; border: 1px solid #3d3d3d; padding: 4px; }"
            "QMenu::item { padding: 8px 24px; }"
            "QMenu::item:selected { background: #094771; }"
            "QMenu::item:disabled { color: #666; }"
            "QMenu::separator { height: 1px; background: #3d3d3d; margin: 4px 0; }"
        )

        if entry.is_directory:
            a = menu.addAction("📂 Open Folder")
            a.triggered.connect(lambda: self.controller.open_folder(entry.path))
        else:
            a = menu.addAction("📄 Open (Safe Viewer)")
            a.triggered.connect(lambda: self._open_file_entry(entry))
            menu.addSeparator()
            for label, vtype in [("📝 Text View", "text"), ("🔢 Hex View", "hex")]:
                act = menu.addAction(label)
                act.triggered.connect(lambda _, t=vtype: self._open_with_type(entry, t))
            act_str = menu.addAction("🔤 Strings Extract")
            act_str.triggered.connect(lambda: self._extract_strings(entry))
            menu.addSeparator()
            act_hash = menu.addAction("🔐 Compute SHA-256")
            act_hash.triggered.connect(
                lambda: self.controller.compute_hash(entry.path, entry.size)
            )

        menu.addSeparator()
        a_detail = menu.addAction("ℹ️ Properties")
        a_detail.triggered.connect(lambda: self._show_properties(entry))

        if not entry.is_directory:
            menu.addSeparator()
            a_tl = menu.addAction("📅 Jump to Timeline")
            a_tl.triggered.connect(
                lambda: self.terminal_command.emit(f"timeline {entry.path}")
            )
            a_exp = menu.addAction("📤 Export to Workspace")
            a_exp.triggered.connect(lambda: self._export_file(entry))

            # ── Forensic analysis actions ────────────────────────
            menu.addSeparator()
            a_ml = menu.addAction("🤖 Send to ML Analysis")
            a_ml.triggered.connect(lambda: self._send_to_ml(entry))
            a_tag = menu.addAction("🏷️ Tag as Evidence")
            a_tag.triggered.connect(lambda: self._tag_as_evidence(entry))
            a_note = menu.addAction("📝 Add Investigator Note")
            a_note.triggered.connect(lambda: self._add_file_note(entry))
            a_copy = menu.addAction("📋 Copy Path")
            a_copy.triggered.connect(lambda: self._copy_path(entry))
            a_copy_hash = menu.addAction("📋 Copy Hash")
            a_copy_hash.triggered.connect(lambda: self._copy_hash(entry))

        # Blocked actions
        menu.addSeparator()
        hdr = menu.addAction("━━ ⛔ BLOCKED (Forensic) ━━")
        hdr.setEnabled(False)
        for act_name in ("🚫 Delete", "🚫 Rename", "🚫 Cut", "🚫 Paste", "🚫 Edit"):
            b = menu.addAction(act_name)
            b.setEnabled(False)
        menu.addSeparator()
        notice = menu.addAction("🔒 All actions logged to CoC")
        notice.setEnabled(False)

        menu.exec(global_pos)

    def _send_to_ml(self, entry: FileEntry):
        """Send file to ML analysis pipeline."""
        self.terminal_command.emit(f"ml_analyze {entry.path}")
        if self.coc_logger:
            self.coc_logger("FILE_SENT_TO_ML", {"path": entry.path, "size": entry.size})
        QMessageBox.information(
            self, "ML Analysis",
            f"File queued for ML analysis:\n{entry.name}\n\n"
            "Check ML Analytics tab for results."
        )

    def _tag_as_evidence(self, entry: FileEntry):
        """Tag a file as key evidence with CoC logging."""
        if self.coc_logger:
            self.coc_logger("EVIDENCE_TAGGED", {
                "path": entry.path,
                "name": entry.name,
                "sha256": entry.sha256 or "pending",
            })
        QMessageBox.information(
            self, "Evidence Tagged",
            f"✅ Tagged as evidence:\n{entry.name}\n\n"
            "Action logged to Chain of Custody."
        )

    def _add_file_note(self, entry: FileEntry):
        """Add an investigator note about this file."""
        from PyQt6.QtWidgets import QInputDialog
        note, ok = QInputDialog.getMultiLineText(
            self, "Investigator Note",
            f"Add note for: {entry.name}",
        )
        if ok and note.strip():
            if self.coc_logger:
                self.coc_logger("INVESTIGATOR_NOTE", {
                    "path": entry.path,
                    "note": note.strip()[:500],
                })

    def _copy_path(self, entry: FileEntry):
        QApplication.clipboard().setText(entry.path)

    def _copy_hash(self, entry: FileEntry):
        h = entry.sha256 or entry.md5 or ""
        if h:
            QApplication.clipboard().setText(h)
        else:
            QMessageBox.information(self, "No Hash", "Hash not computed yet. Use 'Compute SHA-256' first.")

    def _open_with_type(self, entry: FileEntry, viewer_type: str):
        try:
            from src.ui.viewers import TextViewer, HexViewer
            ViewerClass = TextViewer if viewer_type == "text" else HexViewer
            viewer = ViewerClass(read_file_func=self.read_file_func)
            data = self.read_file_func(entry.path, 0, -1) if self.read_file_func else None
            viewer.load_file(entry.path, data)
            viewer.setWindowTitle(f"{entry.name} — FEPD {viewer_type.title()} Viewer")
            viewer.resize(800, 600)
            viewer.show()
        except Exception as exc:
            QMessageBox.critical(self, "Viewer Error", str(exc))

    def _show_properties(self, entry: FileEntry):
        try:
            from src.ui.viewers import FileDetailsDialog
            node = self.vfs.get_node(entry.path)
            if node:
                dlg = FileDetailsDialog(node, self)
                dlg.exec()
        except Exception as exc:
            QMessageBox.information(
                self, "Properties",
                f"Name: {entry.name}\nPath: {entry.path}\n"
                f"Size: {entry.display_size}\nType: {entry.display_type}",
            )

    def _extract_strings(self, entry: FileEntry):
        if not self.read_file_func:
            QMessageBox.warning(self, "Error", "File reading not available")
            return
        try:
            data = self.read_file_func(
                entry.path, 0, min(entry.size or MAX_FILE_SIZE_STRINGS, MAX_FILE_SIZE_STRINGS)
            )
            if not data:
                return
            import re as _re
            pattern = rb"[\x20-\x7E]{" + str(MIN_STRING_LENGTH).encode() + rb",}"
            strings = sorted(set(
                s.decode("ascii", errors="ignore") for s in _re.findall(pattern, data)
            ), key=len, reverse=True)

            from src.ui.viewers import TextViewer
            header = (
                f"═══ STRINGS: {entry.name} ═══\n"
                f"Total: {len(strings)} | Min length: {MIN_STRING_LENGTH}\n\n"
            )
            viewer = TextViewer()
            viewer.display_content(
                (header + "\n".join(strings[:MAX_STRINGS_DISPLAY])).encode()
            )
            viewer.setWindowTitle(f"Strings: {entry.name}")
            viewer.resize(800, 600)
            viewer.show()
        except Exception as exc:
            QMessageBox.critical(self, "Strings Error", str(exc))

    def _export_file(self, entry: FileEntry):
        save_path, _ = QFileDialog.getSaveFileName(self, "Export File", entry.name)
        if not save_path:
            return
        ok = self.controller.export_file(entry, Path(save_path))
        if ok:
            QMessageBox.information(self, "Exported", f"Saved to:\n{save_path}")
        else:
            QMessageBox.warning(self, "Export Failed", "Could not export file.")

    # =====================================================================
    # SEARCH
    # =====================================================================

    def _on_search_changed(self, text: str):
        if text:
            self._search_timer.start(SEARCH_DEBOUNCE_MS)
        else:
            self._search_timer.stop()
            # Reload current directory
            self.controller.refresh_current()

    def _execute_search(self):
        query = self.search_box.text().strip()
        if not query:
            return
        results = self.controller.search(query, limit=200)
        self._contents_model.set_entries(results)
        self.stats_label.setText(f"Search: {len(results)} results for '{query}'")

    # =====================================================================
    # SORT / FILTER
    # =====================================================================

    def _on_sort_changed(self, sort_text: str):
        parts = sort_text.split()
        if len(parts) < 2:
            return
        col_map = {"name": 1, "size": 2, "type": 3, "date": 4}
        col = col_map.get(parts[0].lower(), 1)
        order = Qt.SortOrder.AscendingOrder if "↑" in parts[1] else Qt.SortOrder.DescendingOrder
        self.contents_view.sortByColumn(col, order)

    def _on_filter_changed(self, filter_text: str):
        filt = filter_text.lower()
        # Reload current entries and filter
        entries = self.controller.navigator.list_directory(self.controller.current_path)
        if filt == "all files":
            self._contents_model.set_entries(entries)
        else:
            cat_map = {
                "images": {"jpg", "jpeg", "png", "gif", "bmp", "ico", "tiff", "tif", "webp"},
                "documents": {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv"},
                "executables": {"exe", "dll", "sys", "com", "bat", "cmd", "msi", "ps1"},
                "archives": {"zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab"},
            }
            valid_exts = cat_map.get(filt, set())
            filtered = [
                e for e in entries
                if e.is_directory or e.extension in valid_exts
            ]
            self._contents_model.set_entries(filtered)
        self.stats_label.setText(f"{self._contents_model.rowCount()} items")

    # =====================================================================
    # KEYBOARD SHORTCUTS
    # =====================================================================

    def _setup_shortcuts(self):
        # Write-blocked
        for keys, action in [
            ("Delete", "Delete"), ("Ctrl+X", "Cut"), ("F2", "Rename"),
            ("Ctrl+V", "Paste"), ("Ctrl+D", "Delete"),
        ]:
            sc = QShortcut(QKeySequence(keys), self)
            sc.activated.connect(lambda a=action: _block_write(self, a))

        # Navigation
        QShortcut(QKeySequence("Alt+Left"), self).activated.connect(self._on_back)
        QShortcut(QKeySequence("Alt+Right"), self).activated.connect(self._on_forward)
        QShortcut(QKeySequence("Alt+Up"), self).activated.connect(self._on_up)
        QShortcut(QKeySequence("Backspace"), self).activated.connect(self._on_up)

        # Viewers
        QShortcut(QKeySequence("Ctrl+H"), self).activated.connect(self._open_sel_hex)
        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(self._open_sel_text)
        QShortcut(QKeySequence("Return"), self).activated.connect(self._open_sel)
        QShortcut(QKeySequence("Ctrl+I"), self).activated.connect(self._show_sel_props)
        QShortcut(QKeySequence("Ctrl+E"), self).activated.connect(self._export_sel)
        QShortcut(QKeySequence("F5"), self).activated.connect(self.refresh)

    def _selected_entry(self) -> Optional[FileEntry]:
        idx = self.contents_view.currentIndex()
        if idx.isValid():
            return self._contents_model.get_entry(idx.row())
        return None

    def _open_sel_hex(self):
        e = self._selected_entry()
        if e and not e.is_directory:
            self._open_with_type(e, "hex")

    def _open_sel_text(self):
        e = self._selected_entry()
        if e and not e.is_directory:
            self._open_with_type(e, "text")

    def _open_sel(self):
        e = self._selected_entry()
        if e:
            if e.is_directory:
                self.controller.open_folder(e.path)
            else:
                self._open_file_entry(e)

    def _show_sel_props(self):
        e = self._selected_entry()
        if e:
            self._show_properties(e)

    def _export_sel(self):
        e = self._selected_entry()
        if e and not e.is_directory:
            self._export_file(e)

    # =====================================================================
    # TERMINAL SYNC
    # =====================================================================

    def sync_to_terminal_path(self, terminal_path: str):
        """Sync file browser to terminal's cd path."""
        if terminal_path:
            ok = self.controller.sync_from_terminal(terminal_path)
            if ok:
                self._expand_tree_to(terminal_path)

    def get_current_path(self) -> str:
        return self.controller.current_path

    def get_current_user(self) -> Optional[str]:
        return self.controller.current_user

    def navigate_to_path(self, path: str):
        self.controller.open_folder(path)
        self._expand_tree_to(path)
        self.path_changed.emit(path)

    # =====================================================================
    # TREE HELPERS
    # =====================================================================

    def _auto_expand(self):
        """Expand first two levels for immediate visibility."""
        try:
            for row in range(self._tree_model.rowCount()):
                root_idx = self._tree_model.index(row, 0)
                self.tree_view.expand(root_idx)
                for child_row in range(self._tree_model.rowCount(root_idx)):
                    child_idx = self._tree_model.index(child_row, 0, root_idx)
                    self.tree_view.expand(child_idx)
        except Exception:
            pass

        # Load root contents into center panel
        self.controller.open_folder("/")

    def _expand_tree_to(self, path: str):
        """Expand tree nodes to match a path."""
        parts = path.strip("/").split("/")
        parent_idx = QModelIndex()
        for part in parts:
            found = False
            for row in range(self._tree_model.rowCount(parent_idx)):
                idx = self._tree_model.index(row, 0, parent_idx)
                node = self._tree_model.node_at(idx)
                if node and node.name == part:
                    self.tree_view.expand(idx)
                    parent_idx = idx
                    found = True
                    break
            if not found:
                break
        if parent_idx.isValid():
            self.tree_view.setCurrentIndex(parent_idx)
            self.tree_view.scrollTo(parent_idx)

    def refresh(self):
        """Full refresh from VFS."""
        self._tree_model.refresh()
        self._auto_expand()
        self.controller.refresh_current()

    # =====================================================================
    # STYLE HELPERS
    # =====================================================================

    @staticmethod
    def _nav_button(text: str, tooltip: str) -> QPushButton:
        btn = QPushButton(text)
        btn.setFixedSize(28, 28)
        btn.setToolTip(tooltip)
        btn.setStyleSheet(
            "QPushButton { background: transparent; border: none; color: #ccc; "
            "font-size: 16px; border-radius: 4px; }"
            "QPushButton:hover { background: #3e3e42; }"
            "QPushButton:disabled { color: #555; }"
        )
        return btn

    @staticmethod
    def _tree_style() -> str:
        return """
            QTreeView {
                background-color: #1e1e1e; color: #fff; border: none;
                font-family: 'Segoe UI', Arial; font-size: 12px;
            }
            QTreeView::item { padding: 4px 2px; border: none; }
            QTreeView::item:selected { background: #094771; color: #fff; }
            QTreeView::item:hover:!selected { background: #2a2d2e; }
            QHeaderView::section {
                background: #252526; color: #ccc; padding: 6px 8px;
                border: none; border-right: 1px solid #3e3e42;
                border-bottom: 1px solid #3e3e42; font-size: 11px;
            }
            QScrollBar:vertical {
                background: #1e1e1e; width: 12px;
            }
            QScrollBar::handle:vertical {
                background: #5a5a5a; min-height: 20px; border-radius: 6px; margin: 2px;
            }
            QScrollBar::handle:vertical:hover { background: #787878; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """

    @staticmethod
    def _table_style() -> str:
        return """
            QTableView {
                background-color: #1e1e1e; color: #e0e0e0; border: none;
                gridline-color: #2a2a2a;
                font-family: 'Segoe UI', Arial; font-size: 12px;
            }
            QTableView::item { padding: 4px 6px; }
            QTableView::item:selected { background: #094771; color: #fff; }
            QTableView::item:hover:!selected { background: #2a2d2e; }
            QHeaderView::section {
                background: #252526; color: #ccc; padding: 6px 8px;
                border: none; border-right: 1px solid #3e3e42;
                border-bottom: 1px solid #3e3e42; font-size: 11px;
            }
            QScrollBar:vertical {
                background: #1e1e1e; width: 12px;
            }
            QScrollBar::handle:vertical {
                background: #5a5a5a; min-height: 20px; border-radius: 6px; margin: 2px;
            }
            QScrollBar::handle:vertical:hover { background: #787878; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """
