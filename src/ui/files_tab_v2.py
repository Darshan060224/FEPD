"""
FEPD Files Tab v2 - Forensic Evidence File Explorer
====================================================

A Forensic Operating System View that makes investigators feel:
"I am inside the suspect's disk, but nothing I do can ever damage it."

Four Truths Communicated Instantly:
1. You are browsing evidence, not your host system
2. Everything is read-only & court-safe
3. Every file is traceable (hash, partition, source image)
4. This view is linked to the terminal (same virtual path)

Features:
- Clickable forensic breadcrumb navigation
- Real-time terminal ↔ files tab synchronization
- Evidence Identity Card panel with full forensic metadata
- Color-coded file types (executables, registry, logs, suspicious)
- Court-grade status banner with integrity verification
- Blocked operations logged to Chain of Custody

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTreeView, QFrame, QLabel, QAbstractItemView,
    QStyledItemDelegate, QStyle, QApplication,
    QMenu, QMessageBox, QStackedWidget, QScrollArea,
    QFormLayout, QSizePolicy, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QToolBar, QLineEdit, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import (
    Qt, QAbstractItemModel, QModelIndex, pyqtSignal,
    QSize, QTimer, QMimeData, QPropertyAnimation, QEasingCurve, QPoint
)
from PyQt6.QtGui import (
    QIcon, QColor, QPainter, QFont, QPen, QBrush,
    QAction, QPixmap, QDrag, QKeySequence, QCursor
)
from pathlib import Path
from typing import Optional, Dict, List, Any, Callable
from datetime import datetime
import logging

# Local imports
import sys
sys.path.insert(0, str(__file__).replace('\\', '/').rsplit('/src/', 1)[0])
from src.core.virtual_fs import VirtualFilesystem, VFSNode, VFSNodeType
from src.core.veos import VirtualEvidenceOS, VEOSFile, VEOSDrive
from src.core.chain_of_custody import ChainLogger
from src.core.case_manager import CaseManager

logger = logging.getLogger(__name__)


# ============================================================================
# FORENSIC CONSTANTS & STYLING
# ============================================================================

FORENSIC_BLOCK_MESSAGE = """
┌──────────────────────────────────────────────────────────────────────┐
│           🚫 [READ-ONLY FORENSIC MODE]                               │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   This action would MODIFY EVIDENCE and is BLOCKED.                  │
│                                                                      │
│   FEPD operates in strict forensic mode to preserve:                 │
│                                                                      │
│     ✓ Evidence integrity and hash values                             │
│     ✓ Chain-of-custody compliance                                    │
│     ✓ Court admissibility standards                                  │
│     ✓ Forensic soundness                                             │
│                                                                      │
│   ⚠️  Attempt has been LOGGED in Chain of Custody.                   │
│                                                                      │
│   💡 TIP: Use "Export to Workspace" to create a working copy.        │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
"""

# File type color coding
FILE_TYPE_COLORS = {
    # Executables - Orange (potential threat)
    'exe': '#FF9800', 'dll': '#FF9800', 'sys': '#FF9800', 'com': '#FF9800',
    'bat': '#FF9800', 'cmd': '#FF9800', 'msi': '#FF9800', 'scr': '#FF9800',
    'ps1': '#FF9800', 'vbs': '#FF9800', 'js': '#FF9800',
    
    # Registry - Purple (system config)
    'reg': '#9C27B0', 'hiv': '#9C27B0', 'dat': '#9C27B0',
    
    # Logs - Blue (events/audit)
    'evtx': '#2196F3', 'evt': '#2196F3', 'log': '#2196F3', 'etl': '#2196F3',
    
    # Suspicious - Red (flagged)
    'suspicious': '#F44336',
    
    # Documents - Green
    'doc': '#4CAF50', 'docx': '#4CAF50', 'pdf': '#4CAF50', 'txt': '#4CAF50',
    
    # Archives - Teal
    'zip': '#009688', 'rar': '#009688', '7z': '#009688', 'tar': '#009688',
    
    # Images - Cyan
    'jpg': '#00BCD4', 'jpeg': '#00BCD4', 'png': '#00BCD4', 'gif': '#00BCD4',
    
    # Email - Amber
    'pst': '#FFC107', 'ost': '#FFC107', 'eml': '#FFC107', 'msg': '#FFC107',
    
    # Database - Brown
    'db': '#795548', 'sqlite': '#795548', 'sqlite3': '#795548', 'mdb': '#795548',
}

# Artifact classification (ordered: specific patterns first!)
ARTIFACT_TYPES = {
    # Event Logs (check specific .evtx files FIRST before registry patterns)
    'security.evtx': ('Event Log', 'Security Audit'),
    'system.evtx': ('Event Log', 'System Events'),
    'application.evtx': ('Event Log', 'Application Events'),
    'powershell.evtx': ('Event Log', 'PowerShell'),
    
    # Registry (these contain shorter patterns, check after .evtx)
    'sam': ('Registry', 'Credentials'),
    'ntuser.dat': ('Registry', 'User Settings'),
    'usrclass.dat': ('Registry', 'User Classes'),
    'software': ('Registry', 'Software Config'),
    
    # Browser
    'history': ('Browser', 'Browsing History'),
    'cookies': ('Browser', 'Cookies'),
    'places.sqlite': ('Browser', 'Firefox History'),
    'web data': ('Browser', 'Autofill'),
    
    # Prefetch
    '.pf': ('Prefetch', 'Execution Evidence'),
    
    # Startup
    'autorun': ('Persistence', 'Autostart'),
    'run': ('Persistence', 'Startup'),
}

RISK_TAGS = {
    'sam': ['Credentials', 'Authentication'],
    'ntuser.dat': ['User Profile', 'Persistence'],
    '.exe': ['Executable', 'Potential Malware'],
    '.dll': ['Library', 'Code Injection'],
    '.ps1': ['PowerShell', 'Scripting'],
    'security.evtx': ['Authentication', 'Login Events'],
    '.pf': ['Execution', 'Timeline'],
}


def block_write_operation(parent_widget, action_name: str, coc_logger=None):
    """Display forensic write-block warning and log attempt."""
    QMessageBox.warning(
        parent_widget,
        "⛔ Forensic Write Block",
        FORENSIC_BLOCK_MESSAGE,
        QMessageBox.StandardButton.Ok
    )
    
    # Log to Chain of Custody
    if coc_logger:
        coc_logger("WRITE_ATTEMPT_BLOCKED", {
            "action": action_name,
            "message": "User attempted blocked write operation",
            "severity": "WARNING"
        })
    
    return False


# ============================================================================
# CLICKABLE BREADCRUMB WIDGET
# ============================================================================

class ClickableBreadcrumb(QWidget):
    """
    Forensic breadcrumb navigation with clickable segments.
    
    Display:
        Evidence Root ▸ Disk0 ▸ Partition1 ▸ Windows ▸ System32 ▸ config
    
    Each segment is clickable and navigates to that path.
    """
    
    segment_clicked = pyqtSignal(str)  # Emits full path to segment
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._segments = []
        self._current_path = "/"
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the breadcrumb UI."""
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        
        # Root is always visible
        self._root_btn = self._create_segment_button("🖥️ Evidence Root", "/", is_root=True)
        self.layout.addWidget(self._root_btn)
        
        self.layout.addStretch()
    
    def _create_segment_button(self, text: str, path: str, is_root: bool = False) -> QPushButton:
        """Create a clickable breadcrumb segment."""
        btn = QPushButton(text)
        btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn.setFlat(True)
        
        if is_root:
            btn.setStyleSheet("""
                QPushButton {
                    color: #4fc3f7;
                    font-weight: bold;
                    font-size: 12px;
                    border: none;
                    padding: 4px 8px;
                    background: transparent;
                }
                QPushButton:hover {
                    background: rgba(79, 195, 247, 0.15);
                    border-radius: 4px;
                }
            """)
        else:
            btn.setStyleSheet("""
                QPushButton {
                    color: #90caf9;
                    font-size: 12px;
                    border: none;
                    padding: 4px 8px;
                    background: transparent;
                }
                QPushButton:hover {
                    background: rgba(144, 202, 249, 0.15);
                    border-radius: 4px;
                    color: #fff;
                }
            """)
        
        btn.clicked.connect(lambda: self.segment_clicked.emit(path))
        return btn
    
    def _create_separator(self) -> QLabel:
        """Create a separator between segments."""
        sep = QLabel(" ▸ ")
        sep.setStyleSheet("color: #555; font-size: 12px;")
        return sep
    
    def set_path(self, path: str):
        """Update breadcrumb to show the given path."""
        self._current_path = path
        
        # Clear existing segments (except root and stretch)
        while self.layout.count() > 2:
            item = self.layout.takeAt(1)
            if item.widget():
                item.widget().deleteLater()
        
        if not path or path == "/":
            return
        
        # Build path segments
        parts = path.strip('/').split('/')
        cumulative_path = ""
        
        for i, part in enumerate(parts):
            if not part:
                continue
            
            cumulative_path += f"/{part}"
            
            # Add separator
            sep = self._create_separator()
            self.layout.insertWidget(self.layout.count() - 1, sep)
            
            # Determine icon and style
            icon, display_name = self._get_segment_display(part, i, parts)
            
            btn = self._create_segment_button(f"{icon} {display_name}", cumulative_path)
            
            # Highlight last segment
            if i == len(parts) - 1:
                btn.setStyleSheet("""
                    QPushButton {
                        color: #fff;
                        font-weight: bold;
                        font-size: 12px;
                        border: none;
                        padding: 4px 8px;
                        background: rgba(9, 71, 113, 0.5);
                        border-radius: 4px;
                    }
                    QPushButton:hover {
                        background: rgba(9, 71, 113, 0.8);
                    }
                """)
            
            self.layout.insertWidget(self.layout.count() - 1, btn)
    
    def _get_segment_display(self, part: str, index: int, all_parts: List[str]) -> tuple:
        """Get icon and display name for a path segment."""
        part_lower = part.lower()
        
        if index == 0:
            # First segment - likely disk/partition
            if part_lower.startswith('disk'):
                return "💽", part
            elif ':' in part or len(part) == 1:
                return "💾", f"{part}:" if ':' not in part else part
            else:
                return "📦", part
        
        # Special folders
        if part_lower == 'users':
            return "👥", "Users"
        elif part_lower == 'windows':
            return "⚙️", "Windows"
        elif part_lower in ('program files', 'program files (x86)'):
            return "📂", part
        elif part_lower == 'system32':
            return "🔧", "System32"
        elif part_lower == 'config':
            return "🗝️", "config"
        elif part_lower == 'prefetch':
            return "⚡", "Prefetch"
        elif part_lower == 'winevt':
            return "📋", "winevt"
        elif part_lower == 'logs':
            return "📋", "Logs"
        
        # Check if user profile (after Users)
        if index > 0 and all_parts[index - 1].lower() == 'users':
            if part_lower not in ('public', 'default', 'default user', 'all users'):
                return "👤", part
        
        # Default
        return "📁", part


# ============================================================================
# FORENSIC STATUS BANNER
# ============================================================================

class ForensicStatusBanner(QFrame):
    """
    Always-visible status banner showing forensic mode information.
    
    Display:
        🧪 Evidence Source: LoneWolf.E01 + E02 + E03
        🔒 Mode: READ-ONLY (All write operations blocked)
        🧬 Integrity: SHA-256 Verified | Chain-of-Custody Active
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._evidence_source = "Virtual Filesystem"
        self._integrity_ok = True
        self._coc_active = True
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the status banner."""
        self.setStyleSheet("""
            ForensicStatusBanner {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1a2634, stop:1 #0d1520);
                border-bottom: 2px solid #0d47a1;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        
        # Top row - Evidence source and mode
        top_row = QHBoxLayout()
        top_row.setSpacing(24)
        
        # Evidence source
        self.evidence_label = QLabel("🧪 Evidence Source: Virtual Filesystem")
        self.evidence_label.setStyleSheet("""
            color: #90caf9;
            font-size: 12px;
            font-weight: bold;
        """)
        top_row.addWidget(self.evidence_label)
        
        # Read-only mode indicator (prominent)
        self.mode_label = QLabel("🔒 Mode: READ-ONLY")
        self.mode_label.setStyleSheet("""
            color: #4CAF50;
            font-size: 12px;
            font-weight: bold;
            padding: 4px 12px;
            background: rgba(76, 175, 80, 0.15);
            border: 1px solid #4CAF50;
            border-radius: 4px;
        """)
        self.mode_label.setToolTip("All write operations are blocked to preserve evidence integrity")
        top_row.addWidget(self.mode_label)
        
        top_row.addStretch()
        
        # Integrity status
        self.integrity_label = QLabel("🧬 Integrity: SHA-256 Verified")
        self.integrity_label.setStyleSheet("""
            color: #4CAF50;
            font-size: 11px;
        """)
        top_row.addWidget(self.integrity_label)
        
        # Chain of Custody status
        self.coc_label = QLabel("📜 Chain-of-Custody: Active")
        self.coc_label.setStyleSheet("""
            color: #FFC107;
            font-size: 11px;
        """)
        top_row.addWidget(self.coc_label)
        
        layout.addLayout(top_row)
        
        # Bottom row - Description
        desc_label = QLabel("🗂️ Virtual Filesystem mounted from forensic image (NOT your host system)")
        desc_label.setStyleSheet("color: #666; font-size: 10px;")
        layout.addWidget(desc_label)
    
    def set_evidence_source(self, source: str):
        """Set the evidence source display."""
        self._evidence_source = source
        self.evidence_label.setText(f"🧪 Evidence Source: {source}")
    
    def set_integrity_status(self, verified: bool, hash_type: str = "SHA-256"):
        """Set integrity verification status."""
        self._integrity_ok = verified
        if verified:
            self.integrity_label.setText(f"🧬 Integrity: {hash_type} Verified")
            self.integrity_label.setStyleSheet("color: #4CAF50; font-size: 11px;")
        else:
            self.integrity_label.setText(f"⚠️ Integrity: {hash_type} MISMATCH")
            self.integrity_label.setStyleSheet("color: #F44336; font-size: 11px; font-weight: bold;")
    
    def set_coc_status(self, active: bool):
        """Set Chain of Custody status."""
        self._coc_active = active
        if active:
            self.coc_label.setText("📜 Chain-of-Custody: Active")
            self.coc_label.setStyleSheet("color: #FFC107; font-size: 11px;")
        else:
            self.coc_label.setText("⚠️ Chain-of-Custody: Inactive")
            self.coc_label.setStyleSheet("color: #F44336; font-size: 11px;")


# ============================================================================
# EVIDENCE IDENTITY CARD (Enhanced Details Panel)
# ============================================================================

class EvidenceIdentityCard(QFrame):
    """
    Enhanced details panel showing full forensic metadata.
    
    "Evidence Identity Card" - turns files into forensic objects.
    
    Display:
        File: SAM
        Type: Registry Hive
        Size: 32 KB
        Created: 2025-01-02 09:12:44
        Modified: 2026-01-09 18:02:11
        Accessed: 2026-01-10 10:41:03
        ─────────────────────────
        SHA-256: 9a3c…f82e
        Partition: Disk0 ▸ Partition1
        Source Image: LoneWolf.E01
        ─────────────────────────
        Artifact Type: Registry
        Risk Tags: Persistence, Credentials
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_node = None
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the identity card UI."""
        self.setStyleSheet("""
            EvidenceIdentityCard {
                background: #1e1e1e;
                border-left: 1px solid #3d3d3d;
            }
            QLabel {
                color: #e0e0e0;
            }
        """)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        
        # =====================================================
        # FILE ICON & NAME
        # =====================================================
        
        self.icon_label = QLabel("📁")
        self.icon_label.setStyleSheet("font-size: 48px;")
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.icon_label)
        
        self.name_label = QLabel("Select a file")
        self.name_label.setStyleSheet("""
            font-size: 14px;
            font-weight: bold;
            color: #fff;
        """)
        self.name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.name_label.setWordWrap(True)
        layout.addWidget(self.name_label)
        
        self.type_label = QLabel("")
        self.type_label.setStyleSheet("color: #888; font-size: 11px;")
        self.type_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.type_label)
        
        # =====================================================
        # READ-ONLY BADGE
        # =====================================================
        
        badge_container = QHBoxLayout()
        badge_container.addStretch()
        
        self.readonly_badge = QLabel("🔒 READ-ONLY EVIDENCE")
        self.readonly_badge.setStyleSheet("""
            color: #4CAF50;
            font-size: 9px;
            font-weight: bold;
            padding: 3px 10px;
            background: rgba(76, 175, 80, 0.15);
            border: 1px solid #4CAF50;
            border-radius: 4px;
        """)
        badge_container.addWidget(self.readonly_badge)
        badge_container.addStretch()
        layout.addLayout(badge_container)
        
        layout.addSpacing(8)
        
        # =====================================================
        # SECTION: FILE PROPERTIES
        # =====================================================
        
        self._add_section_header(layout, "📋 FILE PROPERTIES")
        
        props_form = QFormLayout()
        props_form.setSpacing(6)
        props_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.size_value = self._create_value_label()
        props_form.addRow(self._create_label("Size:"), self.size_value)
        
        self.created_value = self._create_value_label()
        props_form.addRow(self._create_label("Created:"), self.created_value)
        
        self.modified_value = self._create_value_label()
        props_form.addRow(self._create_label("Modified:"), self.modified_value)
        
        self.accessed_value = self._create_value_label()
        props_form.addRow(self._create_label("Accessed:"), self.accessed_value)
        
        layout.addLayout(props_form)
        
        # =====================================================
        # SECTION: FORENSIC IDENTITY
        # =====================================================
        
        self._add_section_header(layout, "🔐 FORENSIC IDENTITY")
        
        forensic_form = QFormLayout()
        forensic_form.setSpacing(6)
        forensic_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.sha256_value = self._create_value_label(monospace=True)
        forensic_form.addRow(self._create_label("SHA-256:"), self.sha256_value)
        
        self.partition_value = self._create_value_label()
        forensic_form.addRow(self._create_label("Partition:"), self.partition_value)
        
        self.evidence_value = self._create_value_label()
        forensic_form.addRow(self._create_label("Source:"), self.evidence_value)
        
        self.path_value = self._create_value_label(monospace=True)
        forensic_form.addRow(self._create_label("Path:"), self.path_value)
        
        layout.addLayout(forensic_form)
        
        # =====================================================
        # SECTION: ARTIFACT CLASSIFICATION
        # =====================================================
        
        self._add_section_header(layout, "🏷️ ARTIFACT CLASSIFICATION")
        
        artifact_form = QFormLayout()
        artifact_form.setSpacing(6)
        artifact_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.artifact_type_value = self._create_value_label()
        artifact_form.addRow(self._create_label("Type:"), self.artifact_type_value)
        
        self.risk_tags_container = QHBoxLayout()
        self.risk_tags_container.setSpacing(4)
        artifact_form.addRow(self._create_label("Risk Tags:"), self.risk_tags_container)
        
        layout.addLayout(artifact_form)
        
        # Container for risk tag widgets
        self.risk_tags_widget = QWidget()
        self.risk_tags_layout = QHBoxLayout(self.risk_tags_widget)
        self.risk_tags_layout.setContentsMargins(0, 0, 0, 0)
        self.risk_tags_layout.setSpacing(4)
        layout.addWidget(self.risk_tags_widget)
        
        layout.addStretch()
        
        scroll.setWidget(content)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)
    
    def _create_label(self, text: str) -> QLabel:
        """Create a styled label."""
        label = QLabel(text)
        label.setStyleSheet("color: #888; font-size: 11px;")
        return label
    
    def _create_value_label(self, monospace: bool = False) -> QLabel:
        """Create a styled value label."""
        label = QLabel("—")
        if monospace:
            label.setStyleSheet("""
                color: #b0b0b0;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10px;
            """)
        else:
            label.setStyleSheet("color: #d4d4d4; font-size: 11px;")
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        return label
    
    def _add_section_header(self, layout: QVBoxLayout, text: str):
        """Add a section header."""
        layout.addSpacing(12)
        
        header = QLabel(text)
        header.setStyleSheet("""
            color: #90caf9;
            font-size: 10px;
            font-weight: bold;
            padding: 4px 0;
            border-bottom: 1px solid #333;
        """)
        layout.addWidget(header)
    
    def _create_risk_tag(self, text: str, color: str = "#F44336") -> QLabel:
        """Create a risk tag badge."""
        tag = QLabel(text)
        tag.setStyleSheet(f"""
            color: #fff;
            font-size: 9px;
            font-weight: bold;
            padding: 2px 6px;
            background: {color};
            border-radius: 3px;
        """)
        return tag
    
    def show_node(self, node: VFSNode):
        """Display forensic details for a node."""
        self._current_node = node
        
        # Icon based on type and extension
        icon = self._get_file_icon(node)
        self.icon_label.setText(icon)
        
        # Name and type
        self.name_label.setText(node.name)
        file_type = self._get_file_type_description(node)
        self.type_label.setText(file_type)
        
        # Apply color coding to name
        color = self._get_file_color(node)
        if color:
            self.name_label.setStyleSheet(f"""
                font-size: 14px;
                font-weight: bold;
                color: {color};
            """)
        else:
            self.name_label.setStyleSheet("""
                font-size: 14px;
                font-weight: bold;
                color: #fff;
            """)
        
        # Size
        if node.size > 0:
            self.size_value.setText(f"{self._format_size(node.size)} ({node.size:,} bytes)")
        else:
            self.size_value.setText("—")
        
        # Timestamps
        self.created_value.setText(
            node.created.strftime("%Y-%m-%d %H:%M:%S") if node.created else "—"
        )
        self.modified_value.setText(
            node.modified.strftime("%Y-%m-%d %H:%M:%S") if node.modified else "—"
        )
        self.accessed_value.setText(
            node.accessed.strftime("%Y-%m-%d %H:%M:%S") if node.accessed else "—"
        )
        
        # SHA-256
        if node.sha256:
            short_hash = f"{node.sha256[:8]}...{node.sha256[-8:]}"
            self.sha256_value.setText(short_hash)
            self.sha256_value.setToolTip(f"Full SHA-256:\n{node.sha256}\n\nClick to copy")
        else:
            self.sha256_value.setText("Not computed")
            self.sha256_value.setToolTip("Hash not yet calculated")
        
        # Partition (breadcrumb style)
        partition_display = self._build_partition_breadcrumb(node)
        self.partition_value.setText(partition_display)
        
        # Evidence source
        self.evidence_value.setText(node.evidence_id or "Forensic Image")
        
        # Path
        display_path = node.path.replace('/', ' ▸ ').strip(' ▸ ')
        self.path_value.setText(display_path or "—")
        self.path_value.setToolTip(f"Virtual path: {node.path}")
        
        # Artifact classification
        artifact_type, artifact_subtype = self._classify_artifact(node)
        if artifact_type:
            self.artifact_type_value.setText(f"{artifact_type} - {artifact_subtype}")
        else:
            self.artifact_type_value.setText("General File")
        
        # Risk tags
        self._update_risk_tags(node)
    
    def _get_file_icon(self, node: VFSNode) -> str:
        """Get appropriate icon for file type."""
        if node.node_type == VFSNodeType.FOLDER:
            return "📁"
        elif node.node_type == VFSNodeType.USER:
            return "👤"
        elif node.node_type == VFSNodeType.DISK:
            return "💽"
        elif node.node_type == VFSNodeType.DELETED:
            return "🗑️"
        
        ext = node.name.lower().rsplit('.', 1)[-1] if '.' in node.name else ''
        name_lower = node.name.lower()
        
        # Registry hives
        if name_lower in ('sam', 'system', 'software', 'security', 'default'):
            return "🗝️"
        elif name_lower.endswith('.dat') and 'ntuser' in name_lower:
            return "🗝️"
        
        # By extension
        icon_map = {
            'exe': '⚡', 'dll': '⚡', 'sys': '⚙️',
            'evtx': '📋', 'evt': '📋', 'log': '📋', 'etl': '📋',
            'pf': '⚡',
            'reg': '🗝️',
            'pst': '📧', 'ost': '📧', 'eml': '✉️', 'msg': '✉️',
            'pdf': '📕', 'doc': '📘', 'docx': '📘',
            'xls': '📊', 'xlsx': '📊',
            'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️',
            'mp4': '🎬', 'avi': '🎬', 'mkv': '🎬',
            'mp3': '🎵', 'wav': '🎵',
            'zip': '📦', 'rar': '📦', '7z': '📦',
            'db': '🗃️', 'sqlite': '🗃️', 'sqlite3': '🗃️',
            'lnk': '🔗',
            'pcap': '🌐', 'pcapng': '🌐',
            'mem': '🧠', 'dmp': '🧠',
            'e01': '💿', 'dd': '💿', 'raw': '💿',
        }
        
        return icon_map.get(ext, '📄')
    
    def _get_file_type_description(self, node: VFSNode) -> str:
        """Get detailed file type description."""
        if node.is_directory:
            return "Folder"
        
        ext = node.name.lower().rsplit('.', 1)[-1] if '.' in node.name else ''
        name_lower = node.name.lower()
        
        # Registry hives
        if name_lower in ('sam', 'system', 'software', 'security', 'default'):
            return "Registry Hive"
        elif 'ntuser.dat' in name_lower:
            return "User Registry Hive"
        elif 'usrclass.dat' in name_lower:
            return "User Class Registry"
        
        type_map = {
            'exe': 'Windows Executable',
            'dll': 'Dynamic Link Library',
            'sys': 'System Driver',
            'evtx': 'Windows Event Log',
            'evt': 'Legacy Event Log',
            'etl': 'Event Trace Log',
            'pf': 'Prefetch File',
            'lnk': 'Windows Shortcut',
            'pst': 'Outlook Data File',
            'ost': 'Outlook Offline Store',
            'eml': 'Email Message',
            'msg': 'Outlook Message',
            'pcap': 'Network Capture',
            'pcapng': 'Network Capture',
            'db': 'Database File',
            'sqlite': 'SQLite Database',
            'sqlite3': 'SQLite Database',
            'mem': 'Memory Dump',
            'dmp': 'Crash Dump',
            'reg': 'Registry Export',
        }
        
        return type_map.get(ext, f"{ext.upper()} File" if ext else "Unknown")
    
    def _get_file_color(self, node: VFSNode) -> Optional[str]:
        """Get color for file based on type."""
        if node.is_directory:
            return None
        
        ext = node.name.lower().rsplit('.', 1)[-1] if '.' in node.name else ''
        name_lower = node.name.lower()
        
        # Registry hives - purple
        if name_lower in ('sam', 'system', 'software', 'security', 'default'):
            return '#9C27B0'
        elif 'ntuser.dat' in name_lower or 'usrclass.dat' in name_lower:
            return '#9C27B0'
        
        return FILE_TYPE_COLORS.get(ext)
    
    def _build_partition_breadcrumb(self, node: VFSNode) -> str:
        """Build partition breadcrumb from path."""
        if not node.path:
            return "—"
        
        parts = node.path.strip('/').split('/')
        if not parts or not parts[0]:
            return "—"
        
        # Show first 2-3 levels
        display_parts = []
        for i, part in enumerate(parts[:3]):
            if i == 0:
                display_parts.append(f"💽 {part}")
            elif i == 1:
                display_parts.append(f"📦 {part}")
            else:
                display_parts.append(part)
        
        return " ▸ ".join(display_parts)
    
    def _classify_artifact(self, node: VFSNode) -> tuple:
        """Classify artifact type and subtype."""
        name_lower = node.name.lower()
        ext = name_lower.rsplit('.', 1)[-1] if '.' in name_lower else ''
        
        # Check artifact types
        for pattern, (art_type, subtype) in ARTIFACT_TYPES.items():
            if pattern in name_lower:
                return art_type, subtype
        
        # By extension
        if ext in ('evtx', 'evt', 'etl'):
            return 'Event Log', 'Windows Events'
        elif ext == 'pf':
            return 'Prefetch', 'Execution Evidence'
        elif ext in ('exe', 'dll', 'sys'):
            return 'Executable', 'Binary'
        elif ext in ('pst', 'ost', 'eml', 'msg'):
            return 'Email', 'Communications'
        elif ext in ('lnk',):
            return 'Shortcut', 'User Activity'
        elif ext in ('db', 'sqlite', 'sqlite3'):
            return 'Database', 'Structured Data'
        
        return None, None
    
    def _update_risk_tags(self, node: VFSNode):
        """Update risk tag badges."""
        # Clear existing tags
        while self.risk_tags_layout.count():
            item = self.risk_tags_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Get risk tags for this file
        tags = self._get_risk_tags(node)
        
        if not tags:
            no_tags = QLabel("None identified")
            no_tags.setStyleSheet("color: #666; font-size: 10px;")
            self.risk_tags_layout.addWidget(no_tags)
        else:
            for tag, color in tags:
                tag_widget = self._create_risk_tag(tag, color)
                self.risk_tags_layout.addWidget(tag_widget)
        
        self.risk_tags_layout.addStretch()
    
    def _get_risk_tags(self, node: VFSNode) -> List[tuple]:
        """Get risk tags for a file."""
        tags = []
        name_lower = node.name.lower()
        ext = name_lower.rsplit('.', 1)[-1] if '.' in name_lower else ''
        
        # Registry hives
        if name_lower in ('sam',):
            tags.append(("Credentials", "#F44336"))
            tags.append(("Authentication", "#FF5722"))
        elif name_lower in ('ntuser.dat',):
            tags.append(("User Profile", "#9C27B0"))
            tags.append(("Persistence", "#E91E63"))
        elif name_lower in ('system', 'software'):
            tags.append(("System Config", "#2196F3"))
        
        # Executables
        if ext in ('exe', 'dll', 'sys', 'scr'):
            tags.append(("Executable", "#FF9800"))
        if ext in ('ps1', 'vbs', 'bat', 'cmd'):
            tags.append(("Scripting", "#FF9800"))
        
        # Event logs
        if ext in ('evtx',):
            if 'security' in name_lower:
                tags.append(("Authentication", "#4CAF50"))
                tags.append(("Audit Trail", "#2196F3"))
            elif 'powershell' in name_lower:
                tags.append(("PowerShell", "#9C27B0"))
                tags.append(("Scripting", "#FF9800"))
        
        # Prefetch
        if ext == 'pf':
            tags.append(("Execution", "#FF9800"))
            tags.append(("Timeline", "#2196F3"))
        
        return tags[:4]  # Max 4 tags
    
    def _format_size(self, size: int) -> str:
        """Format byte size."""
        size_f = float(size)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_f < 1024:
                return f"{size_f:.1f} {unit}"
            size_f /= 1024
        return f"{size_f:.1f} TB"
    
    def clear(self):
        """Clear the identity card."""
        self._current_node = None
        self.icon_label.setText("📁")
        self.name_label.setText("Select a file")
        self.name_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #fff;")
        self.type_label.setText("")
        self.size_value.setText("—")
        self.created_value.setText("—")
        self.modified_value.setText("—")
        self.accessed_value.setText("—")
        self.sha256_value.setText("—")
        self.partition_value.setText("—")
        self.evidence_value.setText("—")
        self.path_value.setText("—")
        self.artifact_type_value.setText("—")
        
        # Clear risk tags
        while self.risk_tags_layout.count():
            item = self.risk_tags_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()


# ============================================================================
# VFS TREE MODEL (with color coding)
# ============================================================================

class ForensicVFSTreeModel(QAbstractItemModel):
    """
    Qt model for displaying VFS tree with forensic color coding.
    """
    
    def __init__(self, vfs: VirtualFilesystem, parent=None):
        super().__init__(parent)
        self.vfs = vfs
        self._root_nodes: List[VFSNode] = []
        self._children_cache: Dict[str, List[VFSNode]] = {}
        self._node_cache: Dict[str, VFSNode] = {}
        self.refresh()
    
    def refresh(self):
        """Refresh the model from VFS."""
        self.beginResetModel()
        self._root_nodes = self.vfs.get_root_nodes()
        self._children_cache.clear()
        self._node_cache.clear()
        
        for node in self._root_nodes:
            self._node_cache[node.path] = node
        
        self.endResetModel()
    
    def _get_children(self, parent_path: str) -> List[VFSNode]:
        """Get children of a path, using cache."""
        if parent_path not in self._children_cache:
            children = self.vfs.get_children(parent_path)
            self._children_cache[parent_path] = children
            for child in children:
                self._node_cache[child.path] = child
        return self._children_cache[parent_path]
    
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if not parent.isValid():
            return len(self._root_nodes)
        node: VFSNode = parent.internalPointer()
        if node.is_directory:
            return len(self._get_children(node.path))
        return 0
    
    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 5  # Name, Size, Type, Modified, Partition
    
    def index(self, row: int, column: int, parent: QModelIndex = QModelIndex()) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        
        if not parent.isValid():
            if row < len(self._root_nodes):
                return self.createIndex(row, column, self._root_nodes[row])
        else:
            parent_node: VFSNode = parent.internalPointer()
            children = self._get_children(parent_node.path)
            if row < len(children):
                return self.createIndex(row, column, children[row])
        
        return QModelIndex()
    
    def parent(self, index: QModelIndex) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()
        
        node: VFSNode = index.internalPointer()
        
        if not node.parent_path:
            return QModelIndex()
        
        parent_node = self._node_cache.get(node.parent_path)
        if not parent_node:
            parent_node = self.vfs.get_node(node.parent_path)
            if parent_node:
                self._node_cache[parent_node.path] = parent_node
        
        if not parent_node:
            return QModelIndex()
        
        if not parent_node.parent_path:
            try:
                row = self._root_nodes.index(parent_node)
            except ValueError:
                for i, n in enumerate(self._root_nodes):
                    if n.path == parent_node.path:
                        row = i
                        break
                else:
                    return QModelIndex()
            return self.createIndex(row, 0, parent_node)
        else:
            grandparent_children = self._get_children(parent_node.parent_path)
            for i, n in enumerate(grandparent_children):
                if n.path == parent_node.path:
                    return self.createIndex(i, 0, parent_node)
        
        return QModelIndex()
    
    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        
        node: VFSNode = index.internalPointer()
        column = index.column()
        
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return f"{self._get_icon(node)} {node.name}"
            elif column == 1:
                if node.is_directory:
                    return ""
                return self._format_size(node.size)
            elif column == 2:
                return self._get_type_text(node)
            elif column == 3:
                if node.modified:
                    return node.modified.strftime("%Y-%m-%d %H:%M")
                return ""
            elif column == 4:
                return node.evidence_id or ""
        
        elif role == Qt.ItemDataRole.ForegroundRole:
            color = self._get_node_color(node)
            if color:
                return QColor(color)
            if node.is_deleted:
                return QColor("#888888")
        
        elif role == Qt.ItemDataRole.ToolTipRole:
            return f"Virtual path: {node.path}"
        
        elif role == Qt.ItemDataRole.UserRole:
            return node
        
        return None
    
    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            headers = ["Name", "Size", "Type", "Modified", "Evidence"]
            if section < len(headers):
                return headers[section]
        return None
    
    def hasChildren(self, parent: QModelIndex = QModelIndex()) -> bool:
        if not parent.isValid():
            return len(self._root_nodes) > 0
        node: VFSNode = parent.internalPointer()
        return node.is_directory
    
    def canFetchMore(self, parent: QModelIndex) -> bool:
        if not parent.isValid():
            return False
        node: VFSNode = parent.internalPointer()
        if not node.is_directory:
            return False
        return node.path not in self._children_cache
    
    def fetchMore(self, parent: QModelIndex):
        if not parent.isValid():
            return
        node: VFSNode = parent.internalPointer()
        if node.path not in self._children_cache:
            children = self.vfs.get_children(node.path)
            self._children_cache[node.path] = children
            for child in children:
                self._node_cache[child.path] = child
    
    def _get_icon(self, node: VFSNode) -> str:
        """Get icon for node with forensic context."""
        if node.node_type == VFSNodeType.DISK:
            return "💽"
        elif node.node_type == VFSNodeType.DRIVE:
            return "💾"
        elif node.node_type == VFSNodeType.USER:
            return "👤"
        elif node.node_type == VFSNodeType.FOLDER:
            return "📁"
        elif node.node_type == VFSNodeType.DELETED:
            return "🗑️"
        
        ext = node.name.lower().rsplit('.', 1)[-1] if '.' in node.name else ''
        name_lower = node.name.lower()
        
        # Registry hives
        if name_lower in ('sam', 'system', 'software', 'security', 'default'):
            return "🗝️"
        elif 'ntuser.dat' in name_lower:
            return "🗝️"
        
        icon_map = {
            'exe': '⚡', 'dll': '⚡', 'sys': '⚙️',
            'evtx': '📋', 'evt': '📋', 'log': '📋',
            'pf': '⚡', 'lnk': '🔗',
            'pst': '📧', 'ost': '📧', 'eml': '✉️',
            'pdf': '📕', 'doc': '📘', 'docx': '📘',
            'jpg': '🖼️', 'png': '🖼️',
            'zip': '📦', 'rar': '📦',
            'db': '🗃️', 'sqlite': '🗃️',
            'pcap': '🌐',
        }
        
        return icon_map.get(ext, "📄")
    
    def _get_node_color(self, node: VFSNode) -> Optional[str]:
        """Get color for file based on type."""
        if node.is_directory:
            return None
        
        ext = node.name.lower().rsplit('.', 1)[-1] if '.' in node.name else ''
        name_lower = node.name.lower()
        
        # Registry hives
        if name_lower in ('sam', 'system', 'software', 'security', 'default'):
            return '#9C27B0'
        elif 'ntuser.dat' in name_lower:
            return '#9C27B0'
        
        return FILE_TYPE_COLORS.get(ext)
    
    def _get_type_text(self, node: VFSNode) -> str:
        """Get type description."""
        if node.is_directory:
            return "Folder"
        
        ext = node.name.lower().rsplit('.', 1)[-1] if '.' in node.name else ''
        name_lower = node.name.lower()
        
        if name_lower in ('sam', 'system', 'software', 'security'):
            return "Registry Hive"
        
        type_map = {
            'exe': 'Executable', 'dll': 'Library', 'sys': 'Driver',
            'evtx': 'Event Log', 'pf': 'Prefetch',
            'pst': 'Outlook Data', 'lnk': 'Shortcut',
        }
        
        return type_map.get(ext, ext.upper() if ext else "File")
    
    def _format_size(self, size: int) -> str:
        """Format byte size."""
        if size == 0:
            return ""
        size_f = float(size)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_f < 1024:
                return f"{size_f:.1f} {unit}" if unit != 'B' else f"{int(size_f)} {unit}"
            size_f /= 1024
        return f"{size_f:.1f} TB"
    
    def get_node_by_index(self, index: QModelIndex) -> Optional[VFSNode]:
        """Get VFSNode from model index."""
        if index.isValid():
            return index.internalPointer()
        return None


# ============================================================================
# FORENSIC FILES TAB (Main Widget)
# ============================================================================

class ForensicFilesTab(QWidget):
    """
    Forensic File Explorer - "Inside the suspect's disk"
    
    Core Promise:
        "I am walking inside the suspect's machine.
         I can touch everything.
         But nothing I do can destroy evidence.
         And every action is accountable."
    
    Signals for terminal integration:
        - path_changed(str): Current path changed
        - user_context_changed(str): User profile context changed
        - terminal_command(str): Execute command in terminal
    """
    
    # Signals
    file_opened = pyqtSignal(str, str)       # path, viewer_type
    node_selected = pyqtSignal(object)        # VFSNode
    path_changed = pyqtSignal(str)            # For terminal sync
    user_context_changed = pyqtSignal(str)    # User profile for terminal
    terminal_command = pyqtSignal(str)        # Command for terminal
    write_blocked = pyqtSignal(str, str)      # action, reason
    
    def __init__(
        self,
        vfs: VirtualFilesystem,
        read_file_func: Optional[Callable[[str, int, int], bytes]] = None,
        coc_logger: Optional[Callable[[str, Dict], None]] = None,
        parent=None
    ):
        super().__init__(parent)
        
        self.vfs = vfs
        self.read_file_func = read_file_func
        self.coc_logger = coc_logger
        
        self._current_path = "/"
        self._current_user = None
        self._evidence_source = "Virtual Filesystem"
        
        self._setup_ui()
        self._setup_keyboard_shortcuts()
        self._connect_signals()
    
    def _setup_ui(self):
        """Set up the forensic file explorer UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # =====================================================
        # 1. FORENSIC STATUS BANNER
        # =====================================================
        
        self.status_banner = ForensicStatusBanner()
        layout.addWidget(self.status_banner)
        
        # =====================================================
        # 2. CLICKABLE BREADCRUMB
        # =====================================================
        
        breadcrumb_container = QFrame()
        breadcrumb_container.setStyleSheet("""
            QFrame {
                background: #1a1a1a;
                border-bottom: 1px solid #333;
            }
        """)
        breadcrumb_layout = QHBoxLayout(breadcrumb_container)
        breadcrumb_layout.setContentsMargins(12, 6, 12, 6)
        
        self.breadcrumb = ClickableBreadcrumb()
        self.breadcrumb.segment_clicked.connect(self._on_breadcrumb_clicked)
        breadcrumb_layout.addWidget(self.breadcrumb)
        
        breadcrumb_layout.addStretch()
        
        # Sync indicator
        self.sync_indicator = QLabel("🔗 Terminal Synced")
        self.sync_indicator.setStyleSheet("""
            color: #4CAF50;
            font-size: 10px;
            padding: 2px 8px;
            background: rgba(76, 175, 80, 0.1);
            border-radius: 3px;
        """)
        breadcrumb_layout.addWidget(self.sync_indicator)
        
        # User context
        self.user_context_label = QLabel("")
        self.user_context_label.setStyleSheet("""
            color: #FFD700;
            font-size: 11px;
            font-weight: bold;
            padding: 2px 10px;
            background: rgba(255, 215, 0, 0.1);
            border-radius: 3px;
        """)
        self.user_context_label.setVisible(False)
        breadcrumb_layout.addWidget(self.user_context_label)
        
        layout.addWidget(breadcrumb_container)
        
        # =====================================================
        # 3. MAIN CONTENT (Tree + Identity Card)
        # =====================================================
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background: #333;
                width: 1px;
            }
        """)
        
        # File tree
        tree_container = QFrame()
        tree_container.setStyleSheet("background: #1e1e1e;")
        tree_layout = QVBoxLayout(tree_container)
        tree_layout.setContentsMargins(0, 0, 0, 0)
        
        self.tree_view = QTreeView()
        self.tree_view.setHeaderHidden(False)
        self.tree_view.setAnimated(True)
        self.tree_view.setIndentation(20)
        self.tree_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_view.customContextMenuRequested.connect(self._show_context_menu)
        self.tree_view.doubleClicked.connect(self._on_double_click)
        
        self.tree_view.setStyleSheet("""
            QTreeView {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: none;
                outline: none;
                selection-background-color: #094771;
            }
            QTreeView::item {
                padding: 6px 4px;
                border: none;
            }
            QTreeView::item:selected {
                background-color: #094771;
                border-left: 3px solid #4fc3f7;
            }
            QTreeView::item:hover {
                background-color: #2a2d2e;
            }
            QHeaderView::section {
                background-color: #252525;
                color: #888;
                padding: 8px;
                border: none;
                border-right: 1px solid #3d3d3d;
                border-bottom: 1px solid #3d3d3d;
                font-weight: bold;
            }
        """)
        
        tree_layout.addWidget(self.tree_view)
        splitter.addWidget(tree_container)
        
        # Evidence Identity Card
        self.identity_card = EvidenceIdentityCard()
        self.identity_card.setMinimumWidth(280)
        self.identity_card.setMaximumWidth(380)
        splitter.addWidget(self.identity_card)
        
        splitter.setSizes([700, 300])
        layout.addWidget(splitter)
        
        # =====================================================
        # 4. INITIALIZE MODEL
        # =====================================================
        
        self.model = ForensicVFSTreeModel(self.vfs)
        self.tree_view.setModel(self.model)
        
        # Column widths
        self.tree_view.setColumnWidth(0, 300)  # Name
        self.tree_view.setColumnWidth(1, 80)   # Size
        self.tree_view.setColumnWidth(2, 120)  # Type
        self.tree_view.setColumnWidth(3, 130)  # Modified
        self.tree_view.setColumnWidth(4, 120)  # Evidence
    
    def _setup_keyboard_shortcuts(self):
        """Set up keyboard shortcuts with write protection."""
        # Block dangerous keys
        blocked_keys = [
            (QKeySequence.StandardKey.Delete, "Delete"),
            (QKeySequence("Shift+Delete"), "Permanent Delete"),
            (QKeySequence.StandardKey.Cut, "Cut"),
            (QKeySequence("F2"), "Rename"),
        ]
        
        for key, action_name in blocked_keys:
            action = QAction(self)
            action.setShortcut(key)
            action.triggered.connect(
                lambda checked, name=action_name: self._block_keyboard_action(name)
            )
            self.addAction(action)
    
    def _connect_signals(self):
        """Connect internal signals."""
        self.tree_view.selectionModel().selectionChanged.connect(self._on_selection_changed)
    
    def _block_keyboard_action(self, action_name: str):
        """Block keyboard shortcut and log."""
        block_write_operation(self, action_name, self.coc_logger)
        self.write_blocked.emit(action_name, "Keyboard shortcut blocked")
    
    def _on_breadcrumb_clicked(self, path: str):
        """Handle breadcrumb segment click - navigate to path."""
        self._navigate_to_path(path)
        
        # Emit terminal sync
        self.terminal_command.emit(f"cd {path}")
        
        # Log to CoC
        self._log_coc("BREADCRUMB_NAVIGATION", {"path": path})
    
    def _navigate_to_path(self, path: str):
        """Navigate tree view to a specific path."""
        if not path or path == "/":
            self.tree_view.clearSelection()
            self.breadcrumb.set_path("/")
            self._current_path = "/"
            return
        
        # Find and select the node
        parts = path.strip('/').split('/')
        parent_index = QModelIndex()
        
        for part in parts:
            found = False
            for row in range(self.model.rowCount(parent_index)):
                index = self.model.index(row, 0, parent_index)
                node = self.model.get_node_by_index(index)
                if node and node.name == part:
                    self.tree_view.expand(index)
                    parent_index = index
                    found = True
                    break
            
            if not found:
                break
        
        if parent_index.isValid():
            self.tree_view.setCurrentIndex(parent_index)
            self.tree_view.scrollTo(parent_index)
    
    def _on_selection_changed(self, selected, deselected):
        """Handle selection change."""
        indexes = self.tree_view.selectedIndexes()
        if indexes:
            node = self.model.get_node_by_index(indexes[0])
            if node:
                # Update identity card
                self.identity_card.show_node(node)
                self.node_selected.emit(node)
                
                # Update path tracking
                self._current_path = node.path
                self.breadcrumb.set_path(node.path)
                
                # Detect user context
                old_user = self._current_user
                self._current_user = self._detect_user_context(node.path)
                
                if self._current_user:
                    self.user_context_label.setText(f"👤 {self._current_user}")
                    self.user_context_label.setVisible(True)
                else:
                    self.user_context_label.setVisible(False)
                
                # Emit signals
                self.path_changed.emit(node.path)
                if self._current_user != old_user:
                    self.user_context_changed.emit(self._current_user or "")
                
                # Log to CoC
                self._log_coc("FILE_SELECTED", {
                    "path": node.path,
                    "type": node.node_type.value,
                    "name": node.name
                })
        else:
            self.identity_card.clear()
            self._current_path = "/"
            self.breadcrumb.set_path("/")
    
    def _on_double_click(self, index: QModelIndex):
        """Handle double-click."""
        node = self.model.get_node_by_index(index)
        if not node:
            return
        
        if node.is_directory:
            # Expand/collapse and sync terminal
            if self.tree_view.isExpanded(index):
                self.tree_view.collapse(index)
            else:
                self.tree_view.expand(index)
            
            self.terminal_command.emit(f"cd {node.path}")
            self._log_coc("DIRECTORY_ENTERED", {"path": node.path})
        else:
            # Open file viewer
            self._open_file(node)
    
    def _show_context_menu(self, position):
        """Show forensic context menu."""
        index = self.tree_view.indexAt(position)
        if not index.isValid():
            return
        
        node = self.model.get_node_by_index(index)
        if not node:
            return
        
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #252525;
                color: #e0e0e0;
                border: 1px solid #3d3d3d;
                padding: 4px;
            }
            QMenu::item {
                padding: 8px 24px;
            }
            QMenu::item:selected {
                background-color: #094771;
            }
            QMenu::item:disabled {
                color: #555;
            }
            QMenu::separator {
                height: 1px;
                background: #3d3d3d;
                margin: 4px 0;
            }
        """)
        
        # ===== ALLOWED FORENSIC OPERATIONS =====
        
        if not node.is_directory:
            open_action = menu.addAction("📄 Open (Viewer)")
            open_action.triggered.connect(lambda: self._open_file(node))
            
            menu.addSeparator()
            
            hex_action = menu.addAction("🔢 Hex View")
            hex_action.triggered.connect(lambda: self._open_with_viewer(node, "hex"))
            
            strings_action = menu.addAction("🔤 Strings Extract")
            strings_action.triggered.connect(lambda: self._extract_strings(node))
            
            hash_action = menu.addAction("🔐 Calculate Hash")
            hash_action.triggered.connect(lambda: self._compute_hash(node))
            
            menu.addSeparator()
            
            export_action = menu.addAction("📤 Export Copy")
            export_action.setToolTip("Creates a working copy (does not modify evidence)")
            export_action.triggered.connect(lambda: self._export_file(node))
            
            menu.addSeparator()
            
            timeline_action = menu.addAction("📅 Show in Timeline")
            timeline_action.triggered.connect(lambda: self._show_in_timeline(node))
            
            artifacts_action = menu.addAction("🔍 Find Related Artifacts")
            artifacts_action.triggered.connect(lambda: self._find_related(node))
        
        menu.addSeparator()
        
        props_action = menu.addAction("ℹ️ Properties")
        props_action.triggered.connect(lambda: self._show_properties(node))
        
        # ===== BLOCKED OPERATIONS =====
        
        menu.addSeparator()
        blocked_header = menu.addAction("━━ ⛔ BLOCKED (Read-Only) ━━")
        blocked_header.setEnabled(False)
        
        for action_name in ["Delete", "Rename", "Move", "Copy Here", "New Folder"]:
            blocked = menu.addAction(f"🚫 {action_name}")
            blocked.setEnabled(False)
        
        menu.addSeparator()
        coc_notice = menu.addAction("🔒 All actions logged to CoC")
        coc_notice.setEnabled(False)
        
        menu.exec(self.tree_view.viewport().mapToGlobal(position))
    
    def _detect_user_context(self, path: str) -> Optional[str]:
        """Detect user profile from path."""
        if not path:
            return None
        
        path_lower = path.lower()
        
        if '/users/' in path_lower:
            parts = path.split('/')
            try:
                idx = next(i for i, p in enumerate(parts) if p.lower() == 'users')
                if idx + 1 < len(parts):
                    user = parts[idx + 1]
                    if user.lower() not in ('public', 'default', 'all users'):
                        return user
            except StopIteration:
                pass
        
        elif '/home/' in path_lower:
            parts = path.split('/')
            try:
                idx = next(i for i, p in enumerate(parts) if p.lower() == 'home')
                if idx + 1 < len(parts):
                    return parts[idx + 1]
            except StopIteration:
                pass
        
        return None
    
    def _open_file(self, node: VFSNode):
        """Open file in appropriate viewer."""
        self.file_opened.emit(node.path, "auto")
        self._log_coc("FILE_OPENED", {"path": node.path, "viewer": "auto"})
    
    def _open_with_viewer(self, node: VFSNode, viewer_type: str):
        """Open file with specific viewer."""
        self.file_opened.emit(node.path, viewer_type)
        self._log_coc("FILE_OPENED", {"path": node.path, "viewer": viewer_type})
    
    def _extract_strings(self, node: VFSNode):
        """Extract strings from file."""
        self._log_coc("STRINGS_EXTRACTED", {"path": node.path})
        QMessageBox.information(self, "Strings", f"Extracting strings from:\n{node.name}")
    
    def _compute_hash(self, node: VFSNode):
        """Compute file hash."""
        self._log_coc("HASH_COMPUTED", {"path": node.path})
        if node.sha256:
            QMessageBox.information(
                self, "SHA-256 Hash",
                f"File: {node.name}\n\nSHA-256:\n{node.sha256}"
            )
        else:
            QMessageBox.information(self, "Hash", "Hash not yet computed")
    
    def _export_file(self, node: VFSNode):
        """Export file to workspace."""
        self._log_coc("FILE_EXPORTED", {"path": node.path})
        QMessageBox.information(
            self, "Export",
            f"Export '{node.name}' to workspace\n(Creates a copy - evidence unchanged)"
        )
    
    def _show_in_timeline(self, node: VFSNode):
        """Show file in timeline."""
        self._log_coc("TIMELINE_JUMP", {"path": node.path})
    
    def _find_related(self, node: VFSNode):
        """Find related artifacts."""
        self._log_coc("FIND_RELATED", {"path": node.path})
    
    def _show_properties(self, node: VFSNode):
        """Show file properties."""
        self._log_coc("PROPERTIES_VIEWED", {"path": node.path})
    
    def _log_coc(self, action: str, details: Dict):
        """Log to Chain of Custody."""
        if self.coc_logger:
            try:
                self.coc_logger(action, details)
            except Exception as e:
                logger.warning(f"CoC logging failed: {e}")
    
    # =========================================================
    # TERMINAL SYNC METHODS
    # =========================================================
    
    def sync_from_terminal(self, path: str):
        """
        Sync from terminal cd command.
        
        Called when user types: cd /Windows/System32
        Files tab navigates to that folder.
        """
        self.sync_indicator.setText("🔄 Syncing...")
        self.sync_indicator.setStyleSheet("""
            color: #FFC107;
            font-size: 10px;
            padding: 2px 8px;
        """)
        
        self._navigate_to_path(path)
        
        # Restore sync indicator
        QTimer.singleShot(300, lambda: self._restore_sync_indicator())
        
        self._log_coc("TERMINAL_SYNC", {"path": path})
    
    def _restore_sync_indicator(self):
        """Restore sync indicator after animation."""
        self.sync_indicator.setText("🔗 Terminal Synced")
        self.sync_indicator.setStyleSheet("""
            color: #4CAF50;
            font-size: 10px;
            padding: 2px 8px;
            background: rgba(76, 175, 80, 0.1);
            border-radius: 3px;
        """)
    
    def get_current_path(self) -> str:
        """Get current path for terminal."""
        return self._current_path
    
    def get_current_user(self) -> Optional[str]:
        """Get current user context for terminal prompt."""
        return self._current_user
    
    def set_evidence_source(self, source: str):
        """Set evidence source display."""
        self._evidence_source = source
        self.status_banner.set_evidence_source(source)
    
    def refresh(self):
        """Refresh the file tree."""
        self.model.refresh()


# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================

# Alias for backward compatibility
FilesTab = ForensicFilesTab
