"""
FEPD - TAB 2: IMAGE INGEST (Professional Architecture)
=========================================================

The entry point of the entire forensic workflow.

Pipeline:
    User selects image
            ↓
    Case validation
            ↓
    Image loader (E01 / RAW / VMDK)
            ↓
    Hash verification (SHA-256)
            ↓
    Partition discovery
            ↓
    Filesystem mount (read-only)
            ↓
    VEOS virtual drives
            ↓
    Files tab enabled

Image Ingest → Files Tab → Artifacts → Timeline → ML

Architecture:
    UI (this file)  ──►  IngestController  ──►  ImageLoader
                                           ──►  HashVerifier
                                           ──►  PartitionScanner
                                           ──►  FilesystemBuilder
                    ──►  EvidenceManager   ──►  ImageRegistry

Copyright (c) 2026 FEPD Development Team
"""

import csv
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QMessageBox, QGroupBox, QSplitter,
    QLineEdit, QProgressBar, QFrame, QInputDialog,
    QScrollArea, QGridLayout, QSizePolicy,
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QColor, QFont

# Local imports  ── use absolute paths so the module works from any entry-point
import sys
sys.path.insert(0, str(Path(__file__).resolve()).replace("\\", "/").rsplit("/src/", 1)[0])

from src.models.evidence_image import (
    EvidenceImage, ImageFormat, ImageStatus, ImageType,
    SUPPORTED_EXTENSIONS, SUPPORTED_DISK_EXTENSIONS,
    SUPPORTED_MEMORY_EXTENSIONS, FORMAT_DESCRIPTIONS,
)
from src.models.partition import Partition, FilesystemType
from src.ingest.ingest_controller import IngestController, IngestResult
from src.evidence.evidence_manager import EvidenceManager
from src.evidence.image_registry import ImageRegistry
from src.core.case_manager import CaseManager
from src.core.chain_of_custody import ChainLogger
from src.services.evidence_summary import EvidenceSummaryService
from src.services.quick_alerts import QuickAlertsService

logger = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================

MAX_BATCH_IMAGES: int = 10
WARN_SIZE_GB: int = 100
EXPORT_FORMATS: List[str] = ["JSON", "CSV", "HTML"]

# Table column indices
COL_ID       = 0
COL_NAME     = 1
COL_FORMAT   = 2
COL_SIZE     = 3
COL_HASH     = 4
COL_VERIFIED = 5
COL_PARTS    = 6
COL_DRIVES   = 7
COL_STATUS   = 8
EVIDENCE_COLUMNS = [
    "ID", "Image Name", "Format", "Size",
    "SHA-256", "Verified", "Partitions", "VEOS Drives", "Status",
]

PARTITION_COLUMNS = ["Partition", "Filesystem", "Size", "Mount", "Role"]


# ============================================================================
# Background Worker
# ============================================================================

class _IngestWorker(QThread):
    """
    Runs IngestController.run() on a background thread
    so the UI stays responsive during hashing / scanning.
    """

    progress      = pyqtSignal(int, str)          # (pct, message)
    speed_update  = pyqtSignal(float, float)       # (MB/s, ETA_sec)
    finished      = pyqtSignal(object)             # IngestResult
    error         = pyqtSignal(str)                # error message

    def __init__(
        self,
        image_path: str,
        case_path: Path,
        expected_hash: str = "",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.image_path = image_path
        self.case_path = case_path
        self.expected_hash = expected_hash or None
        self._cancelled = False

    def run(self) -> None:
        try:
            ctrl = IngestController(
                case_path=self.case_path,
                operator=os.getenv("USERNAME", os.getenv("USER", "unknown")),
            )
            result = ctrl.run(
                image_path=self.image_path,
                expected_hash=self.expected_hash,
                on_progress=self._on_progress,
                is_cancelled=lambda: self._cancelled,
            )
            if result.success:
                self.finished.emit(result)
            else:
                self.error.emit(result.error or "Unknown error")
        except Exception as exc:
            logger.error("Worker error: %s", exc, exc_info=True)
            self.error.emit(str(exc))

    def cancel(self) -> None:
        self._cancelled = True

    # Map IngestController callbacks → Qt signals
    def _on_progress(self, pct: int, msg: str, speed: float, eta: float) -> None:
        self.progress.emit(pct, msg)
        if speed > 0:
            self.speed_update.emit(speed, eta)


# ============================================================================
# Image Ingest Tab
# ============================================================================

class ImageIngestTab(QWidget):
    """
    TAB 2: IMAGE INGEST — Evidence Acquisition

    The foundation of the entire FEPD system.
    Once this completes:  Image Ingest → Files → Artifacts → Timeline → ML → Report

    Signals:
        ingest_complete(dict):       Emitted after successful ingestion.
        filesystem_ready(bool):      Emitted to enable/disable downstream tabs.
    """

    ingest_complete  = pyqtSignal(dict)
    filesystem_ready = pyqtSignal(bool)

    def __init__(
        self,
        case_manager: CaseManager,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.case_manager = case_manager
        self.evidence_manager = EvidenceManager()
        self.chain_logger: Optional[ChainLogger] = None
        self._worker: Optional[_IngestWorker] = None
        self._batch_queue: List[str] = []
        self._batch_idx: int = 0

        self._init_ui()

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _init_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # ── Header ──
        hdr = QLabel("Image Ingest")
        hdr.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        hdr.setStyleSheet("color: #e0e0e0; padding: 4px 0;")
        root.addWidget(hdr)

        # ── Action buttons ──
        btn_bar = QHBoxLayout()
        btn_bar.setSpacing(8)

        self.btn_add_disk = self._action_button(
            "Add Disk Image", "#1565c0", self._on_add_disk_image,
        )
        self.btn_add_mem = self._action_button(
            "Add Memory Dump", "#00838f", self._on_add_memory_dump,
        )
        self.btn_batch = self._action_button(
            "Batch Import", "#2e7d32", self._on_batch_import,
        )
        self.btn_export = self._action_button(
            "Export Evidence List", "#5d4037", self._on_export_evidence_list,
        )

        btn_bar.addWidget(self.btn_add_disk)
        btn_bar.addWidget(self.btn_add_mem)
        btn_bar.addWidget(self.btn_batch)
        btn_bar.addWidget(self.btn_export)
        btn_bar.addStretch()
        root.addLayout(btn_bar)

        # ── Hash verification ──
        hash_group = QGroupBox("Hash Verification (Optional)")
        hash_group.setStyleSheet(self._group_style())
        hash_lay = QHBoxLayout()
        hash_lay.addWidget(QLabel("Expected SHA-256:"))
        self.txt_expected_hash = QLineEdit()
        self.txt_expected_hash.setPlaceholderText(
            "Paste expected hash here for court-admissible verification"
        )
        hash_lay.addWidget(self.txt_expected_hash)
        btn_import_hash = QPushButton("Import .sha256")
        btn_import_hash.clicked.connect(self._on_import_hash_file)
        hash_lay.addWidget(btn_import_hash)
        hash_group.setLayout(hash_lay)
        root.addWidget(hash_group)

        # ── Splitter: evidence table + partition viewer ──
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Evidence table
        ev_group = QGroupBox("Evidence Table")
        ev_group.setStyleSheet(self._group_style())
        ev_lay = QVBoxLayout()
        self.tbl_evidence = QTableWidget(0, len(EVIDENCE_COLUMNS))
        self.tbl_evidence.setHorizontalHeaderLabels(EVIDENCE_COLUMNS)
        self.tbl_evidence.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.tbl_evidence.horizontalHeader().setSectionResizeMode(
            COL_NAME, QHeaderView.ResizeMode.Stretch
        )
        self.tbl_evidence.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.tbl_evidence.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.tbl_evidence.currentCellChanged.connect(self._on_evidence_selected)
        ev_lay.addWidget(self.tbl_evidence)
        ev_group.setLayout(ev_lay)
        splitter.addWidget(ev_group)

        # Partition viewer
        part_group = QGroupBox("Partition Viewer")
        part_group.setStyleSheet(self._group_style())
        part_lay = QVBoxLayout()
        self.tbl_partitions = QTableWidget(0, len(PARTITION_COLUMNS))
        self.tbl_partitions.setHorizontalHeaderLabels(PARTITION_COLUMNS)
        self.tbl_partitions.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.tbl_partitions.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        part_lay.addWidget(self.tbl_partitions)
        part_group.setLayout(part_lay)
        splitter.addWidget(part_group)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, stretch=1)

        # ── Status / progress panel ──
        status_group = QGroupBox("Ingestion Status")
        status_group.setStyleSheet(self._group_style())
        status_lay = QVBoxLayout()

        self.lbl_status = QLabel("Ready — select an evidence image to begin.")
        self.lbl_status.setStyleSheet("font-size: 13px;")
        status_lay.addWidget(self.lbl_status)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setVisible(False)
        status_lay.addWidget(self.progress_bar)

        speed_lay = QHBoxLayout()
        self.lbl_speed = QLabel("Speed: —")
        speed_lay.addWidget(self.lbl_speed)
        self.lbl_eta = QLabel("ETA: —")
        speed_lay.addWidget(self.lbl_eta)
        speed_lay.addStretch()
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setStyleSheet(
            "background-color: #c62828; color: white; font-weight: bold; "
            "padding: 6px 16px; border-radius: 4px;"
        )
        self.btn_cancel.setVisible(False)
        self.btn_cancel.clicked.connect(self._on_cancel)
        speed_lay.addWidget(self.btn_cancel)
        status_lay.addLayout(speed_lay)

        status_group.setLayout(status_lay)
        root.addWidget(status_group)

        # ── Evidence Overview Dashboard (hidden until ingestion completes) ──
        self._build_dashboard(root)

    # ------------------------------------------------------------------
    # Evidence Overview Dashboard
    # ------------------------------------------------------------------

    def _build_dashboard(self, root: QVBoxLayout) -> None:
        """Build the Smart Evidence Overview Dashboard (initially hidden)."""
        self.dashboard_frame = QFrame()
        self.dashboard_frame.setVisible(False)
        self.dashboard_frame.setStyleSheet(
            "QFrame#dashboard { border: 1px solid #3e3e42; border-radius: 8px; "
            "background: #1e1e1e; }"
        )
        self.dashboard_frame.setObjectName("dashboard")
        dash_root = QVBoxLayout(self.dashboard_frame)
        dash_root.setContentsMargins(16, 12, 16, 16)
        dash_root.setSpacing(12)

        # Dashboard title
        title = QLabel("📊 Smart Evidence Overview")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #4fc3f7; padding-bottom: 4px;")
        dash_root.addWidget(title)

        # ── ROW 1: Evidence Info  |  System Overview ──
        row1 = QHBoxLayout()
        row1.setSpacing(12)

        # -- Evidence Information --
        self._grp_evidence = QGroupBox("Evidence Information")
        self._grp_evidence.setStyleSheet(self._dash_group_style())
        ev_grid = QGridLayout()
        ev_grid.setVerticalSpacing(6)
        ev_grid.setHorizontalSpacing(12)
        self._ev_labels = {}
        ev_fields = [
            ("Image Name", "image_name"),
            ("Image Size", "image_size"),
            ("Filesystem", "filesystem"),
            ("Partitions", "partitions"),
            ("Mount Points", "mount_points"),
            ("SHA-256", "sha256"),
        ]
        for i, (label_text, key) in enumerate(ev_fields):
            lbl = QLabel(f"{label_text}:")
            lbl.setStyleSheet("color: #9e9e9e; font-size: 12px;")
            val = QLabel("—")
            val.setStyleSheet("color: #e0e0e0; font-size: 12px; font-weight: bold;")
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            val.setWordWrap(True)
            ev_grid.addWidget(lbl, i, 0)
            ev_grid.addWidget(val, i, 1)
            self._ev_labels[key] = val
        self._grp_evidence.setLayout(ev_grid)
        row1.addWidget(self._grp_evidence)

        # -- System Overview --
        self._grp_system = QGroupBox("System Overview")
        self._grp_system.setStyleSheet(self._dash_group_style())
        sys_grid = QGridLayout()
        sys_grid.setVerticalSpacing(6)
        sys_grid.setHorizontalSpacing(12)
        self._sys_labels = {}
        sys_fields = [
            ("Operating System", "os"),
            ("Total Files", "total_files"),
            ("Total Folders", "total_folders"),
            ("Deleted Files", "deleted"),
            ("User Accounts", "users"),
        ]
        for i, (label_text, key) in enumerate(sys_fields):
            lbl = QLabel(f"{label_text}:")
            lbl.setStyleSheet("color: #9e9e9e; font-size: 12px;")
            val = QLabel("—")
            val.setStyleSheet("color: #e0e0e0; font-size: 12px; font-weight: bold;")
            sys_grid.addWidget(lbl, i, 0)
            sys_grid.addWidget(val, i, 1)
            self._sys_labels[key] = val
        self._grp_system.setLayout(sys_grid)
        row1.addWidget(self._grp_system)

        dash_root.addLayout(row1)

        # ── ROW 2: User Accounts  |  Recent Activity ──
        row2 = QHBoxLayout()
        row2.setSpacing(12)

        # -- User Accounts Table --
        self._grp_users = QGroupBox("👤 User Accounts")
        self._grp_users.setStyleSheet(self._dash_group_style())
        users_lay = QVBoxLayout()
        self.tbl_users = QTableWidget(0, 4)
        self.tbl_users.setHorizontalHeaderLabels(
            ["User Name", "Home Directory", "Files", "Last Activity"]
        )
        self.tbl_users.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.tbl_users.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_users.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_users.setMaximumHeight(160)
        self.tbl_users.setStyleSheet(self._dash_table_style())
        users_lay.addWidget(self.tbl_users)
        self._grp_users.setLayout(users_lay)
        row2.addWidget(self._grp_users, stretch=3)

        # -- Recent Activity --
        self._grp_activity = QGroupBox("⏱ Recent Activity")
        self._grp_activity.setStyleSheet(self._dash_group_style())
        act_grid = QGridLayout()
        act_grid.setVerticalSpacing(6)
        self._act_labels = {}
        act_fields = [
            ("Last File Created", "created"),
            ("Last File Modified", "modified"),
            ("Last File Accessed", "accessed"),
        ]
        for i, (label_text, key) in enumerate(act_fields):
            lbl = QLabel(f"{label_text}:")
            lbl.setStyleSheet("color: #9e9e9e; font-size: 12px;")
            val = QLabel("—")
            val.setStyleSheet("color: #e0e0e0; font-size: 12px; font-weight: bold;")
            act_grid.addWidget(lbl, i, 0)
            act_grid.addWidget(val, i, 1)
            self._act_labels[key] = val
        self._grp_activity.setLayout(act_grid)
        row2.addWidget(self._grp_activity, stretch=2)

        dash_root.addLayout(row2)

        # ── ROW 3: File Categories  |  Important Folders ──
        row3 = QHBoxLayout()
        row3.setSpacing(12)

        # -- File Category Summary --
        self._grp_categories = QGroupBox("📊 File Category Summary")
        self._grp_categories.setStyleSheet(self._dash_group_style())
        cat_lay = QVBoxLayout()
        self.tbl_categories = QTableWidget(0, 3)
        self.tbl_categories.setHorizontalHeaderLabels(["Category", "Count", "Size"])
        self.tbl_categories.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.tbl_categories.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_categories.setMaximumHeight(220)
        self.tbl_categories.setStyleSheet(self._dash_table_style())
        cat_lay.addWidget(self.tbl_categories)

        # Disk usage bar (text-based — no matplotlib dependency)
        self.lbl_disk_usage = QLabel("")
        self.lbl_disk_usage.setStyleSheet("color: #bbb; font-size: 11px; padding-top: 4px;")
        self.lbl_disk_usage.setWordWrap(True)
        cat_lay.addWidget(self.lbl_disk_usage)

        self._grp_categories.setLayout(cat_lay)
        row3.addWidget(self._grp_categories, stretch=3)

        # -- Important Folders --
        self._grp_folders = QGroupBox("📂 Important Folders")
        self._grp_folders.setStyleSheet(self._dash_group_style())
        folders_lay = QVBoxLayout()
        self.tbl_folders = QTableWidget(0, 3)
        self.tbl_folders.setHorizontalHeaderLabels(["Folder", "Files", "Size"])
        self.tbl_folders.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.tbl_folders.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_folders.setMaximumHeight(220)
        self.tbl_folders.setStyleSheet(self._dash_table_style())
        folders_lay.addWidget(self.tbl_folders)
        self._grp_folders.setLayout(folders_lay)
        row3.addWidget(self._grp_folders, stretch=2)

        dash_root.addLayout(row3)

        # ── ROW 4: Most Active Folders ──
        self._grp_active = QGroupBox("🔥 Most Active Folders")
        self._grp_active.setStyleSheet(self._dash_group_style())
        active_lay = QVBoxLayout()
        self.tbl_active = QTableWidget(0, 3)
        self.tbl_active.setHorizontalHeaderLabels(["Folder", "Modified Files", "Latest Activity"])
        self.tbl_active.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.tbl_active.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_active.setMaximumHeight(180)
        self.tbl_active.setStyleSheet(self._dash_table_style())
        active_lay.addWidget(self.tbl_active)
        self._grp_active.setLayout(active_lay)
        dash_root.addWidget(self._grp_active)

        # ── ROW 5: Quick Alerts ──
        self._grp_alerts = QGroupBox("⚠️ Quick Alerts — Suspicious Indicators")
        self._grp_alerts.setStyleSheet(self._dash_group_style())
        alerts_lay = QVBoxLayout()
        self.lbl_alerts = QLabel("No alerts.")
        self.lbl_alerts.setStyleSheet("color: #bbb; font-size: 12px;")
        self.lbl_alerts.setWordWrap(True)
        alerts_lay.addWidget(self.lbl_alerts)
        self._grp_alerts.setLayout(alerts_lay)
        dash_root.addWidget(self._grp_alerts)

        # Wrap dashboard in a scroll area so it works on small screens
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.dashboard_frame)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setVisible(False)
        self._dashboard_scroll = scroll
        root.addWidget(scroll, stretch=2)

    # ------------------------------------------------------------------
    # Dashboard population
    # ------------------------------------------------------------------

    def show_evidence_dashboard(self, summary, alerts=None) -> None:
        """
        Populate and reveal the Evidence Overview Dashboard.

        Parameters
        ----------
        summary : EvidenceSummary
            Output of ``EvidenceSummaryService.generate()``.
        alerts : list[Alert], optional
            Output of ``QuickAlertsService.scan()``.
        """
        # ── Evidence info ──
        self._ev_labels["image_name"].setText(summary.image_name or "—")
        self._ev_labels["image_size"].setText(summary.image_size_display or "—")
        self._ev_labels["filesystem"].setText(summary.filesystem or "—")
        self._ev_labels["partitions"].setText(str(summary.partition_count))
        self._ev_labels["mount_points"].setText(
            ", ".join(summary.mount_points) if summary.mount_points else "—"
        )
        sha = summary.sha256 or "—"
        self._ev_labels["sha256"].setText(sha[:16] + "…" if len(sha) > 16 else sha)
        self._ev_labels["sha256"].setToolTip(sha)

        # ── System overview ──
        self._sys_labels["os"].setText(summary.os_detected or "—")
        self._sys_labels["total_files"].setText(f"{summary.total_files:,}")
        self._sys_labels["total_folders"].setText(f"{summary.total_folders:,}")
        self._sys_labels["deleted"].setText(f"{summary.total_deleted:,}")
        self._sys_labels["users"].setText(str(len(summary.user_accounts)))

        # ── User accounts ──
        self.tbl_users.setRowCount(0)
        for u in summary.user_accounts:
            row = self.tbl_users.rowCount()
            self.tbl_users.insertRow(row)
            self.tbl_users.setItem(row, 0, QTableWidgetItem(u.username))
            self.tbl_users.setItem(row, 1, QTableWidgetItem(u.home_path))
            self.tbl_users.setItem(row, 2, QTableWidgetItem(f"{u.file_count:,}"))
            self.tbl_users.setItem(
                row, 3, QTableWidgetItem(self._fmt_ts(u.last_activity))
            )

        # ── Recent activity ──
        self._act_labels["created"].setText(self._fmt_ts(summary.last_file_created))
        self._act_labels["modified"].setText(self._fmt_ts(summary.last_file_modified))
        self._act_labels["accessed"].setText(self._fmt_ts(summary.last_file_accessed))

        # ── File categories ──
        self.tbl_categories.setRowCount(0)
        cat_order = [
            "Images", "Videos", "Documents", "Executables",
            "Archives", "Audio", "Databases", "Email", "Other",
        ]
        for cat in cat_order:
            cnt = summary.category_counts.get(cat, 0)
            if cnt == 0:
                continue
            row = self.tbl_categories.rowCount()
            self.tbl_categories.insertRow(row)
            self.tbl_categories.setItem(row, 0, QTableWidgetItem(cat))
            self.tbl_categories.setItem(row, 1, QTableWidgetItem(f"{cnt:,}"))
            sz = summary.category_sizes.get(cat, 0)
            self.tbl_categories.setItem(row, 2, QTableWidgetItem(self._human_size(sz)))

        # Disk usage text bar
        usage_parts = []
        for cat, pct in summary.disk_usage_pct.items():
            if pct >= 1.0:
                usage_parts.append(f"{cat}: {pct:.0f}%")
        self.lbl_disk_usage.setText("Disk usage: " + "  ·  ".join(usage_parts) if usage_parts else "")

        # ── Important folders ──
        self.tbl_folders.setRowCount(0)
        for f in summary.important_folders:
            row = self.tbl_folders.rowCount()
            self.tbl_folders.insertRow(row)
            self.tbl_folders.setItem(row, 0, QTableWidgetItem(f.name))
            self.tbl_folders.setItem(row, 1, QTableWidgetItem(f"{f.file_count:,}"))
            self.tbl_folders.setItem(row, 2, QTableWidgetItem(self._human_size(f.total_size)))

        # ── Most active folders ──
        self.tbl_active.setRowCount(0)
        for f in summary.most_active_folders:
            row = self.tbl_active.rowCount()
            self.tbl_active.insertRow(row)
            self.tbl_active.setItem(row, 0, QTableWidgetItem(f.name or f.path))
            self.tbl_active.setItem(row, 1, QTableWidgetItem(f"{f.modified_count:,}"))
            self.tbl_active.setItem(
                row, 2, QTableWidgetItem(self._fmt_ts(f.latest_modified))
            )

        # ── Quick alerts ──
        if alerts:
            lines = []
            for a in alerts:
                sev_color = {
                    "high": "#f44336", "medium": "#ff9800", "low": "#4caf50"
                }.get(a.severity, "#bbb")
                lines.append(
                    f'<span style="color:{sev_color}; font-weight:bold;">'
                    f'{a.icon} {a.title}</span> — {a.detail}'
                )
            self.lbl_alerts.setText("<br>".join(lines))
            self._grp_alerts.setVisible(True)
        else:
            self.lbl_alerts.setText(
                '<span style="color:#4caf50;">✅ No suspicious indicators detected.</span>'
            )
            self._grp_alerts.setVisible(True)

        # Show dashboard
        self.dashboard_frame.setVisible(True)
        self._dashboard_scroll.setVisible(True)

    def _generate_dashboard(self, evidence: EvidenceImage) -> None:
        """Run the summary + alerts services and populate the dashboard."""
        try:
            vfs = getattr(self, "_vfs", None)
            if vfs is None:
                # Try to obtain VFS through the parent main window
                main = self.window()
                vfs = getattr(main, "vfs", None)
            if vfs is None:
                logger.warning("VFS not available — dashboard skipped")
                return
            summary = EvidenceSummaryService(vfs).generate(
                image_name=evidence.name,
                image_size=evidence.size,
                sha256=evidence.sha256,
                filesystem=getattr(evidence, "filesystem", ""),
                partitions=getattr(evidence, "partitions", None),
            )
            alerts = QuickAlertsService(vfs).scan()
            self.show_evidence_dashboard(summary, alerts)
        except Exception as exc:
            logger.error("Dashboard generation failed: %s", exc)

    # ------------------------------------------------------------------
    # Dashboard style helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dash_group_style() -> str:
        return (
            "QGroupBox { font-weight: bold; font-size: 12px; color: #bbb; "
            "border: 1px solid #3e3e42; border-radius: 6px; margin-top: 8px; "
            "padding-top: 14px; background: #252526; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; "
            "padding: 0 6px; color: #ccc; }"
        )

    @staticmethod
    def _dash_table_style() -> str:
        return (
            "QTableWidget { background: #1e1e1e; alternate-background-color: #252526; "
            "gridline-color: #3e3e42; font-size: 11px; }"
            "QHeaderView::section { background: #2d2d30; color: #ccc; "
            "border: 1px solid #3e3e42; padding: 4px; font-weight: bold; }"
        )

    @staticmethod
    def _fmt_ts(ts: Optional[str]) -> str:
        """Format a timestamp string for display."""
        if not ts:
            return "—"
        # Truncate to first 19 chars (YYYY-MM-DD HH:MM:SS)
        return ts[:19] if len(ts) > 19 else ts

    @staticmethod
    def _human_size(size: float) -> str:
        if size <= 0:
            return "0 B"
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(size) < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    # ------------------------------------------------------------------
    # Button actions
    # ------------------------------------------------------------------

    def _on_add_disk_image(self) -> None:
        """Add a single disk image (E01 / RAW / DD / IMG / VMDK / …)."""
        if not self._check_case():
            return
        exts = " ".join(f"*{e}" for e in sorted(SUPPORTED_DISK_EXTENSIONS))
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Disk Image",
            str(Path.home()),
            f"Disk Images ({exts});;All Files (*)",
        )
        if path:
            self._warn_and_start(path)

    def _on_add_memory_dump(self) -> None:
        """Add a memory dump (.mem / .vmem)."""
        if not self._check_case():
            return
        exts = " ".join(f"*{e}" for e in sorted(SUPPORTED_MEMORY_EXTENSIONS))
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Memory Dump",
            str(Path.home()),
            f"Memory Dumps ({exts});;All Files (*)",
        )
        if path:
            self._warn_and_start(path)

    def _on_batch_import(self) -> None:
        """Select multiple images for sequential ingestion."""
        if not self._check_case():
            return
        exts = " ".join(f"*{e}" for e in sorted(SUPPORTED_EXTENSIONS))
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            f"Select Evidence Images (max {MAX_BATCH_IMAGES})",
            str(Path.home()),
            f"Forensic Images ({exts});;All Files (*)",
        )
        if not paths:
            return
        if len(paths) > MAX_BATCH_IMAGES:
            QMessageBox.warning(
                self, "Too Many Files",
                f"Selected {len(paths)} files — maximum is {MAX_BATCH_IMAGES}.\n"
                "Please reduce selection or ingest in multiple batches.",
            )
            return
        self._batch_queue = paths
        self._batch_idx = 0
        self._process_next_batch()

    def _on_export_evidence_list(self) -> None:
        """Export current evidence table to JSON / CSV / HTML."""
        if self.tbl_evidence.rowCount() == 0:
            QMessageBox.information(self, "Nothing to Export", "No evidence loaded yet.")
            return
        fmt, ok = QInputDialog.getItem(
            self, "Export Format", "Select format:", EXPORT_FORMATS, 0, False,
        )
        if not ok:
            return
        ext = fmt.lower()
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Evidence List",
            str(Path.home() / f"evidence_list.{ext}"),
            f"{fmt} Files (*.{ext});;All Files (*)",
        )
        if path:
            self._export_to_file(path, fmt)

    def _on_import_hash_file(self) -> None:
        """Load an expected hash from a .sha256 / .md5 sidecar file."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Hash File",
            str(Path.home()),
            "Hash Files (*.sha256 *.md5 *.sha1);;All Files (*)",
        )
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8").strip()
            hash_val = content.split()[0]
            self.txt_expected_hash.setText(hash_val)
        except Exception as exc:
            QMessageBox.critical(self, "Import Error", f"Failed to read hash file:\n{exc}")

    def _on_cancel(self) -> None:
        """Cancel the running ingestion."""
        if self._worker and self._worker.isRunning():
            reply = QMessageBox.question(
                self, "Cancel",
                "Cancel the ongoing ingestion? Progress will be lost.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._worker.cancel()
                self._hide_progress("Cancelled by user.")

    # ------------------------------------------------------------------
    # Case validation  (Step 1)
    # ------------------------------------------------------------------

    def _check_case(self) -> bool:
        """Verify a case is loaded before ingestion."""
        if self.case_manager and self.case_manager.current_case:
            return True
        QMessageBox.warning(
            self,
            "No Case Loaded",
            "Please create or open a case first.\n\n"
            "Go to the Case tab to create or load a case.",
        )
        return False

    # ------------------------------------------------------------------
    # Ingestion launch
    # ------------------------------------------------------------------

    def _warn_and_start(self, image_path: str) -> None:
        """Show a size warning if needed, then start ingestion."""
        size_gb = Path(image_path).stat().st_size / (1024 ** 3)
        if size_gb > WARN_SIZE_GB:
            reply = QMessageBox.question(
                self,
                "Large Image",
                f"Image is {size_gb:.1f} GB — hashing may take a while.\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        self._start_ingestion(image_path)

    def _start_ingestion(self, image_path: str) -> None:
        """Kick off the background ingestion worker."""
        case_path = Path(self.case_manager.current_case["path"])

        # Init CoC logger
        self.chain_logger = ChainLogger(str(case_path))
        self.chain_logger.log(
            action="EVIDENCE_INGEST_START",
            operator=os.getenv("USERNAME", "unknown"),
            details={"source_image": image_path, "timestamp": datetime.now().isoformat()},
        )

        # Show progress
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.btn_cancel.setVisible(True)
        self.lbl_status.setText(f"Ingesting: {Path(image_path).name}")
        self.lbl_speed.setText("Speed: —")
        self.lbl_eta.setText("ETA: —")

        # Disable buttons during ingestion
        self._set_buttons_enabled(False)

        self._worker = _IngestWorker(
            image_path=image_path,
            case_path=case_path,
            expected_hash=self.txt_expected_hash.text().strip(),
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.speed_update.connect(self._on_speed)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    # ------------------------------------------------------------------
    # Worker signal handlers
    # ------------------------------------------------------------------

    def _on_progress(self, pct: int, msg: str) -> None:
        self.progress_bar.setValue(pct)
        self.lbl_status.setText(msg)

    def _on_speed(self, speed: float, eta: float) -> None:
        self.lbl_speed.setText(f"Speed: {speed:.1f} MB/s")
        if eta < 60:
            self.lbl_eta.setText(f"ETA: {eta:.0f}s")
        else:
            m, s = divmod(int(eta), 60)
            self.lbl_eta.setText(f"ETA: {m}m {s}s")

    def _on_finished(self, result: IngestResult) -> None:
        """Handle successful ingestion."""
        self._hide_progress(
            f"Ingestion complete — {result.evidence.name} ({result.elapsed:.1f}s)"
        )

        evidence = result.evidence
        partitions = result.partitions

        # Register with evidence manager
        self.evidence_manager.register(evidence, partitions)

        # Register with global image registry
        try:
            registry = ImageRegistry(Path("cases"))
            case_id = self.case_manager.current_case.get("case_id", "")
            registry.register(
                sha256=evidence.sha256,
                case_id=case_id,
                name=evidence.name,
                image_format=evidence.format.value,
                evidence_id=evidence.evidence_id,
            )
        except Exception as exc:
            logger.warning("Registry update failed: %s", exc)

        # Chain of Custody
        if self.chain_logger:
            self.chain_logger.log(
                action="EVIDENCE_INGEST_COMPLETE",
                operator=os.getenv("USERNAME", "unknown"),
                details={
                    "evidence_id": evidence.evidence_id,
                    "hash": evidence.sha256,
                    "hash_verified": evidence.hash_verified,
                    "partitions": len(partitions),
                    "veos_drives": evidence.veos_drives,
                    "ingestion_time": result.elapsed,
                },
            )

        # Populate UI tables
        self._add_evidence_row(evidence)
        self._populate_partition_table(partitions)

        # ── Smart Evidence Overview Dashboard ──
        self._generate_dashboard(evidence)

        # Signal downstream tabs
        self.ingest_complete.emit(result.to_dict())
        self.filesystem_ready.emit(True)

        QMessageBox.information(
            self,
            "Ingestion Complete",
            f"Evidence: {evidence.name}\n"
            f"Hash: {evidence.hash_short}\n"
            f"Verified: {'Yes' if evidence.hash_verified else 'N/A'}\n"
            f"Partitions: {len(partitions)}\n"
            f"VEOS Drives: {', '.join(evidence.veos_drives)}\n"
            f"Time: {result.elapsed:.1f}s",
        )

        # Batch continuation
        if self._batch_queue:
            self._batch_idx += 1
            self._process_next_batch()

    def _on_error(self, msg: str) -> None:
        """Handle ingestion error."""
        self._hide_progress("Error")

        if self.chain_logger:
            self.chain_logger.log(
                action="EVIDENCE_INGEST_ERROR",
                operator=os.getenv("USERNAME", "unknown"),
                details={"error": msg},
            )

        QMessageBox.critical(self, "Ingestion Failed", msg)

        if self._batch_queue:
            self._batch_idx += 1
            self._process_next_batch()

    # ------------------------------------------------------------------
    # Evidence table
    # ------------------------------------------------------------------

    def _add_evidence_row(self, ev: EvidenceImage) -> None:
        """Insert one row into the evidence table."""
        row = self.tbl_evidence.rowCount()
        self.tbl_evidence.insertRow(row)

        self.tbl_evidence.setItem(row, COL_ID,       QTableWidgetItem(ev.evidence_id))
        self.tbl_evidence.setItem(row, COL_NAME,     QTableWidgetItem(ev.name))
        self.tbl_evidence.setItem(row, COL_FORMAT,   QTableWidgetItem(ev.format_display))
        self.tbl_evidence.setItem(row, COL_SIZE,     QTableWidgetItem(ev.size_display))
        self.tbl_evidence.setItem(row, COL_HASH,     QTableWidgetItem(ev.hash_short))

        v_item = QTableWidgetItem("Yes" if ev.hash_verified else "N/A")
        v_item.setForeground(QColor("#4caf50") if ev.hash_verified else QColor("#9e9e9e"))
        self.tbl_evidence.setItem(row, COL_VERIFIED, v_item)

        self.tbl_evidence.setItem(row, COL_PARTS,    QTableWidgetItem(str(len(ev.partitions))))
        self.tbl_evidence.setItem(row, COL_DRIVES,   QTableWidgetItem(", ".join(ev.veos_drives)))

        s_item = QTableWidgetItem(ev.status.value)
        if ev.is_loaded:
            s_item.setForeground(QColor("#4caf50"))
        elif ev.is_error:
            s_item.setForeground(QColor("#f44336"))
        self.tbl_evidence.setItem(row, COL_STATUS, s_item)

    # ------------------------------------------------------------------
    # Partition table
    # ------------------------------------------------------------------

    def _populate_partition_table(self, partitions: List[Partition]) -> None:
        """Fill the partition viewer from a list of Partition objects."""
        self.tbl_partitions.setRowCount(0)
        for p in partitions:
            row = self.tbl_partitions.rowCount()
            self.tbl_partitions.insertRow(row)
            self.tbl_partitions.setItem(row, 0, QTableWidgetItem(str(p.id)))
            self.tbl_partitions.setItem(row, 1, QTableWidgetItem(p.filesystem.value))
            self.tbl_partitions.setItem(row, 2, QTableWidgetItem(p.size_display))
            self.tbl_partitions.setItem(row, 3, QTableWidgetItem(p.mount_point))
            self.tbl_partitions.setItem(row, 4, QTableWidgetItem(p.role.value))

    def _on_evidence_selected(self, row: int, *_) -> None:
        """When user clicks an evidence row, show its partitions."""
        if row < 0:
            return
        id_item = self.tbl_evidence.item(row, COL_ID)
        if not id_item:
            return
        eid = id_item.text()
        parts = self.evidence_manager.get_partitions(eid)
        self._populate_partition_table(parts)

    # ------------------------------------------------------------------
    # Batch processing
    # ------------------------------------------------------------------

    def _process_next_batch(self) -> None:
        if self._batch_idx < len(self._batch_queue):
            path = self._batch_queue[self._batch_idx]
            self.lbl_status.setText(
                f"Batch {self._batch_idx + 1}/{len(self._batch_queue)}: "
                f"{Path(path).name}"
            )
            self._start_ingestion(path)
        else:
            self._batch_queue = []
            self._batch_idx = 0
            QMessageBox.information(self, "Batch Complete", "All images processed.")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _export_to_file(self, path: str, fmt: str) -> None:
        """Export the evidence table to a file."""
        rows: List[Dict[str, str]] = []
        for r in range(self.tbl_evidence.rowCount()):
            rows.append({
                col: (self.tbl_evidence.item(r, c).text() if self.tbl_evidence.item(r, c) else "")
                for c, col in enumerate(EVIDENCE_COLUMNS)
            })
        try:
            if fmt == "JSON":
                Path(path).write_text(json.dumps(rows, indent=2), encoding="utf-8")
            elif fmt == "CSV":
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=EVIDENCE_COLUMNS)
                    w.writeheader()
                    w.writerows(rows)
            elif fmt == "HTML":
                html = (
                    "<html><head><style>table{border-collapse:collapse;width:100%}"
                    "th,td{border:1px solid #555;padding:6px;text-align:left}"
                    "th{background:#1e1e1e;color:#e0e0e0}</style></head><body>\n"
                    "<h2>FEPD Evidence List</h2>\n<table>\n<tr>"
                    + "".join(f"<th>{c}</th>" for c in EVIDENCE_COLUMNS)
                    + "</tr>\n"
                )
                for row in rows:
                    html += "<tr>" + "".join(f"<td>{row[c]}</td>" for c in EVIDENCE_COLUMNS) + "</tr>\n"
                html += "</table></body></html>"
                Path(path).write_text(html, encoding="utf-8")

            QMessageBox.information(self, "Exported", f"Evidence list saved to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", str(exc))

    # ------------------------------------------------------------------
    # Load existing evidence when case is opened
    # ------------------------------------------------------------------

    def set_case(self, case_info: Dict[str, Any]) -> None:
        """Called when a case is opened / switched."""
        case_path = Path(case_info.get("path", ""))
        self.evidence_manager = EvidenceManager(case_path)
        self.evidence_manager.load_from_db()
        self._rebuild_tables()

    def _rebuild_tables(self) -> None:
        """Rebuild UI tables from the evidence manager."""
        self.tbl_evidence.setRowCount(0)
        self.tbl_partitions.setRowCount(0)
        for img in self.evidence_manager.images:
            self._add_evidence_row(img)
        # Show partitions for first image
        if self.evidence_manager.images:
            first = self.evidence_manager.images[0]
            parts = self.evidence_manager.get_partitions(first.evidence_id)
            self._populate_partition_table(parts)
            self.filesystem_ready.emit(self.evidence_manager.is_ready)

    # ------------------------------------------------------------------
    # UI helpers
    # ------------------------------------------------------------------

    def _hide_progress(self, status_text: str) -> None:
        self.progress_bar.setVisible(False)
        self.btn_cancel.setVisible(False)
        self.lbl_status.setText(status_text)
        self.lbl_speed.setText("Speed: —")
        self.lbl_eta.setText("ETA: —")
        self._set_buttons_enabled(True)

    def _set_buttons_enabled(self, enabled: bool) -> None:
        self.btn_add_disk.setEnabled(enabled)
        self.btn_add_mem.setEnabled(enabled)
        self.btn_batch.setEnabled(enabled)

    @staticmethod
    def _action_button(text: str, color: str, slot) -> QPushButton:
        btn = QPushButton(text)
        btn.setMinimumHeight(38)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(
            f"QPushButton {{ background-color: {color}; color: white; "
            f"font-weight: bold; font-size: 13px; padding: 6px 18px; "
            f"border-radius: 4px; }}"
            f"QPushButton:hover {{ background-color: {color}cc; }}"
            f"QPushButton:disabled {{ background-color: #555; color: #999; }}"
        )
        btn.clicked.connect(slot)
        return btn

    @staticmethod
    def _group_style() -> str:
        return (
            "QGroupBox { font-weight: bold; font-size: 13px; "
            "border: 1px solid #444; border-radius: 6px; margin-top: 8px; "
            "padding-top: 14px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 12px; "
            "padding: 0 6px; }"
        )
