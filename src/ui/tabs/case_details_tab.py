"""
Case Details Tab Widget for FEPD
Forensic Investigation Dashboard — Case overview, summary, progress, alerts.
"""

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QFormLayout, QPushButton, QTextEdit,
    QScrollArea, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox, QFileDialog, QSplitter,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor

logger = logging.getLogger(__name__)

# Reusable group box style
_GROUP_STYLE = """
    QGroupBox {
        font-weight: bold;
        border: 2px solid #3d3d3d;
        border-radius: 5px;
        margin-top: 10px;
        padding-top: 10px;
        color: #e0e0e0;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 5px;
    }
"""

_LABEL_STYLE = "font-weight: normal; font-size: 11pt; color: #d4d4d4;"
_BTN_STYLE = (
    "QPushButton { background: #1565c0; color: white; font-weight: bold; "
    "padding: 6px 14px; border-radius: 4px; font-size: 11px; }"
    "QPushButton:hover { background: #1976d2; }"
)


class CaseDetailsTab(QWidget):
    """
    Forensic Investigation Dashboard.
    Shows case metadata, evidence summary, progress, alerts,
    chain of custody, notes, integrity status, and quick navigation.
    """

    # Signals for quick navigation
    navigate_to_tab = pyqtSignal(str)  # tab name

    def __init__(self, case_metadata: dict, case_path: Path, parent=None):
        super().__init__(parent)
        self.case_path = Path(case_path)
        self.case_metadata = self._merge_case_metadata(case_metadata or {})
        self._init_ui()
        logger.info("Case Details Tab initialized")

    def _merge_case_metadata(self, incoming: dict) -> dict:
        """Merge incoming metadata with case.json fallback to avoid blank fields."""
        merged = dict(incoming or {})
        case_json = self.case_path / "case.json"
        file_meta = {}
        if case_json.exists():
            try:
                file_meta = json.loads(case_json.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.debug("Could not load case.json metadata: %s", exc)

        for key in ("case_id", "case_name", "investigator", "created_date", "last_modified", "status"):
            if not merged.get(key):
                merged[key] = file_meta.get(key)

        ev_in = merged.get("evidence_image") if isinstance(merged.get("evidence_image"), dict) else {}
        ev_file = file_meta.get("evidence_image") if isinstance(file_meta.get("evidence_image"), dict) else {}
        if not ev_file:
            # Support alternate metadata layouts.
            ev_list = file_meta.get("evidence_images") if isinstance(file_meta.get("evidence_images"), list) else []
            if ev_list and isinstance(ev_list[0], dict):
                ev_file = ev_list[0]
            elif isinstance(file_meta.get("evidence"), dict):
                ev_file = file_meta.get("evidence", {})
        merged_ev = dict(ev_file)
        merged_ev.update({k: v for k, v in ev_in.items() if v not in (None, "")})
        if merged_ev:
            merged["evidence_image"] = merged_ev

        if not merged.get("case_id"):
            merged["case_id"] = self.case_path.name
        return merged

    # ════════════════════════════════════════════════════════════════
    # UI CONSTRUCTION
    # ════════════════════════════════════════════════════════════════

    def _init_ui(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background-color: #2a303b; }")

        content = QWidget()
        content.setMinimumWidth(800)
        main = QVBoxLayout(content)
        main.setSpacing(16)
        main.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Forensic Investigation Dashboard")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #4fc3f7;")
        main.addWidget(title)

        # Row 1: Case Details + Evidence Image (side by side)
        row1 = QSplitter(Qt.Orientation.Horizontal)
        row1.addWidget(self._create_case_details_group())
        row1.addWidget(self._create_evidence_info_group())
        row1.setSizes([500, 500])
        main.addWidget(row1)

        # Case Summary
        main.addWidget(self._create_case_summary_group())

        # Evidence Inventory
        main.addWidget(self._create_evidence_inventory_group())

        # Chain of Custody
        main.addWidget(self._create_chain_of_custody_group())

        # Investigator Notes
        main.addWidget(self._create_notes_group())

        # Quick Navigation
        main.addWidget(self._create_quick_nav_group())

        main.addStretch()
        scroll.setWidget(content)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)

    # ════════════════════════════════════════════════════════════════
    # 1. CASE DETAILS
    # ════════════════════════════════════════════════════════════════

    def _create_case_details_group(self) -> QGroupBox:
        group = QGroupBox("Case Details")
        group.setStyleSheet(_GROUP_STYLE)
        group.setMinimumHeight(150)
        layout = QFormLayout()
        layout.setSpacing(8)
        layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        fields = [
            ("Case ID:", self.case_metadata.get('case_id', 'N/A')),
            ("Case Name:", self.case_metadata.get('case_name', 'N/A')),
            ("Investigator:", self.case_metadata.get('investigator', 'N/A')),
            ("Created:", self._fmt_date(self.case_metadata.get('created_date', 'N/A'))),
            ("Last Modified:", self._fmt_date(self.case_metadata.get('last_modified', 'N/A'))),
            ("Status:", (self.case_metadata.get('status', 'Active') or 'Active').upper()),
        ]
        for label_text, value in fields:
            lbl = QLabel(str(value))
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            lbl.setStyleSheet(_LABEL_STYLE)
            lbl.setWordWrap(True)
            layout.addRow(f"<b>{label_text}</b>", lbl)

        group.setLayout(layout)
        return group

    # ════════════════════════════════════════════════════════════════
    # 2. EVIDENCE IMAGE INFO
    # ════════════════════════════════════════════════════════════════

    def _create_evidence_info_group(self) -> QGroupBox:
        group = QGroupBox("Evidence Image Information")
        group.setStyleSheet(_GROUP_STYLE)
        group.setMinimumHeight(150)
        layout = QFormLayout()
        layout.setSpacing(8)
        layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        ev = self.case_metadata.get('evidence_image', {})
        fields = [
            ("Filename:", ev.get('filename', 'N/A')),
            ("Path:", ev.get('path', 'N/A')),
            ("File Size:", self._fmt_size(ev.get('size_bytes', 0))),
            ("SHA-256:", ev.get('sha256_hash', 'N/A')),
        ]
        for label_text, value in fields:
            lbl = QLabel(str(value))
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            lbl.setStyleSheet(_LABEL_STYLE)
            lbl.setWordWrap(True)
            if label_text == "SHA-256:":
                lbl.setStyleSheet(_LABEL_STYLE + " font-family: monospace; font-size: 10pt;")
            layout.addRow(f"<b>{label_text}</b>", lbl)

        group.setLayout(layout)
        return group

    # ════════════════════════════════════════════════════════════════
    # 3. CASE SUMMARY (reads from VFS database)
    # ════════════════════════════════════════════════════════════════

    def _create_case_summary_group(self) -> QGroupBox:
        group = QGroupBox("Case Summary")
        group.setStyleSheet(_GROUP_STYLE)
        group.setMinimumHeight(200)
        layout = QVBoxLayout()
        layout.setSpacing(6)

        stats = self._query_case_stats()
        grid = QFormLayout()
        grid.setSpacing(4)

        stat_items = [
            ("Evidence Images:", str(stats.get('images', 1))),
            ("Partitions Found:", str(stats.get('partitions', 1))),
            ("Total Files Indexed:", f"{stats.get('total_files', 0):,}"),
            ("Deleted Files:", f"{stats.get('deleted_files', 0):,}"),
            ("Carved Files:", f"{stats.get('carved_files', 0):,}"),
            ("Artifacts Extracted:", f"{stats.get('artifacts', 0):,}"),
            ("Timeline Events:", f"{stats.get('events', 0):,}"),
            ("Anomalies Detected:", str(stats.get('anomalies', 0))),
            ("High Risk Events:", str(stats.get('high_risk', 0))),
        ]
        for label_text, value in stat_items:
            val_lbl = QLabel(value)
            val_lbl.setStyleSheet("font-weight: bold; font-size: 12pt; color: #4fc3f7;")
            grid.addRow(f"<b style='color:#aaa;'>{label_text}</b>", val_lbl)

        layout.addLayout(grid)
        group.setLayout(layout)
        return group

    def _query_case_stats(self) -> dict:
        """Query case database for summary statistics."""
        stats = {
            'images': 1, 'partitions': 1, 'total_files': 0,
            'deleted_files': 0, 'carved_files': 0, 'artifacts': 0,
            'events': 0, 'anomalies': 0, 'high_risk': 0,
        }
        # Try VFS database
        for db_name in ("vfs.db", "evidence.db"):
            db_path = self.case_path / db_name
            if db_path.exists():
                try:
                    conn = sqlite3.connect(str(db_path))
                    cur = conn.cursor()
                    # Total files
                    try:
                        cur.execute("SELECT COUNT(*) FROM files")
                        stats['total_files'] = cur.fetchone()[0]
                    except sqlite3.OperationalError:
                        pass
                    # Deleted files
                    try:
                        cur.execute("SELECT COUNT(*) FROM files WHERE is_deleted = 1")
                        stats['deleted_files'] = cur.fetchone()[0]
                    except sqlite3.OperationalError:
                        try:
                            cur.execute("SELECT COUNT(*) FROM files WHERE deleted = 1")
                            stats['deleted_files'] = cur.fetchone()[0]
                        except sqlite3.OperationalError:
                            pass
                    # Carved files
                    try:
                        cur.execute("SELECT COUNT(*) FROM files WHERE is_carved = 1")
                        stats['carved_files'] = cur.fetchone()[0]
                    except sqlite3.OperationalError:
                        try:
                            cur.execute("SELECT COUNT(*) FROM files WHERE carved = 1")
                            stats['carved_files'] = cur.fetchone()[0]
                        except sqlite3.OperationalError:
                            pass
                    conn.close()
                except Exception as e:
                    logger.debug(f"Stats query failed on {db_name}: {e}")

        # Try events database
        for db_name in ("vfs.db", "evidence.db", "case.db"):
            db_path = self.case_path / db_name
            if db_path.exists():
                try:
                    conn = sqlite3.connect(str(db_path))
                    cur = conn.cursor()
                    try:
                        cur.execute("SELECT COUNT(*) FROM events")
                        stats['events'] = cur.fetchone()[0]
                    except sqlite3.OperationalError:
                        pass
                    try:
                        cur.execute("SELECT COUNT(*) FROM artifacts")
                        stats['artifacts'] = cur.fetchone()[0]
                    except sqlite3.OperationalError:
                        pass
                    conn.close()
                except Exception:
                    pass

        # Case-normalized fallback from unified index tables.
        case_db = self.case_path / "case.db"
        if case_db.exists():
            try:
                conn = sqlite3.connect(str(case_db))
                cur = conn.cursor()
                try:
                    cur.execute("SELECT COUNT(*) FROM ui_files")
                    stats['total_files'] = max(stats['total_files'], int(cur.fetchone()[0] or 0))
                except sqlite3.OperationalError:
                    pass
                try:
                    cur.execute("SELECT COUNT(*) FROM ui_artifacts")
                    stats['artifacts'] = max(stats['artifacts'], int(cur.fetchone()[0] or 0))
                except sqlite3.OperationalError:
                    pass
                conn.close()
            except Exception as exc:
                logger.debug("Could not query normalized case stats: %s", exc)

        ev = self.case_metadata.get('evidence_image', {}) if isinstance(self.case_metadata.get('evidence_image'), dict) else {}
        if ev and stats['images'] == 1:
            stats['images'] = 1
            parts = ev.get('partitions')
            if isinstance(parts, list):
                stats['partitions'] = max(1, len(parts))

        # Runtime ML summary fallback (written by ML Analytics tab after analysis).
        runtime_ml = self.case_path / "results" / "runtime_ml_summary.json"
        if runtime_ml.exists():
            try:
                payload = json.loads(runtime_ml.read_text(encoding="utf-8"))
                stats['anomalies'] = max(stats['anomalies'], int(payload.get('anomalies_detected', 0) or 0))
                stats['high_risk'] = max(stats['high_risk'], int(payload.get('high_risk_events', 0) or 0))
                stats['events'] = max(stats['events'], int(payload.get('total_events', 0) or 0))
            except Exception as exc:
                logger.debug("Could not read runtime ML summary: %s", exc)

        # UEBA findings file fallback.
        ueba_file = self.case_path / "results" / "ueba_findings.json"
        if ueba_file.exists():
            try:
                ueba = json.loads(ueba_file.read_text(encoding="utf-8"))
                summary = ueba.get('summary', {}) if isinstance(ueba, dict) else {}
                stats['anomalies'] = max(stats['anomalies'], int(summary.get('anomalies_detected', 0) or 0))
            except Exception as exc:
                logger.debug("Could not read UEBA findings summary: %s", exc)
        return stats

    # ════════════════════════════════════════════════════════════════
    # 6. EVIDENCE INVENTORY
    # ════════════════════════════════════════════════════════════════

    def _create_evidence_inventory_group(self) -> QGroupBox:
        group = QGroupBox("Evidence Inventory")
        group.setStyleSheet(_GROUP_STYLE)
        group.setMinimumHeight(150)
        layout = QVBoxLayout()

        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["Evidence", "Type", "Size", "Hash", "Status"])
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table.setMaximumHeight(120)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        ev = self.case_metadata.get('evidence_image', {})
        filename = ev.get('filename', 'N/A')
        if filename != 'N/A':
            table.setRowCount(1)
            ext = Path(filename).suffix.lower()
            ev_type = "Disk Image" if ext in ('.e01', '.dd', '.raw', '.img', '.vmdk') else \
                      "Memory Dump" if ext in ('.mem', '.dmp', '.vmem') else "Evidence"
            items = [
                filename,
                ev_type,
                self._fmt_size(ev.get('size_bytes', 0)),
                (ev.get('sha256_hash', 'N/A') or 'N/A')[:16] + "...",
                "✅ Loaded",
            ]
            for col, val in enumerate(items):
                item = QTableWidgetItem(val)
                if col == 4:
                    item.setForeground(QColor("#4caf50"))
                table.setItem(0, col, item)

        layout.addWidget(table)

        btn_row = QHBoxLayout()
        btn_verify = QPushButton("Verify Hash")
        btn_verify.setStyleSheet(_BTN_STYLE)
        btn_verify.clicked.connect(self._verify_evidence_hash)
        btn_row.addWidget(btn_verify)

        btn_meta = QPushButton("Export Metadata")
        btn_meta.setStyleSheet(_BTN_STYLE)
        btn_meta.clicked.connect(self._export_metadata)
        btn_row.addWidget(btn_meta)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        group.setLayout(layout)
        return group

    # ════════════════════════════════════════════════════════════════
    # 7. CHAIN OF CUSTODY
    # ════════════════════════════════════════════════════════════════

    def _create_chain_of_custody_group(self) -> QGroupBox:
        group = QGroupBox("Chain of Custody")
        group.setStyleSheet(_GROUP_STYLE)
        group.setMinimumHeight(180)
        layout = QVBoxLayout()
        layout.setSpacing(8)

        coc_log_path = self.case_path / "chain_of_custody.log"
        if coc_log_path.exists():
            try:
                entries = []
                with open(coc_log_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue

                total = len(entries)
                first_ts = entries[0].get('timestamp', '')[:10] if entries else '—'
                last_ts = entries[-1].get('timestamp', '')[:10] if entries else '—'
                last_action = entries[-1].get('action', '—') if entries else '—'
                last_user = entries[-1].get('user', '—') if entries else '—'

                summary = QLabel(
                    f"<b>Total Entries:</b> {total:,} &nbsp;&nbsp; "
                    f"<b>First Entry:</b> {first_ts} &nbsp;&nbsp; "
                    f"<b>Last Entry:</b> {last_ts} &nbsp;&nbsp; "
                    f"<b>Last Action:</b> {last_action} &nbsp;&nbsp; "
                    f"<b>Last User:</b> {last_user}"
                )
                summary.setStyleSheet("font-size: 11pt; color: #d4d4d4; padding: 4px;")
                layout.addWidget(summary)

                # Table of all entries (scrollable, 4 visible rows)
                table = QTableWidget(len(entries), 4)
                table.setHorizontalHeaderLabels(["Timestamp", "User", "Action", "Details"])
                table.horizontalHeader().setStretchLastSection(True)
                table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
                table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
                table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
                row_h = 28
                table.verticalHeader().setDefaultSectionSize(row_h)
                table.verticalHeader().setVisible(False)
                # Show exactly 4 rows + header height
                header_h = table.horizontalHeader().height() or 26
                table.setFixedHeight(header_h + row_h * 4 + 4)
                table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
                table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)

                for i, e in enumerate(entries):
                    table.setItem(i, 0, QTableWidgetItem(e.get('timestamp', '')[:19]))
                    table.setItem(i, 1, QTableWidgetItem(e.get('user', '—')))
                    table.setItem(i, 2, QTableWidgetItem(e.get('action', '—')))
                    table.setItem(i, 3, QTableWidgetItem(str(e.get('details', ''))[:80]))

                # Scroll to the bottom so newest entries are visible
                table.scrollToBottom()
                layout.addWidget(table)

            except Exception as e:
                err = QLabel(f"Could not load chain of custody log: {e}")
                err.setStyleSheet("color: red;")
                layout.addWidget(err)
        else:
            lbl = QLabel("Chain of custody log not found")
            lbl.setStyleSheet("color: orange;")
            layout.addWidget(lbl)

        # Buttons
        btn_row = QHBoxLayout()
        for text, handler in [
            ("View Full Log", self._open_coc_log),
            ("Export Chain of Custody", self._export_coc),
            ("Verify Integrity", self._verify_coc_integrity),
        ]:
            btn = QPushButton(text)
            btn.setStyleSheet(_BTN_STYLE)
            btn.clicked.connect(handler)
            btn_row.addWidget(btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        group.setLayout(layout)
        return group

    # ════════════════════════════════════════════════════════════════
    # 9. INVESTIGATOR NOTES
    # ════════════════════════════════════════════════════════════════

    def _create_notes_group(self) -> QGroupBox:
        group = QGroupBox("Investigator Notes")
        group.setStyleSheet(_GROUP_STYLE)
        group.setMinimumHeight(200)
        layout = QVBoxLayout()

        self._notes_display = QTextEdit()
        self._notes_display.setReadOnly(True)
        self._notes_display.setMaximumHeight(120)
        self._notes_display.setStyleSheet(
            "font-family: monospace; font-size: 10pt; background: #1e1e1e; "
            "color: #d4d4d4; border: 1px solid #3d3d3d;"
        )

        # Load existing notes
        notes_path = self.case_path / "investigator_notes.txt"
        if notes_path.exists():
            try:
                self._notes_display.setPlainText(notes_path.read_text(encoding='utf-8'))
            except Exception:
                pass
        layout.addWidget(self._notes_display)

        # Input area
        self._notes_input = QTextEdit()
        self._notes_input.setMaximumHeight(60)
        self._notes_input.setPlaceholderText("Type your investigation note here...")
        self._notes_input.setStyleSheet(
            "font-family: monospace; font-size: 10pt; background: #252525; "
            "color: #e0e0e0; border: 1px solid #3d3d3d;"
        )
        layout.addWidget(self._notes_input)

        btn = QPushButton("Add Note")
        btn.setStyleSheet(_BTN_STYLE)
        btn.setMaximumWidth(120)
        btn.clicked.connect(self._add_note)
        layout.addWidget(btn)

        group.setLayout(layout)
        return group

    # ════════════════════════════════════════════════════════════════
    # 11. QUICK NAVIGATION
    # ════════════════════════════════════════════════════════════════

    def _create_quick_nav_group(self) -> QGroupBox:
        group = QGroupBox("Quick Navigation")
        group.setStyleSheet(_GROUP_STYLE)
        group.setMinimumHeight(150)
        layout = QVBoxLayout()
        layout.setSpacing(8)

        nav_items = [
            ("📁  Open Files", "files"),
            ("🔍  Open Artifacts", "artifacts"),
            ("📊  Open Timeline", "timeline"),
            ("🤖  Run ML Analysis", "ml"),
            ("📄  Generate Report", "report"),
        ]
        for text, tab_name in nav_items:
            btn = QPushButton(text)
            btn.setStyleSheet(
                "QPushButton { background: #2a2a2a; color: #e0e0e0; font-size: 12pt; "
                "padding: 8px 16px; border: 1px solid #3d3d3d; border-radius: 4px; text-align: left; }"
                "QPushButton:hover { background: #094771; border-color: #1565c0; }"
            )
            btn.clicked.connect(lambda _, t=tab_name: self.navigate_to_tab.emit(t))
            layout.addWidget(btn)

        layout.addStretch()
        group.setLayout(layout)
        return group

    # ════════════════════════════════════════════════════════════════
    # HELPER METHODS
    # ════════════════════════════════════════════════════════════════

    def _fmt_date(self, date_str: str) -> str:
        if date_str in ('N/A', '', None):
            return 'N/A'
        try:
            dt = datetime.fromisoformat(str(date_str))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return str(date_str)

    def _fmt_size(self, size_bytes) -> str:
        size_bytes = int(size_bytes or 0)
        if size_bytes == 0:
            return "N/A"
        val = float(size_bytes)
        for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
            if val < 1024.0:
                return f"{val:.2f} {unit} ({size_bytes:,} bytes)"
            val /= 1024.0
        return f"{val:.2f} PB"

    # ── Button handlers ──────────────────────────────────────────

    def _open_coc_log(self):
        coc_path = self.case_path / "chain_of_custody.log"
        if coc_path.exists():
            import os
            try:
                os.startfile(str(coc_path))
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to open log: {e}")

    def _export_coc(self):
        coc_path = self.case_path / "chain_of_custody.log"
        if not coc_path.exists():
            QMessageBox.warning(self, "Not Found", "Chain of custody log not found.")
            return
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Export Chain of Custody", "chain_of_custody_export.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        if save_path:
            import shutil
            shutil.copy2(str(coc_path), save_path)
            QMessageBox.information(self, "Exported", f"Chain of custody exported to:\n{save_path}")

    def _verify_coc_integrity(self):
        try:
            from src.core.chain_of_custody import ChainLogger
            coc = ChainLogger(str(self.case_path))
            result = coc.verify_chain()
            if result.get('valid'):
                QMessageBox.information(
                    self, "Integrity Verified",
                    f"✅ Chain of custody integrity VERIFIED\n\n"
                    f"Total entries: {result.get('total_entries', 0):,}\n"
                    f"First action: {result.get('first_action', '—')}\n"
                    f"Last action: {result.get('last_action', '—')}"
                )
            else:
                QMessageBox.warning(
                    self, "Integrity Issue",
                    f"❌ Chain integrity issue\n\n"
                    f"Error: {result.get('error', 'Unknown')}\n"
                    f"Broken at entry: {result.get('broken_at', '—')}"
                )
        except Exception as e:
            QMessageBox.critical(self, "Verification Error", f"Error: {e}")

    def _verify_evidence_hash(self):
        ev = self.case_metadata.get('evidence_image', {})
        stored_hash = ev.get('sha256_hash', '')
        if not stored_hash:
            QMessageBox.information(self, "Hash", "No stored hash available for verification.")
            return
        QMessageBox.information(
            self, "Evidence Hash",
            f"Stored SHA-256:\n{stored_hash}\n\n"
            f"Evidence file: {ev.get('filename', 'N/A')}"
        )

    def _export_metadata(self):
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Export Metadata", "case_metadata.json",
            "JSON Files (*.json);;All Files (*)"
        )
        if save_path:
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(self.case_metadata, f, indent=2, default=str)
            QMessageBox.information(self, "Exported", f"Metadata exported to:\n{save_path}")

    def _add_note(self):
        text = self._notes_input.toPlainText().strip()
        if not text:
            return
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        note_line = f"[{timestamp}] {text}\n"

        notes_path = self.case_path / "investigator_notes.txt"
        with open(notes_path, 'a', encoding='utf-8') as f:
            f.write(note_line)

        # Update display
        current = self._notes_display.toPlainText()
        self._notes_display.setPlainText(current + note_line)
        self._notes_input.clear()


    def refresh(self):
        """Refresh the case details display."""
        layout = self.layout()
        for i in reversed(range(layout.count())):
            widget = layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        self._init_ui()
        logger.info("Case details refreshed")
