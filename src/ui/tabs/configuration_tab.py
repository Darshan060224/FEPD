"""
FEPD - Forensic Evidence Parser Dashboard
Configuration Tab (Host Profile / System Configuration)

Displays a comprehensive technical snapshot of the analyzed system:
  - System Information (OS, hostname, build, timezone)
  - Hardware Information (CPU, RAM, disk, BIOS)
  - Network Configuration (adapters, IP, MAC, DNS, gateway)
  - Installed Software (programs from Uninstall keys)
  - Running Services (with risk indicators)
  - Security Configuration (firewall, defender, UAC)

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from typing import Optional, List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QGroupBox, QFormLayout, QLineEdit, QFileDialog,
    QHeaderView, QAbstractItemView, QTextEdit, QProgressBar,
    QTreeWidget, QTreeWidgetItem, QMessageBox, QTabWidget,
    QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QFont

from src.parsers.system_config_extractor import (
    extract_full_config,
    SystemConfiguration,
    NetworkAdapter,
    InstalledSoftware,
    ServiceEntry,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Suspicious-service heuristics
# ---------------------------------------------------------------------------

_SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
    "\\users\\public\\", "\\programdata\\",
    "powershell", "cmd.exe /c", "mshta", "wscript", "cscript",
    "rundll32", "regsvr32", "certutil",
]

_SUSPICIOUS_NAMES = [
    "svchost",  # only if NOT under system32
]


def _is_suspicious_service(entry: ServiceEntry) -> str:
    """Return a risk label or empty string."""
    img = entry.image_path.lower()
    if not img or img == "unknown":
        return ""
    for pat in _SUSPICIOUS_PATHS:
        if pat in img:
            return "⚠ Suspicious path"
    # svchost outside system32
    if "svchost" in img and "system32" not in img:
        return "⚠ Unusual svchost"
    return ""


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

class ConfigExtractionWorker(QThread):
    """Extracts system configuration in a background thread."""

    progress = pyqtSignal(int, str)
    finished = pyqtSignal(object)  # SystemConfiguration
    error = pyqtSignal(str)

    def __init__(self, system_hive: Optional[Path], software_hive: Optional[Path], source: str = ""):
        super().__init__()
        self._system_hive = system_hive
        self._software_hive = software_hive
        self._source = source

    def run(self):
        try:
            self.progress.emit(10, "Opening registry hives…")
            config = extract_full_config(
                system_hive=self._system_hive,
                software_hive=self._software_hive,
                evidence_source=self._source,
            )
            self.progress.emit(100, "Extraction complete")
            self.finished.emit(config)
        except Exception as exc:
            logger.error("Config extraction failed: %s", exc, exc_info=True)
            self.error.emit(str(exc))


# ---------------------------------------------------------------------------
# Configuration Tab widget
# ---------------------------------------------------------------------------

class ConfigurationTab(QWidget):
    """
    TAB: ⚙ Configuration (Host Profile)

    Five-section host-profile panel extracted from forensic evidence.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._config: Optional[SystemConfiguration] = None
        self._worker: Optional[ConfigExtractionWorker] = None
        self._init_ui()

    # ------------------------------------------------------------------ UI
    def _init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("⚙ System Configuration / Host Profile")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        hdr.addWidget(title)
        hdr.addStretch()

        # Hive selection
        hdr.addWidget(QLabel("SYSTEM hive:"))
        self.txt_system_hive = QLineEdit()
        self.txt_system_hive.setPlaceholderText("Path to SYSTEM hive…")
        self.txt_system_hive.setMinimumWidth(200)
        hdr.addWidget(self.txt_system_hive)
        btn_sys = QPushButton("Browse…")
        btn_sys.clicked.connect(lambda: self._browse_hive(self.txt_system_hive))
        hdr.addWidget(btn_sys)

        hdr.addWidget(QLabel("SOFTWARE hive:"))
        self.txt_software_hive = QLineEdit()
        self.txt_software_hive.setPlaceholderText("Path to SOFTWARE hive…")
        self.txt_software_hive.setMinimumWidth(200)
        hdr.addWidget(self.txt_software_hive)
        btn_sw = QPushButton("Browse…")
        btn_sw.clicked.connect(lambda: self._browse_hive(self.txt_software_hive))
        hdr.addWidget(btn_sw)

        self.btn_extract = QPushButton("▶ Extract Configuration")
        self.btn_extract.setMinimumHeight(35)
        self.btn_extract.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        self.btn_extract.clicked.connect(self._on_extract)
        hdr.addWidget(self.btn_extract)

        root.addLayout(hdr)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        root.addWidget(self.progress_bar)
        self.lbl_status = QLabel("Load SYSTEM and/or SOFTWARE registry hives, then click Extract.")
        root.addWidget(self.lbl_status)

        # Sub-tabs for the 6 sections
        self.section_tabs = QTabWidget()
        self.section_tabs.setTabPosition(QTabWidget.TabPosition.West)

        self._build_system_info_section()
        self._build_hardware_section()
        self._build_network_section()
        self._build_software_section()
        self._build_services_section()
        self._build_security_section()

        root.addWidget(self.section_tabs, stretch=1)

    # ----- Section builders -----

    def _build_system_info_section(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("<h3>🖥 System Information</h3>"))

        self.form_system = QFormLayout()
        self._sys_fields = {}
        for label in [
            "Operating System", "Hostname", "Build Number", "System Version",
            "Install Date", "Time Zone", "Last Boot Time",
            "Registered Owner", "Registered Organization", "Product ID",
        ]:
            val = QLabel("—")
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.form_system.addRow(QLabel(f"<b>{label}:</b>"), val)
            self._sys_fields[label] = val

        layout.addLayout(self.form_system)
        layout.addStretch()
        self.section_tabs.addTab(widget, "🖥 System")

    def _build_hardware_section(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("<h3>🔧 Hardware Information</h3>"))

        self.form_hw = QFormLayout()
        self._hw_fields = {}
        for label in [
            "CPU Model", "CPU Cores", "Total RAM", "Disk Size", "Disk Model",
            "BIOS Version", "Motherboard", "System Manufacturer", "System Model",
        ]:
            val = QLabel("—")
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.form_hw.addRow(QLabel(f"<b>{label}:</b>"), val)
            self._hw_fields[label] = val

        layout.addLayout(self.form_hw)
        layout.addStretch()
        self.section_tabs.addTab(widget, "🔧 Hardware")

    def _build_network_section(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("<h3>🌐 Network Configuration</h3>"))

        self.table_network = QTableWidget(0, 8)
        self.table_network.setHorizontalHeaderLabels([
            "Adapter", "IP Address", "MAC Address", "DNS Servers",
            "Gateway", "DHCP", "DHCP Server", "Domain",
        ])
        self.table_network.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_network.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_network.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_network.setAlternatingRowColors(True)

        layout.addWidget(self.table_network)
        self.lbl_net_count = QLabel("Adapters: 0")
        layout.addWidget(self.lbl_net_count)
        self.section_tabs.addTab(widget, "🌐 Network")

    def _build_software_section(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        top = QHBoxLayout()
        top.addWidget(QLabel("<h3>📦 Installed Software</h3>"))
        top.addStretch()
        self.txt_sw_filter = QLineEdit()
        self.txt_sw_filter.setPlaceholderText("Filter programs…")
        self.txt_sw_filter.textChanged.connect(self._filter_software)
        top.addWidget(self.txt_sw_filter)
        layout.addLayout(top)

        self.table_software = QTableWidget(0, 5)
        self.table_software.setHorizontalHeaderLabels([
            "Program Name", "Version", "Publisher", "Install Date", "Install Location",
        ])
        hdr = self.table_software.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.table_software.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_software.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_software.setAlternatingRowColors(True)
        self.table_software.setSortingEnabled(True)

        layout.addWidget(self.table_software)
        self.lbl_sw_count = QLabel("Programs: 0")
        layout.addWidget(self.lbl_sw_count)
        self.section_tabs.addTab(widget, "📦 Software")

    def _build_services_section(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        top = QHBoxLayout()
        top.addWidget(QLabel("<h3>⚡ Services</h3>"))
        top.addStretch()
        self.cmb_svc_filter = QComboBox()
        self.cmb_svc_filter.addItems([
            "All", "Automatic", "Manual", "Disabled", "⚠ Suspicious Only",
        ])
        self.cmb_svc_filter.currentTextChanged.connect(self._filter_services)
        top.addWidget(QLabel("Startup:"))
        top.addWidget(self.cmb_svc_filter)
        self.txt_svc_filter = QLineEdit()
        self.txt_svc_filter.setPlaceholderText("Search services…")
        self.txt_svc_filter.textChanged.connect(self._filter_services)
        top.addWidget(self.txt_svc_filter)
        layout.addLayout(top)

        self.table_services = QTableWidget(0, 5)
        self.table_services.setHorizontalHeaderLabels([
            "Service Name", "Display Name", "Startup Type", "Binary Path", "Risk",
        ])
        hdr = self.table_services.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_services.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_services.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_services.setAlternatingRowColors(True)
        self.table_services.setSortingEnabled(True)

        layout.addWidget(self.table_services)
        self.lbl_svc_count = QLabel("Services: 0")
        layout.addWidget(self.lbl_svc_count)
        self.section_tabs.addTab(widget, "⚡ Services")

    def _build_security_section(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("<h3>🛡 Security Configuration</h3>"))

        self.form_sec = QFormLayout()
        self._sec_fields = {}
        for label in ["Firewall", "Windows Defender", "UAC", "Audit Policy", "Antivirus"]:
            val = QLabel("—")
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.form_sec.addRow(QLabel(f"<b>{label}:</b>"), val)
            self._sec_fields[label] = val

        layout.addLayout(self.form_sec)
        layout.addStretch()
        self.section_tabs.addTab(widget, "🛡 Security")

    # ---------------------------------------------------------------- Actions

    def _browse_hive(self, target: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(self, "Select Registry Hive", "", "All Files (*)")
        if path:
            target.setText(path)

    def _on_extract(self):
        sys_path = self.txt_system_hive.text().strip()
        sw_path = self.txt_software_hive.text().strip()

        system_hive = Path(sys_path) if sys_path else None
        software_hive = Path(sw_path) if sw_path else None

        if not system_hive and not software_hive:
            QMessageBox.warning(self, "No Hive Selected",
                                "Please provide at least one registry hive (SYSTEM or SOFTWARE).")
            return

        if system_hive and not system_hive.exists():
            QMessageBox.warning(self, "File Not Found", f"SYSTEM hive not found:\n{system_hive}")
            return
        if software_hive and not software_hive.exists():
            QMessageBox.warning(self, "File Not Found", f"SOFTWARE hive not found:\n{software_hive}")
            return

        self.btn_extract.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.lbl_status.setText("Extracting configuration…")

        self._worker = ConfigExtractionWorker(system_hive, software_hive, source=sys_path or sw_path)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_progress(self, pct: int, msg: str):
        self.progress_bar.setValue(pct)
        self.lbl_status.setText(msg)

    def _on_error(self, msg: str):
        self.btn_extract.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.lbl_status.setText(f"Error: {msg}")
        QMessageBox.critical(self, "Extraction Error", msg)

    def _on_finished(self, config: SystemConfiguration):
        self._config = config
        self.btn_extract.setEnabled(True)
        self.progress_bar.setVisible(False)

        self._populate_system_info()
        self._populate_hardware()
        self._populate_network()
        self._populate_software()
        self._populate_services()
        self._populate_security()

        total_items = (
            len(config.network_adapters)
            + len(config.installed_software)
            + len(config.services)
        )
        self.lbl_status.setText(
            f"Extraction complete — {len(config.installed_software)} programs, "
            f"{len(config.services)} services, {len(config.network_adapters)} adapters  "
            f"(extracted {config.extraction_timestamp})"
        )

    # ---------------------------------------------------------------- Populate

    def _populate_system_info(self):
        if not self._config:
            return
        d = self._config.system_info.to_dict()
        for label, val in d.items():
            if label in self._sys_fields:
                self._sys_fields[label].setText(val)

    def _populate_hardware(self):
        if not self._config:
            return
        d = self._config.hardware_info.to_dict()
        for label, val in d.items():
            if label in self._hw_fields:
                self._hw_fields[label].setText(val)

    def _populate_network(self):
        if not self._config:
            return
        adapters = self._config.network_adapters
        self.table_network.setRowCount(len(adapters))
        for row, adapter in enumerate(adapters):
            vals = adapter.to_dict()
            for col, key in enumerate(vals):
                item = QTableWidgetItem(vals[key])
                self.table_network.setItem(row, col, item)
        self.lbl_net_count.setText(f"Adapters: {len(adapters)}")

    def _populate_software(self, filter_text: str = ""):
        if not self._config:
            return
        programs = self._config.installed_software
        if filter_text:
            lf = filter_text.lower()
            programs = [p for p in programs if lf in p.name.lower() or lf in p.publisher.lower()]

        self.table_software.setSortingEnabled(False)
        self.table_software.setRowCount(len(programs))
        for row, prog in enumerate(programs):
            for col, val in enumerate(prog.to_list()):
                item = QTableWidgetItem(val)
                self.table_software.setItem(row, col, item)
        self.table_software.setSortingEnabled(True)
        self.lbl_sw_count.setText(f"Programs: {len(programs)}")

    def _populate_services(self, startup_filter: str = "All", text_filter: str = ""):
        if not self._config:
            return
        services = self._config.services

        if startup_filter == "⚠ Suspicious Only":
            services = [s for s in services if _is_suspicious_service(s)]
        elif startup_filter != "All":
            services = [s for s in services if s.startup_type == startup_filter]

        if text_filter:
            lf = text_filter.lower()
            services = [
                s for s in services
                if lf in s.service_name.lower()
                or lf in s.display_name.lower()
                or lf in s.image_path.lower()
            ]

        self.table_services.setSortingEnabled(False)
        self.table_services.setRowCount(len(services))
        for row, svc in enumerate(services):
            for col, val in enumerate(svc.to_list()):
                item = QTableWidgetItem(val)
                self.table_services.setItem(row, col, item)
            # Risk column
            risk = _is_suspicious_service(svc)
            risk_item = QTableWidgetItem(risk)
            if risk:
                risk_item.setForeground(QBrush(QColor("#D64550")))
                risk_item.setFont(QFont("", -1, QFont.Weight.Bold))
                # Highlight the whole row
                for c in range(5):
                    existing = self.table_services.item(row, c)
                    if existing:
                        existing.setBackground(QBrush(QColor(255, 235, 235)))
            self.table_services.setItem(row, 4, risk_item)

        self.table_services.setSortingEnabled(True)
        self.lbl_svc_count.setText(f"Services: {len(services)}")

    def _populate_security(self):
        if not self._config:
            return
        d = self._config.security_config.to_dict()
        for label, val in d.items():
            if label in self._sec_fields:
                w = self._sec_fields[label]
                w.setText(val)
                # Color-code
                low = val.lower()
                if "enabled" in low or "running" in low or "installed" in low:
                    w.setStyleSheet("color: #22B573; font-weight: bold;")
                elif "disabled" in low or "off" in low:
                    w.setStyleSheet("color: #D64550; font-weight: bold;")

    # -------------------------------------------------------------- Filters

    def _filter_software(self):
        self._populate_software(filter_text=self.txt_sw_filter.text().strip())

    def _filter_services(self):
        self._populate_services(
            startup_filter=self.cmb_svc_filter.currentText(),
            text_filter=self.txt_svc_filter.text().strip(),
        )

    # ------------------------------------------------------------- Public API

    def load_hives(self, system_hive: Optional[Path] = None, software_hive: Optional[Path] = None):
        """Programmatically set hive paths and trigger extraction."""
        if system_hive:
            self.txt_system_hive.setText(str(system_hive))
        if software_hive:
            self.txt_software_hive.setText(str(software_hive))
        self._on_extract()

    def apply_forensic_section(self, section_name: str, fields: dict):
        """Populate UI directly from routed forensic section payloads.

        This is used when parsed evidence is already available and we do not need
        manual hive extraction through the top browse controls.
        """
        if not isinstance(fields, dict):
            return

        section = str(section_name or "").strip()

        if section == "System Information":
            for label, widget in self._sys_fields.items():
                widget.setText(str(fields.get(label) or "—"))
        elif section == "Hardware Information":
            for label, widget in self._hw_fields.items():
                widget.setText(str(fields.get(label) or "—"))
        elif section == "Network Configuration":
            self.table_network.setRowCount(1)
            ordered = [
                fields.get("Adapter Name"),
                fields.get("IP Address"),
                fields.get("MAC Address"),
                fields.get("DNS Servers"),
                fields.get("Gateway"),
                fields.get("DHCP Enabled"),
                fields.get("DHCP Server"),
                fields.get("Domain"),
            ]
            for col, val in enumerate(ordered):
                self.table_network.setItem(0, col, QTableWidgetItem(str(val) if val not in (None, "") else "—"))
            self.lbl_net_count.setText("Adapters: 1")
        elif section == "Installed Software":
            programs = fields.get("programs") if isinstance(fields.get("programs"), list) else []
            self.table_software.setSortingEnabled(False)
            self.table_software.setRowCount(len(programs))
            for row, prog in enumerate(programs):
                self.table_software.setItem(row, 0, QTableWidgetItem(str(prog.get("name") or "—")))
                self.table_software.setItem(row, 1, QTableWidgetItem(str(prog.get("version") or "—")))
                self.table_software.setItem(row, 2, QTableWidgetItem(str(prog.get("publisher") or "—")))
                self.table_software.setItem(row, 3, QTableWidgetItem(str(prog.get("install_date") or "—")))
                self.table_software.setItem(row, 4, QTableWidgetItem(str(prog.get("path") or "—")))
            self.table_software.setSortingEnabled(True)
            self.lbl_sw_count.setText(f"Programs: {len(programs)}")
        elif section == "Services":
            services = fields.get("services") if isinstance(fields.get("services"), list) else []
            self.table_services.setSortingEnabled(False)
            self.table_services.setRowCount(len(services))
            for row, svc in enumerate(services):
                self.table_services.setItem(row, 0, QTableWidgetItem(str(svc.get("name") or "—")))
                self.table_services.setItem(row, 1, QTableWidgetItem(str(svc.get("display_name") or "—")))
                self.table_services.setItem(row, 2, QTableWidgetItem(str(svc.get("startup_type") or "—")))
                self.table_services.setItem(row, 3, QTableWidgetItem(str(svc.get("path") or "—")))
                self.table_services.setItem(row, 4, QTableWidgetItem(str(svc.get("risk_level") or "")))
            self.table_services.setSortingEnabled(True)
            self.lbl_svc_count.setText(f"Services: {len(services)}")
        elif section == "Security Configuration":
            mapping = {
                "Firewall": fields.get("Firewall Status"),
                "Windows Defender": fields.get("Windows Defender Status"),
                "UAC": fields.get("UAC Level"),
                "Audit Policy": fields.get("Audit Policy"),
                "Antivirus": fields.get("Antivirus"),
            }
            for label, value in mapping.items():
                widget = self._sec_fields.get(label)
                if widget is not None:
                    widget.setText(str(value) if value not in (None, "") else "—")

        self.lbl_status.setText("Configuration updated from parsed forensic evidence.")

    def get_config(self) -> Optional[SystemConfiguration]:
        """Return the extracted configuration, or None."""
        return self._config
