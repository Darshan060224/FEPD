"""
FEPD - Platform Analysis Tab
=============================
Forensic parser controls for:
- macOS (Unified Logs, FSEvents, TCC)
- Linux (syslog, journald, auditd)
- Mobile (iOS, Android)

Copyright (c) 2025 FEPD Development Team
"""

import logging
from pathlib import Path
from typing import Optional, Dict, List
import pandas as pd

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QGroupBox, QFileDialog, QTextEdit,
    QTabWidget, QCheckBox, QProgressBar, QTableWidget,
    QTableWidgetItem, QLineEdit, QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont


class ParserWorker(QThread):
    """Background worker for platform parsing."""
    
    finished = pyqtSignal(pd.DataFrame)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, str)
    
    def __init__(self, platform: str, sources: List[str], options: Dict):
        super().__init__()
        self.platform = platform
        self.sources = sources
        self.options = options
        self.logger = logging.getLogger(__name__)
    
    def run(self):
        """Execute parsing in background."""
        try:
            if self.platform == "macos":
                df = self._parse_macos()
            elif self.platform == "linux":
                df = self._parse_linux()
            elif self.platform == "mobile":
                df = self._parse_mobile()
            else:
                raise ValueError(f"Unknown platform: {self.platform}")
            
            self.finished.emit(df)
            
        except Exception as e:
            self.logger.error(f"Parsing failed: {e}")
            self.error.emit(str(e))
    
    def _parse_macos(self) -> pd.DataFrame:
        """Parse macOS artifacts."""
        from src.parsers.macos_parser import MacOSParser
        
        self.progress.emit(10, "Initializing macOS parser...")
        parser = MacOSParser()
        all_events = []
        
        for idx, source in enumerate(self.sources):
            progress = 20 + (idx * 60 // len(self.sources))
            self.progress.emit(progress, f"Parsing {Path(source).name}...")
            
            source_path = Path(source)
            if source.endswith('.tracev3') or source.endswith('.logarchive'):
                # Unified Logs
                events = parser.parse_unified_log(source_path)
            elif 'fseventsd' in source:
                # FSEvents
                events = parser.parse_fseventsd_file(source_path)
            elif source.endswith('.plist'):
                # Plist (login items, quarantine, etc.)
                events = parser.parse_login_items(source_path)
            elif source.endswith('.db') or source.endswith('.sqlite'):
                # Safari / Spotlight / Quarantine DB
                if 'safari' in source.lower() or 'History' in source:
                    events = parser.parse_safari_history(source_path)
                elif 'Spotlight' in source:
                    events = parser.parse_spotlight_store(source_path)
                elif 'Quarantine' in source:
                    events = parser.parse_quarantine_events(source_path)
                else:
                    self.logger.warning(f"Unknown macOS DB: {source}")
                    continue
            elif 'history' in source.lower():
                # Shell history
                events = parser.parse_bash_history(source_path)
            else:
                # Try parse_all_artifacts for directories
                if source_path.is_dir():
                    events = list(parser.parse_all_artifacts(source_path))
                else:
                    self.logger.warning(f"Unknown macOS source: {source}")
                    continue
            
            all_events.extend(events)
        
        self.progress.emit(90, "Consolidating events...")
        df = pd.DataFrame(all_events)
        
        self.progress.emit(100, f"Complete - {len(df)} events parsed")
        return df
    
    def _parse_linux(self) -> pd.DataFrame:
        """Parse Linux artifacts."""
        from src.parsers.linux_parser import LinuxParser
        
        self.progress.emit(10, "Initializing Linux parser...")
        parser = LinuxParser()
        all_events = []
        
        for idx, source in enumerate(self.sources):
            progress = 20 + (idx * 60 // len(self.sources))
            self.progress.emit(progress, f"Parsing {Path(source).name}...")
            
            source_path = Path(source)
            source_lower = source.lower()
            
            if 'syslog' in source_lower or source_lower.endswith('.log'):
                # Syslog / generic log
                events = parser.parse_syslog(source_path)
            elif 'auth' in source_lower or 'secure' in source_lower:
                # Auth / audit log
                events = parser.parse_auth_log(source_path)
            elif 'journal' in source_lower or 'audit' in source_lower:
                # journald / auditd — parse as auth log (similar structure)
                events = parser.parse_auth_log(source_path)
            elif 'cron' in source_lower:
                events = parser.parse_cron_log(source_path)
            elif 'apt' in source_lower:
                events = parser.parse_apt_history(source_path)
            elif 'wtmp' in source_lower or 'btmp' in source_lower:
                events = parser.parse_wtmp(source_path)
            elif 'history' in source_lower:
                if 'zsh' in source_lower:
                    events = parser.parse_zsh_history(source_path)
                else:
                    events = parser.parse_bash_history(source_path)
            else:
                # Try parse_all_artifacts for directories
                if source_path.is_dir():
                    events = list(parser.parse_all_artifacts(source_path))
                else:
                    self.logger.warning(f"Unknown Linux source: {source}")
                    continue
            
            all_events.extend(events)
        
        self.progress.emit(90, "Consolidating events...")
        df = pd.DataFrame(all_events)
        
        self.progress.emit(100, f"Complete - {len(df)} events parsed")
        return df
    
    def _parse_mobile(self) -> pd.DataFrame:
        """Parse mobile artifacts."""
        from src.parsers.mobile_parser import MobileParser
        
        self.progress.emit(10, "Initializing mobile parser...")
        all_events = []
        
        for idx, source in enumerate(self.sources):
            progress = 20 + (idx * 60 // len(self.sources))
            self.progress.emit(progress, f"Parsing {Path(source).name}...")
            
            # Detect iOS vs Android and create parser with correct platform
            if self.options.get('platform_type') == 'ios':
                platform = 'ios'
            elif self.options.get('platform_type') == 'android':
                platform = 'android'
            else:
                # Auto-detect
                if Path(source).suffix == '.ab' or 'android' in source.lower():
                    platform = 'android'
                else:
                    platform = 'ios'
            
            parser = MobileParser(platform=platform)
            events = list(parser.parse_all_artifacts(source))
            all_events.extend(events)
        
        self.progress.emit(90, "Consolidating events...")
        df = pd.DataFrame(all_events)
        
        self.progress.emit(100, f"Complete - {len(df)} events parsed")
        return df


class PlatformAnalysisTab(QWidget):
    """
    Platform Analysis Tab with:
    1. macOS Parser
    2. Linux Parser
    3. Mobile Parser
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.parser_worker: Optional[ParserWorker] = None
        self.current_results: Optional[pd.DataFrame] = None
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Title
        title = QLabel("🖥️ Platform Analysis")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Sub-tabs for different platforms
        self.sub_tabs = QTabWidget()
        self.sub_tabs.addTab(self._create_macos_tab(), "🍎 macOS")
        self.sub_tabs.addTab(self._create_linux_tab(), "🐧 Linux")
        self.sub_tabs.addTab(self._create_mobile_tab(), "📱 Mobile")
        
        layout.addWidget(self.sub_tabs)
    
    def _create_macos_tab(self) -> QWidget:
        """Create macOS parser tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info
        info_label = QLabel(
            "macOS Artifact Parser - Unified Logs, FSEvents, TCC, quarantine, launch services"
        )
        layout.addWidget(info_label)
        
        # Source selection
        sources_group = QGroupBox("Artifact Sources")
        sources_layout = QVBoxLayout(sources_group)
        
        # Unified Logs
        ulog_layout = QHBoxLayout()
        self.macos_ulog_check = QCheckBox("Unified Logs (.tracev3, .logarchive)")
        self.macos_ulog_check.setChecked(True)
        ulog_layout.addWidget(self.macos_ulog_check)
        self.macos_ulog_path = QLineEdit()
        self.macos_ulog_path.setPlaceholderText("/var/db/diagnostics/...")
        ulog_layout.addWidget(self.macos_ulog_path)
        btn_ulog_browse = QPushButton("📁 Browse")
        btn_ulog_browse.clicked.connect(lambda: self._browse_directory(self.macos_ulog_path))
        ulog_layout.addWidget(btn_ulog_browse)
        sources_layout.addLayout(ulog_layout)
        
        # FSEvents
        fsevents_layout = QHBoxLayout()
        self.macos_fsevents_check = QCheckBox("FSEvents")
        fsevents_layout.addWidget(self.macos_fsevents_check)
        self.macos_fsevents_path = QLineEdit()
        self.macos_fsevents_path.setPlaceholderText("/.fseventsd/...")
        fsevents_layout.addWidget(self.macos_fsevents_path)
        btn_fsevents_browse = QPushButton("📁 Browse")
        btn_fsevents_browse.clicked.connect(lambda: self._browse_directory(self.macos_fsevents_path))
        fsevents_layout.addWidget(btn_fsevents_browse)
        sources_layout.addLayout(fsevents_layout)
        
        # TCC
        tcc_layout = QHBoxLayout()
        self.macos_tcc_check = QCheckBox("TCC Database (Privacy)")
        tcc_layout.addWidget(self.macos_tcc_check)
        self.macos_tcc_path = QLineEdit()
        self.macos_tcc_path.setPlaceholderText("/Library/Application Support/com.apple.TCC/TCC.db")
        tcc_layout.addWidget(self.macos_tcc_path)
        btn_tcc_browse = QPushButton("📁 Browse")
        btn_tcc_browse.clicked.connect(lambda: self._browse_file(self.macos_tcc_path))
        tcc_layout.addWidget(btn_tcc_browse)
        sources_layout.addLayout(tcc_layout)
        
        layout.addWidget(sources_group)
        
        # Parse button
        btn_parse = QPushButton("🔍 Parse macOS Artifacts")
        btn_parse.clicked.connect(lambda: self._parse_platform("macos"))
        btn_parse.setMinimumHeight(40)
        layout.addWidget(btn_parse)
        
        # Progress
        self.macos_progress = QProgressBar()
        self.macos_progress.setVisible(False)
        layout.addWidget(self.macos_progress)
        
        self.macos_status = QLabel("")
        layout.addWidget(self.macos_status)
        
        # Results summary
        self.macos_summary = QTextEdit()
        self.macos_summary.setReadOnly(True)
        self.macos_summary.setMaximumHeight(200)
        layout.addWidget(self.macos_summary)
        
        return widget
    
    def _create_linux_tab(self) -> QWidget:
        """Create Linux parser tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info
        info_label = QLabel(
            "Linux Artifact Parser - syslog, journald, auditd, systemd logs"
        )
        layout.addWidget(info_label)
        
        # Source selection
        sources_group = QGroupBox("Artifact Sources")
        sources_layout = QVBoxLayout(sources_group)
        
        # Syslog
        syslog_layout = QHBoxLayout()
        self.linux_syslog_check = QCheckBox("Syslog (/var/log/syslog)")
        self.linux_syslog_check.setChecked(True)
        syslog_layout.addWidget(self.linux_syslog_check)
        self.linux_syslog_path = QLineEdit()
        self.linux_syslog_path.setPlaceholderText("/var/log/syslog")
        syslog_layout.addWidget(self.linux_syslog_path)
        btn_syslog_browse = QPushButton("📁 Browse")
        btn_syslog_browse.clicked.connect(lambda: self._browse_file(self.linux_syslog_path))
        syslog_layout.addWidget(btn_syslog_browse)
        sources_layout.addLayout(syslog_layout)
        
        # journald
        journal_layout = QHBoxLayout()
        self.linux_journal_check = QCheckBox("journald (/var/log/journal)")
        journal_layout.addWidget(self.linux_journal_check)
        self.linux_journal_path = QLineEdit()
        self.linux_journal_path.setPlaceholderText("/var/log/journal/...")
        journal_layout.addWidget(self.linux_journal_path)
        btn_journal_browse = QPushButton("📁 Browse")
        btn_journal_browse.clicked.connect(lambda: self._browse_directory(self.linux_journal_path))
        journal_layout.addWidget(btn_journal_browse)
        sources_layout.addLayout(journal_layout)
        
        # auditd
        audit_layout = QHBoxLayout()
        self.linux_audit_check = QCheckBox("auditd (/var/log/audit)")
        audit_layout.addWidget(self.linux_audit_check)
        self.linux_audit_path = QLineEdit()
        self.linux_audit_path.setPlaceholderText("/var/log/audit/audit.log")
        audit_layout.addWidget(self.linux_audit_path)
        btn_audit_browse = QPushButton("📁 Browse")
        btn_audit_browse.clicked.connect(lambda: self._browse_file(self.linux_audit_path))
        audit_layout.addWidget(btn_audit_browse)
        sources_layout.addLayout(audit_layout)
        
        layout.addWidget(sources_group)
        
        # Parse button
        btn_parse = QPushButton("🔍 Parse Linux Artifacts")
        btn_parse.clicked.connect(lambda: self._parse_platform("linux"))
        btn_parse.setMinimumHeight(40)
        layout.addWidget(btn_parse)
        
        # Progress
        self.linux_progress = QProgressBar()
        self.linux_progress.setVisible(False)
        layout.addWidget(self.linux_progress)
        
        self.linux_status = QLabel("")
        layout.addWidget(self.linux_status)
        
        # Results summary
        self.linux_summary = QTextEdit()
        self.linux_summary.setReadOnly(True)
        self.linux_summary.setMaximumHeight(200)
        layout.addWidget(self.linux_summary)
        
        return widget
    
    def _create_mobile_tab(self) -> QWidget:
        """Create Mobile parser tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info
        info_label = QLabel(
            "Mobile Forensics - iOS backups, Android backups, SMS, calls, location data"
        )
        layout.addWidget(info_label)
        
        # Source selection
        sources_group = QGroupBox("Backup Source")
        sources_layout = QVBoxLayout(sources_group)
        
        # Platform selection
        platform_layout = QHBoxLayout()
        platform_layout.addWidget(QLabel("Platform:"))
        self.mobile_platform_combo = QComboBox()
        self.mobile_platform_combo.addItems(["Auto-detect", "iOS", "Android"])
        platform_layout.addWidget(self.mobile_platform_combo)
        platform_layout.addStretch()
        sources_layout.addLayout(platform_layout)
        
        # Backup path
        backup_layout = QHBoxLayout()
        backup_layout.addWidget(QLabel("Backup Path:"))
        self.mobile_backup_path = QLineEdit()
        self.mobile_backup_path.setPlaceholderText("iOS: ~/Library/Application Support/MobileSync/Backup/...")
        backup_layout.addWidget(self.mobile_backup_path)
        btn_backup_browse = QPushButton("📁 Browse")
        btn_backup_browse.clicked.connect(lambda: self._browse_directory(self.mobile_backup_path))
        backup_layout.addWidget(btn_backup_browse)
        sources_layout.addLayout(backup_layout)
        
        layout.addWidget(sources_group)
        
        # Parse button
        btn_parse = QPushButton("🔍 Parse Mobile Backup")
        btn_parse.clicked.connect(lambda: self._parse_platform("mobile"))
        btn_parse.setMinimumHeight(40)
        layout.addWidget(btn_parse)
        
        # Progress
        self.mobile_progress = QProgressBar()
        self.mobile_progress.setVisible(False)
        layout.addWidget(self.mobile_progress)
        
        self.mobile_status = QLabel("")
        layout.addWidget(self.mobile_status)
        
        # Results summary
        self.mobile_summary = QTextEdit()
        self.mobile_summary.setReadOnly(True)
        self.mobile_summary.setMaximumHeight(200)
        layout.addWidget(self.mobile_summary)
        
        return widget
    
    def _browse_file(self, line_edit: QLineEdit):
        """Browse for file."""
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            "Select File",
            "",
            "All Files (*)"
        )
        if filepath:
            line_edit.setText(filepath)
    
    def _browse_directory(self, line_edit: QLineEdit):
        """Browse for directory."""
        dirpath = QFileDialog.getExistingDirectory(
            self,
            "Select Directory",
            ""
        )
        if dirpath:
            line_edit.setText(dirpath)
    
    def _parse_platform(self, platform: str):
        """Parse platform artifacts."""
        # Collect sources
        sources = []
        options = {}
        
        if platform == "macos":
            if self.macos_ulog_check.isChecked() and self.macos_ulog_path.text():
                sources.append(self.macos_ulog_path.text())
            if self.macos_fsevents_check.isChecked() and self.macos_fsevents_path.text():
                sources.append(self.macos_fsevents_path.text())
            if self.macos_tcc_check.isChecked() and self.macos_tcc_path.text():
                sources.append(self.macos_tcc_path.text())
            
            progress_bar = self.macos_progress
            status_label = self.macos_status
            summary_text = self.macos_summary
            
        elif platform == "linux":
            if self.linux_syslog_check.isChecked() and self.linux_syslog_path.text():
                sources.append(self.linux_syslog_path.text())
            if self.linux_journal_check.isChecked() and self.linux_journal_path.text():
                sources.append(self.linux_journal_path.text())
            if self.linux_audit_check.isChecked() and self.linux_audit_path.text():
                sources.append(self.linux_audit_path.text())
            
            progress_bar = self.linux_progress
            status_label = self.linux_status
            summary_text = self.linux_summary
            
        elif platform == "mobile":
            if self.mobile_backup_path.text():
                sources.append(self.mobile_backup_path.text())
            
            platform_type = self.mobile_platform_combo.currentText().lower()
            if platform_type != "auto-detect":
                options['platform_type'] = platform_type
            
            progress_bar = self.mobile_progress
            status_label = self.mobile_status
            summary_text = self.mobile_summary
        
        else:
            return
        
        if not sources:
            status_label.setText("⚠️ Please select at least one source")
            return
        
        # Show progress
        progress_bar.setVisible(True)
        progress_bar.setValue(0)
        status_label.setText("Parsing...")
        summary_text.clear()
        
        # Create and start worker
        self.parser_worker = ParserWorker(platform, sources, options)
        self.parser_worker.progress.connect(
            lambda p, s: self._on_parse_progress(progress_bar, status_label, p, s)
        )
        self.parser_worker.finished.connect(
            lambda df: self._on_parse_complete(progress_bar, status_label, summary_text, df)
        )
        self.parser_worker.error.connect(
            lambda err: self._on_parse_error(progress_bar, status_label, err)
        )
        self.parser_worker.start()
        
        self.logger.info(f"Parsing {platform} artifacts from {len(sources)} sources")
    
    def _on_parse_progress(self, progress_bar, status_label, progress: int, status: str):
        """Handle parsing progress."""
        progress_bar.setValue(progress)
        status_label.setText(status)
    
    def _on_parse_complete(self, progress_bar, status_label, summary_text, df: pd.DataFrame):
        """Handle parsing completion."""
        self.current_results = df
        
        progress_bar.setVisible(False)
        status_label.setText(f"✅ Parsing complete - {len(df)} events")
        
        # Generate summary
        summary = f"""
Parsing Results
═══════════════

Total Events: {len(df)}

Event Types:
{df['event_type'].value_counts().head(10).to_string() if 'event_type' in df.columns else 'N/A'}

Time Range: {df['timestamp'].min()} to {df['timestamp'].max()}

Top Sources:
{df['source'].value_counts().head(5).to_string() if 'source' in df.columns else 'N/A'}
        """.strip()
        
        summary_text.setText(summary)
        
        self.logger.info(f"Parsing complete: {len(df)} events")
    
    def _on_parse_error(self, progress_bar, status_label, error_msg: str):
        """Handle parsing error."""
        progress_bar.setVisible(False)
        status_label.setText(f"❌ Parsing error: {error_msg}")
        self.logger.error(f"Parsing error: {error_msg}")
    
    def get_results(self) -> Optional[pd.DataFrame]:
        """Get parsed results."""
        return self.current_results
    
    def load_events(self, events_df: pd.DataFrame):
        """
        Load events for platform analysis.
        
        Args:
            events_df: DataFrame with forensic events
        """
        self.logger.info(f"Loaded {len(events_df)} events for platform analysis")
        # Store events for analysis
        self.current_results = events_df
