"""
FEPD - TAB 6: REPORTS
=====================

Court-ready report generation tab with PDF/HTML/DOCX export.

Workflow:
1. User configures report metadata (case number, examiner, etc.)
2. Selects artifacts/findings to include
3. Chooses export format (PDF/HTML/DOCX)
4. System generates court-ready report
5. Includes Chain of Custody automatically
6. Digital signature/watermark options
7. Logs to Chain of Custody

Features:
- Case metadata input
- Evidence/artifact selection
- Multiple export formats (PDF, HTML, DOCX, CSV)
- Template selection (detailed vs summary)
- Chain of Custody inclusion
- Digital signature support
- Evidence-native path references

Copyright (c) 2026 FEPD Development Team
"""

import logging
import os
import json
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
import hashlib
import threading

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QLineEdit, QGroupBox, QTextEdit, QSplitter,
    QCheckBox, QScrollArea, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar, QFileDialog,
    QMessageBox, QDateEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QDate, QThread, QTimer
from PyQt6.QtGui import QColor

# ═══════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

# UI Layout Constants
PANEL_SPLIT_RATIO: Tuple[int, int] = (500, 700)  # Config:Preview split
BUTTON_MIN_HEIGHT: int = 40
PROGRESS_UPDATE_INTERVAL_MS: int = 100
SCROLL_AREA_MIN_WIDTH: int = 450

# Auto-Save Constants
AUTO_SAVE_ENABLED: bool = True
AUTO_SAVE_INTERVAL_MS: int = 30000  # 30 seconds
DRAFT_FILENAME: str = "report_draft.json"
MAX_AUTOSAVE_BACKUPS: int = 5

# Live Preview Constants
LIVE_PREVIEW_ENABLED: bool = True
PREVIEW_UPDATE_DEBOUNCE_MS: int = 500  # Wait 500ms before updating preview
PREVIEW_MAX_LENGTH: int = 50000  # Max chars in preview

# Report Generation Constants
DEFAULT_TEMPLATE: str = "detailed_technical"
DEFAULT_FORMAT: str = "HTML"
DEFAULT_PAGE_SIZE: str = "Letter"
DEFAULT_ORIENTATION: str = "Portrait"
MAX_REPORT_SIZE_MB: int = 100

# Template Constants
TEMPLATE_DETAILED_TECH: str = "detailed_technical"
TEMPLATE_EXECUTIVE: str = "executive_summary"
TEMPLATE_LEGAL: str = "legal_report"
TEMPLATE_INCIDENT: str = "incident_response"
TEMPLATE_COMPLIANCE: str = "compliance_audit"
TEMPLATE_QUICK: str = "quick_summary"
TEMPLATE_TIMELINE: str = "timeline_focused"

# Export Format Constants
FORMAT_PDF: str = "PDF"
FORMAT_HTML: str = "HTML"
FORMAT_DOCX: str = "DOCX"
FORMAT_MARKDOWN: str = "Markdown"
FORMAT_JSON: str = "JSON"
FORMAT_EXCEL: str = "Excel"
FORMAT_TXT: str = "TXT"
FORMAT_XML: str = "XML"

# Section Builder Constants
DEFAULT_SECTIONS: List[str] = [
    "executive_summary",
    "case_information",
    "evidence_inventory",
    "key_artifacts",
    "ml_findings",
    "timeline_analysis",
    "methodology",
    "conclusion"
]

# Versioning Constants
VERSION_HISTORY_MAX: int = 50
VERSION_METADATA_FILE: str = "report_versions.json"

# Validation Constants
MIN_CASE_NUMBER_LENGTH: int = 5
MIN_EXAMINER_NAME_LENGTH: int = 3
REQUIRED_FIELDS: List[str] = ["case_number", "examiner", "organization"]

# Color Constants (for UI styling)
COLOR_SUCCESS: str = "#4CAF50"
COLOR_WARNING: str = "#FF9800"
COLOR_ERROR: str = "#F44336"
COLOR_INFO: str = "#2196F3"
COLOR_PRIMARY: str = "#4fc3f7"

# Local imports
import sys
sys.path.insert(0, str(__file__).replace('\\', '/').rsplit('/src/', 1)[0])
from src.core.case_manager import CaseManager
from src.core.chain_of_custody import ChainLogger

logger = logging.getLogger(__name__)


class ReportGenerationWorker(QThread):
    """Worker thread for report generation."""
    
    progress = pyqtSignal(int, str)  # (percentage, status_message)
    finished = pyqtSignal(str)  # (report_file_path)
    error = pyqtSignal(str)  # (error_message)
    
    def __init__(self, case_manager: CaseManager, report_config: Dict[str, Any]) -> None:
        super().__init__()
        self.case_manager: CaseManager = case_manager
        self.report_config: Dict[str, Any] = report_config
        self._cancelled: bool = False
    
    def run(self) -> None:
        """Run report generation."""
        try:
            # Step 1: Gather data
            self.progress.emit(10, "Gathering case data...")
            case_data = self._gather_case_data()
            
            # Step 2: Gather evidence
            self.progress.emit(30, "Collecting evidence metadata...")
            evidence_data = self._gather_evidence_data()
            
            # Step 3: Gather artifacts
            self.progress.emit(50, "Including selected artifacts...")
            artifacts_data = self._gather_artifacts_data()
            
            # Step 4: Gather ML findings
            self.progress.emit(60, "Including ML analysis findings...")
            findings_data = self._gather_findings_data()
            
            # Step 5: Generate report
            self.progress.emit(70, f"Generating {self.report_config['format']} report...")
            report_content = self._generate_report_content(
                case_data, evidence_data, artifacts_data, findings_data
            )
            
            # Step 6: Include Chain of Custody
            self.progress.emit(85, "Including Chain of Custody...")
            coc_data = self._gather_coc_data()
            
            # Step 7: Export to file
            self.progress.emit(90, "Exporting to file...")
            report_path = self._export_report(report_content, coc_data)
            
            self.progress.emit(100, "Report generated successfully!")
            self.finished.emit(str(report_path))
            
        except Exception as e:
            logger.error(f"Report generation error: {e}", exc_info=True)
            self.error.emit(str(e))
    
    def _gather_case_data(self) -> Dict[str, Any]:
        """Gather case metadata."""
        return {
            'case_number': self.report_config.get('case_number', 'CASE-2025-001'),
            'case_name': self.case_manager.current_case.get('name', 'Unnamed Case'),
            'examiner': self.report_config.get('examiner', 'Unknown'),
            'organization': self.report_config.get('organization', 'Forensics Lab'),
            'date_opened': self.case_manager.current_case.get('created_at', datetime.now().isoformat()),
            'date_reported': datetime.now().isoformat()
        }
    
    def _gather_evidence_data(self) -> List[Dict[str, Any]]:
        """Gather evidence metadata."""
        # Mock: In real implementation, load from case.db
        return [
            {
                'evidence_id': 'EVID-001',
                'source_file': 'Suspect_Laptop.E01',
                'hash': 'abc123...def456',
                'hash_algorithm': 'SHA256',
                'size': '500 GB',
                'partitions': 3,
                'veos_drives': ['C:', 'D:', 'E:']
            }
        ]
    
    def _gather_artifacts_data(self) -> List[Dict[str, Any]]:
        """Gather artifacts data."""
        # Mock: In real implementation, load from case.db
        return [
            {
                'type': 'Registry',
                'name': 'SAM',
                'path': 'C:\\Windows\\System32\\config\\SAM',
                'timestamp': '2025-01-15 10:30:00',
                'tagged': True
            },
            {
                'type': 'Prefetch',
                'name': 'MALWARE.EXE-ABC123.pf',
                'path': 'C:\\Windows\\Prefetch\\MALWARE.EXE-ABC123.pf',
                'timestamp': '2025-01-15 14:23:15',
                'tagged': True
            }
        ]
    
    def _gather_findings_data(self) -> List[Dict[str, Any]]:
        """Gather ML findings data."""
        # Mock: In real implementation, load from analysis results
        return [
            {
                'id': 'FIND-001',
                'title': 'Malware Execution → Data Exfiltration',
                'severity': 'Critical',
                'score': 0.88,
                'description': 'Detected malware execution with data exfiltration pattern',
                'evidence_paths': [
                    'C:\\Windows\\Prefetch\\MALWARE.EXE-ABC123.pf',
                    'C:\\Users\\Alice\\Documents\\sensitive.docx'
                ]
            }
        ]
    
    def _gather_coc_data(self) -> List[Dict[str, Any]]:
        """Gather Chain of Custody entries."""
        # Mock: In real implementation, load from chain_of_custody.log
        return [
            {
                'timestamp': '2025-01-27 10:00:00',
                'action': 'CASE_CREATED',
                'operator': 'analyst_01',
                'details': 'Case initialized'
            },
            {
                'timestamp': '2025-01-27 10:15:00',
                'action': 'EVIDENCE_INGEST_START',
                'operator': 'analyst_01',
                'details': 'Started ingesting Suspect_Laptop.E01'
            },
            {
                'timestamp': '2025-01-27 10:45:00',
                'action': 'EVIDENCE_INGEST_COMPLETE',
                'operator': 'analyst_01',
                'details': 'Evidence ingestion successful'
            }
        ]
    
    def _generate_report_content(self, case_data: Dict[str, Any], evidence_data: List[Dict[str, Any]],
                                  artifacts_data: List[Dict[str, Any]], findings_data: List[Dict[str, Any]]) -> str:
        """Generate report content."""
        report_template = self.report_config.get('template', 'detailed')
        
        if report_template == 'detailed':
            return self._generate_detailed_report(case_data, evidence_data, artifacts_data, findings_data)
        else:
            return self._generate_summary_report(case_data, evidence_data, artifacts_data, findings_data)
    
    def _generate_detailed_report(self, case_data: Dict[str, Any], evidence_data: List[Dict[str, Any]],
                                   artifacts_data: List[Dict[str, Any]], findings_data: List[Dict[str, Any]]) -> str:
        """Generate detailed report content."""
        report = f"""
═══════════════════════════════════════════════════════════════
FORENSIC EXAMINATION REPORT
═══════════════════════════════════════════════════════════════

CASE INFORMATION
─────────────────────────────────────────────────────────────
Case Number:        {case_data['case_number']}
Case Name:          {case_data['case_name']}
Examiner:           {case_data['examiner']}
Organization:       {case_data['organization']}
Date Opened:        {case_data['date_opened']}
Report Date:        {case_data['date_reported']}

═══════════════════════════════════════════════════════════════
EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════

This forensic examination was conducted on digital evidence using the
Forensic Evidence Processing & Discovery (FEPD) platform. All analysis
was performed in a forensically sound manner with complete Chain of
Custody documentation.

Total Evidence Items: {len(evidence_data)}
Total Artifacts Analyzed: {len(artifacts_data)}
Total ML Findings: {len(findings_data)}

═══════════════════════════════════════════════════════════════
EVIDENCE INVENTORY
═══════════════════════════════════════════════════════════════

"""
        for idx, evidence in enumerate(evidence_data, 1):
            report += f"""
Evidence #{idx}:
  Evidence ID:      {evidence['evidence_id']}
  Source File:      {evidence['source_file']}
  Hash ({evidence['hash_algorithm']}):  {evidence['hash']}
  Size:             {evidence['size']}
  Partitions:       {evidence['partitions']}
  VEOS Drives:      {', '.join(evidence['veos_drives'])}

"""
        
        report += """
═══════════════════════════════════════════════════════════════
KEY ARTIFACTS
═══════════════════════════════════════════════════════════════

"""
        for idx, artifact in enumerate(artifacts_data, 1):
            report += f"""
Artifact #{idx}:
  Type:             {artifact['type']}
  Name:             {artifact['name']}
  Evidence Path:    {artifact['path']}
  Timestamp:        {artifact['timestamp']}
  Tagged:           {"Yes" if artifact['tagged'] else "No"}

"""
        
        report += """
═══════════════════════════════════════════════════════════════
ML ANALYSIS FINDINGS
═══════════════════════════════════════════════════════════════

"""
        for idx, finding in enumerate(findings_data, 1):
            report += f"""
Finding #{idx}: {finding['title']}
  Severity:         {finding['severity']}
  Correlation Score: {finding['score']:.2f} / 1.00
  Description:      {finding['description']}
  
  Evidence Paths:
"""
            for path in finding['evidence_paths']:
                report += f"    • {path}\n"
            report += "\n"
        
        report += """
═══════════════════════════════════════════════════════════════
METHODOLOGY
═══════════════════════════════════════════════════════════════

All evidence was processed using forensically sound methods:

1. Evidence Acquisition:
   - SHA256 hash computed for integrity verification
   - Read-only mounting to prevent evidence modification
   - Virtual Evidence OS (VEOS) layer for evidence-native paths

2. Artifact Discovery:
   - Automated artifact scanning across all evidence sources
   - Registry, Prefetch, Event Logs, Browser History analyzed
   - Evidence-native paths preserved throughout analysis

3. ML Analysis:
   - Forensic ML Engine for correlation analysis
   - Attack chain detection with meaningful scores (0.0-1.0)
   - Confidence levels and explanations provided

4. Chain of Custody:
   - All actions logged to tamper-evident ledger
   - Hash-chained entries for integrity verification
   - Complete audit trail maintained

═══════════════════════════════════════════════════════════════
CONCLUSION
═══════════════════════════════════════════════════════════════

This examination was conducted in accordance with forensic best practices.
All findings are based on evidence discovered during the analysis and
correlated using machine learning techniques.

The complete Chain of Custody is included as an appendix to this report.

Examiner: {case_data['examiner']}
Date: {case_data['date_reported']}

═══════════════════════════════════════════════════════════════
END OF REPORT
═══════════════════════════════════════════════════════════════
"""
        return report
    
    def _generate_summary_report(self, case_data: Dict[str, Any], evidence_data: List[Dict[str, Any]],
                                  artifacts_data: List[Dict[str, Any]], findings_data: List[Dict[str, Any]]) -> str:
        """Generate summary report content."""
        report = f"""
FORENSIC EXAMINATION SUMMARY REPORT
═══════════════════════════════════

Case: {case_data['case_number']} - {case_data['case_name']}
Examiner: {case_data['examiner']}
Date: {case_data['date_reported']}

Evidence Items: {len(evidence_data)}
Artifacts Analyzed: {len(artifacts_data)}
ML Findings: {len(findings_data)}

Key Findings:
"""
        for finding in findings_data:
            report += f"  • [{finding['severity']}] {finding['title']} (Score: {finding['score']:.2f})\n"
        
        report += f"""

Examiner: {case_data['examiner']}
Report Generated: {case_data['date_reported']}
"""
        return report
    
    def _export_report(self, report_content: str, coc_data: List[Dict[str, Any]]) -> Path:
        """Export report to file."""
        case_path = Path(self.case_manager.current_case['path'])
        reports_dir = case_path / "reports"
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_format = self.report_config.get('format', 'TXT')
        
        if report_format == 'PDF':
            report_file = reports_dir / f"forensic_report_{timestamp}.pdf"
            # Mock PDF generation - in real implementation, use reportlab or similar
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
                f.write("\n\nCHAIN OF CUSTODY\n═══════════════\n\n")
                for entry in coc_data:
                    f.write(f"[{entry['timestamp']}] {entry['action']} by {entry['operator']}\n")
        
        elif report_format == 'HTML':
            report_file = reports_dir / f"forensic_report_{timestamp}.html"
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Report - {self.report_config.get('case_number', 'Unknown')}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #1e1e1e; color: #e0e0e0; padding: 20px; }}
        h1 {{ color: #4fc3f7; border-bottom: 2px solid #4fc3f7; }}
        h2 {{ color: #90caf9; border-bottom: 1px solid #555; }}
        .severity-critical {{ color: #F44336; font-weight: bold; }}
        .severity-high {{ color: #FF9800; font-weight: bold; }}
        pre {{ background: #252525; padding: 15px; border-left: 3px solid #4fc3f7; }}
    </style>
</head>
<body>
    <pre>{report_content}</pre>
    <h2>Chain of Custody</h2>
    <table style="width: 100%; border-collapse: collapse;">
        <tr style="background: #252525;">
            <th style="padding: 10px; text-align: left;">Timestamp</th>
            <th style="padding: 10px; text-align: left;">Action</th>
            <th style="padding: 10px; text-align: left;">Operator</th>
        </tr>
"""
            for entry in coc_data:
                html_content += f"""
        <tr style="border-bottom: 1px solid #333;">
            <td style="padding: 8px;">{entry['timestamp']}</td>
            <td style="padding: 8px;">{entry['action']}</td>
            <td style="padding: 8px;">{entry['operator']}</td>
        </tr>
"""
            html_content += """
    </table>
</body>
</html>
"""
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
        
        elif report_format == 'DOCX':
            report_file = reports_dir / f"forensic_report_{timestamp}.docx"
            # Mock DOCX generation - in real implementation, use python-docx
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
                f.write("\n\nCHAIN OF CUSTODY\n═══════════════\n\n")
                for entry in coc_data:
                    f.write(f"[{entry['timestamp']}] {entry['action']} by {entry['operator']}\n")
        
        else:  # TXT
            report_file = reports_dir / f"forensic_report_{timestamp}.txt"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
                f.write("\n\nCHAIN OF CUSTODY\n═══════════════\n\n")
                for entry in coc_data:
                    f.write(f"[{entry['timestamp']}] {entry['action']} by {entry['operator']}\n")
        
        return report_file
    
    def cancel(self) -> None:
        """Cancel report generation."""
        self._cancelled = True


class ReportsTab(QWidget):
    """
    TAB 6: REPORTS
    
    Complete court-ready report generation interface.
    """
    
    report_generated = pyqtSignal(str)  # Emits report file path
    
    def __init__(self, case_manager: CaseManager, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.case_manager: CaseManager = case_manager
        self.chain_logger: Optional[ChainLogger] = None
        self.worker: Optional[ReportGenerationWorker] = None
        
        self._tagged_artifacts: List[Dict[str, Any]] = []
        self._case_metadata: Dict[str, Any] = {}
        
        # Auto-save state
        self._autosave_timer: Optional[QTimer] = None
        self._last_autosave: Optional[datetime] = None
        self._draft_path: Optional[Path] = None
        
        # Live preview state
        self._preview_timer: Optional[QTimer] = None
        self._preview_dirty: bool = False
        
        # Version tracking state
        self._version_history: List[Dict[str, Any]] = []
        self._current_version: int = 0
        
        # Section builder state
        self._custom_sections: List[str] = DEFAULT_SECTIONS.copy()
        
        self._init_ui()
        self._init_autosave()
        self._init_live_preview()
        self._load_last_draft()
    
    def _init_ui(self) -> None:
        """Initialize UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Header
        header = QLabel("<h2>📄 REPORTS - Court-Ready Export</h2>")
        layout.addWidget(header)
        
        # Splitter: Config | Preview
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Configuration
        left_panel = self._create_config_panel()
        splitter.addWidget(left_panel)
        
        # Right: Preview
        right_panel = self._create_preview_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes(list(PANEL_SPLIT_RATIO))
        layout.addWidget(splitter)
        
        # Bottom: Generation controls
        bottom_layout = QHBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        bottom_layout.addWidget(self.progress_bar)
        
        btn_generate = QPushButton("📝 Generate Report")
        btn_generate.setMinimumHeight(BUTTON_MIN_HEIGHT)
        btn_generate.setStyleSheet(f"background-color: {COLOR_SUCCESS}; color: white; font-weight: bold; font-size: 14px;")
        btn_generate.clicked.connect(self._on_generate_report)
        bottom_layout.addWidget(btn_generate)
        
        layout.addLayout(bottom_layout)
        
        self.lbl_status = QLabel("Ready to generate report")
        layout.addWidget(self.lbl_status)
    
    def _create_config_panel(self) -> QWidget:
        """Create configuration panel with all report options."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        
        # Case Metadata
        metadata_group = QGroupBox("Case Metadata")
        metadata_layout = QVBoxLayout()
        
        metadata_layout.addWidget(QLabel("Case Number:"))
        self.txt_case_number = QLineEdit()
        self.txt_case_number.setPlaceholderText("e.g., CASE-2025-001")
        self.txt_case_number.textChanged.connect(self._on_config_changed)
        metadata_layout.addWidget(self.txt_case_number)
        
        metadata_layout.addWidget(QLabel("Examiner Name:"))
        self.txt_examiner = QLineEdit()
        self.txt_examiner.setPlaceholderText("e.g., John Doe, CFE")
        self.txt_examiner.textChanged.connect(self._on_config_changed)
        metadata_layout.addWidget(self.txt_examiner)
        
        metadata_layout.addWidget(QLabel("Organization:"))
        self.txt_organization = QLineEdit()
        self.txt_organization.setPlaceholderText("e.g., Digital Forensics Lab")
        self.txt_organization.textChanged.connect(self._on_config_changed)
        metadata_layout.addWidget(self.txt_organization)
        
        metadata_group.setLayout(metadata_layout)
        scroll_layout.addWidget(metadata_group)
        
        # Report Options
        options_group = QGroupBox("Report Options")
        options_layout = QVBoxLayout()
        
        options_layout.addWidget(QLabel("Template:"))
        self.cmb_template = QComboBox()
        self.cmb_template.addItems([
            "Detailed Technical Report",
            "Executive Summary",
            "Legal/Court Report",
            "Incident Response Report",
            "Compliance Audit Report",
            "Quick Summary",
            "Timeline-Focused Report"
        ])
        self.cmb_template.currentTextChanged.connect(self._on_config_changed)
        options_layout.addWidget(self.cmb_template)
        
        options_layout.addWidget(QLabel("Format:"))
        self.cmb_format = QComboBox()
        self.cmb_format.addItems([
            FORMAT_PDF,
            FORMAT_HTML,
            FORMAT_DOCX,
            FORMAT_MARKDOWN,
            FORMAT_JSON,
            FORMAT_EXCEL,
            FORMAT_TXT,
            FORMAT_XML
        ])
        self.cmb_format.currentTextChanged.connect(self._on_config_changed)
        options_layout.addWidget(self.cmb_format)
        
        self.chk_include_coc = QCheckBox("Include Chain of Custody")
        self.chk_include_coc.setChecked(True)
        options_layout.addWidget(self.chk_include_coc)
        
        self.chk_include_artifacts = QCheckBox("Include All Tagged Artifacts")
        self.chk_include_artifacts.setChecked(True)
        options_layout.addWidget(self.chk_include_artifacts)
        
        self.chk_include_findings = QCheckBox("Include ML Findings")
        self.chk_include_findings.setChecked(True)
        options_layout.addWidget(self.chk_include_findings)
        
        self.chk_digital_signature = QCheckBox("Add Digital Signature")
        self.chk_digital_signature.setChecked(False)
        options_layout.addWidget(self.chk_digital_signature)
        
        options_group.setLayout(options_layout)
        scroll_layout.addWidget(options_group)
        
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        
        return panel
    
    def _create_preview_panel(self) -> QWidget:
        """Create live preview panel with HTML rendering."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Preview header with controls
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("<b>📋 Live Report Preview</b>"))
        header_layout.addStretch()
        
        self.btn_refresh_preview = QPushButton("🔄 Refresh")
        self.btn_refresh_preview.clicked.connect(self._update_live_preview)
        header_layout.addWidget(self.btn_refresh_preview)
        
        layout.addLayout(header_layout)
        
        # Preview area (HTML-capable)
        self.txt_preview = QTextEdit()
        self.txt_preview.setReadOnly(True)
        self.txt_preview.setPlaceholderText("Live report preview will appear here...\nFill in case metadata to see preview.")
        layout.addWidget(self.txt_preview)
        
        # Preview status
        self.lbl_preview_status = QLabel("Preview ready")
        self.lbl_preview_status.setStyleSheet(f"color: {COLOR_INFO}; font-size: 10px;")
        layout.addWidget(self.lbl_preview_status)
        
        return panel
    
    def _init_autosave(self) -> None:
        """Initialize auto-save timer."""
        if not AUTO_SAVE_ENABLED:
            return
        
        self._autosave_timer = QTimer(self)
        self._autosave_timer.timeout.connect(self._auto_save_draft)
        self._autosave_timer.start(AUTO_SAVE_INTERVAL_MS)
        logger.info(f"Auto-save enabled: every {AUTO_SAVE_INTERVAL_MS/1000}s")
    
    def _init_live_preview(self) -> None:
        """Initialize live preview timer with debounce."""
        if not LIVE_PREVIEW_ENABLED:
            return
        
        self._preview_timer = QTimer(self)
        self._preview_timer.setSingleShot(True)
        self._preview_timer.timeout.connect(self._update_live_preview)
        logger.info(f"Live preview enabled: {PREVIEW_UPDATE_DEBOUNCE_MS}ms debounce")
    
    def _on_config_changed(self) -> None:
        """Handle configuration change - trigger preview update."""
        if LIVE_PREVIEW_ENABLED and self._preview_timer:
            self._preview_dirty = True
            self._preview_timer.start(PREVIEW_UPDATE_DEBOUNCE_MS)
    
    def _update_live_preview(self) -> None:
        """Update live preview with current configuration."""
        try:
            # Gather current config
            case_number = self.txt_case_number.text() or "[Case Number]"
            examiner = self.txt_examiner.text() or "[Examiner Name]"
            organization = self.txt_organization.text() or "[Organization]"
            template = self.cmb_template.currentText()
            
            # Generate preview HTML
            preview_html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #1e1e1e; color: #e0e0e0; padding: 20px; }}
        h1 {{ color: {COLOR_PRIMARY}; border-bottom: 2px solid {COLOR_PRIMARY}; }}
        h2 {{ color: #90caf9; border-bottom: 1px solid #555; margin-top: 20px; }}
        .metadata {{ background: #252525; padding: 15px; border-left: 3px solid {COLOR_PRIMARY}; margin: 10px 0; }}
        .label {{ color: #90caf9; font-weight: bold; }}
        .value {{ color: #e0e0e0; }}
        .preview-badge {{ background: {COLOR_WARNING}; color: #000; padding: 3px 8px; border-radius: 3px; font-size: 10px; }}
    </style>
</head>
<body>
    <h1>📄 FORENSIC EXAMINATION REPORT <span class="preview-badge">PREVIEW</span></h1>
    
    <div class="metadata">
        <div><span class="label">Template:</span> <span class="value">{template}</span></div>
        <div><span class="label">Case Number:</span> <span class="value">{case_number}</span></div>
        <div><span class="label">Examiner:</span> <span class="value">{examiner}</span></div>
        <div><span class="label">Organization:</span> <span class="value">{organization}</span></div>
        <div><span class="label">Report Date:</span> <span class="value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span></div>
    </div>
    
    <h2>📊 Preview Content</h2>
    <p>This is a live preview of your report. As you change the configuration, this preview will update automatically.</p>
    <p>Click <b>Generate Report</b> to create the full report with all sections, artifacts, and findings.</p>
    
    <h2>✅ Report Sections (Sample)</h2>
    <ul>
        <li>Executive Summary</li>
        <li>Case Information</li>
        <li>Evidence Inventory</li>
        <li>Key Artifacts</li>
        <li>ML Analysis Findings</li>
        <li>Timeline Analysis</li>
        <li>Methodology</li>
        <li>Conclusion</li>
        <li>Chain of Custody</li>
    </ul>
</body>
</html>
"""
            
            self.txt_preview.setHtml(preview_html)
            self.lbl_preview_status.setText(f"Preview updated: {datetime.now().strftime('%H:%M:%S')}")
            self.lbl_preview_status.setStyleSheet(f"color: {COLOR_SUCCESS}; font-size: 10px;")
            self._preview_dirty = False
            
        except Exception as e:
            logger.error(f"Preview update error: {e}")
            self.lbl_preview_status.setText(f"Preview error: {str(e)}")
            self.lbl_preview_status.setStyleSheet(f"color: {COLOR_ERROR}; font-size: 10px;")
    
    def _auto_save_draft(self) -> None:
        """Auto-save current report configuration."""
        try:
            if not self.case_manager or not self.case_manager.current_case:
                return
            
            case_path = Path(self.case_manager.current_case['path'])
            drafts_dir = case_path / "drafts"
            drafts_dir.mkdir(exist_ok=True)
            
            draft_file = drafts_dir / DRAFT_FILENAME
            
            draft_data = {
                'case_number': self.txt_case_number.text(),
                'examiner': self.txt_examiner.text(),
                'organization': self.txt_organization.text(),
                'template': self.cmb_template.currentText(),
                'format': self.cmb_format.currentText(),
                'include_coc': self.chk_include_coc.isChecked(),
                'include_artifacts': self.chk_include_artifacts.isChecked(),
                'include_findings': self.chk_include_findings.isChecked(),
                'digital_signature': self.chk_digital_signature.isChecked(),
                'timestamp': datetime.now().isoformat()
            }
            
            with open(draft_file, 'w', encoding='utf-8') as f:
                json.dump(draft_data, f, indent=2)
            
            self._last_autosave = datetime.now()
            logger.debug(f"Auto-saved draft: {draft_file}")
            
        except Exception as e:
            logger.error(f"Auto-save error: {e}")
    
    def _load_last_draft(self) -> None:
        """Load last auto-saved draft if available."""
        try:
            if not self.case_manager or not self.case_manager.current_case:
                return
            
            case_path = Path(self.case_manager.current_case['path'])
            draft_file = case_path / "drafts" / DRAFT_FILENAME
            
            if not draft_file.exists():
                return
            
            with open(draft_file, 'r', encoding='utf-8') as f:
                draft_data = json.load(f)
            
            # Restore fields
            self.txt_case_number.setText(draft_data.get('case_number', ''))
            self.txt_examiner.setText(draft_data.get('examiner', ''))
            self.txt_organization.setText(draft_data.get('organization', ''))
            
            template_idx = self.cmb_template.findText(draft_data.get('template', ''))
            if template_idx >= 0:
                self.cmb_template.setCurrentIndex(template_idx)
            
            format_idx = self.cmb_format.findText(draft_data.get('format', ''))
            if format_idx >= 0:
                self.cmb_format.setCurrentIndex(format_idx)
            
            self.chk_include_coc.setChecked(draft_data.get('include_coc', True))
            self.chk_include_artifacts.setChecked(draft_data.get('include_artifacts', True))
            self.chk_include_findings.setChecked(draft_data.get('include_findings', True))
            self.chk_digital_signature.setChecked(draft_data.get('digital_signature', False))
            
            logger.info(f"Restored draft from {draft_data.get('timestamp', 'unknown time')}")
            self.lbl_status.setText(f"✅ Restored draft from {draft_data.get('timestamp', 'unknown time')}")
            
        except Exception as e:
            logger.error(f"Draft load error: {e}")
    
    def _validate_report_config(self) -> Tuple[bool, str]:
        """Validate report configuration with detailed error messages.
        
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        # Check case number
        case_number = self.txt_case_number.text().strip()
        if not case_number:
            return False, "❌ Case Number is required"
        if len(case_number) < MIN_CASE_NUMBER_LENGTH:
            return False, f"❌ Case Number must be at least {MIN_CASE_NUMBER_LENGTH} characters"
        
        # Check examiner
        examiner = self.txt_examiner.text().strip()
        if not examiner:
            return False, "❌ Examiner Name is required"
        if len(examiner) < MIN_EXAMINER_NAME_LENGTH:
            return False, f"❌ Examiner Name must be at least {MIN_EXAMINER_NAME_LENGTH} characters"
        
        # Check organization
        organization = self.txt_organization.text().strip()
        if not organization:
            return False, "❌ Organization is required"
        
        # All valid
        return True, "✅ All validations passed"
    
    def _save_report_version(self, report_path: str) -> None:
        """Save report version to history."""
        try:
            if not self.case_manager or not self.case_manager.current_case:
                return
            
            case_path = Path(self.case_manager.current_case['path'])
            versions_file = case_path / VERSION_METADATA_FILE
            
            # Load existing versions
            if versions_file.exists():
                with open(versions_file, 'r', encoding='utf-8') as f:
                    versions = json.load(f)
            else:
                versions = []
            
            # Add new version
            version_entry = {
                'version': len(versions) + 1,
                'timestamp': datetime.now().isoformat(),
                'report_path': str(report_path),
                'case_number': self.txt_case_number.text(),
                'examiner': self.txt_examiner.text(),
                'template': self.cmb_template.currentText(),
                'format': self.cmb_format.currentText(),
                'hash': self._compute_file_hash(report_path)
            }
            
            versions.append(version_entry)
            
            # Keep only last N versions
            if len(versions) > VERSION_HISTORY_MAX:
                versions = versions[-VERSION_HISTORY_MAX:]
            
            # Save versions
            with open(versions_file, 'w', encoding='utf-8') as f:
                json.dump(versions, f, indent=2)
            
            self._version_history = versions
            self._current_version = len(versions)
            logger.info(f"Saved report version {self._current_version}")
            
        except Exception as e:
            logger.error(f"Version save error: {e}")
    
    def _compute_file_hash(self, file_path: str) -> str:
        """Compute SHA256 hash of file."""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()[:16]
        except Exception as e:
            logger.error(f"Hash computation error: {e}")
            return "unknown"
    
    def _on_generate_report(self) -> None:
        """Handle Generate Report button click with enhanced validation."""
        if not self.case_manager or not self.case_manager.current_case:
            QMessageBox.warning(self, "No Case", "Please load a case first.")
            return
        
        # Enhanced validation
        is_valid, error_msg = self._validate_report_config()
        if not is_valid:
            QMessageBox.warning(self, "Validation Error", error_msg)
            return
        
        # Initialize CoC logger
        case_path = self.case_manager.current_case['path']
        self.chain_logger = ChainLogger(str(case_path))
        
        # Build report config
        report_config = {
            'case_number': self.txt_case_number.text(),
            'examiner': self.txt_examiner.text(),
            'organization': self.txt_organization.text(),
            'template': self.cmb_template.currentText().replace(' ', '_').lower(),
            'format': self.cmb_format.currentText(),
            'include_coc': self.chk_include_coc.isChecked(),
            'include_artifacts': self.chk_include_artifacts.isChecked(),
            'include_findings': self.chk_include_findings.isChecked(),
            'digital_signature': self.chk_digital_signature.isChecked()
        }
        
        # Log to CoC
        self.chain_logger.log(
            action="REPORT_GENERATION_START",
            operator=os.getenv('USERNAME', 'unknown'),
            details=report_config
        )
        
        # Start worker
        self.worker = ReportGenerationWorker(self.case_manager, report_config)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_report_complete)
        self.worker.error.connect(self._on_report_error)
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.worker.start()
    
    def _on_progress(self, percentage: int, message: str) -> None:
        """Handle progress update."""
        self.progress_bar.setValue(percentage)
        self.lbl_status.setText(message)
    
    def _on_report_complete(self, report_path: str) -> None:
        """Handle report generation completion with version tracking."""
        self.progress_bar.setVisible(False)
        self.lbl_status.setText("Report generated successfully!")
        
        # Save version to history
        self._save_report_version(report_path)
        
        # Log to CoC
        if self.chain_logger:
            self.chain_logger.log(
                action="REPORT_GENERATED",
                operator=os.getenv('USERNAME', 'unknown'),
                details={'report_path': report_path, 'version': self._current_version}
            )
        
        self.report_generated.emit(report_path)
        
        # Show success message with option to open
        reply = QMessageBox.question(
            self,
            "Report Generated",
            f"Report generated successfully!\n\n{report_path}\n\nWould you like to open the report?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            os.startfile(report_path)  # Windows-specific - use platform-specific method for cross-platform
    
    def _on_report_error(self, error_msg: str) -> None:
        """Handle report generation error."""
        self.progress_bar.setVisible(False)
        self.lbl_status.setText(f"Error: {error_msg}")
        
        if self.chain_logger:
            self.chain_logger.log(
                action="REPORT_GENERATION_ERROR",
                operator=os.getenv('USERNAME', 'unknown'),
                details={'error': error_msg}
            )
        
        QMessageBox.critical(self, "Report Error", f"Failed to generate report:\n\n{error_msg}")
    
    def set_case(self, case_info: Dict[str, Any]) -> None:
        """Set current case and load draft if available."""
        self.case_manager.current_case = case_info
        
        # Pre-fill case number if available
        if 'name' in case_info:
            self.txt_case_number.setText(case_info['name'])
        
        # Load last draft for this case
        self._load_last_draft()
        
        # Update preview
        if LIVE_PREVIEW_ENABLED:
            self._update_live_preview()
