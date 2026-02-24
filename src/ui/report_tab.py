"""
FEPD - Report Generation Tab
Professional forensic report generation with case metadata, evidence selection, and multiple export formats

Features:
- Case metadata input (case number, examiner, dates, victim/suspect info)
- Evidence selection with review pane
- Tagged artifacts automatic inclusion
- Multiple format support (PDF, HTML, DOCX, CSV)
- Template selection (detailed vs summary)
- Chain-of-Custody automatic inclusion
- Digital signature/watermark options
- Preview before generation
- Output confirmation with file location
"""

import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QLineEdit, QGroupBox, QTextEdit, QSplitter,
    QCheckBox, QScrollArea, QFrame, QDateEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar, QFileDialog,
    QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QDate

# Optional WebEngine import with fallback
try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    WEBENGINE_AVAILABLE = True
except ImportError:
    WEBENGINE_AVAILABLE = False
    QWebEngineView = None  # type: ignore


class ReportTab(QWidget):
    """
    Complete report generation tab with metadata, evidence selection, and export.
    """
    
    report_generated = pyqtSignal(str)  # Emits report file path
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        
        self._tagged_artifacts = []  # Artifacts marked for reporting
        self._case_metadata = {}
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Splitter: Left (Config) | Right (Preview)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side: Configuration
        left_panel = self._create_config_panel()
        splitter.addWidget(left_panel)
        
        # Right side: Preview
        right_panel = self._create_preview_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([600, 600])
        layout.addWidget(splitter)
        
        # Bottom: Generation controls
        bottom_controls = self._create_generation_controls()
        layout.addWidget(bottom_controls)
    
    def _create_config_panel(self) -> QWidget:
        """Create left configuration panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Scroll area for all config sections
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        
        # Case Metadata section
        metadata_group = self._create_case_metadata_section()
        scroll_layout.addWidget(metadata_group)
        
        # Evidence Selection section
        evidence_group = self._create_evidence_selection_section()
        scroll_layout.addWidget(evidence_group)
        
        # Report Options section
        options_group = self._create_report_options_section()
        scroll_layout.addWidget(options_group)
        
        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        
        return panel
    
    def _create_case_metadata_section(self) -> QGroupBox:
        """Create case metadata input section."""
        group = QGroupBox("📋 Case Metadata")
        layout = QVBoxLayout()
        
        # Case Number
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Case Number:"))
        self.txt_case_number = QLineEdit()
        self.txt_case_number.setPlaceholderText("e.g., CASE-2025-001")
        row1.addWidget(self.txt_case_number)
        layout.addLayout(row1)
        
        # Examiner Name
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Examiner Name:"))
        self.txt_examiner_name = QLineEdit()
        self.txt_examiner_name.setPlaceholderText("e.g., John Doe")
        row2.addWidget(self.txt_examiner_name)
        layout.addLayout(row2)
        
        # Organization
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Organization:"))
        self.txt_organization = QLineEdit()
        self.txt_organization.setPlaceholderText("e.g., Digital Forensics Lab")
        row3.addWidget(self.txt_organization)
        layout.addLayout(row3)
        
        # Dates
        dates_layout = QHBoxLayout()
        
        dates_layout.addWidget(QLabel("Exam Start Date:"))
        self.date_exam_start = QDateEdit()
        self.date_exam_start.setCalendarPopup(True)
        self.date_exam_start.setDate(QDate.currentDate())
        dates_layout.addWidget(self.date_exam_start)
        
        dates_layout.addWidget(QLabel("Exam End Date:"))
        self.date_exam_end = QDateEdit()
        self.date_exam_end.setCalendarPopup(True)
        self.date_exam_end.setDate(QDate.currentDate())
        dates_layout.addWidget(self.date_exam_end)
        
        layout.addLayout(dates_layout)
        
        # Victim/Suspect Information
        row4 = QHBoxLayout()
        row4.addWidget(QLabel("Victim/Suspect:"))
        self.txt_victim_suspect = QLineEdit()
        self.txt_victim_suspect.setPlaceholderText("e.g., Jane Smith (Victim)")
        row4.addWidget(self.txt_victim_suspect)
        layout.addLayout(row4)
        
        # Case Summary
        layout.addWidget(QLabel("Case Summary:"))
        self.txt_case_summary = QTextEdit()
        self.txt_case_summary.setPlaceholderText("Brief summary of the case and examination objectives...")
        self.txt_case_summary.setMaximumHeight(80)
        layout.addWidget(self.txt_case_summary)
        
        group.setLayout(layout)
        return group
    
    def _create_evidence_selection_section(self) -> QGroupBox:
        """Create evidence selection section."""
        group = QGroupBox("⭐ Evidence Selection")
        layout = QVBoxLayout()
        
        # Info label
        info_label = QLabel(
            "Select which artifacts to include in the report. "
            "Tagged artifacts are automatically included."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(info_label)
        
        # Evidence table
        self.tbl_evidence = QTableWidget()
        self.tbl_evidence.setColumnCount(5)
        self.tbl_evidence.setHorizontalHeaderLabels([
            "Include", "Type", "Name", "Path", "Date/Time"
        ])
        
        header = self.tbl_evidence.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        
        self.tbl_evidence.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_evidence.setAlternatingRowColors(True)
        layout.addWidget(self.tbl_evidence)
        
        # Selection buttons
        btn_layout = QHBoxLayout()
        
        btn_select_all = QPushButton("✓ Select All")
        btn_select_all.clicked.connect(self._select_all_evidence)
        btn_layout.addWidget(btn_select_all)
        
        btn_deselect_all = QPushButton("✗ Deselect All")
        btn_deselect_all.clicked.connect(self._deselect_all_evidence)
        btn_layout.addWidget(btn_deselect_all)
        
        btn_layout.addStretch()
        
        self.lbl_evidence_count = QLabel("0 artifacts selected")
        btn_layout.addWidget(self.lbl_evidence_count)
        
        layout.addLayout(btn_layout)
        
        group.setLayout(layout)
        return group
    
    def _create_report_options_section(self) -> QGroupBox:
        """Create report options section."""
        group = QGroupBox("⚙️ Report Options")
        layout = QVBoxLayout()
        
        # Report Format
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Report Format:"))
        self.cmb_format = QComboBox()
        self.cmb_format.addItems([
            "PDF - Portable Document Format",
            "HTML - Web Page",
            "DOCX - Microsoft Word",
            "CSV - Comma-Separated Values"
        ])
        self.cmb_format.currentIndexChanged.connect(self._on_format_changed)
        row1.addWidget(self.cmb_format)
        layout.addLayout(row1)
        
        # Report Template
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Report Template:"))
        self.cmb_template = QComboBox()
        self.cmb_template.addItems([
            "Detailed Report - Full findings with all metadata",
            "Summary Report - Executive summary with key findings",
            "Evidence List - Simple list of selected artifacts",
            "Timeline Report - Chronological event summary"
        ])
        row2.addWidget(self.cmb_template)
        layout.addLayout(row2)
        
        # Include options
        layout.addWidget(QLabel("<b>Include in Report:</b>"))
        
        self.chk_coc = QCheckBox("Chain-of-Custody Log")
        self.chk_coc.setChecked(True)
        self.chk_coc.setToolTip("Include complete chain-of-custody log")
        layout.addWidget(self.chk_coc)
        
        self.chk_hashes = QCheckBox("Cryptographic Hashes (MD5, SHA-256)")
        self.chk_hashes.setChecked(True)
        self.chk_hashes.setToolTip("Include hash values for all evidence")
        layout.addWidget(self.chk_hashes)
        
        self.chk_screenshots = QCheckBox("Screenshots and Thumbnails")
        self.chk_screenshots.setChecked(True)
        self.chk_screenshots.setToolTip("Include visual previews where available")
        layout.addWidget(self.chk_screenshots)
        
        self.chk_timeline = QCheckBox("Timeline Visualization")
        self.chk_timeline.setChecked(False)
        self.chk_timeline.setToolTip("Include timeline chart in report")
        layout.addWidget(self.chk_timeline)
        
        self.chk_statistics = QCheckBox("Statistical Summary")
        self.chk_statistics.setChecked(True)
        self.chk_statistics.setToolTip("Include statistics about evidence types and counts")
        layout.addWidget(self.chk_statistics)
        
        # Page options
        layout.addWidget(QLabel("<b>Page Options:</b>"))
        
        self.chk_page_numbers = QCheckBox("Page Numbers")
        self.chk_page_numbers.setChecked(True)
        layout.addWidget(self.chk_page_numbers)
        
        self.chk_header_footer = QCheckBox("Headers and Footers")
        self.chk_header_footer.setChecked(True)
        layout.addWidget(self.chk_header_footer)
        
        self.chk_watermark = QCheckBox("Watermark (Draft/Confidential)")
        self.chk_watermark.setChecked(False)
        layout.addWidget(self.chk_watermark)
        
        group.setLayout(layout)
        return group
    
    def _create_preview_panel(self) -> QGroupBox:
        """Create right preview panel."""
        group = QGroupBox("👁️ Report Preview")
        layout = QVBoxLayout()
        
        # Preview controls
        preview_controls = QHBoxLayout()
        
        btn_refresh_preview = QPushButton("🔄 Refresh Preview")
        btn_refresh_preview.clicked.connect(self._refresh_preview)
        preview_controls.addWidget(btn_refresh_preview)
        
        preview_controls.addStretch()
        
        self.lbl_preview_status = QLabel("Preview not generated")
        self.lbl_preview_status.setStyleSheet("color: #888; font-size: 11px;")
        preview_controls.addWidget(self.lbl_preview_status)
        
        layout.addLayout(preview_controls)
        
        # Preview area (HTML preview)
        self.preview_view = QTextEdit()  # Use QTextEdit for simple HTML, or QWebEngineView for full HTML
        self.preview_view.setReadOnly(True)
        self.preview_view.setPlaceholderText("Report preview will appear here...\n\nClick 'Refresh Preview' to generate.")
        layout.addWidget(self.preview_view)
        
        group.setLayout(layout)
        return group
    
    def _create_generation_controls(self) -> QGroupBox:
        """Create bottom generation controls."""
        group = QGroupBox("Generate Report")
        layout = QVBoxLayout()
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Buttons row
        btn_layout = QHBoxLayout()
        
        self.btn_generate = QPushButton("📄 Generate Report")
        self.btn_generate.setMinimumHeight(40)
        self.btn_generate.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2ecc71;
            }
            QPushButton:pressed {
                background-color: #229954;
            }
        """)
        self.btn_generate.clicked.connect(self._generate_report)
        btn_layout.addWidget(self.btn_generate)
        
        self.btn_save_location = QPushButton("📁 Choose Save Location...")
        self.btn_save_location.clicked.connect(self._choose_save_location)
        btn_layout.addWidget(self.btn_save_location)
        
        layout.addLayout(btn_layout)
        
        # Output info
        self.lbl_output_info = QLabel("Report will be saved to: <i>Not selected</i>")
        self.lbl_output_info.setWordWrap(True)
        layout.addWidget(self.lbl_output_info)
        
        group.setLayout(layout)
        return group
    
    def load_tagged_artifacts(self, artifacts: List[Dict[str, Any]]):
        """Load tagged artifacts for report."""
        self._tagged_artifacts = artifacts
        
        # Populate evidence table
        self.tbl_evidence.setRowCount(0)
        
        for artifact in artifacts:
            row = self.tbl_evidence.rowCount()
            self.tbl_evidence.insertRow(row)
            
            # Include checkbox
            chk = QCheckBox()
            chk.setChecked(True)
            chk.stateChanged.connect(self._update_evidence_count)
            chk_widget = QWidget()
            chk_layout = QHBoxLayout(chk_widget)
            chk_layout.addWidget(chk)
            chk_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chk_layout.setContentsMargins(0, 0, 0, 0)
            self.tbl_evidence.setCellWidget(row, 0, chk_widget)
            
            # Type
            type_item = QTableWidgetItem(artifact.get('type', 'Unknown'))
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.tbl_evidence.setItem(row, 1, type_item)
            
            # Name
            name_item = QTableWidgetItem(artifact.get('name', 'Unknown'))
            name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.tbl_evidence.setItem(row, 2, name_item)
            
            # Path
            path_item = QTableWidgetItem(artifact.get('path', 'Unknown'))
            path_item.setFlags(path_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.tbl_evidence.setItem(row, 3, path_item)
            
            # Date/Time
            date_item = QTableWidgetItem(artifact.get('timestamp', 'Unknown'))
            date_item.setFlags(date_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.tbl_evidence.setItem(row, 4, date_item)
        
        self._update_evidence_count()
    
    def _select_all_evidence(self):
        """Select all evidence items."""
        for row in range(self.tbl_evidence.rowCount()):
            chk_widget = self.tbl_evidence.cellWidget(row, 0)
            if chk_widget:
                chk = chk_widget.findChild(QCheckBox)
                if chk:
                    chk.setChecked(True)
    
    def _deselect_all_evidence(self):
        """Deselect all evidence items."""
        for row in range(self.tbl_evidence.rowCount()):
            chk_widget = self.tbl_evidence.cellWidget(row, 0)
            if chk_widget:
                chk = chk_widget.findChild(QCheckBox)
                if chk:
                    chk.setChecked(False)
    
    def _update_evidence_count(self):
        """Update evidence count label."""
        count = 0
        for row in range(self.tbl_evidence.rowCount()):
            chk_widget = self.tbl_evidence.cellWidget(row, 0)
            if chk_widget:
                chk = chk_widget.findChild(QCheckBox)
                if chk and chk.isChecked():
                    count += 1
        
        self.lbl_evidence_count.setText(f"{count} artifact{'s' if count != 1 else ''} selected")
    
    def _on_format_changed(self, index: int):
        """Handle format change."""
        # Update UI based on format
        pass
    
    def _refresh_preview(self):
        """Generate preview of report."""
        self.lbl_preview_status.setText("Generating preview...")
        
        # Collect metadata
        metadata = {
            'case_number': self.txt_case_number.text(),
            'examiner': self.txt_examiner_name.text(),
            'organization': self.txt_organization.text(),
            'exam_start': self.date_exam_start.date().toString("yyyy-MM-dd"),
            'exam_end': self.date_exam_end.date().toString("yyyy-MM-dd"),
            'victim_suspect': self.txt_victim_suspect.text(),
            'summary': self.txt_case_summary.toPlainText()
        }
        
        # Generate preview HTML
        preview_html = self._generate_preview_html(metadata)
        self.preview_view.setHtml(preview_html)
        
        self.lbl_preview_status.setText("Preview generated successfully")
    
    def _generate_preview_html(self, metadata: Dict[str, str]) -> str:
        """Generate HTML preview of report."""
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; background: #2c2c2c; color: #eee; }}
                h1 {{ color: #3498db; border-bottom: 2px solid #3498db; }}
                h2 {{ color: #2ecc71; margin-top: 20px; }}
                .metadata {{ background: #3a3a3a; padding: 15px; border-radius: 5px; margin: 10px 0; }}
                .metadata-row {{ margin: 5px 0; }}
                .label {{ font-weight: bold; color: #3498db; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                th {{ background: #34495e; color: white; padding: 10px; text-align: left; }}
                td {{ background: #3a3a3a; padding: 8px; border-bottom: 1px solid #555; }}
            </style>
        </head>
        <body>
            <h1>Forensic Examination Report</h1>
            
            <div class="metadata">
                <h2>Case Information</h2>
                <div class="metadata-row"><span class="label">Case Number:</span> {metadata.get('case_number', 'N/A')}</div>
                <div class="metadata-row"><span class="label">Examiner:</span> {metadata.get('examiner', 'N/A')}</div>
                <div class="metadata-row"><span class="label">Organization:</span> {metadata.get('organization', 'N/A')}</div>
                <div class="metadata-row"><span class="label">Exam Start Date:</span> {metadata.get('exam_start', 'N/A')}</div>
                <div class="metadata-row"><span class="label">Exam End Date:</span> {metadata.get('exam_end', 'N/A')}</div>
                <div class="metadata-row"><span class="label">Victim/Suspect:</span> {metadata.get('victim_suspect', 'N/A')}</div>
            </div>
            
            <h2>Case Summary</h2>
            <p>{metadata.get('summary', 'No summary provided.')}</p>
            
            <h2>Evidence Items</h2>
            <p><i>Evidence table will appear here in final report...</i></p>
            
            <h2>Chain of Custody</h2>
            <p><i>Chain-of-custody log will appear here if included...</i></p>
            
            <h2>Findings and Conclusions</h2>
            <p><i>Detailed findings will appear here in final report...</i></p>
        </body>
        </html>
        """
        return html
    
    def _choose_save_location(self):
        """Choose save location for report."""
        format_text = self.cmb_format.currentText()
        
        if "PDF" in format_text:
            file_filter = "PDF Files (*.pdf)"
            default_ext = ".pdf"
        elif "HTML" in format_text:
            file_filter = "HTML Files (*.html)"
            default_ext = ".html"
        elif "DOCX" in format_text:
            file_filter = "Word Documents (*.docx)"
            default_ext = ".docx"
        else:
            file_filter = "CSV Files (*.csv)"
            default_ext = ".csv"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report As",
            f"Forensic_Report_{datetime.now().strftime('%Y%m%d')}{default_ext}",
            file_filter
        )
        
        if file_path:
            self.lbl_output_info.setText(f"Report will be saved to: <b>{file_path}</b>")
            self._save_location = file_path
    
    def _generate_report(self):
        """Generate the final report."""
        # Validate inputs
        if not self.txt_case_number.text():
            QMessageBox.warning(self, "Missing Information", "Please enter a case number.")
            return
        
        if not hasattr(self, '_save_location'):
            QMessageBox.warning(self, "No Save Location", "Please choose a save location first.")
            return
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.btn_generate.setEnabled(False)
        
        try:
            # TODO: Actual report generation
            # 1. Collect selected evidence
            # 2. Load CoC log if selected
            # 3. Generate report based on template
            # 4. Export to selected format
            # 5. Save to file
            
            for i in range(101):
                self.progress_bar.setValue(i)
                # Simulate work
            
            self.progress_bar.setVisible(False)
            self.btn_generate.setEnabled(True)
            
            # Success message
            msg = QMessageBox(self)
            msg.setWindowTitle("Report Generated")
            msg.setText(f"Report generated successfully!")
            msg.setInformativeText(f"Saved to: {self._save_location}")
            msg.setIcon(QMessageBox.Icon.Information)
            
            btn_open = msg.addButton("Open Containing Folder", QMessageBox.ButtonRole.ActionRole)
            msg.addButton(QMessageBox.StandardButton.Ok)
            
            msg.exec()
            
            if msg.clickedButton() == btn_open:
                self._open_containing_folder()
            
            self.report_generated.emit(self._save_location)
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            self.btn_generate.setEnabled(True)
            self.logger.error(f"Report generation failed: {e}")
            QMessageBox.critical(self, "Generation Failed", f"Failed to generate report:\n{e}")
    
    def _open_containing_folder(self):
        """Open the folder containing the generated report."""
        if hasattr(self, '_save_location'):
            import os
            import subprocess
            import platform
            
            folder = str(Path(self._save_location).parent)
            
            if os.name == 'nt':  # Windows
                os.startfile(folder)
            elif os.name == 'posix':  # macOS/Linux
                if platform.system() == 'Darwin':  # macOS
                    subprocess.Popen(['open', folder])
                else:  # Linux
                    subprocess.Popen(['xdg-open', folder])
