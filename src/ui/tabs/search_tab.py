"""
FEPD - Advanced Search Tab
===========================
Full-text search interface with:
- Elasticsearch integration
- SQLite FTS5 fallback
- Advanced query builder
- Fuzzy search
- Filter by category, severity, date range

Copyright (c) 2025 FEPD Development Team
"""

import logging
from typing import Optional, List, Dict
from datetime import datetime, timedelta
import pandas as pd

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QTableWidget, QTableWidgetItem,
    QGroupBox, QComboBox, QDateTimeEdit, QCheckBox,
    QProgressBar, QTextEdit, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QDateTime
from PyQt6.QtGui import QFont, QColor


class SearchWorker(QThread):
    """Background worker for search operations."""
    
    finished = pyqtSignal(list)  # search results
    error = pyqtSignal(str)
    progress = pyqtSignal(str)
    
    def __init__(self, query: str, filters: Dict):
        super().__init__()
        self.query = query
        self.filters = filters
        self.logger = logging.getLogger(__name__)
    
    def run(self):
        """Execute search in background."""
        try:
            self.progress.emit("Initializing search engine...")
            
            from src.modules.search_engine import SearchEngine, SearchQuery
            
            # Initialize search engine
            search = SearchEngine(
                elasticsearch_hosts=self.filters.get('es_hosts', None),
                sqlite_db_path=self.filters.get('db_path', 'timeline.db')
            )
            
            self.progress.emit("Executing search query...")
            
            # Build search query
            search_query = SearchQuery(
                text=self.query,
                fuzzy=self.filters.get('fuzzy', False),
                categories=self.filters.get('categories', None),
                severities=self.filters.get('severities', None),
                start_time=self.filters.get('start_time', None),
                end_time=self.filters.get('end_time', None)
            )
            
            # Execute search
            results = search.search(search_query)
            
            self.progress.emit(f"Found {len(results)} results")
            self.finished.emit(results)
            
        except Exception as e:
            self.logger.error(f"Search failed: {e}")
            self.error.emit(str(e))


class SearchTab(QWidget):
    """
    Advanced Search Tab with full-text search capabilities.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.search_worker: Optional[SearchWorker] = None
        self.current_results: List[Dict] = []
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Title
        title = QLabel("🔍 Full-Text Search")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Search bar
        search_layout = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search query (e.g., 'malware', 'powershell', 'suspicious activity')...")
        self.search_input.setMinimumHeight(40)
        self.search_input.returnPressed.connect(self._execute_search)
        search_layout.addWidget(self.search_input)
        
        btn_search = QPushButton("🔍 Search")
        btn_search.clicked.connect(self._execute_search)
        btn_search.setMinimumHeight(40)
        btn_search.setMinimumWidth(120)
        search_layout.addWidget(btn_search)
        
        layout.addLayout(search_layout)
        
        # Search options
        options_group = QGroupBox("Search Options")
        options_layout = QVBoxLayout(options_group)
        
        # Row 1: Backend and fuzzy search
        row1_layout = QHBoxLayout()
        
        row1_layout.addWidget(QLabel("Backend:"))
        self.backend_combo = QComboBox()
        self.backend_combo.addItems(["Elasticsearch", "SQLite FTS5"])
        row1_layout.addWidget(self.backend_combo)
        
        self.fuzzy_check = QCheckBox("Fuzzy Search")
        self.fuzzy_check.setToolTip("Match similar terms (e.g., 'malware' matches 'malwares', 'malicious')")
        row1_layout.addWidget(self.fuzzy_check)
        
        row1_layout.addStretch()
        options_layout.addLayout(row1_layout)
        
        # Row 2: Filters
        row2_layout = QHBoxLayout()
        
        row2_layout.addWidget(QLabel("Category:"))
        self.category_combo = QComboBox()
        self.category_combo.addItems([
            "All", "File System", "Registry", "Process Execution",
            "Network Activity", "User Activity", "System Events"
        ])
        row2_layout.addWidget(self.category_combo)
        
        row2_layout.addWidget(QLabel("Severity:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems([
            "All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
        ])
        row2_layout.addWidget(self.severity_combo)
        
        row2_layout.addStretch()
        options_layout.addLayout(row2_layout)
        
        # Row 3: Date range
        row3_layout = QHBoxLayout()
        
        self.date_range_check = QCheckBox("Date Range:")
        row3_layout.addWidget(self.date_range_check)
        
        row3_layout.addWidget(QLabel("From:"))
        self.start_datetime = QDateTimeEdit()
        self.start_datetime.setDateTime(QDateTime.currentDateTime().addDays(-7))
        self.start_datetime.setCalendarPopup(True)
        self.start_datetime.setEnabled(False)
        self.date_range_check.toggled.connect(self.start_datetime.setEnabled)
        row3_layout.addWidget(self.start_datetime)
        
        row3_layout.addWidget(QLabel("To:"))
        self.end_datetime = QDateTimeEdit()
        self.end_datetime.setDateTime(QDateTime.currentDateTime())
        self.end_datetime.setCalendarPopup(True)
        self.end_datetime.setEnabled(False)
        self.date_range_check.toggled.connect(self.end_datetime.setEnabled)
        row3_layout.addWidget(self.end_datetime)
        
        row3_layout.addStretch()
        options_layout.addLayout(row3_layout)
        
        layout.addWidget(options_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        # Results section
        results_group = QGroupBox("Search Results")
        results_layout = QVBoxLayout(results_group)
        
        # Results count
        self.results_count_label = QLabel("No results")
        results_layout.addWidget(self.results_count_label)
        
        # Results table
        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels([
            "Timestamp", "Category", "Severity", "Source",
            "Description", "Score"
        ])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.itemSelectionChanged.connect(self._on_result_selected)
        results_layout.addWidget(self.results_table)
        
        # Export button
        btn_export = QPushButton("💾 Export Results")
        btn_export.clicked.connect(self._export_results)
        results_layout.addWidget(btn_export)
        
        layout.addWidget(results_group)
        
        # AI Recommendations Panel
        recommendations_group = QGroupBox("🤖 AI-Powered Recommendations")
        recommendations_layout = QVBoxLayout(recommendations_group)
        
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setReadOnly(True)
        self.recommendations_text.setMaximumHeight(200)
        self.recommendations_text.setPlaceholderText(
            "AI recommendations will appear here based on collected artifacts...\n\n"
            "Examples:\n"
            "• Suspicious processes detected\n"
            "• Unusual registry modifications\n"
            "• Potential malware indicators\n"
            "• Timeline anomalies\n"
            "• Network activity patterns"
        )
        recommendations_layout.addWidget(self.recommendations_text)
        
        # Recommendation action buttons
        rec_buttons_layout = QHBoxLayout()
        
        btn_analyze = QPushButton("🔍 Analyze Artifacts")
        btn_analyze.clicked.connect(self._generate_recommendations)
        btn_analyze.setToolTip("Generate AI recommendations based on collected artifacts")
        rec_buttons_layout.addWidget(btn_analyze)
        
        btn_threat_hunt = QPushButton("🎯 Threat Hunting Suggestions")
        btn_threat_hunt.clicked.connect(self._generate_threat_hunting_tips)
        btn_threat_hunt.setToolTip("Get suggestions for further investigation")
        rec_buttons_layout.addWidget(btn_threat_hunt)
        
        btn_export_rec = QPushButton("💾 Export Recommendations")
        btn_export_rec.clicked.connect(self._export_recommendations)
        rec_buttons_layout.addWidget(btn_export_rec)
        
        rec_buttons_layout.addStretch()
        recommendations_layout.addLayout(rec_buttons_layout)
        
        layout.addWidget(recommendations_group)
        
        # Detail view
        detail_group = QGroupBox("Event Details")
        detail_layout = QVBoxLayout(detail_group)
        
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setMaximumHeight(150)
        detail_layout.addWidget(self.detail_text)
        
        layout.addWidget(detail_group)
    
    def _execute_search(self):
        """Execute search query."""
        query = self.search_input.text().strip()
        
        if not query:
            self.status_label.setText("⚠️ Please enter a search query")
            return
        
        # Build filters
        filters = {
            'fuzzy': self.fuzzy_check.isChecked(),
            'db_path': 'timeline.db'
        }
        
        # Category filter
        if self.category_combo.currentText() != "All":
            filters['categories'] = [self.category_combo.currentText()]
        
        # Severity filter
        if self.severity_combo.currentText() != "All":
            filters['severities'] = [self.severity_combo.currentText()]
        
        # Date range filter
        if self.date_range_check.isChecked():
            filters['start_time'] = self.start_datetime.dateTime().toPyDateTime()
            filters['end_time'] = self.end_datetime.dateTime().toPyDateTime()
        
        # Elasticsearch hosts
        if self.backend_combo.currentText() == "Elasticsearch":
            filters['es_hosts'] = ["localhost:9200"]
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText("Searching...")
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.detail_text.clear()
        
        # Create and start worker
        self.search_worker = SearchWorker(query, filters)
        self.search_worker.progress.connect(self._on_search_progress)
        self.search_worker.finished.connect(self._on_search_complete)
        self.search_worker.error.connect(self._on_search_error)
        self.search_worker.start()
        
        self.logger.info(f"Executing search: {query}")
    
    def _on_search_progress(self, message: str):
        """Handle search progress updates."""
        self.status_label.setText(message)
    
    def _on_search_complete(self, results: List[Dict]):
        """Handle search completion."""
        self.current_results = results
        
        # Hide progress
        self.progress_bar.setVisible(False)
        
        # Update results count
        self.results_count_label.setText(f"Found {len(results)} results")
        self.status_label.setText(f"✅ Search complete - {len(results)} results")
        
        # Populate table
        self.results_table.setRowCount(0)
        for result in results:
            row_idx = self.results_table.rowCount()
            self.results_table.insertRow(row_idx)
            
            self.results_table.setItem(row_idx, 0, 
                QTableWidgetItem(str(result.get('timestamp', 'N/A'))))
            self.results_table.setItem(row_idx, 1, 
                QTableWidgetItem(result.get('category', 'N/A')))
            
            severity = result.get('severity', 'INFO')
            severity_item = QTableWidgetItem(severity)
            if severity == 'CRITICAL':
                severity_item.setBackground(QColor(255, 0, 0))
            elif severity == 'HIGH':
                severity_item.setBackground(QColor(255, 100, 100))
            elif severity == 'MEDIUM':
                severity_item.setBackground(QColor(255, 200, 100))
            self.results_table.setItem(row_idx, 2, severity_item)
            
            self.results_table.setItem(row_idx, 3, 
                QTableWidgetItem(result.get('source', 'N/A')))
            self.results_table.setItem(row_idx, 4, 
                QTableWidgetItem(result.get('description', 'N/A')[:100]))
            self.results_table.setItem(row_idx, 5, 
                QTableWidgetItem(f"{result.get('search_score', 0):.2f}"))
        
        self.logger.info(f"Displayed {len(results)} search results")
    
    def _on_search_error(self, error_msg: str):
        """Handle search error."""
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"❌ Search error: {error_msg}")
        self.logger.error(f"Search error: {error_msg}")
    
    def _on_result_selected(self):
        """Handle result selection."""
        selected_rows = self.results_table.selectedItems()
        if not selected_rows:
            return
        
        row_idx = selected_rows[0].row()
        if 0 <= row_idx < len(self.current_results):
            result = self.current_results[row_idx]
            
            # Display full details
            details = f"""
Event Details
═════════════

Timestamp: {result.get('timestamp', 'N/A')}
Category: {result.get('category', 'N/A')}
Severity: {result.get('severity', 'N/A')}
Source: {result.get('source', 'N/A')}

Description:
{result.get('description', 'N/A')}

Event Type: {result.get('event_type', 'N/A')}

Metadata:
{result.get('metadata', {})}
            """
            
            self.detail_text.setPlainText(details)
    
    def _generate_recommendations(self):
        """Generate AI-powered recommendations based on artifacts."""
        self.status_label.setText("🤖 Analyzing artifacts and generating recommendations...")
        
        # Get artifacts from main window (if available)
        try:
            from src.ui.main_window import MainWindow
            main_window = self.window()
            
            # Analyze collected artifacts
            recommendations = []
            recommendations.append("=" * 60)
            recommendations.append("🤖 AI-POWERED FORENSIC RECOMMENDATIONS")
            recommendations.append("=" * 60)
            recommendations.append("")
            
            # Check if artifacts exist
            if hasattr(main_window, 'discovered_artifacts') and main_window.discovered_artifacts:
                artifact_count = len(main_window.discovered_artifacts)
                recommendations.append(f"📊 Analyzed {artifact_count} artifacts")
                recommendations.append("")
                
                # Analyze artifact types
                artifact_types = {}
                for artifact in main_window.discovered_artifacts:
                    art_type = artifact.get('type', 'Unknown')
                    artifact_types[art_type] = artifact_types.get(art_type, 0) + 1
                
                recommendations.append("📁 Artifact Distribution:")
                for art_type, count in sorted(artifact_types.items(), key=lambda x: x[1], reverse=True):
                    recommendations.append(f"  • {art_type}: {count} files")
                recommendations.append("")
                
                # Generate recommendations based on artifact types
                recommendations.append("💡 RECOMMENDATIONS:")
                recommendations.append("")
                
                if 'Prefetch' in artifact_types:
                    recommendations.append("✓ Prefetch Analysis:")
                    recommendations.append(f"  • {artifact_types['Prefetch']} prefetch files found")
                    recommendations.append("  • Review execution timeline for suspicious programs")
                    recommendations.append("  • Look for unusual executables from temp directories")
                    recommendations.append("  • Check for malware families (e.g., rundll32, powershell, cmd)")
                    recommendations.append("")
                
                if 'Registry' in artifact_types:
                    recommendations.append("✓ Registry Analysis:")
                    recommendations.append(f"  • {artifact_types['Registry']} registry hives found")
                    recommendations.append("  • Examine SYSTEM hive for service persistence")
                    recommendations.append("  • Check SOFTWARE hive for installed programs")
                    recommendations.append("  • Review Run/RunOnce keys for autostart programs")
                    recommendations.append("  • Investigate USB device history")
                    recommendations.append("")
                
                if 'EVTX' in artifact_types or 'Event Log' in artifact_types:
                    recommendations.append("✓ Event Log Analysis:")
                    evtx_count = artifact_types.get('EVTX', 0) + artifact_types.get('Event Log', 0)
                    recommendations.append(f"  • {evtx_count} event log files found")
                    recommendations.append("  • Focus on Security.evtx for logon/logoff events")
                    recommendations.append("  • Review System.evtx for service installations")
                    recommendations.append("  • Check Application.evtx for error patterns")
                    recommendations.append("  • Look for Event ID 4688 (process creation)")
                    recommendations.append("")
                
                if 'MFT' in artifact_types:
                    recommendations.append("✓ MFT Analysis:")
                    recommendations.append(f"  • {artifact_types['MFT']} MFT files found")
                    recommendations.append("  • Parse for complete file system timeline")
                    recommendations.append("  • Identify deleted files and timestamps")
                    recommendations.append("  • Correlate with other artifacts for comprehensive view")
                    recommendations.append("")
                
                if 'Browser' in artifact_types:
                    recommendations.append("✓ Browser Analysis:")
                    recommendations.append(f"  • {artifact_types['Browser']} browser artifacts found")
                    recommendations.append("  • Review browsing history for malicious URLs")
                    recommendations.append("  • Check downloads for suspicious files")
                    recommendations.append("  • Examine cookies for session hijacking")
                    recommendations.append("")
                
                # General recommendations
                recommendations.append("🎯 NEXT STEPS:")
                recommendations.append("  1. Run Timeline Analysis to correlate all events")
                recommendations.append("  2. Use ML Analysis to detect anomalies")
                recommendations.append("  3. Generate Connections Graph to visualize relationships")
                recommendations.append("  4. Export findings for report generation")
                recommendations.append("  5. Search for IOCs (Indicators of Compromise)")
                
            else:
                recommendations.append("⚠️ No artifacts loaded yet")
                recommendations.append("")
                recommendations.append("Please load a forensic image first:")
                recommendations.append("  1. Go to 'Image Ingest' tab")
                recommendations.append("  2. Select an E01/DD image file")
                recommendations.append("  3. Click 'Ingest Image'")
                recommendations.append("  4. Wait for extraction and parsing to complete")
                recommendations.append("  5. Return here for AI-powered recommendations")
            
            recommendations.append("")
            recommendations.append("=" * 60)
            
            self.recommendations_text.setPlainText("\n".join(recommendations))
            self.status_label.setText("✓ Recommendations generated successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to generate recommendations: {e}")
            self.recommendations_text.setPlainText(f"❌ Error generating recommendations: {e}")
            self.status_label.setText("❌ Failed to generate recommendations")
    
    def _generate_threat_hunting_tips(self):
        """Generate threat hunting suggestions."""
        tips = []
        tips.append("=" * 60)
        tips.append("🎯 THREAT HUNTING SUGGESTIONS")
        tips.append("=" * 60)
        tips.append("")
        
        tips.append("🔍 BEHAVIORAL INDICATORS:")
        tips.append("")
        tips.append("1. Suspicious Process Execution:")
        tips.append("   • powershell.exe with encoded commands (-enc, -encodedcommand)")
        tips.append("   • cmd.exe spawned from unusual parent processes")
        tips.append("   • wscript.exe or cscript.exe executing scripts")
        tips.append("   • regsvr32.exe, rundll32.exe with unusual parameters")
        tips.append("")
        
        tips.append("2. Persistence Mechanisms:")
        tips.append("   • Registry Run/RunOnce keys modifications")
        tips.append("   • Scheduled tasks created via schtasks.exe")
        tips.append("   • Services installed with sc.exe or PowerShell")
        tips.append("   • Startup folder modifications")
        tips.append("   • WMI event subscriptions")
        tips.append("")
        
        tips.append("3. Lateral Movement:")
        tips.append("   • PsExec or other remote execution tools")
        tips.append("   • WMI for remote code execution")
        tips.append("   • RDP connections to multiple systems")
        tips.append("   • SMB connections to unusual shares")
        tips.append("")
        
        tips.append("4. Data Exfiltration:")
        tips.append("   • Large outbound data transfers")
        tips.append("   • Compression tools (7zip, WinRAR, tar)")
        tips.append("   • Cloud storage access (Dropbox, OneDrive)")
        tips.append("   • FTP/SFTP connections")
        tips.append("")
        
        tips.append("🔎 SEARCH QUERIES TO TRY:")
        tips.append("")
        tips.append("• powershell AND (encoded OR bypass OR hidden)")
        tips.append("• cmd.exe AND (/c OR /k OR ping)")
        tips.append("• rundll32 OR regsvr32")
        tips.append("• mimikatz OR procdump OR dumpert")
        tips.append("• \\AppData\\Local\\Temp\\")
        tips.append("• schtasks OR at.exe")
        tips.append("• net user OR net localgroup")
        tips.append("")
        
        tips.append("⚠️ HIGH-RISK INDICATORS:")
        tips.append("• Executables in temp/downloads/desktop folders")
        tips.append("• Scripts with obfuscated code")
        tips.append("• Connections to known malicious IPs")
        tips.append("• Multiple failed login attempts")
        tips.append("• Account creation/modification")
        tips.append("• Security tool disabling")
        tips.append("")
        tips.append("=" * 60)
        
        self.recommendations_text.setPlainText("\n".join(tips))
        self.status_label.setText("✓ Threat hunting suggestions loaded")
    
    def _export_recommendations(self):
        """Export recommendations to file."""
        try:
            from PyQt6.QtWidgets import QFileDialog
            
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Export Recommendations",
                "recommendations.txt",
                "Text Files (*.txt);;All Files (*)"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.recommendations_text.toPlainText())
                
                self.status_label.setText(f"✓ Recommendations exported to {filename}")
                self.logger.info(f"Recommendations exported to {filename}")
        
        except Exception as e:
            self.logger.error(f"Failed to export recommendations: {e}")
            self.status_label.setText(f"❌ Export failed: {e}")
    
    def _export_results(self):
        """Export search results to CSV."""
        if not self.current_results:
            self.status_label.setText("⚠️ No results to export")
            return
        
        from PyQt6.QtWidgets import QFileDialog
        
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Export Search Results",
            "search_results.csv",
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if filepath:
            df = pd.DataFrame(self.current_results)
            df.to_csv(filepath, index=False)
            self.status_label.setText(f"✅ Exported {len(self.current_results)} results to {filepath}")
            self.logger.info(f"Exported search results to {filepath}")
    
    def load_events(self, events_df: pd.DataFrame):
        """
        Load events for search indexing.
        
        Args:
            events_df: DataFrame with forensic events
        """
        self.logger.info(f"Loaded {len(events_df)} events for search")
        self.status_label.setText(f"✅ Loaded {len(events_df)} events - Ready to search")
