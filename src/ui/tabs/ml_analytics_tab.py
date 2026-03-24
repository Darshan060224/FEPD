"""
FEPD - ML Analytics Tab
=======================
Machine Learning analytics interface including:
- Anomaly Detection
- UEBA Profiling
- Threat Intelligence
- ML Explainability

Copyright (c) 2025 FEPD Development Team
"""

import logging
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime
import pandas as pd

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QTextEdit,
    QGroupBox, QProgressBar, QComboBox, QSpinBox,
    QCheckBox, QLineEdit, QSplitter, QTabWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor


class MLAnalysisWorker(QThread):
    """Background worker for ML analysis."""
    
    progress = pyqtSignal(int, str)  # progress percentage, status message
    finished = pyqtSignal(dict)  # results
    error = pyqtSignal(str)  # error message
    
    def __init__(self, events_df: pd.DataFrame, analysis_type: str, config: Dict, case_path: Path = None):
        super().__init__()
        self.events_df = events_df
        self.analysis_type = analysis_type
        self.config = config
        self.case_path = case_path
        self.logger = logging.getLogger(__name__)
    
    def run(self):
        """Run ML analysis in background."""
        try:
            if self.analysis_type == "anomaly":
                self._run_anomaly_detection()
            elif self.analysis_type == "ueba":
                self._run_ueba_profiling()
            elif self.analysis_type == "threat_intel":
                self._run_threat_intelligence()
        except Exception as e:
            self.logger.error(f"ML analysis failed: {e}")
            self.error.emit(str(e))
    
    def _run_anomaly_detection(self):
        """Run anomaly detection analysis."""
        self.progress.emit(10, "Loading anomaly detection engine...")
        
        from src.ml.ml_anomaly_detector import MLAnomalyDetectionEngine
        
        engine = MLAnomalyDetectionEngine()
        
        self.progress.emit(30, "Training models on baseline data...")
        
        # Split into training/test
        train_size = int(len(self.events_df) * 0.7)
        train_df = self.events_df.iloc[:train_size]
        test_df = self.events_df.iloc[train_size:]
        
        engine.train(train_df, save=False, epochs=200)
        
        self.progress.emit(60, "Detecting anomalies...")
        
        results = engine.detect_anomalies(test_df)
        
        self.progress.emit(90, "Generating report...")
        
        report = engine.get_anomaly_report(results, total_events=len(test_df))
        
        self.progress.emit(100, "Complete!")
        
        self.finished.emit({
            'results': results,
            'report': report,
            'type': 'anomaly'
        })
    
    def _run_ueba_profiling(self):
        """Run UEBA user profiling analysis."""
        self.progress.emit(10, "Loading UEBA profiler...")
        
        from src.ml.ueba_profiler import UEBAProfiler
        from src.modules.ml_output_handler import MLEntity
        
        profiler = UEBAProfiler(case_path=self.case_path)
        
        self.progress.emit(30, "Building user behavior profiles...")
        
        # Split into training/test
        train_size = int(len(self.events_df) * 0.7)
        train_df = self.events_df.iloc[:train_size]
        test_df = self.events_df.iloc[train_size:]
        
        profiler.build_profiles(train_df)
        
        self.progress.emit(60, "Detecting behavioral anomalies...")
        
        results = profiler.detect_anomalies(test_df)
        
        self.progress.emit(75, "Detecting insider threats...")
        
        threats = profiler.detect_insider_threats(test_df)
        
        self.progress.emit(85, "Detecting account takeover...")
        
        takeovers = profiler.detect_account_takeover(test_df)
        
        self.progress.emit(95, "Identifying high-risk users...")
        
        high_risk = profiler.get_high_risk_users(top_n=10)
        
        # Save findings to ml_findings.json
        if self.case_path:
            self.progress.emit(97, "Saving findings to ml_findings.json...")
            
            # Extract entity info from events if available
            entity = MLEntity(
                user_id=test_df['user_id'].iloc[0] if 'user_id' in test_df.columns and len(test_df) > 0 else "Unknown",
                device_id=test_df['device_id'].iloc[0] if 'device_id' in test_df.columns and len(test_df) > 0 else "Unknown",
                platform=test_df['platform'].iloc[0] if 'platform' in test_df.columns and len(test_df) > 0 else "Unknown"
            )
            
            profiler.save_findings(test_df, entity=entity)
        
        self.progress.emit(100, "Complete!")
        
        self.finished.emit({
            'results': results,
            'insider_threats': threats,
            'takeovers': takeovers,
            'high_risk_users': high_risk,
            'type': 'ueba'
        })
    
    def _run_threat_intelligence(self):
        """Run threat intelligence enrichment."""
        self.progress.emit(10, "Loading threat intelligence engine...")
        
        from src.ml.threat_intel import ThreatIntelligenceEngine
        
        # Get API keys from config
        engine = ThreatIntelligenceEngine(
            misp_url=self.config.get('misp_url'),
            misp_key=self.config.get('misp_key'),
            otx_api_key=self.config.get('otx_key'),
            vt_api_key=self.config.get('vt_key')
        )
        
        self.progress.emit(30, "Enriching events with threat intelligence...")
        
        enriched = engine.enrich_events(self.events_df.to_dict('records'))
        
        self.progress.emit(90, "Analyzing matches...")
        
        # Count matches
        threat_matches = []
        for event in enriched:
            if event.get('threat_matches'):
                threat_matches.append(event)
        
        self.progress.emit(100, "Complete!")
        
        self.finished.emit({
            'enriched_events': pd.DataFrame(enriched),
            'threat_matches': threat_matches,
            'total_matches': len(threat_matches),
            'type': 'threat_intel'
        })


class HybridAnalysisWorker(QThread):
    """Background worker for hybrid (network + artifact + rule) analysis."""
    
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, events_df: pd.DataFrame):
        super().__init__()
        self.events_df = events_df
    
    def run(self):
        try:
            from src.ml.engine.hybrid_engine import HybridAnomalyEngine
            
            engine = HybridAnomalyEngine()
            engine.load_network_model()
            
            events = self.events_df.to_dict("records")
            
            results = engine.analyse(
                events,
                progress_callback=lambda p, s: self.progress.emit(p, s),
            )
            
            model_info = {}
            if engine._network_model and engine._network_model.is_loaded:
                model_info = engine._network_model.get_model_info()
            
            self.finished.emit({
                "results": [r.to_dict() for r in results],
                "model_info": model_info,
            })
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.error.emit(str(e))


class MLAnalyticsTab(QWidget):
    """
    ML Analytics Tab with three sub-tabs:
    1. Anomaly Detection
    2. UEBA Profiling
    3. Threat Intelligence
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.events_df: Optional[pd.DataFrame] = None
        self.current_results: Optional[Dict] = None
        self.worker: Optional[MLAnalysisWorker] = None
        self.case_path: Optional[Path] = None
        self.data_source_path: Optional[Path] = None
        self.models_dir: Optional[Path] = None
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Title
        title = QLabel("🤖 Machine Learning Analytics")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Sub-tabs for different ML features
        self.sub_tabs = QTabWidget()
        self.sub_tabs.addTab(self._create_overview_tab(), "📊 Top Findings")
        self.sub_tabs.addTab(self._create_anomaly_tab(), "🔍 Anomaly Detection")
        self.sub_tabs.addTab(self._create_ueba_tab(), "👤 UEBA Profiling")
        self.sub_tabs.addTab(self._create_network_intrusion_tab(), "🌐 Network Intrusion")
        self.sub_tabs.addTab(self._create_threat_intel_tab(), "🛡️ Threat Intelligence")
        
        layout.addWidget(self.sub_tabs)

    def _create_overview_tab(self) -> QWidget:
        """Create Top Findings overview dashboard."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        layout.addWidget(QLabel("<h3>📊 ML Investigation Overview</h3>"))
        layout.addWidget(QLabel(
            "Run any analysis below to populate this dashboard with top findings.\n"
            "Results are cached and displayed here for quick investigator reference."
        ))

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Top Suspicious Processes
        proc_group = QGroupBox("⚡ Top Suspicious Processes")
        proc_lay = QVBoxLayout(proc_group)
        self.overview_proc_table = QTableWidget(0, 3)
        self.overview_proc_table.setHorizontalHeaderLabels(["Process", "Risk Score", "Reason"])
        self.overview_proc_table.horizontalHeader().setStretchLastSection(True)
        proc_lay.addWidget(self.overview_proc_table)
        splitter.addWidget(proc_group)

        # Middle: Top Suspicious Files
        file_group = QGroupBox("📄 Top Suspicious Files")
        file_lay = QVBoxLayout(file_group)
        self.overview_file_table = QTableWidget(0, 3)
        self.overview_file_table.setHorizontalHeaderLabels(["File", "Risk Score", "Reason"])
        self.overview_file_table.horizontalHeader().setStretchLastSection(True)
        file_lay.addWidget(self.overview_file_table)
        splitter.addWidget(file_group)

        # Right: High Risk Users
        user_group = QGroupBox("👤 High Risk Users")
        user_lay = QVBoxLayout(user_group)
        self.overview_user_table = QTableWidget(0, 3)
        self.overview_user_table.setHorizontalHeaderLabels(["User", "Risk Score", "Alerts"])
        self.overview_user_table.horizontalHeader().setStretchLastSection(True)
        user_lay.addWidget(self.overview_user_table)
        splitter.addWidget(user_group)

        layout.addWidget(splitter)

        # Anomaly Score summary
        score_group = QGroupBox("📈 Anomaly Score Distribution")
        score_lay = QVBoxLayout(score_group)
        self.overview_summary = QTextEdit()
        self.overview_summary.setReadOnly(True)
        self.overview_summary.setMaximumHeight(200)
        self.overview_summary.setPlaceholderText("Run an analysis to see overall anomaly score distribution...")
        score_lay.addWidget(self.overview_summary)
        layout.addWidget(score_group)

        return widget
    
    def _create_anomaly_tab(self) -> QWidget:
        """Create Anomaly Detection sub-tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info section
        info_group = QGroupBox("Anomaly Detection Engine")
        info_layout = QVBoxLayout(info_group)
        
        info_label = QLabel(
            "This engine identifies unusual forensic events by learning normal activity patterns.\n\n"
            "It flags:\n"
            "• Rare file executions and process launches\n"
            "• Unusual registry modifications\n"
            "• Off-hours user actions\n"
            "• Abnormal process frequency\n"
            "• Timeline irregularities and clock manipulation\n\n"
            "Events are automatically loaded from the current case."
        )
        info_layout.addWidget(info_label)
        layout.addWidget(info_group)
        
        # Controls
        controls_group = QGroupBox("Analysis Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        btn_run = QPushButton("▶️ Run Anomaly Detection")
        btn_run.clicked.connect(lambda: self._run_analysis("anomaly"))
        btn_run.setMinimumHeight(40)
        controls_layout.addWidget(btn_run)
        
        btn_export = QPushButton("💾 Export Results")
        btn_export.clicked.connect(self._export_results)
        controls_layout.addWidget(btn_export)
        
        layout.addWidget(controls_group)
        
        # Progress bar
        self.anomaly_progress = QProgressBar()
        self.anomaly_progress.setVisible(False)
        layout.addWidget(self.anomaly_progress)
        
        self.anomaly_status = QLabel("")
        layout.addWidget(self.anomaly_status)
        
        # Results table
        self.anomaly_table = QTableWidget(0, 7)
        self.anomaly_table.setHorizontalHeaderLabels([
            "Timestamp", "Event Type", "Source", "Severity",
            "Anomaly Score", "Cluster", "Flags"
        ])
        self.anomaly_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.anomaly_table)
        
        # Summary
        self.anomaly_summary = QTextEdit()
        self.anomaly_summary.setReadOnly(True)
        self.anomaly_summary.setMaximumHeight(150)
        layout.addWidget(self.anomaly_summary)
        
        return widget
    
    def _create_ueba_tab(self) -> QWidget:
        """Create UEBA Profiling sub-tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info section
        info_group = QGroupBox("Behavior Analysis")
        info_layout = QVBoxLayout(info_group)
        
        info_label = QLabel(
            "Analyzes user and entity behavior to detect suspicious patterns:\n\n"
            "• Data exfiltration indicators (large file transfers, USB activity)\n"
            "• Privilege abuse (accessing sensitive files, admin operations)\n"
            "• Account takeover (unusual login times, new locations)\n"
            "• Lateral movement (accessing new systems or shares)\n"
            "• Off-hours activity deviations"
        )
        info_layout.addWidget(info_label)
        layout.addWidget(info_group)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        btn_run = QPushButton("▶️ Run UEBA Analysis")
        btn_run.clicked.connect(lambda: self._run_analysis("ueba"))
        btn_run.setMinimumHeight(40)
        controls_layout.addWidget(btn_run)
        
        btn_view_profiles = QPushButton("👥 View User Profiles")
        btn_view_profiles.clicked.connect(self._view_user_profiles)
        controls_layout.addWidget(btn_view_profiles)
        
        layout.addLayout(controls_layout)
        
        # Progress bar
        self.ueba_progress = QProgressBar()
        self.ueba_progress.setVisible(False)
        layout.addWidget(self.ueba_progress)
        
        self.ueba_status = QLabel("")
        layout.addWidget(self.ueba_status)
        
        # Splitter for results
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # High-risk users list
        risk_group = QGroupBox("High-Risk Users")
        risk_layout = QVBoxLayout(risk_group)
        
        self.risk_table = QTableWidget(0, 3)
        self.risk_table.setHorizontalHeaderLabels(["User ID", "Risk Score", "Alerts"])
        risk_layout.addWidget(self.risk_table)
        
        splitter.addWidget(risk_group)
        
        # Threats/Alerts
        alerts_group = QGroupBox("Detected Threats")
        alerts_layout = QVBoxLayout(alerts_group)
        
        self.alerts_table = QTableWidget(0, 4)
        self.alerts_table.setHorizontalHeaderLabels([
            "Type", "User", "Description", "Severity"
        ])
        alerts_layout.addWidget(self.alerts_table)
        
        splitter.addWidget(alerts_group)
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_network_intrusion_tab(self) -> QWidget:
        """Create Network Intrusion Detection sub-tab (UNSW-NB15 + Hybrid engine)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Model info card
        info_group = QGroupBox("Network Intrusion Detection (UNSW-NB15)")
        info_layout = QVBoxLayout(info_group)
        
        self.ni_model_info = QLabel(
            "Trained on UNSW-NB15 dataset — detects network-based attacks.\n\n"
            "Hybrid pipeline:\n"
            "  • Supervised model (RandomForest / XGBoost / Ensemble)\n"
            "  • Case-adaptive IsolationForest (behavioural baseline)\n"
            "  • Rule-based forensic detector (known attack techniques)\n\n"
            "Fused score → severity classification → results table."
        )
        info_layout.addWidget(self.ni_model_info)
        layout.addWidget(info_group)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        btn_run_hybrid = QPushButton("▶️ Run Hybrid Detection")
        btn_run_hybrid.clicked.connect(self._run_hybrid_analysis)
        btn_run_hybrid.setMinimumHeight(40)
        controls_layout.addWidget(btn_run_hybrid)
        
        btn_model_info = QPushButton("ℹ️ Model Info")
        btn_model_info.clicked.connect(self._show_model_info)
        controls_layout.addWidget(btn_model_info)
        
        layout.addLayout(controls_layout)
        
        # Progress
        self.ni_progress = QProgressBar()
        self.ni_progress.setVisible(False)
        layout.addWidget(self.ni_progress)
        
        self.ni_status = QLabel("")
        layout.addWidget(self.ni_status)
        
        # Results table
        self.ni_table = QTableWidget(0, 8)
        self.ni_table.setHorizontalHeaderLabels([
            "Timestamp", "Event", "Source", "Severity",
            "Score", "Network", "Artifact", "Flags"
        ])
        self.ni_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.ni_table)
        
        # Summary text
        self.ni_summary = QTextEdit()
        self.ni_summary.setReadOnly(True)
        self.ni_summary.setMaximumHeight(140)
        layout.addWidget(self.ni_summary)
        
        return widget
    
    def _run_hybrid_analysis(self):
        """Run the hybrid anomaly detection pipeline."""
        if self.events_df is None or self.events_df.empty:
            self.ni_status.setText("⚠️ No events loaded. Please ingest data first.")
            return
        
        self.ni_progress.setVisible(True)
        self.ni_progress.setValue(0)
        self.ni_status.setText("Starting hybrid analysis…")
        
        # Run in a background thread
        self.worker = HybridAnalysisWorker(self.events_df)
        self.worker.progress.connect(lambda p, s: self._update_hybrid_progress(p, s))
        self.worker.finished.connect(self._on_hybrid_complete)
        self.worker.error.connect(lambda e: self._on_hybrid_error(e))
        self.worker.start()
    
    def _update_hybrid_progress(self, pct: int, msg: str):
        self.ni_progress.setValue(pct)
        self.ni_status.setText(msg)
    
    def _on_hybrid_complete(self, results: dict):
        self.ni_progress.setVisible(False)
        hybrid_results = results.get("results", [])
        model_info = results.get("model_info", {})
        
        # Populate table
        self.ni_table.setRowCount(0)
        total = len(hybrid_results)
        anomalies = 0
        
        for r in hybrid_results:
            if isinstance(r, dict):
                row = r
            else:
                row = r.to_dict()
            
            severity = row.get("severity", "LOW")
            if severity in ("HIGH", "CRITICAL"):
                anomalies += 1
            
            row_idx = self.ni_table.rowCount()
            self.ni_table.insertRow(row_idx)
            
            self.ni_table.setItem(row_idx, 0, QTableWidgetItem(str(row.get("timestamp", ""))))
            self.ni_table.setItem(row_idx, 1, QTableWidgetItem(str(row.get("event", ""))))
            self.ni_table.setItem(row_idx, 2, QTableWidgetItem(str(row.get("source", ""))))
            
            sev_item = QTableWidgetItem(severity)
            if severity == "CRITICAL":
                sev_item.setBackground(QColor(255, 50, 50))
            elif severity == "HIGH":
                sev_item.setBackground(QColor(255, 130, 80))
            elif severity == "MEDIUM":
                sev_item.setBackground(QColor(255, 220, 100))
            self.ni_table.setItem(row_idx, 3, sev_item)
            
            score = row.get("score", 0)
            score_item = QTableWidgetItem(f"{score:.3f}")
            if score > 0.8:
                score_item.setBackground(QColor(255, 100, 100))
            elif score > 0.6:
                score_item.setBackground(QColor(255, 200, 100))
            self.ni_table.setItem(row_idx, 4, score_item)
            
            self.ni_table.setItem(row_idx, 5, QTableWidgetItem(f"{row.get('network_score', 0):.2f}"))
            self.ni_table.setItem(row_idx, 6, QTableWidgetItem(f"{row.get('artifact_score', 0):.2f}"))
            self.ni_table.setItem(row_idx, 7, QTableWidgetItem(str(row.get("flags", ""))))
        
        # Summary
        metrics = model_info.get("metrics", {})
        summary_lines = [
            "📊 Hybrid Detection Summary",
            "",
            f"Total Events Analyzed: {total}",
            f"Anomalies Detected: {anomalies}",
            f"Anomaly Rate: {anomalies/total:.2%}" if total else "Anomaly Rate: N/A",
            "",
        ]
        if metrics:
            summary_lines.append("Model Metrics (UNSW-NB15):")
            summary_lines.append(f"  Accuracy:  {metrics.get('accuracy', 0):.4f}")
            summary_lines.append(f"  AUC:       {metrics.get('auc', 0):.4f}")
            summary_lines.append(f"  F1 Score:  {metrics.get('f1', 0):.4f}")
        
        self.ni_summary.setText("\n".join(summary_lines))
        self.ni_status.setText(f"✅ Found {anomalies} anomalies in {total} events")
    
    def _on_hybrid_error(self, err: str):
        self.ni_progress.setVisible(False)
        self.ni_status.setText(f"❌ Error: {err}")
    
    def _show_model_info(self):
        """Show trained model metadata in a dialog."""
        from PyQt6.QtWidgets import QMessageBox
        try:
            from src.ml.models.network_intrusion_model import NetworkIntrusionModel
            model = NetworkIntrusionModel()
            if not model.load():
                QMessageBox.warning(self, "Model Not Found",
                    "No trained model found.\n\nRun:\n  python scripts/ml/train_unsw_nb15.py")
                return
            info = model.get_model_info()
            metrics = info.get("metrics", {})
            top_feats = info.get("top_features", {})
            
            text = (
                f"Model: {info.get('name', '?')}\n"
                f"Version: {info.get('version', '?')}\n"
                f"Dataset: {info.get('dataset', '?')}\n"
                f"Trained: {info.get('trained_date', '?')}\n"
                f"Features: {info.get('n_features', 0)}\n\n"
                f"Metrics:\n"
                f"  Accuracy:  {metrics.get('accuracy', 0):.4f}\n"
                f"  AUC:       {metrics.get('auc', 0):.4f}\n"
                f"  Precision: {metrics.get('precision', 0):.4f}\n"
                f"  Recall:    {metrics.get('recall', 0):.4f}\n"
                f"  F1:        {metrics.get('f1', 0):.4f}\n\n"
                f"Top Features:\n"
            )
            for feat, imp in list(top_feats.items())[:10]:
                text += f"  {feat}: {imp:.4f}\n"
            
            QMessageBox.information(self, "Network Intrusion Model", text)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def _create_threat_intel_tab(self) -> QWidget:
        """Create Threat Intelligence sub-tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info section
        info_group = QGroupBox("Threat Enrichment")
        info_layout = QVBoxLayout(info_group)
        
        info_label = QLabel(
            "Enriches evidence with known threat indicators:\n\n"
            "• Hash lookups against malware databases\n"
            "• Domain/IP reputation checking\n"
            "• YARA pattern scanning for malware signatures\n"
            "• Sigma rule matching for attack detection\n"
            "• IOC (Indicator of Compromise) correlation"
        )
        info_layout.addWidget(info_label)
        layout.addWidget(info_group)
        
        # API Configuration
        config_group = QGroupBox("API Configuration")
        config_layout = QVBoxLayout(config_group)
        
        api_layout = QHBoxLayout()
        api_layout.addWidget(QLabel("VirusTotal API Key:"))
        self.vt_key_input = QLineEdit()
        self.vt_key_input.setPlaceholderText("Enter your VirusTotal API key")
        api_layout.addWidget(self.vt_key_input)
        config_layout.addLayout(api_layout)
        
        otx_layout = QHBoxLayout()
        otx_layout.addWidget(QLabel("OTX API Key:"))
        self.otx_key_input = QLineEdit()
        self.otx_key_input.setPlaceholderText("Enter your AlienVault OTX API key")
        otx_layout.addWidget(self.otx_key_input)
        config_layout.addLayout(otx_layout)
        
        layout.addWidget(config_group)
        
        # Controls
        btn_run = QPushButton("▶️ Run Threat Intelligence Scan")
        btn_run.clicked.connect(lambda: self._run_analysis("threat_intel"))
        btn_run.setMinimumHeight(40)
        layout.addWidget(btn_run)
        
        # Progress bar
        self.ti_progress = QProgressBar()
        self.ti_progress.setVisible(False)
        layout.addWidget(self.ti_progress)
        
        self.ti_status = QLabel("")
        layout.addWidget(self.ti_status)
        
        # Threat matches table
        self.ti_table = QTableWidget(0, 6)
        self.ti_table.setHorizontalHeaderLabels([
            "Indicator", "Type", "Threat Name", "Severity", "Source", "Description"
        ])
        self.ti_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.ti_table)
        
        # Summary
        self.ti_summary = QTextEdit()
        self.ti_summary.setReadOnly(True)
        self.ti_summary.setMaximumHeight(100)
        layout.addWidget(self.ti_summary)
        
        return widget
    
    def _run_analysis(self, analysis_type: str):
        """Run ML analysis in background thread."""
        if self.events_df is None or self.events_df.empty:
            self.logger.warning("No events loaded")
            self._show_status(analysis_type, "⚠️ No events loaded. Please ingest data first.")
            return
        
        # Get configuration
        config = {
            'vt_key': self.vt_key_input.text() if hasattr(self, 'vt_key_input') else None,
            'otx_key': self.otx_key_input.text() if hasattr(self, 'otx_key_input') else None,
        }
        
        # Show progress
        self._show_progress(analysis_type, True)
        self._show_status(analysis_type, "Starting analysis...")
        
        # Create and start worker
        self.worker = MLAnalysisWorker(self.events_df, analysis_type, config, case_path=self.case_path)
        self.worker.progress.connect(lambda p, s: self._update_progress(analysis_type, p, s))
        self.worker.finished.connect(self._on_analysis_complete)
        self.worker.error.connect(self._on_analysis_error)
        self.worker.start()
    
    def _update_progress(self, analysis_type: str, progress: int, status: str):
        """Update progress bar and status."""
        if analysis_type == "anomaly":
            self.anomaly_progress.setValue(progress)
            self.anomaly_status.setText(status)
        elif analysis_type == "ueba":
            self.ueba_progress.setValue(progress)
            self.ueba_status.setText(status)
        elif analysis_type == "threat_intel":
            self.ti_progress.setValue(progress)
            self.ti_status.setText(status)
    
    def _show_progress(self, analysis_type: str, visible: bool):
        """Show/hide progress bar."""
        if analysis_type == "anomaly":
            self.anomaly_progress.setVisible(visible)
            if not visible:
                self.anomaly_progress.setValue(0)
        elif analysis_type == "ueba":
            self.ueba_progress.setVisible(visible)
            if not visible:
                self.ueba_progress.setValue(0)
        elif analysis_type == "threat_intel":
            self.ti_progress.setVisible(visible)
            if not visible:
                self.ti_progress.setValue(0)
    
    def _show_status(self, analysis_type: str, message: str):
        """Show status message."""
        if analysis_type == "anomaly":
            self.anomaly_status.setText(message)
        elif analysis_type == "ueba":
            self.ueba_status.setText(message)
        elif analysis_type == "threat_intel":
            self.ti_status.setText(message)
    
    def _on_analysis_complete(self, results: Dict):
        """Handle analysis completion."""
        self.current_results = results
        analysis_type = results.get('type')
        
        # Hide progress
        self._show_progress(analysis_type, False)
        
        if analysis_type == "anomaly":
            self._display_anomaly_results(results)
        elif analysis_type == "ueba":
            self._display_ueba_results(results)
        elif analysis_type == "threat_intel":
            self._display_threat_intel_results(results)
        
        self.logger.info(f"{analysis_type} analysis complete")
    
    def _on_analysis_error(self, error_msg: str):
        """Handle analysis error."""
        self.logger.error(f"Analysis error: {error_msg}")
        # Show error in all status labels
        self._show_status("anomaly", f"❌ Error: {error_msg}")
        self._show_status("ueba", f"❌ Error: {error_msg}")
        self._show_status("threat_intel", f"❌ Error: {error_msg}")
        
        # Hide all progress bars
        self._show_progress("anomaly", False)
        self._show_progress("ueba", False)
        self._show_progress("threat_intel", False)
    
    def _display_anomaly_results(self, results: Dict):
        """Display anomaly detection results."""
        raw_results = results.get('results', [])
        report = results.get('report', {}) or {}

        # Normalize results into a DataFrame regardless of source shape
        if isinstance(raw_results, list):
            if not raw_results:
                results_df = pd.DataFrame()
            else:
                # ForensicFinding objects expose to_dict(); fall back to raw mapping
                normalized_rows = []
                for item in raw_results:
                    if hasattr(item, "to_dict"):
                        row = item.to_dict()
                    elif isinstance(item, dict):
                        row = dict(item)
                    else:
                        continue
                    row.setdefault('is_anomaly', True)
                    row.setdefault('event_type', row.get('artifact_type', 'unknown'))
                    row.setdefault('source', row.get('metadata', {}).get('entity_id', 'unknown'))
                    row.setdefault('cluster_label', row.get('metadata', {}).get('anomaly_types', ['unknown']))
                    row.setdefault('severity', row.get('severity', row.get('metadata', {}).get('severity', 'low')))
                    row.setdefault('anomaly_score', row.get('score', 0.0))
                    normalized_rows.append(row)
                results_df = pd.DataFrame(normalized_rows)
        elif isinstance(raw_results, pd.DataFrame):
            results_df = raw_results.copy()
        else:
            results_df = pd.DataFrame()

        if 'is_anomaly' not in results_df.columns:
            results_df['is_anomaly'] = False
        if 'anomaly_score' not in results_df.columns and 'score' in results_df.columns:
            results_df['anomaly_score'] = results_df['score']
        
        # Populate table with anomalies only
        anomalies = results_df[results_df.get('is_anomaly', False)]
        
        self.anomaly_table.setRowCount(0)
        for idx, row in anomalies.iterrows():
            row_idx = self.anomaly_table.rowCount()
            self.anomaly_table.insertRow(row_idx)
            
            self.anomaly_table.setItem(row_idx, 0, QTableWidgetItem(str(row.get('timestamp', 'N/A'))))
            self.anomaly_table.setItem(row_idx, 1, QTableWidgetItem(str(row.get('event_type', 'N/A'))))
            self.anomaly_table.setItem(row_idx, 2, QTableWidgetItem(str(row.get('source', 'N/A'))))
            self.anomaly_table.setItem(row_idx, 3, QTableWidgetItem(str(row.get('severity', 'N/A'))))
            
            score = row.get('anomaly_score', 0)
            score_item = QTableWidgetItem(f"{score:.3f}")
            if score > 0.8:
                score_item.setBackground(QColor(255, 100, 100))  # Red
            elif score > 0.6:
                score_item.setBackground(QColor(255, 200, 100))  # Orange
            self.anomaly_table.setItem(row_idx, 4, score_item)
            
            self.anomaly_table.setItem(row_idx, 5, QTableWidgetItem(str(row.get('cluster_label', 'N/A'))))
            
            # Generate forensic flags based on detection conditions
            flags = []
            score = row.get('anomaly_score', 0)
            
            # Score-based flags
            if score > 0.85:
                flags.append('RARE_BEHAVIOR')
            elif score > 0.6:
                flags.append('UNUSUAL_PATTERN')
            
            # Detection method flags  
            if row.get('ae_anomaly'):
                flags.append('BEHAVIOR_DEVIATION')
            if row.get('clock_skew'):
                flags.append('TIME_ANOMALY')
            if row.get('if_anomaly'):
                flags.append('OUTLIER_GROUP')
            
            # Cluster-based flags
            cluster_size = row.get('cluster_size')
            if cluster_size is not None and cluster_size < 3:
                flags.append('ISOLATED_EVENT')
            
            # User-based flags
            if row.get('user_changed') or row.get('account_switch'):
                flags.append('ACCOUNT_SHIFT')
            
            # Display unique flags
            unique_flags = list(dict.fromkeys(flags))  # Preserve order, remove duplicates
            self.anomaly_table.setItem(row_idx, 6, QTableWidgetItem(', '.join(unique_flags) if unique_flags else '-'))
        
        # Display summary with safe defaults
        total_events = report.get('total_events')
        if total_events is None and self.events_df is not None:
            total_events = len(self.events_df)
        anomalies_detected = report.get('anomalies_detected', len(anomalies))
        anomaly_rate = report.get('anomaly_rate')
        if anomaly_rate is None:
            anomaly_rate = (anomalies_detected / total_events) if total_events else 0.0
        clock_skew_flags = report.get('clock_skew_analysis', {}).get('potential_attacks', 0)

        high_risk_count = 0
        if not anomalies.empty and 'severity' in anomalies.columns:
            high_risk_count = int(
                anomalies['severity']
                .astype(str)
                .str.lower()
                .isin(['high', 'critical'])
                .sum()
            )

        summary = f"""
    📊 Anomaly Detection Summary

    Total Events Analyzed: {total_events}
    Anomalies Detected: {anomalies_detected}
    Anomaly Rate: {anomaly_rate:.2%}

    Clock Skew Analysis: {clock_skew_flags} potential attacks

    Top Anomalous Events shown in table above.
        """.strip()
        
        self.anomaly_summary.setText(summary)
        self._show_status("anomaly", f"✅ Found {anomalies_detected} anomalies")

        # Persist runtime anomaly counters for Case Details summary synchronization.
        if self.case_path:
            try:
                import json
                out_dir = self.case_path / "results"
                out_dir.mkdir(parents=True, exist_ok=True)
                payload = {
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                    "anomalies_detected": int(anomalies_detected),
                    "high_risk_events": int(high_risk_count),
                    "clock_skew_flags": int(clock_skew_flags),
                    "total_events": int(total_events or 0),
                }
                (out_dir / "runtime_ml_summary.json").write_text(
                    json.dumps(payload, indent=2),
                    encoding="utf-8",
                )
            except Exception as exc:
                self.logger.warning("Could not persist runtime ML summary: %s", exc)
    
    def _display_ueba_results(self, results: Dict):
        """Display UEBA profiling results."""
        # Reload ml_findings.json to get latest results
        self._load_ml_findings()
        
        # Also display legacy format if tables still empty
        if self.risk_table.rowCount() == 0:
            # High-risk users
            for user in results.get('high_risk_users', [])[:10]:
                row_idx = self.risk_table.rowCount()
                self.risk_table.insertRow(row_idx)
                
                self.risk_table.setItem(row_idx, 0, QTableWidgetItem(user['user_id']))
                
                risk_score = user['risk_score']
                risk_item = QTableWidgetItem(f"{risk_score:.2f}")
                if risk_score > 0.8:
                    risk_item.setBackground(QColor(255, 100, 100))
                elif risk_score > 0.5:
                    risk_item.setBackground(QColor(255, 200, 100))
                self.risk_table.setItem(row_idx, 1, risk_item)
                
                self.risk_table.setItem(row_idx, 2, QTableWidgetItem(str(user.get('alert_count', 0))))
        
        if self.alerts_table.rowCount() == 0:
            # Threats and alerts
            for threat in results.get('insider_threats', []):
                row_idx = self.alerts_table.rowCount()
                self.alerts_table.insertRow(row_idx)
                
                self.alerts_table.setItem(row_idx, 0, QTableWidgetItem("Insider Threat"))
                self.alerts_table.setItem(row_idx, 1, QTableWidgetItem(threat.get('user_id', 'N/A')))
                self.alerts_table.setItem(row_idx, 2, QTableWidgetItem(threat.get('description', 'N/A')))
                self.alerts_table.setItem(row_idx, 3, QTableWidgetItem(threat.get('severity', 'HIGH')))
            
            for takeover in results.get('takeovers', []):
                row_idx = self.alerts_table.rowCount()
                self.alerts_table.insertRow(row_idx)
                
                self.alerts_table.setItem(row_idx, 0, QTableWidgetItem("Account Takeover"))
                self.alerts_table.setItem(row_idx, 1, QTableWidgetItem(takeover.get('user_id', 'N/A')))
                self.alerts_table.setItem(row_idx, 2, QTableWidgetItem(takeover.get('description', 'N/A')))
                self.alerts_table.setItem(row_idx, 3, QTableWidgetItem("CRITICAL"))
        
        total_threats = len(results.get('insider_threats', [])) + len(results.get('takeovers', []))
        self._show_status("ueba", f"✅ Found {total_threats} potential threats")
    
    def _display_threat_intel_results(self, results: Dict):
        """Display threat intelligence results."""
        threat_matches = results.get('threat_matches', [])
        
        self.ti_table.setRowCount(0)
        for match_event in threat_matches:
            for match in match_event.get('threat_matches', []):
                row_idx = self.ti_table.rowCount()
                self.ti_table.insertRow(row_idx)
                
                self.ti_table.setItem(row_idx, 0, QTableWidgetItem(match.get('indicator', 'N/A')))
                self.ti_table.setItem(row_idx, 1, QTableWidgetItem(match.get('type', 'N/A')))
                self.ti_table.setItem(row_idx, 2, QTableWidgetItem(match.get('threat_name', 'Unknown')))
                
                severity = match.get('severity', 'MEDIUM')
                severity_item = QTableWidgetItem(severity)
                if severity == 'CRITICAL':
                    severity_item.setBackground(QColor(255, 0, 0))
                elif severity == 'HIGH':
                    severity_item.setBackground(QColor(255, 100, 100))
                self.ti_table.setItem(row_idx, 3, severity_item)
                
                self.ti_table.setItem(row_idx, 4, QTableWidgetItem(match.get('source', 'N/A')))
                self.ti_table.setItem(row_idx, 5, QTableWidgetItem(match.get('description', 'N/A')))
        
        # Summary
        summary = f"""
🛡️ Threat Intelligence Summary

Total Matches: {len(threat_matches)}
Unique Threats: {len(set(m.get('threat_name', '') for e in threat_matches for m in e.get('threat_matches', [])))}

Critical Matches: {sum(1 for e in threat_matches for m in e.get('threat_matches', []) if m.get('severity') == 'CRITICAL')}
High Matches: {sum(1 for e in threat_matches for m in e.get('threat_matches', []) if m.get('severity') == 'HIGH')}
        """.strip()
        
        self.ti_summary.setText(summary)
        self._show_status("threat_intel", f"✅ Found {len(threat_matches)} threat matches")
    
    def _view_user_profiles(self):
        """Open user profiles dialog."""
        if not self.current_results or 'profiles' not in self.current_results:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self,
                "No Profiles Available",
                "Please run UEBA analysis first to view user profiles."
            )
            return
        
        from ..dialogs.custom_dialogs import UserProfilesDialog
        
        profiles = self.current_results['profiles']
        dialog = UserProfilesDialog(profiles, self)
        dialog.exec()
        
        self.logger.info("User profiles dialog opened")
    
    def _export_results(self):
        """Export current results to file."""
        if self.current_results is None:
            return
        
        from PyQt6.QtWidgets import QFileDialog, QMessageBox
        
        # Get current tab index to determine which results to export
        current_tab = self.sub_tabs.currentIndex()
        
        if current_tab == 0:  # Anomaly Detection
            data_type = "anomaly_detection"
            results_data = self.current_results.get('anomalies', [])
        elif current_tab == 1:  # UEBA
            data_type = "ueba_analysis"
            results_data = {
                'high_risk_users': self.current_results.get('high_risk_users', []),
                'threats': self.current_results.get('threats', [])
            }
        elif current_tab == 2:  # Threat Intel
            data_type = "threat_intelligence"
            results_data = self.current_results.get('matches', [])
        else:
            return
        
        # File dialog with multiple format options
        filepath, selected_filter = QFileDialog.getSaveFileName(
            self,
            f"Export {data_type.replace('_', ' ').title()} Results",
            f"fepd_{data_type}_results.csv",
            "CSV Files (*.csv);;JSON Files (*.json);;Excel Files (*.xlsx);;All Files (*)"
        )
        
        if not filepath:
            return
        
        try:
            import json
            
            if filepath.endswith('.csv') or '*.csv' in selected_filter:
                # Export to CSV
                if isinstance(results_data, list):
                    df = pd.DataFrame(results_data)
                    df.to_csv(filepath, index=False)
                else:
                    # Multiple tables - create separate CSV files
                    base_path = filepath.rsplit('.', 1)[0]
                    for key, value in results_data.items():
                        df = pd.DataFrame(value)
                        df.to_csv(f"{base_path}_{key}.csv", index=False)
            
            elif filepath.endswith('.json') or '*.json' in selected_filter:
                # Export to JSON
                with open(filepath, 'w') as f:
                    json.dump(results_data, f, indent=2, default=str)
            
            elif filepath.endswith('.xlsx') or '*.xlsx' in selected_filter:
                # Export to Excel
                try:
                    if isinstance(results_data, list):
                        df = pd.DataFrame(results_data)
                        df.to_excel(filepath, index=False, sheet_name='Results')
                    else:
                        # Multiple sheets
                        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                            for key, value in results_data.items():
                                df = pd.DataFrame(value)
                                df.to_excel(writer, sheet_name=key.replace('_', ' ').title(), index=False)
                except ImportError:
                    self.logger.warning("openpyxl not installed, falling back to CSV")
                    # Fallback to CSV
                    csv_path = filepath.rsplit('.', 1)[0] + '.csv'
                    if isinstance(results_data, list):
                        df = pd.DataFrame(results_data)
                        df.to_csv(csv_path, index=False)
                    else:
                        for key, value in results_data.items():
                            df = pd.DataFrame(value)
                            df.to_csv(f"{csv_path}_{key}.csv", index=False)
            
            QMessageBox.information(self, "Export Successful", f"Results exported to:\n{filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")
            QMessageBox.critical(self, "Export Failed", f"Failed to export results:\n{str(e)}")
    
    def set_case_context(self, case_path: Path, data_source_path: Path = None, models_dir: Path = None):
        """
        Set case context for forensic data analysis.
        
        Args:
            case_path: Path to the current case directory
            data_source_path: Path to dataa directory (not used - for compatibility)
            models_dir: Path to models directory (default: workspace/models)
        """
        self.case_path = Path(case_path)
        
        if models_dir:
            self.models_dir = Path(models_dir)
        else:
            # Auto-detect models directory
            workspace_root = self.case_path.parent.parent
            self.models_dir = workspace_root / "models"
        
        self.logger.info(f"Case context set: {self.case_path}")
        self.logger.info(f"Models: {self.models_dir}")
        
        # Load existing ML findings if available
        self._load_ml_findings()
    
    def _load_ml_findings(self):
        """Load existing ML findings from case directory."""
        if not self.case_path:
            return
        
        findings_file = self.case_path / "ml_findings.json"
        if not findings_file.exists():
            self.logger.info("No existing ML findings found")
            return
        
        try:
            import json
            with open(findings_file, 'r') as f:
                findings = json.load(f)
            
            self.logger.info(f"Loaded {len(findings)} ML findings from {findings_file}")
            # Could populate UI with existing findings here if needed
            
        except Exception as e:
            self.logger.error(f"Failed to load ML findings: {e}")
    
    def _display_forensic_results(self, ml_results: Dict, timeline_results: Dict):
        """Display forensic analysis results."""
        from PyQt6.QtWidgets import QMessageBox, QDialog, QVBoxLayout, QTextEdit, QPushButton
        
        # Extract key findings
        exec_summary = ml_results.get('executive_summary', {})
        malware_analysis = ml_results.get('analyses', {}).get('malware', {})
        network_analysis = ml_results.get('analyses', {}).get('network', {})
        
        # Build results text
        results_text = f"""
╔══════════════════════════════════════════════════════════════╗
║          FORENSIC ML ANALYSIS RESULTS                        ║
╚══════════════════════════════════════════════════════════════╝

📊 ANALYSIS SUMMARY
{'═' * 60}

Malware Samples Analyzed: {exec_summary.get('total_malware_samples_analyzed', 0):,}
Network Days Analyzed: {exec_summary.get('total_network_days_analyzed', 0)}

🔴 CRITICAL FINDINGS
{'═' * 60}
"""
        
        for finding in exec_summary.get('critical_findings', []):
            results_text += f"{finding}\n"
        
        # Malware details
        if malware_analysis.get('status') == 'success':
            risk_dist = malware_analysis.get('risk_analysis', {}).get('risk_distribution', {})
            results_text += f"""
🦠 MALWARE ANALYSIS
{'═' * 60}
Critical Risk: {risk_dist.get('critical', 0)}
High Risk: {risk_dist.get('high', 0)}
Medium Risk: {risk_dist.get('medium', 0)}
Low Risk: {risk_dist.get('low', 0)}

Insights:
"""
            for insight in malware_analysis.get('insights', []):
                results_text += f"• {insight}\n"
        
        # Network analysis
        if network_analysis.get('status') == 'success':
            anomalies = network_analysis.get('anomaly_analysis', {})
            results_text += f"""
🌐 NETWORK ANALYSIS
{'═' * 60}
Anomalous Days Detected: {anomalies.get('anomalous_days_detected', 0)}
Detection Threshold: {anomalies.get('threshold_used', 'N/A')}
"""
        
        # Recommendations
        results_text += f"""
💡 RECOMMENDATIONS
{'═' * 60}
"""
        for rec in exec_summary.get('recommendations', []):
            results_text += f"• {rec}\n"
        
        # Add reports location if case_path is set
        reports_location = ""
        if self.case_path:
            reports_location = f"\n📁 Reports saved to: {self.case_path / 'forensic_data'}"
        
        results_text += f"""
{'═' * 60}{reports_location}
"""
        
        # Create results dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Forensic Analysis Results")
        dialog.setMinimumSize(800, 600)
        
        layout = QVBoxLayout(dialog)
        
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setPlainText(results_text)
        text_edit.setFontFamily("Courier New")
        layout.addWidget(text_edit)
        
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dialog.accept)
        layout.addWidget(btn_close)
        
        dialog.exec()
        
        # Update summary display in anomaly tab
        self.anomaly_summary.setText(results_text[:500] + "\n\n[See full results in dialog]")
    
    def _display_ml_findings_from_file(self):
        """Load ML findings from ml_findings.json if it exists."""
        if not self.case_path:
            return
        
        findings_file = self.case_path / "results" / "ml_findings.json"
        if not findings_file.exists():
            self.logger.info("No existing ML findings found")
            return
        
        try:
            import json
            with open(findings_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings = data.get('findings', [])
            metadata = data.get('metadata', {})
            
            if len(findings) == 0:
                self.logger.info(f"ML findings file exists but contains no findings ({metadata.get('message', 'empty')})")
                self._show_status("ueba", "ℹ️ No anomalies detected in previous analysis")
                return
            
            self.logger.info(f"Loaded {len(findings)} ML findings from {findings_file}")
            
            # Display in UEBA tab
            self._display_ml_findings(findings, metadata)
            
            # Update status
            self._show_status("ueba", f"✅ Loaded {len(findings)} findings from previous analysis")
            
        except Exception as e:
            self.logger.error(f"Failed to load ML findings: {e}", exc_info=True)
    
    def _display_ml_findings(self, findings: list, metadata: dict):
        """
        Display ML findings in the UEBA tab.
        
        Args:
            findings: List of finding dictionaries
            metadata: Metadata about the analysis
        """
        # Clear existing tables
        self.risk_table.setRowCount(0)
        self.alerts_table.setRowCount(0)
        
        if len(findings) == 0:
            return
        
        # Group findings by user for risk table
        user_risks = {}
        for finding in findings:
            user = finding.get('affected_artifact', 'Unknown')
            severity = finding.get('severity', 'low')
            
            if user not in user_risks:
                user_risks[user] = {'count': 0, 'score': 0.0, 'max_severity': 'low'}
            
            user_risks[user]['count'] += 1
            user_risks[user]['score'] += finding.get('score', 0.0)
            
            # Track highest severity
            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            current_sev = severity_order.get(user_risks[user]['max_severity'], 0)
            new_sev = severity_order.get(severity, 0)
            if new_sev > current_sev:
                user_risks[user]['max_severity'] = severity
        
        # Populate risk table (sorted by score)
        sorted_users = sorted(user_risks.items(), key=lambda x: x[1]['score'], reverse=True)
        for user, risk_info in sorted_users:
            row_idx = self.risk_table.rowCount()
            self.risk_table.insertRow(row_idx)
            
            from PyQt6.QtWidgets import QTableWidgetItem
            from PyQt6.QtGui import QColor
            
            self.risk_table.setItem(row_idx, 0, QTableWidgetItem(user))
            
            score_item = QTableWidgetItem(f"{risk_info['score']:.2f}")
            # Color code by score
            if risk_info['score'] > 0.8:
                score_item.setBackground(QColor(255, 100, 100))  # Red
            elif risk_info['score'] > 0.6:
                score_item.setBackground(QColor(255, 200, 100))  # Orange
            else:
                score_item.setBackground(QColor(255, 255, 150))  # Yellow
            self.risk_table.setItem(row_idx, 1, score_item)
            
            alert_item = QTableWidgetItem(str(risk_info['count']))
            self.risk_table.setItem(row_idx, 2, alert_item)
        
        # Populate alerts table
        for finding in findings:
            row_idx = self.alerts_table.rowCount()
            self.alerts_table.insertRow(row_idx)
            
            from PyQt6.QtWidgets import QTableWidgetItem
            from PyQt6.QtGui import QColor
            
            self.alerts_table.setItem(row_idx, 0, QTableWidgetItem(finding.get('finding_type', 'unknown')))
            self.alerts_table.setItem(row_idx, 1, QTableWidgetItem(finding.get('affected_artifact', 'Unknown')))
            self.alerts_table.setItem(row_idx, 2, QTableWidgetItem(finding.get('description', '')))
            
            severity_item = QTableWidgetItem(finding.get('severity', 'low'))
            # Color code by severity
            severity = finding.get('severity', 'low')
            if severity == 'critical':
                severity_item.setBackground(QColor(200, 0, 0))
                severity_item.setForeground(QColor(255, 255, 255))
            elif severity == 'high':
                severity_item.setBackground(QColor(255, 100, 100))
            elif severity == 'medium':
                severity_item.setBackground(QColor(255, 200, 100))
            else:
                severity_item.setBackground(QColor(255, 255, 150))
            self.alerts_table.setItem(row_idx, 3, severity_item)
        
        self.logger.info(f"Displayed {len(findings)} findings in UEBA tab")
    
    def load_events(self, events_df: pd.DataFrame, auto_analyze: bool = True):
        """Load events for analysis.

        Args:
            events_df: Normalized events dataframe.
            auto_analyze: If True, automatically starts anomaly analysis.
        """
        self.events_df = events_df
        self.logger.info(f"Loaded {len(events_df)} events for ML analysis")
        
        self._show_status("anomaly", f"✅ Loaded {len(events_df)} events - Auto-analyzing...")
        self._show_status("ueba", f"✅ Loaded {len(events_df)} events")
        self._show_status("threat_intel", f"✅ Loaded {len(events_df)} events")
        
        # Auto-run anomaly detection if requested
        if auto_analyze and len(events_df) > 0:
            from PyQt6.QtCore import QTimer
            # Delay to allow UI to update
            QTimer.singleShot(1500, lambda: self._run_analysis("anomaly"))

    def apply_top_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Populate ML overview widgets from routed Top Findings section."""
        self.overview_proc_table.setRowCount(0)
        self.overview_file_table.setRowCount(0)
        self.overview_user_table.setRowCount(0)

        if not findings:
            self.overview_summary.setText("No deterministic findings available for this case.")
            return

        proc_rows = []
        file_rows = []
        user_rows = []

        for finding in findings:
            name = str(finding.get('name') or 'unknown')
            reason = str(finding.get('reason') or '')
            reason_lower = reason.lower()
            risk = float(finding.get('risk_score') or 0)
            ftype = str(finding.get('type') or '').lower()
            if not ftype:
                ftype = 'file'

            row = (name, risk, reason)
            if 'user' in ftype or 'account' in ftype:
                user_rows.append(row)
            elif any(k in ftype for k in ('process', 'execution', 'command', 'detection')) or any(
                k in reason_lower for k in ('execution-related', 'process', 'command', 'shell')
            ):
                proc_rows.append(row)
            else:
                file_rows.append(row)

        self._fill_overview_table(self.overview_proc_table, proc_rows[:10])
        self._fill_overview_table(self.overview_file_table, file_rows[:10])
        self._fill_overview_table(self.overview_user_table, user_rows[:10])

        top_score = max((r[1] for r in (proc_rows + file_rows + user_rows)), default=0.0)
        self.overview_summary.setText(
            "\n".join([
                "Top Findings loaded from deterministic forensic routing.",
                f"Total Findings: {len(findings)}",
                f"Highest Risk Score: {top_score:.2f}",
                f"Process Findings: {len(proc_rows)} | User Findings: {len(user_rows)} | File Findings: {len(file_rows)}",
            ])
        )

    def apply_threat_indicators(self, indicators: List[Dict[str, Any]]) -> None:
        """Populate Threat Intelligence table from routed indicators."""
        self.ti_table.setRowCount(0)
        for ind in indicators:
            row = self.ti_table.rowCount()
            self.ti_table.insertRow(row)
            self.ti_table.setItem(row, 0, QTableWidgetItem(str(ind.get('indicator', 'N/A'))))
            self.ti_table.setItem(row, 1, QTableWidgetItem(str(ind.get('type', 'N/A'))))
            self.ti_table.setItem(row, 2, QTableWidgetItem(str(ind.get('threat_name', 'Observed Indicator'))))
            self.ti_table.setItem(row, 3, QTableWidgetItem(str(ind.get('risk', 'MEDIUM')).upper()))
            self.ti_table.setItem(row, 4, QTableWidgetItem(str(ind.get('source', 'Evidence'))))
            self.ti_table.setItem(row, 5, QTableWidgetItem(str(ind.get('reason', 'Indicator observed in evidence'))))

        self.ti_summary.setText(
            f"Loaded {len(indicators)} indicators from forensic evidence routing."
        )
        self._show_status("threat_intel", f"✅ Loaded {len(indicators)} routed indicators")

    def apply_anomaly_findings(self, anomalies: List[Dict[str, Any]]) -> None:
        """Populate Anomaly Detection tab from routed forensic anomalies."""
        self.anomaly_table.setRowCount(0)

        for anomaly in anomalies:
            row = self.anomaly_table.rowCount()
            self.anomaly_table.insertRow(row)

            score = float(anomaly.get('score') or anomaly.get('anomaly_score') or 0.0)
            severity = str(anomaly.get('severity') or 'medium').upper()
            evidence = anomaly.get('evidence') or []
            if isinstance(evidence, list):
                evidence_text = ', '.join(str(x) for x in evidence[:3])
            else:
                evidence_text = str(evidence)

            self.anomaly_table.setItem(row, 0, QTableWidgetItem(str(anomaly.get('timestamp', 'N/A'))))
            self.anomaly_table.setItem(row, 1, QTableWidgetItem(str(anomaly.get('name') or anomaly.get('event_type') or 'N/A')))
            self.anomaly_table.setItem(row, 2, QTableWidgetItem(str(anomaly.get('source', 'Routed Forensic Section'))))
            self.anomaly_table.setItem(row, 3, QTableWidgetItem(severity))
            self.anomaly_table.setItem(row, 4, QTableWidgetItem(f"{score:.3f}"))
            self.anomaly_table.setItem(row, 5, QTableWidgetItem(str(anomaly.get('cluster', 'deterministic'))))
            self.anomaly_table.setItem(row, 6, QTableWidgetItem(evidence_text if evidence_text else str(anomaly.get('reason', '-'))))

        self.anomaly_summary.setText(
            "\n".join([
                "Anomaly findings loaded from deterministic forensic routing.",
                f"Total anomalies: {len(anomalies)}",
            ])
        )
        self._show_status("anomaly", f"✅ Loaded {len(anomalies)} routed anomalies")

    def apply_ueba_profiles(self, profiles: List[Dict[str, Any]]) -> None:
        """Populate UEBA tab from routed forensic profiles."""
        self.risk_table.setRowCount(0)
        self.alerts_table.setRowCount(0)
        self.overview_user_table.setRowCount(0)

        for profile in profiles:
            row = self.risk_table.rowCount()
            self.risk_table.insertRow(row)
            user_id = str(profile.get('user') or profile.get('user_id') or 'Unknown')
            risk_score = float(profile.get('risk_score') or 0.0)
            alert_count = int(profile.get('event_count') or profile.get('alert_count') or 0)

            self.risk_table.setItem(row, 0, QTableWidgetItem(user_id))
            risk_item = QTableWidgetItem(f"{risk_score:.2f}")
            if risk_score >= 70:
                risk_item.setBackground(QColor(255, 100, 100))
            elif risk_score >= 40:
                risk_item.setBackground(QColor(255, 200, 100))
            self.risk_table.setItem(row, 1, risk_item)
            self.risk_table.setItem(row, 2, QTableWidgetItem(str(alert_count)))

            ov_row = self.overview_user_table.rowCount()
            self.overview_user_table.insertRow(ov_row)
            self.overview_user_table.setItem(ov_row, 0, QTableWidgetItem(user_id))
            self.overview_user_table.setItem(ov_row, 1, QTableWidgetItem(f"{risk_score:.2f}"))
            self.overview_user_table.setItem(ov_row, 2, QTableWidgetItem(str(alert_count)))

            if risk_score >= 60:
                severity = 'HIGH'
            elif risk_score >= 30:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'

            alert_row = self.alerts_table.rowCount()
            self.alerts_table.insertRow(alert_row)
            self.alerts_table.setItem(alert_row, 0, QTableWidgetItem('UEBA Profile'))
            self.alerts_table.setItem(alert_row, 1, QTableWidgetItem(user_id))
            self.alerts_table.setItem(
                alert_row,
                2,
                QTableWidgetItem(f"Observed {alert_count} events across sources: {', '.join(profile.get('sources', []))}")
            )
            self.alerts_table.setItem(alert_row, 3, QTableWidgetItem(severity))

        self._show_status("ueba", f"✅ Loaded {len(profiles)} routed profiles")

    def apply_network_intrusion_events(self, events: List[Dict[str, Any]]) -> None:
        """Populate Network Intrusion tab from routed forensic events."""
        self.ni_table.setRowCount(0)

        anomalies = 0
        for evt in events:
            row = self.ni_table.rowCount()
            self.ni_table.insertRow(row)

            severity = str(evt.get('severity') or 'LOW').upper()
            if severity in ('HIGH', 'CRITICAL'):
                anomalies += 1

            timestamp = (
                evt.get('timestamp')
                or evt.get('ts_utc')
                or evt.get('ts_local')
                or evt.get('time')
                or evt.get('event_time')
                or ''
            )

            self.ni_table.setItem(row, 0, QTableWidgetItem(str(timestamp)))
            self.ni_table.setItem(row, 1, QTableWidgetItem(str(evt.get('event', 'network_event'))))
            self.ni_table.setItem(row, 2, QTableWidgetItem(str(evt.get('source', 'memory'))))
            self.ni_table.setItem(row, 3, QTableWidgetItem(severity))
            self.ni_table.setItem(row, 4, QTableWidgetItem(f"{float(evt.get('score') or 0):.3f}"))
            self.ni_table.setItem(row, 5, QTableWidgetItem(f"{float(evt.get('network_score') or 0):.2f}"))
            self.ni_table.setItem(row, 6, QTableWidgetItem(f"{float(evt.get('artifact_score') or 0):.2f}"))
            self.ni_table.setItem(row, 7, QTableWidgetItem(str(evt.get('flags', ''))))

        total = len(events)
        self.ni_summary.setText(
            "\n".join([
                "Network intrusion events loaded from deterministic forensic routing.",
                f"Total events: {total}",
                f"High/Critical: {anomalies}",
            ])
        )
        self.ni_status.setText(f"✅ Loaded {total} routed network intrusion events")

    def _fill_overview_table(self, table: QTableWidget, rows: List[tuple]) -> None:
        """Internal helper to fill overview tables with (name, score, reason) tuples."""
        table.setRowCount(0)
        for name, score, reason in rows:
            idx = table.rowCount()
            table.insertRow(idx)
            table.setItem(idx, 0, QTableWidgetItem(str(name)))
            table.setItem(idx, 1, QTableWidgetItem(f"{float(score):.2f}"))
            table.setItem(idx, 2, QTableWidgetItem(str(reason)))
