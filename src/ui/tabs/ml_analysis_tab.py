"""
FEPD - ML Analysis UI Tab
===========================
UI component for displaying ML predictions and explanations.

Features:
- Evidence type detection display
- ML prediction results
- SHAP/LIME explanations
- Feature importance visualization
- Advisory language (not authoritative)
- Export for court

Copyright (c) 2026 FEPD Development Team
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QGroupBox, QTextEdit, QTableWidget, QTableWidgetItem,
    QProgressBar, QTabWidget, QScrollArea, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from pathlib import Path
import logging
from typing import Dict, List, Optional
import json


class MLAnalysisWorker(QThread):
    """Background worker for ML analysis"""
    
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, str)
    
    def __init__(self, evidence_path: Path, case_id: str, case_path: Path):
        super().__init__()
        self.evidence_path = evidence_path
        self.case_id = case_id
        self.case_path = case_path
        self.logger = logging.getLogger(__name__)
    
    def run(self):
        """Execute ML analysis in background"""
        try:
            from src.ml.inference_pipeline import InferencePipeline
            
            self.progress.emit(10, "Initializing ML pipeline...")
            
            # Initialize pipeline
            pipeline = InferencePipeline(
                case_id=self.case_id,
                case_path=self.case_path,
                operator="ui_analyst"
            )
            
            self.progress.emit(30, "Processing evidence...")
            
            # Run analysis
            results = pipeline.process_evidence(self.evidence_path)
            
            self.progress.emit(100, "Analysis complete")
            self.finished.emit(results)
            
        except Exception as e:
            self.logger.error(f"ML analysis failed: {e}", exc_info=True)
            self.error.emit(str(e))


class MLAnalysisTab(QWidget):
    """
    UI Tab for ML-based forensic analysis.
    
    Displays:
    - Evidence detection results
    - ML predictions with confidence
    - Explainable AI outputs
    - Feature importance
    - Advisory recommendations
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.current_case_id = None
        self.current_case_path = None
        self.worker = None
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Title
        title = QLabel("🤖 ML-Assisted Analysis")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Subtitle with advisory notice
        subtitle = QLabel("⚠️ ML predictions are advisory - analyst judgment is authoritative")
        subtitle.setStyleSheet("color: #ff9800; font-style: italic;")
        layout.addWidget(subtitle)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        # Splitter for main content
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Top section: Evidence Detection
        detection_group = self._create_detection_group()
        splitter.addWidget(detection_group)
        
        # Middle section: ML Predictions
        predictions_group = self._create_predictions_group()
        splitter.addWidget(predictions_group)
        
        # Bottom section: Explanations
        explanations_group = self._create_explanations_group()
        splitter.addWidget(explanations_group)
        
        layout.addWidget(splitter)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.analyze_btn = QPushButton("🔍 Run ML Analysis")
        self.analyze_btn.clicked.connect(self._run_analysis)
        button_layout.addWidget(self.analyze_btn)
        
        self.export_btn = QPushButton("📄 Export Report")
        self.export_btn.clicked.connect(self._export_report)
        self.export_btn.setEnabled(False)
        button_layout.addWidget(self.export_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
    
    def _create_detection_group(self) -> QGroupBox:
        """Create evidence detection display group"""
        group = QGroupBox("Evidence Type Detection")
        layout = QVBoxLayout(group)
        
        # Detection results text
        self.detection_text = QTextEdit()
        self.detection_text.setReadOnly(True)
        self.detection_text.setMaximumHeight(150)
        self.detection_text.setPlaceholderText("No evidence analyzed yet...")
        layout.addWidget(self.detection_text)
        
        return group
    
    def _create_predictions_group(self) -> QGroupBox:
        """Create ML predictions display group"""
        group = QGroupBox("ML Predictions")
        layout = QVBoxLayout(group)
        
        # Predictions table
        self.predictions_table = QTableWidget()
        self.predictions_table.setColumnCount(4)
        self.predictions_table.setHorizontalHeaderLabels([
            "Model", "Prediction", "Confidence", "Status"
        ])
        self.predictions_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.predictions_table)
        
        return group
    
    def _create_explanations_group(self) -> QGroupBox:
        """Create explanations display group"""
        group = QGroupBox("Explanations (SHAP/LIME)")
        layout = QVBoxLayout(group)
        
        # Tab widget for different explanation types
        self.explanation_tabs = QTabWidget()
        
        # Natural language explanation
        self.nl_explanation = QTextEdit()
        self.nl_explanation.setReadOnly(True)
        self.nl_explanation.setPlaceholderText("Explanations will appear here after analysis...")
        self.explanation_tabs.addTab(self.nl_explanation, "Natural Language")
        
        # Feature importance table
        self.feature_table = QTableWidget()
        self.feature_table.setColumnCount(3)
        self.feature_table.setHorizontalHeaderLabels([
            "Feature", "Value", "Importance"
        ])
        self.explanation_tabs.addTab(self.feature_table, "Feature Importance")
        
        # Raw JSON
        self.json_view = QTextEdit()
        self.json_view.setReadOnly(True)
        self.json_view.setFontFamily("Courier New")
        self.explanation_tabs.addTab(self.json_view, "Raw Data")
        
        layout.addWidget(self.explanation_tabs)
        
        return group
    
    def set_case(self, case_id: str, case_path: Path):
        """Set current case"""
        self.current_case_id = case_id
        self.current_case_path = case_path
        self.logger.info(f"ML Analysis tab set to case: {case_id}")
    
    def _run_analysis(self):
        """Run ML analysis on selected evidence"""
        if not self.current_case_id or not self.current_case_path:
            self.status_label.setText("❌ No case loaded")
            return
        
        # Get evidence path (this would come from file selection in real implementation)
        evidence_path = self.current_case_path / "evidence" / "sample.e01"
        
        if not evidence_path.exists():
            self.status_label.setText("❌ No evidence file selected")
            return
        
        # Start background worker
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.analyze_btn.setEnabled(False)
        self.status_label.setText("🔄 Running ML analysis...")
        
        self.worker = MLAnalysisWorker(
            evidence_path=evidence_path,
            case_id=self.current_case_id,
            case_path=self.current_case_path
        )
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_analysis_complete)
        self.worker.error.connect(self._on_analysis_error)
        self.worker.start()
    
    def _on_progress(self, value: int, message: str):
        """Handle progress updates"""
        self.progress_bar.setValue(value)
        self.status_label.setText(f"🔄 {message}")
    
    def _on_analysis_complete(self, results: Dict):
        """Handle analysis completion"""
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.status_label.setText("✅ Analysis complete")
        
        # Display results
        self._display_detection(results.get("stages", {}).get("detection", {}))
        self._display_predictions(results.get("stages", {}).get("predictions", {}))
        self._display_explanations(results.get("stages", {}).get("explanations", {}))
        
        # Store results for export
        self.current_results = results
    
    def _on_analysis_error(self, error_msg: str):
        """Handle analysis error"""
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.status_label.setText(f"❌ Error: {error_msg}")
    
    def _display_detection(self, detection: Dict):
        """Display evidence detection results"""
        if not detection:
            return
        
        text = f"""
Evidence Type Detection Results
================================

Type: {detection.get('evidence_type', 'Unknown')}
Confidence: {detection.get('confidence', 0):.1%}
Detection Method: {detection.get('detected_by', 'Unknown')}
SHA-256: {detection.get('sha256', 'N/A')}

This evidence type was automatically identified using magic numbers
and structural validation (not file extensions).
        """.strip()
        
        self.detection_text.setPlainText(text)
    
    def _display_predictions(self, predictions: Dict):
        """Display ML predictions"""
        prediction_list = predictions.get("predictions", [])
        
        self.predictions_table.setRowCount(len(prediction_list))
        
        for i, pred in enumerate(prediction_list):
            model_name = pred.get("model_name", "Unknown")
            prediction = "SUSPICIOUS" if pred.get("prediction") == 1 else "BENIGN"
            confidence = pred.get("confidence", 0)
            
            # Determine status color
            if prediction == "SUSPICIOUS":
                status_color = QColor(255, 152, 0) if confidence > 0.7 else QColor(255, 193, 7)
            else:
                status_color = QColor(76, 175, 80)
            
            # Populate table
            self.predictions_table.setItem(i, 0, QTableWidgetItem(model_name))
            self.predictions_table.setItem(i, 1, QTableWidgetItem(prediction))
            self.predictions_table.setItem(i, 2, QTableWidgetItem(f"{confidence:.1%}"))
            
            status_item = QTableWidgetItem("⚠️ Review Required" if prediction == "SUSPICIOUS" else "✓ Normal")
            status_item.setBackground(status_color)
            self.predictions_table.setItem(i, 3, status_item)
    
    def _display_explanations(self, explanations: Dict):
        """Display ML explanations"""
        explanation_list = explanations.get("explanations", [])
        
        if not explanation_list:
            return
        
        # Natural language explanation
        nl_text = []
        for exp in explanation_list:
            nl_text.append(f"Model: {exp.get('model', 'Unknown')}")
            nl_text.append(f"Prediction: {exp.get('prediction')}")
            nl_text.append(f"Confidence: {exp.get('confidence', 0):.1%}")
            nl_text.append(f"\n{exp.get('explanation', 'No explanation available')}\n")
            nl_text.append("-" * 60)
        
        self.nl_explanation.setPlainText("\n".join(nl_text))
        
        # Raw JSON
        self.json_view.setPlainText(json.dumps(explanations, indent=2))
    
    def _export_report(self):
        """Export ML analysis report"""
        if not hasattr(self, 'current_results'):
            return
        
        from datetime import datetime
        
        # Export to case folder
        if self.current_case_path is None:
            return
        output_path = self.current_case_path / "ml_analysis" / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.current_results, f, indent=2)
        
        self.status_label.setText(f"✅ Report exported: {output_path.name}")
        self.logger.info(f"ML report exported: {output_path}")
