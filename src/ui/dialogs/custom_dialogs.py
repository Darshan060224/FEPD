"""
FEPD - Dialogs Package
======================
Custom dialogs for FEPD UI:
- User Profiles Viewer (UEBA)
- ML Explainability Viewer
- Settings Dialog
- Export Options Dialog

Copyright (c) 2025 FEPD Development Team
"""

import logging
from typing import Dict, List, Optional
import pandas as pd

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QTabWidget, QGroupBox, QSplitter,
    QWidget, QComboBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis


class UserProfilesDialog(QDialog):
    """
    Dialog to view detailed UEBA user profiles.
    Shows behavior baselines, risk scores, and activity history.
    """
    
    def __init__(self, profiles: Dict, parent=None):
        super().__init__(parent)
        self.profiles = profiles
        self.logger = logging.getLogger(__name__)
        
        self.setWindowTitle("UEBA User Profiles")
        self.setGeometry(100, 100, 1200, 800)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("👤 User Behavior Analytics Profiles")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # User selection
        selection_layout = QHBoxLayout()
        selection_layout.addWidget(QLabel("Select User:"))
        
        self.user_table = QTableWidget(0, 4)
        self.user_table.setHorizontalHeaderLabels([
            "User ID", "Risk Score", "Total Events", "Status"
        ])
        self.user_table.setMaximumHeight(200)
        self.user_table.itemSelectionChanged.connect(self._on_user_selected)
        
        # Populate user table
        for user_id, profile in self.profiles.items():
            row_idx = self.user_table.rowCount()
            self.user_table.insertRow(row_idx)
            
            self.user_table.setItem(row_idx, 0, QTableWidgetItem(str(user_id)))
            
            risk_score = profile.get('risk_score', 0)
            risk_item = QTableWidgetItem(f"{risk_score:.2f}")
            if risk_score > 0.7:
                risk_item.setBackground(QColor(255, 100, 100))
            elif risk_score > 0.5:
                risk_item.setBackground(QColor(255, 200, 100))
            self.user_table.setItem(row_idx, 1, risk_item)
            
            self.user_table.setItem(row_idx, 2, 
                QTableWidgetItem(str(profile.get('total_events', 0))))
            
            status = "🔴 HIGH RISK" if risk_score > 0.7 else "🟡 MEDIUM" if risk_score > 0.5 else "🟢 NORMAL"
            self.user_table.setItem(row_idx, 3, QTableWidgetItem(status))
        
        layout.addWidget(self.user_table)
        
        # Profile details (tabs)
        self.details_tabs = QTabWidget()
        self.details_tabs.addTab(self._create_baseline_tab(), "📊 Behavior Baseline")
        self.details_tabs.addTab(self._create_activity_tab(), "📈 Activity History")
        self.details_tabs.addTab(self._create_alerts_tab(), "⚠️ Alerts")
        
        layout.addWidget(self.details_tabs)
        
        # Close button
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)
    
    def _create_baseline_tab(self) -> QWidget:
        """Create behavior baseline tab."""
        from PyQt6.QtWidgets import QWidget
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.baseline_text = QTextEdit()
        self.baseline_text.setReadOnly(True)
        self.baseline_text.setPlaceholderText("Select a user to view behavior baseline")
        layout.addWidget(self.baseline_text)
        
        return widget
    
    def _create_activity_tab(self) -> QWidget:
        """Create activity history tab."""
        from PyQt6.QtWidgets import QWidget
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.activity_table = QTableWidget(0, 5)
        self.activity_table.setHorizontalHeaderLabels([
            "Timestamp", "Event Type", "Category", "Severity", "Description"
        ])
        layout.addWidget(self.activity_table)
        
        return widget
    
    def _create_alerts_tab(self) -> QWidget:
        """Create alerts tab."""
        from PyQt6.QtWidgets import QWidget
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.alerts_table = QTableWidget(0, 4)
        self.alerts_table.setHorizontalHeaderLabels([
            "Timestamp", "Alert Type", "Severity", "Description"
        ])
        layout.addWidget(self.alerts_table)
        
        return widget
    
    def _on_user_selected(self):
        """Handle user selection."""
        selected_items = self.user_table.selectedItems()
        if not selected_items:
            return
        
        user_id = self.user_table.item(selected_items[0].row(), 0).text()
        profile = self.profiles.get(user_id, {})
        
        # Update baseline tab
        baseline_info = f"""
User Profile: {user_id}
═══════════════════════════════════════════════════════

Risk Score: {profile.get('risk_score', 0):.2f}
Total Events: {profile.get('total_events', 0)}
Observation Period: {profile.get('start_time', 'N/A')} to {profile.get('end_time', 'N/A')}

Behavior Baseline
─────────────────
Typical Hours: {profile.get('typical_hours', 'N/A')}
Typical Files Accessed: {profile.get('avg_files_accessed', 0):.1f} per session
Typical Data Volume: {profile.get('avg_data_volume', 0):.1f} MB
Typical Locations: {', '.join(profile.get('typical_locations', []))}
Typical Processes: {', '.join(profile.get('typical_processes', [])[:5])}

Activity Patterns
─────────────────
Most Active Hours: {profile.get('peak_hours', 'N/A')}
Most Accessed Categories: {', '.join(profile.get('top_categories', [])[:5])}
Network Activity: {profile.get('network_activity_level', 'Normal')}
File Access Pattern: {profile.get('file_access_pattern', 'Normal')}

Risk Indicators
───────────────
Off-hours Activity: {profile.get('off_hours_count', 0)} events
Large File Transfers: {profile.get('large_file_count', 0)} transfers
Privilege Escalations: {profile.get('privilege_escalation_count', 0)} attempts
Failed Logins: {profile.get('failed_login_count', 0)} failures
Suspicious Processes: {profile.get('suspicious_process_count', 0)} executions
        """.strip()
        
        self.baseline_text.setText(baseline_info)
        
        # Update activity tab
        self.activity_table.setRowCount(0)
        activities = profile.get('recent_activities', [])
        for activity in activities[:100]:  # Limit to 100 most recent
            row_idx = self.activity_table.rowCount()
            self.activity_table.insertRow(row_idx)
            
            self.activity_table.setItem(row_idx, 0, 
                QTableWidgetItem(str(activity.get('timestamp', 'N/A'))))
            self.activity_table.setItem(row_idx, 1, 
                QTableWidgetItem(activity.get('event_type', 'N/A')))
            self.activity_table.setItem(row_idx, 2, 
                QTableWidgetItem(activity.get('category', 'N/A')))
            
            severity = activity.get('severity', 'INFO')
            severity_item = QTableWidgetItem(severity)
            if severity == 'CRITICAL':
                severity_item.setBackground(QColor(255, 0, 0))
            elif severity == 'HIGH':
                severity_item.setBackground(QColor(255, 100, 100))
            self.activity_table.setItem(row_idx, 3, severity_item)
            
            self.activity_table.setItem(row_idx, 4, 
                QTableWidgetItem(activity.get('description', 'N/A')[:100]))
        
        # Update alerts tab
        self.alerts_table.setRowCount(0)
        alerts = profile.get('alerts', [])
        for alert in alerts:
            row_idx = self.alerts_table.rowCount()
            self.alerts_table.insertRow(row_idx)
            
            self.alerts_table.setItem(row_idx, 0, 
                QTableWidgetItem(str(alert.get('timestamp', 'N/A'))))
            self.alerts_table.setItem(row_idx, 1, 
                QTableWidgetItem(alert.get('type', 'N/A')))
            
            severity = alert.get('severity', 'INFO')
            severity_item = QTableWidgetItem(severity)
            if severity == 'CRITICAL':
                severity_item.setBackground(QColor(255, 0, 0))
            elif severity == 'HIGH':
                severity_item.setBackground(QColor(255, 100, 100))
            self.alerts_table.setItem(row_idx, 2, severity_item)
            
            self.alerts_table.setItem(row_idx, 3, 
                QTableWidgetItem(alert.get('description', 'N/A')))


class MLExplanationDialog(QDialog):
    """
    Dialog to view ML model explanations.
    Shows SHAP values, feature importance, and natural language explanations.
    """
    
    def __init__(self, explanation: Dict, parent=None):
        super().__init__(parent)
        self.explanation = explanation
        self.logger = logging.getLogger(__name__)
        
        self.setWindowTitle("ML Explanation")
        self.setGeometry(100, 100, 900, 700)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("🔍 ML Model Explanation")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Natural language explanation
        explanation_group = QGroupBox("Natural Language Explanation")
        explanation_layout = QVBoxLayout(explanation_group)
        
        self.explanation_text = QTextEdit()
        self.explanation_text.setReadOnly(True)
        self.explanation_text.setText(self.explanation.get('natural_language', 'No explanation available'))
        self.explanation_text.setMinimumHeight(200)
        explanation_layout.addWidget(self.explanation_text)
        
        layout.addWidget(explanation_group)
        
        # Feature importance table
        features_group = QGroupBox("Feature Importance")
        features_layout = QVBoxLayout(features_group)
        
        self.features_table = QTableWidget(0, 3)
        self.features_table.setHorizontalHeaderLabels([
            "Feature", "Value", "Contribution"
        ])
        
        # Populate feature importance
        features = self.explanation.get('features', [])
        for feature in features:
            row_idx = self.features_table.rowCount()
            self.features_table.insertRow(row_idx)
            
            self.features_table.setItem(row_idx, 0, 
                QTableWidgetItem(feature.get('name', 'N/A')))
            self.features_table.setItem(row_idx, 1, 
                QTableWidgetItem(str(feature.get('value', 'N/A'))))
            
            contribution = feature.get('contribution', 0)
            contrib_item = QTableWidgetItem(f"{contribution:+.4f}")
            if contribution > 0:
                contrib_item.setBackground(QColor(255, 200, 200))
            elif contribution < 0:
                contrib_item.setBackground(QColor(200, 255, 200))
            self.features_table.setItem(row_idx, 2, contrib_item)
        
        features_layout.addWidget(self.features_table)
        layout.addWidget(features_group)
        
        # Evidence section
        evidence_group = QGroupBox("Supporting Evidence")
        evidence_layout = QVBoxLayout(evidence_group)
        
        self.evidence_text = QTextEdit()
        self.evidence_text.setReadOnly(True)
        
        evidence_list = self.explanation.get('evidence', [])
        evidence_str = "\n\n".join([f"• {ev}" for ev in evidence_list])
        self.evidence_text.setText(evidence_str)
        
        evidence_layout.addWidget(self.evidence_text)
        layout.addWidget(evidence_group)
        
        # Close button
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)


class SettingsDialog(QDialog):
    """
    Settings dialog for FEPD configuration.
    """
    
    def __init__(self, config: Dict, parent=None):
        super().__init__(parent)
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        self.setWindowTitle("FEPD Settings")
        self.setGeometry(100, 100, 800, 600)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("⚙️ Application Settings")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Settings tabs
        settings_tabs = QTabWidget()
        settings_tabs.addTab(self._create_general_tab(), "General")
        settings_tabs.addTab(self._create_ml_tab(), "ML Settings")
        settings_tabs.addTab(self._create_api_tab(), "API Keys")
        settings_tabs.addTab(self._create_search_tab(), "Search Engine")
        
        layout.addWidget(settings_tabs)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        btn_save = QPushButton("💾 Save")
        btn_save.clicked.connect(self._save_settings)
        button_layout.addWidget(btn_save)
        
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        button_layout.addWidget(btn_cancel)
        
        layout.addLayout(button_layout)
    
    def _create_general_tab(self) -> QWidget:
        """Create general settings tab."""
        from PyQt6.QtWidgets import QWidget, QComboBox
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Language selection
        lang_layout = QHBoxLayout()
        lang_layout.addWidget(QLabel("Language:"))
        self.language_combo = QComboBox()
        self.language_combo.addItems([
            "English", "Spanish", "French", "German", "Japanese", "Chinese"
        ])
        lang_layout.addWidget(self.language_combo)
        lang_layout.addStretch()
        layout.addLayout(lang_layout)
        
        # Theme selection
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(QLabel("Theme:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark Indigo", "Light", "Dark", "High Contrast"])
        theme_layout.addWidget(self.theme_combo)
        theme_layout.addStretch()
        layout.addLayout(theme_layout)
        
        layout.addStretch()
        return widget
    
    def _create_ml_tab(self) -> QWidget:
        """Create ML settings tab."""
        from PyQt6.QtWidgets import QWidget, QSpinBox, QDoubleSpinBox, QCheckBox
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Anomaly threshold
        threshold_layout = QHBoxLayout()
        threshold_layout.addWidget(QLabel("Anomaly Threshold:"))
        self.anomaly_threshold = QDoubleSpinBox()
        self.anomaly_threshold.setRange(0.0, 1.0)
        self.anomaly_threshold.setSingleStep(0.05)
        self.anomaly_threshold.setValue(0.7)
        threshold_layout.addWidget(self.anomaly_threshold)
        threshold_layout.addStretch()
        layout.addLayout(threshold_layout)
        
        # UEBA sensitivity
        ueba_layout = QHBoxLayout()
        ueba_layout.addWidget(QLabel("UEBA Sensitivity:"))
        self.ueba_sensitivity = QComboBox()
        self.ueba_sensitivity.addItems(["Low", "Medium", "High"])
        self.ueba_sensitivity.setCurrentText("Medium")
        ueba_layout.addWidget(self.ueba_sensitivity)
        ueba_layout.addStretch()
        layout.addLayout(ueba_layout)
        
        layout.addStretch()
        return widget
    
    def _create_api_tab(self) -> QWidget:
        """Create API keys tab."""
        from PyQt6.QtWidgets import QWidget, QLineEdit
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # VirusTotal API
        vt_layout = QHBoxLayout()
        vt_layout.addWidget(QLabel("VirusTotal API Key:"))
        self.vt_api_key = QLineEdit()
        self.vt_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        vt_layout.addWidget(self.vt_api_key)
        layout.addLayout(vt_layout)
        
        # OTX API
        otx_layout = QHBoxLayout()
        otx_layout.addWidget(QLabel("AlienVault OTX API Key:"))
        self.otx_api_key = QLineEdit()
        self.otx_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        otx_layout.addWidget(self.otx_api_key)
        layout.addLayout(otx_layout)
        
        layout.addStretch()
        return widget
    
    def _create_search_tab(self) -> QWidget:
        """Create search engine settings tab."""
        from PyQt6.QtWidgets import QWidget, QLineEdit, QCheckBox
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Elasticsearch
        es_layout = QHBoxLayout()
        es_layout.addWidget(QLabel("Elasticsearch Hosts:"))
        self.es_hosts = QLineEdit()
        self.es_hosts.setPlaceholderText("localhost:9200")
        es_layout.addWidget(self.es_hosts)
        layout.addLayout(es_layout)
        
        # Enable Elasticsearch
        self.es_enable = QCheckBox("Enable Elasticsearch")
        layout.addWidget(self.es_enable)
        
        layout.addStretch()
        return widget
    
    def _save_settings(self):
        """Save settings."""
        # TODO: Implement settings persistence
        self.logger.info("Settings saved")
        self.accept()
