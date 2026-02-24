"""
Create Case Dialog for FEPD Case Tab

Dialog for creating a new forensic case with all required metadata.

Copyright (c) 2026 FEPD Development Team
"""

import logging
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

logger = logging.getLogger(__name__)


class CreateCaseDialog(QDialog):
    """Dialog for creating a new case."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.case_data = {}
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI."""
        self.setWindowTitle("Create New Case")
        self.setModal(True)
        self.setMinimumWidth(500)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("➕ Create New Forensic Case")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Form
        form = QFormLayout()
        
        self.txt_case_name = QLineEdit()
        self.txt_case_name.setPlaceholderText("e.g., LoneWolf_Investigation")
        form.addRow("Case Name *:", self.txt_case_name)
        
        self.txt_operator = QLineEdit()
        self.txt_operator.setPlaceholderText("Your name")
        form.addRow("Operator *:", self.txt_operator)
        
        self.txt_organization = QLineEdit()
        self.txt_organization.setPlaceholderText("Organization (optional)")
        form.addRow("Organization:", self.txt_organization)
        
        self.txt_notes = QTextEdit()
        self.txt_notes.setPlaceholderText("Case description, objectives, etc.")
        self.txt_notes.setMaximumHeight(100)
        form.addRow("Notes:", self.txt_notes)
        
        layout.addLayout(form)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        btn_create = QPushButton("Create Case")
        btn_create.clicked.connect(self._on_create)
        btn_create.setStyleSheet("""
            QPushButton {
                background-color: #2e7d32;
                color: white;
                padding: 8px 20px;
                font-weight: bold;
            }
        """)
        
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        
        btn_layout.addStretch()
        btn_layout.addWidget(btn_create)
        btn_layout.addWidget(btn_cancel)
        
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
    
    def _on_create(self):
        """Validate and accept."""
        case_name = self.txt_case_name.text().strip()
        operator = self.txt_operator.text().strip()
        
        if not case_name:
            QMessageBox.warning(self, "Validation", "Case Name is required.")
            return
        
        if not operator:
            QMessageBox.warning(self, "Validation", "Operator name is required.")
            return
        
        self.case_data = {
            'case_name': case_name,
            'operator': operator,
            'organization': self.txt_organization.text().strip(),
            'notes': self.txt_notes.toPlainText().strip()
        }
        
        self.accept()
    
    def get_case_data(self):
        """Get entered case data."""
        return self.case_data
