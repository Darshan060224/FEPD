"""
Case Selection Dialog for FEPD
Modal dialog that appears on startup to create or open a case.
"""

import logging
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, 
    QLabel, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QIcon

logger = logging.getLogger(__name__)


class CaseDialog(QDialog):
    """
    Modal dialog for case selection on application startup.
    Provides options to create a new case or open an existing case.
    """
    
    # Signals
    case_selected = pyqtSignal(dict)  # Emitted when a case is selected with case metadata
    
    def __init__(self, parent=None):
        """
        Initialize the Case Dialog.
        
        Args:
            parent: Parent widget (typically None for modal startup)
        """
        super().__init__(parent)
        
        self.selected_case = None
        self.selected_image_path = None
        self._init_ui()
        
        logger.info("Case Dialog initialized")
    
    def _init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("FEPD - Case Selection")
        self.setModal(True)
        self.setMinimumWidth(500)
        self.setMinimumHeight(300)
        
        # Prevent closing without selecting a case
        self.setWindowFlags(
            Qt.WindowType.Dialog | 
            Qt.WindowType.CustomizeWindowHint | 
            Qt.WindowType.WindowTitleHint
        )
        
        # Main layout
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title_label = QLabel("Forensic Evidence Parser Dashboard")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Please select a case to begin analysis")
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet("color: gray;")
        layout.addWidget(subtitle_label)
        
        # Add spacing
        layout.addSpacing(20)
        
        # Description
        desc_label = QLabel(
            "Before you can begin forensic analysis, you must either create "
            "a new case or open an existing case. All evidence processing and "
            "analysis will be associated with the selected case."
        )
        desc_label.setWordWrap(True)
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setStyleSheet("color: #555;")
        layout.addWidget(desc_label)
        
        # Add spacing
        layout.addSpacing(30)
        
        # Button container
        button_layout = QHBoxLayout()
        button_layout.setSpacing(20)
        
        # Create New Case button
        self.create_case_btn = QPushButton("Create New Case")
        self.create_case_btn.setMinimumHeight(60)
        self.create_case_btn.setMinimumWidth(200)
        button_font = QFont()
        button_font.setPointSize(11)
        self.create_case_btn.setFont(button_font)
        self.create_case_btn.setStyleSheet("""
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:pressed {
                background-color: #005a9e;
            }
        """)
        self.create_case_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.create_case_btn.clicked.connect(self._on_create_case)
        button_layout.addWidget(self.create_case_btn)
        
        # Open Existing Case button
        self.open_case_btn = QPushButton("Open Existing Case")
        self.open_case_btn.setMinimumHeight(60)
        self.open_case_btn.setMinimumWidth(200)
        self.open_case_btn.setFont(button_font)
        self.open_case_btn.setStyleSheet("""
            QPushButton {
                background-color: #107c10;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #0e6b0e;
            }
            QPushButton:pressed {
                background-color: #0c5a0c;
            }
        """)
        self.open_case_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_case_btn.clicked.connect(self._on_open_case)
        button_layout.addWidget(self.open_case_btn)
        
        layout.addLayout(button_layout)
        
        # Add spacing
        layout.addSpacing(20)
        
        # Info label
        info_label = QLabel(
            "⚠️ A case must be selected to continue. "
            "This ensures proper chain of custody and evidence tracking."
        )
        info_label.setWordWrap(True)
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_label.setStyleSheet("""
            background-color: #fff4ce;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #ffeaa7;
        """)
        layout.addWidget(info_label)
        
        # Add stretch to push everything up
        layout.addStretch()
        
        self.setLayout(layout)
    
    def _on_create_case(self):
        """Handle Create New Case button click."""
        logger.info("User clicked 'Create New Case'")
        
        # Import here to avoid circular imports
        from .case_creation_dialog import CaseCreationDialog
        
        # Show case creation dialog
        creation_dialog = CaseCreationDialog(self)
        if creation_dialog.exec() == QDialog.DialogCode.Accepted:
            case_metadata = creation_dialog.get_case_metadata()
            image_path = creation_dialog.get_image_path()
            if case_metadata and image_path:
                self.selected_case = case_metadata
                self.selected_image_path = image_path
                logger.info(f"Case created: {case_metadata['case_id']}, Image: {image_path}")
                self.case_selected.emit(case_metadata)
                self.accept()
    
    def _on_open_case(self):
        """Handle Open Existing Case button click."""
        logger.info("User clicked 'Open Existing Case'")
        
        # Import here to avoid circular imports
        from .case_open_dialog import CaseOpenDialog
        
        # Show case open dialog
        open_dialog = CaseOpenDialog(self)
        if open_dialog.exec() == QDialog.DialogCode.Accepted:
            case_metadata = open_dialog.get_case_metadata()
            image_path = open_dialog.get_image_path()
            if case_metadata and image_path:
                self.selected_case = case_metadata
                self.selected_image_path = image_path
                logger.info(f"Case opened: {case_metadata['case_id']}, Image: {image_path}")
                self.case_selected.emit(case_metadata)
                self.accept()
    
    def get_selected_case(self):
        """
        Get the selected case metadata.
        
        Returns:
            Dictionary containing case metadata, or None if no case selected
        """
        return self.selected_case
    
    def get_image_path(self):
        """
        Get the selected forensic image path.
        
        Returns:
            str: Path to the forensic image, or None if no image selected
        """
        return self.selected_image_path
    
    def closeEvent(self, event):
        """
        Handle close event.
        Prevent closing without selecting a case.
        """
        if self.selected_case is None:
            reply = QMessageBox.question(
                self,
                "Exit Application",
                "No case has been selected. Do you want to exit the application?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                logger.info("User chose to exit without selecting a case")
                event.accept()
            else:
                logger.info("User cancelled exit")
                event.ignore()
        else:
            event.accept()
