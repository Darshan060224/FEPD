"""
Case Details Tab Widget for FEPD
Displays case metadata in a formatted view.
"""

import logging
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QFormLayout, QPushButton, QTextEdit,
    QScrollArea
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

logger = logging.getLogger(__name__)


class CaseDetailsTab(QWidget):
    """
    Widget for displaying case metadata and information.
    Shows case details, evidence information, and chain of custody summary.
    """
    
    def __init__(self, case_metadata: dict, case_path: Path, parent=None):
        """
        Initialize the Case Details Tab.
        
        Args:
            case_metadata: Dictionary containing case metadata
            case_path: Path to the case directory
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.case_metadata = case_metadata
        self.case_path = case_path
        
        self._init_ui()
        
        logger.info("Case Details Tab initialized")
    
    def _init_ui(self):
        """Initialize the user interface."""
        # Create scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        
        # Main content widget
        content_widget = QWidget()
        main_layout = QVBoxLayout(content_widget)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title_label = QLabel("Case Information")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)
        
        # Case Details Group
        case_group = self._create_case_details_group()
        main_layout.addWidget(case_group)
        
        # Evidence Information Group
        evidence_group = self._create_evidence_info_group()
        main_layout.addWidget(evidence_group)
        
        # Chain of Custody Group
        coc_group = self._create_chain_of_custody_group()
        main_layout.addWidget(coc_group)
        
        # Case Directory Group
        directory_group = self._create_directory_info_group()
        main_layout.addWidget(directory_group)
        
        # Add stretch to push everything to top
        main_layout.addStretch()
        
        # Set content widget to scroll area
        scroll.setWidget(content_widget)
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)
    
    def _create_case_details_group(self) -> QGroupBox:
        """Create the case details group box."""
        group = QGroupBox("Case Details")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        layout = QFormLayout()
        layout.setSpacing(10)
        layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        # Case ID
        case_id_label = QLabel(self.case_metadata.get('case_id', 'N/A'))
        case_id_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        case_id_label.setStyleSheet("font-weight: normal; font-size: 11pt;")
        layout.addRow("<b>Case ID:</b>", case_id_label)
        
        # Case Name
        case_name_label = QLabel(self.case_metadata.get('case_name', 'N/A'))
        case_name_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        case_name_label.setStyleSheet("font-weight: normal; font-size: 11pt;")
        case_name_label.setWordWrap(True)
        layout.addRow("<b>Case Name:</b>", case_name_label)
        
        # Investigator
        investigator_label = QLabel(self.case_metadata.get('investigator', 'N/A'))
        investigator_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        investigator_label.setStyleSheet("font-weight: normal; font-size: 11pt;")
        layout.addRow("<b>Investigator:</b>", investigator_label)
        
        # Created Date
        created_date = self.case_metadata.get('created_date', 'N/A')
        if created_date != 'N/A':
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(created_date)
                created_date = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        created_label = QLabel(created_date)
        created_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        created_label.setStyleSheet("font-weight: normal; font-size: 11pt;")
        layout.addRow("<b>Created:</b>", created_label)
        
        # Last Modified Date
        modified_date = self.case_metadata.get('last_modified', 'N/A')
        if modified_date != 'N/A':
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(modified_date)
                modified_date = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        modified_label = QLabel(modified_date)
        modified_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        modified_label.setStyleSheet("font-weight: normal; font-size: 11pt;")
        layout.addRow("<b>Last Modified:</b>", modified_label)
        
        # Status
        status = self.case_metadata.get('status', 'Unknown')
        status_label = QLabel(status.upper())
        status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        status_label.setStyleSheet("font-weight: normal; font-size: 11pt; color: green;")
        layout.addRow("<b>Status:</b>", status_label)
        
        group.setLayout(layout)
        return group
    
    def _create_evidence_info_group(self) -> QGroupBox:
        """Create the evidence information group box."""
        group = QGroupBox("Evidence Image Information")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        layout = QFormLayout()
        layout.setSpacing(10)
        layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        evidence_info = self.case_metadata.get('evidence_image', {})
        
        # Filename
        filename = evidence_info.get('filename', 'N/A')
        filename_label = QLabel(filename)
        filename_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        filename_label.setStyleSheet("font-weight: normal; font-size: 11pt;")
        filename_label.setWordWrap(True)
        layout.addRow("<b>Filename:</b>", filename_label)
        
        # Path
        path = evidence_info.get('path', 'N/A')
        path_label = QLabel(path)
        path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        path_label.setStyleSheet("font-weight: normal; font-size: 10pt; color: #555;")
        path_label.setWordWrap(True)
        layout.addRow("<b>Path:</b>", path_label)
        
        # File Size
        size_bytes = evidence_info.get('size_bytes', 0)
        size_formatted = self._format_file_size(size_bytes)
        size_label = QLabel(size_formatted)
        size_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        size_label.setStyleSheet("font-weight: normal; font-size: 11pt;")
        layout.addRow("<b>File Size:</b>", size_label)
        
        # SHA-256 Hash
        sha256_hash = evidence_info.get('sha256_hash', 'N/A')
        hash_label = QLabel(sha256_hash)
        hash_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        hash_label.setStyleSheet("font-weight: normal; font-size: 10pt; font-family: monospace;")
        hash_label.setWordWrap(True)
        layout.addRow("<b>SHA-256 Hash:</b>", hash_label)
        
        group.setLayout(layout)
        return group
    
    def _create_chain_of_custody_group(self) -> QGroupBox:
        """Create the chain of custody group box."""
        group = QGroupBox("Chain of Custody")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(10)
        
        # Description
        desc_label = QLabel(
            "Chain of custody log tracks all access and modifications to the evidence. "
            "This ensures forensic integrity and legal admissibility."
        )
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("font-weight: normal; color: #555;")
        layout.addWidget(desc_label)
        
        # Log preview
        coc_log_path = self.case_path / "chain_of_custody.log"
        if coc_log_path.exists():
            try:
                with open(coc_log_path, 'r', encoding='utf-8') as f:
                    # Read last 1000 characters for preview
                    f.seek(0, 2)  # Go to end
                    file_size = f.tell()
                    if file_size > 1000:
                        f.seek(-1000, 2)  # Read last 1000 chars
                        content = "...\n" + f.read()
                    else:
                        f.seek(0)
                        content = f.read()
                
                log_preview = QTextEdit()
                log_preview.setPlainText(content)
                log_preview.setReadOnly(True)
                log_preview.setMaximumHeight(150)
                log_preview.setStyleSheet("font-family: monospace; font-size: 9pt;")
                layout.addWidget(log_preview)
                
            except Exception as e:
                error_label = QLabel(f"Could not load chain of custody log: {e}")
                error_label.setStyleSheet("color: red; font-weight: normal;")
                layout.addWidget(error_label)
        else:
            error_label = QLabel("Chain of custody log not found")
            error_label.setStyleSheet("color: orange; font-weight: normal;")
            layout.addWidget(error_label)
        
        # Open log button
        open_btn = QPushButton("Open Full Log")
        open_btn.setMaximumWidth(150)
        open_btn.clicked.connect(self._open_coc_log)
        layout.addWidget(open_btn)
        
        group.setLayout(layout)
        return group
    
    def _create_directory_info_group(self) -> QGroupBox:
        """Create the case directory information group box."""
        group = QGroupBox("Case Directory")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(10)
        
        # Directory path
        path_label = QLabel(str(self.case_path.absolute()))
        path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        path_label.setStyleSheet("font-weight: normal; font-size: 10pt; font-family: monospace;")
        path_label.setWordWrap(True)
        layout.addWidget(path_label)
        
        # Open directory button
        btn_layout = QHBoxLayout()
        
        open_dir_btn = QPushButton("Open in File Explorer")
        open_dir_btn.setMaximumWidth(200)
        open_dir_btn.clicked.connect(self._open_case_directory)
        btn_layout.addWidget(open_dir_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        group.setLayout(layout)
        return group
    
    def _format_file_size(self, size_bytes: int) -> str:
        """
        Format file size in human-readable format.
        
        Args:
            size_bytes: Size in bytes
        
        Returns:
            Formatted size string
        """
        size_value: float = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_value < 1024.0:
                return f"{size_value:.2f} {unit} ({size_bytes:,} bytes)"
            size_value /= 1024.0
        return f"{size_value:.2f} PB"
    
    def _open_coc_log(self):
        """Open the chain of custody log in system default editor."""
        coc_log_path = self.case_path / "chain_of_custody.log"
        
        if coc_log_path.exists():
            import os
            import platform
            
            try:
                if platform.system() == 'Windows':
                    os.startfile(str(coc_log_path))
                elif platform.system() == 'Darwin':  # macOS
                    os.system(f'open "{coc_log_path}"')
                else:  # Linux
                    os.system(f'xdg-open "{coc_log_path}"')
                
                logger.info(f"Opened chain of custody log: {coc_log_path}")
            except Exception as e:
                logger.error(f"Failed to open log file: {e}")
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.warning(
                    self,
                    "Cannot Open File",
                    f"Failed to open log file:\n{e}"
                )
    
    def _open_case_directory(self):
        """Open the case directory in file explorer."""
        import os
        import platform
        
        try:
            if platform.system() == 'Windows':
                os.startfile(str(self.case_path))
            elif platform.system() == 'Darwin':  # macOS
                os.system(f'open "{self.case_path}"')
            else:  # Linux
                os.system(f'xdg-open "{self.case_path}"')
            
            logger.info(f"Opened case directory: {self.case_path}")
        except Exception as e:
            logger.error(f"Failed to open directory: {e}")
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self,
                "Cannot Open Directory",
                f"Failed to open directory:\n{e}"
            )
    
    def refresh(self):
        """Refresh the case details display."""
        # Clear current layout
        layout = self.layout()
        for i in reversed(range(layout.count())):
            widget = layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        
        # Reinitialize UI
        self._init_ui()
        logger.info("Case details refreshed")
