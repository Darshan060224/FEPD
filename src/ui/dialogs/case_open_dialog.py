"""
Case Open Dialog for FEPD
Dialog for opening an existing forensic case.
"""

import logging
from pathlib import Path
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QFileDialog, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from src.core.case_manager import CaseManager

logger = logging.getLogger(__name__)


class CaseOpenDialog(QDialog):
    """
    Dialog for opening an existing forensic case.
    Shows list of available cases or allows browsing for case directory.
    """
    
    def __init__(self, parent=None):
        """
        Initialize the Case Open Dialog.
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.case_manager = CaseManager()
        self.case_metadata = None
        self.image_path = None
        
        self._init_ui()
        self._load_cases()
        
        logger.info("Case Open Dialog initialized")
    
    def _init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Open Existing Case")
        self.setModal(True)
        self.setMinimumWidth(800)
        self.setMinimumHeight(500)
        
        # Main layout
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(25, 25, 25, 25)
        
        # Title
        title_label = QLabel("Open Existing Case")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)
        
        # Description
        desc_label = QLabel(
            "Select a case from the list below or browse for a case directory."
        )
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: gray;")
        layout.addWidget(desc_label)
        
        # Add spacing
        layout.addSpacing(10)
        
        # Cases table
        self.cases_table = QTableWidget()
        self.cases_table.setColumnCount(4)
        self.cases_table.setHorizontalHeaderLabels([
            "Case ID", "Case Name", "Investigator", "Created Date"
        ])
        
        # Configure table
        self.cases_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.cases_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.cases_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.cases_table.verticalHeader().setVisible(False)
        self.cases_table.setAlternatingRowColors(True)
        
        # Set column widths
        header = self.cases_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        # Connect double-click to open
        self.cases_table.doubleClicked.connect(self._on_table_double_click)
        self.cases_table.itemSelectionChanged.connect(self._on_selection_changed)
        
        layout.addWidget(self.cases_table)
        
        # Browse button
        browse_layout = QHBoxLayout()
        browse_layout.addStretch()
        
        self.browse_btn = QPushButton("Browse for Case Directory...")
        self.browse_btn.setMinimumHeight(35)
        self.browse_btn.clicked.connect(self._browse_case_directory)
        browse_layout.addWidget(self.browse_btn)
        
        layout.addLayout(browse_layout)
        
        # Add spacing
        layout.addSpacing(10)
        
        # Info box
        info_label = QLabel(
            "💡 Tip: Double-click a case to open it, or select and click 'Open Case'."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("""
            background-color: #d1ecf1;
            color: #0c5460;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #bee5eb;
        """)
        layout.addWidget(info_label)
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        # Cancel button
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setMinimumHeight(35)
        self.cancel_btn.setMinimumWidth(100)
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        # Open button
        self.open_btn = QPushButton("Open Case")
        self.open_btn.setMinimumHeight(35)
        self.open_btn.setMinimumWidth(120)
        self.open_btn.setEnabled(False)
        self.open_btn.setStyleSheet("""
            QPushButton {
                background-color: #107c10;
                color: white;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover:enabled {
                background-color: #0e6b0e;
            }
            QPushButton:pressed:enabled {
                background-color: #0c5a0c;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.open_btn.clicked.connect(self._open_selected_case)
        button_layout.addWidget(self.open_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _load_cases(self):
        """Load and display available cases."""
        cases = self.case_manager.get_case_list()
        
        self.cases_table.setRowCount(len(cases))
        
        for row, case in enumerate(cases):
            # Case ID
            case_id_item = QTableWidgetItem(case.get('case_id', 'Unknown'))
            case_id_item.setData(Qt.ItemDataRole.UserRole, case.get('path'))
            self.cases_table.setItem(row, 0, case_id_item)
            
            # Case Name
            case_name_item = QTableWidgetItem(case.get('case_name', 'Unknown'))
            self.cases_table.setItem(row, 1, case_name_item)
            
            # Investigator
            investigator_item = QTableWidgetItem(case.get('investigator', 'Unknown'))
            self.cases_table.setItem(row, 2, investigator_item)
            
            # Created Date
            created_date = case.get('created_date', 'Unknown')
            if created_date != 'Unknown':
                try:
                    # Format ISO date to more readable format
                    from datetime import datetime
                    dt = datetime.fromisoformat(created_date)
                    created_date = dt.strftime('%Y-%m-%d %H:%M')
                except:
                    pass
            
            created_item = QTableWidgetItem(created_date)
            self.cases_table.setItem(row, 3, created_item)
        
        if len(cases) == 0:
            # Show message if no cases found
            self.cases_table.setRowCount(1)
            no_cases_item = QTableWidgetItem("No cases found. Use 'Browse' to locate a case directory.")
            no_cases_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            no_cases_item.setForeground(Qt.GlobalColor.gray)
            self.cases_table.setItem(0, 0, no_cases_item)
            self.cases_table.setSpan(0, 0, 1, 4)
        
        logger.info(f"Loaded {len(cases)} cases")
    
    def _on_selection_changed(self):
        """Handle table selection change."""
        has_selection = bool(self.cases_table.selectedItems())
        self.open_btn.setEnabled(has_selection)
    
    def _on_table_double_click(self, index):
        """Handle double-click on table row."""
        if index.isValid():
            self._open_selected_case()
    
    def _open_selected_case(self):
        """Open the selected case from the table."""
        selected_rows = self.cases_table.selectionModel().selectedRows()
        
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        case_path_item = self.cases_table.item(row, 0)
        case_path = case_path_item.data(Qt.ItemDataRole.UserRole)
        
        if case_path:
            self._open_case(case_path)
    
    def _browse_case_directory(self):
        """Browse for a case directory."""
        case_dir = QFileDialog.getExistingDirectory(
            self,
            "Select Case Directory",
            str(self.case_manager.base_cases_dir),
            QFileDialog.Option.ShowDirsOnly
        )
        
        if case_dir:
            self._open_case(case_dir)
    
    def _open_case(self, case_path):
        """
        Open a case from the given path.
        
        Args:
            case_path: Path to the case directory
        """
        try:
            logger.info(f"Opening case from: {case_path}")
            
            case_metadata = self.case_manager.open_case(case_path)
            self.case_metadata = case_metadata
            
            # Try to read image path from config.json
            config_file = Path(case_path) / "config.json"
            image_path = None
            
            if config_file.exists():
                try:
                    import json
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config_data = json.load(f)
                        image_path = config_data.get('image_path')
                        logger.info(f"Image path from config: {image_path}")
                except Exception as e:
                    logger.warning(f"Could not read config.json: {e}")
            
            # If no image path in config or file doesn't exist, prompt user to select
            if not image_path or not Path(image_path).exists():
                logger.info("Image path not found or invalid, prompting user to select")
                
                reply = QMessageBox.question(
                    self,
                    "Select Forensic Image",
                    f"No forensic image is associated with this case.\n\n"
                    f"Would you like to select an image file now?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes
                )
                
                if reply == QMessageBox.StandardButton.Yes:
                    file_path, _ = QFileDialog.getOpenFileName(
                        self,
                        "Select Forensic Image",
                        "",
                        "Evidence Images (*.E01 *.e01 *.dd *.raw *.001 *.aff *.afd);;All Files (*.*)"
                    )
                    
                    if file_path:
                        image_path = file_path
                        logger.info(f"User selected image: {image_path}")
                    else:
                        QMessageBox.warning(
                            self,
                            "No Image Selected",
                            "No forensic image selected. The case will open but you will need to "
                            "select an image later for analysis."
                        )
                else:
                    QMessageBox.warning(
                        self,
                        "No Image Selected",
                        "Case opened without forensic image. You will need to select an image "
                        "later for analysis."
                    )
            
            self.image_path = image_path
            
            logger.info(f"Case opened successfully: {case_metadata['case_id']}")
            
            QMessageBox.information(
                self,
                "Case Opened",
                f"Case '{case_metadata['case_id']}' opened successfully!\n\n"
                f"Case Name: {case_metadata['case_name']}\n"
                f"Investigator: {case_metadata['investigator']}\n"
                f"Image: {Path(image_path).name if image_path else 'Not selected'}"
            )
            
            self.accept()
            
        except FileNotFoundError as e:
            logger.error(f"Case not found: {e}")
            QMessageBox.critical(
                self,
                "Case Not Found",
                f"Could not find case:\n\n{e}"
            )
        
        except ValueError as e:
            logger.error(f"Invalid case format: {e}")
            QMessageBox.critical(
                self,
                "Invalid Case",
                f"Invalid case format:\n\n{e}"
            )
        
        except Exception as e:
            logger.error(f"Failed to open case: {e}")
            QMessageBox.critical(
                self,
                "Error Opening Case",
                f"Failed to open case:\n\n{e}"
            )
    
    def get_case_metadata(self):
        """
        Get the opened case metadata.
        
        Returns:
            Dictionary containing case metadata, or None if no case opened
        """
        return self.case_metadata
    
    def get_image_path(self):
        """
        Get the selected forensic image path.
        
        Returns:
            str: Path to the forensic image, or None if no image selected
        """
        return self.image_path
