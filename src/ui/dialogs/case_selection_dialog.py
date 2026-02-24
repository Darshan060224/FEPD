"""
Case Selection Dialog - Choose to create new case or open existing case.
Handles startup workflow with last case detection.
"""

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                              QPushButton, QFrame)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon
import logging


logger = logging.getLogger(__name__)


class CaseSelectionDialog(QDialog):
    """
    Dialog for case selection on startup.
    
    Features:
    - New case or open existing
    - Recent case detection
    - Quick open last case
    - Clean modern interface
    
    Signals:
        new_case_requested: Emitted when user wants new case
        open_case_requested: Emitted when user wants to open case
        open_last_case_requested: Emitted when user wants last case (str: case_id)
    
    Example:
        >>> dialog = CaseSelectionDialog(has_last_case=True, last_case_id='case1')
        >>> dialog.new_case_requested.connect(on_new_case)
        >>> dialog.exec()
    """
    
    new_case_requested = pyqtSignal()
    open_case_requested = pyqtSignal()
    open_last_case_requested = pyqtSignal(str)
    
    def __init__(self, has_last_case: bool = False, last_case_id: str = None, 
                 last_opened: str = None, parent=None):
        """
        Initialize case selection dialog.
        
        Args:
            has_last_case: Whether a recent case exists
            last_case_id: ID of last case
            last_opened: Last opened timestamp
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.has_last_case = has_last_case
        self.last_case_id = last_case_id
        self.last_opened = last_opened
        
        self.setWindowTitle("FEPD - Case Selection")
        self.setModal(True)
        self.resize(500, 350)
        
        self._init_ui()
        
        logger.info("CaseSelectionDialog initialized")
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title = QLabel("Welcome to FEPD")
        title.setStyleSheet("font-size: 18pt; font-weight: bold; color: #2c3e50;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Forensic Evidence Processing and Discovery")
        subtitle.setStyleSheet("font-size: 10pt; color: #7f8c8d;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)
        
        layout.addSpacing(10)
        
        # Quick open last case (if available)
        if self.has_last_case and self.last_case_id:
            last_case_frame = self._create_last_case_section()
            layout.addWidget(last_case_frame)
            
            # Separator
            separator = QFrame()
            separator.setFrameShape(QFrame.Shape.HLine)
            separator.setStyleSheet("color: #bdc3c7;")
            layout.addWidget(separator)
        
        # New case button
        new_case_btn = QPushButton("Create New Case")
        new_case_btn.setFixedHeight(60)
        new_case_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        new_case_btn.clicked.connect(self._on_new_case)
        new_case_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 15px;
                border-radius: 5px;
                font-size: 12pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        layout.addWidget(new_case_btn)
        
        # Open case button
        open_case_btn = QPushButton("Open Existing Case")
        open_case_btn.setFixedHeight(60)
        open_case_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        open_case_btn.clicked.connect(self._on_open_case)
        open_case_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 15px;
                border-radius: 5px;
                font-size: 12pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        layout.addWidget(open_case_btn)
        
        layout.addStretch()
        
        # Exit button
        exit_layout = QHBoxLayout()
        exit_layout.addStretch()
        
        exit_btn = QPushButton("Exit")
        exit_btn.setFixedWidth(100)
        exit_btn.clicked.connect(self.reject)
        exit_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        exit_layout.addWidget(exit_btn)
        
        layout.addLayout(exit_layout)
    
    def _create_last_case_section(self) -> QFrame:
        """Create section for quick opening last case."""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #ecf0f1;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setSpacing(10)
        
        # Title
        title = QLabel("Continue Recent Case")
        title.setStyleSheet("font-weight: bold; color: #2c3e50; font-size: 11pt;")
        layout.addWidget(title)
        
        # Case info
        info_text = f"Case: {self.last_case_id}"
        if self.last_opened:
            from datetime import datetime
            try:
                opened = datetime.fromisoformat(self.last_opened)
                time_str = opened.strftime("%Y-%m-%d %H:%M")
                info_text += f"\nLast opened: {time_str}"
            except:
                pass
        
        info_label = QLabel(info_text)
        info_label.setStyleSheet("color: #7f8c8d;")
        layout.addWidget(info_label)
        
        # Open button
        open_btn = QPushButton("Open This Case")
        open_btn.setFixedHeight(40)
        open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        open_btn.clicked.connect(self._on_open_last_case)
        open_btn.setStyleSheet("""
            QPushButton {
                background-color: #e67e22;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d35400;
            }
        """)
        layout.addWidget(open_btn)
        
        return frame
    
    def _on_new_case(self):
        """Handle new case button click."""
        logger.info("User selected: Create new case")
        self.new_case_requested.emit()
        self.accept()
    
    def _on_open_case(self):
        """Handle open case button click."""
        logger.info("User selected: Open existing case")
        self.open_case_requested.emit()
        self.accept()
    
    def _on_open_last_case(self):
        """Handle open last case button click."""
        logger.info(f"User selected: Open last case ({self.last_case_id})")
        self.open_last_case_requested.emit(self.last_case_id)
        self.accept()


if __name__ == '__main__':
    """Quick test of CaseSelectionDialog."""
    import sys
    from PyQt6.QtWidgets import QApplication
    from datetime import datetime
    
    print("=" * 60)
    print("CaseSelectionDialog Test")
    print("=" * 60)
    
    app = QApplication(sys.argv)
    
    # Test 1: Dialog with last case
    print("\nTest 1: Dialog with last case...")
    dialog1 = CaseSelectionDialog(
        has_last_case=True,
        last_case_id='case_2024_001',
        last_opened=datetime.now().isoformat()
    )
    
    # Connect signals
    def on_new_case():
        print("   ✓ Signal: new_case_requested")
    
    def on_open_case():
        print("   ✓ Signal: open_case_requested")
    
    def on_open_last(case_id):
        print(f"   ✓ Signal: open_last_case_requested ({case_id})")
    
    dialog1.new_case_requested.connect(on_new_case)
    dialog1.open_case_requested.connect(on_open_case)
    dialog1.open_last_case_requested.connect(on_open_last)
    
    print("   Showing dialog with last case...")
    result1 = dialog1.exec()
    print(f"   Result: {'Accepted' if result1 == QDialog.DialogCode.Accepted else 'Rejected'}")
    
    # Test 2: Dialog without last case
    print("\nTest 2: Dialog without last case...")
    dialog2 = CaseSelectionDialog(has_last_case=False)
    
    dialog2.new_case_requested.connect(on_new_case)
    dialog2.open_case_requested.connect(on_open_case)
    
    print("   Showing dialog without last case...")
    result2 = dialog2.exec()
    print(f"   Result: {'Accepted' if result2 == QDialog.DialogCode.Accepted else 'Rejected'}")
    
    print("\n" + "=" * 60)
    print("✅ CaseSelectionDialog test completed!")
    print("=" * 60)
