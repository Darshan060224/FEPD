"""
Restore Session Dialog - Prompt user to restore previous session or start fresh.
Shows snapshot metadata and gives user choice.
"""

from pathlib import Path
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QFrame, QWidget
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from datetime import datetime
from typing import Optional, Dict, Any


class RestoreSessionDialog(QDialog):
    """
    Dialog asking user whether to restore previous session or start fresh.
    
    Features:
    - Shows snapshot metadata (timestamp, event count, filters)
    - Two prominent buttons: Restore / Start Fresh
    - Optional "Don't ask again" checkbox
    
    Example:
        >>> dialog = RestoreSessionDialog(
        ...     parent=self,
        ...     snapshot_metadata={
        ...         'timestamp': '2024-11-10T14:30:00',
        ...         'total_events': 465,
        ...         'has_filters': True
        ...     }
        ... )
        >>> result = dialog.exec()
        >>> if result == RestoreSessionDialog.RESTORE:
        ...     # Restore session
        >>> elif result == RestoreSessionDialog.START_FRESH:
        ...     # Start fresh, delete snapshot
    """
    
    # Return codes
    RESTORE = 1
    START_FRESH = 2
    
    def __init__(
        self,
        case_path: str,
        parent=None,
        snapshot_metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize restore session dialog.
        
        Args:
            case_path: Path to the case directory
            parent: Parent widget
            snapshot_metadata: Snapshot metadata from SessionManager
        """
        super().__init__(parent)
        self.case_path = Path(case_path)
        self.setWindowTitle("Previous Session Found")
        self.setModal(True)
        self.setMinimumWidth(500)
        self.setMinimumHeight(250)
        
        self.snapshot_metadata = snapshot_metadata or {}
        self.result_code = None
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Title with icon
        title_layout = QHBoxLayout()
        title_icon = QLabel("💾")
        title_icon.setStyleSheet("font-size: 32px;")
        title_layout.addWidget(title_icon)
        
        title_label = QLabel("Previous Session Available")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        layout.addLayout(title_layout)
        
        # Description
        desc = QLabel(
            "A saved session was found for this case. "
            "You can restore your previous analysis state or start fresh."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #555; margin-bottom: 10px;")
        layout.addWidget(desc)
        
        # Snapshot info panel
        info_frame = QFrame()
        info_frame.setFrameShape(QFrame.Shape.StyledPanel)
        info_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        info_layout = QVBoxLayout(info_frame)
        
        # Parse timestamp
        timestamp_str = self.snapshot_metadata.get('timestamp', '')
        if timestamp_str:
            try:
                dt = datetime.fromisoformat(timestamp_str)
                formatted_time = dt.strftime('%B %d, %Y at %I:%M %p')
            except:
                formatted_time = timestamp_str
        else:
            formatted_time = 'Unknown'
        
        # Info labels
        info_items = [
            ("📅 Last Saved:", formatted_time),
            ("📊 Events:", str(self.snapshot_metadata.get('total_events', 'N/A'))),
            ("🗂 Artifacts:", str(self.snapshot_metadata.get('total_artifacts', 'N/A'))),
            ("🔍 Filters Applied:", "Yes" if self.snapshot_metadata.get('has_filters') else "No"),
        ]
        
        for label_text, value_text in info_items:
            row = QHBoxLayout()
            
            label = QLabel(label_text)
            label.setStyleSheet("font-weight: bold; color: #333;")
            label.setMinimumWidth(120)
            row.addWidget(label)
            
            value = QLabel(value_text)
            value.setStyleSheet("color: #555;")
            row.addWidget(value)
            row.addStretch()
            
            info_layout.addLayout(row)
        
        layout.addWidget(info_frame)
        
        # Spacer
        layout.addSpacing(10)
        
        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        # Start Fresh button
        self.start_fresh_btn = QPushButton("🆕 Start Fresh")
        self.start_fresh_btn.setMinimumWidth(150)
        self.start_fresh_btn.setMinimumHeight(40)
        self.start_fresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
            QPushButton:pressed {
                background-color: #545b62;
            }
        """)
        self.start_fresh_btn.clicked.connect(self._on_start_fresh)
        button_layout.addWidget(self.start_fresh_btn)
        
        button_layout.addSpacing(10)
        
        # Restore button (primary)
        self.restore_btn = QPushButton("✅ Restore Session")
        self.restore_btn.setMinimumWidth(150)
        self.restore_btn.setMinimumHeight(40)
        self.restore_btn.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
            QPushButton:pressed {
                background-color: #1e7e34;
            }
        """)
        self.restore_btn.clicked.connect(self._on_restore)
        self.restore_btn.setDefault(True)  # Make it the default action
        button_layout.addWidget(self.restore_btn)
        
        layout.addLayout(button_layout)
        
        # Help text
        help_text = QLabel(
            "💡 Tip: Restoring will reload your filters, scroll position, and UI layout."
        )
        help_text.setStyleSheet("color: #6c757d; font-size: 11px; margin-top: 10px;")
        help_text.setWordWrap(True)
        layout.addWidget(help_text)
    
    def _on_restore(self):
        """Handle Restore button click."""
        self.result_code = self.RESTORE
        self.accept()
    
    def _on_start_fresh(self):
        """Handle Start Fresh button click."""
        self.result_code = self.START_FRESH
        self.accept()
    
    def exec(self) -> int:
        """
        Execute dialog and return result code.
        
        Returns:
            RESTORE (1) or START_FRESH (2)
        """
        super().exec()
        return self.result_code if self.result_code else self.START_FRESH


if __name__ == '__main__':
    """Quick test of the dialog."""
    import sys
    from PyQt6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    # Test with sample metadata
    dialog = RestoreSessionDialog(
        snapshot_metadata={
            'timestamp': '2024-11-10T14:30:00',
            'total_events': 465,
            'total_artifacts': 132,
            'has_filters': True,
            'selected_tab': 1
        }
    )
    
    result = dialog.exec()
    
    if result == RestoreSessionDialog.RESTORE:
        print("✅ User chose: RESTORE SESSION")
    elif result == RestoreSessionDialog.START_FRESH:
        print("🆕 User chose: START FRESH")
    else:
        print("❌ Dialog cancelled")
    
    sys.exit(0)
