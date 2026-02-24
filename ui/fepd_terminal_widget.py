"""FEPD OS Terminal Integration - UI Tab Component

This module provides the FEPD Forensic Terminal as a PyQt6 widget.
This is a real OS-style terminal, not a chat box with an input field.

Add this as a new tab: [ Overview ] [ Timeline ] [ Artifacts ] [ ML ] [ 🖥 FEPD Terminal ]
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtCore import pyqtSignal

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import the new forensic terminal
try:
    from src.ui.widgets.forensic_terminal import ForensicTerminal, ForensicTerminalWidget
    FORENSIC_TERMINAL_AVAILABLE = True
except ImportError:
    FORENSIC_TERMINAL_AVAILABLE = False


class FEPDTerminalWidget(QWidget):
    """
    FEPD Forensic Terminal Widget.
    
    This is a real OS-style terminal where:
    - User types directly into a single text surface
    - Cursor is always at the prompt line
    - Cannot edit command history
    - Windows/Linux commands are mapped to FEPD equivalents
    - Mutating commands are blocked with forensic protection
    """
    
    # Signals
    command_executed = pyqtSignal(str, str)  # (command, output)
    case_changed = pyqtSignal(str)           # case_name
    
    def __init__(self, workspace_root='.', parent=None):
        super().__init__(parent)
        self.workspace_root = workspace_root
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        if FORENSIC_TERMINAL_AVAILABLE:
            # Use the new forensic terminal
            self.terminal = ForensicTerminal(workspace_root, self)
            layout.addWidget(self.terminal)
            
            # Connect signals
            self.terminal.command_executed.connect(self.command_executed.emit)
            self.terminal.case_changed.connect(self.case_changed.emit)
        else:
            # Fallback to basic text display
            from PyQt6.QtWidgets import QPlainTextEdit
            self.terminal = QPlainTextEdit(self)
            self.terminal.setReadOnly(True)
            self.terminal.setPlainText(
                "FEPD Forensic Terminal\n"
                "======================\n\n"
                "Error: Could not load forensic terminal module.\n"
                "Check that src/ui/widgets/forensic_terminal.py exists.\n"
            )
            layout.addWidget(self.terminal)
    
    def execute_command(self, command: str):
        """Execute a command programmatically."""
        if FORENSIC_TERMINAL_AVAILABLE:
            self.terminal.execute(command)
    
    def execute_command_direct(self, command: str):
        """Alias for execute_command (compatibility)."""
        self.execute_command(command)
    
    def load_case(self, case_name: str):
        """Load a case programmatically."""
        if FORENSIC_TERMINAL_AVAILABLE:
            self.terminal.load_case(case_name)
    
    def clear_output(self):
        """Clear the terminal."""
        if FORENSIC_TERMINAL_AVAILABLE:
            self.terminal.clear()
            self.terminal._print_prompt()
    
    def showEvent(self, event):
        """Auto-focus terminal when shown."""
        super().showEvent(event)
        if FORENSIC_TERMINAL_AVAILABLE:
            self.terminal.setFocus()
    
    def focusInEvent(self, event):
        """Focus the terminal when widget receives focus."""
        super().focusInEvent(event)
        if FORENSIC_TERMINAL_AVAILABLE:
            self.terminal.setFocus()


# Example integration into main FEPD UI:
"""
from ui.fepd_terminal_widget import FEPDTerminalWidget

class FEPDMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # ... existing code ...
        
        # Add FEPD Terminal tab
        self.terminal_widget = FEPDTerminalWidget(workspace_root='.')
        self.tabs.addTab(self.terminal_widget, "🖥 FEPD Terminal")
"""
