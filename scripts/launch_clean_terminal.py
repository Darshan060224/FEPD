"""
Quick Start: Test the Clean FEPD Terminal in the GUI

This script launches the FEPD terminal tab to verify the clean experience.
"""

import sys
from PyQt6.QtWidgets import QApplication
from ui.fepd_terminal_widget import FEPDTerminalWidget

def main():
    app = QApplication(sys.argv)
    
    # Create standalone terminal widget
    terminal = FEPDTerminalWidget(workspace_root='.')
    terminal.setWindowTitle("FEPD OS Terminal - Clean Experience")
    terminal.resize(900, 600)
    terminal.show()
    
    print("✓ FEPD Terminal launched")
    print()
    print("Expected experience:")
    print("─" * 50)
    print("  • No welcome banner")
    print("  • Only the prompt: fepd:global[unknown]$ _")
    print("  • Try commands:")
    print("    - create_case test")
    print("    - use case test")
    print("    - use user analyst")
    print("    - ls")
    print("    - cat (to see minimal error)")
    print("─" * 50)
    
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
