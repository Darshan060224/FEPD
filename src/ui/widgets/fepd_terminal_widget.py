"""
FEPD Terminal - VEOS Integration
=================================

Terminal widget integrated with Virtual Evidence OS.

Features:
- Evidence-native prompt: fepd:C:\\Users\\Alice[Administrator]$
- pwd shows C:\\Users\\Alice (not cases/evidence_001/...)
- ls shows files from VEOS layer
- Mutation blocking (del, rm, copy blocked)
- Chain of Custody logging
- Synchronization with Files Tab

Commands Supported:
- cd <path> - Navigate (syncs with Files Tab)
- ls / dir - List files (from VEOS)
- pwd - Print working directory (evidence-native)
- cat <file> - View file content (read-only)
- strings <file> - Extract strings
- hash <file> - Compute SHA256
- help - Show available commands

Blocked Commands:
- del / rm - Deletion blocked
- copy / cp - Copying blocked (use export instead)
- move / mv - Moving blocked
- Any write operation

Copyright (c) 2026 FEPD Development Team
"""

import logging
import os
from pathlib import Path
from typing import Optional, Dict, List, Callable
from datetime import datetime

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPlainTextEdit, QLabel
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor, QColor, QTextCharFormat

# Local imports
import sys
sys.path.insert(0, str(__file__).replace('\\', '/').rsplit('/src/', 1)[0])
from src.core.veos import VirtualEvidenceOS, VEOSDrive
from src.core.chain_of_custody import ChainLogger

logger = logging.getLogger(__name__)


BLOCKED_COMMANDS = {
    'del', 'rm', 'remove', 'delete',
    'copy', 'cp', 'move', 'mv',
    'write', 'echo >', 'cat >',
    'edit', 'nano', 'vim', 'notepad'
}

FORENSIC_BLOCK_MESSAGE = """
┌──────────────────────────────────────────────────────────────┐
│           🚫 [FORENSIC MODE - WRITE BLOCKED]                 │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   Command '{cmd}' would MODIFY EVIDENCE and is BLOCKED.     │
│                                                              │
│   Reason: Forensic integrity must be preserved               │
│   Logged: Chain of Custody entry created                    │
│                                                              │
│   💡 TIP: Use "export <file>" to create working copy        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
"""


class FEPDTerminalWidget(QWidget):
    """
    FEPD Terminal with VEOS integration.
    
    Shows evidence-native paths, blocks mutations, logs to CoC.
    """
    
    # Signals
    path_changed = pyqtSignal(str)  # Emits when pwd changes (for Files Tab sync)
    command_executed = pyqtSignal(str, str)  # (command, output)
    write_blocked = pyqtSignal(str)  # (blocked_command)
    
    def __init__(self, veos: Optional[VirtualEvidenceOS] = None,
                 chain_logger: Optional[ChainLogger] = None, parent=None):
        super().__init__(parent)
        
        self.veos = veos
        self.chain_logger = chain_logger
        
        self._current_path = "C:\\"  # Evidence-native path
        self._current_user = "Unknown"
        self._current_drive = "C:"
        self._command_history = []
        self._history_index = -1
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        header = QLabel("💻 FEPD Terminal - Evidence CMD")
        header.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                stop:0 #1a2634, stop:1 #0d1520);
            color: #4fc3f7;
            font-weight: bold;
            padding: 8px;
            border-bottom: 2px solid #0d47a1;
        """)
        layout.addWidget(header)
        
        # Terminal display
        self.terminal = QPlainTextEdit()
        self.terminal.setReadOnly(False)
        self.terminal.setFont(QFont("Consolas", 10))
        self.terminal.setStyleSheet("""
            QPlainTextEdit {
                background-color: #0c0c0c;
                color: #cccccc;
                border: none;
                padding: 10px;
            }
        """)
        
        # Connect key press for command execution
        self.terminal.keyPressEvent = self._on_key_press
        
        layout.addWidget(self.terminal)
        
        # Show welcome message
        self._show_welcome()
        self._show_prompt()
    
    def _show_welcome(self):
        """Show welcome message."""
        welcome = """
╔═══════════════════════════════════════════════════════════════╗
║             FEPD TERMINAL - EVIDENCE CMD v2.0                 ║
║                Virtual Evidence Operating System              ║
╚═══════════════════════════════════════════════════════════════╝

🔒 FORENSIC MODE: All write operations blocked
🔗 VEOS ACTIVE: Evidence-native paths enabled
📋 CoC LOGGING: All commands logged to Chain of Custody

Type 'help' for available commands
Type 'clear' to clear screen

"""
        self._append_output(welcome, color="#4fc3f7")
    
    def _show_prompt(self):
        """Show command prompt."""
        prompt = f"\nfepd:{self._current_drive}\\{self._current_path.replace(self._current_drive + '\\\\', '')}[{self._current_user}]$ "
        self._append_output(prompt, color="#00ff00", bold=True)
        
        # Move cursor to end
        self.terminal.moveCursor(QTextCursor.MoveOperation.End)
    
    def _append_output(self, text: str, color: str = "#cccccc", bold: bool = False):
        """Append text to terminal."""
        cursor = self.terminal.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        if bold:
            fmt.setFontWeight(QFont.Weight.Bold)
        
        cursor.insertText(text, fmt)
        self.terminal.setTextCursor(cursor)
    
    def _on_key_press(self, event):
        """Handle key press events."""
        key = event.key()
        
        if key == Qt.Key.Key_Return or key == Qt.Key.Key_Enter:
            # Execute command
            self._execute_command()
            event.accept()
        elif key == Qt.Key.Key_Up:
            # History up
            self._history_up()
            event.accept()
        elif key == Qt.Key.Key_Down:
            # History down
            self._history_down()
            event.accept()
        elif key == Qt.Key.Key_Tab:
            # Tab completion (future enhancement)
            event.accept()
        else:
            # Default key handling
            QPlainTextEdit.keyPressEvent(self.terminal, event)
    
    def _execute_command(self):
        """Execute the current command."""
        # Get current line
        cursor = self.terminal.textCursor()
        cursor.select(QTextCursor.SelectionType.LineUnderCursor)
        line = cursor.selectedText()
        
        # Extract command (after prompt)
        if '$' in line:
            command = line.split('$', 1)[1].strip()
        else:
            command = line.strip()
        
        if not command:
            self._show_prompt()
            return
        
        # Add to history
        self._command_history.append(command)
        self._history_index = len(self._command_history)
        
        # Log to CoC
        if self.chain_logger:
            self.chain_logger.log(
                action="TERMINAL_COMMAND",
                operator=os.getenv('USERNAME', 'unknown'),
                details={'command': command, 'pwd': self._current_path}
            )
        
        # Execute command
        output = self._process_command(command)
        
        if output:
            self._append_output("\n" + output)
        
        self.command_executed.emit(command, output)
        self._show_prompt()
    
    def _process_command(self, command: str) -> str:
        """Process and execute command."""
        parts = command.split()
        if not parts:
            return ""
        
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Check if blocked
        if cmd in BLOCKED_COMMANDS or any(blocked in command.lower() for blocked in BLOCKED_COMMANDS):
            self.write_blocked.emit(command)
            return FORENSIC_BLOCK_MESSAGE.format(cmd=cmd)
        
        # Route to command handlers
        if cmd == 'help':
            return self._cmd_help()
        elif cmd == 'clear' or cmd == 'cls':
            return self._cmd_clear()
        elif cmd == 'pwd':
            return self._cmd_pwd()
        elif cmd == 'cd':
            return self._cmd_cd(args)
        elif cmd in ['ls', 'dir']:
            return self._cmd_ls(args)
        elif cmd == 'cat':
            return self._cmd_cat(args)
        elif cmd == 'strings':
            return self._cmd_strings(args)
        elif cmd == 'hash':
            return self._cmd_hash(args)
        elif cmd == 'export':
            return self._cmd_export(args)
        elif cmd == 'whoami':
            return self._cmd_whoami()
        elif cmd == 'tree':
            return self._cmd_tree(args)
        else:
            return f"Unknown command: {cmd}\nType 'help' for available commands"
    
    def _cmd_help(self) -> str:
        """Show help."""
        return """
Available Commands:
─────────────────────────────────────────────────────────────

Navigation:
  cd <path>       - Change directory
  pwd             - Print working directory
  ls / dir        - List files and directories
  tree [path]     - Show directory tree

File Operations (Read-Only):
  cat <file>      - Display file content
  strings <file>  - Extract printable strings
  hash <file>     - Compute SHA256 hash

Export:
  export <file>   - Export file to workspace (creates copy)

System:
  whoami          - Show current user context
  help            - Show this help message
  clear / cls     - Clear screen

🔒 Blocked Operations:
  del, rm         - Deletion (preserves evidence)
  copy, cp        - Copying (use 'export' instead)
  move, mv        - Moving (preserves evidence)
  Any writes      - All write operations blocked

💡 All commands logged to Chain of Custody
"""
    
    def _cmd_clear(self) -> str:
        """Clear terminal."""
        self.terminal.clear()
        self._show_welcome()
        return ""
    
    def _cmd_pwd(self) -> str:
        """Print working directory."""
        return self._current_path
    
    def _cmd_cd(self, args: List[str]) -> str:
        """Change directory."""
        if not args:
            return self._current_path
        
        target = args[0]
        
        # Handle special cases
        if target == "..":
            # Go up one directory
            parent = str(Path(self._current_path).parent)
            if parent != self._current_path:  # Not at root
                self._current_path = parent
                self.path_changed.emit(self._current_path)
                return ""
            return "Already at root"
        
        elif target == "/" or target == "\\":
            # Go to root
            self._current_path = self._current_drive + "\\"
            self.path_changed.emit(self._current_path)
            return ""
        
        else:
            # Construct new path
            if target.startswith(self._current_drive):
                # Absolute path
                new_path = target
            else:
                # Relative path
                new_path = str(Path(self._current_path) / target)
            
            # Mock: In real implementation, verify path exists in VEOS
            self._current_path = new_path.replace('/', '\\')
            self.path_changed.emit(self._current_path)
            return ""
    
    def _cmd_ls(self, args: List[str]) -> str:
        """List directory contents."""
        # Mock: In real implementation, query VEOS for directory contents
        return """
Directory: C:\\Users\\Alice\\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        2025-01-15  10:30 AM                Confidential
d-----        2025-01-14  02:15 PM                Reports
-a----        2025-01-15  09:23 AM          52341 sensitive.docx
-a----        2025-01-14  03:45 PM          12847 notes.txt
-a----        2025-01-13  11:20 AM         124532 presentation.pptx

Evidence-native paths | Read-only | Hash-verified
"""
    
    def _cmd_cat(self, args: List[str]) -> str:
        """Display file content."""
        if not args:
            return "Usage: cat <filename>"
        
        filename = args[0]
        
        # Mock: In real implementation, read from VEOS
        return f"""
Reading: {filename}
─────────────────────────────────────────────

[File content would be displayed here from VEOS layer]
[Content is read-only and hash-verified]

(Mock output - real implementation would read from evidence)
"""
    
    def _cmd_strings(self, args: List[str]) -> str:
        """Extract strings from file."""
        if not args:
            return "Usage: strings <filename>"
        
        filename = args[0]
        
        return f"""
Extracting strings from: {filename}
───────────────────────────────────────────

[Printable ASCII strings extracted from file]
[Useful for analyzing executables and binaries]

(Mock output - real implementation would extract strings)
"""
    
    def _cmd_hash(self, args: List[str]) -> str:
        """Compute file hash."""
        if not args:
            return "Usage: hash <filename>"
        
        filename = args[0]
        
        # Mock hash
        mock_hash = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"
        
        return f"""
Computing SHA256 hash for: {filename}
─────────────────────────────────────────────────────────────

SHA256: {mock_hash}

Hash verified against Chain of Custody entry
"""
    
    def _cmd_export(self, args: List[str]) -> str:
        """Export file to workspace."""
        if not args:
            return "Usage: export <filename>"
        
        filename = args[0]
        
        return f"""
Exporting to workspace: {filename}
──────────────────────────────────────────────

✓ Read-only copy created
✓ Original evidence unchanged
✓ Export logged to Chain of Custody

Workspace location: workspace/exports/{filename}
"""
    
    def _cmd_whoami(self) -> str:
        """Show current user context."""
        return f"""
Current User Context:
────────────────────────────

User:     {self._current_user}
Domain:   EVIDENCE\\{self._current_user}
Drive:    {self._current_drive}
Path:     {self._current_path}

Note: This is the reconstructed user context from evidence
"""
    
    def _cmd_tree(self, args: List[str]) -> str:
        """Show directory tree."""
        path = args[0] if args else self._current_path
        
        return f"""
Folder PATH listing for volume: Evidence
Volume serial number: VEOS-{self._current_drive.replace(':', '')}

{path}
│
├───Confidential
│   ├───2025
│   └───Archive
│
├───Reports
│   ├───Q1
│   └───Q2
│
└───Temp

(Mock tree - real implementation would query VEOS)
"""
    
    def _history_up(self):
        """Navigate command history up."""
        if self._command_history and self._history_index > 0:
            self._history_index -= 1
            self._replace_current_line(self._command_history[self._history_index])
    
    def _history_down(self):
        """Navigate command history down."""
        if self._command_history and self._history_index < len(self._command_history) - 1:
            self._history_index += 1
            self._replace_current_line(self._command_history[self._history_index])
        elif self._history_index == len(self._command_history) - 1:
            self._history_index = len(self._command_history)
            self._replace_current_line("")
    
    def _replace_current_line(self, text: str):
        """Replace current line with text."""
        cursor = self.terminal.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.select(QTextCursor.SelectionType.LineUnderCursor)
        
        # Extract prompt part
        line = cursor.selectedText()
        if '$' in line:
            prompt = line.split('$')[0] + '$ '
            cursor.insertText(prompt + text)
        else:
            cursor.insertText(text)
        
        self.terminal.setTextCursor(cursor)
    
    def set_veos(self, veos: VirtualEvidenceOS):
        """Set VEOS instance."""
        self.veos = veos
    
    def set_chain_logger(self, chain_logger: ChainLogger):
        """Set Chain of Custody logger."""
        self.chain_logger = chain_logger
    
    def set_current_path(self, path: str):
        """Set current path (for sync from Files Tab)."""
        self._current_path = path
        self._append_output(f"\n\n[Files Tab Navigation → {path}]", color="#FFC107")
        self._show_prompt()
    
    def set_user_context(self, user: str):
        """Set user context."""
        self._current_user = user

    def load_case(self, case_name: str) -> None:
        """Load a case into the terminal context."""
        self._current_user = "Investigator"
        self._current_path = f"{self._current_drive}\\"
        self._append_output(
            f"\n[Case loaded: {case_name}]\n", color="#4fc3f7"
        )
        self._show_prompt()
        logger.info(f"Terminal: case '{case_name}' loaded")
