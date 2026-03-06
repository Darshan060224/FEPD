"""
FEPD Terminal Widget (Professional UI)
========================================

PyQt6-based terminal widget that provides:
  - Shell-like text input with prompt
  - Command history navigation (↑/↓)
  - Tab autocomplete
  - Color-coded output (errors=red, dirs=blue, warnings=yellow)
  - Read-only output area (users can only type at the prompt line)
  - Copy/paste support
  - Export session to file

This widget delegates all command execution to the TerminalEngine.
It is purely a UI — zero business logic.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import logging
from datetime import datetime
from typing import Optional, List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPlainTextEdit, QLabel,
    QHBoxLayout, QCompleter,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QStringListModel
from PyQt6.QtGui import (
    QFont, QTextCursor, QColor, QTextCharFormat,
    QKeyEvent, QMouseEvent, QPalette, QTextOption,
)

from ..core.terminal_engine import TerminalEngine

logger = logging.getLogger(__name__)


# ============================================================================
# Color scheme (Windows Terminal-inspired)
# ============================================================================
COLORS = {
    "background":   "#0c0c0c",
    "text":         "#cccccc",
    "prompt":       "#6ec6ff",
    "error":        "#f44747",
    "warning":      "#cca700",
    "success":      "#89d185",
    "info":         "#4fc1ff",
    "directory":    "#569cd6",
    "executable":   "#ce9178",
    "blocked":      "#d16969",
    "selection_bg": "#264f78",
}

FONT_FAMILY = "Consolas"
FONT_SIZE = 11


class TerminalWidget(QWidget):
    """
    Professional forensic terminal UI widget.

    Signals:
        path_changed(str):       Emitted when CWD changes (for tab sync).
        command_executed(str, str): Emitted after command execution (cmd, output).
        write_blocked(str):      Emitted when a write command is blocked.
    """

    path_changed = pyqtSignal(str)
    command_executed = pyqtSignal(str, str)
    write_blocked = pyqtSignal(str)

    def __init__(
        self,
        engine: Optional[TerminalEngine] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._engine = engine
        self._current_input = ""
        self._autocomplete_active = False
        self._init_ui()

        if self._engine:
            self._print_banner()
            self._print_prompt()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _init_ui(self) -> None:
        """Build the terminal UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header bar
        header = QLabel("  FEPD Forensic Terminal")
        header.setFixedHeight(28)
        header.setStyleSheet(f"""
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                stop:0 #1a2634, stop:1 #0d1520);
            color: {COLORS['info']};
            font-weight: bold;
            font-size: 12px;
            padding-left: 8px;
            border-bottom: 1px solid #0d47a1;
        """)
        layout.addWidget(header)

        # Terminal text area
        self._terminal = QPlainTextEdit()
        self._terminal.setReadOnly(False)
        self._terminal.setFont(QFont(FONT_FAMILY, FONT_SIZE))
        self._terminal.setWordWrapMode(QTextOption.WrapMode.NoWrap)
        self._terminal.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {COLORS['background']};
                color: {COLORS['text']};
                border: none;
                padding: 8px;
                selection-background-color: {COLORS['selection_bg']};
            }}
        """)
        self._terminal.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self._terminal.installEventFilter(self)

        # Track prompt position
        self._prompt_start = 0

        layout.addWidget(self._terminal)

    # ------------------------------------------------------------------
    # Event filter (captures key presses)
    # ------------------------------------------------------------------

    def eventFilter(self, obj, event) -> bool:
        """Intercept key events for the terminal."""
        if obj is not self._terminal:
            return super().eventFilter(obj, event)

        if event.type() != event.Type.KeyPress:
            return super().eventFilter(obj, event)

        key_event: QKeyEvent = event
        key = key_event.key()
        modifiers = key_event.modifiers()

        # Prevent editing before the prompt
        cursor = self._terminal.textCursor()
        if cursor.position() < self._prompt_start:
            # Allow copy (Ctrl+C without selection is ignored)
            if modifiers == Qt.KeyboardModifier.ControlModifier and key == Qt.Key.Key_C:
                if cursor.hasSelection():
                    return super().eventFilter(obj, event)
            # Move cursor to end of document
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self._terminal.setTextCursor(cursor)

        # ── Enter: execute command ──
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._execute_current_line()
            return True

        # ── Up arrow: history ──
        if key == Qt.Key.Key_Up:
            self._navigate_history(-1)
            return True

        # ── Down arrow: history ──
        if key == Qt.Key.Key_Down:
            self._navigate_history(1)
            return True

        # ── Tab: autocomplete ──
        if key == Qt.Key.Key_Tab:
            self._handle_tab()
            return True

        # ── Ctrl+C: cancel current input ──
        if modifiers == Qt.KeyboardModifier.ControlModifier and key == Qt.Key.Key_C:
            if not cursor.hasSelection():
                self._cancel_input()
                return True

        # ── Ctrl+L: clear ──
        if modifiers == Qt.KeyboardModifier.ControlModifier and key == Qt.Key.Key_L:
            self._clear_terminal()
            return True

        # ── Backspace: don't delete past prompt ──
        if key == Qt.Key.Key_Backspace:
            if cursor.position() <= self._prompt_start:
                return True

        # ── Home: jump to start of input (not prompt) ──
        if key == Qt.Key.Key_Home:
            cursor.setPosition(self._prompt_start)
            self._terminal.setTextCursor(cursor)
            return True

        return super().eventFilter(obj, event)

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def _execute_current_line(self) -> None:
        """Extract the current input line and execute it."""
        # Get text after the prompt
        full_text = self._terminal.toPlainText()
        command = full_text[self._prompt_start:].strip()

        # Add newline after user input
        self._append_text("\n")

        if not command:
            self._print_prompt()
            return

        if not self._engine:
            self._append_colored("[No terminal engine attached]\n", COLORS["error"])
            self._print_prompt()
            return

        # Execute through the engine pipeline
        output = self._engine.execute(command)

        # Handle special outputs
        if output == "__CLEAR__":
            self._clear_terminal()
            return
        if output == "__EXIT__":
            self._append_colored("Terminal session ended.\n", COLORS["warning"])
            self._print_prompt()
            return

        # Render output with color coding
        if output:
            self._render_output(output, command)

        # Emit signals
        self.command_executed.emit(command, output or "")

        # Check if path changed
        if command.startswith("cd "):
            self.path_changed.emit(self._engine.session.path)

        # Print next prompt
        self._print_prompt()

    def _render_output(self, output: str, command: str) -> None:
        """Render command output with appropriate coloring."""
        if not output:
            return

        if output.startswith("[DENIED]") or output.startswith("\n[DENIED]"):
            self._append_colored(output + "\n", COLORS["blocked"])
            self.write_blocked.emit(command)
        elif output.startswith("[ERROR]"):
            self._append_colored(output + "\n", COLORS["error"])
        elif output.startswith("[WARNING]"):
            self._append_colored(output + "\n", COLORS["warning"])
        else:
            self._append_text(output + "\n")

    # ------------------------------------------------------------------
    # History navigation
    # ------------------------------------------------------------------

    def _navigate_history(self, direction: int) -> None:
        """Navigate command history (direction: -1=up, +1=down)."""
        if not self._engine:
            return

        if direction < 0:
            cmd = self._engine.session.history_up()
        else:
            cmd = self._engine.session.history_down()

        if cmd is not None:
            self._replace_input(cmd)

    def _replace_input(self, text: str) -> None:
        """Replace the current input line with new text."""
        cursor = self._terminal.textCursor()
        cursor.setPosition(self._prompt_start)
        cursor.movePosition(QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()
        cursor.insertText(text)
        self._terminal.setTextCursor(cursor)

    # ------------------------------------------------------------------
    # Autocomplete
    # ------------------------------------------------------------------

    def _handle_tab(self) -> None:
        """Handle Tab key for autocomplete."""
        if not self._engine:
            return

        # Get current partial input
        full_text = self._terminal.toPlainText()
        partial = full_text[self._prompt_start:]

        suggestions = self._engine.autocomplete(partial)

        if not suggestions:
            return

        if len(suggestions) == 1:
            # Single match — complete it
            parts = partial.strip().split()
            if len(parts) <= 1:
                # Completing command name
                self._replace_input(suggestions[0] + " ")
            else:
                # Completing argument
                prefix = " ".join(parts[:-1])
                self._replace_input(f"{prefix} {suggestions[0]}")
        else:
            # Multiple matches — show options
            self._append_text("\n")
            self._append_colored("  ".join(suggestions[:20]) + "\n", COLORS["info"])
            self._print_prompt()
            self._replace_input(partial)  # Restore what they typed

    # ------------------------------------------------------------------
    # Text output helpers
    # ------------------------------------------------------------------

    def _append_text(self, text: str) -> None:
        """Append plain text to the terminal."""
        cursor = self._terminal.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        self._terminal.setTextCursor(cursor)
        self._terminal.ensureCursorVisible()

    def _append_colored(self, text: str, color: str) -> None:
        """Append colored text to the terminal."""
        cursor = self._terminal.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(text)
        # Reset format
        fmt.setForeground(QColor(COLORS["text"]))
        cursor.setCharFormat(fmt)
        self._terminal.setTextCursor(cursor)
        self._terminal.ensureCursorVisible()

    def _print_prompt(self) -> None:
        """Print the shell prompt and mark the input start position."""
        prompt = self._engine.prompt() if self._engine else "fepd:global$ "
        self._append_colored(prompt, COLORS["prompt"])
        self._prompt_start = len(self._terminal.toPlainText())

    def _print_banner(self) -> None:
        """Print the terminal welcome banner."""
        banner = (
            "╔══════════════════════════════════════════════════════════╗\n"
            "║           FEPD Forensic Terminal v2.0                   ║\n"
            "║                                                        ║\n"
            "║   Evidence is READ-ONLY. All commands are audited.      ║\n"
            "║   Type 'help' for available commands.                   ║\n"
            "║   Type 'cases' to list forensic cases.                  ║\n"
            "╚══════════════════════════════════════════════════════════╝\n"
            "\n"
        )
        self._append_colored(banner, COLORS["info"])

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _cancel_input(self) -> None:
        """Cancel current input (Ctrl+C without selection)."""
        self._append_text("^C\n")
        self._print_prompt()

    def _clear_terminal(self) -> None:
        """Clear all terminal content."""
        self._terminal.clear()
        self._prompt_start = 0
        self._print_banner()
        self._print_prompt()

    def set_engine(self, engine: TerminalEngine) -> None:
        """Attach a new TerminalEngine."""
        self._engine = engine
        self._terminal.clear()
        self._prompt_start = 0
        self._print_banner()
        self._print_prompt()

    def export_session(self, filepath: str) -> None:
        """Export the terminal session text to a file."""
        try:
            text = self._terminal.toPlainText()
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"# FEPD Terminal Session Export\n")
                f.write(f"# Exported: {datetime.utcnow().isoformat()}Z\n")
                f.write(f"# {'=' * 50}\n\n")
                f.write(text)
            logger.info("Session exported to %s", filepath)
        except Exception as e:
            logger.error("Failed to export session: %s", e)
