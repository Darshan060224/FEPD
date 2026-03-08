"""
FEPD Terminal - Virtual Evidence OS Shell
==========================================

A real forensic shell over the SQLite-backed VFS.  Every command
(ls, cd, pwd, cat, stat, hash, hexdump, strings, find, tree)
reads live data from the ``VirtualFilesystem`` database.

Features:
  - Evidence-native prompt with current working directory
  - Full directory listing with file-type icons
  - ``ls -l`` detailed + ``ls -a`` hidden files
  - ``cd`` navigation with ``.``, ``..``, ``/``, ``~``
  - File inspection: cat, stat, hash, hexdump, strings
  - find / tree with depth limit
  - Pagination for large directories (``ls | more``)
  - Read-only enforcement — write commands blocked
  - Command history (↑ / ↓)
  - Tab autocomplete
  - Chain of Custody logging for every command
  - Bidirectional sync with Files Tab

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Tuple

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPlainTextEdit, QLabel, QCompleter
from PyQt6.QtCore import Qt, pyqtSignal, QStringListModel
from PyQt6.QtGui import QFont, QTextCursor, QColor, QTextCharFormat, QTextOption

import sys
sys.path.insert(0, str(__file__).replace("\\", "/").rsplit("/src/", 1)[0])
from src.core.virtual_fs import VirtualFilesystem, VFSNode, VFSNodeType

logger = logging.getLogger(__name__)

# ── colour palette ──────────────────────────────────────────────────────────
COLORS: Dict[str, str] = {
    "bg":           "#0c0c0c",
    "text":         "#cccccc",
    "prompt_user":  "#89d185",
    "prompt_path":  "#569cd6",
    "prompt_char":  "#d4d4d4",
    "error":        "#f44747",
    "warning":      "#cca700",
    "success":      "#89d185",
    "info":         "#4fc1ff",
    "dir":          "#569cd6",
    "exe":          "#ce9178",
    "deleted":      "#d16969",
    "blocked":      "#f44747",
}

# ── file-type icon map ──────────────────────────────────────────────────────
_EXT_ICON: Dict[str, str] = {
    # images
    ".jpg": "🖼", ".jpeg": "🖼", ".png": "🖼", ".gif": "🖼",
    ".bmp": "🖼", ".ico": "🖼", ".svg": "🖼", ".webp": "🖼",
    # documents
    ".pdf": "📄", ".doc": "📄", ".docx": "📄", ".xls": "📄",
    ".xlsx": "📄", ".ppt": "📄", ".pptx": "📄", ".odt": "📄",
    ".txt": "📝", ".log": "📝", ".csv": "📝", ".rtf": "📝",
    # executables / scripts
    ".exe": "⚙", ".dll": "⚙", ".sys": "⚙", ".msi": "⚙",
    ".bat": "⚙", ".cmd": "⚙", ".ps1": "⚙", ".vbs": "⚙",
    ".js": "⚙", ".py": "⚙", ".sh": "⚙", ".hta": "⚙",
    # archives
    ".zip": "📦", ".rar": "📦", ".7z": "📦", ".tar": "📦",
    ".gz": "📦", ".cab": "📦", ".iso": "📦",
    # audio / video
    ".mp3": "🎵", ".wav": "🎵", ".flac": "🎵", ".ogg": "🎵",
    ".mp4": "🎬", ".avi": "🎬", ".mkv": "🎬", ".mov": "🎬",
    # databases / email
    ".db": "🗃", ".sqlite": "🗃", ".mdb": "🗃", ".pst": "📧",
    ".ost": "📧", ".eml": "📧", ".msg": "📧",
}

def _icon_for(node: VFSNode) -> str:
    """Return a display icon for the VFS node."""
    if node.is_directory:
        return "📁"
    if node.is_deleted:
        return "🗑"
    ext = os.path.splitext(node.name)[1].lower()
    return _EXT_ICON.get(ext, "📄")

# ── read-only guard ─────────────────────────────────────────────────────────
_BLOCKED_COMMANDS = frozenset({
    "rm", "del", "delete", "remove", "rmdir",
    "mv", "move", "rename", "ren",
    "cp", "copy", "xcopy", "robocopy",
    "touch", "mkdir", "md",
    "echo", "write",
    "nano", "vim", "vi", "notepad", "edit",
    "chmod", "chown", "chattr",
    "format", "fdisk", "mkfs",
})

_BLOCK_MSG = (
    "\n\x1b[31m[DENIED] Evidence is immutable.\x1b[0m\n"
    "FEPD Terminal operates in read-only forensic mode.\n"
    "All write operations are blocked to preserve evidence integrity.\n"
)

# ── pagination ──────────────────────────────────────────────────────────────
PAGE_SIZE = 80  # entries before pagination kicks in


# ============================================================================
# Main Widget
# ============================================================================

class FEPDTerminalWidget(QWidget):
    """
    FEPD forensic terminal — a real shell over the VFS evidence database.
    """

    # signals
    path_changed = pyqtSignal(str)        # cwd changed (for Files-tab sync)
    command_executed = pyqtSignal(str, str)  # (cmd, output)
    write_blocked = pyqtSignal(str)       # blocked command logged

    def __init__(
        self,
        vfs: Optional[VirtualFilesystem] = None,
        chain_logger: Any = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.vfs: Optional[VirtualFilesystem] = vfs
        self.chain_logger = chain_logger
        self._cwd: str = "/"              # current working directory (VFS path)
        self._home: str = "/"             # user home shortcut (~)
        self._user: str = os.getenv("USERNAME", "investigator")
        self._history: List[str] = []
        self._hist_idx: int = 0
        self._page_buf: Optional[List[str]] = None  # leftover lines for "more"
        self._read_file_func: Optional[Callable] = None
        self._init_ui()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _init_ui(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # header bar
        hdr = QLabel("  FEPD Forensic Terminal — Virtual Evidence OS")
        hdr.setFixedHeight(28)
        hdr.setStyleSheet(
            "background: qlineargradient(x1:0,y1:0,x2:0,y2:1,"
            "stop:0 #1a2634, stop:1 #0d1520);"
            f"color: {COLORS['info']}; font-weight: bold; font-size: 12px;"
            "padding-left: 8px; border-bottom: 1px solid #0d47a1;"
        )
        lay.addWidget(hdr)

        # terminal area
        self._term = QPlainTextEdit()
        self._term.setReadOnly(False)
        self._term.setFont(QFont("Consolas", 11))
        self._term.setWordWrapMode(QTextOption.WrapMode.NoWrap)
        self._term.setStyleSheet(
            f"QPlainTextEdit {{ background: {COLORS['bg']};"
            f" color: {COLORS['text']}; border: none; padding: 8px; }}"
            f"QPlainTextEdit:focus {{ border: none; }}"
        )
        self._term.keyPressEvent = self._on_key  # type: ignore[assignment]
        lay.addWidget(self._term)

        # autocomplete
        self._completer = QCompleter()
        self._completer.setWidget(self._term)
        self._completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._comp_model = QStringListModel()
        self._completer.setModel(self._comp_model)
        self._completer.activated.connect(self._insert_completion)  # type: ignore[attr-defined]

        self._print_banner()
        self._print_prompt()

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------

    def _write(self, text: str, color: str = COLORS["text"],
               bold: bool = False) -> None:
        cur = self._term.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        if bold:
            fmt.setFontWeight(QFont.Weight.Bold)
        cur.insertText(text, fmt)
        self._term.setTextCursor(cur)

    def _writeln(self, text: str = "", color: str = COLORS["text"],
                 bold: bool = False) -> None:
        self._write(text + "\n", color, bold)

    def _print_banner(self) -> None:
        self._writeln(
            "╔═══════════════════════════════════════════════════════════════╗",
            COLORS["info"],
        )
        self._writeln(
            "║          FEPD FORENSIC TERMINAL — VEOS Shell v3.0           ║",
            COLORS["info"],
        )
        self._writeln(
            "╚═══════════════════════════════════════════════════════════════╝",
            COLORS["info"],
        )
        self._writeln()
        self._writeln("🔒 Read-only forensic mode  •  All commands logged to CoC",
                      COLORS["prompt_user"])
        self._writeln("Type 'help' for available commands.\n", COLORS["text"])

    def _prompt_str(self) -> str:
        """Build the visible prompt string."""
        display = self._cwd
        if self._home != "/" and self._cwd.startswith(self._home):
            display = "~" + self._cwd[len(self._home):]
        return f"fepd:{display}$ "

    def _print_prompt(self) -> None:
        p = self._prompt_str()
        self._write(p, COLORS["prompt_path"], bold=True)
        self._term.moveCursor(QTextCursor.MoveOperation.End)

    # ------------------------------------------------------------------
    # Key handling
    # ------------------------------------------------------------------

    def _on_key(self, ev: Any) -> None:
        key = ev.key()

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._execute_line()
            ev.accept()
            return

        if key == Qt.Key.Key_Up:
            self._history_nav(-1)
            ev.accept()
            return
        if key == Qt.Key.Key_Down:
            self._history_nav(+1)
            ev.accept()
            return

        if key == Qt.Key.Key_Tab:
            self._tab_complete()
            ev.accept()
            return

        # prevent editing above prompt
        cur = self._term.textCursor()
        doc = self._term.document()
        if cur.blockNumber() < doc.blockCount() - 1:
            cur.movePosition(QTextCursor.MoveOperation.End)
            self._term.setTextCursor(cur)

        if key == Qt.Key.Key_Backspace:
            # don't delete past the prompt
            line = cur.block().text()
            prompt = self._prompt_str()
            if len(line) <= len(prompt):
                ev.accept()
                return

        if key == Qt.Key.Key_Home:
            # move to after prompt, not start of line
            line = cur.block().text()
            prompt = self._prompt_str()
            pos = cur.block().position() + len(prompt)
            cur.setPosition(pos)
            self._term.setTextCursor(cur)
            ev.accept()
            return

        QPlainTextEdit.keyPressEvent(self._term, ev)

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def _current_input(self) -> str:
        line = self._term.textCursor().block().text()
        prompt = self._prompt_str()
        if line.startswith(prompt):
            return line[len(prompt):]
        if "$" in line:
            return line.split("$", 1)[1].strip()
        return line.strip()

    def _execute_line(self) -> None:
        cmd = self._current_input().strip()
        self._writeln()  # newline after command

        if not cmd:
            self._print_prompt()
            return

        # pagination continuation
        if self._page_buf and cmd.lower() in ("", "q", "more"):
            if cmd.lower() == "q":
                self._page_buf = None
                self._print_prompt()
                return
            self._show_page()
            return

        self._history.append(cmd)
        self._hist_idx = len(self._history)

        # CoC logging
        if self.chain_logger:
            try:
                self.chain_logger.log(
                    action="TERMINAL_COMMAND",
                    operator=self._user,
                    details={"command": cmd, "cwd": self._cwd},
                )
            except Exception:
                pass

        output, color = self._dispatch(cmd)
        if output:
            self._writeln(output, color)

        self.command_executed.emit(cmd, output)
        self._print_prompt()

    def _dispatch(self, raw: str) -> Tuple[str, str]:
        """Parse and route a command.  Returns (output, colour)."""
        parts = raw.split()
        cmd = parts[0].lower()
        args = parts[1:]

        # check write guard
        if cmd in _BLOCKED_COMMANDS:
            self.write_blocked.emit(raw)
            return _BLOCK_MSG, COLORS["blocked"]

        # redirect / pipe shorthand
        if ">" in raw:
            return ("[DENIED] Output redirection is blocked in forensic mode.",
                    COLORS["blocked"])

        router: Dict[str, Callable[..., str]] = {
            "help":     lambda a: self._cmd_help(),
            "clear":    lambda a: self._cmd_clear(),
            "cls":      lambda a: self._cmd_clear(),
            "pwd":      lambda a: self._cmd_pwd(),
            "cd":       self._cmd_cd,
            "ls":       self._cmd_ls,
            "dir":      self._cmd_ls,
            "stat":     self._cmd_stat,
            "cat":      self._cmd_cat,
            "hash":     self._cmd_hash,
            "hexdump":  self._cmd_hexdump,
            "strings":  self._cmd_strings,
            "find":     self._cmd_find,
            "tree":     self._cmd_tree,
            "whoami":   lambda a: self._cmd_whoami(),
        }

        handler = router.get(cmd)
        if handler is None:
            return (f"Unknown command: {cmd}\nType 'help' for available commands.",
                    COLORS["error"])

        try:
            out = handler(args)
            return out, COLORS["text"]
        except Exception as exc:
            logger.exception("Terminal command failed: %s", raw)
            return f"Error: {exc}", COLORS["error"]

    # ------------------------------------------------------------------
    # History navigation
    # ------------------------------------------------------------------

    def _history_nav(self, delta: int) -> None:
        if not self._history:
            return
        self._hist_idx = max(0, min(len(self._history), self._hist_idx + delta))
        text = self._history[self._hist_idx] if self._hist_idx < len(self._history) else ""
        self._replace_input(text)

    def _replace_input(self, text: str) -> None:
        cur = self._term.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        cur.movePosition(QTextCursor.MoveOperation.StartOfBlock,
                         QTextCursor.MoveMode.KeepAnchor)
        prompt = self._prompt_str()
        cur.insertText(prompt + text)
        self._term.setTextCursor(cur)

    # ------------------------------------------------------------------
    # Tab autocomplete
    # ------------------------------------------------------------------

    def _tab_complete(self) -> None:
        inp = self._current_input()
        parts = inp.rsplit(" ", 1)
        prefix = parts[-1] if parts else ""
        if not prefix:
            return

        children = self._ls_children(self._cwd)
        matches = [n.name for n in children if n.name.lower().startswith(prefix.lower())]
        if len(matches) == 1:
            completed = matches[0]
            # append slash for dirs
            node = next((n for n in children if n.name == completed), None)
            if node and node.is_directory:
                completed += "/"
            new_input = (parts[0] + " " + completed) if len(parts) == 2 else completed
            self._replace_input(new_input)
        elif matches:
            self._writeln()
            self._writeln("  ".join(sorted(matches)), COLORS["info"])
            self._print_prompt()
            self._write(inp)  # restore what user had

    def _insert_completion(self, completion: str) -> None:
        """Insert the selected completion from QCompleter into the input."""
        inp = self._current_input()
        parts = inp.rsplit(" ", 1)
        new_input = (parts[0] + " " + completion) if len(parts) == 2 else completion
        self._replace_input(new_input)

    # ------------------------------------------------------------------
    # VFS helpers
    # ------------------------------------------------------------------

    def _ls_children(self, parent: str) -> List[VFSNode]:
        if not self.vfs:
            return []
        return self.vfs.get_children(parent)

    def _resolve(self, target: str) -> str:
        """Resolve a relative or special path against cwd."""
        if not target:
            return self._cwd

        # ~ expansion
        if target.startswith("~"):
            target = self._home + target[1:]

        if target.startswith("/"):
            # absolute
            resolved = str(PurePosixPath(target))
        else:
            resolved = str(PurePosixPath(self._cwd) / target)

        # normalise (resolve ..)
        resolved = str(PurePosixPath(resolved))
        # ensure leading /
        if not resolved.startswith("/"):
            resolved = "/" + resolved
        # strip trailing / unless root
        if resolved != "/" and resolved.endswith("/"):
            resolved = resolved.rstrip("/")
        return resolved

    def _node_at(self, path: str) -> Optional[VFSNode]:
        if not self.vfs:
            return None
        return self.vfs.get_node(path)

    def _node_exists(self, path: str) -> bool:
        return self._node_at(path) is not None

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------

    def _paginate(self, lines: List[str]) -> str:
        """Return first page and buffer the rest."""
        if len(lines) <= PAGE_SIZE:
            return "\n".join(lines)
        self._page_buf = lines[PAGE_SIZE:]
        footer = f"\n-- {len(self._page_buf)} more lines (press ENTER for next page, 'q' to stop) --"
        return "\n".join(lines[:PAGE_SIZE]) + footer

    def _show_page(self) -> None:
        if not self._page_buf:
            self._print_prompt()
            return
        chunk = self._page_buf[:PAGE_SIZE]
        self._page_buf = self._page_buf[PAGE_SIZE:] or None
        self._writeln("\n".join(chunk))
        if self._page_buf:
            self._writeln(
                f"-- {len(self._page_buf)} more lines (ENTER=next, q=stop) --",
                COLORS["warning"],
            )
        else:
            self._print_prompt()

    # ==================================================================
    # COMMANDS
    # ==================================================================

    # ── help ─────────────────────────────────────────────────────────

    def _cmd_help(self) -> str:
        return (
            "\n"
            "╔══════════════════════════════════════════════════════════╗\n"
            "║              FEPD Terminal — Command Reference          ║\n"
            "╠══════════════════════════════════════════════════════════╣\n"
            "║                                                        ║\n"
            "║  Navigation                                            ║\n"
            "║    ls  [path] [-l] [-a]   List directory contents      ║\n"
            "║    cd  <path>             Change directory              ║\n"
            "║    pwd                    Print working directory       ║\n"
            "║    tree [path] [-d N]     Show directory tree           ║\n"
            "║                                                        ║\n"
            "║  File Inspection                                       ║\n"
            "║    cat    <file>          Display text file content     ║\n"
            "║    stat   <file>          File metadata / timestamps   ║\n"
            "║    hash   <file>          SHA-256 + MD5 hash           ║\n"
            "║    hexdump <file>         Hex dump (first 256 bytes)   ║\n"
            "║    strings <file>         Extract printable strings    ║\n"
            "║                                                        ║\n"
            "║  Search                                                ║\n"
            "║    find <pattern>         Search files by name         ║\n"
            "║                                                        ║\n"
            "║  System                                                ║\n"
            "║    whoami                 Show investigator context    ║\n"
            "║    clear / cls            Clear terminal               ║\n"
            "║    help                   This help message            ║\n"
            "║                                                        ║\n"
            "║  🔒 Write commands (rm, mv, cp, touch …) are BLOCKED  ║\n"
            "║  ↑ / ↓  Command history   |   TAB  Autocomplete       ║\n"
            "╚══════════════════════════════════════════════════════════╝\n"
        )

    # ── clear ────────────────────────────────────────────────────────

    def _cmd_clear(self) -> str:
        self._term.clear()
        self._print_banner()
        return ""

    # ── pwd ──────────────────────────────────────────────────────────

    def _cmd_pwd(self) -> str:
        return self._cwd

    # ── whoami ───────────────────────────────────────────────────────

    def _cmd_whoami(self) -> str:
        return (
            f"User:      {self._user}\n"
            f"Directory: {self._cwd}\n"
            f"Home:      {self._home}\n"
            f"Mode:      Read-only forensic shell\n"
        )

    # ── cd ───────────────────────────────────────────────────────────

    def _cmd_cd(self, args: List[str]) -> str:
        if not self.vfs:
            return "[No evidence loaded — load an image first]"

        if not args:
            return self._cwd

        target = self._resolve(args[0])

        # root is always valid
        if target == "/":
            self._cwd = "/"
            self.path_changed.emit(self._cwd)
            return ""

        node = self._node_at(target)
        if node is None:
            return f"cd: no such directory: {args[0]}"
        if not node.is_directory:
            return f"cd: not a directory: {args[0]}"

        self._cwd = target
        self.path_changed.emit(self._cwd)
        return ""

    # ── ls ───────────────────────────────────────────────────────────

    def _cmd_ls(self, args: List[str]) -> str:
        if not self.vfs:
            return "[No evidence loaded — load an image first]"

        # parse flags
        flags = {a for a in args if a.startswith("-")}
        positional = [a for a in args if not a.startswith("-")]
        long_fmt = bool(flags & {"-l", "--long"})
        show_all = bool(flags & {"-a", "--all"})

        target = self._resolve(positional[0]) if positional else self._cwd
        children = self._ls_children(target)

        if not children:
            # check if path even exists
            if not self._node_exists(target):
                return f"ls: cannot access '{positional[0] if positional else self._cwd}': No such directory"
            return "(empty directory)"

        # filter hidden (files starting with .)
        if not show_all:
            children = [c for c in children if not c.name.startswith(".")]

        # sort: directories first, then alphabetically
        children.sort(key=lambda n: (0 if n.is_directory else 1, n.name.lower()))

        lines: List[str] = []
        if long_fmt:
            lines.append(f"{'Type':<6} {'Size':>10}  {'Modified':<20} {'Name'}")
            lines.append(f"{'─'*5}  {'─'*10}  {'─'*19}  {'─'*30}")
            for n in children:
                typ = "DIR" if n.is_directory else "FILE"
                if n.is_deleted:
                    typ = "DEL"
                sz = self._human_size(n.size) if not n.is_directory else ""
                mod = n.modified.strftime("%Y-%m-%d %H:%M:%S") if n.modified else ""
                icon = _icon_for(n)
                # colour name
                name_str = f"{icon} {n.name}"
                lines.append(f"{typ:<6} {sz:>10}  {mod:<20} {name_str}")
            lines.append(f"\n  {len(children)} item(s)")
        else:
            for n in children:
                icon = _icon_for(n)
                lines.append(f"{icon} {n.name}")

        return self._paginate(lines)

    # ── stat ─────────────────────────────────────────────────────────

    def _cmd_stat(self, args: List[str]) -> str:
        if not args:
            return "Usage: stat <file>"
        if not self.vfs:
            return "[No evidence loaded]"

        path = self._resolve(args[0])
        node = self._node_at(path)
        if node is None:
            return f"stat: cannot stat '{args[0]}': No such file or directory"

        lines = [
            f"  Name:       {node.name}",
            f"  Path:       {node.path}",
            f"  Type:       {node.node_type.value}",
            f"  Size:       {self._human_size(node.size)}  ({node.size:,} bytes)",
            f"  Created:    {node.created or '—'}",
            f"  Modified:   {node.modified or '—'}",
            f"  Accessed:   {node.accessed or '—'}",
            f"  SHA-256:    {node.sha256 or '—'}",
            f"  MD5:        {node.md5 or '—'}",
            f"  MIME:       {node.mime_type or '—'}",
            f"  Deleted:    {'Yes' if node.is_deleted else 'No'}",
            f"  iNode:      {node.inode or '—'}",
            f"  Evidence:   {node.evidence_id or '—'}",
            f"  Partition:  {node.partition_info or '—'}",
        ]
        return "\n".join(lines)

    # ── cat ──────────────────────────────────────────────────────────

    def _cmd_cat(self, args: List[str]) -> str:
        if not args:
            return "Usage: cat <file>"
        if not self.vfs:
            return "[No evidence loaded]"

        path = self._resolve(args[0])
        node = self._node_at(path)
        if node is None:
            return f"cat: {args[0]}: No such file"
        if node.is_directory:
            return f"cat: {args[0]}: Is a directory"

        data = self._read_bytes(node)
        if data is None:
            return f"cat: {args[0]}: Cannot read file content (binary reading not available)"

        # limit to first 8 KB of text
        try:
            text = data[:8192].decode("utf-8", errors="replace")
        except Exception:
            text = data[:8192].decode("latin-1", errors="replace")

        if len(data) > 8192:
            text += f"\n\n… [{len(data) - 8192:,} more bytes truncated]"

        return text

    # ── hash ─────────────────────────────────────────────────────────

    def _cmd_hash(self, args: List[str]) -> str:
        if not args:
            return "Usage: hash <file>"
        if not self.vfs:
            return "[No evidence loaded]"

        path = self._resolve(args[0])
        node = self._node_at(path)
        if node is None:
            return f"hash: {args[0]}: No such file"
        if node.is_directory:
            return f"hash: {args[0]}: Is a directory"

        lines = [f"  File: {node.name}"]
        if node.sha256:
            lines.append(f"  SHA-256: {node.sha256}")
        if node.md5:
            lines.append(f"  MD5:     {node.md5}")

        # compute hashes from raw bytes if stored hashes absent
        if not node.sha256 and not node.md5:
            data = self._read_bytes(node)
            if data:
                lines.append(f"  SHA-256: {hashlib.sha256(data).hexdigest()}")
                lines.append(f"  MD5:     {hashlib.md5(data).hexdigest()}")
            else:
                lines.append("  (stored hashes unavailable; file bytes not accessible)")

        return "\n".join(lines)

    # ── hexdump ──────────────────────────────────────────────────────

    def _cmd_hexdump(self, args: List[str]) -> str:
        if not args:
            return "Usage: hexdump <file>"
        if not self.vfs:
            return "[No evidence loaded]"

        path = self._resolve(args[0])
        node = self._node_at(path)
        if node is None:
            return f"hexdump: {args[0]}: No such file"
        if node.is_directory:
            return f"hexdump: {args[0]}: Is a directory"

        data = self._read_bytes(node)
        if data is None:
            return f"hexdump: {args[0]}: Cannot read file content"

        chunk = data[:256]
        lines: List[str] = []
        for off in range(0, len(chunk), 16):
            row = chunk[off:off + 16]
            hexpart = " ".join(f"{b:02X}" for b in row)
            ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            lines.append(f"{off:08X}  {hexpart:<48}  {ascpart}")
        if len(data) > 256:
            lines.append(f"\n… [{len(data) - 256:,} more bytes not shown]")
        return "\n".join(lines)

    # ── strings ──────────────────────────────────────────────────────

    def _cmd_strings(self, args: List[str]) -> str:
        if not args:
            return "Usage: strings <file>"
        if not self.vfs:
            return "[No evidence loaded]"

        path = self._resolve(args[0])
        node = self._node_at(path)
        if node is None:
            return f"strings: {args[0]}: No such file"

        data = self._read_bytes(node)
        if data is None:
            return f"strings: {args[0]}: Cannot read file content"

        # extract printable ASCII strings (min length 4)
        result: List[str] = []
        current: List[str] = []
        for b in data[:65536]:  # limit scan to 64 KB
            if 32 <= b < 127:
                current.append(chr(b))
            else:
                if len(current) >= 4:
                    result.append("".join(current))
                current = []
        if len(current) >= 4:
            result.append("".join(current))

        if not result:
            return "(no printable strings found)"

        return self._paginate(result)

    # ── find ─────────────────────────────────────────────────────────

    def _cmd_find(self, args: List[str]) -> str:
        if not args:
            return "Usage: find <pattern>  (supports * and ? wildcards)"
        if not self.vfs:
            return "[No evidence loaded]"

        pattern = args[0]
        nodes = self.vfs.search(pattern, limit=500)
        if not nodes:
            return f"find: no matches for '{pattern}'"

        lines = [f"  {_icon_for(n)} {n.path}" for n in nodes]
        lines.append(f"\n  {len(nodes)} result(s)")
        return self._paginate(lines)

    # ── tree ─────────────────────────────────────────────────────────

    def _cmd_tree(self, args: List[str]) -> str:
        if not self.vfs:
            return "[No evidence loaded]"

        # parse -d <depth> flag
        max_depth = 3
        positional: List[str] = []
        i = 0
        while i < len(args):
            if args[i] == "-d" and i + 1 < len(args):
                try:
                    max_depth = int(args[i + 1])
                except ValueError:
                    pass
                i += 2
            else:
                positional.append(args[i])
                i += 1

        root = self._resolve(positional[0]) if positional else self._cwd
        root_node = self._node_at(root)
        if root_node is None:
            return f"tree: '{root}': not found"

        lines: List[str] = [f"  {root_node.name or root}"]
        self._tree_recurse(root, "", max_depth, 0, lines)

        dir_count = sum(1 for l in lines if "📁" in l)
        file_count = len(lines) - dir_count - 1  # minus header
        lines.append(f"\n  {dir_count} directories, {file_count} files")
        return self._paginate(lines)

    def _tree_recurse(self, path: str, prefix: str,
                      max_depth: int, depth: int,
                      lines: List[str]) -> None:
        if depth >= max_depth:
            return
        children = self._ls_children(path)
        children.sort(key=lambda n: (0 if n.is_directory else 1, n.name.lower()))
        for idx, child in enumerate(children):
            is_last = idx == len(children) - 1
            connector = "└── " if is_last else "├── "
            icon = _icon_for(child)
            lines.append(f"  {prefix}{connector}{icon} {child.name}")
            if child.is_directory:
                ext = "    " if is_last else "│   "
                self._tree_recurse(child.path, prefix + ext,
                                   max_depth, depth + 1, lines)

    # ------------------------------------------------------------------
    # File reading
    # ------------------------------------------------------------------

    def _read_bytes(self, node: VFSNode) -> Optional[bytes]:
        """Attempt to read file bytes via the read_file_func callback."""
        if self._read_file_func:
            try:
                return self._read_file_func(node.path, 0, -1)
            except Exception:
                pass
        # fallback: check physical_path in metadata
        phys = (node.metadata or {}).get("physical_path")
        if phys and os.path.isfile(phys):
            try:
                with open(phys, "rb") as f:
                    return f.read()
            except Exception:
                pass
        return None

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _human_size(size: float) -> str:
        if size <= 0:
            return "0 B"
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(size) < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    # ==================================================================
    # PUBLIC API  (called from main_window / Files tab)
    # ==================================================================

    def set_vfs(self, vfs: VirtualFilesystem) -> None:
        """Attach VFS database (usually after image ingestion)."""
        self.vfs = vfs
        self._writeln("\n[VFS attached — evidence filesystem ready]",
                      COLORS["success"])
        # auto-detect home
        self._detect_home()
        self._print_prompt()

    def set_read_file_func(self, fn: Callable) -> None:
        """Set the function used to read file bytes from the forensic image."""
        self._read_file_func = fn

    def set_chain_logger(self, chain_logger: Any) -> None:
        self.chain_logger = chain_logger

    def set_current_path(self, path: str) -> None:
        """Sync from Files Tab — navigate to the given VFS path."""
        if not path:
            return
        self._cwd = path
        self._writeln(f"\n[Synced from Files Tab → {path}]", COLORS["warning"])
        self._print_prompt()

    def set_user_context(self, user: str) -> None:
        self._user = user

    def load_case(self, case_name: str) -> None:
        self._cwd = "/"
        self._user = os.getenv("USERNAME", "investigator")
        self._writeln(f"\n[Case loaded: {case_name}]", COLORS["info"])
        self._print_prompt()

    # ------------------------------------------------------------------
    # Home detection
    # ------------------------------------------------------------------

    def _detect_home(self) -> None:
        """Try to find a user home folder and set it as ~."""
        if not self.vfs:
            return
        users = self.vfs.find_user_folders()
        if users:
            # pick first non-system user
            skip = {"default", "public", "all users", "default user"}
            for u in users:
                if u.name.lower() not in skip:
                    self._home = u.path
                    self._cwd = u.path
                    return
            self._home = users[0].path
            self._cwd = users[0].path
