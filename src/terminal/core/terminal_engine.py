"""
FEPD Terminal Engine
======================

Central orchestrator: wires Parser → Validator → Dispatcher → Commands.

This is the single entry point for all terminal command execution.
Every command flows through this pipeline:

    User Input
       ↓
    CommandParser.parse()
       ↓
    CommandValidator.validate()
       ↓
    CoCLogger.log_*()
       ↓
    CommandDispatcher.dispatch()
       ↓
    Command Module (ls, cd, cat, ...)
       ↓
    VEOS Filesystem
       ↓
    Output Renderer

The engine owns all subsystems and manages their lifecycle.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import sys
import logging
from typing import Optional, Dict, Any, List

# Core
from .command_parser import CommandParser, ParsedCommand
from .command_dispatcher import CommandDispatcher, CommandNotFoundError
from .session_manager import SessionManager

# Security
from ..security.read_only_guard import ReadOnlyGuard
from ..security.command_validator import CommandValidator

# Logging
from ..logging.coc_logger import CoCLogger

# Commands
from ..commands.ls import ls_command
from ..commands.cd import cd_command
from ..commands.pwd import pwd_command
from ..commands.cat import cat_command
from ..commands.tree import tree_command
from ..commands.hash import hash_command
from ..commands.hexdump import hexdump_command
from ..commands.strings import strings_command
from ..commands.find import find_command
from ..commands.grep import grep_command
from ..commands.timeline import timeline_command
from ..commands.score import score_command
from ..commands.explain import explain_command
from ..commands.artifacts import artifacts_command
from ..commands.connections import connections_command

# Intelligence
from ..intelligence.timeline_engine import TimelineEngine
from ..intelligence.artifact_correlator import ArtifactCorrelator
from ..intelligence.ml_explainer import MLExplainer

logger = logging.getLogger(__name__)


class TerminalEngine:
    """
    FEPD Forensic Terminal Engine — the central command pipeline.

    Usage:
        engine = TerminalEngine(workspace_root="C:/FEPD")
        output = engine.execute("ls")
        output = engine.execute("cd Users")
        output = engine.execute("cat notes.txt")
        prompt = engine.prompt()

    Architecture:
        Engine owns:  Parser, Validator, Dispatcher, Session, CoC Logger
        Engine uses:  VFS, ML Bridge, Timeline Engine, Artifact Correlator
    """

    def __init__(
        self,
        workspace_root: str,
        vfs: Any = None,
        ml_bridge: Any = None,
        case_path: Optional[str] = None,
        db_path: Optional[str] = None,
    ) -> None:
        self.workspace_root = workspace_root

        # ── Core subsystems ──
        self.parser = CommandParser()
        self.session = SessionManager(workspace_root)
        self.guard = ReadOnlyGuard()
        self.validator = CommandValidator(self.guard)
        self.dispatcher = CommandDispatcher()
        self.coc = CoCLogger(case_path=case_path, db_path=db_path)

        # ── External integrations ──
        self.vfs = vfs
        self.ml_bridge = ml_bridge

        # ── Intelligence engines ──
        self.timeline_engine = TimelineEngine(db_path=db_path, vfs=vfs)
        self.artifact_correlator = ArtifactCorrelator(vfs=vfs, db_path=db_path)
        self.ml_explainer = MLExplainer(ml_bridge=ml_bridge)

        # ── Register all commands ──
        self._register_commands()

        logger.info("TerminalEngine initialized (workspace: %s)", workspace_root)

    # ------------------------------------------------------------------
    # Command Registration
    # ------------------------------------------------------------------

    def _register_commands(self) -> None:
        """Register all built-in commands with the dispatcher."""
        d = self.dispatcher

        # Navigation
        d.register("ls",       ls_command,       aliases=["dir"],      help_text="List directory contents")
        d.register("cd",       cd_command,       aliases=["chdir"],    help_text="Change directory")
        d.register("pwd",      pwd_command,                            help_text="Print working directory")
        d.register("tree",     tree_command,                           help_text="Display directory tree")

        # File inspection
        d.register("cat",      cat_command,      aliases=["type", "more"], help_text="Display file contents")
        d.register("hash",     hash_command,     aliases=["certutil"],     help_text="Compute file hash (SHA256)")
        d.register("hexdump",  hexdump_command,  aliases=["xxd"],          help_text="Hex dump of file")
        d.register("strings",  strings_command,                            help_text="Extract printable strings")

        # Search
        d.register("find",     find_command,     aliases=["where"],   help_text="Search for files")
        d.register("grep",     grep_command,     aliases=["findstr"], help_text="Search file contents")
        d.register("timeline", timeline_command,                      help_text="Show file/directory timeline")

        # Intelligence
        d.register("score",    score_command,                         help_text="AI risk score for file")
        d.register("explain",  explain_command,                       help_text="ML explainability report")
        d.register("artifacts", artifacts_command,                    help_text="Find related forensic artifacts")
        d.register("connections", connections_command,                help_text="Show network connections")

        # Built-in terminal commands (handled internally)
        d.register("help",     self._cmd_help,                        help_text="Show available commands")
        d.register("clear",    self._cmd_clear,  aliases=["cls"],     help_text="Clear terminal screen")
        d.register("history",  self._cmd_history,                     help_text="Show command history")
        d.register("whoami",   self._cmd_whoami,                      help_text="Show current investigator")
        d.register("cases",    self._cmd_cases,                       help_text="List available cases")
        d.register("exit",     self._cmd_exit,   aliases=["quit"],    help_text="Exit terminal")
        d.register("who_used", self._cmd_who_used,                    help_text="Show who accessed a file")
        d.register("stat",     self._cmd_stat,                        help_text="Show detailed file metadata")

    # ------------------------------------------------------------------
    # Main Execution Pipeline
    # ------------------------------------------------------------------

    def execute(self, raw_input: str) -> str:
        """
        Execute a raw command string through the full pipeline.

        Pipeline:
            parse → validate → log → dispatch → format output

        Args:
            raw_input: The raw text the user typed.

        Returns:
            Command output string (may be empty).
        """
        # 1. Parse
        parsed = self.parser.parse(raw_input)
        if parsed.is_empty:
            return ""

        # 2. Validate (security check)
        validation = self.validator.validate(parsed, self.session)
        if not validation.is_valid:
            # Log the blocked attempt
            reason = ""
            if validation.blocked:
                reason = validation.blocked.reason
            self.coc.log_blocked(self.session, raw_input, reason=reason)
            self.session.add_history(raw_input, "[BLOCKED]")
            return validation.error_message

        # 3. Dispatch to command handler
        try:
            output = self.dispatcher.dispatch(
                parsed,
                session=self.session,
                vfs=self.vfs,
                ml_bridge=self.ml_bridge,
                db_path=self._get_db_path(),
                timeline_engine=self.timeline_engine,
                artifact_correlator=self.artifact_correlator,
                ml_explainer=self.ml_explainer,
            )
        except CommandNotFoundError as e:
            output = str(e)
            self.coc.log_error(self.session, raw_input, str(e))
            self.session.add_history(raw_input, "[NOT FOUND]")
            return output
        except Exception as e:
            output = f"[ERROR] {e}"
            self.coc.log_error(self.session, raw_input, str(e))
            self.session.add_history(raw_input, "[ERROR]")
            return output

        # 4. Log successful execution
        self.coc.log_command(self.session, raw_input, output=output)
        self.session.add_history(raw_input, output[:100] if output else "")

        # 5. Print warnings if any
        if validation.warnings:
            warning_text = "\n".join(f"[WARNING] {w}" for w in validation.warnings)
            output = warning_text + "\n" + output if output else warning_text

        return output

    # ------------------------------------------------------------------
    # Prompt
    # ------------------------------------------------------------------

    def prompt(self) -> str:
        """Generate the current shell prompt string."""
        return self.session.prompt()

    # ------------------------------------------------------------------
    # Autocomplete
    # ------------------------------------------------------------------

    def autocomplete(self, partial: str) -> List[str]:
        """
        Generate autocomplete suggestions for partial input.

        Supports:
          - Command name completion (ls, cd, cat...)
          - File/directory path completion
          - Case name completion

        Args:
            partial: The partially typed command text.

        Returns:
            List of completion suggestions.
        """
        parts = partial.strip().split()

        if not parts:
            return sorted(self.dispatcher.all_names)

        if len(parts) == 1 and not partial.endswith(" "):
            # Completing a command name
            prefix = parts[0].lower()
            return [
                name for name in self.dispatcher.all_names
                if name.startswith(prefix)
            ]

        # Completing a file/directory argument
        if len(parts) >= 1 and self.vfs:
            # Last token is the path being typed
            path_partial = parts[-1] if not partial.endswith(" ") else ""
            return self._complete_path(path_partial)

        return []

    def _complete_path(self, partial: str) -> List[str]:
        """Complete a file/directory path from the VFS."""
        if not self.vfs:
            return []

        # Normalize
        path = partial
        if len(path) >= 2 and path[1] == ":":
            path = path[2:]
        path = path.replace("\\", "/")

        # Split into directory and prefix
        if "/" in path:
            dir_part = path.rsplit("/", 1)[0]
            prefix = path.rsplit("/", 1)[1]
        else:
            # Relative to CWD
            cwd = self.session.path
            if len(cwd) >= 2 and cwd[1] == ":":
                cwd = cwd[2:]
            dir_part = cwd.replace("\\", "/")
            prefix = path

        if not dir_part.startswith("/"):
            dir_part = "/" + dir_part

        try:
            items = self.vfs.list_dir(dir_part)
            if prefix:
                items = [i for i in items if i.lower().startswith(prefix.lower())]
            return items[:20]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # VFS / Case management
    # ------------------------------------------------------------------

    def set_vfs(self, vfs: Any) -> None:
        """Attach or update the VFS layer."""
        self.vfs = vfs
        self.timeline_engine.vfs = vfs
        self.artifact_correlator.vfs = vfs

    def load_case(self, case_name: str, db_path: Optional[str] = None) -> None:
        """Load a case into the terminal session."""
        self.session.load_case(case_name)
        if db_path:
            self.coc = CoCLogger(db_path=db_path)
            self.timeline_engine.db_path = db_path
            self.artifact_correlator.db_path = db_path

    def _get_db_path(self) -> Optional[str]:
        """Get the current case database path."""
        return getattr(self.coc, "_db_path", None)

    # ------------------------------------------------------------------
    # Built-in command handlers
    # ------------------------------------------------------------------

    def _cmd_help(self, args, flags, session, vfs, **ctx) -> str:
        """Show available commands."""
        commands = self.dispatcher.list_commands()
        aliases = self.dispatcher.list_aliases()

        output = [
            "FEPD Forensic Terminal — Command Reference",
            "=" * 50,
            "",
        ]

        # Group commands by category
        categories = {
            "Navigation": ["ls", "cd", "pwd", "tree"],
            "File Inspection": ["cat", "stat", "hash", "hexdump", "strings"],
            "Search": ["find", "grep", "timeline"],
            "Intelligence": ["score", "explain", "artifacts", "connections", "who_used"],
            "Case Management": ["cases", "whoami"],
            "Terminal": ["help", "clear", "history", "exit"],
        }

        for category, cmd_names in categories.items():
            output.append(f"  {category}:")
            for name in cmd_names:
                desc = commands.get(name, "")
                # Find aliases
                cmd_aliases = [k for k, v in aliases.items() if v == name]
                alias_str = f" ({', '.join(cmd_aliases)})" if cmd_aliases else ""
                output.append(f"    {name:<16s}{desc}{alias_str}")
            output.append("")

        output.append("Type 'help <command>' for detailed usage.")
        output.append("[All commands are READ-ONLY — evidence is immutable]")

        return "\n".join(output)

    def _cmd_clear(self, args, flags, session, vfs, **ctx) -> str:
        """Clear the terminal (returns special marker)."""
        return "__CLEAR__"

    def _cmd_history(self, args, flags, session, vfs, **ctx) -> str:
        """Show command history."""
        history = session.get_history(50)
        if not history:
            return "No command history."

        output = ["Command History:", ""]
        for i, entry in enumerate(history, 1):
            output.append(f"  {i:4d}  {entry.timestamp[:19]}  {entry.command}")

        return "\n".join(output)

    def _cmd_whoami(self, args, flags, session, vfs, **ctx) -> str:
        """Show current investigator identity."""
        return (
            f"User:    {session.user}\n"
            f"Case:    {session.case or 'none'}\n"
            f"Path:    {session.path}\n"
            f"Session: Active"
        )

    def _cmd_cases(self, args, flags, session, vfs, **ctx) -> str:
        """List available cases."""
        cases_dir = os.path.join(self.workspace_root, "cases")
        if not os.path.isdir(cases_dir):
            return "No cases directory found."

        cases = []
        try:
            for entry in os.listdir(cases_dir):
                full = os.path.join(cases_dir, entry)
                if os.path.isdir(full) and not entry.startswith("."):
                    cases.append(entry)
        except Exception:
            return "Error listing cases."

        if not cases:
            return "No cases found."

        output = ["Available Cases:", ""]
        for c in sorted(cases):
            output.append(f"  {c}")
        output.append(f"\n[{len(cases)} case(s)]")
        output.append("Use: use case <name>")
        return "\n".join(output)

    def _cmd_exit(self, args, flags, session, vfs, **ctx) -> str:
        """Exit message."""
        return "__EXIT__"

    def _cmd_who_used(self, args, flags, session, vfs, **ctx) -> str:
        """Show who accessed a file."""
        if not args:
            return "Usage: who_used <filename>"
        if not vfs:
            return "No evidence mounted."

        target = args[0]
        # Convert to VFS path
        path = target
        if len(path) >= 2 and path[1] == ":":
            path = path[2:]
        path = path.replace("\\", "/")
        if not path.startswith("/"):
            cwd = session.path
            if len(cwd) >= 2 and cwd[1] == ":":
                cwd = cwd[2:]
            cwd = cwd.replace("\\", "/")
            path = os.path.join(cwd, path).replace("\\", "/")

        try:
            node = vfs._node_at(path)
            if node is None:
                return f"File not found: {target}"

            meta = vfs.stat(path) or {}
            owner = meta.get("owner", "Unknown")
            atime = meta.get("atime", meta.get("mtime", "[unknown]"))

            output = [
                f"File: {target}",
                f"",
                f"User:        {owner}",
                f"Last Access: {atime}",
                f"Source:      Evidence filesystem metadata",
            ]
            return "\n".join(output)
        except Exception as e:
            return f"Error: {e}"

    def _cmd_stat(self, args, flags, session, vfs, **ctx) -> str:
        """Show detailed file metadata."""
        if not args:
            return "Usage: stat <filename>"
        if not vfs:
            return "No evidence mounted."

        target = args[0]
        path = target
        if len(path) >= 2 and path[1] == ":":
            path = path[2:]
        path = path.replace("\\", "/")
        if not path.startswith("/"):
            cwd = session.path
            if len(cwd) >= 2 and cwd[1] == ":":
                cwd = cwd[2:]
            cwd = cwd.replace("\\", "/")
            path = os.path.join(cwd, path).replace("\\", "/")

        try:
            node = vfs._node_at(path)
            if node is None:
                return f"Not found: {target}"

            meta = vfs.stat(path) or {}
            display = "C:" + path.replace("/", "\\") if path.startswith("/") else path

            output = [
                f"  File: {display}",
                f"  Type: {'directory' if getattr(node, 'is_dir', False) else 'file'}",
            ]

            for key in ("size", "owner", "hash", "ml_score", "mtime", "atime", "ctime", "crtime",
                         "inode", "mft_entry", "permissions"):
                val = meta.get(key)
                if val is not None:
                    label = key.replace("_", " ").title()
                    output.append(f"  {label}: {val}")

            return "\n".join(output)
        except Exception as e:
            return f"Error: {e}"
