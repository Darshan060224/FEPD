"""
FEPD Read-Only Guard
======================

Enforces evidence immutability at the command layer.

Any command or pattern that would modify evidence is intercepted
and blocked BEFORE execution. This is the terminal's firewall.

Blocked categories:
  - File deletion:    rm, del, remove, delete, erase
  - File creation:    touch, mkdir, echo >, cat >
  - File modification: mv, move, rename, cp, copy, write
  - Editors:          nano, vim, vi, notepad, edit
  - System mutation:  chmod, chown, mkfs, format, fdisk
  - Redirect writes:  >, >>, 2>

All blocked attempts are logged for Chain of Custody.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Set, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.command_parser import ParsedCommand

logger = logging.getLogger(__name__)


# ============================================================================
# Blocked command sets
# ============================================================================

# Commands that DELETE evidence
DELETE_COMMANDS: Set[str] = {
    "rm", "del", "delete", "remove", "erase", "rmdir",
    "shred", "wipe", "unlink",
}

# Commands that CREATE files (modifying evidence directory)
CREATE_COMMANDS: Set[str] = {
    "touch", "mkdir", "mkfile", "new-item",
}

# Commands that MOVE / RENAME evidence
MOVE_COMMANDS: Set[str] = {
    "mv", "move", "rename", "ren",
}

# Commands that COPY evidence (potential exfiltration)
COPY_COMMANDS: Set[str] = {
    "cp", "copy", "xcopy", "robocopy",
}

# Commands that EDIT / MODIFY evidence
EDIT_COMMANDS: Set[str] = {
    "nano", "vim", "vi", "emacs", "notepad", "notepad++",
    "edit", "sed", "awk", "write", "truncate", "append",
}

# System-level mutation commands
SYSTEM_COMMANDS: Set[str] = {
    "chmod", "chown", "chgrp", "mkfs", "format", "fdisk",
    "dd", "mount", "umount", "kill", "shutdown", "reboot",
    "useradd", "userdel", "passwd", "su", "sudo",
}

# All blocked commands combined
ALL_BLOCKED_COMMANDS: Set[str] = (
    DELETE_COMMANDS | CREATE_COMMANDS | MOVE_COMMANDS |
    COPY_COMMANDS | EDIT_COMMANDS | SYSTEM_COMMANDS
)

# Redirect patterns that indicate write intent
WRITE_REDIRECT_PATTERNS = {">", ">>", "2>", "2>>", "&>"}


# ============================================================================
# Block reasons
# ============================================================================

@dataclass(frozen=True)
class BlockedResult:
    """Result of a guard check when a command is blocked."""
    is_blocked: bool
    command: str
    reason: str
    category: str  # 'delete', 'create', 'move', 'copy', 'edit', 'system', 'redirect'

    @property
    def denial_message(self) -> str:
        """Formatted denial message for the terminal."""
        return (
            f"\n[DENIED] Evidence is immutable.\n"
            f"Command:  {self.command}\n"
            f"Reason:   {self.reason}\n"
            f"Category: {self.category}\n"
            f"\n"
            f"FEPD Terminal is read-only by design.\n"
            f"Evidence integrity must be preserved for legal admissibility.\n"
        )


# Singleton for "allowed"
ALLOWED = BlockedResult(is_blocked=False, command="", reason="", category="")


# ============================================================================
# Guard implementation
# ============================================================================

class ReadOnlyGuard:
    """
    Validates commands against the read-only policy.

    Usage:
        guard = ReadOnlyGuard()
        result = guard.check(parsed_command)
        if result.is_blocked:
            print(result.denial_message)
    """

    def __init__(self, extra_blocked: Optional[Set[str]] = None) -> None:
        """
        Args:
            extra_blocked: Additional command names to block
                           (beyond the built-in set).
        """
        self._blocked = set(ALL_BLOCKED_COMMANDS)
        if extra_blocked:
            self._blocked.update(extra_blocked)

    def check(self, parsed: "ParsedCommand") -> BlockedResult:
        """
        Check a parsed command against the read-only policy.

        Args:
            parsed: ParsedCommand from the parser.

        Returns:
            BlockedResult — check .is_blocked to see if denied.
        """
        if parsed.is_empty:
            return ALLOWED

        cmd = parsed.command.lower()

        # 1. Check for redirect operators (>, >>)
        if parsed.has_redirect:
            return BlockedResult(
                is_blocked=True,
                command=parsed.raw,
                reason="Redirect operators (>, >>) would write to evidence filesystem.",
                category="redirect",
            )

        # 2. Check against blocked command sets
        if cmd in DELETE_COMMANDS:
            return BlockedResult(
                is_blocked=True,
                command=cmd,
                reason=f"'{cmd}' would delete evidence files.",
                category="delete",
            )

        if cmd in CREATE_COMMANDS:
            return BlockedResult(
                is_blocked=True,
                command=cmd,
                reason=f"'{cmd}' would create files in the evidence filesystem.",
                category="create",
            )

        if cmd in MOVE_COMMANDS:
            return BlockedResult(
                is_blocked=True,
                command=cmd,
                reason=f"'{cmd}' would move/rename evidence files.",
                category="move",
            )

        if cmd in COPY_COMMANDS:
            return BlockedResult(
                is_blocked=True,
                command=cmd,
                reason=f"'{cmd}' would copy evidence (use 'export' for working copies).",
                category="copy",
            )

        if cmd in EDIT_COMMANDS:
            return BlockedResult(
                is_blocked=True,
                command=cmd,
                reason=f"'{cmd}' would modify evidence content.",
                category="edit",
            )

        if cmd in SYSTEM_COMMANDS:
            return BlockedResult(
                is_blocked=True,
                command=cmd,
                reason=f"'{cmd}' is a system mutation command blocked in forensic mode.",
                category="system",
            )

        # 3. Check any extra blocked commands
        if cmd in self._blocked and cmd not in ALL_BLOCKED_COMMANDS:
            return BlockedResult(
                is_blocked=True,
                command=cmd,
                reason=f"'{cmd}' is blocked by custom policy.",
                category="custom",
            )

        return ALLOWED

    def add_blocked(self, command: str) -> None:
        """Add a command to the blocked list at runtime."""
        self._blocked.add(command.lower())

    def remove_blocked(self, command: str) -> None:
        """Remove a command from the blocked list (if custom)."""
        cmd = command.lower()
        if cmd not in ALL_BLOCKED_COMMANDS:
            self._blocked.discard(cmd)

    @property
    def blocked_commands(self) -> Set[str]:
        """Return the full set of blocked commands."""
        return set(self._blocked)
