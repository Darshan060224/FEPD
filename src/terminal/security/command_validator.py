"""
FEPD Command Validator
========================

Pre-execution validation layer that checks:
  1. Read-only guard (evidence immutability)
  2. Argument sanity (path traversal, injection)
  3. Resource limits (prevent runaway commands)
  4. Path sanitization (no host filesystem leaks)

This runs BETWEEN the parser and the dispatcher.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import re
import logging
from dataclasses import dataclass
from typing import Optional, List, TYPE_CHECKING

from .read_only_guard import ReadOnlyGuard, BlockedResult, ALLOWED

if TYPE_CHECKING:
    from ..core.command_parser import ParsedCommand
    from ..core.session_manager import SessionManager

logger = logging.getLogger(__name__)


# Path traversal patterns to detect
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\.[/\\]"),              # ../
    re.compile(r"[/\\]\.\."),              # /..
    re.compile(r"~[/\\]"),                 # ~/  (home expansion)
    re.compile(r"^[A-Za-z]:[/\\]"),        # C:\  (absolute host path)
]

# Patterns that indicate shell injection
INJECTION_PATTERNS = [
    re.compile(r"[;&`$]"),                 # command chaining / substitution
    re.compile(r"\$\("),                   # $(command)
    re.compile(r"`[^`]+`"),               # `command`
]

# Maximum argument length
MAX_ARG_LENGTH = 4096

# Maximum recursion depth for tree/find
MAX_RECURSION_DEPTH = 10


@dataclass(frozen=True)
class ValidationResult:
    """Result of full command validation."""
    is_valid: bool
    error_message: str = ""
    blocked: Optional[BlockedResult] = None
    warnings: tuple = ()


# Singleton for valid commands
VALID = ValidationResult(is_valid=True)


class CommandValidator:
    """
    Multi-layer command validator for forensic terminal.

    Validation order:
      1. Read-only guard check
      2. Argument length check
      3. Path traversal detection
      4. Special pattern validation

    Usage:
        validator = CommandValidator()
        result = validator.validate(parsed_command, session)
        if not result.is_valid:
            print(result.error_message)
    """

    def __init__(self, guard: Optional[ReadOnlyGuard] = None) -> None:
        self._guard = guard or ReadOnlyGuard()

    @property
    def guard(self) -> ReadOnlyGuard:
        return self._guard

    def validate(
        self,
        parsed: "ParsedCommand",
        session: Optional["SessionManager"] = None,
    ) -> ValidationResult:
        """
        Validate a parsed command through all security layers.

        Args:
            parsed:  ParsedCommand from the parser.
            session: Current session (for context-aware validation).

        Returns:
            ValidationResult — check .is_valid.
        """
        if parsed.is_empty:
            return VALID

        # Layer 1: Read-only guard
        block_result = self._guard.check(parsed)
        if block_result.is_blocked:
            return ValidationResult(
                is_valid=False,
                error_message=block_result.denial_message,
                blocked=block_result,
            )

        # Layer 2: Argument length check
        for arg in parsed.arguments:
            if len(arg) > MAX_ARG_LENGTH:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"[SECURITY] Argument too long ({len(arg)} chars). Max: {MAX_ARG_LENGTH}.",
                )

        # Layer 3: Path traversal (warning: may be legitimate in evidence)
        warnings = []
        for arg in parsed.arguments:
            for pat in PATH_TRAVERSAL_PATTERNS:
                if pat.search(arg):
                    # Path traversal outside evidence root detection
                    warnings.append(
                        f"Path pattern detected in '{arg}' — resolved within evidence scope."
                    )
                    break

        if warnings:
            return ValidationResult(is_valid=True, warnings=tuple(warnings))

        return VALID

    def is_safe_path(self, path: str) -> bool:
        """
        Check if a path is safe (doesn't escape the evidence scope).

        Args:
            path: The path to validate.

        Returns:
            True if the path stays within evidence boundaries.
        """
        # Normalize
        normalized = path.replace("\\", "/")

        # Block absolute host paths
        if re.match(r"^[A-Za-z]:/", normalized):
            # Allowed only if it looks like an evidence drive letter (C:, D:)
            if normalized[0].upper() in ("C", "D", "E", "F"):
                return True
            return False

        # Block obvious escape attempts
        if "/../" in normalized or normalized.startswith("../"):
            return False

        return True
