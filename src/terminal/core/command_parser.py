"""
FEPD Command Parser
=====================

Tokenizes raw user input into a structured ParsedCommand object.

Supports:
  - Simple commands:     ls
  - Commands with args:  cat notes.txt
  - Quoted arguments:    find "my file.txt"
  - Flags:               ls -la
  - Pipe chains:         strings malware.exe | grep http
  - Redirection detect:  echo foo > bar  (will be blocked by security)

Parser output (ParsedCommand):
  {
    "raw":       "cat notes.txt",
    "command":   "cat",
    "arguments": ["notes.txt"],
    "flags":     [],
    "pipe_to":   None
  }

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import shlex
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ParsedCommand:
    """Immutable result of parsing a single command string."""
    raw: str                          # Original input
    command: str                      # Primary command token (lowercase)
    arguments: List[str] = field(default_factory=list)   # Positional args
    flags: List[str] = field(default_factory=list)       # Flags (-a, --all, /b)
    pipe_to: Optional["ParsedCommand"] = None            # Piped downstream command
    has_redirect: bool = False        # Contains > or >> (always blocked)
    is_empty: bool = False            # Blank input


# Sentinel for empty input
EMPTY_COMMAND = ParsedCommand(raw="", command="", is_empty=True)


class CommandParser:
    """
    Lexer / tokenizer for the FEPD forensic terminal.

    Design goals:
      - Accept both Windows (dir /b) and Linux (ls -la) styles
      - Detect pipe chains (|)
      - Detect redirect operators so security can block them
      - Handle quoted paths with spaces
      - Never raise — always return a ParsedCommand (possibly with error info)
    """

    # Redirect operators to detect
    REDIRECT_OPERATORS = {">", ">>", "<", "<<", "2>", "2>>", "&>"}

    def parse(self, raw_input: str) -> ParsedCommand:
        """
        Parse a raw input string into a ParsedCommand.

        Args:
            raw_input: The raw text the user typed.

        Returns:
            ParsedCommand with structured tokens.
        """
        stripped = raw_input.strip()
        if not stripped:
            return EMPTY_COMMAND

        # ----------------------------------------------------------
        # 1. Detect pipe chains and split
        # ----------------------------------------------------------
        pipe_segments = self._split_pipes(stripped)

        if len(pipe_segments) > 1:
            # Parse each segment, chain via pipe_to
            return self._parse_pipe_chain(stripped, pipe_segments)

        # ----------------------------------------------------------
        # 2. Single command — tokenize
        # ----------------------------------------------------------
        return self._parse_single(stripped)

    def _parse_single(self, text: str) -> ParsedCommand:
        """Parse a single command (no pipes)."""
        tokens = self._tokenize(text)
        if not tokens:
            return EMPTY_COMMAND

        command = tokens[0].lower()
        rest = tokens[1:]

        arguments: List[str] = []
        flags: List[str] = []
        has_redirect = False

        for token in rest:
            if token in self.REDIRECT_OPERATORS:
                has_redirect = True
                arguments.append(token)
            elif token.startswith("-") or token.startswith("/"):
                flags.append(token)
            else:
                arguments.append(token)

        return ParsedCommand(
            raw=text,
            command=command,
            arguments=arguments,
            flags=flags,
            has_redirect=has_redirect,
        )

    def _parse_pipe_chain(self, raw: str, segments: List[str]) -> ParsedCommand:
        """Recursively build a ParsedCommand chain for piped commands."""
        # Parse from right to left to build the pipe_to chain
        parsed_segments = [self._parse_single(seg) for seg in segments]

        # Chain them: first → second → third ...
        for i in range(len(parsed_segments) - 2, -1, -1):
            seg = parsed_segments[i]
            # dataclass is frozen, so rebuild with pipe_to set
            parsed_segments[i] = ParsedCommand(
                raw=seg.raw,
                command=seg.command,
                arguments=seg.arguments,
                flags=seg.flags,
                pipe_to=parsed_segments[i + 1],
                has_redirect=seg.has_redirect,
            )

        # Top-level keeps the full raw input
        top = parsed_segments[0]
        return ParsedCommand(
            raw=raw,
            command=top.command,
            arguments=top.arguments,
            flags=top.flags,
            pipe_to=top.pipe_to,
            has_redirect=top.has_redirect,
        )

    # ------------------------------------------------------------------
    # Tokenization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """
        Split text respecting quotes.

        Uses shlex for proper handling of quoted strings.
        Falls back to simple split if shlex fails (e.g., unmatched quotes).
        """
        try:
            return shlex.split(text, posix=False)
        except ValueError:
            # Unmatched quotes — best-effort split
            return text.split()

    @staticmethod
    def _split_pipes(text: str) -> List[str]:
        """
        Split on | but not inside quotes.

        Simple state-machine approach.
        """
        segments: List[str] = []
        current: List[str] = []
        in_quote = False
        quote_char = ""

        for ch in text:
            if ch in ('"', "'") and not in_quote:
                in_quote = True
                quote_char = ch
                current.append(ch)
            elif ch == quote_char and in_quote:
                in_quote = False
                quote_char = ""
                current.append(ch)
            elif ch == "|" and not in_quote:
                segments.append("".join(current).strip())
                current = []
            else:
                current.append(ch)

        tail = "".join(current).strip()
        if tail:
            segments.append(tail)

        return [s for s in segments if s]


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------
_default_parser = CommandParser()


def parse(raw_input: str) -> ParsedCommand:
    """Module-level shortcut for parsing a command string."""
    return _default_parser.parse(raw_input)
