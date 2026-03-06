"""
FEPD Command Dispatcher
=========================

Maps parsed commands to their handler modules and executes them.

Responsibilities:
  1. Maintain a registry of command_name → handler_function
  2. Look up the handler for a ParsedCommand
  3. Invoke the handler, passing VEOS context + session
  4. Support pipe chains by feeding output of one command into the next
  5. Return the final output string (or error message)

The dispatcher never executes commands directly — it delegates to
the individual command modules in ``src/terminal/commands/``.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, Optional, List, TYPE_CHECKING

from .command_parser import ParsedCommand, EMPTY_COMMAND

if TYPE_CHECKING:
    from .session_manager import SessionManager

logger = logging.getLogger(__name__)

# Type alias for command handlers
# Signature: handler(args, flags, session, vfs, **ctx) -> str
CommandHandler = Callable[..., str]


class CommandNotFoundError(Exception):
    """Raised when no handler is registered for a command."""
    pass


class CommandDispatcher:
    """
    Registry + dispatcher for FEPD terminal commands.

    Usage:
        dispatcher = CommandDispatcher()
        dispatcher.register("ls",   ls_handler)
        dispatcher.register("cd",   cd_handler)
        ...
        output = dispatcher.dispatch(parsed_cmd, session, vfs)
    """

    def __init__(self) -> None:
        self._registry: Dict[str, CommandHandler] = {}
        self._aliases: Dict[str, str] = {}
        self._help_texts: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        name: str,
        handler: CommandHandler,
        aliases: Optional[List[str]] = None,
        help_text: str = "",
    ) -> None:
        """
        Register a command handler.

        Args:
            name:      Canonical command name (lowercase).
            handler:   Callable(args, flags, session, vfs, **ctx) → str.
            aliases:   Alternative names (e.g., "dir" for "ls").
            help_text: One-line description shown in ``help`` output.
        """
        name = name.lower()
        self._registry[name] = handler
        self._help_texts[name] = help_text

        if aliases:
            for alias in aliases:
                self._aliases[alias.lower()] = name

    def unregister(self, name: str) -> None:
        """Remove a command from the registry."""
        name = name.lower()
        self._registry.pop(name, None)
        self._help_texts.pop(name, None)
        # Remove aliases pointing to this command
        self._aliases = {k: v for k, v in self._aliases.items() if v != name}

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve(self, command_name: str) -> Optional[CommandHandler]:
        """
        Resolve a command name (or alias) to its handler.

        Returns None if the command is not registered.
        """
        key = command_name.lower()
        # Direct lookup
        if key in self._registry:
            return self._registry[key]
        # Alias lookup
        canonical = self._aliases.get(key)
        if canonical and canonical in self._registry:
            return self._registry[canonical]
        return None

    def is_registered(self, command_name: str) -> bool:
        """Check if a command (or alias) is known."""
        return self.resolve(command_name) is not None

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def dispatch(
        self,
        parsed: ParsedCommand,
        session: "SessionManager",
        vfs: object,
        **extra_ctx,
    ) -> str:
        """
        Execute a parsed command through its registered handler.

        Handles pipe chains by feeding the output of one command
        as stdin to the next.

        Args:
            parsed:     ParsedCommand from the parser.
            session:    Current SessionManager instance.
            vfs:        VirtualFilesystem (VEOS) layer.
            **extra_ctx: Additional context (ml_bridge, audit, etc.).

        Returns:
            Command output as a string.

        Raises:
            CommandNotFoundError: If no handler is registered.
        """
        if parsed.is_empty:
            return ""

        handler = self.resolve(parsed.command)
        if handler is None:
            raise CommandNotFoundError(
                f"'{parsed.command}' is not recognized as a FEPD command.\n"
                f"Type 'help' for a list of available commands."
            )

        # Execute the handler
        try:
            output = handler(
                args=parsed.arguments,
                flags=parsed.flags,
                session=session,
                vfs=vfs,
                raw=parsed.raw,
                **extra_ctx,
            )
        except Exception as e:
            logger.exception("Command '%s' raised an exception", parsed.command)
            output = f"[ERROR] {parsed.command}: {e}"

        # ----------------------------------------------------------
        # Handle pipe chain
        # ----------------------------------------------------------
        if parsed.pipe_to and output:
            return self._dispatch_piped(parsed.pipe_to, output, session, vfs, **extra_ctx)

        return output or ""

    def _dispatch_piped(
        self,
        parsed: ParsedCommand,
        stdin_text: str,
        session: "SessionManager",
        vfs: object,
        **extra_ctx,
    ) -> str:
        """
        Dispatch a piped command, injecting the previous output as stdin.
        """
        handler = self.resolve(parsed.command)
        if handler is None:
            return f"[PIPE ERROR] '{parsed.command}' is not recognized."

        try:
            output = handler(
                args=parsed.arguments,
                flags=parsed.flags,
                session=session,
                vfs=vfs,
                raw=parsed.raw,
                stdin=stdin_text,
                **extra_ctx,
            )
        except Exception as e:
            logger.exception("Piped command '%s' raised an exception", parsed.command)
            output = f"[ERROR] {parsed.command}: {e}"

        # Continue pipe chain if more segments
        if parsed.pipe_to and output:
            return self._dispatch_piped(parsed.pipe_to, output, session, vfs, **extra_ctx)

        return output or ""

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def list_commands(self) -> Dict[str, str]:
        """Return dict of {command_name: help_text} for all registered commands."""
        return dict(self._help_texts)

    def list_aliases(self) -> Dict[str, str]:
        """Return dict of {alias: canonical_name}."""
        return dict(self._aliases)

    @property
    def command_names(self) -> List[str]:
        """All registered command names (no aliases)."""
        return sorted(self._registry.keys())

    @property
    def all_names(self) -> List[str]:
        """All registered command names + aliases."""
        return sorted(set(list(self._registry.keys()) + list(self._aliases.keys())))
