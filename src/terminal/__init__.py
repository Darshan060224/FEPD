"""
FEPD Professional Forensic Terminal
====================================

A modular, layered forensic shell system that emulates native OS terminals
(bash, PowerShell, zsh) while enforcing forensic constraints:

  - Evidence is READ-ONLY
  - Every command is audited (Chain of Custody)
  - All paths are VEOS evidence paths
  - Write operations are blocked at every layer

Architecture:

    Terminal UI  →  Command Parser  →  Dispatcher  →  Command Modules
                                                          │
                                              Evidence Intelligence Engine
                                                          │
                                                   VEOS Filesystem
                                                          │
                                                    Evidence Image

Copyright (c) 2026 FEPD Development Team
"""

__version__ = "2.0.0"

from .core.terminal_engine import TerminalEngine
from .core.command_parser import CommandParser, ParsedCommand
from .core.command_dispatcher import CommandDispatcher
from .core.session_manager import SessionManager
from .security.read_only_guard import ReadOnlyGuard
from .security.command_validator import CommandValidator
from .logging.coc_logger import CoCLogger
from .ui.terminal_widget import TerminalWidget

__all__ = [
    "TerminalEngine",
    "CommandParser",
    "ParsedCommand",
    "CommandDispatcher",
    "SessionManager",
    "ReadOnlyGuard",
    "CommandValidator",
    "CoCLogger",
    "TerminalWidget",
]
