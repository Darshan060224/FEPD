"""
FEPD Terminal Core
===================
Core components: engine, parser, dispatcher, session manager.
"""

from .terminal_engine import TerminalEngine
from .command_parser import CommandParser, ParsedCommand
from .command_dispatcher import CommandDispatcher
from .session_manager import SessionManager

__all__ = [
    "TerminalEngine",
    "CommandParser",
    "ParsedCommand",
    "CommandDispatcher",
    "SessionManager",
]
