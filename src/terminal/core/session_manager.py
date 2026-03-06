"""
FEPD Terminal Session Manager
===============================

Tracks the active forensic session state:
  - current_user        (Investigator identity)
  - current_case        (Active case name)
  - current_path        (VEOS evidence path)
  - command_history     (Full audit trail of commands)

The session is the single source of truth for the terminal's context.
It is consulted by every other layer before executing anything.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

# Maximum commands stored in memory history (disk log is unlimited)
MAX_HISTORY_SIZE: int = 2000


@dataclass
class HistoryEntry:
    """A single command history record."""
    timestamp: str
    command: str
    path: str
    case: str
    user: str
    result_summary: str = ""


@dataclass
class SessionState:
    """Immutable snapshot of session state at a point in time."""
    user: str
    case: Optional[str]
    path: str
    timestamp: str


class SessionManager:
    """
    Manages the forensic terminal session lifecycle.

    Responsibilities:
      1. Track current user, case, and evidence path
      2. Maintain command history (in-memory + persistent)
      3. Provide session snapshots for audit logging
      4. Generate the shell prompt string

    Thread-safety: Session is single-threaded (GUI thread only).
    """

    def __init__(self, workspace_root: str) -> None:
        self.workspace_root = workspace_root
        self._user: str = "Investigator"
        self._case: Optional[str] = None
        self._path: str = "C:\\"
        self._history: List[HistoryEntry] = []
        self._history_index: int = -1
        self._env: Dict[str, str] = {
            "COMPUTERNAME": "EVIDENCE-PC",
            "USERNAME": "Investigator",
            "SYSTEMROOT": "C:\\Windows",
            "TEMP": "C:\\Users\\Temp",
            "FEPD_VERSION": "2.0.0",
        }
        self._session_start = datetime.utcnow().isoformat() + "Z"

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def user(self) -> str:
        return self._user

    @user.setter
    def user(self, value: str) -> None:
        self._user = value
        self._env["USERNAME"] = value

    @property
    def case(self) -> Optional[str]:
        return self._case

    @case.setter
    def case(self, value: Optional[str]) -> None:
        self._case = value

    @property
    def path(self) -> str:
        return self._path

    @path.setter
    def path(self, value: str) -> None:
        self._path = value

    @property
    def env(self) -> Dict[str, str]:
        return dict(self._env)

    # ------------------------------------------------------------------
    # Prompt generation
    # ------------------------------------------------------------------

    def prompt(self) -> str:
        """
        Generate the shell prompt.

        Format:
            fepd:<case>[<user>]$ <path>
            fepd:sv[Investigator]$ C:\\Users\\Alice\\Documents

        When no case is loaded:
            fepd:global[Investigator]$
        """
        case_label = self._case or "global"
        return f"fepd:{case_label}[{self._user}]$ "

    # ------------------------------------------------------------------
    # History management
    # ------------------------------------------------------------------

    def add_history(self, command: str, result_summary: str = "") -> None:
        """Record a command in session history."""
        entry = HistoryEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            command=command,
            path=self._path,
            case=self._case or "global",
            user=self._user,
            result_summary=result_summary[:200],
        )
        self._history.append(entry)
        if len(self._history) > MAX_HISTORY_SIZE:
            self._history = self._history[-MAX_HISTORY_SIZE:]
        # Reset navigation index
        self._history_index = len(self._history)

    def history_up(self) -> Optional[str]:
        """Navigate history backwards (↑ key)."""
        if not self._history:
            return None
        self._history_index = max(0, self._history_index - 1)
        return self._history[self._history_index].command

    def history_down(self) -> Optional[str]:
        """Navigate history forwards (↓ key)."""
        if not self._history:
            return None
        self._history_index = min(len(self._history), self._history_index + 1)
        if self._history_index >= len(self._history):
            return ""
        return self._history[self._history_index].command

    def get_history(self, last_n: int = 50) -> List[HistoryEntry]:
        """Return recent history entries."""
        return self._history[-last_n:]

    def clear_history(self) -> None:
        """Clear in-memory history."""
        self._history.clear()
        self._history_index = -1

    # ------------------------------------------------------------------
    # State snapshots
    # ------------------------------------------------------------------

    def snapshot(self) -> SessionState:
        """Create an immutable snapshot of the current session."""
        return SessionState(
            user=self._user,
            case=self._case,
            path=self._path,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize session state for logging/export."""
        return {
            "user": self._user,
            "case": self._case,
            "path": self._path,
            "session_start": self._session_start,
            "history_count": len(self._history),
            "environment": dict(self._env),
        }

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Reset session to initial state (e.g., when switching cases)."""
        self._path = "C:\\"
        self._history_index = len(self._history)

    def load_case(self, case_name: str) -> None:
        """Update session when a case is loaded."""
        self._case = case_name
        self._path = "C:\\"
        self._history_index = len(self._history)
        logger.info("Session bound to case: %s", case_name)

    def unload_case(self) -> None:
        """Clear case binding."""
        self._case = None
        self._path = "C:\\"
        logger.info("Session unbound from case")

    def set_user(self, username: str) -> None:
        """Switch the investigator identity for user-context commands."""
        self._user = username
        self._env["USERNAME"] = username
        logger.info("Session user changed to: %s", username)
