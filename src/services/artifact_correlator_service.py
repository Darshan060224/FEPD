"""
FEPD Artifact Correlator Service
=================================

Thin UI-facing wrapper around the terminal's ``ArtifactCorrelator``
so the Files Tab can show per-file forensic activity without importing
terminal internals directly.

All operations are **read-only**.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Any

from src.terminal.intelligence.artifact_correlator import (
    ArtifactCorrelator,
    CorrelationResult,
)

logger = logging.getLogger(__name__)


class ArtifactCorrelatorService:
    """
    Provides per-file artifact correlation for the Files tab's
    Activities panel.

    Parameters
    ----------
    vfs : VirtualFilesystem
        The active virtual filesystem instance.
    db_path : str, optional
        Path to the case SQLite database (for pre-parsed artifacts).
    """

    def __init__(self, vfs: Any = None, db_path: Optional[str] = None):
        self._correlator = ArtifactCorrelator(vfs=vfs, db_path=db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate_file(self, file_path: str) -> List[CorrelationResult]:
        """Return artifact correlation results for a single file."""
        try:
            return self._correlator.correlate(file_path)
        except Exception as exc:
            logger.warning("Artifact correlation failed for %s: %s", file_path, exc)
            return []

    def correlate_user(self, username: str) -> List[CorrelationResult]:
        """Return artifacts associated with a user profile."""
        try:
            return self._correlator.correlate_user(username)
        except Exception as exc:
            logger.warning("User correlation failed for %s: %s", username, exc)
            return []

    def format_activities(self, results: List[CorrelationResult]) -> str:
        """Format correlation results into human-readable text for the UI."""
        if not results:
            return "No related forensic artifacts found."

        found = [r for r in results if r.found]
        if not found:
            return "No related forensic artifacts found."

        lines = []
        for r in found:
            conf = f"[{r.confidence:.0%}]" if r.confidence else ""
            lines.append(f"• {r.artifact_type} {conf}")
            lines.append(f"  {r.description}")
            if r.source_path:
                lines.append(f"  Source: {r.source_path}")
            lines.append("")

        return "\n".join(lines).strip()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def update_vfs(self, vfs: Any) -> None:
        """Update the underlying VFS reference (e.g. after evidence reload)."""
        self._correlator.vfs = vfs

    def update_db(self, db_path: str) -> None:
        """Update the case database path."""
        self._correlator.db_path = db_path
