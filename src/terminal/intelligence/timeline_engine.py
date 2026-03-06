"""
FEPD Timeline Engine
======================

Advanced timeline correlation engine for forensic investigations.
Aggregates MACB timestamps, event logs, and file activity into
a unified forensic timeline.

Used by the ``timeline`` command and can be queried programmatically
by the terminal engine.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import sqlite3
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class TimelineEvent:
    """A single event in the forensic timeline."""
    timestamp: str
    event_type: str          # 'created', 'modified', 'accessed', 'deleted', 'executed'
    source: str              # 'MFT', 'Prefetch', 'EventLog', 'Registry'
    path: str                # Evidence path
    details: str = ""
    user: str = ""
    score: float = 0.0       # ML anomaly score


class TimelineEngine:
    """
    Forensic timeline correlation engine.

    Aggregates events from:
      - File system timestamps (MACB from VFS)
      - Event logs (if indexed)
      - Prefetch data (if indexed)
      - Registry changes (if indexed)

    Usage:
        engine = TimelineEngine(db_path="case.db", vfs=vfs)
        events = engine.get_file_timeline("C:/Users/Alice/notes.txt")
        events = engine.get_range("2025-01-10", "2025-01-15")
    """

    def __init__(self, db_path: Optional[str] = None, vfs: Any = None) -> None:
        self.db_path = db_path
        self.vfs = vfs

    def get_file_timeline(self, vfs_path: str) -> List[TimelineEvent]:
        """
        Get timeline events for a specific file.

        Args:
            vfs_path: VFS path (e.g., "/Users/Alice/notes.txt")

        Returns:
            List of TimelineEvent objects sorted by timestamp.
        """
        events = []

        # Get MACB times from VFS
        if self.vfs:
            try:
                meta = self.vfs.stat(vfs_path) or {}
                macb_fields = [
                    ("mtime", "modified"),
                    ("atime", "accessed"),
                    ("ctime", "created"),
                    ("crtime", "metadata_changed"),
                ]
                for key, event_type in macb_fields:
                    ts = meta.get(key)
                    if ts:
                        events.append(TimelineEvent(
                            timestamp=self._normalize_ts(ts),
                            event_type=event_type,
                            source="MFT",
                            path=vfs_path,
                            user=meta.get("owner", ""),
                            score=float(meta.get("ml_score", 0) or 0),
                        ))
            except Exception as e:
                logger.debug("VFS timeline error: %s", e)

        # Query database for additional events
        if self.db_path:
            db_events = self._query_events(vfs_path)
            events.extend(db_events)

        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)
        return events

    def get_range(
        self,
        start: str,
        end: str,
        limit: int = 500,
    ) -> List[TimelineEvent]:
        """
        Get timeline events within a time range.

        Args:
            start: Start timestamp (ISO format).
            end:   End timestamp (ISO format).
            limit: Maximum events to return.

        Returns:
            List of TimelineEvent objects.
        """
        events = []

        if self.db_path and os.path.exists(self.db_path):
            try:
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()

                # Check for timeline table
                cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='timeline_events'"
                )
                if cur.fetchone():
                    cur.execute(
                        """SELECT * FROM timeline_events
                           WHERE timestamp BETWEEN ? AND ?
                           ORDER BY timestamp LIMIT ?""",
                        (start, end, limit),
                    )
                    for row in cur.fetchall():
                        events.append(TimelineEvent(
                            timestamp=row["timestamp"],
                            event_type=row.get("event_type", "unknown"),
                            source=row.get("source", "DB"),
                            path=row.get("path", ""),
                            details=row.get("details", ""),
                            user=row.get("user", ""),
                        ))

                conn.close()
            except Exception as e:
                logger.debug("Timeline range query error: %s", e)

        return events

    def _query_events(self, vfs_path: str) -> List[TimelineEvent]:
        """Query events from the case database for a specific path."""
        events = []
        if not self.db_path or not os.path.exists(self.db_path):
            return events

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Check for timeline_events table
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='timeline_events'"
            )
            if cur.fetchone():
                cur.execute(
                    "SELECT * FROM timeline_events WHERE path LIKE ? ORDER BY timestamp",
                    (f"%{os.path.basename(vfs_path)}%",),
                )
                for row in cur.fetchall():
                    events.append(TimelineEvent(
                        timestamp=row["timestamp"],
                        event_type=row.get("event_type", "unknown"),
                        source=row.get("source", "DB"),
                        path=row.get("path", vfs_path),
                        details=row.get("details", ""),
                    ))

            conn.close()
        except Exception:
            pass

        return events

    @staticmethod
    def _normalize_ts(value: Any) -> str:
        """Normalize a timestamp value to ISO string."""
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).isoformat()
        return str(value)
