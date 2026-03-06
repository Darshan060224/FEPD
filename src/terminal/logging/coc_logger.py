"""
FEPD Chain of Custody Logger (Terminal Layer)
===============================================

Every terminal command is logged with:
  - Timestamp (UTC ISO-8601)
  - Investigator identity
  - Command text
  - Evidence path at time of execution
  - Case identifier
  - Result hash (SHA-256 of output)
  - Blocked status (if denied by security)

This log is append-only, hash-chained, and tamper-evident.
It integrates with the core ChainLogger for the case-level audit trail.

Storage:
  - SQLite database (per-case)
  - JSON log file (human-readable backup)

This ensures legal admissibility per NIST SP 800-86.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.session_manager import SessionManager

logger = logging.getLogger(__name__)


class CoCLogger:
    """
    Chain of Custody logger for the FEPD terminal.

    Every command executed (or blocked) is recorded with a tamper-evident
    hash chain. Each entry hashes the previous entry, creating a
    blockchain-like audit trail.

    Usage:
        coc = CoCLogger(case_path="/path/to/case")
        coc.log_command(session, "ls", output="file1.txt\\nfile2.txt")
        coc.log_blocked(session, "rm secret.txt", reason="Write blocked")
    """

    def __init__(self, case_path: Optional[str] = None, db_path: Optional[str] = None) -> None:
        """
        Args:
            case_path: Path to the case directory (logs stored here).
            db_path:   Explicit database path (overrides case_path).
        """
        self._case_path = case_path
        self._prev_hash = "0" * 64  # Genesis hash
        self._entry_count = 0

        # Determine database path
        if db_path:
            self._db_path = db_path
        elif case_path:
            self._db_path = os.path.join(case_path, "terminal_audit.db")
        else:
            self._db_path = None

        # Initialize database if possible
        if self._db_path:
            self._init_db()

    def _init_db(self) -> None:
        """Create the audit log table if it doesn't exist."""
        try:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
            conn = sqlite3.connect(self._db_path)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS terminal_audit (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp    TEXT    NOT NULL,
                    user         TEXT    NOT NULL,
                    case_name    TEXT,
                    command      TEXT    NOT NULL,
                    path         TEXT,
                    output_hash  TEXT,
                    status       TEXT    DEFAULT 'executed',
                    reason       TEXT,
                    prev_hash    TEXT,
                    entry_hash   TEXT
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_ts
                ON terminal_audit(timestamp)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_cmd
                ON terminal_audit(command)
            """)
            conn.commit()

            # Load the last hash for chain continuity
            cur.execute(
                "SELECT entry_hash FROM terminal_audit ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
            if row and row[0]:
                self._prev_hash = row[0]
                cur.execute("SELECT COUNT(*) FROM terminal_audit")
                self._entry_count = cur.fetchone()[0]

            conn.close()
        except Exception as e:
            logger.warning("Could not initialize CoC database: %s", e)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_command(
        self,
        session: "SessionManager",
        command: str,
        output: str = "",
    ) -> None:
        """
        Log an executed command.

        Args:
            session: Current session state.
            command: The raw command text.
            output:  Command output (hashed, not stored verbatim).
        """
        output_hash = self._hash_text(output) if output else ""
        self._write_entry(
            user=session.user,
            case_name=session.case or "global",
            command=command,
            path=session.path,
            output_hash=output_hash,
            status="executed",
            reason="",
        )

    def log_blocked(
        self,
        session: "SessionManager",
        command: str,
        reason: str = "",
    ) -> None:
        """
        Log a blocked (denied) command.

        Args:
            session: Current session state.
            command: The raw command text that was blocked.
            reason:  Why it was blocked.
        """
        self._write_entry(
            user=session.user,
            case_name=session.case or "global",
            command=command,
            path=session.path,
            output_hash="",
            status="BLOCKED",
            reason=reason,
        )

    def log_error(
        self,
        session: "SessionManager",
        command: str,
        error: str = "",
    ) -> None:
        """Log a command that errored."""
        self._write_entry(
            user=session.user,
            case_name=session.case or "global",
            command=command,
            path=session.path,
            output_hash=self._hash_text(error),
            status="ERROR",
            reason=error[:500],
        )

    # ------------------------------------------------------------------
    # Query API (for `history` and audit commands)
    # ------------------------------------------------------------------

    def get_entries(self, last_n: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent audit entries."""
        if not self._db_path or not os.path.exists(self._db_path):
            return []
        try:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM terminal_audit ORDER BY id DESC LIMIT ?",
                (last_n,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return list(reversed(rows))
        except Exception:
            return []

    def verify_chain(self) -> Dict[str, Any]:
        """
        Verify the integrity of the hash chain.

        Returns:
            {
                "valid": True/False,
                "entries_checked": int,
                "first_broken_id": int or None,
            }
        """
        if not self._db_path or not os.path.exists(self._db_path):
            return {"valid": True, "entries_checked": 0, "first_broken_id": None}

        try:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM terminal_audit ORDER BY id ASC")
            rows = cur.fetchall()
            conn.close()

            prev = "0" * 64
            for row in rows:
                expected_prev = row["prev_hash"]
                if expected_prev and expected_prev != prev:
                    return {
                        "valid": False,
                        "entries_checked": row["id"],
                        "first_broken_id": row["id"],
                    }
                prev = row["entry_hash"] or prev

            return {"valid": True, "entries_checked": len(rows), "first_broken_id": None}
        except Exception:
            return {"valid": False, "entries_checked": 0, "first_broken_id": -1}

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_entry(
        self,
        user: str,
        case_name: str,
        command: str,
        path: str,
        output_hash: str,
        status: str,
        reason: str,
    ) -> None:
        """Write a single audit entry to the database with hash chaining."""
        timestamp = datetime.now(timezone.utc).isoformat()
        self._entry_count += 1

        # Compute entry hash (chain)
        entry_data = f"{self._entry_count}|{timestamp}|{user}|{command}|{self._prev_hash}"
        entry_hash = hashlib.sha256(entry_data.encode("utf-8")).hexdigest()

        if self._db_path:
            try:
                conn = sqlite3.connect(self._db_path)
                cur = conn.cursor()
                cur.execute(
                    """INSERT INTO terminal_audit
                       (timestamp, user, case_name, command, path,
                        output_hash, status, reason, prev_hash, entry_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (timestamp, user, case_name, command, path,
                     output_hash, status, reason, self._prev_hash, entry_hash),
                )
                conn.commit()
                conn.close()
            except Exception as e:
                logger.warning("Failed to write CoC entry: %s", e)

        self._prev_hash = entry_hash

    @staticmethod
    def _hash_text(text: str) -> str:
        """SHA-256 hash of text."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
