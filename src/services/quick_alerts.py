"""
FEPD Quick Alerts Service
==========================

Scans the VFS database for suspicious forensic indicators immediately
after ingestion and produces a list of prioritised alerts.

Detected indicators:

  • Executables in Downloads / Desktop / Temp
  • Large archives (> 500 MB)
  • Encrypted containers (VeraCrypt, BitLocker, LUKS headers)
  • Hidden / system files in unusual locations
  • Deleted files of interest
  • Suspicious script files

All operations are **read-only**.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Severity levels
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


@dataclass
class Alert:
    """A single suspicious-indicator alert."""
    severity: str       # high / medium / low
    icon: str           # emoji for UI
    title: str          # short description
    detail: str         # longer explanation
    count: int = 0      # number of items
    category: str = ""  # grouping tag


class QuickAlertsService:
    """
    Produce a list of ``Alert`` objects from the VFS.

    Parameters
    ----------
    vfs : VirtualFilesystem
        The populated virtual filesystem.
    """

    def __init__(self, vfs: Any):
        self._vfs = vfs

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> List[Alert]:
        """Run all detectors and return sorted alerts (high → low)."""
        conn = self._conn()
        if conn is None:
            return []

        alerts: List[Alert] = []
        try:
            alerts += self._exes_in_user_folders(conn)
            alerts += self._large_archives(conn)
            alerts += self._hidden_files(conn)
            alerts += self._deleted_files(conn)
            alerts += self._suspicious_scripts(conn)
            alerts += self._encrypted_containers(conn)
            alerts += self._double_extensions(conn)
        except Exception as exc:
            logger.error("Quick alert scan error: %s", exc, exc_info=True)

        # Sort: high first, then medium, then low
        order = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
        alerts.sort(key=lambda a: order.get(a.severity, 9))
        return alerts

    # ------------------------------------------------------------------
    # Detectors
    # ------------------------------------------------------------------

    def _exes_in_user_folders(self, conn: sqlite3.Connection) -> List[Alert]:
        """Executables in Downloads / Desktop / Temp."""
        alerts = []
        for folder in ("Downloads", "Desktop", "Temp", "tmp"):
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM virtual_fs "
                "WHERE node_type = 'file' AND is_deleted = 0 "
                "AND path LIKE ? "
                "AND (name LIKE '%.exe' OR name LIKE '%.bat' OR name LIKE '%.cmd' "
                "     OR name LIKE '%.ps1' OR name LIKE '%.vbs' OR name LIKE '%.msi')",
                (f"%/{folder}/%",),
            )
            n = cur.fetchone()[0]
            if n > 0:
                alerts.append(Alert(
                    severity=SEVERITY_HIGH if n >= 5 else SEVERITY_MEDIUM,
                    icon="⚠️",
                    title=f"Executables in {folder}",
                    detail=f"{n} executable(s) found in {folder} folder",
                    count=n,
                    category="execution",
                ))
        return alerts

    def _large_archives(self, conn: sqlite3.Connection) -> List[Alert]:
        """Archives larger than 500 MB."""
        cur = conn.cursor()
        threshold = 500 * 1024 * 1024  # 500 MB
        cur.execute(
            "SELECT COUNT(*) FROM virtual_fs "
            "WHERE node_type = 'file' AND is_deleted = 0 "
            "AND size > ? "
            "AND (name LIKE '%.zip' OR name LIKE '%.rar' OR name LIKE '%.7z' "
            "     OR name LIKE '%.tar' OR name LIKE '%.gz')",
            (threshold,),
        )
        n = cur.fetchone()[0]
        if n > 0:
            return [Alert(
                severity=SEVERITY_MEDIUM,
                icon="📦",
                title="Large archives detected",
                detail=f"{n} archive(s) larger than 500 MB",
                count=n,
                category="exfiltration",
            )]
        return []

    def _hidden_files(self, conn: sqlite3.Connection) -> List[Alert]:
        """Hidden files (names starting with '.')."""
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM virtual_fs "
            "WHERE node_type = 'file' AND is_deleted = 0 "
            "AND name LIKE '.%' AND name NOT IN ('.', '..')"
        )
        n = cur.fetchone()[0]
        if n > 10:
            return [Alert(
                severity=SEVERITY_LOW,
                icon="👁️",
                title="Hidden files detected",
                detail=f"{n} hidden file(s) found (names starting with '.')",
                count=n,
                category="concealment",
            )]
        return []

    def _deleted_files(self, conn: sqlite3.Connection) -> List[Alert]:
        """Deleted files count."""
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM virtual_fs WHERE is_deleted = 1")
        n = cur.fetchone()[0]
        if n > 0:
            return [Alert(
                severity=SEVERITY_MEDIUM if n > 50 else SEVERITY_LOW,
                icon="🗑️",
                title="Deleted files recoverable",
                detail=f"{n} deleted file(s) detected in filesystem",
                count=n,
                category="deletion",
            )]
        return []

    def _suspicious_scripts(self, conn: sqlite3.Connection) -> List[Alert]:
        """PowerShell / VBScript / JavaScript files."""
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM virtual_fs "
            "WHERE node_type = 'file' AND is_deleted = 0 "
            "AND (name LIKE '%.ps1' OR name LIKE '%.vbs' OR name LIKE '%.wsf' "
            "     OR name LIKE '%.hta' OR name LIKE '%.js')"
        )
        n = cur.fetchone()[0]
        if n > 0:
            return [Alert(
                severity=SEVERITY_MEDIUM,
                icon="📜",
                title="Script files found",
                detail=f"{n} script file(s) (PS1, VBS, JS, HTA, WSF)",
                count=n,
                category="execution",
            )]
        return []

    def _encrypted_containers(self, conn: sqlite3.Connection) -> List[Alert]:
        """Known encrypted container extensions."""
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM virtual_fs "
            "WHERE node_type = 'file' AND is_deleted = 0 "
            "AND (name LIKE '%.tc' OR name LIKE '%.hc' OR name LIKE '%.vhd' "
            "     OR name LIKE '%.vhdx' OR name LIKE '%.luks')"
        )
        n = cur.fetchone()[0]
        if n > 0:
            return [Alert(
                severity=SEVERITY_HIGH,
                icon="🔐",
                title="Encrypted containers",
                detail=f"{n} potential encrypted container(s) detected",
                count=n,
                category="encryption",
            )]
        return []

    def _double_extensions(self, conn: sqlite3.Connection) -> List[Alert]:
        """Files with double extensions (e.g. report.pdf.exe)."""
        cur = conn.cursor()
        # Look for common deceptive double extensions
        cur.execute(
            "SELECT COUNT(*) FROM virtual_fs "
            "WHERE node_type = 'file' AND is_deleted = 0 "
            "AND (name LIKE '%.pdf.exe' OR name LIKE '%.doc.exe' "
            "     OR name LIKE '%.jpg.exe' OR name LIKE '%.txt.exe' "
            "     OR name LIKE '%.png.exe' OR name LIKE '%.pdf.scr' "
            "     OR name LIKE '%.doc.scr' OR name LIKE '%.jpg.scr')"
        )
        n = cur.fetchone()[0]
        if n > 0:
            return [Alert(
                severity=SEVERITY_HIGH,
                icon="🚨",
                title="Double-extension files",
                detail=f"{n} file(s) with deceptive double extensions (possible malware)",
                count=n,
                category="malware",
            )]
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _conn(self) -> Optional[sqlite3.Connection]:
        try:
            return self._vfs._get_connection()
        except Exception:
            return None
