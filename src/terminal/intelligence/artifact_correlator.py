"""
FEPD Artifact Correlator
===========================

Cross-references evidence files with known forensic artifact locations
to build a correlation map for investigations.

Correlates:
  - Windows artifacts (Prefetch, ShimCache, AmCache, MUICache)
  - Registry hives
  - Event logs
  - Browser artifacts
  - USB history
  - Recycle Bin entries

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import sqlite3
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    """A single artifact correlation entry."""
    artifact_type: str        # 'Prefetch', 'ShimCache', 'AmCache', etc.
    source_path: str          # Where the artifact was found
    description: str          # Human-readable description
    confidence: float = 0.0   # 0.0 - 1.0 confidence level
    details: Dict[str, Any] = field(default_factory=dict)
    found: bool = True


class ArtifactCorrelator:
    """
    Cross-references files/processes with forensic artifacts.

    Usage:
        correlator = ArtifactCorrelator(vfs=vfs, db_path="case.db")
        results = correlator.correlate("chrome.exe")
    """

    # Windows artifact knowledge base
    WINDOWS_ARTIFACTS = {
        "Prefetch": {
            "paths": ["/Windows/Prefetch"],
            "pattern": "{name}-*.pf",
            "description": "Application execution history (last 8 runs)",
        },
        "ShimCache": {
            "paths": ["/Windows/System32/config/SYSTEM"],
            "pattern": None,
            "description": "Application compatibility cache (execution evidence)",
        },
        "AmCache": {
            "paths": ["/Windows/AppCompat/Programs/Amcache.hve"],
            "pattern": None,
            "description": "Application installation and first-run data",
        },
        "MUICache": {
            "paths": ["/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat"],
            "pattern": None,
            "description": "Application display name cache",
        },
        "UserAssist": {
            "paths": ["/Users/*/NTUSER.DAT"],
            "pattern": None,
            "description": "Application GUI execution counts and timestamps",
        },
        "BAM/DAM": {
            "paths": ["/Windows/System32/config/SYSTEM"],
            "pattern": None,
            "description": "Background/Desktop Activity Moderator (execution evidence)",
        },
        "Jump Lists": {
            "paths": ["/Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations"],
            "pattern": None,
            "description": "Task bar pinned application activity",
        },
        "LNK Files": {
            "paths": ["/Users/*/AppData/Roaming/Microsoft/Windows/Recent"],
            "pattern": "*.lnk",
            "description": "Shortcut files tracking file access",
        },
        "Event Logs": {
            "paths": ["/Windows/System32/winevt/Logs"],
            "pattern": "*.evtx",
            "description": "Windows event log records",
        },
        "Recycle Bin": {
            "paths": ["/$Recycle.Bin"],
            "pattern": None,
            "description": "Deleted file recovery data",
        },
    }

    def __init__(
        self,
        vfs: Any = None,
        db_path: Optional[str] = None,
    ) -> None:
        self.vfs = vfs
        self.db_path = db_path

    def correlate(self, target: str) -> List[CorrelationResult]:
        """
        Find all artifacts related to a file or process name.

        Args:
            target: Filename or process name to correlate.

        Returns:
            List of CorrelationResult objects.
        """
        target_name = os.path.basename(target).lower()
        results = []

        for artifact_name, artifact_info in self.WINDOWS_ARTIFACTS.items():
            result = self._check_artifact(artifact_name, artifact_info, target_name)
            results.append(result)

        # Also check database for pre-parsed artifacts
        if self.db_path:
            db_results = self._query_db_artifacts(target_name)
            results.extend(db_results)

        return results

    def correlate_user(self, username: str) -> List[CorrelationResult]:
        """Find artifacts related to a specific user."""
        results = []
        user_paths = [
            f"/Users/{username}",
            f"/Users/{username}/NTUSER.DAT",
            f"/Users/{username}/AppData",
        ]

        for path in user_paths:
            if self.vfs:
                try:
                    node = self.vfs._node_at(path)
                    if node:
                        results.append(CorrelationResult(
                            artifact_type="User Profile",
                            source_path=path,
                            description=f"User profile directory for {username}",
                            confidence=1.0,
                            found=True,
                        ))
                except Exception:
                    pass

        return results

    def _check_artifact(
        self,
        name: str,
        info: Dict,
        target_name: str,
    ) -> CorrelationResult:
        """Check a single artifact type in the VFS."""
        if not self.vfs:
            return CorrelationResult(
                artifact_type=name,
                source_path="",
                description=info["description"],
                found=False,
            )

        for base_path in info["paths"]:
            # Handle wildcard user paths
            paths_to_check = self._expand_wildcards(base_path)

            for check_path in paths_to_check:
                try:
                    node = self.vfs._node_at(check_path)
                    if node:
                        return CorrelationResult(
                            artifact_type=name,
                            source_path=check_path,
                            description=info["description"],
                            confidence=0.8 if node.is_dir else 1.0,
                            found=True,
                        )
                except Exception:
                    continue

        return CorrelationResult(
            artifact_type=name,
            source_path="",
            description=info["description"],
            found=False,
        )

    def _expand_wildcards(self, path: str) -> List[str]:
        """Expand wildcard (*) in paths."""
        if "*" not in path:
            return [path]

        paths = []
        parts = path.split("*")
        base = parts[0].rstrip("/")

        if self.vfs:
            try:
                items = self.vfs.list_dir(base)
                for item in items[:20]:
                    expanded = base + "/" + item + ("/" + parts[1].lstrip("/") if len(parts) > 1 else "")
                    paths.append(expanded)
            except Exception:
                pass

        if not paths:
            # Fallback: common usernames
            for user in ["Administrator", "Default", "Public", "User"]:
                paths.append(path.replace("*", user))

        return paths

    def _query_db_artifacts(self, target_name: str) -> List[CorrelationResult]:
        """Query pre-parsed artifacts from the case database."""
        results = []
        if not self.db_path or not os.path.exists(self.db_path):
            return results

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='artifacts'"
            )
            if cur.fetchone():
                cur.execute(
                    "SELECT * FROM artifacts WHERE name LIKE ? LIMIT 50",
                    (f"%{target_name}%",),
                )
                for row in cur.fetchall():
                    results.append(CorrelationResult(
                        artifact_type=row.get("type", "Unknown"),
                        source_path=row.get("path", ""),
                        description=row.get("description", ""),
                        confidence=float(row.get("confidence", 0.5)),
                        found=True,
                    ))

            conn.close()
        except Exception:
            pass

        return results
