"""
FEPD - Image Registry
=======================

Global registry that tracks which evidence images have been ingested
across all cases.  Prevents duplicate ingestion and supports
cross-case evidence lookup.

Storage: JSON file at ``<cases_dir>/.image_registry.json``.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ImageRegistry:
    """
    Persistent global registry of ingested evidence images.

    Keyed by SHA-256 hash.  Stores which case each image belongs to,
    along with name, format, and ingestion timestamp.
    """

    def __init__(self, cases_dir: Optional[Path] = None) -> None:
        self.cases_dir = Path(cases_dir or "cases")
        self._registry_path = self.cases_dir / ".image_registry.json"
        self._data: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_duplicate(self, sha256: str) -> Optional[Dict[str, Any]]:
        """
        Check if an image with this hash has already been ingested.

        Returns:
            Registry record dict if duplicate, or None.
        """
        return self._data.get(sha256.lower())

    def register(
        self,
        sha256: str,
        case_id: str,
        name: str,
        image_format: str = "",
        evidence_id: str = "",
    ) -> None:
        """Register a newly ingested evidence image."""
        self._data[sha256.lower()] = {
            "case_id": case_id,
            "evidence_name": name,
            "evidence_id": evidence_id,
            "format": image_format,
            "registered_at": datetime.now().isoformat(),
        }
        self._save()
        logger.info("Image registered: %s (case %s)", name, case_id)

    def unregister(self, sha256: str) -> None:
        """Remove an image from the registry."""
        self._data.pop(sha256.lower(), None)
        self._save()

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        """Return a copy of all registry entries."""
        return dict(self._data)

    def count(self) -> int:
        return len(self._data)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self._registry_path.exists():
            try:
                self._data = json.loads(self._registry_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning("Failed to load image registry: %s", exc)
                self._data = {}

    def _save(self) -> None:
        try:
            self._registry_path.parent.mkdir(parents=True, exist_ok=True)
            self._registry_path.write_text(
                json.dumps(self._data, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.error("Failed to save image registry: %s", exc)
