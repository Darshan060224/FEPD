"""
FEPD - Evidence Manager
=========================

Central manager for all loaded evidence in a case.
Tracks EvidenceImage objects with their partitions and VEOS drives.

Used by:
  - Files tab (browse evidence)
  - Artifacts tab (enumerate forensic artifacts)
  - Timeline tab (aggregate timestamps)
  - Terminal (evidence commands)
  - ML Analytics (feature extraction)

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models.evidence_image import EvidenceImage, ImageFormat, ImageStatus, ImageType
from ..models.partition import Partition, FilesystemType, PartitionRole

logger = logging.getLogger(__name__)


class EvidenceManager:
    """
    In-memory registry of evidence loaded into the current case.

    Responsibilities:
      - Store / retrieve EvidenceImage + Partition records
      - Check readiness (is any evidence loaded?)
      - Load state from and save state to case.db
      - Provide lookup by evidence ID
    """

    def __init__(self, case_path: Optional[Path] = None) -> None:
        self.case_path = Path(case_path) if case_path else None
        self._images: Dict[str, EvidenceImage] = {}        # evidence_id → image
        self._partitions: Dict[str, List[Partition]] = {}  # evidence_id → partitions

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        """True if at least one evidence image is loaded successfully."""
        return any(img.is_loaded for img in self._images.values())

    @property
    def images(self) -> List[EvidenceImage]:
        """All registered evidence images."""
        return list(self._images.values())

    @property
    def loaded_images(self) -> List[EvidenceImage]:
        """Only images with status == LOADED."""
        return [img for img in self._images.values() if img.is_loaded]

    @property
    def count(self) -> int:
        return len(self._images)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def register(
        self,
        evidence: EvidenceImage,
        partitions: Optional[List[Partition]] = None,
    ) -> None:
        """Register a new evidence image (and its partitions)."""
        self._images[evidence.evidence_id] = evidence
        if partitions:
            self._partitions[evidence.evidence_id] = partitions
        logger.info(
            "Evidence registered: %s (%s, %s)",
            evidence.name,
            evidence.evidence_id,
            evidence.status.value,
        )

    def unregister(self, evidence_id: str) -> None:
        """Remove an evidence image."""
        self._images.pop(evidence_id, None)
        self._partitions.pop(evidence_id, None)

    def get_image(self, evidence_id: str) -> Optional[EvidenceImage]:
        """Retrieve by evidence ID."""
        return self._images.get(evidence_id)

    def get_partitions(self, evidence_id: str) -> List[Partition]:
        """Retrieve partitions for a given evidence image."""
        return self._partitions.get(evidence_id, [])

    def all_partitions(self) -> List[Partition]:
        """Flat list of all partitions across all images."""
        result: List[Partition] = []
        for parts in self._partitions.values():
            result.extend(parts)
        return result

    def all_veos_drives(self) -> List[str]:
        """All VEOS drive letters across all loaded images."""
        drives: List[str] = []
        for img in self._images.values():
            drives.extend(img.veos_drives)
        return drives

    # ------------------------------------------------------------------
    # Persistence (load from / save to case.db)
    # ------------------------------------------------------------------

    def load_from_db(self) -> None:
        """Load evidence and partition records from the case SQLite database."""
        if not self.case_path:
            return

        case_db = self.case_path / "case.db"
        if not case_db.exists():
            return

        conn = sqlite3.connect(str(case_db))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            # Load evidence images
            cursor.execute("SELECT * FROM evidence")
            for row in cursor.fetchall():
                evidence = EvidenceImage(
                    evidence_id=row["evidence_id"],
                    name=row.get("name", Path(row["source_path"]).name),
                    path=row["source_path"],
                    format=ImageFormat(row.get("format", "UNKNOWN")),
                    image_type=ImageType(row.get("image_type", "disk")),
                    size=row.get("size", 0),
                    sha256=row.get("hash", ""),
                    hash_verified=bool(row.get("hash_verified", 0)),
                    operator=row.get("operator", ""),
                    ingested_at=row.get("ingestion_date", ""),
                    mount_handler=row.get("mount_handler", ""),
                    veos_drives=json.loads(row.get("veos_drives", "[]")),
                    segments=json.loads(row.get("segments", "[]")),
                    status=ImageStatus(row.get("status", "Loaded")),
                )
                self._images[evidence.evidence_id] = evidence

            # Load partitions
            cursor.execute("SELECT * FROM partitions")
            for row in cursor.fetchall():
                p = Partition(
                    id=row["id"],
                    evidence_id=row["evidence_id"],
                    filesystem=FilesystemType(row.get("filesystem", "Unknown")),
                    size=row.get("size", 0),
                    start_offset=row.get("start_offset", 0),
                    mount_point=row.get("mount_point", ""),
                    description=row.get("description", ""),
                    role=PartitionRole(row.get("role", "Unknown")),
                )
                self._partitions.setdefault(p.evidence_id, []).append(p)

            logger.info(
                "Loaded %d evidence images and %d partitions from DB",
                len(self._images),
                sum(len(v) for v in self._partitions.values()),
            )

        except Exception as exc:
            logger.error("Failed to load evidence from DB: %s", exc)
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Summary for UI / Reports
    # ------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """Return a summary dict suitable for reports & dashboard."""
        return {
            "total_images": self.count,
            "loaded_images": len(self.loaded_images),
            "total_partitions": len(self.all_partitions()),
            "veos_drives": self.all_veos_drives(),
            "images": [img.to_dict() for img in self._images.values()],
        }
