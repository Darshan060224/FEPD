"""
FEPD - Ingest Controller
===========================

Orchestrates the full ingestion pipeline:

    1. Case validation
    2. Image loading (format detection + open)
    3. SHA-256 hash verification
    4. Partition discovery
    5. Filesystem / VEOS build
    6. Evidence metadata persistence
    7. Signal: Files tab enabled

This is the single entry-point called by the UI.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..models.evidence_image import EvidenceImage, ImageStatus
from ..models.partition import Partition
from .image_loader import ImageLoader, DiskHandle
from .hash_verifier import HashVerifier, ProgressCallback
from .partition_scanner import PartitionScanner
from .filesystem_builder import FilesystemBuilder, VEOSDriveInfo

try:
    from ..modules.forensic_detection_pipeline import run_forensic_detection_pipeline
    FORENSIC_DETECTION_AVAILABLE = True
except Exception:
    FORENSIC_DETECTION_AVAILABLE = False

logger = logging.getLogger(__name__)


# ============================================================================
# Result container
# ============================================================================

class IngestResult:
    """
    Outcome of a single image ingestion run.

    Attributes:
        success:     Whether the pipeline completed without error.
        evidence:    The EvidenceImage (with all fields populated).
        partitions:  Discovered partitions.
        drives:      VEOS drive records.
        elapsed:     Wall-clock seconds for the full pipeline.
        error:       Error message if ``success`` is False.
    """

    def __init__(self) -> None:
        self.success: bool = False
        self.evidence: Optional[EvidenceImage] = None
        self.partitions: List[Partition] = []
        self.drives: List[VEOSDriveInfo] = []
        self.elapsed: float = 0.0
        self.error: str = ""
        self.forensic_detection_output: str = ""
        self.forensic_detection_summary: Dict[str, Any] = {}
        self.forensic_detection_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "evidence": self.evidence.to_dict() if self.evidence else {},
            "partitions": [p.to_dict() for p in self.partitions],
            "drives": [d.to_dict() for d in self.drives],
            "elapsed": self.elapsed,
            "error": self.error,
            "forensic_detection_output": self.forensic_detection_output,
            "forensic_detection_summary": self.forensic_detection_summary,
            "forensic_detection_error": self.forensic_detection_error,
        }


# ============================================================================
# Ingest Controller
# ============================================================================

class IngestController:
    """
    Runs the full ingestion pipeline for a single evidence image.

    Usage (from a QThread or background worker)::

        ctrl = IngestController(case_path=Path("cases/case-001"))
        result = ctrl.run(image_path, expected_hash, on_progress, is_cancelled)
        if result.success:
            # enable Files tab, update UI table, etc.
    """

    def __init__(
        self,
        case_path: Optional[Path] = None,
        operator: str = "",
        auto_run_forensic_detection: bool = True,
    ) -> None:
        self.case_path = case_path
        self.operator = operator or os.getenv("USERNAME", os.getenv("USER", "unknown"))
        self.auto_run_forensic_detection = auto_run_forensic_detection

        # Sub-modules
        self._loader = ImageLoader()
        self._hasher = HashVerifier()
        self._scanner = PartitionScanner()
        self._builder = FilesystemBuilder()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        image_path: str | Path,
        expected_hash: Optional[str] = None,
        on_progress: Optional[ProgressCallback] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> IngestResult:
        """
        Execute the full ingestion pipeline and return an IngestResult.

        Pipeline stages:
          1. Validate → 2. Load → 3. Hash → 4. Partitions → 5. VEOS → 6. Persist

        Args:
            image_path:     Path to the forensic image file.
            expected_hash:  Optional SHA-256 for verification.
            on_progress:    Callback(pct, msg, speed, eta).
            is_cancelled:   Callable that returns True when the user cancels.
        """
        result = IngestResult()
        t0 = time.time()

        # ── Prepare EvidenceImage model ──
        evidence = EvidenceImage.from_path(image_path)
        evidence.operator = self.operator
        evidence.expected_hash = expected_hash or None
        result.evidence = evidence

        handle: Optional[DiskHandle] = None

        try:
            # ── Step 1: Validate format ──
            self._emit(on_progress, 5, "Validating image format…")
            if not self._loader.validate(evidence):
                result.error = evidence.error_message
                return result

            # ── Step 2: Open image ──
            self._emit(on_progress, 10, "Loading image (read-only)…")
            handle = self._loader.load(evidence)

            # ── Step 3: Hash ──
            self._emit(on_progress, 15, "Computing SHA-256…")
            hash_ok = self._hasher.compute_and_verify(
                evidence,
                on_progress=self._wrap_hash_progress(on_progress),
                is_cancelled=is_cancelled,
            )
            if not hash_ok:
                result.error = evidence.error_message
                return result

            # ── Step 4: Partition discovery ──
            self._emit(on_progress, 60, "Discovering partitions…")
            partitions = self._scanner.scan(evidence, handle)
            result.partitions = partitions

            # ── Step 5: Build VEOS ──
            self._emit(on_progress, 75, "Building VEOS virtual drives…")
            drives = self._builder.build(evidence, partitions, handle)
            result.drives = drives

            # ── Step 6: Persist metadata ──
            self._emit(on_progress, 90, "Saving evidence metadata…")
            self._persist_metadata(evidence, partitions, drives)

            # ── Step 7: Forensic detection pipeline ──
            if self.auto_run_forensic_detection and FORENSIC_DETECTION_AVAILABLE:
                self._emit(on_progress, 93, "Running forensic detection pipeline…")
                self._run_forensic_detection(result, evidence, on_progress)

            # ── Done ──
            evidence.status = ImageStatus.LOADED
            evidence.ingestion_time = time.time() - t0
            result.elapsed = evidence.ingestion_time
            result.success = True

            self._emit(
                on_progress,
                100,
                f"Ingestion complete! ({result.elapsed:.1f}s)",
            )
            logger.info(
                "Ingestion complete: %s in %.1fs — %d partitions, %d drives",
                evidence.name,
                result.elapsed,
                len(partitions),
                len(drives),
            )

        except Exception as exc:
            evidence.status = ImageStatus.ERROR
            evidence.error_message = str(exc)
            result.error = str(exc)
            logger.error("Ingestion failed: %s", exc, exc_info=True)

        finally:
            if handle is not None:
                handle.close()

        result.elapsed = time.time() - t0
        return result

    # ------------------------------------------------------------------
    # Metadata persistence (SQLite)
    # ------------------------------------------------------------------

    def _persist_metadata(
        self,
        evidence: EvidenceImage,
        partitions: List[Partition],
        drives: List[VEOSDriveInfo],
    ) -> None:
        """Save evidence record into the case SQLite database."""
        if not self.case_path:
            return

        case_db = self.case_path / "case.db"
        conn = sqlite3.connect(str(case_db))
        cursor = conn.cursor()

        # Ensure table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id   TEXT PRIMARY KEY,
                source_path   TEXT NOT NULL,
                name          TEXT,
                format        TEXT,
                image_type    TEXT,
                size          INTEGER,
                hash          TEXT,
                hash_algorithm TEXT DEFAULT 'SHA256',
                hash_verified INTEGER DEFAULT 0,
                ingestion_date TEXT,
                operator      TEXT,
                partition_count INTEGER,
                veos_drives   TEXT,
                mount_handler TEXT,
                segments      TEXT,
                status        TEXT
            )
        """)

        # Ensure partitions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS partitions (
                id            INTEGER,
                evidence_id   TEXT,
                filesystem    TEXT,
                size          INTEGER,
                start_offset  INTEGER,
                mount_point   TEXT,
                description   TEXT,
                role          TEXT,
                PRIMARY KEY (evidence_id, id)
            )
        """)

        # Upsert evidence
        cursor.execute("""
            INSERT OR REPLACE INTO evidence (
                evidence_id, source_path, name, format, image_type, size,
                hash, hash_algorithm, hash_verified, ingestion_date,
                operator, partition_count, veos_drives, mount_handler,
                segments, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            evidence.evidence_id,
            evidence.path,
            evidence.name,
            evidence.format.value,
            evidence.image_type.value,
            evidence.size,
            evidence.sha256,
            "SHA256",
            1 if evidence.hash_verified else 0,
            evidence.ingested_at,
            evidence.operator,
            len(partitions),
            json.dumps(evidence.veos_drives),
            evidence.mount_handler,
            json.dumps(evidence.segments),
            evidence.status.value,
        ))

        # Upsert partitions
        for p in partitions:
            cursor.execute("""
                INSERT OR REPLACE INTO partitions
                    (id, evidence_id, filesystem, size, start_offset,
                     mount_point, description, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                p.id,
                evidence.evidence_id,
                p.filesystem.value,
                p.size,
                p.start_offset,
                p.mount_point,
                p.description,
                p.role.value,
            ))

        conn.commit()
        conn.close()
        logger.debug("Metadata persisted to %s", case_db)

    def _run_forensic_detection(
        self,
        result: IngestResult,
        evidence: EvidenceImage,
        on_progress: Optional[ProgressCallback],
    ) -> None:
        """Run post-ingestion forensic detection without failing ingestion on errors."""
        if not self.case_path:
            return

        if not FORENSIC_DETECTION_AVAILABLE:
            result.forensic_detection_error = "forensic_detection_pipeline_unavailable"
            return

        try:
            output_dir = self.case_path / "forensic_detection" / evidence.evidence_id
            memory_dump_path = self._resolve_case_memory_dump_path()
            pipeline_result = run_forensic_detection_pipeline(
                image_path=str(evidence.path),
                output_dir=str(output_dir),
                memory_dump=memory_dump_path,
                suspicious_ips=[],
            )

            result.forensic_detection_output = str(output_dir / "forensic_detection_results.json")
            result.forensic_detection_summary = pipeline_result.get("summary", {})

            self._persist_forensic_detection_run(
                evidence_id=evidence.evidence_id,
                output_path=result.forensic_detection_output,
                summary=result.forensic_detection_summary,
            )
            self._emit(on_progress, 98, "Forensic detection complete")

        except Exception as exc:
            result.forensic_detection_error = str(exc)
            logger.warning("Forensic detection pipeline failed: %s", exc, exc_info=True)

    def _resolve_case_memory_dump_path(self) -> Optional[str]:
        """Resolve optional memory dump path from case.json metadata or evidence DB."""
        if not self.case_path:
            return None

        # 1) case.json memory_dump.path
        case_json = self.case_path / "case.json"
        if case_json.exists():
            try:
                data = json.loads(case_json.read_text(encoding="utf-8"))
                memory_info = data.get("memory_dump", {}) if isinstance(data, dict) else {}
                raw_path = (memory_info.get("path") or "").strip() if isinstance(memory_info, dict) else ""
                if raw_path:
                    memory_path = Path(raw_path)
                    if memory_path.exists() and memory_path.is_file():
                        return str(memory_path)
                    logger.warning("Case memory dump path not found on disk: %s", raw_path)
            except Exception as exc:
                logger.warning("Failed to parse case.json memory dump path: %s", exc)

        # 2) evidence table fallback (supports memory added through ingest UI)
        case_db = self.case_path / "case.db"
        if not case_db.exists():
            return None

        try:
            conn = sqlite3.connect(str(case_db))
            cur = conn.cursor()
            cur.execute(
                """
                SELECT source_path
                FROM evidence
                WHERE LOWER(image_type) = 'memory'
                   OR UPPER(format) IN ('MEM', 'VMEM', 'MDDRAM')
                ORDER BY ingestion_date DESC
                """
            )
            rows = cur.fetchall()
            conn.close()

            for row in rows:
                raw = str(row[0] or "").strip()
                if not raw:
                    continue
                p = Path(raw)
                if p.exists() and p.is_file():
                    return str(p)

            return None
        except Exception as exc:
            logger.warning("Failed to resolve memory dump from case DB: %s", exc)
            return None

    def _persist_forensic_detection_run(
        self,
        evidence_id: str,
        output_path: str,
        summary: Dict[str, Any],
    ) -> None:
        """Persist forensic detection run metadata to the case database."""
        if not self.case_path:
            return

        case_db = self.case_path / "case.db"
        conn = sqlite3.connect(str(case_db))
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS forensic_detection_runs (
                evidence_id    TEXT PRIMARY KEY,
                output_path    TEXT,
                summary_json   TEXT,
                completed_at   TEXT
            )
        """)

        cursor.execute(
            """
            INSERT OR REPLACE INTO forensic_detection_runs
                (evidence_id, output_path, summary_json, completed_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                evidence_id,
                output_path,
                json.dumps(summary),
                datetime.utcnow().isoformat() + "Z",
            ),
        )

        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Progress helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _emit(
        cb: Optional[ProgressCallback],
        pct: int,
        msg: str,
        speed: float = 0.0,
        eta: float = 0.0,
    ) -> None:
        if cb:
            cb(pct, msg, speed, eta)

    @staticmethod
    def _wrap_hash_progress(
        outer: Optional[ProgressCallback],
    ) -> Optional[ProgressCallback]:
        """
        Map the hash verifier's 0-100 % range into the
        controller's 15-55 % slice of the overall pipeline.
        """
        if outer is None:
            return None

        def inner(pct: int, msg: str, speed: float, eta: float) -> None:
            mapped = 15 + int(pct * 0.45)   # 0 → 15,  100 → 60
            outer(mapped, msg, speed, eta)

        return inner
