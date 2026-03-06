"""
FEPD - Filesystem Builder
============================

Mounts discovered partitions read-only and creates VEOS virtual drives.
This is the bridge between raw partition data and the Virtual Evidence OS.

Flow:
    List[Partition]  →  mount read-only  →  build VEOS drives  →  register

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models.evidence_image import EvidenceImage, ImageStatus
from ..models.partition import Partition, FilesystemType
from .image_loader import DiskHandle

logger = logging.getLogger(__name__)


# ============================================================================
# VEOS Drive Record (lightweight — the full VEOSDrive lives in src.core.veos)
# ============================================================================

class VEOSDriveInfo:
    """
    Lightweight record of a mounted VEOS drive.
    Used by the ingest pipeline; the full VEOSDrive / VirtualEvidenceOS
    classes in ``src.core.veos`` can consume these to build a complete OS view.
    """

    def __init__(
        self,
        letter: str,
        source_image: str,
        partition_index: int,
        filesystem: str,
        offset: int,
        size: int = 0,
    ) -> None:
        self.letter = letter
        self.source_image = source_image
        self.partition_index = partition_index
        self.filesystem = filesystem
        self.offset = offset
        self.size = size

    def to_dict(self) -> Dict[str, Any]:
        return {
            "letter": self.letter,
            "source_image": self.source_image,
            "partition_index": self.partition_index,
            "filesystem": self.filesystem,
            "offset": self.offset,
            "size": self.size,
        }

    def __repr__(self) -> str:
        return f"VEOSDriveInfo({self.letter}: {self.filesystem}, {self.size} bytes)"


# ============================================================================
# Filesystem Builder
# ============================================================================

class FilesystemBuilder:
    """
    Mounts partitions and creates VEOS drive mappings.

    All access is read-only.  No data is written to the evidence image.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(
        self,
        evidence: EvidenceImage,
        partitions: List[Partition],
        handle: DiskHandle,
    ) -> List[VEOSDriveInfo]:
        """
        Build VEOS drives from the discovered partitions.

        Updates ``evidence.veos_drives`` and ``evidence.status``.

        Returns:
            List of VEOSDriveInfo objects ready for the VEOS layer.
        """
        evidence.status = ImageStatus.BUILDING_VEOS
        drives: List[VEOSDriveInfo] = []

        for part in partitions:
            if not part.mount_point:
                continue

            drive = VEOSDriveInfo(
                letter=part.mount_point.rstrip(":"),
                source_image=evidence.path,
                partition_index=part.id,
                filesystem=part.filesystem.value,
                offset=part.start_offset,
                size=part.size,
            )
            drives.append(drive)

            logger.info(
                "VEOS drive %s: → Partition %d (%s, %s bytes, offset %d)",
                drive.letter,
                part.id,
                part.filesystem.value,
                f"{part.size:,}",
                part.start_offset,
            )

        # Attempt to build the pytsk3 FS_Info objects for each drive
        # so downstream systems can enumerate files.
        if handle.handler_type == "pytsk3" and handle.img_info is not None:
            self._attach_fs_info_objects(drives, handle)

        # Try to register with the real VEOS layer (if available)
        self._register_with_veos(evidence, drives)

        # Store on evidence
        evidence.veos_drives = [f"{d.letter}:" for d in drives]
        return drives

    # ------------------------------------------------------------------
    # pytsk3 filesystem handles
    # ------------------------------------------------------------------

    def _attach_fs_info_objects(
        self,
        drives: List[VEOSDriveInfo],
        handle: DiskHandle,
    ) -> None:
        """Attach pytsk3.FS_Info objects to the drives for file enumeration."""
        try:
            import pytsk3

            for drive in drives:
                try:
                    fs = pytsk3.FS_Info(handle.img_info, offset=drive.offset)
                    # Store on the drive for downstream use
                    setattr(drive, "_fs_info", fs)
                    logger.debug("FS_Info attached to %s:", drive.letter)
                except Exception as exc:
                    logger.debug("Could not attach FS_Info to %s: %s", drive.letter, exc)

        except ImportError:
            pass

    # ------------------------------------------------------------------
    # VEOS registration bridge
    # ------------------------------------------------------------------

    def _register_with_veos(
        self,
        evidence: EvidenceImage,
        drives: List[VEOSDriveInfo],
    ) -> None:
        """
        Try to create real VEOSDrive objects in the core VEOS layer.
        Gracefully skips if the VEOS module internals aren't available.
        """
        try:
            from ..core.veos import VEOSDrive  # type: ignore[attr-defined]

            for d in drives:
                VEOSDrive(
                    letter=d.letter,
                    source_image=d.source_image,
                    partition_index=d.partition_index,
                    filesystem=d.filesystem,
                    offset=d.offset,
                )
            logger.debug("Registered %d drives with core VEOS layer", len(drives))
        except Exception:
            # Not critical — the ingest pipeline still works without it
            logger.debug("Core VEOS registration skipped (module not available)")
