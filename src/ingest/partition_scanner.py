"""
FEPD - Partition Scanner
==========================

Scans a loaded disk image for partitions and detects filesystems.
Uses pytsk3 Volume_Info when available; falls back to a single
whole-image pseudo-partition.

Flow:
    DiskHandle  →  scan partition table  →  detect filesystem  →  List[Partition]

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from ..models.evidence_image import EvidenceImage, ImageFormat, ImageStatus
from ..models.partition import Partition, FilesystemType, PartitionRole
from .image_loader import DiskHandle

logger = logging.getLogger(__name__)


# Drive-letter assignment sequence
_DRIVE_LETTERS = list("CDEFGHIJKLMNOPQRSTUVWXYZ")


class PartitionScanner:
    """
    Discovers partitions inside a forensic disk image
    and assigns preliminary VEOS drive letters.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        evidence: EvidenceImage,
        handle: DiskHandle,
    ) -> List[Partition]:
        """
        Scan the opened image for partitions.

        Updates ``evidence.status`` and ``evidence.partitions``.

        Returns:
            List of discovered Partition objects.
        """
        evidence.status = ImageStatus.SCANNING

        if handle.handler_type == "pytsk3" and handle.img_info is not None:
            partitions = self._scan_with_pytsk3(handle, evidence)
        else:
            partitions = self._fallback_partition(evidence, handle)

        # Store partition IDs on the evidence image
        evidence.partitions = [p.id for p in partitions]
        logger.info(
            "Partitions discovered: %d  (%s)",
            len(partitions),
            evidence.name,
        )
        return partitions

    # ------------------------------------------------------------------
    # pytsk3 scanning
    # ------------------------------------------------------------------

    def _scan_with_pytsk3(
        self,
        handle: DiskHandle,
        evidence: EvidenceImage,
    ) -> List[Partition]:
        """Use pytsk3 Volume_Info to enumerate partitions."""
        import pytsk3  # guaranteed available if handler_type == "pytsk3"

        img_info = handle.img_info
        partitions: List[Partition] = []
        letter_idx = 0

        try:
            volume = pytsk3.Volume_Info(img_info)
            block_size = volume.info.block_size

            for part in volume:
                if part.len <= 0:
                    continue

                p = Partition.from_tsk_partition(
                    part,
                    block_size=block_size,
                    evidence_id=evidence.evidence_id,
                )

                # Try to detect filesystem at this offset
                p.filesystem = self._detect_filesystem(img_info, p.start_offset)

                # Assign drive letter
                if letter_idx < len(_DRIVE_LETTERS):
                    p.mount_point = f"{_DRIVE_LETTERS[letter_idx]}:"
                    letter_idx += 1

                partitions.append(p)

        except Exception:
            # No volume system — try direct filesystem
            logger.info("No volume system, attempting direct filesystem access")
            partitions = self._try_direct_filesystem(img_info, evidence, handle)

        return partitions

    def _detect_filesystem(self, img_info, offset: int) -> FilesystemType:
        """Detect the filesystem at a given byte offset."""
        try:
            import pytsk3
            fs_info = pytsk3.FS_Info(img_info, offset=offset)
            return FilesystemType.from_tsk(fs_info.info.ftype)
        except Exception:
            return FilesystemType.UNKNOWN

    def _try_direct_filesystem(
        self,
        img_info,
        evidence: EvidenceImage,
        handle: DiskHandle,
    ) -> List[Partition]:
        """If there's no volume system, treat entire image as one partition."""
        try:
            import pytsk3
            fs_info = pytsk3.FS_Info(img_info)
            fs_type = FilesystemType.from_tsk(fs_info.info.ftype)
        except Exception:
            fs_type = FilesystemType.UNKNOWN

        return [
            Partition(
                id=0,
                filesystem=fs_type,
                size=handle.image_size,
                start_offset=0,
                description="Entire image (no partition table)",
                mount_point="C:",
                evidence_id=evidence.evidence_id,
            )
        ]

    # ------------------------------------------------------------------
    # Fallback (no pytsk3)
    # ------------------------------------------------------------------

    def _fallback_partition(
        self,
        evidence: EvidenceImage,
        handle: DiskHandle,
    ) -> List[Partition]:
        """Create a single pseudo-partition when pytsk3 is unavailable."""
        logger.warning("pytsk3 unavailable — creating pseudo-partition")
        return [
            Partition(
                id=0,
                filesystem=FilesystemType.UNKNOWN,
                size=handle.image_size,
                start_offset=0,
                description="Disk Image (partition discovery unavailable)",
                flags="basic_mode",
                mount_point="C:",
                role=PartitionRole.DATA,
                evidence_id=evidence.evidence_id,
            )
        ]
