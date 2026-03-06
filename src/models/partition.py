"""
FEPD - Partition Data Model
==============================

Represents a single partition discovered within a forensic evidence image.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Optional


# ============================================================================
# Enumerations
# ============================================================================

class FilesystemType(Enum):
    """Detected filesystem type."""
    NTFS    = "NTFS"
    FAT32   = "FAT32"
    FAT16   = "FAT16"
    FAT12   = "FAT12"
    EXFAT   = "exFAT"
    EXT4    = "ext4"
    EXT3    = "ext3"
    EXT2    = "ext2"
    APFS    = "APFS"
    HFS_PLUS = "HFS+"
    XFS     = "XFS"
    BTRFS   = "Btrfs"
    SWAP    = "swap"
    RAW     = "RAW"
    UNKNOWN = "Unknown"

    @classmethod
    def from_tsk(cls, tsk_type) -> "FilesystemType":
        """Map pytsk3 filesystem type enum to FilesystemType."""
        mapping = {
            "TSK_FS_TYPE_NTFS":   cls.NTFS,
            "TSK_FS_TYPE_FAT32":  cls.FAT32,
            "TSK_FS_TYPE_FAT16":  cls.FAT16,
            "TSK_FS_TYPE_FAT12":  cls.FAT12,
            "TSK_FS_TYPE_EXFAT":  cls.EXFAT,
            "TSK_FS_TYPE_EXT4":   cls.EXT4,
            "TSK_FS_TYPE_EXT3":   cls.EXT3,
            "TSK_FS_TYPE_EXT2":   cls.EXT2,
            "TSK_FS_TYPE_HFS":    cls.HFS_PLUS,
            "TSK_FS_TYPE_APFS":   cls.APFS,
        }
        tsk_str = str(tsk_type)
        for key_prefix, fs_type in mapping.items():
            if key_prefix in tsk_str:
                return fs_type
        return cls.UNKNOWN


class PartitionRole(Enum):
    """High-level role inferred from partition metadata."""
    SYSTEM   = "System"
    DATA     = "Data"
    RECOVERY = "Recovery"
    EFI      = "EFI System Partition"
    SWAP     = "Swap / Pagefile"
    UNKNOWN  = "Unknown"


# ============================================================================
# Data Model
# ============================================================================

@dataclass
class Partition:
    """
    Represents one partition found inside a forensic disk image.

    Attributes:
        id:              Partition index (0-based).
        filesystem:      Detected filesystem type.
        size:            Partition size in bytes.
        size_display:    Human-readable size string (set on creation).
        mount_point:     Assigned VEOS mount point (e.g., "C:").
        start_offset:    Byte offset from start of image.
        description:     Description from the partition table.
        flags:           Partition flags as string.
        role:            Inferred role (System / Data / Recovery / …).
        evidence_id:     ID of the parent EvidenceImage.
        metadata:        Arbitrary extra metadata.
    """

    id: int = 0
    filesystem: FilesystemType = FilesystemType.UNKNOWN
    size: int = 0
    size_display: str = ""
    mount_point: str = ""
    start_offset: int = 0
    description: str = ""
    flags: str = ""
    role: PartitionRole = PartitionRole.UNKNOWN
    evidence_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Post-init: fill derived fields
    # ------------------------------------------------------------------

    def __post_init__(self) -> None:
        if not self.size_display and self.size > 0:
            self.size_display = _format_size(self.size)
        if self.role == PartitionRole.UNKNOWN:
            self.role = self._infer_role()

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def from_tsk_partition(
        cls,
        part,               # pytsk3 partition object
        block_size: int,
        evidence_id: str = "",
    ) -> "Partition":
        """Create a Partition from a pytsk3 Volume_Info partition entry."""
        size_bytes = part.len * block_size
        desc = part.desc.decode("utf-8", errors="ignore") if hasattr(part, "desc") else ""

        return cls(
            id=part.addr,
            size=size_bytes,
            start_offset=part.start * block_size,
            description=desc,
            flags=str(getattr(part, "flags", "")),
            evidence_id=evidence_id,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Partition":
        """Deserialize from dict."""
        data = dict(data)
        data["filesystem"] = FilesystemType(data.get("filesystem", "Unknown"))
        data["role"] = PartitionRole(data.get("role", "Unknown"))
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["filesystem"] = self.filesystem.value
        d["role"] = self.role.value
        return d

    # ------------------------------------------------------------------
    # Inference helpers
    # ------------------------------------------------------------------

    def _infer_role(self) -> PartitionRole:
        """Infer partition role from description and flags."""
        desc_lower = self.description.lower()
        if "efi" in desc_lower or "esp" in desc_lower:
            return PartitionRole.EFI
        if "recovery" in desc_lower:
            return PartitionRole.RECOVERY
        if "swap" in desc_lower or self.filesystem == FilesystemType.SWAP:
            return PartitionRole.SWAP
        if self.filesystem in (FilesystemType.NTFS, FilesystemType.APFS, FilesystemType.EXT4):
            if self.size > 10 * 1024 ** 3:  # >10 GB → likely system/data
                return PartitionRole.SYSTEM
        if self.size > 0:
            return PartitionRole.DATA
        return PartitionRole.UNKNOWN


# ============================================================================
# Helpers
# ============================================================================

def _format_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.2f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.2f} PB"
