"""
FEPD - Evidence Image Data Model
==================================

Represents a forensic evidence image (disk image, memory dump, etc.)
with all metadata needed for chain of custody, integrity verification,
and VEOS integration.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


# ============================================================================
# Enumerations
# ============================================================================

class ImageFormat(Enum):
    """Supported forensic image formats."""
    E01     = "E01"        # EnCase Evidence File
    E01_SEG = "E01_SEG"    # EnCase segmented (.E02, .E03, …)
    DD      = "DD"         # Raw disk dump
    RAW     = "RAW"        # Raw forensic image
    IMG     = "IMG"        # Generic disk image
    VMDK    = "VMDK"       # VMware virtual disk
    VHD     = "VHD"        # Hyper-V virtual disk
    QCOW2   = "QCOW2"     # QEMU copy-on-write
    AFF     = "AFF"        # Advanced Forensics Format
    MEM     = "MEM"        # Memory dump
    VMEM    = "VMEM"       # VMware memory file
    MDDRAM  = "MDDRAM"     # MDD RAM Image (.mddramimage)
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_extension(cls, ext: str) -> "ImageFormat":
        """Detect format from file extension."""
        mapping = {
            ".e01": cls.E01,
            ".001": cls.E01_SEG,
            ".dd":  cls.DD,
            ".raw": cls.RAW,
            ".img": cls.IMG,
            ".vmdk": cls.VMDK,
            ".vhd": cls.VHD,
            ".vhdx": cls.VHD,
            ".qcow2": cls.QCOW2,
            ".aff":  cls.AFF,
            ".mem":  cls.MEM,
            ".vmem": cls.VMEM,
            ".mddramimage": cls.MDDRAM,
        }
        return mapping.get(ext.lower(), cls.UNKNOWN)


class ImageStatus(Enum):
    """Current status of an evidence image in the pipeline."""
    PENDING       = "Pending"
    VALIDATING    = "Validating"
    HASHING       = "Hashing"
    HASH_VERIFIED = "Hash Verified"
    HASH_MISMATCH = "Hash Mismatch"
    MOUNTING      = "Mounting"
    SCANNING      = "Scanning Partitions"
    BUILDING_VEOS = "Building VEOS"
    LOADED        = "Loaded"
    ERROR         = "Error"


class ImageType(Enum):
    """Broad category of evidence image."""
    DISK   = "disk"
    MEMORY = "memory"


# ============================================================================
# Supported Extensions (quick lookup)
# ============================================================================

SUPPORTED_DISK_EXTENSIONS: set[str] = {
    ".e01", ".001", ".dd", ".raw", ".img",
    ".vmdk", ".vhd", ".vhdx", ".qcow2", ".aff",
}

SUPPORTED_MEMORY_EXTENSIONS: set[str] = {
    ".mem", ".vmem", ".mddramimage",
}

SUPPORTED_EXTENSIONS: set[str] = SUPPORTED_DISK_EXTENSIONS | SUPPORTED_MEMORY_EXTENSIONS

FORMAT_DESCRIPTIONS: Dict[str, str] = {
    ".e01":   "EnCase Evidence File",
    ".001":   "EnCase Segmented Evidence",
    ".dd":    "Raw Disk Image (dd)",
    ".raw":   "Raw Forensic Image",
    ".img":   "Disk Image File",
    ".vmdk":  "VMware Virtual Disk",
    ".vhd":   "Hyper-V Virtual Hard Disk",
    ".vhdx":  "Hyper-V Virtual Hard Disk v2",
    ".qcow2": "QEMU Copy-On-Write Image",
    ".aff":   "Advanced Forensics Format",
    ".mem":   "Physical Memory Dump",
    ".vmem":  "VMware Memory File",
    ".mddramimage": "MDD RAM Image (Physical Memory)",
}


# ============================================================================
# Data Model
# ============================================================================

@dataclass
class EvidenceImage:
    """
    Represents a single evidence image loaded into FEPD.

    Attributes:
        name:            Filename of the evidence image.
        path:            Absolute path on the host filesystem.
        size:            File size in bytes.
        format:          Detected image format (E01 / RAW / DD / …).
        image_type:      Broad category (disk / memory).
        sha256:          SHA-256 hash for integrity verification.
        expected_hash:   Optional hash provided by the investigator for comparison.
        hash_verified:   True if sha256 matches expected_hash.
        partitions:      List of partition IDs discovered within this image.
        veos_drives:     Drive letters assigned by VEOS (e.g., ["C:", "D:"]).
        status:          Current pipeline status.
        evidence_id:     A short unique identifier (first 16 hex of md5 of path).
        operator:        Who ingested this image.
        ingested_at:     ISO-8601 timestamp of ingestion.
        ingestion_time:  Wall-clock seconds taken for ingestion.
        mount_handler:   Backend used to mount ("pytsk3", "basic").
        segments:        For split images, list of segment paths.
        metadata:        Arbitrary additional metadata.
    """

    # Identity
    name: str = ""
    path: str = ""
    evidence_id: str = ""

    # Format
    format: ImageFormat = ImageFormat.UNKNOWN
    image_type: ImageType = ImageType.DISK
    size: int = 0

    # Integrity
    sha256: str = ""
    expected_hash: Optional[str] = None
    hash_verified: bool = False

    # Pipeline outputs
    partitions: List[int] = field(default_factory=list)
    veos_drives: List[str] = field(default_factory=list)
    status: ImageStatus = ImageStatus.PENDING
    error_message: str = ""

    # Operations metadata
    operator: str = ""
    ingested_at: str = ""
    ingestion_time: float = 0.0
    mount_handler: str = ""
    segments: List[str] = field(default_factory=list)

    # Extensible
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def from_path(cls, image_path: str | Path) -> "EvidenceImage":
        """Create an EvidenceImage from a file path (pre-ingestion)."""
        import hashlib

        p = Path(image_path)
        ext = p.suffix.lower()
        fmt = ImageFormat.from_extension(ext)
        img_type = (
            ImageType.MEMORY
            if ext in SUPPORTED_MEMORY_EXTENSIONS
            else ImageType.DISK
        )

        return cls(
            name=p.name,
            path=str(p.resolve()),
            evidence_id=hashlib.md5(str(p.resolve()).encode()).hexdigest()[:16],
            format=fmt,
            image_type=img_type,
            size=p.stat().st_size if p.exists() else 0,
            operator=os.getenv("USERNAME", os.getenv("USER", "unknown")),
            ingested_at=datetime.now().isoformat(),
            status=ImageStatus.PENDING,
        )

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def size_display(self) -> str:
        """Human-readable file size string."""
        return _format_size(self.size)

    @property
    def format_display(self) -> str:
        """Format name for UI display."""
        return self.format.value

    @property
    def hash_short(self) -> str:
        """First 32 hex chars of the SHA-256 for table display."""
        if not self.sha256:
            return "—"
        return self.sha256[:32] + "…"

    @property
    def is_loaded(self) -> bool:
        return self.status == ImageStatus.LOADED

    @property
    def is_error(self) -> bool:
        return self.status == ImageStatus.ERROR

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to plain dict (JSON-safe)."""
        d = asdict(self)
        d["format"] = self.format.value
        d["image_type"] = self.image_type.value
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceImage":
        """Deserialize from dict."""
        data = dict(data)
        data["format"] = ImageFormat(data.get("format", "UNKNOWN"))
        data["image_type"] = ImageType(data.get("image_type", "disk"))
        data["status"] = ImageStatus(data.get("status", "Pending"))
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ============================================================================
# Helpers
# ============================================================================

def _format_size(n: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.2f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.2f} PB"
