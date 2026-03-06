"""
FEPD Evidence Module
======================
Evidence lifecycle management, image registry, and VEOS bridge.

Copyright (c) 2026 FEPD Development Team
"""

from .evidence_manager import EvidenceManager
from .image_registry import ImageRegistry

__all__ = [
    "EvidenceManager",
    "ImageRegistry",
]
