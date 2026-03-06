"""
FEPD - Image Loader
=====================

Detects forensic image format and opens it for read-only access.
Supports E01, RAW/DD, IMG, VMDK, QCOW2, AFF, MEM/VMEM.

Flow:
    image_path  →  detect format  →  open handler  →  return DiskHandle

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models.evidence_image import (
    EvidenceImage,
    ImageFormat,
    ImageStatus,
    ImageType,
    SUPPORTED_EXTENSIONS,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Image Handle (abstraction over pyewf / raw / basic)
# ============================================================================

class DiskHandle:
    """
    A thin wrapper around the opened disk image.

    Provides:
      - read-only access to the image bytes
      - image size
      - cleanup / close
    """

    def __init__(
        self,
        handler_type: str,
        img_info: Any = None,
        ewf_handle: Any = None,
        raw_handle: Any = None,
        image_size: int = 0,
    ) -> None:
        self.handler_type = handler_type      # "pytsk3" | "basic"
        self.img_info = img_info              # pytsk3.Img_Info (if available)
        self.ewf_handle = ewf_handle          # pyewf.handle (if E01)
        self.raw_handle = raw_handle          # open file handle (basic mode)
        self.image_size = image_size
        self.is_open = True

    def close(self) -> None:
        """Release all resources."""
        if self.ewf_handle is not None:
            try:
                self.ewf_handle.close()
            except Exception:
                pass
        if self.raw_handle is not None:
            try:
                self.raw_handle.close()
            except Exception:
                pass
        self.is_open = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ============================================================================
# Image Loader
# ============================================================================

class ImageLoader:
    """
    Loads a forensic evidence image for read-only analysis.

    Responsibilities:
      1. Validate that the file exists and the extension is supported.
      2. Open the image using the best available backend:
         - pytsk3 + pyewf  (preferred — full forensic support)
         - basic file I/O  (fallback)
      3. Return a DiskHandle for downstream pipeline steps.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, evidence: EvidenceImage) -> bool:
        """
        Validate that the image file exists and has a supported format.

        Updates ``evidence.status`` to VALIDATING or ERROR.
        Returns True if valid.
        """
        evidence.status = ImageStatus.VALIDATING

        path = Path(evidence.path)
        if not path.exists():
            evidence.status = ImageStatus.ERROR
            evidence.error_message = f"File not found: {evidence.path}"
            logger.error(evidence.error_message)
            return False

        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            evidence.status = ImageStatus.ERROR
            evidence.error_message = (
                f"Unsupported format: {path.suffix}\n"
                f"Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
            )
            logger.error(evidence.error_message)
            return False

        # Re-detect format (may have changed since from_path)
        evidence.format = ImageFormat.from_extension(path.suffix)
        logger.info("Image validated: %s (%s)", evidence.name, evidence.format.value)
        return True

    def load(self, evidence: EvidenceImage) -> DiskHandle:
        """
        Open the image read-only and return a DiskHandle.

        Updates ``evidence.status`` to MOUNTING → LOADED or ERROR.
        """
        evidence.status = ImageStatus.MOUNTING
        path = Path(evidence.path)

        # Detect segments for split E01 images
        segments = self._find_segments(path)
        evidence.segments = [str(s) for s in segments]

        # Attempt pytsk3/pyewf first
        handle = self._try_pytsk3(path, segments, evidence)
        if handle is not None:
            return handle

        # Fallback to basic file access
        return self._open_basic(path, evidence)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _find_segments(self, path: Path) -> List[Path]:
        """
        Find all segments for split images (E01→E02→…, 001→002→…).
        Returns a list with at least the primary file.
        """
        try:
            import pyewf
            filenames = pyewf.glob(str(path))
            return [Path(f) for f in filenames]
        except (ImportError, Exception):
            return [path]

    def _try_pytsk3(
        self,
        path: Path,
        segments: List[Path],
        evidence: EvidenceImage,
    ) -> Optional[DiskHandle]:
        """Attempt to open image with pytsk3 + pyewf."""
        try:
            import pytsk3

            ewf_handle = None

            if evidence.format in (ImageFormat.E01, ImageFormat.E01_SEG):
                import pyewf
                filenames = [str(s) for s in segments]
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)

                # pytsk3 requires an Img_Info-compatible wrapper
                img_info = _EWFImgInfo(ewf_handle)
            else:
                img_info = pytsk3.Img_Info(str(path))

            image_size = img_info.get_size()
            evidence.mount_handler = "pytsk3"

            logger.info(
                "Image opened via pytsk3: %s (%s bytes)",
                evidence.name,
                f"{image_size:,}",
            )

            return DiskHandle(
                handler_type="pytsk3",
                img_info=img_info,
                ewf_handle=ewf_handle,
                image_size=image_size,
            )

        except ImportError:
            logger.info("pytsk3/pyewf not installed — falling back to basic I/O")
            return None
        except Exception as exc:
            logger.warning("pytsk3 open failed (%s) — falling back", exc)
            return None

    def _open_basic(self, path: Path, evidence: EvidenceImage) -> DiskHandle:
        """Open with plain file I/O (no partition / filesystem support)."""
        try:
            image_size = path.stat().st_size
            evidence.mount_handler = "basic"
            logger.info("Image opened in basic mode: %s", evidence.name)

            return DiskHandle(
                handler_type="basic",
                raw_handle=None,    # we don't actually hold an open fd
                image_size=image_size,
            )
        except Exception as exc:
            evidence.status = ImageStatus.ERROR
            evidence.error_message = f"Failed to open image: {exc}"
            logger.error(evidence.error_message)
            raise


# ============================================================================
# pytsk3-compatible EWF wrapper
# ============================================================================

class _EWFImgInfo:
    """Wraps a pyewf.handle so pytsk3 can read from it."""

    def __init__(self, ewf_handle) -> None:
        self._handle = ewf_handle
        self._size = ewf_handle.get_media_size()

    def get_size(self) -> int:
        return self._size

    def read(self, offset: int, length: int) -> bytes:
        self._handle.seek(offset)
        return self._handle.read(length)

    def close(self) -> None:
        self._handle.close()
