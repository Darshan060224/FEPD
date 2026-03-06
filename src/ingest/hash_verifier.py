"""
FEPD - Hash Verifier
======================

Computes cryptographic hashes (SHA-256) for forensic integrity verification.
Supports progress reporting and optional expected-hash comparison.

Flow:
    image_path  →  SHA-256 (with progress)  →  compare expected  →  result

Purpose:
  - Integrity verification
  - Court admissibility
  - Chain of custody

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Callable, Optional

from ..models.evidence_image import EvidenceImage, ImageStatus

logger = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================

HASH_BUFFER_SIZE: int = 8 * 1024 * 1024  # 8 MB chunks
PROGRESS_INTERVAL_SEC: float = 0.5        # report progress every 500 ms


# ============================================================================
# Callback signature
# ============================================================================
# progress_callback(percent: int, message: str, speed_mb_s: float, eta_sec: float)
ProgressCallback = Callable[[int, str, float, float], None]


# ============================================================================
# Hash Verifier
# ============================================================================

class HashVerifier:
    """
    Computes SHA-256 for a forensic evidence image
    and optionally verifies against an expected hash.

    Usage:
        verifier = HashVerifier()
        ok = verifier.compute_and_verify(evidence, progress_fn, cancel_fn)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute_and_verify(
        self,
        evidence: EvidenceImage,
        on_progress: Optional[ProgressCallback] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> bool:
        """
        Compute SHA-256 hash, store it on *evidence*, and verify
        against expected_hash if provided.

        Updates ``evidence.sha256``, ``evidence.hash_verified``,
        and ``evidence.status``.

        Returns:
            True if hash was computed (and verified if expected).
            False if verification failed or cancelled.
        """
        evidence.status = ImageStatus.HASHING
        path = Path(evidence.path)

        if not path.exists():
            evidence.status = ImageStatus.ERROR
            evidence.error_message = f"Hash: file not found: {path}"
            return False

        total_size = path.stat().st_size
        sha256 = hashlib.sha256()
        bytes_read = 0
        t_start = time.time()
        t_last = t_start
        bytes_last = 0

        try:
            with open(path, "rb") as f:
                while True:
                    # Check cancellation
                    if is_cancelled and is_cancelled():
                        evidence.status = ImageStatus.ERROR
                        evidence.error_message = "Hashing cancelled by user"
                        return False

                    chunk = f.read(HASH_BUFFER_SIZE)
                    if not chunk:
                        break

                    sha256.update(chunk)
                    bytes_read += len(chunk)

                    # Periodic progress update
                    now = time.time()
                    if on_progress and (now - t_last) >= PROGRESS_INTERVAL_SEC:
                        pct = int((bytes_read / total_size) * 100) if total_size else 0
                        dt = now - t_last
                        db = bytes_read - bytes_last
                        speed = (db / (1024 ** 2)) / dt if dt > 0 else 0.0
                        remaining = total_size - bytes_read
                        eta = (remaining / (db / dt)) if db > 0 else 0.0

                        msg = (
                            f"Hashing: {bytes_read / (1024**3):.2f} GB / "
                            f"{total_size / (1024**3):.2f} GB  "
                            f"({speed:.1f} MB/s, ~{eta:.0f}s remaining)"
                        )
                        on_progress(pct, msg, speed, eta)

                        t_last = now
                        bytes_last = bytes_read

        except Exception as exc:
            evidence.status = ImageStatus.ERROR
            evidence.error_message = f"Hash computation failed: {exc}"
            logger.error(evidence.error_message, exc_info=True)
            return False

        # Store hash
        evidence.sha256 = sha256.hexdigest()
        logger.info("SHA-256: %s  (%s)", evidence.sha256, evidence.name)

        # Report 100 %
        elapsed = time.time() - t_start
        if on_progress:
            on_progress(100, f"Hash complete ({elapsed:.1f}s)", 0.0, 0.0)

        # Verify against expected hash (if provided)
        if evidence.expected_hash:
            if evidence.sha256.lower() == evidence.expected_hash.strip().lower():
                evidence.hash_verified = True
                evidence.status = ImageStatus.HASH_VERIFIED
                logger.info("Hash VERIFIED against expected value.")
                return True
            else:
                evidence.hash_verified = False
                evidence.status = ImageStatus.HASH_MISMATCH
                evidence.error_message = (
                    f"Hash Mismatch!\n"
                    f"Expected: {evidence.expected_hash}\n"
                    f"Computed: {evidence.sha256}"
                )
                logger.error(evidence.error_message)
                return False

        # No expected hash → success (not verified)
        evidence.hash_verified = False
        evidence.status = ImageStatus.HASH_VERIFIED
        return True
