"""
Image Viewer
============

Forensic-grade image viewer for evidence inspection.

Features
--------
- Magic-byte file-type detection (does NOT trust extensions)
- Pillow-first decoding pipeline (tolerates corrupted / carved images)
- Automatic hex fallback when decoding fails
- EXIF metadata extraction
- Thumbnail generation
- Zoom / rotate / fit-to-window
"""

from PyQt6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout, QScrollArea,
    QSizePolicy, QFrame, QPlainTextEdit, QStackedWidget, QToolBar,
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QPixmap, QImage, QAction, QFont
from typing import Optional, Dict, Tuple
from pathlib import Path
import io
import logging

from .base_viewer import BaseViewer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Magic-byte signatures  (checked in order, longest match first)
# ---------------------------------------------------------------------------

_SIGNATURES: list[Tuple[bytes, str, str]] = [
    # (magic_bytes, format_label, PIL_format_hint)
    (b"\x89PNG\r\n\x1a\n",       "PNG",  "PNG"),
    (b"\xff\xd8\xff",             "JPEG", "JPEG"),
    (b"GIF87a",                   "GIF",  "GIF"),
    (b"GIF89a",                   "GIF",  "GIF"),
    (b"BM",                       "BMP",  "BMP"),
    (b"II\x2a\x00",              "TIFF", "TIFF"),   # little-endian
    (b"MM\x00\x2a",              "TIFF", "TIFF"),   # big-endian
    (b"RIFF",                     "WEBP", "WEBP"),   # RIFF....WEBP
    (b"\x00\x00\x01\x00",        "ICO",  "ICO"),
]


def detect_image_type(data: bytes) -> Optional[Tuple[str, str]]:
    """Return ``(label, PIL_hint)`` or ``None`` based on magic bytes."""
    if not data or len(data) < 4:
        return None
    for magic, label, hint in _SIGNATURES:
        if data[:len(magic)] == magic:
            # Extra check for WEBP (bytes 8-12 must be 'WEBP')
            if label == "WEBP" and data[8:12] != b"WEBP":
                continue
            return label, hint
    return None


def decode_image_robust(data: bytes) -> Tuple[Optional[QPixmap], str, Dict]:
    """
    Attempt to decode *data* into a ``QPixmap`` using a multi-stage pipeline.

    Returns ``(pixmap_or_None, format_label, metadata_dict)``.

    Pipeline
    --------
    1. Detect real type via magic bytes
    2. Try Pillow (handles partial / carved JPEGs)
    3. Fall back to Qt ``QImage.loadFromData``
    4. If JPEG, try appending missing EOI marker and retry
    """
    meta: Dict = {}
    fmt_label = "Unknown"

    detected = detect_image_type(data)
    if detected:
        fmt_label, pil_hint = detected
    else:
        pil_hint = None

    # --- Stage 1: Pillow decode (most tolerant) --------------------------
    try:
        from PIL import Image as PILImage, ExifTags

        img = PILImage.open(io.BytesIO(data))
        img.load()  # force decode — catches deferred errors
        fmt_label = img.format or fmt_label

        # Extract EXIF
        try:
            exif_raw = img.getexif()
            if exif_raw:
                for tag_id, value in exif_raw.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    meta[tag_name] = str(value)[:200]
        except Exception:
            pass

        meta["width"] = img.width
        meta["height"] = img.height
        meta["mode"] = img.mode

        # Convert to QImage
        if img.mode == "RGBA":
            qimg = QImage(
                img.tobytes("raw", "RGBA"),
                img.width, img.height,
                img.width * 4,
                QImage.Format.Format_RGBA8888,
            )
        else:
            rgb = img.convert("RGB")
            qimg = QImage(
                rgb.tobytes("raw", "RGB"),
                rgb.width, rgb.height,
                rgb.width * 3,
                QImage.Format.Format_RGB888,
            )

        pix = QPixmap.fromImage(qimg)
        if not pix.isNull():
            return pix, fmt_label, meta

    except Exception as exc:
        logger.debug("Pillow decode failed: %s", exc)

    # --- Stage 2: Qt native decode (fast, less tolerant) -----------------
    qimg = QImage()
    if qimg.loadFromData(data):
        meta["width"] = qimg.width()
        meta["height"] = qimg.height()
        return QPixmap.fromImage(qimg), fmt_label, meta

    # --- Stage 3: JPEG EOI repair attempt --------------------------------
    if fmt_label == "JPEG" or (data[:3] == b"\xff\xd8\xff"):
        if data[-2:] != b"\xff\xd9":
            repaired = data + b"\xff\xd9"
            try:
                from PIL import Image as PILImage
                img = PILImage.open(io.BytesIO(repaired))
                img.load()
                rgb = img.convert("RGB")
                qimg = QImage(
                    rgb.tobytes("raw", "RGB"),
                    rgb.width, rgb.height,
                    rgb.width * 3,
                    QImage.Format.Format_RGB888,
                )
                pix = QPixmap.fromImage(qimg)
                if not pix.isNull():
                    meta["width"] = img.width
                    meta["height"] = img.height
                    meta["_repaired"] = "Missing JPEG EOI marker appended"
                    return pix, fmt_label + " (repaired)", meta
            except Exception:
                pass

    # All stages failed
    return None, fmt_label, meta


def generate_thumbnail(data: bytes, max_dim: int = 256) -> Optional[QPixmap]:
    """Return a small thumbnail QPixmap or ``None``."""
    try:
        from PIL import Image as PILImage
        img = PILImage.open(io.BytesIO(data))
        img.load()
        img.thumbnail((max_dim, max_dim), PILImage.Resampling.LANCZOS)
        rgb = img.convert("RGB")
        qimg = QImage(
            rgb.tobytes("raw", "RGB"),
            rgb.width, rgb.height,
            rgb.width * 3,
            QImage.Format.Format_RGB888,
        )
        return QPixmap.fromImage(qimg)
    except Exception:
        return None


def hex_dump(data: bytes, limit: int = 2048) -> str:
    """Pretty hex+ASCII dump for display when image decode fails."""
    lines = []
    chunk_data = data[:limit]
    for offset in range(0, len(chunk_data), 16):
        chunk = chunk_data[offset: offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(48)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08X}  {hex_part}  |{ascii_part}|")
    if len(data) > limit:
        lines.append(f"... ({len(data) - limit:,} more bytes)")
    return "\n".join(lines)


class ImageViewer(BaseViewer):
    """
    Forensic-grade image viewer.

    - Magic-byte detection (ignores file extension)
    - Pillow-first decode pipeline (tolerant of carved / partial images)
    - Automatic hex fallback when decode fails
    - EXIF metadata display
    - Zoom / Rotate / Fit controls
    - 256 px thumbnails for fast browsing
    """

    SUPPORTED_EXTENSIONS = [
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
        '.tiff', '.tif', '.webp', '.svg',
    ]

    def __init__(self, parent: Optional[QWidget] = None, read_file_func=None):
        self._zoom_factor = 1.0
        self._original_pixmap: Optional[QPixmap] = None
        self._raw_data: Optional[bytes] = None
        self._exif_meta: Dict = {}
        self._decoded_format: str = ""

        super().__init__(parent, title="Image Viewer", read_file_func=read_file_func)
        self.title_icon.setText("🖼️")

    # ------------------------------------------------------------------
    # Content widget — stacked: image  |  hex fallback
    # ------------------------------------------------------------------

    def _create_content_widget(self) -> QWidget:
        container = QWidget()
        vlay = QVBoxLayout(container)
        vlay.setContentsMargins(0, 0, 0, 0)

        self._stack = QStackedWidget()

        # Page 0 — Image view
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(False)
        self.scroll_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scroll_area.setStyleSheet(
            "QScrollArea { background-color: #1e1e1e; border: none; }"
            "QScrollBar:vertical, QScrollBar:horizontal { background: #2d2d2d; }"
            "QScrollBar::handle:vertical, QScrollBar::handle:horizontal {"
            "  background: #555; border-radius: 4px; }"
        )
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setStyleSheet("background: transparent;")
        self.image_label.setSizePolicy(
            QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored,
        )
        self.scroll_area.setWidget(self.image_label)
        self._stack.addWidget(self.scroll_area)   # index 0

        # Page 1 — Hex fallback
        self._hex_fallback = QPlainTextEdit()
        self._hex_fallback.setReadOnly(True)
        self._hex_fallback.setFont(QFont("Consolas", 9))
        self._hex_fallback.setStyleSheet(
            "QPlainTextEdit { background: #1e1e1e; color: #81c784; border: none; }"
        )
        self._stack.addWidget(self._hex_fallback)  # index 1

        vlay.addWidget(self._stack)

        # Info bar (EXIF / format / repair notes)
        self._info_bar = QLabel()
        self._info_bar.setWordWrap(True)
        self._info_bar.setStyleSheet(
            "background: #252526; color: #9e9e9e; font-size: 10px; padding: 4px 8px;"
        )
        self._info_bar.setVisible(False)
        vlay.addWidget(self._info_bar)

        return container

    def _setup_toolbar(self):
        super()._setup_toolbar()

        # Fit to window
        fit_action = QAction("⊡ Fit", self)
        fit_action.setToolTip("Fit to Window")
        fit_action.triggered.connect(self._fit_to_window)
        self.toolbar.addAction(fit_action)

        # Actual size
        actual_action = QAction("1:1", self)
        actual_action.setToolTip("Actual Size")
        actual_action.triggered.connect(self._actual_size)
        self.toolbar.addAction(actual_action)

        self.toolbar.addSeparator()

        # Rotate
        rotate_left = QAction("↺", self)
        rotate_left.setToolTip("Rotate Left")
        rotate_left.triggered.connect(lambda: self._rotate(-90))
        self.toolbar.addAction(rotate_left)

        rotate_right = QAction("↻", self)
        rotate_right.setToolTip("Rotate Right")
        rotate_right.triggered.connect(lambda: self._rotate(90))
        self.toolbar.addAction(rotate_right)

        self.toolbar.addSeparator()

        # Toggle hex view
        self._hex_toggle = QAction("🔢 Hex", self)
        self._hex_toggle.setToolTip("Toggle hex view of raw data")
        self._hex_toggle.setCheckable(True)
        self._hex_toggle.toggled.connect(self._toggle_hex)
        self.toolbar.addAction(self._hex_toggle)

        # EXIF toggle
        self._exif_toggle = QAction("ℹ EXIF", self)
        self._exif_toggle.setToolTip("Show / hide EXIF metadata")
        self._exif_toggle.setCheckable(True)
        self._exif_toggle.toggled.connect(self._toggle_exif)
        self.toolbar.addAction(self._exif_toggle)

    # ------------------------------------------------------------------
    # LOAD FILE  (robust pipeline)
    # ------------------------------------------------------------------

    def load_file(self, path: str, data: Optional[bytes] = None) -> bool:
        try:
            name = Path(path).name
            self.set_file_info(path, name)

            # Read bytes
            if data is None and self.read_file_func:
                data = self.read_file_func(path, 0, -1)
            if data is None:
                self.image_label.setText("Error: Could not read file")
                return False

            self._raw_data = data

            # ----- Robust decode pipeline -----
            pixmap, fmt_label, meta = decode_image_robust(data)
            self._exif_meta = meta
            self._decoded_format = fmt_label

            if pixmap and not pixmap.isNull():
                self._original_pixmap = pixmap
                self._zoom_factor = 1.0
                self._stack.setCurrentIndex(0)
                self._fit_to_window()

                w = meta.get("width", pixmap.width())
                h = meta.get("height", pixmap.height())
                repair_note = f" [{meta['_repaired']}]" if "_repaired" in meta else ""

                self.set_status(
                    f"{w} × {h} pixels | {fmt_label}{repair_note} | "
                    f"{self._format_size(len(data))} | Zoom: {int(self._zoom_factor * 100)}%"
                )

                # Show info bar for repairs
                if "_repaired" in meta:
                    self._info_bar.setText(f"⚠️ {meta['_repaired']}")
                    self._info_bar.setVisible(True)
                else:
                    self._info_bar.setVisible(False)

                return True

            # ----- Decode failed → hex fallback -----
            logger.warning("Image decode failed for %s — showing hex fallback", name)
            self._show_hex_fallback(data, name, fmt_label)
            return True  # We still loaded *something*

        except Exception as e:
            self.image_label.setText(f"Error loading image: {e}")
            logger.error("ImageViewer error: %s", e, exc_info=True)
            return False

    # ------------------------------------------------------------------
    # Hex fallback
    # ------------------------------------------------------------------

    def _show_hex_fallback(self, data: bytes, name: str, fmt_label: str):
        sig_info = ""
        detected = detect_image_type(data)
        if detected:
            sig_info = f"  |  Detected signature: {detected[0]}"

        header = (
            f"⚠️  Image could not be decoded  —  displaying raw evidence data\n"
            f"File: {name}  |  Size: {self._format_size(len(data))}{sig_info}\n"
            f"First 4 bytes: {' '.join(f'{b:02X}' for b in data[:4])}\n"
            f"{'─' * 78}\n\n"
        )
        self._hex_fallback.setPlainText(header + hex_dump(data, 4096))
        self._stack.setCurrentIndex(1)
        self.set_status(
            f"Hex Fallback | {fmt_label} | {self._format_size(len(data))} | "
            f"Decode failed — raw evidence data shown"
        )

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def _update_display(self):
        if not self._original_pixmap:
            return
        new_size = self._original_pixmap.size() * self._zoom_factor
        scaled = self._original_pixmap.scaled(
            QSize(int(new_size.width()), int(new_size.height())),
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.image_label.setPixmap(scaled)
        self.image_label.resize(scaled.size())
        self.set_status(
            f"{self._original_pixmap.width()} × {self._original_pixmap.height()} | "
            f"{self._decoded_format} | Zoom: {int(self._zoom_factor * 100)}%"
        )

    def _fit_to_window(self):
        if not self._original_pixmap:
            return
        scroll_size = self.scroll_area.viewport().size()
        img_size = self._original_pixmap.size()
        zoom_w = scroll_size.width() / img_size.width() if img_size.width() else 1
        zoom_h = scroll_size.height() / img_size.height() if img_size.height() else 1
        self._zoom_factor = min(zoom_w, zoom_h, 1.0)
        self._update_display()

    def _actual_size(self):
        self._zoom_factor = 1.0
        self._update_display()

    def _zoom_in(self):
        self._zoom_factor = min(4.0, self._zoom_factor * 1.25)
        self._update_display()

    def _zoom_out(self):
        self._zoom_factor = max(0.1, self._zoom_factor / 1.25)
        self._update_display()

    def _rotate(self, degrees: int):
        if not self._original_pixmap:
            return
        from PyQt6.QtGui import QTransform
        transform = QTransform()
        transform.rotate(degrees)
        self._original_pixmap = self._original_pixmap.transformed(
            transform, Qt.TransformationMode.SmoothTransformation,
        )
        self._update_display()

    # ------------------------------------------------------------------
    # Toggles
    # ------------------------------------------------------------------

    def _toggle_hex(self, checked: bool):
        if checked and self._raw_data:
            name = Path(self.file_path).name if self.file_path else "file"
            self._hex_fallback.setPlainText(
                f"Raw data for: {name}  ({self._format_size(len(self._raw_data))})\n"
                f"{'─' * 78}\n\n"
                + hex_dump(self._raw_data, 8192)
            )
            self._stack.setCurrentIndex(1)
        else:
            if self._original_pixmap:
                self._stack.setCurrentIndex(0)

    def _toggle_exif(self, checked: bool):
        if checked and self._exif_meta:
            # Exclude internal keys
            display = {k: v for k, v in self._exif_meta.items() if not k.startswith("_")}
            if display:
                lines = [f"{k}: {v}" for k, v in display.items()]
                self._info_bar.setText("\n".join(lines))
                self._info_bar.setVisible(True)
            else:
                self._info_bar.setText("No EXIF metadata found")
                self._info_bar.setVisible(True)
        else:
            self._info_bar.setVisible(False)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _format_size(self, size: int) -> str:
        size_f = float(size)
        for unit in ['B', 'KB', 'MB']:
            if size_f < 1024:
                return f"{size_f:.1f} {unit}"
            size_f /= 1024
        return f"{size_f:.1f} GB"

    def get_supported_extensions(self) -> list:
        return self.SUPPORTED_EXTENSIONS
