"""
FEPD Preview Service
====================

Determines the appropriate viewer for a given file and generates quick
preview data (thumbnails, text snippets, hex dumps) for the right-hand
details panel of the Files Tab.

Architecture:
    PreviewService
        ├── detect_viewer_type(path, mime) → viewer class name
        ├── generate_quick_preview(bytes, mime) → QWidget or raw data
        └── viewer registry (extensible)
"""

from __future__ import annotations

import io
import logging
from typing import Optional, Callable, Tuple, Dict, Set

logger = logging.getLogger(__name__)


# ============================================================================
# MAGIC-BYTE SIGNATURES  (for carved / mislabelled files)
# ============================================================================

_MAGIC_SIGS: list[Tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n",  "image"),
    (b"\xff\xd8\xff",        "image"),   # JPEG
    (b"GIF87a",              "image"),
    (b"GIF89a",              "image"),
    (b"BM",                  "image"),   # BMP
    (b"II\x2a\x00",         "image"),   # TIFF LE
    (b"MM\x00\x2a",         "image"),   # TIFF BE
    (b"RIFF",                "image"),   # WEBP (checked further below)
    (b"\x00\x00\x01\x00",  "image"),   # ICO
    (b"%PDF",                "pdf"),
    (b"MZ",                  "pe"),      # PE executable (EXE/DLL)
    (b"PK\x03\x04",         "archive"), # ZIP/JAR/DOCX/XLSX
    (b"Rar!\x1a\x07",       "archive"), # RAR
    (b"7z\xbc\xaf\x27\x1c", "archive"), # 7-Zip
    (b"\x1f\x8b",           "archive"), # GZIP
    (b"BZh",                 "archive"), # BZIP2
    (b"\xfd7zXZ\x00",       "archive"), # XZ
]


def _detect_type_by_magic(data: bytes) -> Optional[str]:
    """Return viewer type based on file magic bytes, or ``None``."""
    if not data or len(data) < 4:
        return None
    for magic, vtype in _MAGIC_SIGS:
        if data[:len(magic)] == magic:
            if magic == b"RIFF" and data[8:12] != b"WEBP":
                continue
            return vtype
    return None


# ============================================================================
# EXTENSION → VIEWER TYPE MAPPING
# ============================================================================

_TEXT_EXTENSIONS: Set[str] = {
    "txt", "log", "csv", "json", "xml", "html", "htm",
    "md", "ini", "cfg", "conf", "yaml", "yml", "toml",
    "py", "js", "java", "cpp", "c", "h", "cs", "go", "rs",
    "bat", "cmd", "ps1", "sh", "bash", "zsh",
    "css", "scss", "less", "sql", "rb", "php",
    "reg", "inf", "manifest", "plist",
}

_IMAGE_EXTENSIONS: Set[str] = {
    "jpg", "jpeg", "png", "gif", "bmp", "ico",
    "tiff", "tif", "webp", "svg",
}

_VIDEO_EXTENSIONS: Set[str] = {
    "mp4", "avi", "mkv", "mov", "wmv", "webm", "flv",
    "mp3", "wav", "flac", "ogg", "aac", "m4a", "wma",
}

_PDF_EXTENSIONS: Set[str] = {"pdf"}

_PE_EXTENSIONS: Set[str] = {
    "exe", "dll", "sys", "com", "ocx", "drv", "scr",
}

_ARCHIVE_EXTENSIONS: Set[str] = {
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab",
    "jar", "war", "apk", "ipa",
}

# Maximum bytes to read for a quick hex preview in the details panel
_HEX_PREVIEW_BYTES = 512
# Maximum characters for a text snippet preview
_TEXT_PREVIEW_CHARS = 2000
# Thumbnail max dimension (pixels)
_THUMB_MAX_DIM = 200


# ============================================================================
# PREVIEW SERVICE
# ============================================================================

class PreviewService:
    """
    Stateless service that maps files to viewer types and generates
    lightweight preview data for the details panel.
    """

    def __init__(
        self,
        read_file_func: Optional[Callable[[str, int, int], Optional[bytes]]] = None,
    ):
        self._read_file = read_file_func

    def set_read_file_func(self, func: Callable[[str, int, int], Optional[bytes]]):
        self._read_file = func

    # ------------------------------------------------------------------
    # Viewer type detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_viewer_type(
        filename: str,
        mime_type: Optional[str] = None,
        header_bytes: Optional[bytes] = None,
    ) -> str:
        """
        Return the canonical viewer type string for *filename*.

        Priority order:
          1. Magic bytes (reliable for carved files)
          2. File extension
          3. MIME type
          4. Fallback → hex

        Possible return values:
          ``"text"`` | ``"hex"`` | ``"image"`` | ``"pdf"`` | ``"video"`` | ``"pe"`` | ``"archive"``
        """
        # 1. Magic bytes — most reliable for carved / mislabelled files
        if header_bytes:
            magic_type = _detect_type_by_magic(header_bytes)
            if magic_type:
                return magic_type

        # 2. Extension
        ext = ""
        if "." in filename:
            ext = filename.rsplit(".", 1)[-1].lower()

        if ext in _PDF_EXTENSIONS:
            return "pdf"
        if ext in _PE_EXTENSIONS:
            return "pe"
        if ext in _ARCHIVE_EXTENSIONS:
            return "archive"
        if ext in _IMAGE_EXTENSIONS:
            return "image"
        if ext in _VIDEO_EXTENSIONS:
            return "video"
        if ext in _TEXT_EXTENSIONS:
            return "text"

        # 3. MIME type
        if mime_type:
            mt = mime_type.lower()
            if mt.startswith("text/"):
                return "text"
            if mt.startswith("image/"):
                return "image"
            if mt.startswith("video/") or mt.startswith("audio/"):
                return "video"
            if "pdf" in mt:
                return "pdf"

        # 4. Default — hex
        return "hex"

    # ------------------------------------------------------------------
    # Quick preview generation
    # ------------------------------------------------------------------

    def generate_quick_preview(
        self,
        path: str,
        file_size: int,
        viewer_type: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Generate lightweight preview data for the details panel.

        Returns a dict with keys:
          ``type``  — "text" | "hex" | "image_thumb" | "image_bytes" | "none"
          ``data``  — str (text/hex), bytes (thumb PNG), or QPixmap
          ``lines`` — number of preview lines (for text/hex)

        Uses a cascading pipeline:
          1. If image → attempt thumbnail
          2. If thumbnail fails → hex preview
          3. If text → text snippet
          4. Otherwise → hex dump

        Returns ``None`` if no read function is available.
        """
        if not self._read_file:
            return None

        # Narrowing hint for type checkers — guaranteed not-None past the guard above
        assert self._read_file is not None

        filename = path.rsplit("/", 1)[-1] if "/" in path else path

        # Read header bytes for magic detection
        header = None
        if not viewer_type:
            try:
                header = self._read_file(path, 0, 16)
            except Exception:
                pass

        vtype = viewer_type or self.detect_viewer_type(filename, header_bytes=header)

        try:
            if vtype == "image":
                result = self._preview_image_thumb(path, file_size)
                if result and result["type"] != "none":
                    return result
                # Image decode failed → fall through to hex
                return self._preview_hex(path, file_size)
            elif vtype == "text":
                return self._preview_text(path, file_size)
            elif vtype == "pe":
                return self._preview_pe(path, file_size)
            elif vtype == "archive":
                return self._preview_archive(path, file_size)
            else:
                return self._preview_hex(path, file_size)
        except Exception as exc:
            logger.debug(f"Preview generation failed for {path}: {exc}")
            return {"type": "none", "data": f"Preview unavailable: {exc}", "lines": 0}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _preview_text(self, path: str, file_size: int) -> Dict:
        """Return first ~2 KB of the file decoded as UTF-8."""
        assert self._read_file is not None
        read_len = min(file_size, _TEXT_PREVIEW_CHARS * 2)  # rough byte/char ratio
        data = self._read_file(path, 0, read_len)
        if not data:
            return {"type": "none", "data": "", "lines": 0}

        try:
            text = data.decode("utf-8", errors="replace")[:_TEXT_PREVIEW_CHARS]
        except Exception:
            text = data.decode("latin-1", errors="replace")[:_TEXT_PREVIEW_CHARS]

        lines = text.count("\n") + 1
        return {"type": "text", "data": text, "lines": lines}

    def _preview_hex(self, path: str, file_size: int) -> Dict:
        """Return a classic hex+ASCII dump of the first 512 bytes."""
        assert self._read_file is not None
        read_len = min(file_size, _HEX_PREVIEW_BYTES)
        data = self._read_file(path, 0, read_len)
        if not data:
            return {"type": "none", "data": "", "lines": 0}

        lines = []
        for offset in range(0, len(data), 16):
            chunk = data[offset: offset + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(48)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset:08X}  {hex_part}  |{ascii_part}|")

        text = "\n".join(lines)
        return {"type": "hex", "data": text, "lines": len(lines)}

    def _preview_image(self, path: str, file_size: int) -> Dict:
        """Return raw image bytes (the UI will render a thumbnail from them)."""
        assert self._read_file is not None
        read_len = min(file_size, 5 * 1024 * 1024)
        data = self._read_file(path, 0, read_len)
        if not data:
            return {"type": "none", "data": b"", "lines": 0}
        return {"type": "image_bytes", "data": data, "lines": 0}

    def _preview_image_thumb(self, path: str, file_size: int) -> Dict:
        """
        Generate a thumbnail preview using the robust decode pipeline.

        Uses Pillow for tolerance of carved / corrupted images.
        Falls back to hex if decoding fails entirely.
        """
        assert self._read_file is not None
        read_len = min(file_size, 5 * 1024 * 1024)
        data = self._read_file(path, 0, read_len)
        if not data:
            return {"type": "none", "data": "", "lines": 0}

        # Try generating a thumbnail via the robust decoder
        try:
            from src.ui.viewers.image_viewer import generate_thumbnail
            thumb = generate_thumbnail(data, _THUMB_MAX_DIM)
            if thumb and not thumb.isNull():
                return {"type": "image_thumb", "data": thumb, "lines": 0}
        except Exception as exc:
            logger.debug("Thumbnail generation failed: %s", exc)

        # Thumbnail failed — report as none so caller can fall back to hex
        return {"type": "none", "data": "", "lines": 0}

    def _preview_pe(self, path: str, file_size: int) -> Dict:
        """Return PE metadata for executables (EXE/DLL/SYS)."""
        assert self._read_file is not None
        read_len = min(file_size, 2 * 1024 * 1024)  # Read up to 2MB for PE headers
        data = self._read_file(path, 0, read_len)
        if not data:
            return {"type": "none", "data": "", "lines": 0}

        lines = []
        lines.append("═══ PE EXECUTABLE METADATA ═══\n")

        try:
            import pefile
            pe = pefile.PE(data=data, fast_load=True)

            # Basic info
            machine_types = {0x14c: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0xAA64: "ARM64"}
            machine = machine_types.get(pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:04X}")
            lines.append(f"Architecture:    {machine}")
            lines.append(f"Subsystem:       {'GUI' if pe.OPTIONAL_HEADER.Subsystem == 2 else 'Console' if pe.OPTIONAL_HEADER.Subsystem == 3 else str(pe.OPTIONAL_HEADER.Subsystem)}")
            lines.append(f"Entry Point:     0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
            lines.append(f"Image Base:      0x{pe.OPTIONAL_HEADER.ImageBase:016X}")
            lines.append(f"Sections:        {pe.FILE_HEADER.NumberOfSections}")

            # Compile timestamp
            import datetime
            try:
                ts = datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)
                lines.append(f"Compile Time:    {ts.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            except Exception:
                lines.append(f"Compile Time:    0x{pe.FILE_HEADER.TimeDateStamp:08X}")

            # DLL flag
            is_dll = pe.FILE_HEADER.Characteristics & 0x2000
            lines.append(f"Type:            {'DLL' if is_dll else 'EXE'}")

            # Sections
            lines.append(f"\n{'─' * 50}")
            lines.append("SECTIONS:")
            for section in pe.sections:
                sec_name = section.Name.rstrip(b'\x00').decode('utf-8', errors='replace')
                lines.append(f"  {sec_name:8s}  VAddr: 0x{section.VirtualAddress:08X}  Size: {section.SizeOfRawData:>8,}")

            # Imports (first 20)
            pe.parse_data_directories()
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                lines.append(f"\n{'─' * 50}")
                lines.append("IMPORTS (DLLs):")
                for entry in pe.DIRECTORY_ENTRY_IMPORT[:20]:
                    dll_name = entry.dll.decode('utf-8', errors='replace')
                    func_count = len(entry.imports)
                    lines.append(f"  {dll_name} ({func_count} functions)")

            pe.close()

        except ImportError:
            # pefile not installed — show basic MZ header info + hex
            lines.append("(Install 'pefile' for detailed PE analysis)\n")
            if len(data) >= 64:
                e_lfanew = int.from_bytes(data[60:64], 'little')
                lines.append(f"MZ Header:       Present")
                lines.append(f"PE Offset:       0x{e_lfanew:08X}")
            hex_result = self._preview_hex(path, file_size)
            lines.append(f"\n{'─' * 50}")
            lines.append("HEX DUMP:")
            lines.append(hex_result.get("data", ""))

        except Exception as exc:
            lines.append(f"PE parse error: {exc}\n")
            hex_result = self._preview_hex(path, file_size)
            lines.append(hex_result.get("data", ""))

        text = "\n".join(lines)
        return {"type": "text", "data": text, "lines": len(lines)}

    def _preview_archive(self, path: str, file_size: int) -> Dict:
        """Return archive contents listing."""
        assert self._read_file is not None
        read_len = min(file_size, 10 * 1024 * 1024)
        data = self._read_file(path, 0, read_len)
        if not data:
            return {"type": "none", "data": "", "lines": 0}

        lines = []
        lines.append("═══ ARCHIVE CONTENTS ═══\n")

        filename = path.rsplit("/", 1)[-1] if "/" in path else path
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        try:
            if ext in ("zip", "jar", "war", "apk", "ipa", "docx", "xlsx", "pptx"):
                import zipfile
                import io
                with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                    lines.append(f"Type:    ZIP Archive")
                    lines.append(f"Files:   {len(zf.namelist())}")
                    lines.append(f"\n{'─' * 50}")
                    lines.append(f"{'Name':<40s} {'Size':>10s}  {'Compressed':>10s}")
                    lines.append(f"{'─'*40} {'─'*10}  {'─'*10}")
                    for info in zf.infolist()[:100]:
                        name = info.filename[:40]
                        lines.append(f"{name:<40s} {info.file_size:>10,}  {info.compress_size:>10,}")
                    if len(zf.namelist()) > 100:
                        lines.append(f"\n... and {len(zf.namelist()) - 100} more files")
            else:
                # Unsupported archive — show hex
                lines.append(f"Archive type: {ext.upper()}")
                lines.append("(Detailed listing not available)\n")
                hex_result = self._preview_hex(path, file_size)
                lines.append(hex_result.get("data", ""))

        except Exception as exc:
            lines.append(f"Archive parse error: {exc}\n")
            hex_result = self._preview_hex(path, file_size)
            lines.append(hex_result.get("data", ""))

        text = "\n".join(lines)
        return {"type": "text", "data": text, "lines": len(lines)}
