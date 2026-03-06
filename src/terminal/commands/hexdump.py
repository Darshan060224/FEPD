"""
FEPD Command: hexdump  (hex view of file)
============================================

Displays a hex + ASCII dump of an evidence file.
Essential for binary forensic analysis.

Usage:
  hexdump <filename>
  hexdump -n 256 <filename>    First 256 bytes

Output:
  00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............| 
  00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import logging
from typing import List, Any

logger = logging.getLogger(__name__)

DEFAULT_BYTES = 512
MAX_BYTES = 4096


def hexdump_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """Display hex dump of an evidence file."""
    if not args:
        return "Usage: hexdump <filename> [-n <bytes>]"

    if not vfs:
        return "No evidence mounted."

    # Parse -n <count>
    num_bytes = DEFAULT_BYTES
    target = None
    i = 0
    while i < len(args):
        if args[i] in ("-n", "--bytes") and i + 1 < len(args):
            try:
                num_bytes = min(int(args[i + 1]), MAX_BYTES)
            except ValueError:
                return f"Invalid byte count: {args[i + 1]}"
            i += 2
        else:
            target = args[i]
            i += 1

    if not target:
        return "Usage: hexdump <filename>"

    # Also check flags for -n
    for f in flags:
        if f.startswith("-n"):
            try:
                num_bytes = min(int(f[2:]), MAX_BYTES)
            except ValueError:
                pass

    vfs_path = _to_vfs_path(target, session)

    try:
        node = vfs._node_at(vfs_path)
        if node is None:
            return f"File not found: {_format_path(vfs_path)}"
        if node.is_dir:
            return f"Cannot hexdump a directory."

        if not hasattr(vfs, "read_file"):
            return "[Hex dump requires mounted evidence image]"

        content = vfs.read_file(vfs_path)
        if content is None:
            return "[Cannot read file content]"

        data = content if isinstance(content, bytes) else content.encode("utf-8")
        return _format_hexdump(data[:num_bytes], vfs_path)

    except FileNotFoundError:
        return f"File not found: {_format_path(vfs_path)}"
    except Exception as e:
        return f"Error: {e}"


def _format_hexdump(data: bytes, filepath: str) -> str:
    """Format bytes as a classic hex dump."""
    lines = [f"Hexdump: {_format_path(filepath)}  ({len(data)} bytes)", ""]

    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]

        # Hex part
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad to fixed width
        hex_part = hex_part.ljust(47)

        # ASCII part
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

        lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")

    lines.append(f"\n{len(data)} bytes displayed")
    return "\n".join(lines)


def _to_vfs_path(target: str, session: Any) -> str:
    path = target
    if len(path) >= 2 and path[1] == ":":
        path = path[2:]
    path = path.replace("\\", "/")
    if not path.startswith("/"):
        cwd = session.path
        if len(cwd) >= 2 and cwd[1] == ":":
            cwd = cwd[2:]
        cwd = cwd.replace("\\", "/")
        path = os.path.join(cwd, path).replace("\\", "/")
    return path


def _format_path(vfs_path: str) -> str:
    if vfs_path.startswith("/"):
        return "C:" + vfs_path.replace("/", "\\")
    return vfs_path
