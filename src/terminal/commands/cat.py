"""
FEPD Command: cat  (display file contents)
=============================================

Reads and displays the contents of a file from the VEOS filesystem.
Equivalent to ``type`` (Windows CMD) or ``cat`` (Linux).

The file is always read from the evidence image — never from the host.

Usage:
  cat <filename>
  type <filename>

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import logging
from typing import List, Any

logger = logging.getLogger(__name__)

# Maximum bytes to display (prevent huge file dumps)
MAX_DISPLAY_SIZE = 1024 * 256  # 256 KB


def cat_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """
    Display file contents from the VEOS filesystem.

    Args:
        args:    Target file path.
        flags:   (unused).
        session: SessionManager instance.
        vfs:     VirtualFilesystem instance.

    Returns:
        File content string, or error message.
    """
    if not args:
        return "Usage: cat <filename>"

    if not vfs:
        return "No evidence mounted."

    target = args[0]
    vfs_path = _to_vfs_path(target, session)

    try:
        # Check file exists
        node = vfs._node_at(vfs_path)
        if node is None:
            return f"File not found: {_format_path(vfs_path)}"
        if node.is_dir:
            return f"'{_format_path(vfs_path)}' is a directory, not a file."

        # Try to read content
        if hasattr(vfs, "read_file"):
            content = vfs.read_file(vfs_path)
            if content is None:
                return f"[Cannot read file content — binary or unsupported format]"
            if isinstance(content, bytes):
                # Try UTF-8 decode
                try:
                    text = content[:MAX_DISPLAY_SIZE].decode("utf-8", errors="replace")
                except Exception:
                    return f"[Binary file — use 'hexdump {target}' to view]"
                if len(content) > MAX_DISPLAY_SIZE:
                    text += f"\n\n... [Truncated: {len(content):,} bytes total]"
                return text
            return str(content)[:MAX_DISPLAY_SIZE]

        # VFS doesn't support read_file — show metadata instead
        meta = vfs.stat(vfs_path)
        return _meta_fallback(vfs_path, meta)

    except FileNotFoundError:
        return f"File not found: {_format_path(vfs_path)}"
    except Exception as e:
        return f"Error reading file: {e}"


def _meta_fallback(vfs_path: str, meta: dict) -> str:
    """When raw content isn't available, show file metadata."""
    display = _format_path(vfs_path)
    lines = [f"File: {display}", ""]
    if meta:
        for key in ("size", "hash", "owner", "ml_score", "mtime", "ctime"):
            if key in meta and meta[key] is not None:
                label = key.replace("_", " ").title()
                lines.append(f"  {label}: {meta[key]}")
    else:
        lines.append("  [No metadata available]")
    lines.append("")
    lines.append("[File content not directly accessible — image mount required]")
    return "\n".join(lines)


def _to_vfs_path(target: str, session: Any) -> str:
    """Convert user path to VFS path."""
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
