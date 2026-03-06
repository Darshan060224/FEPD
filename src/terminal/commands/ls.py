"""
FEPD Command: ls  (list directory)
====================================

Lists files and directories in the VEOS evidence filesystem.
Equivalent to ``dir`` (Windows) or ``ls`` (Linux).

Flags:
  -l, /l      Long format (detailed)
  -a, /a      Show hidden files
  -h          Human-readable sizes
  -1          One entry per line (bare)

Output mimics Windows CMD ``dir`` format for familiarity.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import logging
from datetime import datetime
from typing import List, Optional, Any

logger = logging.getLogger(__name__)

# Display limits
MAX_ITEMS = 500


def ls_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """
    List directory contents on the VEOS filesystem.

    Args:
        args:    Positional arguments (target directory).
        flags:   Flags (-l, -a, /b, etc.).
        session: SessionManager instance.
        vfs:     VirtualFilesystem instance.

    Returns:
        Formatted directory listing string.
    """
    if not vfs:
        return _no_vfs_message()

    # Determine target path
    target = _resolve_target(args, session)

    # Parse flags
    long_fmt = any(f in ("-l", "/l", "-la", "-al") for f in flags)
    bare = any(f in ("-1", "/b") for f in flags)
    show_all = any(f in ("-a", "/a", "-la", "-al") for f in flags)

    try:
        items = vfs.list_dir(target)
    except FileNotFoundError:
        return f"Directory not found: {_format_path(target)}"
    except Exception as e:
        return f"Error listing directory: {e}"

    if not items:
        return f"Directory is empty: {_format_path(target)}"

    # Bare format
    if bare:
        return "\n".join(items[:MAX_ITEMS])

    # Build formatted output
    return _format_dir_listing(target, items, vfs, long_fmt, show_all)


def _format_dir_listing(
    target: str,
    items: List[str],
    vfs: Any,
    long_fmt: bool,
    show_all: bool,
) -> str:
    """Format items into a Windows CMD dir-style listing."""
    output = []
    output.append(" Volume in drive C is EVIDENCE")
    output.append(" Volume Serial Number is FEPD-2026")
    output.append("")
    output.append(f" Directory of {_format_path(target)}")
    output.append("")

    total_files = 0
    total_dirs = 0
    total_size = 0

    # Parent directory entries
    if target != "/":
        now_str = datetime.now().strftime("%m/%d/%Y  %I:%M %p")
        output.append(f"{now_str}    <DIR>          .")
        output.append(f"{now_str}    <DIR>          ..")
        total_dirs += 2

    for name in items[:MAX_ITEMS]:
        if not show_all and name.startswith("."):
            continue

        item_path = os.path.join(target, name).replace("\\", "/")
        try:
            meta = vfs.stat(item_path)
            is_dir = meta.get("is_dir", False) if meta else False
            size = meta.get("size", 0) if meta else 0
            mtime = meta.get("mtime") if meta else None

            date_str = _format_date(mtime)

            if is_dir:
                output.append(f"{date_str}    <DIR>          {name}")
                total_dirs += 1
            else:
                output.append(f"{date_str}    {size:>14,} {name}")
                total_files += 1
                total_size += (size or 0)
        except Exception:
            output.append(f"{datetime.now().strftime('%m/%d/%Y  %I:%M %p')}                   {name}")
            total_files += 1

    if len(items) > MAX_ITEMS:
        output.append(f"  ... and {len(items) - MAX_ITEMS} more entries (truncated)")

    output.append(f"               {total_files} File(s)  {total_size:>14,} bytes")
    output.append(f"               {total_dirs} Dir(s)   [EVIDENCE - Read Only]")

    return "\n".join(output)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _resolve_target(args: List[str], session: Any) -> str:
    """Resolve the target directory from args or session CWD."""
    if args:
        path = args[0]
        # Convert Windows-style to VFS path
        if len(path) >= 2 and path[1] == ":":
            path = path[2:]
        path = path.replace("\\", "/")
        if not path.startswith("/"):
            # Relative to CWD
            cwd = getattr(session, "path", "/")
            # Normalize CWD to VFS-style
            if len(cwd) >= 2 and cwd[1] == ":":
                cwd = cwd[2:]
            cwd = cwd.replace("\\", "/")
            path = os.path.join(cwd, path).replace("\\", "/")
        return path
    return _session_vfs_path(session)


def _session_vfs_path(session: Any) -> str:
    """Convert session path to VFS path."""
    path = getattr(session, "path", "/") or "/"
    if len(path) >= 2 and path[1] == ":":
        path = path[2:]
    return path.replace("\\", "/") or "/"


def _format_path(vfs_path: str) -> str:
    """Convert VFS path to Windows-style evidence path for display."""
    if vfs_path.startswith("/"):
        return "C:" + vfs_path.replace("/", "\\")
    return vfs_path


def _format_date(mtime: Any) -> str:
    """Format a modified-time value for display."""
    try:
        if isinstance(mtime, str):
            dt = datetime.fromisoformat(mtime.replace("Z", "+00:00"))
        elif isinstance(mtime, (int, float)):
            dt = datetime.fromtimestamp(mtime)
        else:
            dt = datetime.now()
    except Exception:
        dt = datetime.now()
    return dt.strftime("%m/%d/%Y  %I:%M %p")


def _no_vfs_message() -> str:
    return (
        "No evidence mounted.\n"
        "\n"
        "To begin:\n"
        "  1. cases           → List available cases\n"
        "  2. use case <name> → Load a case\n"
        "  3. detect          → Scan for evidence images\n"
        "  4. mount <index>   → Mount evidence (read-only)\n"
    )
