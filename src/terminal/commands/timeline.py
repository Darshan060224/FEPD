"""
FEPD Command: timeline  (file timeline events)
=================================================

Shows timeline events for individual files or directories.
Critical for forensic investigation — reveals creation, modification,
and access patterns.

Usage:
  timeline <filename>
  timeline                   Timeline of current directory

Output:
  File: notes.txt
  Created:  2025-01-10 08:23:15
  Modified: 2025-01-15 14:32:10
  Accessed: 2025-01-15 14:32:10
  MFT Entry: 234211

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import logging
from datetime import datetime
from typing import List, Any, Dict

logger = logging.getLogger(__name__)

MAX_DIR_ENTRIES = 100


def timeline_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """Show timeline events for evidence files."""
    if not vfs:
        return "No evidence mounted."

    if args:
        target = args[0]
        vfs_path = _to_vfs_path(target, session)
        return _file_timeline(vfs, vfs_path)
    else:
        # Timeline of current directory contents
        cwd = _session_vfs(session)
        return _directory_timeline(vfs, cwd)


def _file_timeline(vfs: Any, vfs_path: str) -> str:
    """Show detailed timeline for a single file."""
    try:
        node = vfs._node_at(vfs_path)
        if node is None:
            return f"Not found: {_format_path(vfs_path)}"

        meta = vfs.stat(vfs_path) or {}

        output = [
            f"Timeline: {_format_path(vfs_path)}",
            "=" * 50,
            "",
        ]

        # MACB times
        timeline_fields = [
            ("Created", "ctime"),
            ("Modified", "mtime"),
            ("Accessed", "atime"),
            ("Changed", "crtime"),
        ]

        for label, key in timeline_fields:
            value = meta.get(key)
            if value:
                output.append(f"  {label:12s}: {_format_timestamp(value)}")
            else:
                output.append(f"  {label:12s}: [unknown]")

        # Additional metadata
        extras = [
            ("Size", "size"),
            ("Owner", "owner"),
            ("MFT Entry", "mft_entry"),
            ("Inode", "inode"),
            ("Hash", "hash"),
            ("ML Score", "ml_score"),
        ]

        output.append("")
        for label, key in extras:
            value = meta.get(key)
            if value is not None:
                output.append(f"  {label:12s}: {value}")

        return "\n".join(output)

    except Exception as e:
        return f"Error retrieving timeline: {e}"


def _directory_timeline(vfs: Any, dir_path: str) -> str:
    """Show timeline overview for all items in a directory."""
    try:
        items = vfs.list_dir(dir_path)
    except FileNotFoundError:
        return f"Directory not found: {_format_path(dir_path)}"
    except Exception as e:
        return f"Error: {e}"

    output = [
        f"Timeline: {_format_path(dir_path)}",
        "=" * 70,
        "",
        f"{'Name':<30s} {'Modified':<22s} {'Size':>12s}",
        f"{'-'*30} {'-'*22} {'-'*12}",
    ]

    entries: List[Dict] = []
    for name in items[:MAX_DIR_ENTRIES]:
        item_path = os.path.join(dir_path, name).replace("\\", "/")
        try:
            meta = vfs.stat(item_path) or {}
            mtime = meta.get("mtime", "")
            size = meta.get("size", "")
            is_dir = meta.get("is_dir", False)
            entries.append({
                "name": name,
                "mtime": mtime,
                "size": size,
                "is_dir": is_dir,
            })
        except Exception:
            entries.append({"name": name, "mtime": "", "size": "", "is_dir": False})

    # Sort by mtime (most recent first)
    entries.sort(key=lambda e: str(e.get("mtime", "")), reverse=True)

    for entry in entries:
        name = entry["name"]
        if entry["is_dir"]:
            name = f"[{name}]"
        name = name[:29]
        mtime = _format_timestamp(entry["mtime"]) if entry["mtime"] else "[unknown]"
        size = str(entry["size"]) if entry["size"] else ""
        output.append(f"{name:<30s} {mtime:<22s} {size:>12s}")

    output.append("")
    output.append(f"[{len(items)} items]")

    return "\n".join(output)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _format_timestamp(value: Any) -> str:
    """Format a timestamp value for display."""
    if not value:
        return "[unknown]"
    try:
        if isinstance(value, str):
            return value[:19].replace("T", " ")
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
        return str(value)
    except Exception:
        return str(value)


def _to_vfs_path(target: str, session: Any) -> str:
    path = target
    if len(path) >= 2 and path[1] == ":":
        path = path[2:]
    path = path.replace("\\", "/")
    if not path.startswith("/"):
        cwd = _session_vfs(session)
        path = os.path.join(cwd, path).replace("\\", "/")
    return path


def _session_vfs(session: Any) -> str:
    path = getattr(session, "path", "/") or "/"
    if len(path) >= 2 and path[1] == ":":
        path = path[2:]
    return path.replace("\\", "/") or "/"


def _format_path(vfs_path: str) -> str:
    if vfs_path.startswith("/"):
        return "C:" + vfs_path.replace("/", "\\")
    return vfs_path
