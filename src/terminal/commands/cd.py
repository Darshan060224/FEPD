"""
FEPD Command: cd  (change directory)
=======================================

Navigate the VEOS evidence filesystem.
Changes the current working directory in the session.

Usage:
  cd <path>      Navigate to path
  cd ..          Go up one level
  cd /           Go to root
  cd             Show current path (like Windows CMD)

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import logging
from typing import List, Any

logger = logging.getLogger(__name__)


def cd_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """
    Change directory in the VEOS evidence filesystem.

    Args:
        args:    Target path.
        flags:   (unused).
        session: SessionManager instance.
        vfs:     VirtualFilesystem instance.

    Returns:
        Empty string on success, error message on failure.
    """
    # No args = show current directory (Windows CMD behavior)
    if not args:
        return _format_path(session.path)

    target = args[0]

    # Handle special targets
    if target in ("\\", "/"):
        session.path = "C:\\"
        return ""

    if target == "..":
        _go_up(session)
        return ""

    if target == ".":
        return ""

    # Resolve the path
    vfs_path = _to_vfs_path(target, session)

    if not vfs:
        return "No evidence mounted. Use 'use case <name>' first."

    # Verify the path exists and is a directory
    try:
        node = vfs._node_at(vfs_path)
        if node is None:
            return f"The system cannot find the path specified: {_format_path(vfs_path)}"
        if not node.is_dir:
            return f"The directory name is invalid: {_format_path(vfs_path)}"

        # Update session
        session.path = "C:" + vfs_path.replace("/", "\\")
        return ""

    except Exception as e:
        return f"Error navigating to path: {e}"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _go_up(session: Any) -> None:
    """Navigate up one directory level."""
    current = session.path
    # Normalize to VFS
    if len(current) >= 2 and current[1] == ":":
        current = current[2:]
    current = current.replace("\\", "/").rstrip("/")

    parent = os.path.dirname(current)
    if not parent:
        parent = "/"

    session.path = "C:" + parent.replace("/", "\\")
    if session.path == "C:":
        session.path = "C:\\"


def _to_vfs_path(target: str, session: Any) -> str:
    """Convert a user-typed path to a VFS path."""
    # Strip drive letter if present
    path = target
    if len(path) >= 2 and path[1] == ":":
        path = path[2:]
    path = path.replace("\\", "/")

    if path.startswith("/"):
        # Absolute path
        return path

    # Relative path — join with CWD
    cwd = session.path
    if len(cwd) >= 2 and cwd[1] == ":":
        cwd = cwd[2:]
    cwd = cwd.replace("\\", "/")

    joined = os.path.join(cwd, path).replace("\\", "/")
    # Normalize /../ etc
    parts = []
    for part in joined.split("/"):
        if part == ".." and parts:
            parts.pop()
        elif part and part != ".":
            parts.append(part)
    return "/" + "/".join(parts)


def _format_path(vfs_or_display: str) -> str:
    """Format a path for display."""
    if vfs_or_display.startswith("/"):
        return "C:" + vfs_or_display.replace("/", "\\")
    return vfs_or_display
