"""
FEPD Command: tree  (directory tree)
======================================

Displays the evidence directory structure as a visual tree.

Usage:
  tree                    Tree from current directory
  tree <path>             Tree from specified path
  tree -d                 Directories only

Output:
  Folder PATH listing for volume EVIDENCE
  C:\\Users\\Alice
  ├───Documents
  │   ├───Reports
  │   └───notes.txt
  └───Downloads

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import logging
from typing import List, Any

logger = logging.getLogger(__name__)

MAX_DEPTH = 5
MAX_ITEMS_PER_DIR = 50


def tree_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """Display directory tree of the evidence filesystem."""
    if not vfs:
        return "No evidence mounted."

    # Parse target
    target = _resolve_target(args, session)
    dirs_only = any(f in ("-d", "/d") for f in flags)

    output = []
    output.append("Folder PATH listing for volume EVIDENCE")
    output.append(f"Volume serial number is FEPD-2026")
    output.append(_format_path(target))

    _build_tree(vfs, target, output, "", 0, dirs_only)

    if not output[3:]:
        output.append("  (empty)")

    return "\n".join(output)


def _build_tree(
    vfs: Any,
    path: str,
    output: List[str],
    prefix: str,
    depth: int,
    dirs_only: bool,
) -> None:
    """Recursively build tree output."""
    if depth > MAX_DEPTH:
        output.append(f"{prefix}└───[... depth limit reached]")
        return

    try:
        items = vfs.list_dir(path)
    except Exception:
        return

    # Sort: directories first, then files
    entries = []
    for name in items[:MAX_ITEMS_PER_DIR]:
        item_path = os.path.join(path, name).replace("\\", "/")
        try:
            meta = vfs.stat(item_path)
            is_dir = meta.get("is_dir", False) if meta else False
        except Exception:
            is_dir = False
        entries.append((name, item_path, is_dir))

    # Filter if dirs_only
    if dirs_only:
        entries = [(n, p, d) for n, p, d in entries if d]

    for i, (name, item_path, is_dir) in enumerate(entries):
        is_last = i == len(entries) - 1
        connector = "└───" if is_last else "├───"
        output.append(f"{prefix}{connector}{name}")

        if is_dir:
            child_prefix = prefix + ("    " if is_last else "│   ")
            _build_tree(vfs, item_path, output, child_prefix, depth + 1, dirs_only)

    if len(items) > MAX_ITEMS_PER_DIR:
        output.append(f"{prefix}└───[... {len(items) - MAX_ITEMS_PER_DIR} more entries]")


def _resolve_target(args: List[str], session: Any) -> str:
    if args:
        path = args[0]
        if len(path) >= 2 and path[1] == ":":
            path = path[2:]
        path = path.replace("\\", "/")
        if not path.startswith("/"):
            cwd = _session_vfs(session)
            path = os.path.join(cwd, path).replace("\\", "/")
        return path
    return _session_vfs(session)


def _session_vfs(session: Any) -> str:
    path = getattr(session, "path", "/") or "/"
    if len(path) >= 2 and path[1] == ":":
        path = path[2:]
    return path.replace("\\", "/") or "/"


def _format_path(vfs_path: str) -> str:
    if vfs_path.startswith("/"):
        return "C:" + vfs_path.replace("/", "\\")
    return vfs_path
