"""
FEPD Command: find  (search for files)
=========================================

Searches the VEOS evidence filesystem for files matching criteria.

Usage:
  find <pattern>                    Search from current directory
  find -name "*.exe"                Search by name pattern
  find -path "Users"                Search by path
  find -size +1M                    Files larger than 1MB

Output:
  C:\\Users\\Alice\\malware.exe
  C:\\Users\\Alice\\Downloads\\suspicious.exe

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import fnmatch
import logging
from typing import List, Any

logger = logging.getLogger(__name__)

MAX_RESULTS = 500


def find_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """Search for files in the evidence filesystem."""
    if not args and not flags:
        return (
            "Usage: find <pattern>\n"
            "       find -name '*.exe'\n"
            "       find -path 'Users'\n"
        )

    if not vfs:
        return "No evidence mounted."

    # Determine search parameters
    pattern = None
    path_filter = None
    search_root = _session_vfs(session)

    # Parse args and flags
    i = 0
    while i < len(args):
        if args[i] in ("-name", "--name") and i + 1 < len(args):
            pattern = args[i + 1]
            i += 2
        elif args[i] in ("-path", "--path") and i + 1 < len(args):
            path_filter = args[i + 1]
            i += 2
        else:
            # Treat as pattern
            pattern = args[i]
            i += 1

    if not pattern and not path_filter:
        pattern = "*"

    # Recursive search
    results = []
    _search_recursive(vfs, search_root, pattern, path_filter, results, 0)

    if not results:
        return f"No files found matching '{pattern or path_filter}'"

    output = [f"Search results ({len(results)} found):", ""]
    for path in results[:MAX_RESULTS]:
        output.append(f"  {_format_path(path)}")

    if len(results) > MAX_RESULTS:
        output.append(f"\n  ... [{len(results) - MAX_RESULTS} more results truncated]")

    return "\n".join(output)


def _search_recursive(
    vfs: Any,
    path: str,
    pattern: str | None,
    path_filter: str | None,
    results: List[str],
    depth: int,
) -> None:
    """Recursively search the VFS tree."""
    if depth > 10 or len(results) >= MAX_RESULTS * 2:
        return

    try:
        items = vfs.list_dir(path)
    except Exception:
        return

    for name in items:
        item_path = os.path.join(path, name).replace("\\", "/")

        # Check name match
        name_match = True
        if pattern:
            name_match = fnmatch.fnmatch(name.lower(), pattern.lower())

        # Check path match
        path_match = True
        if path_filter:
            path_match = path_filter.lower() in item_path.lower()

        if name_match and path_match:
            results.append(item_path)

        # Recurse into directories
        try:
            meta = vfs.stat(item_path)
            if meta and meta.get("is_dir", False):
                _search_recursive(vfs, item_path, pattern, path_filter, results, depth + 1)
        except Exception:
            pass


def _session_vfs(session: Any) -> str:
    path = getattr(session, "path", "/") or "/"
    if len(path) >= 2 and path[1] == ":":
        path = path[2:]
    return path.replace("\\", "/") or "/"


def _format_path(vfs_path: str) -> str:
    if vfs_path.startswith("/"):
        return "C:" + vfs_path.replace("/", "\\")
    return vfs_path
