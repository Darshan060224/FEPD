"""
FEPD Command: strings  (extract printable strings)
=====================================================

Extracts printable ASCII/Unicode strings from binary evidence files.
Critical for malware analysis and artifact extraction.

Usage:
  strings <filename>
  strings -n 8 <filename>      Minimum length 8 (default: 4)
  strings malware.exe | grep http

Output:
  Printable strings found in file, one per line.

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import re
import logging
from typing import List, Any

logger = logging.getLogger(__name__)

DEFAULT_MIN_LENGTH = 4
MAX_STRINGS = 2000
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def strings_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """Extract printable strings from an evidence file."""
    if not args:
        return "Usage: strings <filename> [-n <min_length>]"

    if not vfs:
        return "No evidence mounted."

    # Parse arguments
    min_len = DEFAULT_MIN_LENGTH
    target = None
    i = 0
    while i < len(args):
        if args[i] in ("-n", "--min") and i + 1 < len(args):
            try:
                min_len = max(2, int(args[i + 1]))
            except ValueError:
                return f"Invalid minimum length: {args[i + 1]}"
            i += 2
        else:
            target = args[i]
            i += 1

    if not target:
        return "Usage: strings <filename>"

    vfs_path = _to_vfs_path(target, session)

    try:
        node = vfs._node_at(vfs_path)
        if node is None:
            return f"File not found: {_format_path(vfs_path)}"
        if node.is_dir:
            return "Cannot extract strings from a directory."

        if not hasattr(vfs, "read_file"):
            return "[Strings extraction requires mounted evidence image]"

        content = vfs.read_file(vfs_path)
        if content is None:
            return "[Cannot read file content]"

        data = content if isinstance(content, bytes) else content.encode("utf-8")

        if len(data) > MAX_FILE_SIZE:
            data = data[:MAX_FILE_SIZE]

        # Extract ASCII strings
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        matches = pattern.findall(data)

        if not matches:
            return f"No printable strings found (min length: {min_len})"

        # Apply stdin filter if piped
        stdin = ctx.get("stdin")
        results = [m.decode("ascii", errors="replace") for m in matches[:MAX_STRINGS]]

        if stdin:
            # This would be from a pipe — not applicable here, but output the strings
            pass

        header = f"Strings from {_format_path(vfs_path)} (min: {min_len} chars)\n"
        body = "\n".join(results)

        if len(matches) > MAX_STRINGS:
            body += f"\n\n... [{len(matches) - MAX_STRINGS} more strings truncated]"

        return header + body

    except FileNotFoundError:
        return f"File not found: {_format_path(vfs_path)}"
    except Exception as e:
        return f"Error: {e}"


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
