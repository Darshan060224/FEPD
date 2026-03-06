"""
FEPD Command: grep  (search file contents)
=============================================

Searches for text patterns within evidence files.
Supports piped input: ``strings malware.exe | grep http``

Usage:
  grep <pattern> <filename>
  grep -i <pattern> <filename>     Case-insensitive
  strings file.exe | grep http     Piped input

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import re
import logging
from typing import List, Any

logger = logging.getLogger(__name__)

MAX_MATCHES = 500


def grep_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """Search for text patterns in evidence files or piped input."""
    stdin = ctx.get("stdin", "")

    # Parse flags
    case_insensitive = any(f in ("-i", "--ignore-case") for f in flags)
    show_count = any(f in ("-c", "--count") for f in flags)

    if not args:
        return "Usage: grep <pattern> [<filename>]"

    pattern = args[0]
    target = args[1] if len(args) > 1 else None

    # Build regex
    try:
        re_flags = re.IGNORECASE if case_insensitive else 0
        regex = re.compile(pattern, re_flags)
    except re.error as e:
        return f"Invalid pattern: {e}"

    # If we have piped input, search that
    if stdin:
        return _grep_text(stdin, regex, pattern, show_count)

    # Otherwise, search a file
    if not target:
        return "Usage: grep <pattern> <filename>"

    if not vfs:
        return "No evidence mounted."

    vfs_path = _to_vfs_path(target, session)

    try:
        node = vfs._node_at(vfs_path)
        if node is None:
            return f"File not found: {_format_path(vfs_path)}"
        if node.is_dir:
            return "Cannot grep a directory. Use: find -name '*.txt'"

        if not hasattr(vfs, "read_file"):
            return "[Grep requires mounted evidence image]"

        content = vfs.read_file(vfs_path)
        if content is None:
            return "[Cannot read file content]"

        text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)
        return _grep_text(text, regex, pattern, show_count, _format_path(vfs_path))

    except FileNotFoundError:
        return f"File not found: {_format_path(vfs_path)}"
    except Exception as e:
        return f"Error: {e}"


def _grep_text(
    text: str,
    regex: re.Pattern,
    pattern_str: str,
    show_count: bool,
    source: str = "stdin",
) -> str:
    """Search text for pattern matches."""
    lines = text.split("\n")
    matches = []

    for line_no, line in enumerate(lines, 1):
        if regex.search(line):
            matches.append((line_no, line.rstrip()))
            if len(matches) >= MAX_MATCHES:
                break

    if show_count:
        return f"{len(matches)} matches found for '{pattern_str}' in {source}"

    if not matches:
        return f"No matches for '{pattern_str}'"

    output = []
    for line_no, line in matches:
        if source != "stdin":
            output.append(f"{line_no}: {line}")
        else:
            output.append(line)

    if len(matches) >= MAX_MATCHES:
        output.append(f"\n... [truncated at {MAX_MATCHES} matches]")

    return "\n".join(output)


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
