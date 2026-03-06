"""
FEPD Command: pwd  (print working directory)
===============================================

Displays the current evidence path.
Always shows the VEOS evidence path — never the host filesystem.

Output example:
  C:\\Users\\Alice\\Documents

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

from typing import List, Any


def pwd_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """
    Print the current working directory (evidence path).

    Returns:
        Windows-style evidence path string.
    """
    path = session.path
    if not path:
        return "C:\\"
    return path
