"""
FEPD Command: hash  (compute file hash)
==========================================

Computes cryptographic hashes for evidence files.
Essential for forensic verification and integrity checking.

Usage:
  hash <filename>             SHA-256 (default)
  hash -md5 <filename>        MD5
  hash -sha1 <filename>       SHA-1
  hash -all <filename>        All algorithms

Output:
  File:   notes.txt
  SHA256: a1b2c3d4e5f6...
  Size:   4096 bytes

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import hashlib
import os
import logging
from typing import List, Any

logger = logging.getLogger(__name__)


def hash_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """Compute cryptographic hash of an evidence file."""
    if not args:
        return "Usage: hash <filename> [-md5] [-sha1] [-all]"

    if not vfs:
        return "No evidence mounted."

    target = args[0]
    vfs_path = _to_vfs_path(target, session)

    # Determine which algorithms
    algo = "sha256"
    show_all = any(f in ("-all", "--all") for f in flags)
    if any(f in ("-md5", "--md5") for f in flags):
        algo = "md5"
    elif any(f in ("-sha1", "--sha1") for f in flags):
        algo = "sha1"

    try:
        node = vfs._node_at(vfs_path)
        if node is None:
            return f"File not found: {_format_path(vfs_path)}"
        if node.is_dir:
            return f"Cannot hash a directory: {_format_path(vfs_path)}"

        meta = vfs.stat(vfs_path)
        size = meta.get("size", "unknown") if meta else "unknown"
        stored_hash = meta.get("hash", None) if meta else None

        output = [f"File: {_format_path(vfs_path)}"]

        if stored_hash:
            output.append(f"SHA256: {stored_hash}")
        elif hasattr(vfs, "read_file"):
            content = vfs.read_file(vfs_path)
            if content:
                data = content if isinstance(content, bytes) else content.encode("utf-8")
                if show_all:
                    output.append(f"MD5:    {hashlib.md5(data).hexdigest()}")
                    output.append(f"SHA1:   {hashlib.sha1(data).hexdigest()}")
                    output.append(f"SHA256: {hashlib.sha256(data).hexdigest()}")
                else:
                    h = hashlib.new(algo)
                    h.update(data)
                    output.append(f"{algo.upper()}: {h.hexdigest()}")
            else:
                output.append("[Cannot compute hash — file content not readable]")
        else:
            output.append("[Hash not available — image mount required]")

        output.append(f"Size: {size} bytes" if isinstance(size, int) else f"Size: {size}")

        return "\n".join(output)

    except FileNotFoundError:
        return f"File not found: {_format_path(vfs_path)}"
    except Exception as e:
        return f"Error computing hash: {e}"


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
