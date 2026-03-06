"""
FEPD Command: score  (AI risk score)
=======================================

Queries the ML anomaly detection engine and displays the risk score
for an evidence file. Court-explainable output.

Usage:
  score <filename>

Output:
  Risk Score: 0.92
  Severity: CRITICAL

  Indicators:
  • high entropy
  • unusual execution path
  • suspicious filename

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import logging
from typing import List, Any

logger = logging.getLogger(__name__)

# Severity thresholds
SEVERITY_MAP = [
    (0.9, "CRITICAL", "🔴"),
    (0.7, "HIGH", "🟠"),
    (0.5, "MEDIUM", "🟡"),
    (0.3, "LOW", "🟢"),
    (0.0, "CLEAN", "⚪"),
]


def score_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """Display ML risk score for an evidence file."""
    if not args:
        return "Usage: score <filename>"

    if not vfs:
        return "No evidence mounted."

    target = args[0]
    vfs_path = _to_vfs_path(target, session)

    try:
        node = vfs._node_at(vfs_path)
        if node is None:
            return f"File not found: {_format_path(vfs_path)}"

        meta = vfs.stat(vfs_path) or {}
        ml_score = meta.get("ml_score")

        if ml_score is None:
            # Try ML bridge if available
            ml_bridge = ctx.get("ml_bridge")
            if ml_bridge and hasattr(ml_bridge, "score_file"):
                try:
                    ml_score = ml_bridge.score_file(vfs_path)
                except Exception:
                    pass

        if ml_score is None:
            return (
                f"File: {_format_path(vfs_path)}\n"
                f"Risk Score: [Not analyzed]\n"
                f"\n"
                f"Run ML analysis first, or file has no score data."
            )

        # Convert to float
        try:
            score_val = float(ml_score)
        except (TypeError, ValueError):
            score_val = 0.0

        # Determine severity
        severity = "UNKNOWN"
        icon = "❓"
        for threshold, label, emoji in SEVERITY_MAP:
            if score_val >= threshold:
                severity = label
                icon = emoji
                break

        # Build indicators from metadata
        indicators = _build_indicators(meta, score_val)

        output = [
            f"File: {_format_path(vfs_path)}",
            "",
            f"Risk Score: {score_val:.2f}",
            f"Severity:   {icon} {severity}",
            "",
        ]

        if indicators:
            output.append("Indicators:")
            for ind in indicators:
                output.append(f"  • {ind}")

        return "\n".join(output)

    except Exception as e:
        return f"Error computing score: {e}"


def _build_indicators(meta: dict, score: float) -> List[str]:
    """Build risk indicators based on metadata and score."""
    indicators = []

    name = meta.get("path", "") or ""
    size = meta.get("size", 0)

    # Name-based indicators
    name_lower = name.lower()
    suspicious_exts = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".com")
    if any(name_lower.endswith(ext) for ext in suspicious_exts):
        indicators.append("executable file type")

    temp_paths = ("temp", "tmp", "appdata", "download")
    if any(p in name_lower for p in temp_paths):
        indicators.append("located in temporary/download directory")

    # Size-based
    if size and size < 1024:
        indicators.append("unusually small file size")
    elif size and size > 50 * 1024 * 1024:
        indicators.append("unusually large file size")

    # Score-based
    if score >= 0.9:
        indicators.append("anomaly score exceeds critical threshold")
    elif score >= 0.7:
        indicators.append("anomaly score exceeds high threshold")

    if not indicators:
        indicators.append("no specific risk indicators detected")

    return indicators


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
