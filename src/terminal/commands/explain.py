"""
FEPD Command: explain  (ML explainability)
=============================================

Provides court-explainable reasoning for ML risk scores.
Makes AI decisions transparent and legally defensible.

Usage:
  explain <filename>

Output:
  This file shows anomalous characteristics.

  Reason:
  • entropy higher than normal executables
  • executed from temporary directory
  • created shortly before network activity

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import logging
from typing import List, Any, Dict

logger = logging.getLogger(__name__)


def explain_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """Explain ML risk assessment for an evidence file."""
    if not args:
        return "Usage: explain <filename>"

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

        # Try ML bridge for detailed explanation
        ml_bridge = ctx.get("ml_bridge")
        if ml_bridge and hasattr(ml_bridge, "explain"):
            try:
                explanation = ml_bridge.explain(vfs_path)
                if explanation:
                    return _format_ml_explanation(vfs_path, explanation, ml_score)
            except Exception:
                pass

        # Fallback: Generate rule-based explanation
        return _generate_rule_explanation(vfs_path, meta, ml_score)

    except Exception as e:
        return f"Error generating explanation: {e}"


def _format_ml_explanation(
    vfs_path: str,
    explanation: Dict[str, Any],
    score: Any,
) -> str:
    """Format an ML-provided explanation."""
    output = [
        f"Explainability Report: {_format_path(vfs_path)}",
        "=" * 55,
        "",
    ]

    if score is not None:
        output.append(f"Risk Score: {float(score):.2f}")
        output.append("")

    summary = explanation.get("summary", "Analysis complete.")
    output.append(summary)
    output.append("")

    reasons = explanation.get("reasons", [])
    if reasons:
        output.append("Reasons:")
        for reason in reasons:
            output.append(f"  • {reason}")

    features = explanation.get("features", {})
    if features:
        output.append("")
        output.append("Feature Contributions:")
        for feat, contrib in features.items():
            output.append(f"  {feat}: {contrib}")

    output.append("")
    output.append("[Court-Explainable AI Output — FEPD ML Engine]")

    return "\n".join(output)


def _generate_rule_explanation(
    vfs_path: str,
    meta: Dict[str, Any],
    ml_score: Any,
) -> str:
    """Generate a rule-based explanation from metadata."""
    output = [
        f"Explainability Report: {_format_path(vfs_path)}",
        "=" * 55,
        "",
    ]

    score_val = 0.0
    if ml_score is not None:
        try:
            score_val = float(ml_score)
        except (TypeError, ValueError):
            pass

    if score_val >= 0.7:
        output.append("This file shows anomalous characteristics.")
    elif score_val >= 0.4:
        output.append("This file has some unusual properties.")
    else:
        output.append("This file appears within normal parameters.")

    output.append("")
    output.append("Analysis:")

    name_lower = (meta.get("path", "") or "").lower()
    size = meta.get("size", 0)

    reasons = []

    # Extension analysis
    if any(name_lower.endswith(ext) for ext in (".exe", ".dll", ".scr", ".com")):
        reasons.append("executable file type detected")
    elif any(name_lower.endswith(ext) for ext in (".bat", ".cmd", ".ps1", ".vbs")):
        reasons.append("script file type — potential automation/execution")

    # Location analysis
    if "temp" in name_lower or "tmp" in name_lower:
        reasons.append("located in temporary directory (common malware staging)")
    if "download" in name_lower:
        reasons.append("located in download directory")
    if "appdata" in name_lower:
        reasons.append("located in application data (common persistence location)")
    if "system32" in name_lower:
        reasons.append("located in system directory")

    # Size analysis
    if size and size < 1024:
        reasons.append("file is unusually small for its type")
    elif size and size > 100 * 1024 * 1024:
        reasons.append("file is unusually large — potential data exfiltration")

    # Hash analysis
    file_hash = meta.get("hash")
    if file_hash:
        reasons.append(f"hash fingerprint: {file_hash[:16]}...")

    # Owner analysis
    owner = meta.get("owner")
    if owner:
        reasons.append(f"owner: {owner}")

    if reasons:
        for r in reasons:
            output.append(f"  • {r}")
    else:
        output.append("  • No specific risk indicators detected")

    if ml_score is not None:
        output.append(f"\nML Score: {score_val:.2f}")

    output.append("")
    output.append("[Rule-Based Analysis — ML model explanation not available]")

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
