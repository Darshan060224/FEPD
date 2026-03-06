"""
FEPD Command: artifacts  (find related forensic artifacts)
============================================================

Searches for forensic artifacts related to a file or process.
Cross-references Prefetch, ShimCache, AmCache, Event Logs, etc.

Usage:
  artifacts <filename>
  artifacts chrome.exe

Output:
  Artifacts Found:
    Prefetch
    ShimCache
    AmCache
    Event Logs

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import logging
from typing import List, Any, Dict

logger = logging.getLogger(__name__)

# Known Windows artifact locations mapped to forensic categories
ARTIFACT_SOURCES = {
    "Prefetch": {
        "path_patterns": ["Windows/Prefetch"],
        "description": "Application execution evidence (last 8 runs)",
    },
    "ShimCache": {
        "path_patterns": ["Windows/System32/config/SYSTEM"],
        "description": "Application compatibility database (execution evidence)",
    },
    "AmCache": {
        "path_patterns": ["Windows/AppCompat/Programs/Amcache.hve"],
        "description": "Application installation and execution history",
    },
    "Event Logs": {
        "path_patterns": ["Windows/System32/winevt/Logs"],
        "description": "Windows event log records",
    },
    "Registry Hives": {
        "path_patterns": [
            "Windows/System32/config/SAM",
            "Windows/System32/config/SOFTWARE",
            "Windows/System32/config/SYSTEM",
            "Windows/System32/config/SECURITY",
        ],
        "description": "Windows registry data",
    },
    "Recent Files": {
        "path_patterns": ["Users/*/AppData/Roaming/Microsoft/Windows/Recent"],
        "description": "Recently accessed file shortcuts",
    },
    "Browser History": {
        "path_patterns": [
            "Users/*/AppData/Local/Google/Chrome/User Data",
            "Users/*/AppData/Local/Microsoft/Edge/User Data",
            "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles",
        ],
        "description": "Web browsing history and artifacts",
    },
    "USB History": {
        "path_patterns": ["Windows/inf/setupapi.dev.log"],
        "description": "USB device connection history",
    },
}


def artifacts_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """Find forensic artifacts related to a file or process."""
    if not args:
        return "Usage: artifacts <filename_or_process>"

    if not vfs:
        return "No evidence mounted."

    target = args[0]
    target_name = os.path.basename(target).lower()

    output = [
        f"Artifact Correlation: {target}",
        "=" * 50,
        "",
    ]

    found_artifacts = []

    # Search each artifact source
    for source_name, source_info in ARTIFACT_SOURCES.items():
        found = _check_artifact_source(vfs, source_name, source_info, target_name)
        if found:
            found_artifacts.append(found)

    if found_artifacts:
        output.append("Artifacts Found:")
        output.append("")
        for artifact in found_artifacts:
            status = "✓" if artifact["exists"] else "○"
            output.append(f"  {status} {artifact['name']}")
            output.append(f"    {artifact['description']}")
            if artifact["path"]:
                output.append(f"    Location: C:{artifact['path'].replace('/', chr(92))}")
            output.append("")
    else:
        output.append("No related artifacts found in evidence.")
        output.append("")
        output.append("Possible reasons:")
        output.append("  • Evidence image may be partial")
        output.append("  • Files may have been wiped")
        output.append("  • Artifact locations not indexed")

    return "\n".join(output)


def _check_artifact_source(
    vfs: Any,
    name: str,
    info: Dict,
    target_name: str,
) -> Dict | None:
    """Check if an artifact source exists in the evidence."""
    for path_pattern in info["path_patterns"]:
        # Try to find the artifact path
        # Replace wildcards with common values
        paths_to_check = [path_pattern]
        if "*" in path_pattern:
            # Replace * with common usernames
            for user in ["Administrator", "Default", "Public"]:
                paths_to_check.append(path_pattern.replace("*", user))

        for check_path in paths_to_check:
            vfs_path = "/" + check_path.replace("\\", "/")
            try:
                node = vfs._node_at(vfs_path)
                if node is not None:
                    return {
                        "name": name,
                        "description": info["description"],
                        "path": vfs_path,
                        "exists": True,
                    }
            except Exception:
                continue

    # Not found — still report as potential artifact
    return {
        "name": name,
        "description": info["description"],
        "path": "",
        "exists": False,
    }
