"""
FEPD Command: connections  (network activity correlation)
===========================================================

Shows network connections/activity related to a process or file.
Queries indexed network artifacts from the evidence.

Usage:
  connections <process_name>
  connections chrome.exe

Output:
  Connections:
    192.168.1.5 → 34.120.54.22
    192.168.1.5 → 142.250.183.78

Copyright (c) 2026 FEPD Development Team
"""

from __future__ import annotations

import os
import sqlite3
import logging
from typing import List, Any, Dict

logger = logging.getLogger(__name__)


def connections_command(
    args: List[str],
    flags: List[str],
    session: Any,
    vfs: Any,
    **ctx,
) -> str:
    """Show network connections related to a process."""
    if not args:
        return "Usage: connections <process_name>"

    target = args[0]
    target_name = os.path.basename(target).lower()

    output = [
        f"Network Connections: {target}",
        "=" * 50,
        "",
    ]

    # Try to query indexed network data from the case database
    db_path = ctx.get("db_path")
    if db_path and os.path.exists(db_path):
        connections = _query_network_data(db_path, target_name)
        if connections:
            output.append("Connections Found:")
            output.append("")
            for conn in connections:
                src = conn.get("src", "unknown")
                dst = conn.get("dst", "unknown")
                port = conn.get("port", "")
                proto = conn.get("protocol", "TCP")
                port_str = f":{port}" if port else ""
                output.append(f"  {src} → {dst}{port_str} ({proto})")
            output.append("")
            output.append(f"[{len(connections)} connection(s) found]")
            return "\n".join(output)

    # No database or no results — provide helpful output
    output.append("No indexed network data found.")
    output.append("")
    output.append("To find network artifacts:")
    output.append("  1. Check browser history:  artifacts chrome.exe")
    output.append("  2. Search event logs:      find -name '*.evtx'")
    output.append("  3. Look for PCAPs:         find -name '*.pcap'")
    output.append("")
    output.append("Network indexing may require:")
    output.append("  • Memory dump analysis (volatility)")
    output.append("  • PCAP file parsing")
    output.append("  • Event log extraction")

    return "\n".join(output)


def _query_network_data(db_path: str, process_name: str) -> List[Dict]:
    """Query network connection data from case database."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Check if network_connections table exists
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='network_connections'"
        )
        if cur.fetchone():
            cur.execute(
                "SELECT * FROM network_connections WHERE process LIKE ? LIMIT 100",
                (f"%{process_name}%",),
            )
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows

        conn.close()
    except Exception:
        pass
    return []
