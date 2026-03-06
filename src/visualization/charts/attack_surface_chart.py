"""
Attack Surface Map — Identify attack vectors and exposure.

Investigator reads:
  • Which ports / services are exposed
  • Remote login frequency → brute-force indicators
  • External connections → data exfiltration risk
"""

from __future__ import annotations

from collections import Counter
from typing import List

import numpy as np
from matplotlib.figure import Figure

from src.visualization.engine.data_processor import DataProcessor, ForensicEvent
from src.visualization.engine.visualization_engine import ACCENT_COLORS, SEVERITY_COLORS, apply_dark_theme


# Port-to-risk heuristic (higher = more suspicious)
_PORT_RISK = {
    21: 0.7,   # FTP
    22: 0.5,   # SSH
    23: 0.9,   # Telnet
    25: 0.6,   # SMTP
    53: 0.3,   # DNS
    80: 0.3,   # HTTP
    110: 0.5,  # POP3
    135: 0.8,  # MSRPC
    139: 0.8,  # NetBIOS
    443: 0.2,  # HTTPS
    445: 0.8,  # SMB
    993: 0.3,  # IMAPS
    1433: 0.7, # MSSQL
    1434: 0.7, # MSSQL Browser
    3306: 0.7, # MySQL
    3389: 0.9, # RDP
    4444: 1.0, # Metasploit
    5432: 0.6, # PostgreSQL
    5900: 0.8, # VNC
    5985: 0.7, # WinRM
    8080: 0.5, # HTTP Alt
    8443: 0.4, # HTTPS Alt
}


def generate_attack_surface(
    events: List[ForensicEvent],
    *,
    title: str = "Attack Surface Map",
) -> Figure:
    """
    Multi-panel chart:
      Top-left:   Port risk scatter
      Top-right:  External connection bar
      Bottom:     Attack vector summary
    """
    apply_dark_theme()

    fig = Figure(figsize=(12, 8), dpi=100)

    # ── Panel 1: Port risk scatter ────────────────────────────────────
    ax1 = fig.add_subplot(221)
    port_counts: Counter = Counter()
    for ev in events:
        if ev.port and ev.port > 0:
            port_counts[ev.port] += 1

    if port_counts:
        ports = list(port_counts.keys())
        counts = [port_counts[p] for p in ports]
        risks = [_PORT_RISK.get(p, 0.4) for p in ports]
        colors = [
            SEVERITY_COLORS["CRITICAL"] if r >= 0.8 else
            SEVERITY_COLORS["HIGH"] if r >= 0.6 else
            SEVERITY_COLORS["MEDIUM"] if r >= 0.4 else
            SEVERITY_COLORS["LOW"]
            for r in risks
        ]
        sizes = [30 + 300 * (c / max(counts)) for c in counts]

        ax1.scatter(ports, risks, s=sizes, c=colors, alpha=0.7, edgecolors="#1e1e1e")
        for p, r, c in zip(ports, risks, counts):
            if r >= 0.7 or c >= max(counts) * 0.5:
                ax1.annotate(str(p), (p, r), fontsize=7, color="#ccc",
                             textcoords="offset points", xytext=(5, 5))
        ax1.set_xlabel("Port", fontsize=9)
        ax1.set_ylabel("Risk Score", fontsize=9)
        ax1.set_ylim(-0.05, 1.1)
        ax1.grid(True, alpha=0.3)
    else:
        ax1.text(0.5, 0.5, "No port data", ha="center", va="center", color="#888")

    ax1.set_title("Port Risk", fontsize=11, fontweight="bold")

    # ── Panel 2: External connections ─────────────────────────────────
    ax2 = fig.add_subplot(222)
    ip_counts = Counter(ev.dest_ip for ev in events if ev.dest_ip)

    if ip_counts:
        top_ips = ip_counts.most_common(10)
        labels = [ip for ip, _ in top_ips]
        vals = [c for _, c in top_ips]
        y_pos = range(len(labels))
        ax2.barh(y_pos, vals, color=ACCENT_COLORS[3], height=0.6, edgecolor="#1e1e1e")
        ax2.set_yticks(y_pos)
        ax2.set_yticklabels(labels, fontsize=8)
        ax2.invert_yaxis()
        ax2.set_xlabel("Connections", fontsize=9)
    else:
        ax2.text(0.5, 0.5, "No IP data", ha="center", va="center", color="#888")

    ax2.set_title("Top Destinations", fontsize=11, fontweight="bold")

    # ── Panel 3: Attack vector summary bars ───────────────────────────
    ax3 = fig.add_subplot(212)
    vectors = {
        "Remote Login": 0,
        "External Connection": 0,
        "Suspicious Port": 0,
        "Off-Hours Activity": 0,
        "Rare Process": 0,
        "File Download": 0,
    }

    proc = DataProcessor()
    process_counts = proc.process_counts(events)
    total_processes = process_counts.sum() if not process_counts.empty else 1

    for ev in events:
        if ev.port in (3389, 22, 5900, 5985):
            vectors["Remote Login"] += 1
        if ev.dest_ip:
            vectors["External Connection"] += 1
        if ev.port and _PORT_RISK.get(ev.port, 0) >= 0.7:
            vectors["Suspicious Port"] += 1
        if ev.timestamp and (ev.hour < 6 or ev.hour >= 22):
            vectors["Off-Hours Activity"] += 1
        if ev.process and process_counts.get(ev.process, 0) <= total_processes * 0.01:
            vectors["Rare Process"] += 1
        cat_lower = ev.category.lower()
        if "download" in cat_lower or "transfer" in cat_lower:
            vectors["File Download"] += 1

    labels = list(vectors.keys())
    vals = list(vectors.values())
    colors = [ACCENT_COLORS[i % len(ACCENT_COLORS)] for i in range(len(labels))]

    bars = ax3.bar(labels, vals, color=colors, width=0.6, edgecolor="#1e1e1e")
    for bar, val in zip(bars, vals):
        if val > 0:
            ax3.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(vals) * 0.02,
                     str(val), ha="center", fontsize=9, color="#ccc")

    ax3.set_ylabel("Count", fontsize=9)
    ax3.set_title("Attack Vectors", fontsize=11, fontweight="bold")
    ax3.tick_params(axis="x", labelsize=9)
    ax3.grid(axis="y", alpha=0.3)

    fig.suptitle(title, fontsize=14, fontweight="bold", y=0.98)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    return fig
