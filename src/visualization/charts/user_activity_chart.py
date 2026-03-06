"""
User Activity Map — Hour × user heatmap.

Investigator reads:
  • Which users are active at which hours
  • Off-hours activity per user → account compromise
"""

from __future__ import annotations

from typing import List

import numpy as np
from matplotlib.figure import Figure

from src.visualization.engine.data_processor import DataProcessor, ForensicEvent
from src.visualization.engine.visualization_engine import apply_dark_theme


def generate_user_activity(
    events: List[ForensicEvent],
    *,
    title: str = "User Activity Map",
    cmap: str = "plasma",
    max_users: int = 20,
) -> Figure:
    """
    Heatmap: rows = users, columns = hours (0-23), values = event count.
    """
    apply_dark_theme()

    proc = DataProcessor()
    matrix = proc.user_hour_matrix(events)

    fig = Figure(figsize=(12, max(4, min(len(matrix), max_users) * 0.45)), dpi=100)
    ax = fig.add_subplot(111)

    if matrix.empty:
        ax.text(0.5, 0.5, "No user-timestamped events", ha="center", va="center",
                color="#888", fontsize=14, transform=ax.transAxes)
        ax.set_title(title, pad=15, fontsize=13)
        fig.tight_layout()
        return fig

    # Limit users
    user_totals = matrix.sum(axis=1).sort_values(ascending=False)
    top_users = user_totals.head(max_users).index
    matrix = matrix.loc[top_users]

    data = matrix.values.astype(float)
    im = ax.imshow(data, cmap=cmap, aspect="auto", interpolation="nearest")
    cbar = fig.colorbar(im, ax=ax, fraction=0.02, pad=0.04)
    cbar.set_label("Events", fontsize=9)

    ax.set_xticks(range(24))
    ax.set_xticklabels([f"{h:02d}" for h in range(24)], fontsize=8)
    ax.set_xlabel("Hour of Day", fontsize=10)

    users = list(matrix.index)
    ax.set_yticks(range(len(users)))
    ax.set_yticklabels(users, fontsize=9)
    ax.set_ylabel("User", fontsize=10)

    ax.set_title(title, pad=15, fontsize=13, fontweight="bold")

    # Highlight off-hours (22-06)
    for h in list(range(22, 24)) + list(range(0, 6)):
        ax.axvline(h - 0.5, color="#e57373", linewidth=0.5, alpha=0.4)
        ax.axvline(h + 0.5, color="#e57373", linewidth=0.5, alpha=0.4)

    fig.tight_layout()
    return fig
