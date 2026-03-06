"""
Heatmap Chart — Activity intensity by hour × date.

Investigator reads:
  • Bright cells → heavy activity at that hour/date
  • Activity at 2-4 AM → suspicious off-hours behaviour
"""

from __future__ import annotations

from typing import List, Optional

import numpy as np
import pandas as pd
from matplotlib.figure import Figure

from src.visualization.engine.data_processor import DataProcessor, ForensicEvent
from src.visualization.engine.visualization_engine import ACCENT_COLORS, apply_dark_theme


def generate_heatmap(
    events: List[ForensicEvent],
    *,
    title: str = "Activity Heatmap",
    cmap: str = "YlOrRd",
) -> Figure:
    """
    Build an hour-of-day × date heatmap.

    Args:
        events: Standardised forensic-event list.
        title:  Chart title.
        cmap:   Matplotlib colourmap name.

    Returns:
        ``matplotlib.figure.Figure``
    """
    apply_dark_theme()

    proc = DataProcessor()
    matrix = proc.date_hour_matrix(events)

    fig = Figure(figsize=(12, max(4, len(matrix) * 0.35)), dpi=100)
    ax = fig.add_subplot(111)

    if matrix.empty:
        ax.text(0.5, 0.5, "No timestamped events", ha="center", va="center",
                color="#888", fontsize=14, transform=ax.transAxes)
        ax.set_title(title, pad=15, fontsize=13)
        fig.tight_layout()
        return fig

    data = matrix.values.astype(float)
    im = ax.imshow(data, cmap=cmap, aspect="auto", interpolation="nearest")
    cbar = fig.colorbar(im, ax=ax, fraction=0.02, pad=0.04)
    cbar.set_label("Event Count", fontsize=9)

    # Axis labels
    ax.set_xticks(range(24))
    ax.set_xticklabels([f"{h:02d}" for h in range(24)], fontsize=8)
    ax.set_xlabel("Hour of Day", fontsize=10)

    dates = list(matrix.index)
    if len(dates) > 20:
        step = max(1, len(dates) // 15)
        ax.set_yticks(range(0, len(dates), step))
        ax.set_yticklabels([dates[i] for i in range(0, len(dates), step)], fontsize=8)
    else:
        ax.set_yticks(range(len(dates)))
        ax.set_yticklabels(dates, fontsize=8)
    ax.set_ylabel("Date", fontsize=10)

    ax.set_title(title, pad=15, fontsize=13, fontweight="bold")

    # Annotate high-value cells
    max_val = data.max()
    if max_val > 0:
        for i in range(data.shape[0]):
            for j in range(data.shape[1]):
                val = data[i, j]
                if val >= max_val * 0.7:
                    ax.text(j, i, int(val), ha="center", va="center",
                            color="black", fontsize=7, fontweight="bold")

    fig.tight_layout()
    return fig
