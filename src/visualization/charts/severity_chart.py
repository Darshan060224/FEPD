"""
Severity Analysis — Bar chart of risk levels.

Investigator reads:
  • Proportion of CRITICAL / HIGH / MEDIUM / LOW findings
  • A dominantly-CRITICAL dataset demands immediate attention
"""

from __future__ import annotations

from typing import List

from matplotlib.figure import Figure

from src.visualization.engine.data_processor import DataProcessor, ForensicEvent
from src.visualization.engine.visualization_engine import SEVERITY_COLORS, apply_dark_theme


def generate_severity(
    events: List[ForensicEvent],
    *,
    title: str = "Severity Analysis",
) -> Figure:
    """
    Horizontal bar chart of severity-level counts.
    """
    apply_dark_theme()

    fig = Figure(figsize=(8, 5), dpi=100)
    ax = fig.add_subplot(111)

    proc = DataProcessor()
    sev_counts = proc.severity_counts(events)

    if sev_counts.sum() == 0:
        ax.text(0.5, 0.5, "No severity data", ha="center", va="center",
                color="#888", fontsize=14, transform=ax.transAxes)
        ax.set_title(title, pad=15, fontsize=13)
        fig.tight_layout()
        return fig

    levels = sev_counts.index.tolist()
    counts = sev_counts.values.tolist()
    colors = [SEVERITY_COLORS.get(l, "#888") for l in levels]

    bars = ax.barh(levels, counts, color=colors, height=0.55, edgecolor="#1e1e1e")

    # Value labels
    max_val = max(counts) if counts else 1
    for bar, val in zip(bars, counts):
        ax.text(
            bar.get_width() + max_val * 0.02,
            bar.get_y() + bar.get_height() / 2,
            f"{val:,}",
            va="center", fontsize=10, color="#ccc",
        )

    ax.set_xlabel("Event Count", fontsize=10)
    ax.set_title(title, pad=15, fontsize=13, fontweight="bold")
    ax.invert_yaxis()
    ax.grid(axis="x", alpha=0.3)

    fig.tight_layout()
    return fig
