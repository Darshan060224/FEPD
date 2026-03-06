"""
Artifact Distribution — Pie chart of evidence categories.

Investigator reads:
  • Dominant artifact types (Event Logs, Registry, Prefetch, Browser, …)
  • Missing categories may indicate anti-forensic wiping
"""

from __future__ import annotations

from typing import List

from matplotlib.figure import Figure

from src.visualization.engine.data_processor import DataProcessor, ForensicEvent
from src.visualization.engine.visualization_engine import ACCENT_COLORS, apply_dark_theme


def generate_artifact_distribution(
    events: List[ForensicEvent],
    *,
    title: str = "Artifact Distribution",
    max_slices: int = 10,
) -> Figure:
    """
    Pie / donut chart showing the proportion of each artifact category.
    """
    apply_dark_theme()

    fig = Figure(figsize=(8, 6), dpi=100)
    ax = fig.add_subplot(111)

    proc = DataProcessor()
    cat_counts = proc.category_counts(events)

    if cat_counts.empty:
        ax.text(0.5, 0.5, "No categorised events", ha="center", va="center",
                color="#888", fontsize=14, transform=ax.transAxes)
        ax.set_title(title, pad=15, fontsize=13)
        fig.tight_layout()
        return fig

    # Group small slices into "Other"
    if len(cat_counts) > max_slices:
        top = cat_counts.head(max_slices - 1)
        other_val = cat_counts.iloc[max_slices - 1:].sum()
        top["Other"] = other_val
        cat_counts = top

    labels = cat_counts.index.tolist()
    sizes = cat_counts.values.tolist()
    colors = ACCENT_COLORS[: len(labels)]

    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors,
        autopct="%1.1f%%", startangle=140,
        pctdistance=0.80,
        wedgeprops=dict(width=0.45, edgecolor="#1e1e1e", linewidth=1.5),
    )
    for t in texts:
        t.set_fontsize(9)
        t.set_color("#cccccc")
    for t in autotexts:
        t.set_fontsize(8)
        t.set_color("#ffffff")

    # Centre label
    ax.text(0, 0, f"{sum(sizes):,}\nevents", ha="center", va="center",
            fontsize=12, fontweight="bold", color="#cccccc")

    ax.set_title(title, pad=20, fontsize=13, fontweight="bold")

    fig.tight_layout()
    return fig
