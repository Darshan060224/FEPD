"""
Timeline Chart — Event volume over time.

Investigator reads:
  • Spikes indicate bursts of activity (attacker C2 beaconing, exfiltration)
  • Flat regions may indicate evidence gaps / anti-forensics
"""

from __future__ import annotations

from typing import List

import pandas as pd
from matplotlib.figure import Figure
import matplotlib.dates as mdates

from src.visualization.engine.data_processor import DataProcessor, ForensicEvent
from src.visualization.engine.visualization_engine import ACCENT_COLORS, apply_dark_theme


def generate_timeline(
    events: List[ForensicEvent],
    *,
    title: str = "Event Timeline",
    resolution: str = "hour",
) -> Figure:
    """
    Line chart of event counts binned by time.

    Args:
        events:     ForensicEvent list.
        title:      Chart title.
        resolution: ``"hour"`` | ``"day"`` | ``"minute"``.
    """
    apply_dark_theme()

    fig = Figure(figsize=(12, 5), dpi=100)
    ax = fig.add_subplot(111)

    ts = [e.timestamp for e in events if e.timestamp]
    if not ts:
        ax.text(0.5, 0.5, "No timestamped events", ha="center", va="center",
                color="#888", fontsize=14, transform=ax.transAxes)
        ax.set_title(title, pad=15, fontsize=13)
        fig.tight_layout()
        return fig

    df = pd.DataFrame({"ts": ts})
    df["ts"] = pd.to_datetime(df["ts"])

    freq_map = {"minute": "min", "hour": "h", "day": "D"}
    freq = freq_map.get(resolution, "h")
    counts = df.set_index("ts").resample(freq).size()

    ax.fill_between(counts.index, counts.values, alpha=0.3, color=ACCENT_COLORS[0])
    ax.plot(counts.index, counts.values, color=ACCENT_COLORS[0], linewidth=1.5)

    # Mark peak
    if len(counts) > 0:
        peak_idx = counts.idxmax()
        peak_val = counts.max()
        ax.annotate(
            f"Peak: {peak_val}",
            xy=(peak_idx, peak_val),
            xytext=(20, 15),
            textcoords="offset points",
            fontsize=9,
            color="#e57373",
            arrowprops=dict(arrowstyle="->", color="#e57373"),
        )

    ax.set_xlabel("Time", fontsize=10)
    ax.set_ylabel("Event Count", fontsize=10)
    ax.set_title(title, pad=15, fontsize=13, fontweight="bold")
    ax.grid(True, alpha=0.3)

    # Format x-axis dates
    if resolution == "day":
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
    else:
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d %H:%M"))
    fig.autofmt_xdate(rotation=30)

    fig.tight_layout()
    return fig
