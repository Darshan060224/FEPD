"""
Connections Graph — Entity relationship graph using NetworkX + matplotlib.

Investigator reads:
  • Central nodes are high-connectivity entities (potential C2 servers, pivots)
  • Edge density shows communication intensity
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import List

from matplotlib.figure import Figure

from src.visualization.engine.data_processor import ForensicEvent
from src.visualization.engine.visualization_engine import ACCENT_COLORS, apply_dark_theme

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    _HAS_NX = True
except ImportError:
    _HAS_NX = False


def generate_connections(
    events: List[ForensicEvent],
    *,
    title: str = "Connections Graph",
    max_nodes: int = 60,
    layout: str = "spring",
) -> Figure:
    """
    Network graph of entity relationships:
      • IP ↔ IP
      • User → Process
      • Process → File

    Falls back to a bar chart of top connections if NetworkX is unavailable.
    """
    apply_dark_theme()

    fig = Figure(figsize=(10, 8), dpi=100)
    ax = fig.add_subplot(111)

    edges: List[tuple] = []
    node_types: dict = {}

    for ev in events:
        if ev.source_ip and ev.dest_ip:
            edges.append((ev.source_ip, ev.dest_ip))
            node_types[ev.source_ip] = "ip"
            node_types[ev.dest_ip] = "ip"
        if ev.user and ev.process:
            edges.append((ev.user, ev.process))
            node_types[ev.user] = "user"
            node_types[ev.process] = "process"
        if ev.process and ev.file:
            edges.append((ev.process, ev.file.split("/")[-1].split("\\")[-1]))
            node_types[ev.process] = "process"

    if not edges:
        ax.text(0.5, 0.5, "No connections to display", ha="center", va="center",
                color="#888", fontsize=14, transform=ax.transAxes)
        ax.set_title(title, pad=15, fontsize=13)
        fig.tight_layout()
        return fig

    if not _HAS_NX:
        return _fallback_bar(edges, title, fig, ax)

    # Build graph
    G = nx.Graph()
    edge_counts = Counter(edges)
    for (u, v), w in edge_counts.most_common(max_nodes * 3):
        G.add_edge(u, v, weight=w)

    # Limit nodes
    if G.number_of_nodes() > max_nodes:
        top_nodes = sorted(G.degree, key=lambda x: x[1], reverse=True)[:max_nodes]
        keep = {n for n, _ in top_nodes}
        G = G.subgraph(keep).copy()

    # Layout
    layout_fn = {
        "spring": nx.spring_layout,
        "kamada": nx.kamada_kawai_layout,
        "circular": nx.circular_layout,
        "shell": nx.shell_layout,
    }
    pos = layout_fn.get(layout, nx.spring_layout)(G, seed=42)

    # Node colours by type
    type_colors = {"ip": "#e57373", "user": "#4fc3f7", "process": "#81c784"}
    node_colors = [type_colors.get(node_types.get(n, ""), "#90a4ae") for n in G.nodes()]

    # Node sizes by degree
    degrees = dict(G.degree())
    max_deg = max(degrees.values()) if degrees else 1
    node_sizes = [300 + 700 * (degrees[n] / max_deg) for n in G.nodes()]

    # Edge widths
    weights = [G[u][v].get("weight", 1) for u, v in G.edges()]
    max_w = max(weights) if weights else 1
    edge_widths = [0.5 + 2.5 * (w / max_w) for w in weights]

    nx.draw_networkx_edges(G, pos, ax=ax, alpha=0.4, width=edge_widths, edge_color="#555")
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=node_sizes,
                           edgecolors="#1e1e1e", linewidths=0.5)
    nx.draw_networkx_labels(G, pos, ax=ax, font_size=7, font_color="#e0e0e0")

    ax.set_title(title, pad=15, fontsize=13, fontweight="bold")
    ax.axis("off")

    # Legend
    import matplotlib.patches as mpatches
    legend_items = [
        mpatches.Patch(color="#e57373", label="IP Address"),
        mpatches.Patch(color="#4fc3f7", label="User"),
        mpatches.Patch(color="#81c784", label="Process"),
    ]
    ax.legend(handles=legend_items, loc="lower left", fontsize=8,
              facecolor="#2d2d30", edgecolor="#3e3e42", labelcolor="#ccc")

    fig.tight_layout()
    return fig


def _fallback_bar(edges, title, fig, ax):
    """Simple bar chart when NetworkX is not installed."""
    counter = Counter(edges)
    top = counter.most_common(15)
    labels = [f"{u}→{v}" for (u, v), _ in top]
    values = [c for _, c in top]

    y_pos = range(len(labels))
    ax.barh(y_pos, values, color=ACCENT_COLORS[0], height=0.6)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Count", fontsize=10)
    ax.set_title(f"{title} (top connections)", pad=15, fontsize=13, fontweight="bold")
    ax.invert_yaxis()
    fig.tight_layout()
    return fig
