"""
FEPD Visualization Engine
==========================

Central orchestrator that every tab calls to produce charts.

Pipeline:
    raw data → DataProcessor → ForensicEvent list
        → Chart module → matplotlib Figure
        → FigureCanvas → embedded in PyQt6 widget

Features:
  • One engine instance serves all tabs
  • Automatic caching of recently generated figures
  • PNG / PDF / SVG export via ``save_figure``
  • Dark-theme defaults matching FEPD colour scheme
  • Thread-safe: heavy charts run in QThread
"""

from __future__ import annotations

import io
import logging
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib
matplotlib.use("Agg")  # non-interactive backend — we render to canvas only
import matplotlib.pyplot as plt
from matplotlib.figure import Figure

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QSizePolicy
from PyQt6.QtCore import QObject, pyqtSignal, QThread

try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
except ImportError:
    from matplotlib.backends.backend_qt5agg import FigureCanvasQT as FigureCanvas

from src.visualization.engine.data_processor import DataProcessor, ForensicEvent

logger = logging.getLogger(__name__)


# ============================================================================
# DARK THEME DEFAULTS (matches FEPD palette)
# ============================================================================

DARK_THEME: Dict[str, Any] = {
    "figure.facecolor": "#1e1e1e",
    "axes.facecolor": "#252526",
    "axes.edgecolor": "#3e3e42",
    "axes.labelcolor": "#cccccc",
    "text.color": "#cccccc",
    "xtick.color": "#999999",
    "ytick.color": "#999999",
    "grid.color": "#3e3e42",
    "grid.alpha": 0.4,
    "legend.facecolor": "#2d2d30",
    "legend.edgecolor": "#3e3e42",
    "savefig.facecolor": "#1e1e1e",
    "savefig.edgecolor": "#1e1e1e",
    "font.family": "Segoe UI",
    "font.size": 10,
}

# Accent colour palette for chart series
ACCENT_COLORS = [
    "#4fc3f7",  # cyan
    "#81c784",  # green
    "#ffb74d",  # orange
    "#e57373",  # red
    "#ba68c8",  # purple
    "#4dd0e1",  # teal
    "#aed581",  # lime
    "#ff8a65",  # deep orange
    "#90a4ae",  # blue-grey
    "#fff176",  # yellow
]

SEVERITY_COLORS = {
    "CRITICAL": "#d32f2f",
    "HIGH": "#f57c00",
    "MEDIUM": "#fbc02d",
    "LOW": "#66bb6a",
}


def apply_dark_theme():
    """Apply the dark theme to matplotlib globally."""
    for key, val in DARK_THEME.items():
        plt.rcParams[key] = val


# ============================================================================
# FIGURE CACHE
# ============================================================================

class _FigureCache:
    """LRU cache for matplotlib Figures, keyed by chart-type + data hash."""

    def __init__(self, maxsize: int = 20):
        self._cache: OrderedDict[str, Figure] = OrderedDict()
        self._max = maxsize

    def get(self, key: str) -> Optional[Figure]:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def put(self, key: str, fig: Figure):
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = fig
        while len(self._cache) > self._max:
            self._cache.popitem(last=False)

    def invalidate(self):
        self._cache.clear()


# ============================================================================
# CHART CANVAS WIDGET (embed matplotlib in PyQt6)
# ============================================================================

class ChartCanvas(QWidget):
    """
    Lightweight PyQt6 widget that wraps a ``FigureCanvas``.

    Usage:
        canvas = ChartCanvas()
        canvas.set_figure(fig)
        layout.addWidget(canvas)
    """

    def __init__(self, parent: Optional[QWidget] = None, width: int = 8, height: int = 5):
        super().__init__(parent)
        self._fig = Figure(figsize=(width, height), dpi=100)
        self._canvas = FigureCanvas(self._fig)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self._canvas)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    @property
    def figure(self) -> Figure:
        return self._fig

    @property
    def canvas(self) -> FigureCanvas:
        return self._canvas

    def set_figure(self, fig: Figure):
        """Replace the current figure and redraw."""
        # remove old canvas
        lay = self.layout()
        if lay.count():
            old = lay.takeAt(0).widget()
            if old:
                old.setParent(None)
                old.deleteLater()
        self._fig = fig
        self._canvas = FigureCanvas(fig)
        lay.addWidget(self._canvas)
        self._canvas.draw()

    def redraw(self):
        self._canvas.draw()

    def save(self, path: str, fmt: str = "png", dpi: int = 150):
        """Export the current figure to file."""
        self._fig.savefig(path, format=fmt, dpi=dpi, bbox_inches="tight")


# ============================================================================
# CHART WORKER (QThread)
# ============================================================================

class _ChartWorker(QThread):
    """Runs chart generation off the UI thread."""

    finished = pyqtSignal(str, object)  # chart_type, Figure
    error = pyqtSignal(str, str)        # chart_type, error message

    def __init__(
        self,
        chart_type: str,
        generate_fn,
        events: List[ForensicEvent],
        options: Dict[str, Any],
        parent=None,
    ):
        super().__init__(parent)
        self._chart_type = chart_type
        self._fn = generate_fn
        self._events = events
        self._options = options

    def run(self):
        try:
            apply_dark_theme()
            fig = self._fn(self._events, **self._options)
            self.finished.emit(self._chart_type, fig)
        except Exception as exc:
            logger.exception("Chart generation failed: %s", exc)
            self.error.emit(self._chart_type, str(exc))


# ============================================================================
# VISUALIZATION ENGINE
# ============================================================================

class VisualizationEngine(QObject):
    """
    Central chart factory.

    One instance is shared across all tabs.  Use ``generate()`` to
    request a chart; listen to ``chart_ready`` for the result.

    Supported chart types:
        heatmap, timeline, artifact_distribution, severity,
        user_activity, connections, attack_surface
    """

    chart_ready = pyqtSignal(str, object)   # chart_type, Figure
    chart_error = pyqtSignal(str, str)      # chart_type, error

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.processor = DataProcessor()
        self._cache = _FigureCache(maxsize=30)
        self._workers: Dict[str, _ChartWorker] = {}
        self._chart_registry: Dict[str, Any] = {}
        self._register_defaults()

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    def register_chart(self, chart_type: str, generate_fn):
        """Register a chart-generation function.

        ``generate_fn(events, **options) → Figure``
        """
        self._chart_registry[chart_type] = generate_fn

    def _register_defaults(self):
        from src.visualization.charts.heatmap_chart import generate_heatmap
        from src.visualization.charts.timeline_chart import generate_timeline
        from src.visualization.charts.artifact_distribution import generate_artifact_distribution
        from src.visualization.charts.severity_chart import generate_severity
        from src.visualization.charts.user_activity_chart import generate_user_activity
        from src.visualization.charts.connections_graph import generate_connections
        from src.visualization.charts.attack_surface_chart import generate_attack_surface

        self._chart_registry = {
            "heatmap": generate_heatmap,
            "timeline": generate_timeline,
            "artifact_distribution": generate_artifact_distribution,
            "severity": generate_severity,
            "user_activity": generate_user_activity,
            "connections": generate_connections,
            "attack_surface": generate_attack_surface,
        }

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def load_data(self, data: Any, *, max_events: int = 100_000) -> List[ForensicEvent]:
        """Parse raw data into ForensicEvent list and cache it."""
        events = self.processor.process(data, max_events=max_events)
        self._cache.invalidate()
        return events

    # ------------------------------------------------------------------
    # Chart generation
    # ------------------------------------------------------------------

    def generate(
        self,
        chart_type: str,
        events: Optional[List[ForensicEvent]] = None,
        *,
        async_: bool = True,
        **options,
    ) -> Optional[Figure]:
        """
        Request a chart.

        Args:
            chart_type: Key from the chart registry.
            events: If None, uses the last-loaded dataset.
            async_: If True, runs in QThread and emits ``chart_ready``.
                    If False, blocks and returns the Figure directly.
            **options: Chart-specific parameters.

        Returns:
            ``Figure`` when ``async_=False``, else ``None`` (use signal).
        """
        gen_fn = self._chart_registry.get(chart_type)
        if gen_fn is None:
            self.chart_error.emit(chart_type, f"Unknown chart type: {chart_type}")
            return None

        evts = events or self.processor.last_events
        if not evts:
            self.chart_error.emit(chart_type, "No event data loaded")
            return None

        if async_:
            worker = _ChartWorker(chart_type, gen_fn, evts, options, parent=self)
            worker.finished.connect(self._on_chart_done)
            worker.error.connect(self.chart_error)
            self._workers[chart_type] = worker
            worker.start()
            return None
        else:
            apply_dark_theme()
            fig = gen_fn(evts, **options)
            return fig

    def generate_sync(self, chart_type: str, events=None, **options) -> Optional[Figure]:
        """Convenience wrapper for synchronous generation."""
        return self.generate(chart_type, events, async_=False, **options)

    def _on_chart_done(self, chart_type: str, fig: Figure):
        self._cache.put(chart_type, fig)
        self.chart_ready.emit(chart_type, fig)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @staticmethod
    def save_figure(fig: Figure, path: str, fmt: str = "png", dpi: int = 150):
        """Save a figure to disk (PNG/PDF/SVG)."""
        fig.savefig(path, format=fmt, dpi=dpi, bbox_inches="tight")
        logger.info("Chart saved: %s", path)

    @staticmethod
    def figure_to_bytes(fig: Figure, fmt: str = "png", dpi: int = 150) -> bytes:
        buf = io.BytesIO()
        fig.savefig(buf, format=fmt, dpi=dpi, bbox_inches="tight")
        buf.seek(0)
        return buf.read()
