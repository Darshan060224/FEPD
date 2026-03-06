"""
FEPD Visualization Controller
===============================

Sits between the Visualization Tab UI and the engine.
Handles data loading, chart requests, export, and caching.

Architecture:
    Visualization Tab (UI)
            │
    VisualizationController
            │
    VisualizationEngine → DataProcessor → Chart modules
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from src.visualization.engine.data_processor import DataProcessor, ForensicEvent
from src.visualization.engine.visualization_engine import (
    VisualizationEngine, ChartCanvas, apply_dark_theme,
)

logger = logging.getLogger(__name__)


class VisualizationController(QObject):
    """
    Controller for the Visualization Tab.

    Responsibilities:
      • Accept raw event data (DataFrame, list[dict], etc.)
      • Normalise through DataProcessor
      • Request charts via VisualizationEngine
      • Manage export (PNG / PDF / SVG)
      • Emit signals for the UI to react
    """

    # Signals
    chart_ready = pyqtSignal(str, object)      # chart_type, Figure
    chart_error = pyqtSignal(str, str)         # chart_type, error msg
    data_loaded = pyqtSignal(int)              # event count
    status_message = pyqtSignal(str)

    # Supported chart keys (UI uses these to build tabs)
    CHART_TYPES = [
        "heatmap",
        "timeline",
        "artifact_distribution",
        "severity",
        "user_activity",
        "connections",
        "attack_surface",
    ]

    CHART_LABELS = {
        "heatmap": "🔥 Activity Heatmap",
        "timeline": "📈 Event Timeline",
        "artifact_distribution": "🧾 Artifact Distribution",
        "severity": "⚠️ Severity Analysis",
        "user_activity": "👤 User Activity",
        "connections": "🌐 Connections Graph",
        "attack_surface": "⚔️ Attack Surface",
    }

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.engine = VisualizationEngine(parent=self)
        self._events: List[ForensicEvent] = []

        self.engine.chart_ready.connect(self.chart_ready)
        self.engine.chart_error.connect(self.chart_error)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

    def load_events(self, data: Any, *, max_events: int = 100_000) -> int:
        """Load and normalise event data. Returns event count."""
        self._events = self.engine.load_data(data, max_events=max_events)
        count = len(self._events)
        self.data_loaded.emit(count)
        self.status_message.emit(f"Loaded {count:,} events")
        logger.info("Visualization controller loaded %d events", count)
        return count

    @property
    def events(self) -> List[ForensicEvent]:
        return self._events

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def processor(self) -> DataProcessor:
        return self.engine.processor

    # ------------------------------------------------------------------
    # Chart generation
    # ------------------------------------------------------------------

    def generate_chart(self, chart_type: str, *, async_: bool = True, **options):
        """Request a chart. Result arrives via chart_ready signal."""
        if not self._events:
            self.chart_error.emit(chart_type, "No data loaded")
            return
        self.status_message.emit(f"Generating {chart_type}…")
        self.engine.generate(chart_type, self._events, async_=async_, **options)

    def generate_all(self, *, async_: bool = True, **options):
        """Generate every registered chart type."""
        for ct in self.CHART_TYPES:
            self.generate_chart(ct, async_=async_, **options)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_chart(self, fig, path: str, fmt: str = "png", dpi: int = 150):
        """Save a Figure to disk."""
        self.engine.save_figure(fig, path, fmt=fmt, dpi=dpi)
        self.status_message.emit(f"Saved to {path}")

    def export_all(self, output_dir: str, fmt: str = "png", dpi: int = 150):
        """Generate all charts synchronously and export them."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        for ct in self.CHART_TYPES:
            try:
                fig = self.engine.generate_sync(ct, self._events)
                if fig:
                    fpath = out / f"{ct}.{fmt}"
                    self.engine.save_figure(fig, str(fpath), fmt=fmt, dpi=dpi)
            except Exception as exc:
                logger.error("Export failed for %s: %s", ct, exc)
        self.status_message.emit(f"Exported {len(self.CHART_TYPES)} charts to {output_dir}")

    # ------------------------------------------------------------------
    # Summary statistics (for dashboard text)
    # ------------------------------------------------------------------

    def get_summary(self) -> Dict[str, Any]:
        """Return summary statistics about the current dataset."""
        if not self._events:
            return {}
        proc = self.engine.processor
        return {
            "total_events": len(self._events),
            "severity_counts": proc.severity_counts(self._events).to_dict(),
            "category_counts": proc.category_counts(self._events).head(10).to_dict(),
            "source_counts": proc.source_counts(self._events).head(10).to_dict(),
            "unique_users": len(set(e.user for e in self._events if e.user != "SYSTEM")),
            "date_range": self._date_range(),
        }

    def _date_range(self) -> str:
        ts = [e.timestamp for e in self._events if e.timestamp]
        if not ts:
            return "No timestamps"
        return f"{min(ts).strftime('%Y-%m-%d %H:%M')} → {max(ts).strftime('%Y-%m-%d %H:%M')}"
