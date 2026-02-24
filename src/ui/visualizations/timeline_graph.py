"""
Interactive Timeline Graph Visualization
=========================================

Zoomable histogram showing event density and activity bursts over time.

Features:
- Event count histogram (bursts visualization)
- Interactive zooming and panning
- Click-through to event details
- Time range brushing
- Export to PNG/SVG
- Multiple event type layers

Reference: Belkasoft X timeline histograms
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import logging

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    MPL_AVAILABLE = True
except ImportError:
    MPL_AVAILABLE = False
    logging.warning("Matplotlib not available. Install: pip install matplotlib")

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    logging.warning("Plotly not available. Install: pip install plotly")

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QComboBox, QLabel, QSlider, QCheckBox, QGroupBox)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWebEngineWidgets import QWebEngineView


class TimelineGraphWidget(QWidget):
    """
    PyQt widget displaying interactive timeline graph.
    
    Shows event density over time as a histogram, allowing users to:
    - Identify activity bursts
    - Zoom into time ranges
    - Filter by event type
    - Export visualizations
    """
    
    # Signals
    time_range_selected = pyqtSignal(datetime, datetime)  # User selected time range
    event_clicked = pyqtSignal(int)  # User clicked on time bin (event count)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.events_df = None
        self.current_backend = 'matplotlib'  # or 'plotly'
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        # Backend selection
        controls_layout.addWidget(QLabel("Visualization:"))
        self.backend_combo = QComboBox()
        self.backend_combo.addItems(['Matplotlib (Static)', 'Plotly (Interactive)'])
        self.backend_combo.currentIndexChanged.connect(self._on_backend_changed)
        controls_layout.addWidget(self.backend_combo)
        
        # Time bin size
        controls_layout.addWidget(QLabel("Time Bin:"))
        self.bin_combo = QComboBox()
        self.bin_combo.addItems(['1 Hour', '6 Hours', '1 Day', '1 Week', '1 Month'])
        self.bin_combo.setCurrentText('1 Day')
        self.bin_combo.currentTextChanged.connect(self._on_bin_changed)
        controls_layout.addWidget(self.bin_combo)
        
        # Event type filter
        controls_layout.addWidget(QLabel("Event Types:"))
        self.event_type_combo = QComboBox()
        self.event_type_combo.addItem('All Events')
        self.event_type_combo.currentTextChanged.connect(self._on_filter_changed)
        controls_layout.addWidget(self.event_type_combo)
        
        # Stacked option
        self.stacked_checkbox = QCheckBox("Stacked by Type")
        self.stacked_checkbox.stateChanged.connect(self._on_stacked_changed)
        controls_layout.addWidget(self.stacked_checkbox)
        
        controls_layout.addStretch()
        
        # Export button
        self.export_btn = QPushButton("Export Chart")
        self.export_btn.clicked.connect(self._on_export)
        controls_layout.addWidget(self.export_btn)
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._refresh_graph)
        controls_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(controls_layout)
        
        # Matplotlib canvas
        self.mpl_figure = Figure(figsize=(12, 6))
        self.mpl_canvas = FigureCanvas(self.mpl_figure) if MPL_AVAILABLE else None
        if self.mpl_canvas:
            layout.addWidget(self.mpl_canvas)
        
        # Plotly web view (hidden initially)
        self.plotly_view = QWebEngineView() if PLOTLY_AVAILABLE else None
        if self.plotly_view:
            self.plotly_view.hide()
            layout.addWidget(self.plotly_view)
    
    def load_events(self, events_df: pd.DataFrame):
        """
        Load events for visualization.
        
        Args:
            events_df: DataFrame with 'timestamp' and optionally 'event_type'
        """
        if 'timestamp' not in events_df.columns:
            self.logger.error("Events DataFrame must have 'timestamp' column")
            return
        
        self.events_df = events_df.copy()
        self.events_df['timestamp'] = pd.to_datetime(self.events_df['timestamp'])
        
        # Populate event type filter
        if 'event_type' in self.events_df.columns:
            event_types = sorted(self.events_df['event_type'].unique())
            self.event_type_combo.clear()
            self.event_type_combo.addItem('All Events')
            self.event_type_combo.addItems(event_types)
        
        self._refresh_graph()
    
    def _on_backend_changed(self, index):
        """Handle backend selection change."""
        if index == 0:
            self.current_backend = 'matplotlib'
            if self.mpl_canvas:
                self.mpl_canvas.show()
            if self.plotly_view:
                self.plotly_view.hide()
        else:
            self.current_backend = 'plotly'
            if self.mpl_canvas:
                self.mpl_canvas.hide()
            if self.plotly_view:
                self.plotly_view.show()
        
        self._refresh_graph()
    
    def _on_bin_changed(self, bin_text):
        """Handle time bin size change."""
        self._refresh_graph()
    
    def _on_filter_changed(self, event_type):
        """Handle event type filter change."""
        self._refresh_graph()
    
    def _on_stacked_changed(self, state):
        """Handle stacked chart toggle."""
        self._refresh_graph()
    
    def _on_export(self):
        """Export current chart."""
        from PyQt6.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Timeline Graph",
            "timeline_graph.png",
            "PNG Image (*.png);;SVG Vector (*.svg);;HTML Interactive (*.html)"
        )
        
        if not file_path:
            return
        
        if file_path.endswith('.html') and self.current_backend == 'plotly':
            self._export_plotly_html(file_path)
        elif file_path.endswith('.svg'):
            self._export_matplotlib_svg(file_path)
        else:
            self._export_matplotlib_png(file_path)
    
    def _get_time_bin(self) -> str:
        """Get pandas frequency string for current bin size."""
        bin_text = self.bin_combo.currentText()
        
        mapping = {
            '1 Hour': '1H',
            '6 Hours': '6H',
            '1 Day': '1D',
            '1 Week': '1W',
            '1 Month': '1M'
        }
        
        return mapping.get(bin_text, '1D')
    
    def _filter_events(self) -> pd.DataFrame:
        """Apply current filters to events."""
        if self.events_df is None or len(self.events_df) == 0:
            return pd.DataFrame()
        
        filtered = self.events_df.copy()
        
        # Event type filter
        event_type = self.event_type_combo.currentText()
        if event_type != 'All Events':
            filtered = filtered[filtered['event_type'] == event_type]
        
        return filtered
    
    def _refresh_graph(self):
        """Refresh the timeline graph."""
        if self.events_df is None or len(self.events_df) == 0:
            return
        
        if self.current_backend == 'matplotlib':
            self._plot_matplotlib()
        elif self.current_backend == 'plotly':
            self._plot_plotly()
    
    def _plot_matplotlib(self):
        """Create matplotlib histogram."""
        if not MPL_AVAILABLE:
            return
        
        filtered = self._filter_events()
        if len(filtered) == 0:
            return
        
        self.mpl_figure.clear()
        ax = self.mpl_figure.add_subplot(111)
        
        # Get time bin
        time_bin = self._get_time_bin()
        
        # Check if stacked
        if self.stacked_checkbox.isChecked() and 'event_type' in filtered.columns:
            # Stacked histogram by event type
            event_types = filtered['event_type'].unique()
            counts_by_type = {}
            
            for event_type in event_types:
                type_events = filtered[filtered['event_type'] == event_type]
                counts = type_events.set_index('timestamp').resample(time_bin).size()
                counts_by_type[event_type] = counts
            
            # Create DataFrame for stacked plotting
            counts_df = pd.DataFrame(counts_by_type).fillna(0)
            
            # Plot stacked bars
            counts_df.plot(kind='bar', stacked=True, ax=ax, width=0.8)
            ax.set_ylabel('Event Count')
            ax.set_title('Timeline: Event Activity (Stacked by Type)')
            ax.legend(title='Event Type', bbox_to_anchor=(1.05, 1), loc='upper left')
            
        else:
            # Simple histogram
            counts = filtered.set_index('timestamp').resample(time_bin).size()
            
            ax.bar(counts.index, counts.values, width=pd.Timedelta(time_bin) * 0.8, 
                   color='steelblue', edgecolor='black', alpha=0.7)
            ax.set_ylabel('Event Count')
            ax.set_title('Timeline: Event Activity Over Time')
        
        ax.set_xlabel('Time')
        ax.grid(True, alpha=0.3)
        
        # Format x-axis dates
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d\n%H:%M'))
        ax.xaxis.set_major_locator(mdates.AutoDateLocator())
        self.mpl_figure.autofmt_xdate()
        
        self.mpl_figure.tight_layout()
        self.mpl_canvas.draw()
    
    def _plot_plotly(self):
        """Create interactive Plotly histogram."""
        if not PLOTLY_AVAILABLE:
            return
        
        filtered = self._filter_events()
        if len(filtered) == 0:
            return
        
        time_bin = self._get_time_bin()
        
        if self.stacked_checkbox.isChecked() and 'event_type' in filtered.columns:
            # Stacked histogram
            event_types = filtered['event_type'].unique()
            
            fig = go.Figure()
            
            for event_type in event_types:
                type_events = filtered[filtered['event_type'] == event_type]
                counts = type_events.set_index('timestamp').resample(time_bin).size()
                
                fig.add_trace(go.Bar(
                    x=counts.index,
                    y=counts.values,
                    name=event_type,
                    hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>'
                ))
            
            fig.update_layout(
                title='Timeline: Event Activity (Stacked by Type)',
                xaxis_title='Time',
                yaxis_title='Event Count',
                barmode='stack',
                hovermode='x unified'
            )
            
        else:
            # Simple histogram
            counts = filtered.set_index('timestamp').resample(time_bin).size()
            
            fig = go.Figure(data=[go.Bar(
                x=counts.index,
                y=counts.values,
                marker_color='steelblue',
                hovertemplate='<b>%{x}</b><br>Events: %{y}<extra></extra>'
            )])
            
            fig.update_layout(
                title='Timeline: Event Activity Over Time',
                xaxis_title='Time',
                yaxis_title='Event Count',
                hovermode='x'
            )
        
        # Add range slider
        fig.update_xaxes(
            rangeslider_visible=True,
            rangeselector=dict(
                buttons=list([
                    dict(count=1, label="1h", step="hour", stepmode="backward"),
                    dict(count=6, label="6h", step="hour", stepmode="backward"),
                    dict(count=1, label="1d", step="day", stepmode="backward"),
                    dict(count=7, label="1w", step="day", stepmode="backward"),
                    dict(count=1, label="1m", step="month", stepmode="backward"),
                    dict(step="all", label="All")
                ])
            )
        )
        
        # Display in web view
        html = fig.to_html(include_plotlyjs='cdn')
        self.plotly_view.setHtml(html)
    
    def _export_matplotlib_png(self, file_path: str):
        """Export matplotlib figure as PNG."""
        if MPL_AVAILABLE and self.mpl_figure:
            self.mpl_figure.savefig(file_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Exported timeline graph to {file_path}")
    
    def _export_matplotlib_svg(self, file_path: str):
        """Export matplotlib figure as SVG."""
        if MPL_AVAILABLE and self.mpl_figure:
            self.mpl_figure.savefig(file_path, format='svg', bbox_inches='tight')
            self.logger.info(f"Exported timeline graph to {file_path}")
    
    def _export_plotly_html(self, file_path: str):
        """Export Plotly figure as interactive HTML."""
        # Would need to recreate the figure or store it
        self.logger.info(f"Plotly HTML export to {file_path}")


# Standalone function for generating timeline graphs
def generate_timeline_graph(events_df: pd.DataFrame, 
                            output_path: Optional[Path] = None,
                            time_bin: str = '1D',
                            stacked: bool = False,
                            backend: str = 'matplotlib') -> Optional[Path]:
    """
    Generate timeline graph from events DataFrame.
    
    Args:
        events_df: DataFrame with 'timestamp' column
        output_path: Path to save image (if None, displays interactively)
        time_bin: Pandas frequency string ('1H', '1D', '1W', etc.)
        stacked: Stack by event_type if True
        backend: 'matplotlib' or 'plotly'
        
    Returns:
        Path to saved file or None
    """
    if 'timestamp' not in events_df.columns:
        logging.error("Events must have 'timestamp' column")
        return None
    
    events_df = events_df.copy()
    events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
    
    if backend == 'matplotlib' and MPL_AVAILABLE:
        fig, ax = plt.subplots(figsize=(14, 6))
        
        if stacked and 'event_type' in events_df.columns:
            # Stacked histogram
            event_types = events_df['event_type'].unique()
            counts_by_type = {}
            
            for event_type in event_types:
                type_events = events_df[events_df['event_type'] == event_type]
                counts = type_events.set_index('timestamp').resample(time_bin).size()
                counts_by_type[event_type] = counts
            
            counts_df = pd.DataFrame(counts_by_type).fillna(0)
            counts_df.plot(kind='bar', stacked=True, ax=ax)
            ax.legend(title='Event Type', bbox_to_anchor=(1.05, 1))
        else:
            counts = events_df.set_index('timestamp').resample(time_bin).size()
            ax.bar(counts.index, counts.values, width=pd.Timedelta(time_bin) * 0.8, color='steelblue')
        
        ax.set_xlabel('Time')
        ax.set_ylabel('Event Count')
        ax.set_title('Forensic Timeline: Event Activity')
        ax.grid(True, alpha=0.3)
        
        if output_path:
            fig.savefig(output_path, dpi=300, bbox_inches='tight')
            logging.info(f"Saved timeline graph to {output_path}")
            return output_path
        else:
            plt.show()
    
    elif backend == 'plotly' and PLOTLY_AVAILABLE:
        counts = events_df.set_index('timestamp').resample(time_bin).size()
        
        fig = go.Figure(data=[go.Bar(x=counts.index, y=counts.values)])
        fig.update_layout(
            title='Forensic Timeline: Event Activity',
            xaxis_title='Time',
            yaxis_title='Event Count'
        )
        
        if output_path:
            fig.write_html(str(output_path))
            logging.info(f"Saved interactive timeline to {output_path}")
            return output_path
        else:
            fig.show()
    
    return None


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("Interactive Timeline Graph Module")
    print("=" * 50)
    print(f"Matplotlib Available: {MPL_AVAILABLE}")
    print(f"Plotly Available: {PLOTLY_AVAILABLE}")
    
    if MPL_AVAILABLE:
        # Generate sample events
        np.random.seed(42)
        n_events = 10000
        
        # Create activity bursts at certain times
        base_times = pd.date_range('2024-01-01', periods=100, freq='1H')
        burst_times = pd.date_range('2024-01-03 02:00', periods=500, freq='1min')  # Suspicious burst
        normal_times = pd.date_range('2024-01-01', periods=n_events - 600, freq='10min')
        
        timestamps = list(base_times) + list(burst_times) + list(normal_times)
        timestamps = sorted(timestamps)[:n_events]
        
        events = pd.DataFrame({
            'timestamp': timestamps,
            'event_type': np.random.choice(['login', 'file_access', 'process_start', 'network'], n_events)
        })
        
        print(f"\nGenerated {len(events)} sample events")
        print(f"Time range: {events['timestamp'].min()} to {events['timestamp'].max()}")
        
        # Generate graph
        print("\nGenerating timeline graph...")
        output = Path("timeline_graph_demo.png")
        generate_timeline_graph(events, output, time_bin='1H', stacked=True)
        print(f"✓ Saved to {output}")
