"""
Time-Heatmap Calendar View
===========================

2D calendar heatmap showing event frequency patterns across:
- Hour of day (0-23) on Y-axis
- Day of week (Mon-Sun) on X-axis

Use cases:
- Detect off-hours activity (3am logins)
- Identify malware beacons (regular intervals)
- Spot unusual timing patterns
- Weekend/holiday suspicious activity

Reference: Timesketch heatmaps (medium.com)
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import logging

try:
    import matplotlib.pyplot as plt
    import matplotlib.colors as mcolors
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    import seaborn as sns
    MPL_AVAILABLE = True
except ImportError:
    MPL_AVAILABLE = False
    logging.warning("Matplotlib/Seaborn not available")

try:
    import plotly.graph_objects as go
    import plotly.express as px
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QComboBox, QLabel, QCheckBox, QSpinBox, QGroupBox)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWebEngineWidgets import QWebEngineView


class HeatmapViewWidget(QWidget):
    """
    PyQt widget displaying time-based heatmap calendar.
    
    Shows event frequency as color intensity on a 2D grid:
    - X-axis: Days of week (Mon-Sun)
    - Y-axis: Hours of day (0-23)
    - Color: Event count (darker = more events)
    """
    
    # Signals
    cell_clicked = pyqtSignal(int, int)  # hour, day_of_week
    time_pattern_detected = pyqtSignal(str)  # pattern description
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.events_df = None
        self.current_backend = 'seaborn'
        self.heatmap_data = None
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        # Backend selection
        controls_layout.addWidget(QLabel("Visualization:"))
        self.backend_combo = QComboBox()
        self.backend_combo.addItems(['Seaborn (Static)', 'Plotly (Interactive)'])
        self.backend_combo.currentIndexChanged.connect(self._on_backend_changed)
        controls_layout.addWidget(self.backend_combo)
        
        # Event type filter
        controls_layout.addWidget(QLabel("Event Type:"))
        self.event_type_combo = QComboBox()
        self.event_type_combo.addItem('All Events')
        self.event_type_combo.currentTextChanged.connect(self._on_filter_changed)
        controls_layout.addWidget(self.event_type_combo)
        
        # Colormap selection
        controls_layout.addWidget(QLabel("Color Scheme:"))
        self.colormap_combo = QComboBox()
        self.colormap_combo.addItems(['YlOrRd', 'Reds', 'Blues', 'Greens', 'Viridis', 'Plasma'])
        self.colormap_combo.setCurrentText('YlOrRd')
        self.colormap_combo.currentTextChanged.connect(self._on_colormap_changed)
        controls_layout.addWidget(self.colormap_combo)
        
        # Normalize checkbox
        self.normalize_checkbox = QCheckBox("Normalize (0-100)")
        self.normalize_checkbox.stateChanged.connect(self._on_normalize_changed)
        controls_layout.addWidget(self.normalize_checkbox)
        
        # Highlight off-hours
        self.highlight_offhours = QCheckBox("Highlight Off-Hours")
        self.highlight_offhours.setChecked(True)
        self.highlight_offhours.stateChanged.connect(self._refresh_heatmap)
        controls_layout.addWidget(self.highlight_offhours)
        
        controls_layout.addStretch()
        
        # Pattern detection button
        self.detect_btn = QPushButton("Detect Patterns")
        self.detect_btn.clicked.connect(self._detect_patterns)
        controls_layout.addWidget(self.detect_btn)
        
        # Export button
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self._on_export)
        controls_layout.addWidget(self.export_btn)
        
        layout.addLayout(controls_layout)
        
        # Statistics panel
        stats_group = QGroupBox("Pattern Statistics")
        stats_layout = QHBoxLayout()
        self.stats_label = QLabel("Load events to see patterns")
        stats_layout.addWidget(self.stats_label)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Matplotlib canvas
        self.mpl_figure = Figure(figsize=(12, 8))
        self.mpl_canvas = FigureCanvas(self.mpl_figure) if MPL_AVAILABLE else None
        if self.mpl_canvas:
            layout.addWidget(self.mpl_canvas)
        
        # Plotly web view
        self.plotly_view = QWebEngineView() if PLOTLY_AVAILABLE else None
        if self.plotly_view:
            self.plotly_view.hide()
            layout.addWidget(self.plotly_view)
    
    def load_events(self, events_df: pd.DataFrame):
        """
        Load events for heatmap visualization.
        
        Args:
            events_df: DataFrame with 'timestamp' column
        """
        if 'timestamp' not in events_df.columns:
            self.logger.error("Events DataFrame must have 'timestamp' column")
            return
        
        self.events_df = events_df.copy()
        self.events_df['timestamp'] = pd.to_datetime(self.events_df['timestamp'])
        
        # Extract temporal features
        self.events_df['hour'] = self.events_df['timestamp'].dt.hour
        self.events_df['day_of_week'] = self.events_df['timestamp'].dt.dayofweek
        self.events_df['day_name'] = self.events_df['timestamp'].dt.day_name()
        
        # Populate event type filter
        if 'event_type' in self.events_df.columns:
            event_types = sorted(self.events_df['event_type'].unique())
            self.event_type_combo.clear()
            self.event_type_combo.addItem('All Events')
            self.event_type_combo.addItems(event_types)
        
        self._compute_heatmap_data()
        self._refresh_heatmap()
        self._update_statistics()
    
    def _compute_heatmap_data(self):
        """Compute heatmap matrix from events."""
        filtered = self._filter_events()
        
        if len(filtered) == 0:
            self.heatmap_data = np.zeros((24, 7))
            return
        
        # Create pivot table: hour x day_of_week
        pivot = filtered.groupby(['hour', 'day_of_week']).size().unstack(fill_value=0)
        
        # Ensure all hours and days are present
        all_hours = range(24)
        all_days = range(7)
        
        self.heatmap_data = np.zeros((24, 7))
        
        for hour in all_hours:
            for day in all_days:
                if hour in pivot.index and day in pivot.columns:
                    self.heatmap_data[hour, day] = pivot.loc[hour, day]
        
        # Normalize if requested
        if self.normalize_checkbox.isChecked() and self.heatmap_data.max() > 0:
            self.heatmap_data = (self.heatmap_data / self.heatmap_data.max()) * 100
    
    def _filter_events(self) -> pd.DataFrame:
        """Apply current filters."""
        if self.events_df is None or len(self.events_df) == 0:
            return pd.DataFrame()
        
        filtered = self.events_df.copy()
        
        # Event type filter
        event_type = self.event_type_combo.currentText()
        if event_type != 'All Events':
            filtered = filtered[filtered['event_type'] == event_type]
        
        return filtered
    
    def _on_backend_changed(self, index):
        """Handle backend change."""
        if index == 0:
            self.current_backend = 'seaborn'
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
        
        self._refresh_heatmap()
    
    def _on_filter_changed(self, text):
        """Handle filter change."""
        self._compute_heatmap_data()
        self._refresh_heatmap()
        self._update_statistics()
    
    def _on_colormap_changed(self, text):
        """Handle colormap change."""
        self._refresh_heatmap()
    
    def _on_normalize_changed(self, state):
        """Handle normalize toggle."""
        self._compute_heatmap_data()
        self._refresh_heatmap()
    
    def _on_export(self):
        """Export heatmap."""
        from PyQt6.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Heatmap",
            "heatmap.png",
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
    
    def _refresh_heatmap(self):
        """Refresh heatmap visualization."""
        if self.heatmap_data is None:
            return
        
        if self.current_backend == 'seaborn':
            self._plot_seaborn()
        elif self.current_backend == 'plotly':
            self._plot_plotly()
    
    def _plot_seaborn(self):
        """Create Seaborn heatmap."""
        if not MPL_AVAILABLE:
            return
        
        self.mpl_figure.clear()
        ax = self.mpl_figure.add_subplot(111)
        
        # Day labels
        day_labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        
        # Create heatmap
        colormap = self.colormap_combo.currentText()
        
        sns.heatmap(
            self.heatmap_data,
            cmap=colormap,
            cbar_kws={'label': 'Event Count' if not self.normalize_checkbox.isChecked() else 'Normalized (0-100)'},
            xticklabels=day_labels,
            yticklabels=range(24),
            ax=ax,
            linewidths=0.5,
            linecolor='gray'
        )
        
        # Highlight off-hours if enabled (10pm-6am weekdays)
        if self.highlight_offhours.isChecked():
            # 10pm-11pm (22-23)
            for day in range(5):  # Mon-Fri
                ax.add_patch(plt.Rectangle((day, 22), 1, 2, fill=False,  # type: ignore[attr-defined]
                                          edgecolor='red', lw=2, linestyle='--'))
            # 12am-6am (0-6)
            for day in range(5):
                ax.add_patch(plt.Rectangle((day, 0), 1, 6, fill=False,  # type: ignore[attr-defined]
                                          edgecolor='red', lw=2, linestyle='--'))
        
        ax.set_xlabel('Day of Week', fontsize=12)
        ax.set_ylabel('Hour of Day', fontsize=12)
        ax.set_title('Event Activity Heatmap: Hour × Day', fontsize=14, fontweight='bold')
        
        # Invert y-axis so midnight (0) is at top
        ax.invert_yaxis()
        
        self.mpl_figure.tight_layout()
        self.mpl_canvas.draw()
    
    def _plot_plotly(self):
        """Create interactive Plotly heatmap."""
        if not PLOTLY_AVAILABLE:
            return
        
        day_labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        hour_labels = [f"{h:02d}:00" for h in range(24)]
        
        colormap = self.colormap_combo.currentText().lower()
        
        fig = go.Figure(data=go.Heatmap(
            z=self.heatmap_data,
            x=day_labels,
            y=hour_labels,
            colorscale=colormap,
            hovertemplate='<b>%{x}</b><br>Hour: %{y}<br>Count: %{z}<extra></extra>',
            colorbar=dict(
                title='Event Count' if not self.normalize_checkbox.isChecked() else 'Normalized'
            )
        ))
        
        # Add off-hours rectangles if enabled
        if self.highlight_offhours.isChecked():
            shapes = []
            # 10pm-midnight and midnight-6am on weekdays
            for day_idx in range(5):  # Mon-Fri
                # 22:00-24:00
                shapes.append(dict(
                    type='rect',
                    x0=day_idx - 0.5, x1=day_idx + 0.5,
                    y0=21.5, y1=23.5,
                    line=dict(color='red', width=2, dash='dash'),
                    fillcolor='rgba(255,0,0,0.1)'
                ))
                # 00:00-06:00
                shapes.append(dict(
                    type='rect',
                    x0=day_idx - 0.5, x1=day_idx + 0.5,
                    y0=-0.5, y1=5.5,
                    line=dict(color='red', width=2, dash='dash'),
                    fillcolor='rgba(255,0,0,0.1)'
                ))
            
            fig.update_layout(shapes=shapes)
        
        fig.update_layout(
            title='Event Activity Heatmap: Hour × Day of Week',
            xaxis_title='Day of Week',
            yaxis_title='Hour of Day',
            height=600
        )
        
        # Reverse y-axis
        fig.update_yaxes(autorange='reversed')
        
        html = fig.to_html(include_plotlyjs='cdn')
        self.plotly_view.setHtml(html)
    
    def _update_statistics(self):
        """Update pattern statistics display."""
        if self.events_df is None or len(self.events_df) == 0:
            return
        
        filtered = self._filter_events()
        
        if len(filtered) == 0:
            self.stats_label.setText("No events match filter")
            return
        
        # Calculate statistics
        total_events = len(filtered)
        
        # Peak activity time
        peak_hour = self.heatmap_data.sum(axis=1).argmax()
        peak_day = self.heatmap_data.sum(axis=0).argmax()
        day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        
        # Off-hours activity (10pm-6am weekdays)
        off_hours_mask = (
            ((filtered['hour'] >= 22) | (filtered['hour'] <= 5)) &
            (filtered['day_of_week'] < 5)
        )
        off_hours_count = off_hours_mask.sum()
        off_hours_pct = (off_hours_count / total_events * 100) if total_events > 0 else 0
        
        # Weekend activity
        weekend_mask = filtered['day_of_week'] >= 5
        weekend_count = weekend_mask.sum()
        weekend_pct = (weekend_count / total_events * 100) if total_events > 0 else 0
        
        stats_text = (
            f"Total Events: {total_events:,} | "
            f"Peak: {day_names[peak_day]} {peak_hour:02d}:00 | "
            f"Off-Hours: {off_hours_count:,} ({off_hours_pct:.1f}%) | "
            f"Weekend: {weekend_count:,} ({weekend_pct:.1f}%)"
        )
        
        self.stats_label.setText(stats_text)
    
    def _detect_patterns(self):
        """Detect suspicious timing patterns."""
        if self.heatmap_data is None:
            return
        
        patterns = []
        
        # Pattern 1: Excessive off-hours activity
        off_hours_cells = []
        for hour in list(range(22, 24)) + list(range(0, 6)):
            for day in range(5):  # Weekdays only
                if self.heatmap_data[hour, day] > 0:
                    off_hours_cells.append(self.heatmap_data[hour, day])
        
        if off_hours_cells:
            off_hours_total = sum(off_hours_cells)
            total_events = self.heatmap_data.sum()
            off_hours_pct = (off_hours_total / total_events * 100) if total_events > 0 else 0
            
            if off_hours_pct > 20:
                patterns.append(f"⚠️ High off-hours activity: {off_hours_pct:.1f}% of events occur 10pm-6am on weekdays")
        
        # Pattern 2: Weekend spikes
        weekend_total = self.heatmap_data[:, 5:7].sum()
        weekday_total = self.heatmap_data[:, 0:5].sum()
        
        if weekend_total > weekday_total * 0.5:  # Weekend > 50% of weekday activity
            patterns.append(f"⚠️ Unusual weekend activity detected")
        
        # Pattern 3: Regular intervals (potential beacon)
        # Check if same hour across multiple days has consistent activity
        for hour in range(24):
            hour_counts = self.heatmap_data[hour, :]
            if hour_counts.std() < hour_counts.mean() * 0.2 and hour_counts.mean() > 5:
                # Low variance, high mean = regular pattern
                patterns.append(f"🔍 Regular activity pattern at {hour:02d}:00 (possible beacon)")
        
        # Pattern 4: Single-day spike
        day_totals = self.heatmap_data.sum(axis=0)
        day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        
        for day_idx, day_total in enumerate(day_totals):
            other_days = np.delete(day_totals, day_idx)
            if day_total > other_days.mean() * 2:  # 2x average
                patterns.append(f"📈 Activity spike on {day_names[day_idx]}")
        
        # Display patterns
        if patterns:
            message = "Detected Patterns:\n" + "\n".join(patterns)
            self.time_pattern_detected.emit(message)
            
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "Pattern Detection Results", message)
        else:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "Pattern Detection", "No suspicious patterns detected")
    
    def _export_matplotlib_png(self, file_path: str):
        """Export matplotlib heatmap as PNG."""
        if MPL_AVAILABLE and self.mpl_figure:
            self.mpl_figure.savefig(file_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Exported heatmap to {file_path}")
    
    def _export_matplotlib_svg(self, file_path: str):
        """Export matplotlib heatmap as SVG."""
        if MPL_AVAILABLE and self.mpl_figure:
            self.mpl_figure.savefig(file_path, format='svg', bbox_inches='tight')
            self.logger.info(f"Exported heatmap to {file_path}")
    
    def _export_plotly_html(self, file_path: str):
        """Export Plotly heatmap as HTML."""
        self.logger.info(f"Plotly HTML export to {file_path}")


# Standalone function for generating heatmaps
def generate_heatmap(events_df: pd.DataFrame,
                    output_path: Optional[Path] = None,
                    colormap: str = 'YlOrRd',
                    normalize: bool = False,
                    highlight_offhours: bool = True,
                    backend: str = 'seaborn') -> Optional[Path]:
    """
    Generate time-based heatmap from events.
    
    Args:
        events_df: DataFrame with 'timestamp' column
        output_path: Path to save image
        colormap: Color scheme ('YlOrRd', 'Reds', 'Blues', etc.)
        normalize: Normalize values 0-100
        highlight_offhours: Highlight 10pm-6am weekdays
        backend: 'seaborn' or 'plotly'
        
    Returns:
        Path to saved file or None
    """
    if 'timestamp' not in events_df.columns:
        logging.error("Events must have 'timestamp' column")
        return None
    
    events_df = events_df.copy()
    events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
    events_df['hour'] = events_df['timestamp'].dt.hour
    events_df['day_of_week'] = events_df['timestamp'].dt.dayofweek
    
    # Create pivot table
    pivot = events_df.groupby(['hour', 'day_of_week']).size().unstack(fill_value=0)
    
    # Ensure all hours and days
    heatmap_data = np.zeros((24, 7))
    for hour in range(24):
        for day in range(7):
            if hour in pivot.index and day in pivot.columns:
                heatmap_data[hour, day] = pivot.loc[hour, day]
    
    if normalize and heatmap_data.max() > 0:
        heatmap_data = (heatmap_data / heatmap_data.max()) * 100
    
    if backend == 'seaborn' and MPL_AVAILABLE:
        fig, ax = plt.subplots(figsize=(10, 8))
        
        day_labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        
        sns.heatmap(
            heatmap_data,
            cmap=colormap,
            cbar_kws={'label': 'Event Count' if not normalize else 'Normalized (0-100)'},
            xticklabels=day_labels,
            yticklabels=range(24),
            ax=ax,
            linewidths=0.5
        )
        
        if highlight_offhours:
            for day in range(5):
                ax.add_patch(plt.Rectangle((day, 22), 1, 2, fill=False,  # type: ignore[attr-defined]
                                          edgecolor='red', lw=2, linestyle='--'))
                ax.add_patch(plt.Rectangle((day, 0), 1, 6, fill=False,  # type: ignore[attr-defined]
                                          edgecolor='red', lw=2, linestyle='--'))
        
        ax.set_xlabel('Day of Week')
        ax.set_ylabel('Hour of Day')
        ax.set_title('Forensic Timeline Heatmap: Hourly Activity Patterns')
        ax.invert_yaxis()
        
        if output_path:
            fig.savefig(output_path, dpi=300, bbox_inches='tight')
            logging.info(f"Saved heatmap to {output_path}")
            plt.close(fig)
            return output_path
        else:
            plt.show()
    
    elif backend == 'plotly' and PLOTLY_AVAILABLE:
        day_labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data,
            x=day_labels,
            y=[f"{h:02d}:00" for h in range(24)],
            colorscale=colormap.lower()
        ))
        
        fig.update_layout(
            title='Forensic Timeline Heatmap',
            xaxis_title='Day of Week',
            yaxis_title='Hour of Day'
        )
        
        fig.update_yaxes(autorange='reversed')
        
        if output_path:
            fig.write_html(str(output_path))
            logging.info(f"Saved interactive heatmap to {output_path}")
            return output_path
        else:
            fig.show()
    
    return None


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("Time-Heatmap Calendar View Module")
    print("=" * 50)
    print(f"Matplotlib/Seaborn Available: {MPL_AVAILABLE}")
    print(f"Plotly Available: {PLOTLY_AVAILABLE}")
    
    if MPL_AVAILABLE:
        # Generate sample events with patterns
        np.random.seed(42)
        
        # Normal activity: weekdays 9am-5pm
        normal_times = []
        for _ in range(5000):
            day = np.random.choice(range(5))  # Mon-Fri
            hour = np.random.choice(range(9, 17))  # 9am-5pm
            normal_times.append(
                pd.Timestamp('2024-01-01') + 
                pd.Timedelta(days=day, hours=hour, minutes=np.random.randint(0, 60))
            )
        
        # Suspicious: 3am activity on weekdays
        suspicious_times = []
        for _ in range(200):
            day = np.random.choice(range(5))
            hour = 3
            suspicious_times.append(
                pd.Timestamp('2024-01-01') +
                pd.Timedelta(days=day, hours=hour, minutes=np.random.randint(0, 60))
            )
        
        # Weekend spike
        weekend_times = []
        for _ in range(300):
            day = np.random.choice([5, 6])  # Sat-Sun
            hour = np.random.randint(0, 24)
            weekend_times.append(
                pd.Timestamp('2024-01-01') +
                pd.Timedelta(days=day, hours=hour, minutes=np.random.randint(0, 60))
            )
        
        all_times = normal_times + suspicious_times + weekend_times
        
        events = pd.DataFrame({
            'timestamp': all_times,
            'event_type': np.random.choice(['login', 'file_access', 'network'], len(all_times))
        })
        
        print(f"\nGenerated {len(events)} sample events")
        print("Patterns included:")
        print("  - Normal weekday 9-5 activity")
        print("  - Suspicious 3am weekday activity")
        print("  - Weekend activity spike")
        
        # Generate heatmap
        print("\nGenerating heatmap...")
        output = Path("heatmap_demo.png")
        generate_heatmap(events, output, highlight_offhours=True)
        print(f"✓ Saved to {output}")
