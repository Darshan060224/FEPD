"""
Heatmap Widget - PyQt6 widget for displaying event heatmaps.
Embeds matplotlib figure in Qt application.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel
from PyQt6.QtCore import pyqtSignal
import pandas as pd
import logging
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.backends.backend_qt import NavigationToolbar2QT  # type: ignore[attr-defined]
from .heatmap_generator import HeatmapGenerator

logger = logging.getLogger(__name__)


class HeatmapWidget(QWidget):
    """
    Qt widget for displaying interactive event heatmaps.
    
    Features:
    - Embeds matplotlib heatmap in Qt
    - Clickable cells (emit signal with date/hour)
    - Toolbar for zoom/pan
    - Refresh button
    
    Signals:
        cell_clicked(date: str, hour: int): Emitted when user clicks heatmap cell
    
    Example:
        >>> heatmap = HeatmapWidget()
        >>> heatmap.cell_clicked.connect(self.on_cell_clicked)
        >>> heatmap.update_data(timeline_df)
    """
    
    # Signal emitted when user clicks a cell
    cell_clicked = pyqtSignal(str, int)  # date, hour
    
    def __init__(self, parent=None):
        """
        Initialize heatmap widget.
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.timeline_df = pd.DataFrame()
        self.generator = None
        self.figure = None
        self.canvas = None
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header with title and controls
        header_layout = QHBoxLayout()
        
        title = QLabel("📊 Event Density Heatmap")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Refresh button
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.setToolTip("Regenerate heatmap")
        self.refresh_btn.clicked.connect(self._regenerate_heatmap)
        header_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(header_layout)
        
        # Info label
        self.info_label = QLabel("Load timeline data to generate heatmap")
        self.info_label.setStyleSheet("color: #666; margin: 5px 0;")
        layout.addWidget(self.info_label)
        
        # Matplotlib canvas placeholder
        self.canvas_layout = QVBoxLayout()
        layout.addLayout(self.canvas_layout)
        
        # Instructions
        instructions = QLabel(
            "💡 Click on any cell to filter timeline to that date and hour"
        )
        instructions.setStyleSheet("color: #888; font-size: 11px; margin-top: 10px;")
        layout.addWidget(instructions)
    
    def update_data(self, timeline_df: pd.DataFrame):
        """
        Update heatmap with new timeline data.
        
        Args:
            timeline_df: DataFrame with 'timestamp' column
        
        Example:
            >>> heatmap.update_data(classified_df)
        """
        if timeline_df is None or timeline_df.empty:
            logger.warning("Cannot update heatmap with empty data")
            self.info_label.setText("⚠️ No timeline data available")
            return
        
        self.timeline_df = timeline_df.copy()
        logger.info(f"Heatmap widget received {len(timeline_df)} events")
        
        # Generate heatmap
        self._regenerate_heatmap()
    
    def _regenerate_heatmap(self):
        """Regenerate heatmap from current data."""
        if self.timeline_df.empty:
            logger.warning("No data to generate heatmap")
            return
        
        try:
            # Create generator
            self.generator = HeatmapGenerator(self.timeline_df)
            
            # Get stats
            stats = self.generator.get_stats()
            if stats:
                info_text = (
                    f"📅 {stats.get('date_range', 'N/A')} | "
                    f"📊 {stats.get('total_events', 0)} events | "
                    f"🔥 Peak: {stats.get('peak_hour', 0)}:00 ({stats.get('peak_hour_count', 0)} events)"
                )
                self.info_label.setText(info_text)
            
            # Generate figure
            self.figure = self.generator.generate_heatmap(figsize=(14, 7))
            
            if self.figure:
                self._display_figure()
                logger.info("Heatmap displayed successfully")
            else:
                self.info_label.setText("❌ Failed to generate heatmap")
                
        except Exception as e:
            logger.error(f"Failed to regenerate heatmap: {e}", exc_info=True)
            self.info_label.setText(f"❌ Error: {str(e)}")
    
    def _display_figure(self):
        """Display matplotlib figure in widget."""
        # Clear existing canvas
        if self.canvas:
            self.canvas_layout.removeWidget(self.canvas)
            self.canvas.deleteLater()
            self.canvas = None
        
        if hasattr(self, 'toolbar') and self.toolbar:
            self.canvas_layout.removeWidget(self.toolbar)
            self.toolbar.deleteLater()
            self.toolbar = None
        
        # Create new canvas
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.canvas_layout.addWidget(self.canvas)
        
        # Add matplotlib toolbar
        self.toolbar = NavigationToolbar2QT(self.canvas, self)
        self.canvas_layout.addWidget(self.toolbar)
        
        # Connect click event
        self.canvas.mpl_connect('button_press_event', self._on_canvas_click)
        
        self.canvas.draw()
    
    def _on_canvas_click(self, event):
        """
        Handle click on heatmap canvas.
        
        Args:
            event: Matplotlib mouse event
        """
        if event.inaxes is None:
            return
        
        try:
            # Get clicked coordinates
            x_coord = int(round(event.xdata))
            y_coord = int(round(event.ydata))
            
            # Get axes limits to validate coordinates
            ax = event.inaxes
            
            # Get the actual data from the pivot table
            if self.generator:
                # Recreate pivot to get date mapping
                heatmap_data = self.generator.timeline_df.groupby(['date', 'hour']).size().reset_index(name='count')
                pivot_table = heatmap_data.pivot(index='hour', columns='date', values='count')
                pivot_table = pivot_table.sort_index(axis=1)
                
                # Validate coordinates
                if 0 <= y_coord < len(pivot_table.index) and 0 <= x_coord < len(pivot_table.columns):
                    hour = pivot_table.index[y_coord]
                    date = pivot_table.columns[x_coord]
                    date_str = str(date)
                    
                    logger.info(f"Heatmap cell clicked: {date_str} at {hour}:00")
                    
                    # Emit signal
                    self.cell_clicked.emit(date_str, int(hour))
                    
                    # Show feedback
                    self.info_label.setText(
                        f"🎯 Clicked: {date_str} at {hour:02d}:00 - "
                        f"Timeline filtered to this time slot"
                    )
                else:
                    logger.debug(f"Click outside valid cell range: ({x_coord}, {y_coord})")
            
        except Exception as e:
            logger.error(f"Error handling canvas click: {e}", exc_info=True)
    
    def clear(self):
        """Clear the heatmap display."""
        self.timeline_df = pd.DataFrame()
        self.generator = None
        
        if self.canvas:
            self.canvas_layout.removeWidget(self.canvas)
            self.canvas.deleteLater()
            self.canvas = None
        
        if hasattr(self, 'toolbar') and self.toolbar:
            self.canvas_layout.removeWidget(self.toolbar)
            self.toolbar.deleteLater()
            self.toolbar = None
        
        self.info_label.setText("Load timeline data to generate heatmap")
        logger.info("Heatmap cleared")


if __name__ == '__main__':
    """Quick test of HeatmapWidget."""
    import sys
    from PyQt6.QtWidgets import QApplication
    import numpy as np
    
    app = QApplication(sys.argv)
    
    # Create sample data
    print("Creating sample timeline data...")
    dates = pd.date_range('2024-01-01', periods=20, freq='D')
    events = []
    
    np.random.seed(42)
    for date in dates:
        for hour in range(24):
            if 9 <= hour <= 17:
                count = np.random.randint(5, 15)
            else:
                count = np.random.randint(0, 5)
            
            for _ in range(count):
                timestamp = date.replace(hour=hour, minute=np.random.randint(0, 60))
                events.append({'timestamp': timestamp})
    
    df = pd.DataFrame(events)
    print(f"Created {len(df)} sample events")
    
    # Create widget
    widget = HeatmapWidget()
    widget.setWindowTitle("FEPD Heatmap Widget Test")
    widget.resize(1200, 700)
    
    # Connect signal
    def on_cell_clicked(date, hour):
        print(f"✓ Cell clicked: {date} at {hour}:00")
    
    widget.cell_clicked.connect(on_cell_clicked)
    
    # Update with data
    widget.update_data(df)
    
    widget.show()
    
    print("\n✓ Heatmap widget displayed")
    print("💡 Click on cells to test interaction")
    
    sys.exit(app.exec())
