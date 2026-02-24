"""
FEPD - Advanced Visualizations Tab
===================================
Interactive visualizations for forensic data:
- Heatmaps (activity intensity)
- Connection Graphs (network/entity relationships)
- Timeline Graphs (temporal analysis)
- Process Trees
- Geographic Maps

Copyright (c) 2025 FEPD Development Team
"""

import logging
import json
import time
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
import pandas as pd
import numpy as np

# ============================================================================
# CONSTANTS - Visualization Configuration & Standards
# ============================================================================

# Figure dimensions (width, height in inches)
FIG_SIZE_SMALL: Tuple[int, int] = (10, 6)
FIG_SIZE_MEDIUM: Tuple[int, int] = (12, 8)
FIG_SIZE_LARGE: Tuple[int, int] = (14, 10)
FIG_SIZE_HEATMAP: Tuple[int, int] = (12, 6)
FIG_SIZE_NETWORK: Tuple[int, int] = (14, 10)

# Export settings
EXPORT_DPI: int = 300
EXPORT_DPI_PREVIEW: int = 100
EXPORT_FORMATS: List[str] = ['PNG', 'PDF', 'SVG', 'CSV', 'JSON', 'HTML']

# Performance limits
MAX_NETWORK_NODES: int = 100
MAX_BARS_DISPLAY: int = 50
MAX_TIMELINE_POINTS: int = 1000

# Caching
CACHE_ENABLED: bool = True
CACHE_MAX_SIZE: int = 20  # Max cached visualizations
CACHE_EXPIRY_SEC: int = 300  # 5 minutes

# Auto-refresh
AUTO_REFRESH_INTERVAL_MS: int = 30000  # 30 seconds
AUTO_REFRESH_MIN_INTERVAL_MS: int = 5000  # 5 seconds minimum

# Forensic color scheme (professional, high-contrast, colorblind-friendly)
COLOR_CRITICAL: str = '#d32f2f'  # Red
COLOR_HIGH: str = '#f57c00'      # Orange
COLOR_MEDIUM: str = '#fbc02d'    # Yellow
COLOR_LOW: str = '#689f38'       # Green
COLOR_INFO: str = '#1976d2'      # Blue
COLOR_UNKNOWN: str = '#757575'   # Gray

# Color palettes
FORENSIC_PALETTE: List[str] = [
    '#1976d2', '#388e3c', '#f57c00', '#c62828',
    '#7b1fa2', '#00796b', '#fbc02d', '#455a64'
]

SEVERITY_COLORS: Dict[str, str] = {
    'Critical': COLOR_CRITICAL,
    'High': COLOR_HIGH,
    'Medium': COLOR_MEDIUM,
    'Low': COLOR_LOW,
    'Info': COLOR_INFO,
    'Unknown': COLOR_UNKNOWN
}

NODE_COLORS: Dict[str, str] = {
    'user': '#3498db',
    'process': '#e74c3c',
    'file': '#2ecc71',
    'ip': '#f39c12',
    'registry': '#9b59b6',
    'network': '#1abc9c'
}

# Font sizes
FONT_SIZE_TITLE: int = 14
FONT_SIZE_LABEL: int = 11
FONT_SIZE_TICK: int = 9
FONT_SIZE_LEGEND: int = 10
FONT_SIZE_ANNOTATION: int = 8

# Grid settings
GRID_ALPHA: float = 0.3
GRID_STYLE: str = '--'

# Preset templates
VIZ_PRESETS: Dict[str, Dict[str, Any]] = {
    'Last 24 Hours': {
        'time_range': 'Last 24 Hours',
        'time_bin': '1 Hour',
        'heatmap_type': 'Calendar View'
    },
    'Security Overview': {
        'time_range': 'Last 7 Days',
        'time_bin': '6 Hours',
        'category_filter': 'Network Activity'
    },
    'User Activity': {
        'time_range': 'Last 30 Days',
        'time_bin': '1 Day',
        'category_filter': 'User Activity'
    },
    'Full Timeline': {
        'time_range': 'Entire Timeline',
        'time_bin': '1 Week',
        'heatmap_type': 'Day/Hour'
    }
}

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QGroupBox, QComboBox, QSpinBox,
    QCheckBox, QFileDialog, QTabWidget, QScrollArea,
    QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap

from src.ui.visualizations.attack_surface_map import AttackSurfaceMapWidget, WEB_ENGINE_AVAILABLE

try:
    import matplotlib
    # PyQt6 requires the Qt6 backend; fall back to QtAgg if available
    try:
        matplotlib.use('QtAgg')
    except Exception:
        matplotlib.use('Agg')  # headless fallback (still allows PNG rendering)
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas  # type: ignore[attr-defined]
    from matplotlib.figure import Figure
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    logging.warning("Matplotlib not available for visualizations")

try:
    import squarify
    SQUARIFY_AVAILABLE = True
except ImportError:
    SQUARIFY_AVAILABLE = False
    logging.warning("squarify not available for tree maps")


class VisualizationCanvas(QWidget):
    """Widget to display matplotlib figures in Qt with caching support."""
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.figure: Optional[Any] = None
        self.canvas: Optional[Any] = None
        self._cache: Dict[str, Tuple[Any, float]] = {}  # cache_key -> (figure, timestamp)
        self._init_ui()
    
    def _init_ui(self) -> None:
        """Initialize canvas layout."""
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        if MATPLOTLIB_AVAILABLE:
            self.figure = Figure(figsize=FIG_SIZE_SMALL)
            self.canvas = FigureCanvas(self.figure)
            self.layout.addWidget(self.canvas)
        else:
            placeholder = QLabel(
                "❌ Matplotlib not installed\n\n"
                "💡 Install with: pip install matplotlib\n\n"
                "Required for all chart visualizations."
            )
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #e74c3c; font-size: 12px;")
            self.layout.addWidget(placeholder)
    
    def clear(self) -> None:
        """Clear the canvas and cache."""
        if self.figure:
            self.figure.clear()
            if self.canvas:
                self.canvas.draw()
    
    def save_figure(self, filepath: str, dpi: int = EXPORT_DPI) -> None:
        """Save figure to file with specified DPI."""
        if self.figure:
            self.figure.savefig(filepath, dpi=dpi, bbox_inches='tight')
    
    def get_cached(self, cache_key: str) -> Optional[Any]:
        """Get cached figure if still valid."""
        if not CACHE_ENABLED or cache_key not in self._cache:
            return None
        
        fig, timestamp = self._cache[cache_key]
        if time.time() - timestamp > CACHE_EXPIRY_SEC:
            del self._cache[cache_key]
            return None
        
        return fig
    
    def set_cached(self, cache_key: str, figure: Any) -> None:
        """Cache a generated figure."""
        if not CACHE_ENABLED:
            return
        
        # Limit cache size
        if len(self._cache) >= CACHE_MAX_SIZE:
            # Remove oldest entry
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]
        
        self._cache[cache_key] = (figure, time.time())


class VisualizationWorker(QThread):
    """Background worker for generating visualizations with progress tracking."""
    
    finished = pyqtSignal(object)  # matplotlib figure
    error = pyqtSignal(str)
    progress = pyqtSignal(str)  # status message
    
    def __init__(self, events_df: pd.DataFrame, viz_type: str, config: Dict[str, Any]):
        super().__init__()
        self.events_df = events_df
        self.viz_type = viz_type
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._cancelled: bool = False
    
    def run(self) -> None:
        """Generate visualization in background with progress updates."""
        try:
            self.progress.emit(f"🔄 Preparing {self.viz_type} visualization...")
            
            if self.viz_type == "heatmap":
                self.progress.emit("📊 Generating heatmap...")
                fig = self._generate_heatmap()
            elif self.viz_type == "connections":
                self.progress.emit("🕸️ Building network graph...")
                fig = self._generate_connections_graph()
            elif self.viz_type == "timeline":
                self.progress.emit("📈 Creating timeline...")
                fig = self._generate_timeline()
            else:
                raise ValueError(f"Unknown visualization type: {self.viz_type}")
            
            if not self._cancelled:
                self.progress.emit("✅ Rendering complete!")
                self.finished.emit(fig)
        except ImportError as e:
            error_msg = (
                f"❌ Missing Dependency: {str(e)}\n\n"
                f"💡 Install required packages:\n"
                f"  • Matplotlib: pip install matplotlib\n"
                f"  • NetworkX: pip install networkx\n"
                f"  • Squarify: pip install squarify\n\n"
                f"🔧 Recovery: Install missing packages and try again."
            )
            self.logger.error(f"Import error: {e}")
            self.error.emit(error_msg)
        except Exception as e:
            error_msg = (
                f"❌ Visualization Failed: {str(e)}\n\n"
                f"💡 Possible Solutions:\n"
                f"  • Check that events data is loaded\n"
                f"  • Verify data has required columns (timestamp, event_type)\n"
                f"  • Try reducing time range or filters\n"
                f"  • Check logs for detailed error information\n\n"
                f"🔧 Recovery: Review data format and try different settings."
            )
            self.logger.error(f"Visualization failed: {e}", exc_info=True)
            self.error.emit(error_msg)
    
    def cancel(self) -> None:
        """Cancel visualization generation."""
        self._cancelled = True
        self.logger.info(f"Visualization generation cancelled: {self.viz_type}")
    
    def _generate_heatmap(self):
        """Generate activity heatmap."""
        if not MATPLOTLIB_AVAILABLE:
            raise ImportError("Matplotlib not available")
        
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
        from datetime import datetime
        
        # Convert timestamps to datetime if needed (using ISO8601 format for flexibility)
        if 'ts_local' in self.events_df.columns:
            self.events_df['datetime'] = pd.to_datetime(self.events_df['ts_local'], format='ISO8601')
        elif 'ts_utc' in self.events_df.columns:
            self.events_df['datetime'] = pd.to_datetime(self.events_df['ts_utc'], format='ISO8601')
        else:
            raise ValueError("No timestamp column found")
        
        # Check heatmap type
        heatmap_type = self.config.get('heatmap_type', 'Day/Hour')
        
        if heatmap_type == "Calendar View":
            # Generate calendar-style heatmap (Date x Hour)
            return self._generate_calendar_heatmap()
        else:
            # Generate traditional day-of-week x hour heatmap
            return self._generate_dayofweek_heatmap()
    
    def _generate_dayofweek_heatmap(self):
        """Generate day-of-week x hour heatmap."""
        import matplotlib.pyplot as plt
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        # Extract hour and day of week
        self.events_df['hour'] = self.events_df['datetime'].dt.hour
        self.events_df['day'] = self.events_df['datetime'].dt.dayofweek
        
        # Create pivot table for heatmap
        heatmap_data = self.events_df.pivot_table(
            index='day', 
            columns='hour', 
            values='event_id' if 'event_id' in self.events_df.columns else 'datetime',
            aggfunc='count',
            fill_value=0
        )
        
        # Plot heatmap
        im = ax.imshow(heatmap_data, cmap='YlOrRd', aspect='auto')
        
        # Set labels
        ax.set_xticks(range(24))
        ax.set_xticklabels(range(24))
        ax.set_yticks(range(7))
        ax.set_yticklabels(['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'])
        ax.set_xlabel('Hour of Day')
        ax.set_ylabel('Day of Week')
        ax.set_title('Activity Heatmap (Day of Week vs Hour)')
        
        # Add colorbar
        plt.colorbar(im, ax=ax, label='Event Count')
        
        plt.tight_layout()
        return fig
    
    def _generate_calendar_heatmap(self):
        """Generate calendar-style heatmap (Date x Hour of Day)."""
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
        from matplotlib.colors import LinearSegmentedColormap
        
        # Extract date and hour
        self.events_df['date'] = self.events_df['datetime'].dt.date
        self.events_df['hour'] = self.events_df['datetime'].dt.hour
        
        # Create pivot table: rows=dates, columns=hours
        heatmap_data = self.events_df.pivot_table(
            index='date',
            columns='hour',
            values='event_id' if 'event_id' in self.events_df.columns else 'datetime',
            aggfunc='count',
            fill_value=0
        )
        
        # Ensure all hours 0-23 are present
        for hour in range(24):
            if hour not in heatmap_data.columns:
                heatmap_data[hour] = 0
        heatmap_data = heatmap_data.sort_index(axis=1)
        
        # Create figure
        fig, ax = plt.subplots(figsize=(14, max(6, len(heatmap_data) * 0.3)))
        
        # Plot heatmap
        im = ax.imshow(heatmap_data.values, cmap='YlOrRd', aspect='auto', interpolation='nearest')
        
        # Set x-axis (hours)
        ax.set_xticks(range(24))
        ax.set_xticklabels([f'{h:02d}:00' for h in range(24)], rotation=45, ha='right')
        ax.set_xlabel('Hour of Day', fontsize=11, fontweight='bold')
        
        # Set y-axis (dates)
        dates = heatmap_data.index
        ax.set_yticks(range(len(dates)))
        ax.set_yticklabels([d.strftime('%Y-%m-%d') for d in dates], fontsize=9)
        ax.set_ylabel('Date', fontsize=11, fontweight='bold')
        
        # Title with event count
        total_events = heatmap_data.values.sum()
        ax.set_title(f'📅 Event Calendar Heatmap\n{int(total_events)} total events across {len(dates)} days', 
                    fontsize=13, fontweight='bold', pad=15)
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax, label='Events per Hour', pad=0.02)
        cbar.ax.tick_params(labelsize=9)
        
        # Add grid for better readability
        ax.set_xticks([x - 0.5 for x in range(25)], minor=True)
        ax.set_yticks([y - 0.5 for y in range(len(dates) + 1)], minor=True)
        ax.grid(which='minor', color='white', linestyle='-', linewidth=0.5)
        
        # Add click info text
        fig.text(0.5, 0.02, '💡 Click on a cell to filter timeline to that hour (feature coming soon)', 
                ha='center', fontsize=9, style='italic', color='gray')
        
        plt.tight_layout()
        return fig
    
    def _generate_connections_graph(self):
        """Generate connections/relationships graph with improved performance."""
        if not MATPLOTLIB_AVAILABLE:
            raise ImportError("Matplotlib not available")
        
        import matplotlib.pyplot as plt
        
        # Use non-GUI backend for thread safety
        matplotlib.use('Agg')
        
        try:
            import networkx as nx
        except ImportError:
            # Fallback to simple visualization if networkx not available
            fig, ax = plt.subplots(figsize=(12, 8))
            ax.text(0.5, 0.5, 'NetworkX not installed\nInstall with: pip install networkx', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=14)
            ax.set_title('Entity Relationships Graph')
            plt.tight_layout()
            return fig
        
        # Create network graph
        fig, ax = plt.subplots(figsize=(14, 10))
        
        # Get filtered dataframe from config
        df = self.config.get('filtered_df', self.events_df)
        
        # Limit data for performance (max 100 nodes)
        max_connections = 100
        df_limited = df.head(max_connections) if len(df) > max_connections else df
        
        # Build graph from events with multiple relationship types
        G = nx.DiGraph()  # Use directed graph for better visualization
        
        # Add nodes with attributes
        nodes_added = set()
        edges_added = set()
        
        # Extract relationships from different columns
        for _, row in df_limited.iterrows():
            # User -> Process relationships
            if 'user_account' in row and 'process_name' in row:
                user = str(row.get('user_account', '')).strip()
                process = str(row.get('process_name', '')).strip()
                if user and process and user != 'nan' and process != 'nan':
                    if user not in nodes_added:
                        G.add_node(user, node_type='user', color='#3498db')
                        nodes_added.add(user)
                    if process not in nodes_added:
                        G.add_node(process, node_type='process', color='#e74c3c')
                        nodes_added.add(process)
                    edge_key = (user, process)
                    if edge_key not in edges_added:
                        G.add_edge(user, process, relationship='executes')
                        edges_added.add(edge_key)
            
            # Process -> File relationships
            if 'process_name' in row and 'file_path' in row:
                process = str(row.get('process_name', '')).strip()
                file_path = str(row.get('file_path', ''))[:50].strip()  # Truncate long paths
                if process and file_path and file_path != 'nan':
                    if process not in nodes_added:
                        G.add_node(process, node_type='process', color='#e74c3c')
                        nodes_added.add(process)
                    if file_path not in nodes_added:
                        G.add_node(file_path, node_type='file', color='#2ecc71')
                        nodes_added.add(file_path)
                    edge_key = (process, file_path)
                    if edge_key not in edges_added:
                        G.add_edge(process, file_path, relationship='accesses')
                        edges_added.add(edge_key)
            
            # Network connections
            if 'source_ip' in row and 'dest_ip' in row:
                src = str(row.get('source_ip', '')).strip()
                dst = str(row.get('dest_ip', '')).strip()
                if src and dst and src != 'nan' and dst != 'nan':
                    if src not in nodes_added:
                        G.add_node(src, node_type='ip', color='#f39c12')
                        nodes_added.add(src)
                    if dst not in nodes_added:
                        G.add_node(dst, node_type='ip', color='#f39c12')
                        nodes_added.add(dst)
                    edge_key = (src, dst)
                    if edge_key not in edges_added:
                        G.add_edge(src, dst, relationship='connects')
                        edges_added.add(edge_key)
        
        if len(G.nodes()) == 0:
            ax.text(0.5, 0.5, 'No relationships found in filtered data\n\nTip: Try loading more events or changing filters', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12, color='#e74c3c')
            ax.set_title('Entity Relationships Graph')
            plt.tight_layout()
            return fig
        
        # Choose layout based on config
        layout_type = self.config.get('layout', 'force_directed')
        
        try:
            if layout_type == 'circular':
                pos = nx.circular_layout(G)
            elif layout_type == 'hierarchical':
                pos = nx.spring_layout(G, k=0.5, iterations=50)
            elif layout_type == 'radial':
                pos = nx.kamada_kawai_layout(G)
            elif layout_type == 'spring':
                pos = nx.spring_layout(G, k=0.3, iterations=50)
            else:  # force_directed
                pos = nx.spring_layout(G, k=1.0/np.sqrt(len(G.nodes())), iterations=50)
        except:
            # Fallback to simple layout
            pos = nx.spring_layout(G)
        
        # Get node colors by type
        node_colors = [G.nodes[node].get('color', '#95a5a6') for node in G.nodes()]
        
        # Draw network
        show_labels = self.config.get('show_labels', True)
        
        # Draw edges with transparency
        nx.draw_networkx_edges(G, pos, ax=ax, edge_color='#7f8c8d', 
                               arrows=True, arrowsize=10, alpha=0.3, 
                               width=1.5, connectionstyle='arc3,rad=0.1')
        
        # Draw nodes
        nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors,
                               node_size=800, alpha=0.9, edgecolors='white', linewidths=2)
        
        # Draw labels if enabled
        if show_labels and len(G.nodes()) < 50:  # Only show labels for smaller graphs
            # Truncate labels for readability
            labels = {node: (node[:20] + '...' if len(node) > 20 else node) for node in G.nodes()}
            nx.draw_networkx_labels(G, pos, labels, ax=ax, font_size=8, font_weight='bold')
        
        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#3498db', label='Users'),
            Patch(facecolor='#e74c3c', label='Processes'),
            Patch(facecolor='#2ecc71', label='Files'),
            Patch(facecolor='#f39c12', label='Network IPs')
        ]
        ax.legend(handles=legend_elements, loc='upper left', fontsize=10)
        
        # Title with stats
        time_range = self.config.get('time_range', 'Entire Timeline')
        ax.set_title(f'Entity Relationships Graph\n{len(G.nodes())} nodes, {len(G.edges())} connections | Time Range: {time_range}',
                    fontsize=12, fontweight='bold', pad=15)
        ax.axis('off')
        
        plt.tight_layout()
        return fig
    
    def _generate_timeline(self):
        """Generate timeline graph."""
        if not MATPLOTLIB_AVAILABLE:
            raise ImportError("Matplotlib not available")
        
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
        
        # Use non-GUI backend for thread safety
        matplotlib.use('Agg')
        
        # Create timeline visualization
        fig, ax = plt.subplots(figsize=(12, 6))
        
        # Convert timestamps (using ISO8601 format for flexibility)
        if 'ts_local' in self.events_df.columns:
            self.events_df['datetime'] = pd.to_datetime(self.events_df['ts_local'], format='ISO8601')
        elif 'ts_utc' in self.events_df.columns:
            self.events_df['datetime'] = pd.to_datetime(self.events_df['ts_utc'], format='ISO8601')
        else:
            raise ValueError("No timestamp column found")
        
        # Group by time bin and count events (use 'h' instead of deprecated 'H')
        time_bin = self.config.get('time_bin', '1h')  # Changed from '1H' to '1h'
        
        # Check if we have enough data points
        if len(self.events_df) < 2:
            ax.text(0.5, 0.5, f'Insufficient data ({len(self.events_df)} events)', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=14)
            ax.set_title('Timeline of Events')
            plt.tight_layout()
            return fig
        
        try:
            binned = self.events_df.set_index('datetime').resample(time_bin).size()
            
            # Plot
            if self.config.get('stacked', True) and 'event_type' in self.events_df.columns:
                # Stacked by event type
                pivot_data = self.events_df.set_index('datetime').groupby(
                    [pd.Grouper(freq=time_bin), 'event_type']
                ).size().unstack(fill_value=0)
                
                if not pivot_data.empty:
                    pivot_data.plot(kind='area', stacked=True, ax=ax, alpha=0.7)
                    ax.legend(title='Event Type', bbox_to_anchor=(1.05, 1), loc='upper left')
            else:
                # Simple timeline
                if not binned.empty:
                    binned.plot(kind='line', ax=ax, linewidth=2, marker='o', markersize=4)
            
            ax.set_xlabel('Time')
            ax.set_ylabel('Event Count')
            ax.set_title('Timeline of Events')
            ax.grid(True, alpha=0.3)
            
            # Format x-axis
            if len(binned) > 0:
                ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
                plt.xticks(rotation=45)
        
        except Exception as e:
            ax.text(0.5, 0.5, f'Error generating timeline: {str(e)}', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=10)
        
        plt.tight_layout()
        return fig


class VisualizationsTab(QWidget):
    """
    Advanced Visualizations Tab with:
    1. Heatmap View
    2. Connections Graph
    3. Timeline Graph
    4. Caching & Performance Optimization
    5. Auto-refresh & Real-time Updates
    6. Export to Multiple Formats
    """
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.events_df: Optional[pd.DataFrame] = None
        self.worker: Optional[VisualizationWorker] = None
        self._auto_refresh_timer: Optional[Any] = None
        self._last_config: Dict[str, Any] = {}
        
        self._init_ui()
    
    def _init_ui(self) -> None:
        """Initialize UI components with loading indicators and presets."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header with title and status
        header_layout = QHBoxLayout()
        
        title = QLabel("📈 Visualizations")
        title_font = QFont()
        title_font.setPointSize(FONT_SIZE_TITLE)
        title_font.setBold(True)
        title.setFont(title_font)
        header_layout.addWidget(title)
        
        # Add preset templates dropdown
        header_layout.addWidget(QLabel("Quick Preset:"))
        self.preset_combo = QComboBox()
        self.preset_combo.addItems(["None"] + list(VIZ_PRESETS.keys()))
        self.preset_combo.currentTextChanged.connect(self._on_preset_selected)
        header_layout.addWidget(self.preset_combo)
        
        # Auto-refresh checkbox
        self.auto_refresh_check = QCheckBox("Auto-refresh")
        self.auto_refresh_check.stateChanged.connect(self._on_auto_refresh_changed)
        header_layout.addWidget(self.auto_refresh_check)
        
        header_layout.addStretch()
        
        # Loading indicator
        self.lbl_status = QLabel("Ready")
        self.lbl_status.setStyleSheet("color: #689f38; font-weight: bold;")
        header_layout.addWidget(self.lbl_status)
        
        layout.addLayout(header_layout)
        
        # Sub-tabs for different visualizations
        self.sub_tabs = QTabWidget()
        self.sub_tabs.addTab(self._create_heatmap_tab(), "🔥 Heatmap")
        self.sub_tabs.addTab(self._create_connections_tab(), "🕸️ Connections")
        self.sub_tabs.addTab(self._create_timeline_tab(), "📊 Timeline Graph")
        self.sub_tabs.addTab(self._create_attack_surface_tab(), "🧭 Attack Surface Map")
        self.sub_tabs.addTab(self._create_artifact_distribution_tab(), "📁 Artifact Distribution")
        self.sub_tabs.addTab(self._create_severity_analysis_tab(), "⚠️ Severity Analysis")
        self.sub_tabs.addTab(self._create_user_activity_tab(), "👤 User Activity")
        
        layout.addWidget(self.sub_tabs)
    
    def _create_heatmap_tab(self) -> QWidget:
        """Create Heatmap visualization tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info
        info_label = QLabel(
            "Activity Intensity Heatmap - Shows when activity occurred across time periods"
        )
        layout.addWidget(info_label)
        
        # Controls
        controls_group = QGroupBox("Heatmap Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        # Add heatmap type selector
        controls_layout.addWidget(QLabel("Heatmap Type:"))
        self.heatmap_type_combo = QComboBox()
        self.heatmap_type_combo.addItems(["Day/Hour", "Calendar View"])
        self.heatmap_type_combo.setCurrentText("Calendar View")
        self.heatmap_type_combo.currentTextChanged.connect(self._on_heatmap_type_changed)
        controls_layout.addWidget(self.heatmap_type_combo)
        
        controls_layout.addWidget(QLabel("Time Bin:"))
        self.heatmap_bin_combo = QComboBox()
        self.heatmap_bin_combo.addItems([
            "Entire Timeline",
            "1 Minute", "5 Minutes", "15 Minutes", "30 Minutes",
            "1 Hour", "2 Hours", "4 Hours", "6 Hours", "12 Hours",
            "1 Day", "1 Week", "1 Month", "3 Months", "6 Months", "1 Year"
        ])
        self.heatmap_bin_combo.setCurrentText("1 Hour")
        controls_layout.addWidget(self.heatmap_bin_combo)
        
        controls_layout.addWidget(QLabel("Category Filter:"))
        self.heatmap_category_combo = QComboBox()
        self.heatmap_category_combo.addItems([
            "All Categories",
            "File System", 
            "Registry", 
            "Process Execution",
            "Network Activity", 
            "User Activity",
            "Browser History",
            "Email/Messages",
            "System Events"
        ])
        controls_layout.addWidget(self.heatmap_category_combo)
        
        btn_generate = QPushButton("📊 Generate Heatmap")
        btn_generate.clicked.connect(lambda: self._generate_viz("heatmap"))
        btn_generate.setMinimumHeight(35)
        btn_generate.setStyleSheet(
            "background-color: #1976d2; color: white; font-weight: bold; "
            "border-radius: 4px; padding: 8px;"
        )
        controls_layout.addWidget(btn_generate)
        
        btn_save = QPushButton("💾 Save")
        btn_save.clicked.connect(self._save_heatmap)
        controls_layout.addWidget(btn_save)
        
        btn_export_data = QPushButton("📤 Export Data")
        btn_export_data.clicked.connect(lambda: self._export_viz_data("heatmap"))
        controls_layout.addWidget(btn_export_data)
        
        layout.addWidget(controls_group)
        
        # Canvas
        self.heatmap_canvas = VisualizationCanvas()
        layout.addWidget(self.heatmap_canvas)
        
        return widget
    
    def _create_connections_tab(self) -> QWidget:
        """Create Connections Graph tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info
        info_label = QLabel(
            "Network & Entity Relationships - Shows connections between users, processes, files, and network destinations"
        )
        layout.addWidget(info_label)
        
        # Controls
        controls_group = QGroupBox("Graph Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        controls_layout.addWidget(QLabel("Time Range:"))
        self.graph_time_combo = QComboBox()
        self.graph_time_combo.addItems([
            "Entire Timeline",
            "Last 1 Hour", "Last 6 Hours", "Last 12 Hours", "Last 24 Hours",
            "Last 3 Days", "Last 7 Days", "Last 14 Days", "Last 30 Days",
            "Last 3 Months", "Last 6 Months", "Last Year"
        ])
        self.graph_time_combo.setCurrentText("Entire Timeline")
        controls_layout.addWidget(self.graph_time_combo)
        
        controls_layout.addWidget(QLabel("Layout:"))
        self.graph_layout_combo = QComboBox()
        self.graph_layout_combo.addItems([
            "force_directed", "circular", "hierarchical", "radial", "spring"
        ])
        controls_layout.addWidget(self.graph_layout_combo)
        
        self.graph_labels_check = QCheckBox("Show Labels")
        self.graph_labels_check.setChecked(True)
        controls_layout.addWidget(self.graph_labels_check)
        
        btn_generate = QPushButton("🕸️ Generate Graph")
        btn_generate.clicked.connect(lambda: self._generate_viz("connections"))
        btn_generate.setMinimumHeight(35)
        btn_generate.setStyleSheet(
            "background-color: #388e3c; color: white; font-weight: bold; "
            "border-radius: 4px; padding: 8px;"
        )
        controls_layout.addWidget(btn_generate)
        
        btn_save = QPushButton("💾 Save")
        btn_save.clicked.connect(self._save_connections)
        controls_layout.addWidget(btn_save)
        
        btn_export_data = QPushButton("📤 Export Data")
        btn_export_data.clicked.connect(lambda: self._export_viz_data("connections"))
        controls_layout.addWidget(btn_export_data)
        
        layout.addWidget(controls_group)
        
        # Canvas
        self.connections_canvas = VisualizationCanvas()
        layout.addWidget(self.connections_canvas)
        
        return widget
    
    def _create_timeline_tab(self) -> QWidget:
        """Create Timeline Graph tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info
        info_label = QLabel(
            "Interactive Timeline - Event frequency over time with category breakdowns"
        )
        layout.addWidget(info_label)
        
        # Controls
        controls_group = QGroupBox("Timeline Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        controls_layout.addWidget(QLabel("Time Bin:"))
        self.timeline_bin_combo = QComboBox()
        self.timeline_bin_combo.addItems([
            "Entire Timeline",
            "1 Minute", "5 Minutes", "15 Minutes", "30 Minutes",
            "1 Hour", "2 Hours", "4 Hours", "6 Hours", "12 Hours",
            "1 Day", "1 Week", "2 Weeks", "1 Month", "3 Months", "6 Months", "1 Year"
        ])
        self.timeline_bin_combo.setCurrentText("1 Hour")
        controls_layout.addWidget(self.timeline_bin_combo)
        
        controls_layout.addWidget(QLabel("View Type:"))
        self.timeline_view_combo = QComboBox()
        self.timeline_view_combo.addItems([
            "Stacked Area",
            "Line Chart",
            "Bar Chart",
            "Scatter Plot",
            "Histogram"
        ])
        self.timeline_view_combo.setCurrentText("Stacked Area")
        controls_layout.addWidget(self.timeline_view_combo)
        
        self.timeline_stacked_check = QCheckBox("Show Categories")
        self.timeline_stacked_check.setChecked(True)
        controls_layout.addWidget(self.timeline_stacked_check)
        
        btn_generate = QPushButton("📊 Generate Timeline")
        btn_generate.clicked.connect(lambda: self._generate_viz("timeline"))
        btn_generate.setMinimumHeight(35)
        btn_generate.setStyleSheet(
            "background-color: #f57c00; color: white; font-weight: bold; "
            "border-radius: 4px; padding: 8px;"
        )
        controls_layout.addWidget(btn_generate)
        
        btn_save = QPushButton("💾 Save")
        btn_save.clicked.connect(self._save_timeline)
        controls_layout.addWidget(btn_save)
        
        btn_export_data = QPushButton("📤 Export Data")
        btn_export_data.clicked.connect(lambda: self._export_viz_data("timeline"))
        controls_layout.addWidget(btn_export_data)
        
        layout.addWidget(controls_group)
        
        # Canvas
        self.timeline_canvas = VisualizationCanvas()
        layout.addWidget(self.timeline_canvas)
        
        return widget

    def _create_attack_surface_tab(self) -> QWidget:
        """Create Attack Surface treemap tab (interactive Plotly treemap)."""
        if not WEB_ENGINE_AVAILABLE:
            # Create native Qt fallback visualization instead of just an error
            fallback = QWidget()
            layout = QVBoxLayout(fallback)
            
            # Header with status
            header = QLabel("🧭 Attack Surface Analysis")
            header.setStyleSheet("font-size: 16px; font-weight: bold; color: #4fc3f7;")
            layout.addWidget(header)
            
            status_label = QLabel("ℹ️ Web engine unavailable. Using native renderer.")
            status_label.setStyleSheet("color: #888; font-style: italic;")
            layout.addWidget(status_label)
            
            # Add native matplotlib treemap if available
            if MATPLOTLIB_AVAILABLE and SQUARIFY_AVAILABLE:
                self.attack_surface_canvas = VisualizationCanvas()
                layout.addWidget(self.attack_surface_canvas)
                
                # Generate button
                btn_generate = QPushButton("📊 Generate Attack Surface Treemap")
                btn_generate.clicked.connect(self._generate_native_attack_surface)
                layout.addWidget(btn_generate)
            else:
                # Absolute fallback - just show information
                info_text = QLabel("""
<div style='padding: 20px; background: #252525; border-radius: 8px;'>
<h3>Attack Surface Visualization</h3>
<p>This visualization shows forensic artifact distribution as a treemap:</p>
<ul>
<li><b>Size</b> = File size / event count</li>
<li><b>Color</b> = Risk level (green=low, red=high)</li>
<li><b>Categories</b>: System, Registry, Browser, Network, User Data</li>
</ul>
<p>To enable interactive visualization, install:</p>
<code>pip install PyQt6-WebEngine</code>
<p>Or for native rendering:</p>
<code>pip install matplotlib squarify</code>
</div>
                """)
                info_text.setWordWrap(True)
                info_text.setTextFormat(Qt.TextFormat.RichText)
                layout.addWidget(info_text)
            
            return fallback

        self.attack_surface_map = AttackSurfaceMapWidget()
        # Minimal wiring: log actions; host app can connect these signals to terminal/timeline widgets.
        self.attack_surface_map.audit_event.connect(self._on_attack_surface_audit)
        self.attack_surface_map.timeline_requested.connect(
            lambda path: self.logger.info("[AttackSurface] timeline requested for %s", path)
        )
        self.attack_surface_map.terminal_requested.connect(
            lambda path: self.logger.info("[AttackSurface] terminal navigation to %s", path)
        )
        self.attack_surface_map.explain_requested.connect(
            lambda path: self.logger.info("[AttackSurface] explain risk for %s", path)
        )
        self.attack_surface_map.artifacts_requested.connect(
            lambda path: self.logger.info("[AttackSurface] list artifacts for %s", path)
        )
        return self.attack_surface_map
    
    def _create_artifact_distribution_tab(self) -> QWidget:
        """Create Artifact Distribution visualization tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info
        info_label = QLabel(
            "Artifact Distribution - Shows breakdown of collected artifacts by type"
        )
        layout.addWidget(info_label)
        
        # Controls
        controls_group = QGroupBox("Distribution Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        controls_layout.addWidget(QLabel("Time Range:"))
        self.artifact_time_combo = QComboBox()
        self.artifact_time_combo.addItems([
            "Entire Timeline",
            "Last 1 Hour", "Last 6 Hours", "Last 12 Hours", "Last 24 Hours",
            "Last 3 Days", "Last 7 Days", "Last 14 Days", "Last 30 Days",
            "Last 3 Months", "Last 6 Months", "Last Year"
        ])
        self.artifact_time_combo.setCurrentText("Entire Timeline")
        controls_layout.addWidget(self.artifact_time_combo)
        
        controls_layout.addWidget(QLabel("Chart Type:"))
        self.artifact_chart_combo = QComboBox()
        self.artifact_chart_combo.addItems([
            "Pie Chart", 
            "Bar Chart", 
            "Donut Chart",
            "Tree Map",
            "Sunburst Chart"
        ])
        controls_layout.addWidget(self.artifact_chart_combo)
        
        self.artifact_3d_check = QCheckBox("3D Effect")
        controls_layout.addWidget(self.artifact_3d_check)
        
        btn_generate = QPushButton("📁 Generate Chart")
        btn_generate.clicked.connect(lambda: self._generate_artifact_distribution())
        btn_generate.setMinimumHeight(35)
        controls_layout.addWidget(btn_generate)
        
        btn_save = QPushButton("💾 Save Image")
        btn_save.clicked.connect(self._save_artifact_dist)
        controls_layout.addWidget(btn_save)
        
        layout.addWidget(controls_group)
        
        # Canvas
        self.artifact_dist_canvas = VisualizationCanvas()
        layout.addWidget(self.artifact_dist_canvas)
        
        return widget
    
    def _create_severity_analysis_tab(self) -> QWidget:
        """Create Severity Analysis visualization tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info
        info_label = QLabel(
            "Severity Analysis - Shows distribution of event severity levels over time"
        )
        layout.addWidget(info_label)
        
        # Controls
        controls_group = QGroupBox("Severity Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        controls_layout.addWidget(QLabel("Time Bin:"))
        self.severity_bin_combo = QComboBox()
        self.severity_bin_combo.addItems([
            "Entire Timeline",
            "1 Minute", "5 Minutes", "15 Minutes", "30 Minutes",
            "1 Hour", "2 Hours", "4 Hours", "6 Hours", "12 Hours",
            "1 Day", "1 Week", "2 Weeks", "1 Month", "3 Months", "6 Months", "1 Year"
        ])
        self.severity_bin_combo.setCurrentText("1 Day")
        controls_layout.addWidget(self.severity_bin_combo)
        
        controls_layout.addWidget(QLabel("View Type:"))
        self.severity_view_combo = QComboBox()
        self.severity_view_combo.addItems([
            "Stacked Area", 
            "Line Chart", 
            "Bar Chart",
            "Heatmap",
            "Radar Chart"
        ])
        controls_layout.addWidget(self.severity_view_combo)
        
        btn_generate = QPushButton("⚠️ Generate Analysis")
        btn_generate.clicked.connect(lambda: self._generate_severity_analysis())
        btn_generate.setMinimumHeight(35)
        controls_layout.addWidget(btn_generate)
        
        btn_save = QPushButton("💾 Save Image")
        btn_save.clicked.connect(self._save_severity)
        controls_layout.addWidget(btn_save)
        
        layout.addWidget(controls_group)
        
        # Canvas
        self.severity_canvas = VisualizationCanvas()
        layout.addWidget(self.severity_canvas)
        
        return widget
    
    def _create_user_activity_tab(self) -> QWidget:
        """Create User Activity visualization tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info
        info_label = QLabel(
            "User Activity Analysis - Shows user behavior patterns and activity levels"
        )
        layout.addWidget(info_label)
        
        # Controls
        controls_group = QGroupBox("User Activity Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        controls_layout.addWidget(QLabel("Metric:"))
        self.user_metric_combo = QComboBox()
        self.user_metric_combo.addItems([
            "Event Count", "File Modifications", "Process Executions",
            "Network Connections", "Registry Changes"
        ])
        controls_layout.addWidget(self.user_metric_combo)
        
        btn_generate = QPushButton("👤 Generate Activity Map")
        btn_generate.clicked.connect(lambda: self._generate_user_activity())
        btn_generate.setMinimumHeight(35)
        controls_layout.addWidget(btn_generate)
        
        btn_save = QPushButton("💾 Save Image")
        btn_save.clicked.connect(self._save_user_activity)
        controls_layout.addWidget(btn_save)
        
        layout.addWidget(controls_group)
        
        # Canvas
        self.user_activity_canvas = VisualizationCanvas()
        layout.addWidget(self.user_activity_canvas)
        
        return widget
    
    def _generate_artifact_distribution(self):
        """Generate artifact distribution chart with real data."""
        if not MATPLOTLIB_AVAILABLE:
            self.logger.warning("Matplotlib not available")
            return
        
        if self.events_df is None or self.events_df.empty:
            # Use sample data if no real data available
            artifact_types = {
                'Prefetch Files': 150,
                'Registry Keys': 85,
                'Event Logs': 45,
                'MFT Entries': 320,
                'Browser History': 67,
                'LNK Files': 28,
                'Temp Files': 193,
                'System Files': 412
            }
        else:
            # Extract artifact types from real data
            df = self.events_df.copy()
            
            # Apply time range filter
            time_range = self.artifact_time_combo.currentText()
            df = self._filter_events_by_time_range(df, time_range)
            
            # Try to categorize by artifact source or event type
            if 'artifact_source' in df.columns:
                artifact_counts = df['artifact_source'].value_counts().head(10)
            elif 'event_type' in df.columns:
                artifact_counts = df['event_type'].value_counts().head(10)
            elif 'category' in df.columns:
                artifact_counts = df['category'].value_counts().head(10)
            else:
                # Fallback to sample data
                artifact_types = {
                    'File System Events': len(df) // 3,
                    'Registry Events': len(df) // 4,
                    'Process Events': len(df) // 5,
                    'Network Events': len(df) // 6,
                    'Other': len(df) - (len(df) // 3 + len(df) // 4 + len(df) // 5 + len(df) // 6)
                }
                artifact_counts = pd.Series(artifact_types)
            
            artifact_types = artifact_counts.to_dict()
        
        fig = self.artifact_dist_canvas.figure
        fig.clear()
        ax = fig.add_subplot(111)
        
        chart_type = self.artifact_chart_combo.currentText()
        
        # Prepare labels and values
        labels = list(artifact_types.keys())
        values = list(artifact_types.values())
        
        # Truncate long labels
        short_labels = [label[:25] + '...' if len(label) > 25 else label for label in labels]
        
        # Color palette
        colors = plt.cm.Set3(range(len(labels)))
        
        if chart_type == "Pie Chart":
            pie_result = ax.pie(values, labels=short_labels, 
                   autopct='%1.1f%%', startangle=90, colors=colors,
                   textprops={'fontsize': 9})
            wedges, texts = pie_result[0], pie_result[1]
            autotexts = pie_result[2] if len(pie_result) > 2 else []
            # Bold percentage text
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
            ax.set_title(f'Artifact Distribution - Pie Chart\nTotal: {sum(values):,} artifacts',
                        fontsize=12, fontweight='bold', pad=15)
                        
        elif chart_type == "Donut Chart":
            pie_result = ax.pie(values, labels=short_labels,
                   autopct='%1.1f%%', startangle=90, pctdistance=0.85, colors=colors,
                   textprops={'fontsize': 9})
            wedges, texts = pie_result[0], pie_result[1]
            autotexts = pie_result[2] if len(pie_result) > 2 else []
            # Bold percentage text
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
            # Create center circle
            centre_circle = plt.Circle((0,0),0.70,fc='white')  # type: ignore[attr-defined]
            fig.gca().add_artist(centre_circle)
            # Add total in center
            ax.text(0, 0, f'{sum(values):,}\nartifacts', 
                   ha='center', va='center', fontsize=14, fontweight='bold')
            ax.set_title('Artifact Distribution - Donut Chart',
                        fontsize=12, fontweight='bold', pad=15)
                        
        elif chart_type == "Tree Map":
            if SQUARIFY_AVAILABLE:
                # Create tree map using squarify
                ax.axis('off')
                
                # Normalize sizes and create tree map
                squarify.plot(sizes=values, label=short_labels, alpha=0.8, 
                            color=colors, text_kwargs={'fontsize': 9, 'weight': 'bold'})
                
                # Add title
                ax.set_title(f'Artifact Distribution - Tree Map\nTotal: {sum(values):,} artifacts',
                            fontsize=12, fontweight='bold', pad=15)
                
                # Add legend with full names and counts
                legend_labels = [f'{label}: {val:,}' for label, val in zip(labels, values)]
                ax.legend(handles=[plt.Rectangle((0,0),1,1, fc=c, alpha=0.8)  # type: ignore[attr-defined]
                                 for c in colors[:len(labels)]], 
                        labels=legend_labels, loc='center left', 
                        bbox_to_anchor=(1, 0.5), fontsize=8)
            else:
                # Fallback message
                ax.text(0.5, 0.5, 'Tree Map view\n(Requires squarify package)\n\nInstall: pip install squarify', 
                       ha='center', va='center', transform=ax.transAxes, fontsize=12)
                ax.set_title('Artifact Distribution - Tree Map',
                            fontsize=12, fontweight='bold', pad=15)
                ax.axis('off')
            
        elif chart_type == "Sunburst Chart":
            # Placeholder for sunburst
            ax.text(0.5, 0.5, 'Sunburst Chart view\n(Requires plotly package)\n\nInstall: pip install plotly', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12)
            ax.set_title('Artifact Distribution - Sunburst Chart',
                        fontsize=12, fontweight='bold', pad=15)
            ax.axis('off')
            
        else:  # Bar Chart
            bars = ax.bar(range(len(short_labels)), values, color=colors, 
                         edgecolor='white', linewidth=1.5)
            ax.set_xticks(range(len(short_labels)))
            ax.set_xticklabels(short_labels, rotation=45, ha='right', fontsize=9)
            ax.set_ylabel('Count', fontsize=11, fontweight='bold')
            ax.set_title(f'Artifact Distribution - Bar Chart\nTotal: {sum(values):,} artifacts',
                        fontsize=12, fontweight='bold', pad=15)
            ax.grid(axis='y', alpha=0.3, linestyle='--')
            
            # Add value labels on bars
            max_val = max(values)
            for bar, val in zip(bars, values):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2, height + max_val * 0.01,
                       f'{int(val):,}', ha='center', va='bottom', fontsize=8, fontweight='bold')
        
        # Add time range info
        time_range = self.artifact_time_combo.currentText()
        fig.text(0.99, 0.02, f'Time Range: {time_range}', 
                ha='right', fontsize=9, style='italic', color='gray')
        
        fig.tight_layout()
        self.artifact_dist_canvas.canvas.draw()
    
    def _generate_severity_analysis(self):
        """Generate severity analysis chart with real data."""
        if not MATPLOTLIB_AVAILABLE:
            self.logger.warning("Matplotlib not available")
            return
        
        if self.events_df is None or self.events_df.empty:
            self.logger.warning("No events data available for severity analysis")
            return
        
        fig = self.severity_canvas.figure
        fig.clear()
        ax = fig.add_subplot(111)
        
        df = self.events_df.copy()
        
        # Ensure datetime column exists (using ISO8601 format for flexibility)
        if 'datetime' not in df.columns:
            if 'ts_local' in df.columns:
                df['datetime'] = pd.to_datetime(df['ts_local'], format='ISO8601')
            elif 'ts_utc' in df.columns:
                df['datetime'] = pd.to_datetime(df['ts_utc'], format='ISO8601')
            elif 'timestamp' in df.columns:
                # Fallback for test data or other sources
                df['datetime'] = pd.to_datetime(df['timestamp'])
            else:
                ax.text(0.5, 0.5, 'No timestamp data available', 
                       ha='center', va='center', transform=ax.transAxes, fontsize=12)
                ax.set_title('Severity Analysis Over Time')
                fig.tight_layout()
                self.severity_canvas.canvas.draw()
                return
        
        # Get time bin from config
        time_bin_label = self.severity_bin_combo.currentText()
        time_bin = self._convert_time_bin_to_freq(time_bin_label)
        
        # Create or infer severity levels
        if 'severity' not in df.columns and 'event_type' not in df.columns:
            # No severity data - create sample categorization
            df['severity'] = 'Low'
        elif 'severity' not in df.columns:
            # Infer severity from event_type
            df['severity'] = df.get('event_type', 'Unknown').apply(lambda x: 
                'Critical' if any(word in str(x).lower() for word in ['error', 'fail', 'crash', 'critical']) else
                'High' if any(word in str(x).lower() for word in ['warning', 'alert', 'suspicious']) else
                'Medium' if any(word in str(x).lower() for word in ['modify', 'change', 'update']) else
                'Low'
            )
        
        # Bin events by time
        if time_bin:
            df_binned = df.set_index('datetime').groupby([pd.Grouper(freq=time_bin), 'severity']).size().unstack(fill_value=0)
        else:
            # Entire timeline - aggregate by severity only
            severity_counts = df['severity'].value_counts()
            
            # Create pie chart for entire timeline
            colors = {
                'Critical': '#d32f2f',
                'High': '#f57c00',
                'Medium': '#fbc02d',
                'Low': '#689f38'
            }
            pie_colors = [colors.get(sev, '#95a5a6') for sev in severity_counts.index]
            
            ax.pie(severity_counts.values, labels=severity_counts.index, 
                  colors=pie_colors, autopct='%1.1f%%', startangle=90,
                  explode=[0.05] * len(severity_counts))
            ax.set_title(f'Event Severity Distribution - Entire Timeline\nTotal Events: {len(df):,}',
                        fontsize=12, fontweight='bold', pad=15)
            fig.tight_layout()
            self.severity_canvas.canvas.draw()
            return
        
        # Ensure all severity levels exist
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            if sev not in df_binned.columns:
                df_binned[sev] = 0
        
        # Reorder columns
        df_binned = df_binned[['Critical', 'High', 'Medium', 'Low']]
        
        view_type = self.severity_view_combo.currentText()
        
        if view_type == "Stacked Area":
            df_binned.plot(kind='area', stacked=True, ax=ax,
                          color=['#d32f2f', '#f57c00', '#fbc02d', '#689f38'],
                          alpha=0.7)
            ax.legend(title='Severity', loc='upper left')
            ax.set_ylabel('Event Count', fontsize=11, fontweight='bold')
            ax.set_xlabel('Time', fontsize=11, fontweight='bold')
            ax.set_title(f'Event Severity Over Time (Stacked Area)\nTime Bin: {time_bin_label}',
                        fontsize=12, fontweight='bold', pad=15)
            ax.grid(True, alpha=0.3, linestyle='--')
            
        elif view_type == "Line Chart":
            df_binned.plot(kind='line', ax=ax,
                          color=['#d32f2f', '#f57c00', '#fbc02d', '#689f38'],
                          linewidth=2, marker='o', markersize=4)
            ax.legend(title='Severity', loc='upper left')
            ax.set_ylabel('Event Count', fontsize=11, fontweight='bold')
            ax.set_xlabel('Time', fontsize=11, fontweight='bold')
            ax.set_title(f'Event Severity Over Time (Line Chart)\nTime Bin: {time_bin_label}',
                        fontsize=12, fontweight='bold', pad=15)
            ax.grid(True, alpha=0.3)
            
        elif view_type == "Heatmap":
            # Create heatmap view
            im = ax.imshow(df_binned.T.values, cmap='YlOrRd', aspect='auto')
            ax.set_yticks(range(len(df_binned.columns)))
            ax.set_yticklabels(df_binned.columns)
            ax.set_xlabel('Time Bins', fontsize=11, fontweight='bold')
            ax.set_ylabel('Severity Level', fontsize=11, fontweight='bold')
            ax.set_title(f'Severity Heatmap\nTime Bin: {time_bin_label}',
                        fontsize=12, fontweight='bold', pad=15)
            plt.colorbar(im, ax=ax, label='Event Count')
            
        else:  # Bar Chart
            df_binned.plot(kind='bar', ax=ax, width=0.8,
                          color=['#d32f2f', '#f57c00', '#fbc02d', '#689f38'])
            ax.legend(title='Severity', loc='upper left')
            ax.set_ylabel('Event Count', fontsize=11, fontweight='bold')
            ax.set_xlabel('Time Bin', fontsize=11, fontweight='bold')
            ax.set_title(f'Event Severity Distribution (Bar Chart)\nTime Bin: {time_bin_label}',
                        fontsize=12, fontweight='bold', pad=15)
            ax.grid(axis='y', alpha=0.3, linestyle='--')
            plt.xticks(rotation=45, ha='right')
        
        # Add total count
        total_events = df_binned.sum().sum()
        fig.text(0.99, 0.02, f'Total Events: {int(total_events):,}', 
                ha='right', fontsize=9, style='italic', color='gray')
        
        fig.tight_layout()
        self.severity_canvas.canvas.draw()
    
    def _generate_user_activity(self):
        """Generate user activity chart with real metric-based data."""
        if not MATPLOTLIB_AVAILABLE:
            self.logger.warning("Matplotlib not available")
            return
        
        if self.events_df is None or self.events_df.empty:
            self.logger.warning("No events data available for user activity")
            return
        
        fig = self.user_activity_canvas.figure
        fig.clear()
        ax = fig.add_subplot(111)
        
        # Get selected metric
        selected_metric = self.user_metric_combo.currentText()
        
        # Determine which column to analyze based on metric
        # Support multiple column names for user identification
        user_column = None
        for col in ['user_account', 'user_id', 'user', 'username']:
            if col in self.events_df.columns:
                user_column = col
                break
        
        if user_column is None:
            ax.text(0.5, 0.5, 'No user account data available', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12)
            ax.set_title('User Activity Analysis')
            fig.tight_layout()
            self.user_activity_canvas.canvas.draw()
            return
        
        # Use the found column consistently
        df = self.events_df.copy()
        if user_column != 'user_account':
            df['user_account'] = df[user_column]
        
        # Filter and aggregate based on selected metric
        
        if selected_metric == "Event Count":
            # Count total events per user
            user_data = df['user_account'].value_counts().head(10)
            title_suffix = "Total Events"
            xlabel = "Number of Events"
            
        elif selected_metric == "File Modifications":
            # Count file modification events
            if 'event_type' in df.columns:
                file_events = df[df['event_type'].str.contains('file|modify|write|create', case=False, na=False)]
                user_data = file_events['user_account'].value_counts().head(10)
            else:
                user_data = df['user_account'].value_counts().head(10)
            title_suffix = "File Modifications"
            xlabel = "File Modification Count"
            
        elif selected_metric == "Process Executions":
            # Count process execution events
            if 'process_name' in df.columns:
                proc_events = df[df['process_name'].notna()]
                user_data = proc_events['user_account'].value_counts().head(10)
            else:
                user_data = df['user_account'].value_counts().head(10)
            title_suffix = "Process Executions"
            xlabel = "Process Execution Count"
            
        elif selected_metric == "Network Connections":
            # Count network-related events
            if 'source_ip' in df.columns or 'dest_ip' in df.columns:
                net_events = df[(df['source_ip'].notna()) | (df['dest_ip'].notna())]
                user_data = net_events['user_account'].value_counts().head(10)
            else:
                user_data = df['user_account'].value_counts().head(10)
            title_suffix = "Network Connections"
            xlabel = "Connection Count"
            
        elif selected_metric == "Registry Changes":
            # Count registry-related events
            if 'event_type' in df.columns:
                reg_events = df[df['event_type'].str.contains('registry|reg', case=False, na=False)]
                user_data = reg_events['user_account'].value_counts().head(10)
            elif 'artifact_source' in df.columns:
                reg_events = df[df['artifact_source'].str.contains('registry', case=False, na=False)]
                user_data = reg_events['user_account'].value_counts().head(10)
            else:
                user_data = df['user_account'].value_counts().head(10)
            title_suffix = "Registry Changes"
            xlabel = "Registry Change Count"
        else:
            # Default to event count
            user_data = df['user_account'].value_counts().head(10)
            title_suffix = "Total Activity"
            xlabel = "Activity Count"
        
        # Check if we have data
        if user_data.empty:
            ax.text(0.5, 0.5, f'No data available for metric: {selected_metric}', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=12)
            ax.set_title(f'User Activity - {selected_metric}')
            fig.tight_layout()
            self.user_activity_canvas.canvas.draw()
            return
        
        # Truncate long usernames for display
        users = [user[:25] + '...' if len(str(user)) > 25 else user for user in user_data.index]
        counts = user_data.values
        
        # Color gradient based on count
        max_count = counts.max()
        colors = plt.cm.viridis(counts / max_count)
        
        # Create horizontal bar chart
        bars = ax.barh(users, counts, color=colors, edgecolor='white', linewidth=1.5)
        
        # Add value labels on bars
        for i, (bar, count) in enumerate(zip(bars, counts)):
            width = bar.get_width()
            ax.text(width + max_count * 0.01, bar.get_y() + bar.get_height()/2, 
                   f'{int(count):,}', ha='left', va='center', fontsize=9, fontweight='bold')
        
        # Styling
        ax.set_xlabel(xlabel, fontsize=11, fontweight='bold')
        ax.set_ylabel('User Account', fontsize=11, fontweight='bold')
        ax.set_title(f'User Activity Analysis - {title_suffix}\nTop 10 Users', 
                    fontsize=12, fontweight='bold', pad=15)
        ax.grid(axis='x', alpha=0.3, linestyle='--')
        
        # Add total count annotation
        total_count = counts.sum()
        fig.text(0.99, 0.02, f'Total: {int(total_count):,} {title_suffix.lower()}', 
                ha='right', fontsize=9, style='italic', color='gray')
        
        fig.tight_layout()
        self.user_activity_canvas.canvas.draw()
    
    def _save_artifact_dist(self):
        """Save artifact distribution chart."""
        self._save_viz("artifact_distribution", self.artifact_dist_canvas)
    
    def _save_severity(self):
        """Save severity analysis chart."""
        self._save_viz("severity_analysis", self.severity_canvas)
    
    def _save_user_activity(self):
        """Save user activity chart."""
        self._save_viz("user_activity", self.user_activity_canvas)
    
    def _on_heatmap_type_changed(self, text: str) -> None:
        """Handle heatmap type selection change."""
        # Enable/disable time bin based on heatmap type
        if text == "Calendar View":
            self.heatmap_bin_combo.setEnabled(False)
        else:
            self.heatmap_bin_combo.setEnabled(True)
    
    def _on_preset_selected(self, preset_name: str) -> None:
        """Apply preset configuration."""
        if preset_name == "None" or preset_name not in VIZ_PRESETS:
            return
        
        preset = VIZ_PRESETS[preset_name]
        
        # Apply to heatmap tab
        if hasattr(self, 'heatmap_type_combo') and 'heatmap_type' in preset:
            self.heatmap_type_combo.setCurrentText(preset['heatmap_type'])
        if hasattr(self, 'heatmap_bin_combo') and 'time_bin' in preset:
            self.heatmap_bin_combo.setCurrentText(preset['time_bin'])
        if hasattr(self, 'heatmap_category_combo') and 'category_filter' in preset:
            self.heatmap_category_combo.setCurrentText(preset.get('category_filter', 'All Categories'))
        
        # Apply to connections tab
        if hasattr(self, 'graph_time_combo') and 'time_range' in preset:
            self.graph_time_combo.setCurrentText(preset['time_range'])
        
        # Apply to timeline tab
        if hasattr(self, 'timeline_bin_combo') and 'time_bin' in preset:
            self.timeline_bin_combo.setCurrentText(preset['time_bin'])
        
        self.lbl_status.setText(f"✅ Applied preset: {preset_name}")
        self.lbl_status.setStyleSheet("color: #689f38; font-weight: bold;")
        self.logger.info(f"Applied visualization preset: {preset_name}")
    
    def _on_auto_refresh_changed(self, state: int) -> None:
        """Handle auto-refresh checkbox state change."""
        from PyQt6.QtCore import QTimer
        
        if state:
            # Enable auto-refresh
            if self._auto_refresh_timer is None:
                self._auto_refresh_timer = QTimer(self)
                self._auto_refresh_timer.timeout.connect(self._auto_refresh_visualizations)
            
            self._auto_refresh_timer.start(AUTO_REFRESH_INTERVAL_MS)
            self.lbl_status.setText(f"🔄 Auto-refresh enabled ({AUTO_REFRESH_INTERVAL_MS//1000}s)")
            self.lbl_status.setStyleSheet("color: #1976d2; font-weight: bold;")
            self.logger.info("Auto-refresh enabled")
        else:
            # Disable auto-refresh
            if self._auto_refresh_timer:
                self._auto_refresh_timer.stop()
            
            self.lbl_status.setText("Ready")
            self.lbl_status.setStyleSheet("color: #689f38; font-weight: bold;")
            self.logger.info("Auto-refresh disabled")
    
    def _auto_refresh_visualizations(self) -> None:
        """Auto-refresh current visualization."""
        # Only refresh if events are loaded
        if self.events_df is None or self.events_df.empty:
            return
        
        # Get current active tab
        current_index = self.sub_tabs.currentIndex()
        
        # Refresh based on active tab
        if current_index == 0:  # Heatmap
            self._generate_viz("heatmap")
        elif current_index == 1:  # Connections
            self._generate_viz("connections")
        elif current_index == 2:  # Timeline
            self._generate_viz("timeline")
        
        self.logger.info(f"Auto-refreshed visualization (tab {current_index})")
    
    def _export_viz_data(self, viz_type: str) -> None:
        """Export visualization data to CSV/JSON."""
        if self.events_df is None or self.events_df.empty:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self,
                "No Data",
                "❌ No data available to export.\n\n"
                "💡 Generate a visualization first, then export its data."
            )
            return
        
        from PyQt6.QtWidgets import QInputDialog
        
        # Ask for format
        format_choice, ok = QInputDialog.getItem(
            self,
            "Export Format",
            "Select export format:",
            ['CSV', 'JSON', 'HTML'],
            0,
            False
        )
        
        if not ok:
            return
        
        # Get save path
        from PyQt6.QtWidgets import QFileDialog
        ext = format_choice.lower()
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {viz_type.title()} Data",
            f"fepd_{viz_type}_data.{ext}",
            f"{format_choice} Files (*.{ext});;All Files (*)"
        )
        
        if not filepath:
            return
        
        try:
            # Get filtered dataframe based on current config
            df = self._get_filtered_df_for_export(viz_type)
            
            if format_choice == 'CSV':
                df.to_csv(filepath, index=False)
            elif format_choice == 'JSON':
                df.to_json(filepath, orient='records', indent=2, date_format='iso')
            elif format_choice == 'HTML':
                df.to_html(filepath, index=False)
            
            self.lbl_status.setText(f"✅ Data exported: {Path(filepath).name}")
            self.lbl_status.setStyleSheet("color: #689f38; font-weight: bold;")
            self.logger.info(f"Exported {viz_type} data to {filepath}")
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(
                self,
                "Export Error",
                f"❌ Failed to export data:\n\n{str(e)}\n\n"
                f"💡 Check file permissions and try again."
            )
            self.logger.error(f"Export failed: {e}", exc_info=True)
    
    def _get_filtered_df_for_export(self, viz_type: str) -> pd.DataFrame:
        """Get filtered dataframe for export based on current settings."""
        df = self.events_df.copy()
        
        if viz_type == "heatmap" and hasattr(self, 'heatmap_category_combo'):
            category = self.heatmap_category_combo.currentText()
            if category != "All Categories" and 'category' in df.columns:
                df = df[df['category'] == category]
        
        elif viz_type == "connections" and hasattr(self, 'graph_time_combo'):
            time_range = self.graph_time_combo.currentText()
            if 'datetime' in df.columns:
                df = self._filter_events_by_time_range(df, time_range)
        
        return df
    
    def _convert_time_bin_to_freq(self, time_bin: str) -> str:
        """
        Convert user-friendly time bin names to pandas frequency strings.
        
        Args:
            time_bin: User-friendly time bin name (e.g., "1 Hour", "15 Minutes")
            
        Returns:
            Pandas frequency string (e.g., "1H", "15T")
        """
        time_bin_map = {
            "Entire Timeline": None,  # No binning
            "1 Minute": "1T",
            "5 Minutes": "5T",
            "15 Minutes": "15T",
            "30 Minutes": "30T",
            "1 Hour": "1H",
            "2 Hours": "2H",
            "4 Hours": "4H",
            "6 Hours": "6H",
            "12 Hours": "12H",
            "1 Day": "1D",
            "1 Week": "1W",
            "2 Weeks": "2W",
            "1 Month": "1M",
            "3 Months": "3M",
            "6 Months": "6M",
            "1 Year": "1Y",
            # Fallback for old format
            "15min": "15T",
            "1H": "1H",
            "4H": "4H",
            "1D": "1D",
            "1W": "1W",
            "1M": "1M"
        }
        return time_bin_map.get(time_bin, "1H")
    
    def _filter_events_by_time_range(self, df: pd.DataFrame, time_range: str) -> pd.DataFrame:
        """
        Filter events dataframe by time range selection.
        
        Args:
            df: Events dataframe with 'datetime' column
            time_range: Time range string (e.g., "Last 24 Hours", "Entire Timeline")
            
        Returns:
            Filtered dataframe
        """
        if time_range == "Entire Timeline" or df.empty:
            return df
        
        # Get current max datetime from data
        max_datetime = df['datetime'].max()
        
        # Map time range to timedelta
        time_range_map = {
            "Last 1 Hour": pd.Timedelta(hours=1),
            "Last 6 Hours": pd.Timedelta(hours=6),
            "Last 12 Hours": pd.Timedelta(hours=12),
            "Last 24 Hours": pd.Timedelta(hours=24),
            "Last 3 Days": pd.Timedelta(days=3),
            "Last 7 Days": pd.Timedelta(days=7),
            "Last 14 Days": pd.Timedelta(days=14),
            "Last 30 Days": pd.Timedelta(days=30),
            "Last 3 Months": pd.Timedelta(days=90),
            "Last 6 Months": pd.Timedelta(days=180),
            "Last Year": pd.Timedelta(days=365)
        }
        
        delta = time_range_map.get(time_range)
        if delta:
            cutoff_time = max_datetime - delta
            return df[df['datetime'] >= cutoff_time]
        
        return df
    
    def _generate_viz(self, viz_type: str) -> None:
        """Generate visualization in background with caching and progress."""
        if self.events_df is None or self.events_df.empty:
            self.lbl_status.setText("⚠️ No events loaded")
            self.lbl_status.setStyleSheet("color: #f57c00; font-weight: bold;")
            self.logger.warning("No events loaded")
            return
        
        # Prepare filtered dataframe based on viz type
        filtered_df = self.events_df.copy()
        
        # Get configuration based on viz type
        if viz_type == "heatmap":
            # Apply category filter
            category_filter = self.heatmap_category_combo.currentText()
            if category_filter != "All Categories" and 'category' in filtered_df.columns:
                filtered_df = filtered_df[filtered_df['category'] == category_filter]
            
            config = {
                'heatmap_type': self.heatmap_type_combo.currentText() if hasattr(self, 'heatmap_type_combo') else "Day/Hour",
                'bin_size': self._convert_time_bin_to_freq(self.heatmap_bin_combo.currentText()),
                'bin_label': self.heatmap_bin_combo.currentText(),
                'category_filter': category_filter
            }
            
        elif viz_type == "connections":
            # Apply time range filter
            time_range = self.graph_time_combo.currentText()
            filtered_df = self._filter_events_by_time_range(filtered_df, time_range)
            
            config = {
                'layout': self.graph_layout_combo.currentText(),
                'show_labels': self.graph_labels_check.isChecked(),
                'time_range': time_range
            }
            
        elif viz_type == "timeline":
            config = {
                'time_bin': self._convert_time_bin_to_freq(self.timeline_bin_combo.currentText()),
                'bin_label': self.timeline_bin_combo.currentText(),
                'view_type': self.timeline_view_combo.currentText() if hasattr(self, 'timeline_view_combo') else "Stacked Area",
                'show_categories': self.timeline_stacked_check.isChecked()
            }
        else:
            config = {}
        
        # Generate cache key
        cache_key = f"{viz_type}_{hash(str(config))}"
        
        # Check cache first
        canvas = self._get_canvas_for_type(viz_type)
        if canvas and CACHE_ENABLED:
            cached_fig = canvas.get_cached(cache_key)
            if cached_fig:
                self.lbl_status.setText(f"✅ Loaded from cache")
                self.lbl_status.setStyleSheet("color: #689f38; font-weight: bold;")
                self._display_viz(viz_type, cached_fig)
                self.logger.info(f"Loaded {viz_type} from cache")
                return
        
        # Clear existing canvas
        if canvas:
            canvas.clear()
        
        # Show loading state
        self.lbl_status.setText(f"🔄 Generating {viz_type}...")
        self.lbl_status.setStyleSheet("color: #1976d2; font-weight: bold;")
        
        # Update config to use filtered dataframe
        config['filtered_df'] = filtered_df
        config['cache_key'] = cache_key
        
        # Create and start worker
        self.worker = VisualizationWorker(self.events_df, viz_type, config)
        self.worker.finished.connect(lambda fig: self._display_viz(viz_type, fig))
        self.worker.error.connect(self._on_viz_error)
        self.worker.progress.connect(self._on_viz_progress)
        self.worker.start()
        
        self.logger.info(f"Generating {viz_type} visualization...")
    
    def _get_canvas_for_type(self, viz_type: str) -> Optional[VisualizationCanvas]:
        """Get canvas widget for visualization type."""
        if viz_type == "heatmap":
            return self.heatmap_canvas if hasattr(self, 'heatmap_canvas') else None
        elif viz_type == "connections":
            return self.connections_canvas if hasattr(self, 'connections_canvas') else None
        elif viz_type == "timeline":
            return self.timeline_canvas if hasattr(self, 'timeline_canvas') else None
        return None
    
    def _on_viz_progress(self, message: str) -> None:
        """Handle visualization progress update."""
        self.lbl_status.setText(message)
        self.lbl_status.setStyleSheet("color: #1976d2; font-weight: bold;")
    
    def _on_viz_error(self, error_msg: str) -> None:
        """Handle visualization error with user-friendly message."""
        from PyQt6.QtWidgets import QMessageBox
        
        self.lbl_status.setText("❌ Generation failed")
        self.lbl_status.setStyleSheet("color: #d32f2f; font-weight: bold;")
        
        QMessageBox.critical(self, "Visualization Error", error_msg)
        self.logger.error(f"Visualization error: {error_msg}")
    
    def _display_viz(self, viz_type: str, figure: Any) -> None:
        """Display generated visualization and cache it."""
        canvas = self._get_canvas_for_type(viz_type)
        if not canvas:
            return
        
        # Cache the figure
        cache_key = self._last_config.get('cache_key', '')
        if cache_key and CACHE_ENABLED:
            canvas.set_cached(cache_key, figure)
        
        if canvas.figure and canvas.canvas:
            import io
            buf = io.BytesIO()
            try:
                figure.savefig(buf, format='png', dpi=EXPORT_DPI_PREVIEW, bbox_inches='tight')
                buf.seek(0)
                # Clear and display as image
                canvas.figure.clear()
                ax = canvas.figure.add_subplot(111)
                ax.axis('off')
                # Load image from buffer
                try:
                    from PIL import Image
                except ImportError:
                    ax.text(
                        0.5, 0.5,
                        "❌ Pillow not installed\n\n"
                        "💡 Install with: pip install pillow\n\n"
                        "Required for chart rendering.",
                        ha='center', va='center', fontsize=12, color='#e74c3c'
                    )
                    canvas.canvas.draw()
                    self.lbl_status.setText("⚠️ Missing dependency")
                    self.lbl_status.setStyleSheet("color: #f57c00; font-weight: bold;")
                    return
                img = Image.open(buf)
                ax.imshow(img)
                canvas.canvas.draw()
                
                # Update status
                self.lbl_status.setText(f"✅ {viz_type.title()} ready")
                self.lbl_status.setStyleSheet("color: #689f38; font-weight: bold;")
            except Exception as e:
                self.logger.error(f"Failed to render visualization: {e}")
                self.lbl_status.setText("❌ Render failed")
                self.lbl_status.setStyleSheet("color: #d32f2f; font-weight: bold;")
            buf.close()
        
        self.logger.info(f"{viz_type} visualization displayed")
    
    def _save_heatmap(self) -> None:
        """Save heatmap to file."""
        self._save_viz("heatmap", self.heatmap_canvas)
    
    def _save_connections(self) -> None:
        """Save connections graph to file."""
        self._save_viz("connections", self.connections_canvas)
    
    def _save_timeline(self) -> None:
        """Save timeline graph to file."""
        self._save_viz("timeline", self.timeline_canvas)
    
    def _save_viz(self, name: str, canvas: VisualizationCanvas) -> None:
        """Save visualization to file with multiple format options."""
        from PyQt6.QtWidgets import QFileDialog, QInputDialog
        
        # Ask for format
        format_choice, ok = QInputDialog.getItem(
            self,
            "Export Format",
            "Select export format:",
            ['PNG (High Res)', 'PNG (Screen Res)', 'PDF', 'SVG'],
            0,
            False
        )
        
        if not ok:
            return
        
        # Map format to extension and DPI
        format_map = {
            'PNG (High Res)': ('png', EXPORT_DPI),
            'PNG (Screen Res)': ('png', EXPORT_DPI_PREVIEW),
            'PDF': ('pdf', EXPORT_DPI),
            'SVG': ('svg', None)
        }
        
        ext, dpi = format_map.get(format_choice, ('png', EXPORT_DPI))
        
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            f"Save {name.title()} Visualization",
            f"fepd_{name}.{ext}",
            f"{ext.upper()} Files (*.{ext});;All Files (*)"
        )
        
        if filepath:
            try:
                if dpi:
                    canvas.save_figure(filepath, dpi=dpi)
                else:
                    canvas.save_figure(filepath)
                
                self.lbl_status.setText(f"✅ Saved: {Path(filepath).name}")
                self.lbl_status.setStyleSheet("color: #689f38; font-weight: bold;")
                self.logger.info(f"Saved {name} to {filepath}")
            except Exception as e:
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.critical(
                    self,
                    "Save Error",
                    f"❌ Failed to save visualization:\n\n{str(e)}\n\n"
                    f"💡 Check file permissions and try again."
                )
                self.logger.error(f"Save failed: {e}", exc_info=True)

    def _generate_native_attack_surface(self):
        """Generate native matplotlib treemap for attack surface (fallback when WebEngine unavailable)."""
        if not MATPLOTLIB_AVAILABLE or not SQUARIFY_AVAILABLE:
            return
        
        if not hasattr(self, 'attack_surface_canvas') or self.attack_surface_canvas.figure is None:
            return
        
        fig = self.attack_surface_canvas.figure
        fig.clear()
        ax = fig.add_subplot(111)
        ax.axis('off')
        
        # Sample data or from events
        if self.events_df is not None and len(self.events_df) > 0:
            # Try to extract artifact types from events
            if 'artifact_type' in self.events_df.columns:
                counts = self.events_df['artifact_type'].value_counts()
                labels = counts.index.tolist()
                values = counts.values.tolist()
            elif 'event_type' in self.events_df.columns:
                counts = self.events_df['event_type'].value_counts().head(10)
                labels = counts.index.tolist()
                values = counts.values.tolist()
            else:
                # Default sample data
                labels = ['Registry', 'EVTX', 'Browser', 'Prefetch', 'MFT', 'Network']
                values = [350, 280, 120, 85, 450, 65]
        else:
            # Sample data for demonstration
            labels = ['Registry', 'EVTX', 'Browser', 'Prefetch', 'MFT', 'Network', 'Memory']
            values = [350, 280, 120, 85, 450, 65, 200]
        
        # Define colors based on risk (darker = higher risk)
        risk_colors = {
            'Registry': '#ff6b6b',   # High risk - red
            'EVTX': '#ffa94d',       # Medium risk - orange
            'Browser': '#ffe066',    # Medium risk - yellow
            'Prefetch': '#69db7c',   # Low risk - green
            'MFT': '#74c0fc',        # Low risk - blue
            'Network': '#ff8787',    # High risk - light red
            'Memory': '#e599f7',     # Medium risk - purple
        }
        
        colors = [risk_colors.get(label, '#888888') for label in labels]
        
        # Create treemap
        squarify.plot(
            sizes=values, 
            label=[f"{l}\n({v:,})" for l, v in zip(labels, values)],
            alpha=0.85, 
            color=colors,
            text_kwargs={'fontsize': 10, 'weight': 'bold', 'color': 'black'},
            ax=ax
        )
        
        ax.set_title(
            'Attack Surface Map (Native Renderer)\nArtifact Distribution by Type',
            fontsize=14, fontweight='bold', pad=20, color='#333'
        )
        
        fig.tight_layout()
        self.attack_surface_canvas.canvas.draw()
        self.logger.info("Generated native attack surface treemap")

    def _on_attack_surface_audit(self, record: dict):
        """Log treemap interaction; host app can also consume this signal."""
        self.logger.info("[AttackSurface][Audit] %s", record)
    
    def load_events(self, events_df: pd.DataFrame) -> None:
        """Load events for visualization and update status."""
        self.events_df = events_df
        
        self.lbl_status.setText(f"✅ Loaded {len(events_df):,} events")
        self.lbl_status.setStyleSheet("color: #689f38; font-weight: bold;")
        self.logger.info(f"Loaded {len(events_df):,} events for visualization")
        
        if hasattr(self, "attack_surface_map"):
            try:
                self.attack_surface_map.load_events(events_df)
            except Exception as exc:
                self.logger.error("Failed to load events into Attack Surface Map: %s", exc)
