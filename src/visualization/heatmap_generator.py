"""
Heatmap Generator - Creates event density heatmaps from timeline data.
Visualizes temporal patterns using calendar-style heatmap.
"""

import pandas as pd
import numpy as np
import logging
from datetime import datetime
from typing import Optional, Tuple
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
import matplotlib.dates as mdates

logger = logging.getLogger(__name__)


class HeatmapGenerator:
    """
    Generates event density heatmaps from timeline data.
    
    Features:
    - Calendar-style visualization (date x hour-of-day)
    - Automatic date range detection
    - Event density calculation
    - Customizable color schemes
    
    Example:
        >>> generator = HeatmapGenerator(timeline_df)
        >>> fig = generator.generate_heatmap()
        >>> fig.savefig('heatmap.png')
    """
    
    def __init__(self, timeline_df: pd.DataFrame):
        """
        Initialize heatmap generator with timeline data.
        
        Args:
            timeline_df: DataFrame with 'timestamp' column
        """
        self.timeline_df = timeline_df.copy()
        self._prepare_data()
    
    def _prepare_data(self):
        """Prepare timeline data for heatmap generation."""
        if self.timeline_df.empty:
            logger.warning("Timeline DataFrame is empty")
            return
        
        # Ensure timestamp column exists
        if 'timestamp' not in self.timeline_df.columns:
            logger.error("Timeline DataFrame missing 'timestamp' column")
            return
        
        # Convert timestamp to datetime if needed
        if not pd.api.types.is_datetime64_any_dtype(self.timeline_df['timestamp']):
            try:
                self.timeline_df['timestamp'] = pd.to_datetime(
                    self.timeline_df['timestamp'],
                    errors='coerce'
                )
            except Exception as e:
                logger.error(f"Failed to convert timestamps: {e}")
                return
        
        # Drop rows with invalid timestamps
        self.timeline_df = self.timeline_df.dropna(subset=['timestamp'])
        
        # Extract date and hour components
        self.timeline_df['date'] = self.timeline_df['timestamp'].dt.date
        self.timeline_df['hour'] = self.timeline_df['timestamp'].dt.hour
        
        logger.info(f"Prepared {len(self.timeline_df)} events for heatmap")
    
    def generate_heatmap(
        self,
        figsize: Tuple[int, int] = (14, 8),
        cmap: str = 'YlOrRd'
    ) -> Optional[Figure]:
        """
        Generate event density heatmap.
        
        Args:
            figsize: Figure size (width, height)
            cmap: Matplotlib colormap name
        
        Returns:
            Matplotlib Figure object, or None on error
        
        Example:
            >>> fig = generator.generate_heatmap(figsize=(16, 10), cmap='hot')
        """
        if self.timeline_df.empty:
            logger.warning("No data available for heatmap")
            return None
        
        try:
            # Create pivot table: rows=hour, columns=date, values=count
            heatmap_data = self.timeline_df.groupby(['date', 'hour']).size().reset_index(name='count')
            pivot_table = heatmap_data.pivot(index='hour', columns='date', values='count')
            pivot_table = pivot_table.fillna(0)
            
            # Sort columns by date
            pivot_table = pivot_table.sort_index(axis=1)
            
            logger.info(f"Generated heatmap data: {pivot_table.shape[0]} hours x {pivot_table.shape[1]} days")
            
            # Create figure
            fig, ax = plt.subplots(figsize=figsize)
            
            # Use seaborn if available for better styling
            try:
                import seaborn as sns
                sns.heatmap(
                    pivot_table,
                    cmap=cmap,
                    cbar_kws={'label': 'Event Count'},
                    ax=ax,
                    linewidths=0.5,
                    linecolor='gray'
                )
            except ImportError:
                # Fallback to matplotlib
                im = ax.imshow(
                    pivot_table.values,
                    cmap=cmap,
                    aspect='auto',
                    interpolation='nearest'
                )
                fig.colorbar(im, ax=ax, label='Event Count')
                
                # Set ticks
                ax.set_yticks(range(len(pivot_table.index)))
                ax.set_yticklabels(pivot_table.index)
                
                # Format date labels on x-axis
                date_labels = [str(d) for d in pivot_table.columns]
                ax.set_xticks(range(len(date_labels)))
                ax.set_xticklabels(date_labels, rotation=45, ha='right')
            
            # Customize labels
            ax.set_xlabel('Date', fontsize=12, fontweight='bold')
            ax.set_ylabel('Hour of Day', fontsize=12, fontweight='bold')
            ax.set_title('Event Density Heatmap', fontsize=14, fontweight='bold', pad=20)
            
            # Improve y-axis (hour labels)
            ax.set_yticks(range(24))
            ax.set_yticklabels([f'{h:02d}:00' for h in range(24)])
            
            plt.tight_layout()
            
            logger.info("Heatmap generated successfully")
            return fig
            
        except Exception as e:
            logger.error(f"Failed to generate heatmap: {e}", exc_info=True)
            return None
    
    def get_events_for_cell(self, date: str, hour: int) -> pd.DataFrame:
        """
        Get events for a specific date and hour.
        
        Args:
            date: Date string (YYYY-MM-DD)
            hour: Hour of day (0-23)
        
        Returns:
            DataFrame with events for that date/hour
        
        Example:
            >>> events = generator.get_events_for_cell('2024-01-15', 14)
            >>> print(f"Found {len(events)} events at 2pm on Jan 15")
        """
        try:
            date_obj = pd.to_datetime(date).date()
            
            filtered = self.timeline_df[
                (self.timeline_df['date'] == date_obj) & 
                (self.timeline_df['hour'] == hour)
            ]
            
            logger.debug(f"Found {len(filtered)} events for {date} at {hour}:00")
            return filtered
            
        except Exception as e:
            logger.error(f"Failed to get events for cell: {e}")
            return pd.DataFrame()
    
    def get_stats(self) -> dict:
        """
        Get heatmap statistics.
        
        Returns:
            Dictionary with date range, peak hour, busiest day, etc.
        
        Example:
            >>> stats = generator.get_stats()
            >>> print(f"Peak activity: {stats['peak_hour']}:00 on {stats['busiest_day']}")
        """
        if self.timeline_df.empty:
            return {}
        
        try:
            # Date range
            min_date = self.timeline_df['date'].min()
            max_date = self.timeline_df['date'].max()
            
            # Peak hour
            hour_counts = self.timeline_df['hour'].value_counts()
            peak_hour = hour_counts.idxmax() if not hour_counts.empty else 0
            
            # Busiest day
            day_counts = self.timeline_df['date'].value_counts()
            busiest_day = day_counts.idxmax() if not day_counts.empty else None
            
            stats = {
                'total_events': len(self.timeline_df),
                'date_range': f"{min_date} to {max_date}",
                'min_date': str(min_date),
                'max_date': str(max_date),
                'days_covered': (max_date - min_date).days + 1,
                'peak_hour': int(peak_hour),
                'peak_hour_count': int(hour_counts.max()),
                'busiest_day': str(busiest_day),
                'busiest_day_count': int(day_counts.max()),
                'avg_events_per_day': round(len(self.timeline_df) / len(day_counts), 2)
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to calculate stats: {e}")
            return {}


if __name__ == '__main__':
    """Quick test of HeatmapGenerator."""
    print("=" * 60)
    print("HeatmapGenerator Test")
    print("=" * 60)
    
    # Create sample data
    dates = pd.date_range('2024-01-01', periods=30, freq='D')
    hours = list(range(24)) * 30
    
    # Generate random events with peak during business hours
    np.random.seed(42)
    events = []
    for date in dates:
        # More events during business hours (9-17)
        for hour in range(24):
            if 9 <= hour <= 17:
                count = np.random.randint(5, 20)
            else:
                count = np.random.randint(0, 8)
            
            for _ in range(count):
                timestamp = date.replace(hour=hour, minute=np.random.randint(0, 60))
                events.append({'timestamp': timestamp})
    
    df = pd.DataFrame(events)
    print(f"\n✓ Created {len(df)} sample events")
    
    # Test generator
    generator = HeatmapGenerator(df)
    
    # Get stats
    print("\n📊 Heatmap Statistics:")
    stats = generator.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Generate heatmap
    print("\n🎨 Generating heatmap...")
    fig = generator.generate_heatmap(figsize=(16, 8))
    
    if fig:
        print("  ✓ Heatmap generated successfully")
        # Could save: fig.savefig('test_heatmap.png')
    else:
        print("  ✗ Failed to generate heatmap")
    
    # Test cell query
    print("\n🔍 Testing cell query...")
    cell_events = generator.get_events_for_cell('2024-01-15', 14)
    print(f"  Found {len(cell_events)} events on 2024-01-15 at 14:00")
    
    print("\n" + "=" * 60)
    print("✅ HeatmapGenerator test complete!")
    print("=" * 60)
