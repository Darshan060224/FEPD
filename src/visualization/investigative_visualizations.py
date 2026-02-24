"""
FEPD Investigative Visualizations
==================================

Transforms visualizations from "pretty charts" to "investigation maps."

Key Visualizations:
1. 🔥 Activity Heatmap - Time vs activity density
2. 🧬 User Behavior Graph - Who did what
3. 🧭 Attack Path Flow - From entry to impact
4. 🧱 Artifact Treemap - Distribution like crypto heatmap

Each visualization is clickable and links to Files/Timeline.

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-GUI backend
    import matplotlib.pyplot as plt
    import matplotlib.colors as mcolors
    from matplotlib.figure import Figure
    from matplotlib.patches import Rectangle, FancyBboxPatch
    from matplotlib.collections import PatchCollection
    import matplotlib.dates as mdates
    from matplotlib.axes import Axes
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    logger.warning("Matplotlib not available")

try:
    import squarify
    SQUARIFY_AVAILABLE = True
except ImportError:
    SQUARIFY_AVAILABLE = False


# ============================================================================
# COLOR SCHEMES
# ============================================================================

# Severity colors
SEVERITY_COLORS = {
    'critical': '#F44336',   # Red
    'high_risk': '#FF9800',  # Orange
    'suspicious': '#FFC107', # Yellow
    'normal': '#4CAF50'      # Green
}

# Category colors for treemap
CATEGORY_COLORS = {
    'Registry': '#9C27B0',      # Purple
    'EventLog': '#2196F3',      # Blue
    'Prefetch': '#FF9800',      # Orange
    'Browser': '#00BCD4',       # Cyan
    'Email': '#FFC107',         # Amber
    'Executable': '#F44336',    # Red
    'Document': '#4CAF50',      # Green
    'Database': '#795548',      # Brown
    'Network': '#E91E63',       # Pink
    'Memory': '#673AB7',        # Deep Purple
    'Other': '#9E9E9E'          # Grey
}

# Heatmap colormap
HEATMAP_CMAP = 'YlOrRd'  # Yellow-Orange-Red


# ============================================================================
# ACTIVITY HEATMAP
# ============================================================================

class ActivityHeatmap:
    """
    Time vs Activity Density Heatmap.
    
    Shows when activity occurred with intensity.
    Click on a cell to filter timeline to that time period.
    """
    
    def __init__(self, events_df: pd.DataFrame):
        """
        Initialize heatmap generator.
        
        Args:
            events_df: DataFrame with timestamp column
        """
        self.events_df = events_df
        self._parse_timestamps()
    
    def _parse_timestamps(self):
        """Parse and prepare timestamps."""
        # Find timestamp column
        ts_col = None
        for col in ['timestamp', 'ts_local', 'ts_utc', 'datetime', 'time']:
            if col in self.events_df.columns:
                ts_col = col
                break
        
        if ts_col is None:
            raise ValueError("No timestamp column found")
        
        # Convert to datetime
        self.events_df['_datetime'] = pd.to_datetime(
            self.events_df[ts_col], format='mixed', errors='coerce'
        )
        
        # Extract components
        self.events_df['_date'] = self.events_df['_datetime'].dt.date
        self.events_df['_hour'] = self.events_df['_datetime'].dt.hour
        self.events_df['_day_of_week'] = self.events_df['_datetime'].dt.dayofweek
    
    def generate_day_hour_heatmap(self, figsize: Tuple[int, int] = (14, 6)) -> Figure:
        """
        Generate Day of Week vs Hour heatmap.
        
        Returns:
            matplotlib Figure
        """
        if not MATPLOTLIB_AVAILABLE:
            raise ImportError("Matplotlib required")
        
        # Create pivot table
        pivot = self.events_df.pivot_table(
            index='_day_of_week',
            columns='_hour',
            values='_datetime',
            aggfunc='count',
            fill_value=0
        )
        
        # Ensure all hours are present
        for hour in range(24):
            if hour not in pivot.columns:
                pivot[hour] = 0
        pivot = pivot.reindex(columns=range(24), fill_value=0)
        
        # Ensure all days are present
        for day in range(7):
            if day not in pivot.index:
                pivot.loc[day] = 0
        pivot = pivot.reindex(range(7), fill_value=0)
        
        # Create figure
        fig, ax = plt.subplots(figsize=figsize)
        
        # Create heatmap
        im = ax.imshow(pivot.values, cmap=HEATMAP_CMAP, aspect='auto')
        
        # Labels
        day_labels = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 
                      'Friday', 'Saturday', 'Sunday']
        ax.set_yticks(range(7))
        ax.set_yticklabels(day_labels)
        ax.set_xticks(range(24))
        ax.set_xticklabels([f'{h:02d}:00' for h in range(24)], rotation=45, ha='right')
        
        ax.set_xlabel('Hour of Day', fontweight='bold')
        ax.set_ylabel('Day of Week', fontweight='bold')
        ax.set_title('🔥 Activity Heatmap - When Did Events Occur?', 
                    fontsize=14, fontweight='bold', pad=15)
        
        # Colorbar
        cbar = plt.colorbar(im, ax=ax, label='Event Count')
        
        # Add annotations for high-activity cells
        max_val = pivot.values.max()
        for i in range(7):
            for j in range(24):
                val = pivot.values[i, j]
                if val > max_val * 0.7:  # High activity
                    ax.text(j, i, f'{int(val)}', ha='center', va='center',
                           color='white', fontweight='bold', fontsize=8)
        
        plt.tight_layout()
        return fig
    
    def generate_calendar_heatmap(self, figsize: Tuple[int, int] = (16, 8)) -> Figure:
        """
        Generate Date vs Hour calendar-style heatmap.
        
        Returns:
            matplotlib Figure
        """
        if not MATPLOTLIB_AVAILABLE:
            raise ImportError("Matplotlib required")
        
        # Create pivot table
        pivot = self.events_df.pivot_table(
            index='_date',
            columns='_hour',
            values='_datetime',
            aggfunc='count',
            fill_value=0
        )
        
        # Ensure all hours present
        for hour in range(24):
            if hour not in pivot.columns:
                pivot[hour] = 0
        pivot = pivot.reindex(columns=range(24), fill_value=0)
        
        # Create figure
        fig, ax = plt.subplots(figsize=(figsize[0], max(6, len(pivot) * 0.4)))
        
        im = ax.imshow(pivot.values, cmap=HEATMAP_CMAP, aspect='auto', interpolation='nearest')
        
        # X-axis (hours)
        ax.set_xticks(range(24))
        ax.set_xticklabels([f'{h:02d}:00' for h in range(24)], rotation=45, ha='right')
        ax.set_xlabel('Hour of Day', fontweight='bold')
        
        # Y-axis (dates)
        dates = pivot.index
        ax.set_yticks(range(len(dates)))
        ax.set_yticklabels([d.strftime('%Y-%m-%d') for d in dates], fontsize=8)
        ax.set_ylabel('Date', fontweight='bold')
        
        # Title
        total_events = pivot.values.sum()
        ax.set_title(f'📅 Calendar Heatmap - {int(total_events)} Events Over {len(dates)} Days',
                    fontsize=14, fontweight='bold', pad=15)
        
        # Colorbar
        cbar = plt.colorbar(im, ax=ax, label='Events per Hour', pad=0.02)
        
        # Grid
        ax.set_xticks([x - 0.5 for x in range(25)], minor=True)
        ax.set_yticks([y - 0.5 for y in range(len(dates) + 1)], minor=True)
        ax.grid(which='minor', color='white', linewidth=0.5)
        
        plt.tight_layout()
        return fig
    
    def get_peak_activity_times(self, top_n: int = 5) -> List[Dict]:
        """Get times with highest activity."""
        counts = self.events_df.groupby(['_date', '_hour']).size().reset_index(name='count')
        top = counts.nlargest(top_n, 'count')
        
        results = []
        for _, row in top.iterrows():
            results.append({
                'date': row['_date'],
                'hour': row['_hour'],
                'count': row['count']
            })
        return results


# ============================================================================
# USER BEHAVIOR GRAPH
# ============================================================================

class UserBehaviorGraph:
    """
    User Behavior Graph - Who did what.
    
    Shows relationships between users and their actions.
    """
    
    def __init__(self, events_df: pd.DataFrame):
        self.events_df = events_df
    
    def generate(self, figsize: Tuple[int, int] = (14, 10)) -> Figure:
        """Generate user behavior network graph."""
        if not MATPLOTLIB_AVAILABLE:
            raise ImportError("Matplotlib required")
        
        try:
            import networkx as nx
            HAS_NETWORKX = True
        except ImportError:
            HAS_NETWORKX = False
        
        fig, ax = plt.subplots(figsize=figsize)
        
        if not HAS_NETWORKX:
            ax.text(0.5, 0.5, 'NetworkX not installed\nInstall: pip install networkx',
                   ha='center', va='center', fontsize=14)
            ax.set_title('🧬 User Behavior Graph')
            return fig
        
        # Build graph
        G = nx.DiGraph()
        
        # Find user and action columns
        user_col = None
        for col in ['user', 'user_account', 'norm_user', 'SubjectUserName', 'TargetUserName']:
            if col in self.events_df.columns:
                user_col = col
                break
        
        action_col = None
        for col in ['object', 'norm_object', 'process_name', 'ProcessName', 'file_path']:
            if col in self.events_df.columns:
                action_col = col
                break
        
        if not user_col:
            ax.text(0.5, 0.5, 'No user column found in data',
                   ha='center', va='center', fontsize=14)
            return fig
        
        # Build nodes and edges
        user_actions = defaultdict(Counter)
        
        for _, row in self.events_df.iterrows():
            user = str(row.get(user_col, 'Unknown'))
            action = str(row.get(action_col, 'Unknown'))[:40] if action_col else 'Event'
            
            if user and user != 'Unknown' and user != 'nan':
                user_actions[user][action] += 1
        
        # Add nodes
        for user in list(user_actions.keys())[:20]:  # Limit users
            G.add_node(user, node_type='user', size=300)
            
            # Add top actions for this user
            for action, count in user_actions[user].most_common(5):
                if action and action != 'Unknown' and action != 'nan':
                    G.add_node(action, node_type='action', size=100 + count * 10)
                    G.add_edge(user, action, weight=count)
        
        if len(G.nodes()) == 0:
            ax.text(0.5, 0.5, 'No user relationships found',
                   ha='center', va='center', fontsize=14)
            return fig
        
        # Layout
        try:
            pos = nx.spring_layout(G, k=2, iterations=50)
        except:
            pos = nx.circular_layout(G)
        
        # Draw edges
        edges = G.edges(data=True)
        edge_weights = [d.get('weight', 1) for _, _, d in edges]
        max_weight = max(edge_weights) if edge_weights else 1
        edge_widths = [1 + 3 * (w / max_weight) for w in edge_weights]
        
        nx.draw_networkx_edges(G, pos, ax=ax, edge_color='#7f8c8d',
                               arrows=True, arrowsize=10, alpha=0.5,
                               width=edge_widths)
        
        # Separate users and actions
        user_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'user']
        action_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'action']
        
        # Draw user nodes
        user_sizes = [G.nodes[n].get('size', 300) for n in user_nodes]
        nx.draw_networkx_nodes(G, pos, nodelist=user_nodes, ax=ax,
                               node_color='#3498db', node_size=user_sizes,
                               alpha=0.9, edgecolors='white', linewidths=2)
        
        # Draw action nodes
        action_sizes = [G.nodes[n].get('size', 100) for n in action_nodes]
        nx.draw_networkx_nodes(G, pos, nodelist=action_nodes, ax=ax,
                               node_color='#e74c3c', node_size=action_sizes,
                               alpha=0.8, edgecolors='white', linewidths=1)
        
        # Labels
        if len(G.nodes()) < 30:
            labels = {n: n[:20] + '...' if len(n) > 20 else n for n in G.nodes()}
            nx.draw_networkx_labels(G, pos, labels, ax=ax, font_size=8, font_weight='bold')
        
        # Legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#3498db', label='Users'),
            Patch(facecolor='#e74c3c', label='Actions/Objects')
        ]
        ax.legend(handles=legend_elements, loc='upper left')
        
        ax.set_title(f'🧬 User Behavior Graph - {len(user_nodes)} Users, {len(action_nodes)} Actions',
                    fontsize=14, fontweight='bold', pad=15)
        ax.axis('off')
        
        plt.tight_layout()
        return fig
    
    def get_user_summary(self) -> Dict[str, Any]:
        """Get summary of user activity."""
        user_col = None
        for col in ['user', 'user_account', 'norm_user']:
            if col in self.events_df.columns:
                user_col = col
                break
        
        if not user_col:
            return {'error': 'No user column found'}
        
        user_counts = self.events_df[user_col].value_counts().head(10).to_dict()
        return {
            'total_users': self.events_df[user_col].nunique(),
            'top_users': user_counts
        }


# ============================================================================
# ATTACK PATH FLOW
# ============================================================================

class AttackPathFlow:
    """
    Attack Path Flow - From entry to impact.
    
    Shows sequence of events that form an attack chain.
    """
    
    def __init__(self, events_df: pd.DataFrame):
        self.events_df = events_df
    
    def generate(self, figsize: Tuple[int, int] = (16, 10)) -> Figure:
        """Generate attack path flow diagram."""
        if not MATPLOTLIB_AVAILABLE:
            raise ImportError("Matplotlib required")
        
        fig, ax = plt.subplots(figsize=figsize)
        
        # Find severity column
        severity_col = None
        for col in ['severity', 'anomaly_score', 'risk_level']:
            if col in self.events_df.columns:
                severity_col = col
                break
        
        # Get high-severity events
        if severity_col:
            if self.events_df[severity_col].dtype == 'float64':
                high_severity = self.events_df[self.events_df[severity_col] > 0.5]
            else:
                high_severity = self.events_df[
                    self.events_df[severity_col].isin(['critical', 'high_risk', 'suspicious'])
                ]
        else:
            # Use all events if no severity
            high_severity = self.events_df.head(50)
        
        if len(high_severity) == 0:
            ax.text(0.5, 0.5, 'No high-severity events found\nRun ML analysis first',
                   ha='center', va='center', fontsize=14)
            ax.set_title('🧭 Attack Path Flow')
            return fig
        
        # Sort by timestamp
        ts_col = None
        for col in ['timestamp', 'ts_local', 'ts_utc', '_datetime']:
            if col in high_severity.columns:
                ts_col = col
                break
        
        if ts_col:
            high_severity = high_severity.sort_values(ts_col)
        
        # Build attack stages
        stages = self._identify_attack_stages(high_severity.head(20))
        
        if not stages:
            ax.text(0.5, 0.5, 'Could not identify attack stages',
                   ha='center', va='center', fontsize=14)
            ax.set_title('🧭 Attack Path Flow')
            return fig
        
        # Draw flow
        self._draw_attack_flow(ax, stages)
        
        ax.set_title('🧭 Attack Path Flow - Timeline of Suspicious Activity',
                    fontsize=14, fontweight='bold', pad=15)
        ax.axis('off')
        
        plt.tight_layout()
        return fig
    
    def _identify_attack_stages(self, events: pd.DataFrame) -> List[Dict]:
        """Identify attack stages from events."""
        stages = []
        
        # Map event types to attack stages
        stage_mapping = {
            'LogonSuccess': 'Initial Access',
            'LogonFailure': 'Initial Access',
            'ExplicitCredentials': 'Initial Access',
            'ProcessStart': 'Execution',
            'ProcessCreate': 'Execution',
            'ProcessExecution': 'Execution',
            'ServiceInstalled': 'Persistence',
            'ScheduledTaskCreate': 'Persistence',
            'RegistryModification': 'Persistence',
            'GroupMemberAdded': 'Privilege Escalation',
            'AccountCreated': 'Privilege Escalation',
            'PasswordReset': 'Privilege Escalation',
            'NetworkConnection': 'Lateral Movement',
            'FileActivity': 'Collection',
            'FileCreate': 'Collection',
        }
        
        # Find event type column
        type_col = None
        for col in ['event_type', 'norm_event_type', 'EventID', 'type']:
            if col in events.columns:
                type_col = col
                break
        
        if not type_col:
            return stages
        
        for _, row in events.iterrows():
            event_type = str(row.get(type_col, 'Unknown'))
            stage_name = stage_mapping.get(event_type, 'Other')
            
            # Get severity
            severity = 'suspicious'
            if 'severity' in row:
                severity = str(row['severity'])
            elif 'anomaly_score' in row:
                score = float(row.get('anomaly_score', 0))
                if score > 0.85:
                    severity = 'critical'
                elif score > 0.6:
                    severity = 'high_risk'
            
            # Get object/target
            obj = ""
            for col in ['object', 'norm_object', 'process_name', 'file_path']:
                if col in row and row[col]:
                    obj = str(row[col])[:30]
                    break
            
            stages.append({
                'stage': stage_name,
                'event_type': event_type,
                'object': obj,
                'severity': severity,
                'color': SEVERITY_COLORS.get(severity, '#9E9E9E')
            })
        
        return stages
    
    def _draw_attack_flow(self, ax, stages: List[Dict]):
        """Draw attack flow diagram."""
        # Group stages
        stage_order = ['Initial Access', 'Execution', 'Persistence', 
                       'Privilege Escalation', 'Lateral Movement', 'Collection', 'Other']
        
        grouped = defaultdict(list)
        for stage in stages:
            grouped[stage['stage']].append(stage)
        
        # Calculate layout
        n_stages = len([s for s in stage_order if s in grouped])
        x_step = 1.0 / (n_stages + 1)
        
        x = x_step
        stage_positions = {}
        
        for stage_name in stage_order:
            if stage_name not in grouped:
                continue
            
            events = grouped[stage_name]
            stage_positions[stage_name] = x
            
            # Draw stage box
            box = FancyBboxPatch(
                (x - 0.08, 0.7), 0.16, 0.15,
                boxstyle="round,pad=0.02",
                facecolor='#2196F3',
                edgecolor='white',
                linewidth=2,
                alpha=0.9
            )
            ax.add_patch(box)
            
            # Stage label
            ax.text(x, 0.775, stage_name, ha='center', va='center',
                   fontsize=9, fontweight='bold', color='white')
            
            # Draw events below
            y = 0.55
            for i, evt in enumerate(events[:3]):  # Max 3 per stage
                rect = FancyBboxPatch(
                    (x - 0.07, y - 0.04), 0.14, 0.08,
                    boxstyle="round,pad=0.01",
                    facecolor=evt['color'],
                    edgecolor='white',
                    alpha=0.8
                )
                ax.add_patch(rect)
                
                label = evt['object'] if evt['object'] else evt['event_type']
                ax.text(x, y, label[:15], ha='center', va='center',
                       fontsize=7, color='white')
                
                y -= 0.1
            
            x += x_step
        
        # Draw arrows between stages
        prev_x = None
        for stage_name in stage_order:
            if stage_name not in stage_positions:
                continue
            curr_x = stage_positions[stage_name]
            
            if prev_x is not None:
                ax.annotate(
                    '', xy=(curr_x - 0.09, 0.775), xytext=(prev_x + 0.09, 0.775),
                    arrowprops=dict(arrowstyle='->', color='white', lw=2)
                )
            
            prev_x = curr_x
        
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)


# ============================================================================
# ARTIFACT TREEMAP
# ============================================================================

class ArtifactTreemap:
    """
    Artifact Treemap - Distribution like crypto heatmap.
    
    Each block = artifact cluster
    Color = severity
    Size = volume
    """
    
    def __init__(self, events_df: pd.DataFrame):
        self.events_df = events_df
    
    def generate(self, figsize: Tuple[int, int] = (14, 10)) -> Figure:
        """Generate artifact treemap."""
        if not MATPLOTLIB_AVAILABLE:
            raise ImportError("Matplotlib required")
        
        if not SQUARIFY_AVAILABLE:
            fig, ax = plt.subplots(figsize=figsize)
            ax.text(0.5, 0.5, 'squarify not installed\nInstall: pip install squarify',
                   ha='center', va='center', fontsize=14)
            ax.set_title('🧱 Artifact Treemap')
            return fig
        
        # Find category column
        category_col = None
        for col in ['artifact_type', 'category', 'type', 'source']:
            if col in self.events_df.columns:
                category_col = col
                break
        
        if not category_col:
            # Create categories from file extensions or event types
            if 'norm_event_type' in self.events_df.columns:
                category_col = 'norm_event_type'
            elif 'event_type' in self.events_df.columns:
                category_col = 'event_type'
            else:
                fig, ax = plt.subplots(figsize=figsize)
                ax.text(0.5, 0.5, 'No category column found',
                       ha='center', va='center', fontsize=14)
                return fig
        
        # Count by category
        category_counts = self.events_df[category_col].value_counts().head(20)
        
        if len(category_counts) == 0:
            fig, ax = plt.subplots(figsize=figsize)
            ax.text(0.5, 0.5, 'No categories found',
                   ha='center', va='center', fontsize=14)
            return fig
        
        # Calculate severity per category
        severity_col = None
        for col in ['severity', 'anomaly_score']:
            if col in self.events_df.columns:
                severity_col = col
                break
        
        colors = []
        labels = []
        sizes = []
        
        for category, count in category_counts.items():
            # Map to standard category
            std_category = self._standardize_category(str(category))
            color = CATEGORY_COLORS.get(std_category, '#9E9E9E')
            
            # Adjust color based on severity if available
            if severity_col:
                cat_events = self.events_df[self.events_df[category_col] == category]
                if cat_events[severity_col].dtype == 'float64':
                    avg_score = cat_events[severity_col].mean()
                    if avg_score > 0.6:
                        color = '#F44336'  # Red
                    elif avg_score > 0.3:
                        color = '#FF9800'  # Orange
            
            colors.append(color)
            labels.append(f"{category}\n({count})")
            sizes.append(count)
        
        # Create figure
        fig, ax = plt.subplots(figsize=figsize)
        
        # Draw treemap
        squarify.plot(sizes=sizes, label=labels, color=colors, 
                     alpha=0.85, ax=ax, text_kwargs={'fontsize': 9})
        
        ax.set_title('🧱 Artifact Treemap - Evidence Distribution by Type',
                    fontsize=14, fontweight='bold', pad=15)
        ax.axis('off')
        
        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor=color, label=cat)
            for cat, color in list(CATEGORY_COLORS.items())[:8]
        ]
        ax.legend(handles=legend_elements, loc='upper right', 
                 fontsize=8, title='Categories')
        
        plt.tight_layout()
        return fig
    
    def _standardize_category(self, category: str) -> str:
        """Map category to standard category name."""
        category_lower = category.lower()
        
        mappings = {
            'evtx': 'EventLog',
            'evt': 'EventLog',
            'event': 'EventLog',
            'registry': 'Registry',
            'reg': 'Registry',
            'prefetch': 'Prefetch',
            'pf': 'Prefetch',
            'browser': 'Browser',
            'chrome': 'Browser',
            'firefox': 'Browser',
            'email': 'Email',
            'pst': 'Email',
            'exe': 'Executable',
            'dll': 'Executable',
            'process': 'Executable',
            'document': 'Document',
            'pdf': 'Document',
            'doc': 'Document',
            'network': 'Network',
            'pcap': 'Network',
            'memory': 'Memory',
            'mem': 'Memory',
            'db': 'Database',
            'sqlite': 'Database'
        }
        
        for key, value in mappings.items():
            if key in category_lower:
                return value
        
        return 'Other'


# ============================================================================
# COMBINED VISUALIZATION GENERATOR
# ============================================================================

class InvestigativeVisualizationGenerator:
    """
    Generates all investigative visualizations.
    """
    
    def __init__(self, events_df: pd.DataFrame):
        self.events_df = events_df
    
    def generate_all(self) -> Dict[str, Figure]:
        """Generate all visualizations."""
        results = {}
        
        # Heatmaps
        try:
            heatmap = ActivityHeatmap(self.events_df)
            results['day_hour_heatmap'] = heatmap.generate_day_hour_heatmap()
            results['calendar_heatmap'] = heatmap.generate_calendar_heatmap()
        except Exception as e:
            logger.error(f"Error generating heatmaps: {e}")
        
        # User behavior graph
        try:
            user_graph = UserBehaviorGraph(self.events_df)
            results['user_behavior'] = user_graph.generate()
        except Exception as e:
            logger.error(f"Error generating user behavior graph: {e}")
        
        # Attack path
        try:
            attack_path = AttackPathFlow(self.events_df)
            results['attack_path'] = attack_path.generate()
        except Exception as e:
            logger.error(f"Error generating attack path: {e}")
        
        # Treemap
        try:
            treemap = ArtifactTreemap(self.events_df)
            results['treemap'] = treemap.generate()
        except Exception as e:
            logger.error(f"Error generating treemap: {e}")
        
        return results
    
    def save_all(self, output_dir: str, prefix: str = "viz"):
        """Save all visualizations to files."""
        from pathlib import Path
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        figures = self.generate_all()
        
        for name, fig in figures.items():
            filepath = output_path / f"{prefix}_{name}.png"
            fig.savefig(str(filepath), dpi=150, bbox_inches='tight')
            plt.close(fig)
            logger.info(f"Saved {filepath}")
