"""
Event-Relationship Graph (Connections View)
============================================

Interactive network graph showing relationships between:
- Users
- Files
- IP addresses
- Processes
- Registry keys
- Network connections

Use cases:
- Lateral movement detection
- Data exfiltration paths
- Attack chain reconstruction
- Privilege escalation visualization

Reference: Elasticsearch/Kibana graph analysis
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
from collections import defaultdict, Counter
from datetime import datetime
import logging

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    logging.warning("NetworkX not available")

try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False
    logging.warning("PyVis not available")

try:
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    MPL_AVAILABLE = True
except ImportError:
    MPL_AVAILABLE = False

try:
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QComboBox, QLabel, QCheckBox, QSpinBox, QGroupBox,
                             QSlider, QListWidget, QTextEdit)
from PyQt6.QtCore import Qt, pyqtSignal

# Optional WebEngine import with fallback
try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    WEBENGINE_AVAILABLE = True
except ImportError:
    WEBENGINE_AVAILABLE = False
    QWebEngineView = None  # type: ignore


class ConnectionsGraphWidget(QWidget):
    """
    PyQt widget displaying interactive network graph of entity relationships.
    
    Nodes represent entities (users, files, IPs, processes).
    Edges represent relationships (accessed, created, connected_to, executed).
    """
    
    # Signals
    node_selected = pyqtSignal(str, str)  # node_type, node_id
    path_found = pyqtSignal(list)  # list of nodes in path
    cluster_detected = pyqtSignal(str)  # cluster description
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.events_df = None
        self.graph = None
        self.current_backend = 'pyvis'
        
        # Node type colors
        self.node_colors = {
            'user': '#FF6B6B',      # Red
            'file': '#4ECDC4',      # Teal
            'ip': '#95E1D3',        # Light teal
            'process': '#F38181',   # Pink
            'registry': '#AA96DA',  # Purple
            'domain': '#FCBAD3',    # Light pink
            'port': '#A8E6CF'       # Mint
        }
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        # Backend selection
        controls_layout.addWidget(QLabel("Visualization:"))
        self.backend_combo = QComboBox()
        backends = []
        if PYVIS_AVAILABLE:
            backends.append('PyVis (Interactive)')
        if MPL_AVAILABLE:
            backends.append('NetworkX (Static)')
        if PLOTLY_AVAILABLE:
            backends.append('Plotly (3D)')
        self.backend_combo.addItems(backends)
        self.backend_combo.currentIndexChanged.connect(self._on_backend_changed)
        controls_layout.addWidget(self.backend_combo)
        
        # Layout algorithm
        controls_layout.addWidget(QLabel("Layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(['Force-Directed', 'Hierarchical', 'Circular', 'Kamada-Kawai'])
        self.layout_combo.currentTextChanged.connect(self._on_layout_changed)
        controls_layout.addWidget(self.layout_combo)
        
        # Node limit
        controls_layout.addWidget(QLabel("Max Nodes:"))
        self.node_limit_spin = QSpinBox()
        self.node_limit_spin.setRange(10, 1000)
        self.node_limit_spin.setValue(100)
        self.node_limit_spin.setSingleStep(10)
        self.node_limit_spin.valueChanged.connect(self._on_node_limit_changed)
        controls_layout.addWidget(self.node_limit_spin)
        
        # Min edge weight
        controls_layout.addWidget(QLabel("Min Connections:"))
        self.min_weight_spin = QSpinBox()
        self.min_weight_spin.setRange(1, 100)
        self.min_weight_spin.setValue(1)
        self.min_weight_spin.valueChanged.connect(self._on_min_weight_changed)
        controls_layout.addWidget(self.min_weight_spin)
        
        controls_layout.addStretch()
        
        # Analysis buttons
        self.find_path_btn = QPushButton("Find Path")
        self.find_path_btn.clicked.connect(self._find_shortest_path)
        controls_layout.addWidget(self.find_path_btn)
        
        self.detect_clusters_btn = QPushButton("Detect Communities")
        self.detect_clusters_btn.clicked.connect(self._detect_communities)
        controls_layout.addWidget(self.detect_clusters_btn)
        
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self._on_export)
        controls_layout.addWidget(self.export_btn)
        
        layout.addLayout(controls_layout)
        
        # Filter panel
        filter_group = QGroupBox("Node Type Filters")
        filter_layout = QHBoxLayout()
        
        self.filter_checkboxes = {}
        for node_type in ['user', 'file', 'ip', 'process', 'registry', 'domain']:
            cb = QCheckBox(node_type.capitalize())
            cb.setChecked(True)
            cb.stateChanged.connect(self._on_filter_changed)
            filter_layout.addWidget(cb)
            self.filter_checkboxes[node_type] = cb
        
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # Statistics
        stats_group = QGroupBox("Graph Statistics")
        stats_layout = QVBoxLayout()
        self.stats_label = QLabel("Load events to build graph")
        stats_layout.addWidget(self.stats_label)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Web view for PyVis/Plotly (with fallback to QTextEdit)
        if WEBENGINE_AVAILABLE and QWebEngineView is not None:
            self.web_view = QWebEngineView()
            self._webengine_available = True
        else:
            # Fallback to QTextEdit for HTML display
            self.web_view = QTextEdit()
            self.web_view.setReadOnly(True)
            self.web_view.setPlaceholderText(
                "Qt WebEngine not installed.\n"
                "Install PyQt6-WebEngine for interactive graphs:\n"
                "pip install PyQt6-WebEngine"
            )
            self._webengine_available = False
        layout.addWidget(self.web_view)
        
        # Matplotlib canvas
        if MPL_AVAILABLE:
            self.mpl_figure = Figure(figsize=(12, 8))
            self.mpl_canvas = FigureCanvas(self.mpl_figure)
            self.mpl_canvas.hide()
            layout.addWidget(self.mpl_canvas)
    
    def load_events(self, events_df: pd.DataFrame):
        """
        Build relationship graph from events.
        
        Args:
            events_df: DataFrame with event data
        """
        self.events_df = events_df.copy()
        self._build_graph()
        self._update_statistics()
        self._refresh_visualization()
    
    def _build_graph(self):
        """Build NetworkX graph from events."""
        if not NETWORKX_AVAILABLE:
            self.logger.error("NetworkX not available")
            return
        
        self.graph = nx.DiGraph()
        
        # Extract relationships from events
        for idx, event in self.events_df.iterrows():
            event_type = event.get('event_type', 'unknown')
            timestamp = event.get('timestamp', datetime.now())
            
            # User relationships
            if 'user' in event and pd.notna(event['user']):
                user_node = f"user:{event['user']}"
                self.graph.add_node(user_node, type='user', label=event['user'])
                
                # User -> File
                if 'file_path' in event and pd.notna(event['file_path']):
                    file_node = f"file:{event['file_path']}"
                    self.graph.add_node(file_node, type='file', label=event['file_path'])
                    self.graph.add_edge(user_node, file_node, 
                                      type='accessed', timestamp=timestamp)
                
                # User -> Process
                if 'process_name' in event and pd.notna(event['process_name']):
                    proc_node = f"process:{event['process_name']}"
                    self.graph.add_node(proc_node, type='process', label=event['process_name'])
                    self.graph.add_edge(user_node, proc_node,
                                      type='executed', timestamp=timestamp)
                
                # User -> IP
                if 'remote_ip' in event and pd.notna(event['remote_ip']):
                    ip_node = f"ip:{event['remote_ip']}"
                    self.graph.add_node(ip_node, type='ip', label=event['remote_ip'])
                    self.graph.add_edge(user_node, ip_node,
                                      type='connected_to', timestamp=timestamp)
            
            # Process -> File relationships
            if 'process_name' in event and 'file_path' in event:
                if pd.notna(event['process_name']) and pd.notna(event['file_path']):
                    proc_node = f"process:{event['process_name']}"
                    file_node = f"file:{event['file_path']}"
                    self.graph.add_node(proc_node, type='process', label=event['process_name'])
                    self.graph.add_node(file_node, type='file', label=event['file_path'])
                    
                    if 'file_created' in event_type.lower():
                        self.graph.add_edge(proc_node, file_node, type='created')
                    else:
                        self.graph.add_edge(proc_node, file_node, type='accessed')
            
            # IP -> Domain relationships
            if 'remote_ip' in event and 'domain' in event:
                if pd.notna(event['remote_ip']) and pd.notna(event['domain']):
                    ip_node = f"ip:{event['remote_ip']}"
                    domain_node = f"domain:{event['domain']}"
                    self.graph.add_node(ip_node, type='ip', label=event['remote_ip'])
                    self.graph.add_node(domain_node, type='domain', label=event['domain'])
                    self.graph.add_edge(domain_node, ip_node, type='resolves_to')
            
            # Registry key relationships
            if 'registry_key' in event and pd.notna(event['registry_key']):
                reg_node = f"registry:{event['registry_key']}"
                self.graph.add_node(reg_node, type='registry', label=event['registry_key'])
                
                if 'process_name' in event and pd.notna(event['process_name']):
                    proc_node = f"process:{event['process_name']}"
                    self.graph.add_node(proc_node, type='process', label=event['process_name'])
                    self.graph.add_edge(proc_node, reg_node, type='modified')
        
        # Aggregate edge weights
        self._aggregate_edge_weights()
        
        self.logger.info(f"Built graph with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges")
    
    def _aggregate_edge_weights(self):
        """Count repeated edges as weights."""
        if not self.graph:
            return
        
        # Count edges between same nodes
        edge_counts = defaultdict(int)
        for u, v, data in self.graph.edges(data=True):
            key = (u, v, data.get('type', 'unknown'))
            edge_counts[key] += 1
        
        # Update edge weights
        for (u, v, edge_type), count in edge_counts.items():
            if self.graph.has_edge(u, v):
                self.graph[u][v]['weight'] = count
    
    def _filter_graph(self) -> nx.DiGraph:
        """Apply filters to graph."""
        if not self.graph:
            return nx.DiGraph()
        
        # Get enabled node types
        enabled_types = [
            node_type for node_type, cb in self.filter_checkboxes.items()
            if cb.isChecked()
        ]
        
        # Filter nodes
        filtered_nodes = [
            n for n, data in self.graph.nodes(data=True)
            if data.get('type', 'unknown') in enabled_types
        ]
        
        subgraph = self.graph.subgraph(filtered_nodes).copy()
        
        # Filter by edge weight
        min_weight = self.min_weight_spin.value()
        edges_to_remove = [
            (u, v) for u, v, data in subgraph.edges(data=True)
            if data.get('weight', 1) < min_weight
        ]
        subgraph.remove_edges_from(edges_to_remove)
        
        # Remove isolated nodes
        isolated = list(nx.isolates(subgraph))
        subgraph.remove_nodes_from(isolated)
        
        # Limit nodes by degree centrality
        max_nodes = self.node_limit_spin.value()
        if subgraph.number_of_nodes() > max_nodes:
            degree_cent = nx.degree_centrality(subgraph)
            top_nodes = sorted(degree_cent, key=degree_cent.get, reverse=True)[:max_nodes]
            subgraph = subgraph.subgraph(top_nodes).copy()
        
        return subgraph
    
    def _on_backend_changed(self, index):
        """Handle backend change."""
        backend_text = self.backend_combo.currentText()
        if 'PyVis' in backend_text:
            self.current_backend = 'pyvis'
            self.web_view.show()
            if MPL_AVAILABLE:
                self.mpl_canvas.hide()
        elif 'NetworkX' in backend_text:
            self.current_backend = 'networkx'
            self.web_view.hide()
            if MPL_AVAILABLE:
                self.mpl_canvas.show()
        elif 'Plotly' in backend_text:
            self.current_backend = 'plotly'
            self.web_view.show()
            if MPL_AVAILABLE:
                self.mpl_canvas.hide()
        
        self._refresh_visualization()
    
    def _on_layout_changed(self, text):
        """Handle layout algorithm change."""
        self._refresh_visualization()
    
    def _on_node_limit_changed(self, value):
        """Handle node limit change."""
        self._refresh_visualization()
    
    def _on_min_weight_changed(self, value):
        """Handle min weight change."""
        self._refresh_visualization()
    
    def _on_filter_changed(self, state):
        """Handle filter change."""
        self._refresh_visualization()
    
    def _on_export(self):
        """Export graph."""
        from PyQt6.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Graph",
            "connections.html",
            "HTML Interactive (*.html);;PNG Image (*.png);;GraphML (*.graphml);;GEXF (*.gexf)"
        )
        
        if not file_path:
            return
        
        filtered_graph = self._filter_graph()
        
        if file_path.endswith('.html'):
            self._export_html(filtered_graph, file_path)
        elif file_path.endswith('.png'):
            self._export_png(filtered_graph, file_path)
        elif file_path.endswith('.graphml'):
            nx.write_graphml(filtered_graph, file_path)
        elif file_path.endswith('.gexf'):
            nx.write_gexf(filtered_graph, file_path)
    
    def _refresh_visualization(self):
        """Refresh graph visualization."""
        if not self.graph:
            return
        
        filtered_graph = self._filter_graph()
        
        if self.current_backend == 'pyvis':
            self._plot_pyvis(filtered_graph)
        elif self.current_backend == 'networkx':
            self._plot_networkx(filtered_graph)
        elif self.current_backend == 'plotly':
            self._plot_plotly(filtered_graph)
    
    def _plot_pyvis(self, graph: nx.DiGraph):
        """Create interactive PyVis visualization."""
        if not PYVIS_AVAILABLE:
            return
        
        net = Network(height='600px', width='100%', directed=True)
        
        # Add nodes
        for node, data in graph.nodes(data=True):
            node_type = data.get('type', 'unknown')
            color = self.node_colors.get(node_type, '#CCCCCC')
            label = data.get('label', node)
            
            net.add_node(node, label=label, color=color, title=f"{node_type}: {label}")
        
        # Add edges
        for u, v, data in graph.edges(data=True):
            weight = data.get('weight', 1)
            edge_type = data.get('type', 'related')
            
            net.add_edge(u, v, title=edge_type, width=min(weight, 10))
        
        # Physics options
        layout = self.layout_combo.currentText()
        if 'Force' in layout:
            net.barnes_hut()
        elif 'Hierarchical' in layout:
            net.force_atlas_2based()
        
        # Generate HTML
        html = net.generate_html()
        self._set_html_content(html)
    
    def _plot_networkx(self, graph: nx.DiGraph):
        """Create static NetworkX visualization."""
        if not MPL_AVAILABLE:
            return
        
        self.mpl_figure.clear()
        ax = self.mpl_figure.add_subplot(111)
        
        # Layout
        layout_name = self.layout_combo.currentText()
        if 'Force' in layout_name:
            pos = nx.spring_layout(graph, k=0.5, iterations=50)
        elif 'Circular' in layout_name:
            pos = nx.circular_layout(graph)
        elif 'Kamada' in layout_name:
            pos = nx.kamada_kawai_layout(graph)
        else:
            pos = nx.spring_layout(graph)
        
        # Draw nodes by type
        for node_type, color in self.node_colors.items():
            nodes = [n for n, d in graph.nodes(data=True) if d.get('type') == node_type]
            nx.draw_networkx_nodes(graph, pos, nodelist=nodes, node_color=color,
                                  node_size=500, alpha=0.8, ax=ax, label=node_type)
        
        # Draw edges
        nx.draw_networkx_edges(graph, pos, alpha=0.3, arrows=True,
                              arrowsize=10, ax=ax, edge_color='gray')
        
        # Draw labels
        labels = {n: d.get('label', n)[:15] for n, d in graph.nodes(data=True)}
        nx.draw_networkx_labels(graph, pos, labels, font_size=8, ax=ax)
        
        ax.set_title('Entity Relationship Graph')
        ax.legend(loc='upper left')
        ax.axis('off')
        
        self.mpl_figure.tight_layout()
        self.mpl_canvas.draw()
    
    def _plot_plotly(self, graph: nx.DiGraph):
        """Create 3D Plotly visualization."""
        if not PLOTLY_AVAILABLE:
            return
        
        # 3D layout
        pos = nx.spring_layout(graph, dim=3, k=0.5)
        
        # Edge traces
        edge_trace = go.Scatter3d(
            x=[], y=[], z=[],
            mode='lines',
            line=dict(color='gray', width=1),
            hoverinfo='none'
        )
        
        edge_x: list = []
        edge_y: list = []
        edge_z: list = []
        for u, v in graph.edges():
            x0, y0, z0 = pos[u]
            x1, y1, z1 = pos[v]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            edge_z.extend([z0, z1, None])
        edge_trace = go.Scatter3d(
            x=edge_x, y=edge_y, z=edge_z,
            mode='lines',
            line=dict(color='gray', width=1),
            hoverinfo='none'
        )
        
        # Node traces
        node_traces = []
        for node_type, color in self.node_colors.items():
            nodes = [n for n, d in graph.nodes(data=True) if d.get('type') == node_type]
            if not nodes:
                continue
            
            node_trace = go.Scatter3d(
                x=[pos[n][0] for n in nodes],
                y=[pos[n][1] for n in nodes],
                z=[pos[n][2] for n in nodes],
                mode='markers+text',
                marker=dict(size=8, color=color),
                text=[graph.nodes[n].get('label', n)[:15] for n in nodes],
                name=node_type,
                hoverinfo='text'
            )
            node_traces.append(node_trace)
        
        fig = go.Figure(data=[edge_trace] + node_traces)
        fig.update_layout(
            title='3D Entity Relationship Graph',
            showlegend=True,
            hovermode='closest',
            scene=dict(
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                zaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
            )
        )
        
        html = fig.to_html(include_plotlyjs='cdn')
        self._set_html_content(html)
    
    def _set_html_content(self, html: str):
        """Set HTML content with fallback for QTextEdit."""
        if self._webengine_available:
            self.web_view.setHtml(html)
        else:
            # QTextEdit fallback - show message about installing WebEngine
            fallback_msg = (
                "<h2>Interactive Graph Unavailable</h2>"
                "<p>Qt WebEngine is not installed.</p>"
                "<p>To view interactive graphs, install PyQt6-WebEngine:</p>"
                "<pre>pip install PyQt6-WebEngine</pre>"
                "<hr>"
                "<p><b>Graph Summary:</b></p>"
            )
            if self.graph:
                fallback_msg += f"<p>Nodes: {self.graph.number_of_nodes()}, Edges: {self.graph.number_of_edges()}</p>"
            self.web_view.setHtml(fallback_msg)
    
    def _update_statistics(self):
        """Update graph statistics display."""
        if not self.graph:
            return
        
        filtered = self._filter_graph()
        
        stats = []
        stats.append(f"Nodes: {filtered.number_of_nodes()}")
        stats.append(f"Edges: {filtered.number_of_edges()}")
        
        if filtered.number_of_nodes() > 0:
            # Density
            density = nx.density(filtered)
            stats.append(f"Density: {density:.3f}")
            
            # Most connected nodes
            degree_cent = nx.degree_centrality(filtered)
            if degree_cent:
                top_node = max(degree_cent, key=degree_cent.get)
                stats.append(f"Hub: {filtered.nodes[top_node].get('label', top_node)[:20]}")
            
            # Connected components
            if not nx.is_directed(filtered):
                n_components = nx.number_connected_components(filtered)
            else:
                n_components = nx.number_weakly_connected_components(filtered)
            stats.append(f"Components: {n_components}")
        
        self.stats_label.setText(" | ".join(stats))
    
    def _find_shortest_path(self):
        """Find shortest path between two selected nodes."""
        # Placeholder: would need node selection UI
        self.logger.info("Path finding not yet implemented")
    
    def _detect_communities(self):
        """Detect communities/clusters in graph."""
        if not self.graph:
            return
        
        filtered = self._filter_graph()
        
        if filtered.number_of_nodes() < 2:
            return
        
        # Convert to undirected for community detection
        undirected = filtered.to_undirected()
        
        # Detect communities using Louvain
        try:
            import community as community_louvain
            partition = community_louvain.best_partition(undirected)
            n_communities = len(set(partition.values()))
            
            message = f"Detected {n_communities} communities/clusters in the graph"
            self.cluster_detected.emit(message)
            
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "Community Detection", message)
        except ImportError:
            self.logger.warning("python-louvain not installed")
    
    def _export_html(self, graph, file_path):
        """Export PyVis HTML."""
        if PYVIS_AVAILABLE:
            net = Network(directed=True)
            net.from_nx(graph)
            net.save_graph(file_path)
    
    def _export_png(self, graph, file_path):
        """Export NetworkX PNG."""
        if MPL_AVAILABLE:
            fig, ax = plt.subplots(figsize=(12, 8))
            pos = nx.spring_layout(graph)
            nx.draw(graph, pos, with_labels=True, ax=ax)
            fig.savefig(file_path, dpi=300, bbox_inches='tight')
            plt.close(fig)


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("Event-Relationship Graph Module")
    print("=" * 50)
    print(f"NetworkX Available: {NETWORKX_AVAILABLE}")
    print(f"PyVis Available: {PYVIS_AVAILABLE}")
    print(f"Plotly Available: {PLOTLY_AVAILABLE}")
    
    if NETWORKX_AVAILABLE:
        # Generate sample events
        events = pd.DataFrame({
            'user': ['alice', 'alice', 'bob', 'bob', 'charlie'] * 20,
            'file_path': ['/etc/passwd', '/home/alice/data.txt', '/tmp/malware.exe',
                         '/home/bob/docs.pdf', '/var/log/auth.log'] * 20,
            'process_name': ['bash', 'python', 'explorer.exe', 'chrome.exe', 'sshd'] * 20,
            'remote_ip': ['192.168.1.100', '10.0.0.50', '8.8.8.8', '1.2.3.4', '192.168.1.1'] * 20,
            'event_type': ['file_access', 'file_created', 'process_start', 'network_connection', 'login'] * 20
        })
        
        print(f"\nGenerated {len(events)} sample events")
        print("Relationship types included:")
        print("  - User → File (access)")
        print("  - User → Process (execution)")
        print("  - User → IP (network)")
        print("  - Process → File (creation)")
        
        # This would normally be used in a PyQt application
        print("\n✓ Module ready for integration")
