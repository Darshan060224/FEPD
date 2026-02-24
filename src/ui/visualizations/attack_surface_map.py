"""
FEPD Attack Surface Map - Forensic Treemap Visualization
=========================================================

You are the Attack Surface Visualizer of FEPD.
You do not show raw counts.
You reveal where attacker activity is concentrated across the evidence.

This visualization answers: "Where does the attacker's footprint concentrate?"

Each rectangle represents an attack-relevant surface:
- WindowsEvent: Event log activity
- ProcessExecution: Executed binaries
- RegistryCreated: Persistence attempts
- RegistryModified: Configuration tampering
- FileDropped: Malware/artifacts dropped
- NetworkActivity: C2 / lateral movement
- BrowserArtifact: Phishing / exfil indicators
- MemoryOnly: In-memory malware artifacts

Rectangle Size = log(count + 1) * severity_factor * anomaly_factor
Rectangle Color = mean anomaly score (Gray → Orange → Red → Dark Red)
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, List, Optional, TYPE_CHECKING, cast

import pandas as pd

try:
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

# Import detail panel
from src.ui.widgets.attack_surface_detail_panel import AttackSurfaceDetailPanel

if TYPE_CHECKING:
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton, QFrame, QSplitter
    )
    from PyQt6.QtCore import Qt, pyqtSignal, QObject, pyqtSlot
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtWebChannel import QWebChannel
    WEB_ENGINE_AVAILABLE = True
else:
    try:
        from PyQt6.QtWidgets import (
            QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton, QFrame, QSplitter
        )
        from PyQt6.QtCore import Qt, pyqtSignal, QObject, pyqtSlot
        from PyQt6.QtWebEngineWidgets import QWebEngineView
        from PyQt6.QtWebChannel import QWebChannel
        WEB_ENGINE_AVAILABLE = True
    except ImportError:
        WEB_ENGINE_AVAILABLE = False
        
        class _DummyQObject:
            def __init__(self, *args, **kwargs):
                pass
        
        def _dummy_signal(*args, **kwargs):
            class _DummySignal:
                def connect(self, *a, **k): return None
                def emit(self, *a, **k): return None
            return _DummySignal()
        
        def _dummy_slot(*args, **kwargs):
            def decorator(func): return func
            return decorator
        
        class _DummyWidget:
            def __init__(self, *args, **kwargs): pass
        
        QWidget = cast(Any, _DummyWidget)
        QVBoxLayout = QHBoxLayout = QLabel = QComboBox = QPushButton = QFrame = QSplitter = cast(Any, _DummyWidget)
        Qt = cast(Any, object)
        pyqtSignal = _dummy_signal
        QObject = cast(Any, _DummyQObject)
        pyqtSlot = _dummy_slot
        QWebEngineView = QWebChannel = cast(Any, _DummyWidget)


# =============================================================================
# FORENSIC CATEGORY DEFINITIONS
# =============================================================================

@dataclass
class AttackCategory:
    """Definition of an attack surface category."""
    id: str
    name: str
    description: str
    severity_factor: float  # Base severity weight (1.0 = normal, 2.0 = high)
    keywords: List[str]     # Keywords to detect this category
    icon: str = "🔍"


# Attack categories ordered by forensic importance
ATTACK_CATEGORIES = [
    AttackCategory(
        id="ProcessExecution",
        name="Process Execution",
        description="Executed binaries and scripts",
        severity_factor=1.8,
        keywords=["process", "exec", "run", "spawn", "launch", "cmd", "powershell", "script", "binary", "exe"],
        icon="⚡"
    ),
    AttackCategory(
        id="RegistryPersistence",
        name="Registry Persistence",
        description="Persistence mechanisms via registry",
        severity_factor=2.0,
        keywords=["registry", "run", "runonce", "startup", "services", "hklm", "hkcu", "autorun"],
        icon="🔑"
    ),
    AttackCategory(
        id="RegistryModified",
        name="Registry Modified",
        description="Configuration tampering",
        severity_factor=1.5,
        keywords=["registry", "modify", "change", "update", "set", "config"],
        icon="⚙️"
    ),
    AttackCategory(
        id="FileDropped",
        name="File Dropped",
        description="Files written to disk (potential malware)",
        severity_factor=1.7,
        keywords=["file", "drop", "write", "create", "download", "save", "extract"],
        icon="📥"
    ),
    AttackCategory(
        id="NetworkActivity",
        name="Network Activity",
        description="C2, lateral movement, exfiltration",
        severity_factor=1.9,
        keywords=["network", "connect", "socket", "http", "dns", "ip", "port", "c2", "beacon", "lateral"],
        icon="🌐"
    ),
    AttackCategory(
        id="BrowserArtifact",
        name="Browser Artifacts",
        description="Phishing, downloads, browsing history",
        severity_factor=1.4,
        keywords=["browser", "chrome", "firefox", "edge", "history", "download", "cookie", "cache", "url"],
        icon="🌍"
    ),
    AttackCategory(
        id="WindowsEvent",
        name="Windows Events",
        description="Security/System event log activity",
        severity_factor=1.0,
        keywords=["event", "evtx", "security", "system", "application", "log", "eventlog"],
        icon="📋"
    ),
    AttackCategory(
        id="MemoryArtifact",
        name="Memory Artifacts",
        description="In-memory indicators (injection, hollowing)",
        severity_factor=2.2,
        keywords=["memory", "injection", "hollow", "dump", "malfind", "vad", "heap", "stack"],
        icon="🧠"
    ),
    AttackCategory(
        id="Authentication",
        name="Authentication",
        description="Login attempts, credential access",
        severity_factor=1.6,
        keywords=["login", "logon", "auth", "credential", "password", "ntlm", "kerberos", "sam", "lsass"],
        icon="🔐"
    ),
    AttackCategory(
        id="ScheduledTask",
        name="Scheduled Tasks",
        description="Persistence via scheduled tasks/jobs",
        severity_factor=1.8,
        keywords=["scheduled", "task", "schtask", "cron", "job", "at"],
        icon="⏰"
    ),
    AttackCategory(
        id="Other",
        name="Other Artifacts",
        description="Uncategorized forensic artifacts",
        severity_factor=0.8,
        keywords=[],
        icon="📦"
    ),
]

CATEGORY_MAP = {cat.id: cat for cat in ATTACK_CATEGORIES}

# Constants for configuration
MAX_ARTIFACTS_PER_CATEGORY = 100
TREEMAP_SCALE_FACTOR = 100
MIN_TREEMAP_VALUE = 1
MAX_SAMPLE_PATHS = 10
DEFAULT_CACHE_SIZE = 8


# =============================================================================
# ATTACK SURFACE NODE
# =============================================================================

@dataclass
class AttackSurfaceNode:
    """A node in the attack surface treemap."""
    category_id: str
    category: AttackCategory
    event_count: int = 0
    total_risk_score: float = 0.0  # Sum of risk scores for mean calculation
    max_risk: float = 0.0
    top_signal: str = ""           # Most significant artifact/indicator
    top_signal_score: float = 0.0
    sample_paths: List[str] = field(default_factory=list)
    
    @property
    def mean_risk(self) -> float:
        """Calculate mean anomaly/risk score."""
        if self.event_count == 0:
            return 0.0
        return self.total_risk_score / self.event_count
    
    @property
    def weighted_size(self) -> float:
        """
        Calculate weighted size for treemap rectangle.
        
        weight = log(count + 1) * severity_factor * (1 + anomaly_factor)
        """
        if self.event_count == 0:
            return 0
        
        log_count = math.log(self.event_count + 1)
        severity = self.category.severity_factor
        anomaly_factor = 1 + self.mean_risk  # Range: 1.0 to 2.0
        
        return log_count * severity * anomaly_factor
    
    def add_event(self, risk_score: float, signal_name: str = "", path: str = ""):
        """Add an event to this category."""
        self.event_count += 1
        self.total_risk_score += risk_score
        self.max_risk = max(self.max_risk, risk_score)
        
        # Track top signal (highest risk indicator)
        if risk_score > self.top_signal_score and signal_name:
            self.top_signal = signal_name
            self.top_signal_score = risk_score
        
        # Keep sample paths (limit to MAX_SAMPLE_PATHS)
        if path and len(self.sample_paths) < MAX_SAMPLE_PATHS:
            self.sample_paths.append(path)


# =============================================================================
# LEGACY TREEMAP NODE (for backwards compatibility)
# =============================================================================

@dataclass
class TreemapNode:
    """Legacy node for backwards compatibility."""
    label: str
    parent: str = ""
    event_count: int = 0
    bytes_touched: int = 0
    artifact_count: int = 0
    ml_risk: float = 0.0
    ueba_score: float = 0.0
    children: List[TreemapNode] = field(default_factory=list)

    def combined_risk(self) -> float:
        return max(self.ml_risk, self.ueba_score)


# =============================================================================
# JS BRIDGE
# =============================================================================

class _Bridge(QObject):
    """Bridge for JS -> Python events via QWebChannel."""
    
    actionReceived = pyqtSignal(str)
    
    @pyqtSlot(str)
    def handleAction(self, payload: str):
        self.actionReceived.emit(payload)


# =============================================================================
# ATTACK SURFACE MAP WIDGET
# =============================================================================

class AttackSurfaceMapWidget(QWidget):
    """
    Forensic Attack Surface Treemap Visualization.
    
    Shows where attacker activity is concentrated across evidence.
    Each rectangle = attack category, sized by weighted importance,
    colored by mean anomaly score.
    """
    
    # Signals for integration
    path_selected = pyqtSignal(str)
    timeline_requested = pyqtSignal(str)      # Filter timeline by category
    terminal_requested = pyqtSignal(str)      # Send command to terminal
    artifacts_requested = pyqtSignal(str)     # Show artifacts for category
    explain_requested = pyqtSignal(str)       # Explain risk for category
    audit_event = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.events_df: Optional[pd.DataFrame] = None
        self.attack_nodes: Dict[str, AttackSurfaceNode] = {}
        self.current_user: str = "analyst"
        self.session_id: Optional[str] = None
        self.web_view: Optional[Any] = None
        self.bridge: Optional[_Bridge] = None
        self.channel: Optional[Any] = None
        self.detail_panel: Optional[AttackSurfaceDetailPanel] = None
        self._data_hash: Optional[int] = None
        self._init_ui()
        
        # Set accessibility
        self.setAccessibleName("Attack Surface Map Visualization")
        self.setAccessibleDescription(
            "Interactive treemap showing attack surface concentration. "
            "Click categories to view details. Press Ctrl+R to refresh, Esc to close panels."
        )
    
    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Create splitter for map + detail panel
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background: #2d2d4a;
                width: 2px;
            }
        """)
        
        # Left side: Treemap visualization
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header bar
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: #1a1a2e;
                border-bottom: 1px solid #2d2d4a;
                padding: 8px;
            }
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 8, 12, 8)
        
        title = QLabel("🎯 Attack Surface Map")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #e0e0e0;")
        header_layout.addWidget(title)
        
        subtitle = QLabel("Where does the attacker's footprint concentrate?")
        subtitle.setStyleSheet("font-size: 11px; color: #888; margin-left: 12px;")
        header_layout.addWidget(subtitle)
        
        header_layout.addStretch()
        
        # Legend
        legend = QLabel()
        legend.setTextFormat(Qt.TextFormat.RichText)
        legend.setText(
            '<span style="color:#666666">■</span> Normal  '
            '<span style="color:#f59e0b">■</span> Suspicious  '
            '<span style="color:#ef4444">■</span> High Risk  '
            '<span style="color:#7f1d1d">■</span> Critical'
        )
        legend.setStyleSheet("font-size: 10px; color: #888;")
        header_layout.addWidget(legend)
        
        header_layout.addSpacing(16)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background: #2d2d4a;
                color: #e0e0e0;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background: #3d3d5a;
            }
        """)
        refresh_btn.clicked.connect(self._render)
        header_layout.addWidget(refresh_btn)
        
        left_layout.addWidget(header)
        
        # Insight summary bar
        self.insight_bar = QLabel("")
        self.insight_bar.setStyleSheet("""
            background: #0f1117;
            color: #4ade80;
            padding: 8px 16px;
            font-size: 12px;
            font-family: 'Consolas', monospace;
            border-bottom: 1px solid #1c2535;
        """)
        self.insight_bar.setWordWrap(True)
        left_layout.addWidget(self.insight_bar)
        
        # Web view for Plotly treemap
        if not WEB_ENGINE_AVAILABLE:
            fallback = QLabel("Qt WebEngine not available. Install PyQt6-WebEngine to view Attack Surface Map.")
            fallback.setAlignment(Qt.AlignmentFlag.AlignCenter)
            fallback.setStyleSheet("color: #888; padding: 40px;")
            left_layout.addWidget(fallback)
        else:
            self.web_view = QWebEngineView()
            left_layout.addWidget(self.web_view)
            
            self.bridge = _Bridge()
            self.bridge.actionReceived.connect(self._handle_js_action)
            
            self.channel = QWebChannel()
            self.channel.registerObject("fepdBridge", self.bridge)
            self.web_view.page().setWebChannel(self.channel)
        
        # Right side: Detail panel (initially hidden)
        self.detail_panel = AttackSurfaceDetailPanel()
        self.detail_panel.setVisible(False)
        
        # Connect detail panel signals
        self.detail_panel.navigate_to_files.connect(self.path_selected.emit)
        self.detail_panel.navigate_to_timeline.connect(self.timeline_requested.emit)
        self.detail_panel.navigate_to_ml.connect(self._on_ml_navigation)
        self.detail_panel.close_requested.connect(self._close_detail_panel)
        
        # Add widgets to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(self.detail_panel)
        
        # Set initial sizes (treemap takes 70%, detail panel 30%)
        splitter.setSizes([700, 300])
        
        layout.addWidget(splitter)
    
    # =========================================================================
    # PUBLIC API
    # =========================================================================
    
    def set_user(self, user: str) -> None:
        """Set current user for audit logging."""
        self.current_user = user or "analyst"
    
    def set_session_id(self, session_id: str) -> None:
        """Set session ID for audit tracking."""
        self.session_id = session_id
    
    def load_events(self, events_df: pd.DataFrame) -> None:
        """Load forensic events and categorize them."""
        # Validate data
        if not self._validate_dataframe(events_df):
            self.insight_bar.setText("⚠️ Invalid data format. Expected DataFrame with event_type or category column.")
            return
        
        # Show loading state
        self.insight_bar.setText(f"⏳ Processing {len(events_df):,} events...")
        self.insight_bar.setStyleSheet("""
            background: #1a2a3a;
            color: #fbbf24;
            padding: 8px 16px;
            font-size: 12px;
            font-family: 'Consolas', monospace;
            border-bottom: 1px solid #1c2535;
        """)
        
        # Force UI update
        if WEB_ENGINE_AVAILABLE:
            from PyQt6.QtWidgets import QApplication
            QApplication.processEvents()
        
        self.events_df = events_df
        self.attack_nodes = self._categorize_events(events_df)
        self._update_insight_summary()
        self._render()
        
        # Reset insight bar style
        self.insight_bar.setStyleSheet("""
            background: #0f1117;
            color: #4ade80;
            padding: 8px 16px;
            font-size: 12px;
            font-family: 'Consolas', monospace;
            border-bottom: 1px solid #1c2535;
        """)
    
    def load_tree(self, root: TreemapNode) -> None:
        """Load from legacy TreemapNode structure."""
        self.insight_bar.setText("⏳ Loading tree data...")
        self.attack_nodes = self._build_from_legacy(root)
        self._update_insight_summary()
        self._render()
    
    def load_tree_json(self, tree_json: Dict) -> None:
        """Load from pre-built tree JSON (legacy support)."""
        self.insight_bar.setText("⏳ Loading JSON data...")
        self.attack_nodes = self._build_from_json(tree_json)
        self._update_insight_summary()
        self._render()
    
    # =========================================================================
    # EVENT CATEGORIZATION
    # =========================================================================
    
    def _validate_dataframe(self, df: pd.DataFrame) -> bool:
        """Validate DataFrame has minimum required fields."""
        if df is None or df.empty:
            self.logger.warning("DataFrame is None or empty")
            return False
        
        # Check for at least one categorization field
        required_fields = ['event_type', 'type', 'category', 'artifact_type', 'source']
        has_required = any(col in df.columns for col in required_fields)
        
        if not has_required:
            self.logger.warning(f"DataFrame missing all categorization fields: {required_fields}")
            return False
        
        return True
    
    def _categorize_events(self, df: pd.DataFrame) -> Dict[str, AttackSurfaceNode]:
        """Categorize events into attack surface categories."""
        if df is None or df.empty:
            return self._sample_data()
        
        df = df.copy()
        
        # Initialize nodes for all categories
        nodes = {}
        for cat in ATTACK_CATEGORIES:
            nodes[cat.id] = AttackSurfaceNode(category_id=cat.id, category=cat)
        
        # Find relevant columns
        type_col = self._pick_column(df, ["event_type", "type", "category", "artifact_type", "source"])
        path_col = self._pick_column(df, ["file_path", "path", "artifact_path", "full_path", "name"])
        risk_col = self._pick_column(df, ["ml_risk", "risk_score", "anomaly_score", "score", "ml_score"])
        signal_col = self._pick_column(df, ["signal", "indicator", "name", "artifact", "description", "details"])
        
        for _, row in df.iterrows():
            # Determine category
            event_text = ""
            if type_col:
                event_text += str(row.get(type_col, "")).lower() + " "
            if path_col:
                event_text += str(row.get(path_col, "")).lower() + " "
            if signal_col:
                event_text += str(row.get(signal_col, "")).lower()
            
            category_id = self._classify_event(event_text)
            
            # Get risk score
            risk_score = 0.0
            if risk_col and pd.notna(row.get(risk_col)):
                try:
                    risk_score = float(row[risk_col])
                except (ValueError, TypeError):
                    risk_score = 0.0
            
            # Get signal name (most descriptive field)
            signal_name = ""
            if signal_col and pd.notna(row.get(signal_col)):
                signal_name = str(row[signal_col])[:50]  # Truncate
            elif path_col and pd.notna(row.get(path_col)):
                # Extract filename from path
                path_str = str(row[path_col])
                signal_name = path_str.split("/")[-1].split("\\")[-1][:50]
            
            # Get path for samples
            path = str(row.get(path_col, "")) if path_col else ""
            
            # Add to category
            nodes[category_id].add_event(risk_score, signal_name, path)
        
        return nodes
    
    def _classify_event(self, event_text: str) -> str:
        """Classify event text into an attack category."""
        event_lower = event_text.lower()
        
        for cat in ATTACK_CATEGORIES:
            if cat.id == "Other":
                continue  # Skip "Other" - it's the fallback
            
            for keyword in cat.keywords:
                if keyword in event_lower:
                    return cat.id
        
        return "Other"
    
    def _pick_column(self, df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
        """Pick the first available column from candidates."""
        for col in candidates:
            if col in df.columns:
                return col
        return None
    
    # =========================================================================
    # INSIGHT GENERATION
    # =========================================================================
    
    def keyPressEvent(self, event) -> None:
        """Handle keyboard shortcuts for accessibility."""
        if WEB_ENGINE_AVAILABLE:
            from PyQt6.QtCore import Qt
            
            if event.key() == Qt.Key.Key_R and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
                # Ctrl+R to refresh
                self._render()
                self.insight_bar.setText("🔄 Visualization refreshed")
            elif event.key() == Qt.Key.Key_E and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
                # Ctrl+E to export
                self._export_analysis()
            elif event.key() == Qt.Key.Key_Escape:
                # Esc to close detail panel
                self._close_detail_panel()
            else:
                super().keyPressEvent(event)
        else:
            super().keyPressEvent(event)
    
    def _update_insight_summary(self) -> None:
        """Generate forensic insight summary."""
        if not self.attack_nodes:
            self.insight_bar.setText(
                "📊 No attack surface data yet. "
                "💡 TIP: Load a case and run evidence processing to generate attack surface analysis. "
                "Press Ctrl+R to refresh."
            )
            return
        
        # Find top categories by weighted size
        sorted_nodes = sorted(
            [(k, v) for k, v in self.attack_nodes.items() if v.event_count > 0],
            key=lambda x: x[1].weighted_size,
            reverse=True
        )
        
        if not sorted_nodes:
            self.insight_bar.setText("📊 No significant activity detected.")
            return
        
        # Top 3 categories
        top_3 = sorted_nodes[:3]
        
        # Find highest risk category
        highest_risk = max(
            [(k, v) for k, v in self.attack_nodes.items() if v.event_count > 0],
            key=lambda x: x[1].mean_risk,
            default=(None, None)
        )
        
        # Build insight message
        top_names = [f"{CATEGORY_MAP[k].icon} {CATEGORY_MAP[k].name}" for k, v in top_3]
        
        insight = f"🎯 FOCUS AREAS: {', '.join(top_names)}"
        
        if highest_risk[1] and highest_risk[1].mean_risk > 0.5:
            cat = CATEGORY_MAP[highest_risk[0]]
            insight += f"  |  ⚠️ HIGHEST RISK: {cat.icon} {cat.name} (Avg: {highest_risk[1].mean_risk:.2f})"
            if highest_risk[1].top_signal:
                insight += f"  |  🔍 TOP SIGNAL: {highest_risk[1].top_signal}"
        
        self.insight_bar.setText(insight)
    
    # =========================================================================
    # RENDERING
    # =========================================================================
    
    def _render(self) -> None:
        """Render the attack surface treemap."""
        if not WEB_ENGINE_AVAILABLE:
            return
        
        # Clear previous content to prevent memory buildup
        if self.web_view:
            self.web_view.setHtml("")
        
        if not PLOTLY_AVAILABLE:
            html = "<h3 style='padding:24px; color:#888;'>Install plotly to render Attack Surface Map (pip install plotly)</h3>"
            self.web_view.setHtml(html)
            return
        
        if not self.attack_nodes:
            self.attack_nodes = self._sample_data()
        
        # Build treemap data
        labels, parents, values, colors, customdata = self._build_treemap_data()
        
        fig = go.Figure(go.Treemap(
            labels=labels,
            parents=parents,
            values=values,
            branchvalues="total",
            marker=dict(
                colors=colors,
                colorscale=[
                    [0.0, "#4a4a4a"],   # Gray - Normal
                    [0.3, "#666666"],   # Lighter gray
                    [0.5, "#f59e0b"],   # Orange - Suspicious
                    [0.7, "#ef4444"],   # Red - High Risk
                    [1.0, "#7f1d1d"],   # Dark Red - Critical
                ],
                cmin=0,
                cmax=1,
                line=dict(color="#1a1a2e", width=2),
            ),
            customdata=customdata,
            hovertemplate="%{customdata[4]}<extra></extra>",
            texttemplate="<b>%{customdata[0]}</b><br>%{customdata[1]} events<br>Avg Risk: %{customdata[2]:.2f}<br>%{customdata[3]}",
            textfont=dict(size=12, color="#ffffff"),
            textposition="middle center",
        ))
        
        fig.update_layout(
            margin=dict(l=4, r=4, t=4, b=4),
            paper_bgcolor="#0f1117",
            plot_bgcolor="#0f1117",
            font=dict(color="#e0e0e0"),
        )
        
        html_content = fig.to_html(
            full_html=False,
            include_plotlyjs="cdn",
            div_id="attack-surface-treemap"
        )
        
        html = self._wrap_html(html_content)
        self.web_view.setHtml(html)
    
    def _build_treemap_data(self):
        """Build data arrays for Plotly treemap."""
        labels = ["Attack Surface"]
        parents = [""]
        values = [0]  # Root value will be sum of children
        colors = [0.0]
        customdata = [["Attack Surface", 0, 0.0, "", "Attack Surface Overview", ""]]
        
        total_weighted = 0
        
        for cat_id, node in self.attack_nodes.items():
            if node.event_count == 0:
                continue
            
            cat = node.category
            weighted = node.weighted_size
            total_weighted += weighted
            
            labels.append(cat.name)
            parents.append("Attack Surface")
            values.append(max(MIN_TREEMAP_VALUE, int(weighted * TREEMAP_SCALE_FACTOR)))  # Scale for visibility
            colors.append(node.mean_risk)
            
            # Top signal display (forensic language)
            top_signal_text = ""
            if node.top_signal:
                top_signal_text = f"Top: {node.top_signal}"
            
            # Hover text with forensic details
            hover = (
                f"<b>{cat.icon} {cat.name}</b><br>"
                f"<br>"
                f"Events: {node.event_count:,}<br>"
                f"Avg Risk: {node.mean_risk:.2f}<br>"
                f"Max Risk: {node.max_risk:.2f}<br>"
                f"<br>"
                f"<i>{cat.description}</i>"
            )
            if node.top_signal:
                hover += f"<br><br>🔍 Top Signal: {node.top_signal}"
            
            customdata.append([
                f"{cat.icon} {cat.name}",
                node.event_count,
                node.mean_risk,
                top_signal_text,
                hover,
                cat_id,  # Index 5: category ID for click handling
            ])
        
        # Update root value
        values[0] = sum(values[1:]) if len(values) > 1 else 1
        
        return labels, parents, values, colors, customdata
    
    def _wrap_html(self, fig_html: str) -> str:
        """Wrap Plotly HTML with interactivity handlers."""
        return f"""
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<script src="qrc:///qtwebchannel/qwebchannel.js"></script>
<style>
body {{ 
    margin: 0; 
    background: #0f1117; 
    color: #e0e0e0;
    font-family: 'Inter', 'Segoe UI', sans-serif;
}}
#attack-surface-treemap {{ 
    height: calc(100vh - 10px); 
    width: 100%;
}}
#context-menu {{
    position: absolute;
    display: none;
    z-index: 100;
    background: #1a1a2e;
    border: 1px solid #2d2d4a;
    border-radius: 8px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.5);
    min-width: 200px;
    overflow: hidden;
}}
.menu-header {{
    padding: 12px 16px;
    background: #2d2d4a;
    font-weight: bold;
    border-bottom: 1px solid #3d3d5a;
}}
.menu-item {{
    padding: 10px 16px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 8px;
}}
.menu-item:hover {{
    background: #2d2d4a;
}}
.menu-item .icon {{
    width: 20px;
}}
</style>
</head>
<body>
{fig_html}
<div id="context-menu">
    <div class="menu-header" id="menu-title">Category</div>
    <div class="menu-item" data-action="timeline">
        <span class="icon">📅</span> Filter Timeline
    </div>
    <div class="menu-item" data-action="terminal">
        <span class="icon">💻</span> Show in Terminal
    </div>
    <div class="menu-item" data-action="artifacts">
        <span class="icon">🔍</span> View Artifacts
    </div>
    <div class="menu-item" data-action="explain">
        <span class="icon">💡</span> Explain Risk
    </div>
</div>
<script>
let fepdBridge = null;
let lastClickedCategory = null;

if (typeof qt !== 'undefined') {{
    new QWebChannel(qt.webChannelTransport, function(channel) {{
        fepdBridge = channel.objects.fepdBridge;
    }});
}}

function send(action, data) {{
    if (!fepdBridge) return;
    const payload = Object.assign({{}}, data || {{}}, {{action}});
    fepdBridge.handleAction(JSON.stringify(payload));
}}

const chart = document.getElementById('attack-surface-treemap');
const menu = document.getElementById('context-menu');

if (chart) {{
    // Click - select and show in terminal
    chart.on('plotly_click', function(evt) {{
        if (!evt.points || !evt.points[0]) return;
        const point = evt.points[0];
        if (point.customdata && point.customdata[5]) {{
            const categoryId = point.customdata[5];
            lastClickedCategory = categoryId;
            send('click', {{ category: categoryId, label: point.label }});
        }}
        hideMenu();
    }});
    
    // Double-click - filter timeline
    chart.on('plotly_doubleclick', function() {{
        if (lastClickedCategory) {{
            send('doubleclick', {{ category: lastClickedCategory }});
        }}
    }});
    
    // Right-click - context menu
    chart.addEventListener('contextmenu', function(evt) {{
        evt.preventDefault();
        if (lastClickedCategory) {{
            showMenu(evt);
        }}
    }});
}}

function showMenu(evt) {{
    const title = document.getElementById('menu-title');
    title.textContent = lastClickedCategory || 'Category';
    menu.style.left = evt.pageX + 'px';
    menu.style.top = evt.pageY + 'px';
    menu.style.display = 'block';
}}

function hideMenu() {{
    menu.style.display = 'none';
}}

document.addEventListener('click', function(evt) {{
    if (menu.contains(evt.target)) {{
        const action = evt.target.closest('.menu-item')?.dataset.action;
        if (action && lastClickedCategory) {{
            send('context', {{ category: lastClickedCategory, option: action }});
        }}
    }}
    hideMenu();
}});
</script>
</body>
</html>
"""
    
    # =========================================================================
    # JS ACTION HANDLING
    # =========================================================================
    
    def _handle_js_action(self, payload_json: str) -> None:
        """Handle actions from JavaScript bridge."""
        try:
            data = json.loads(payload_json)
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid payload from treemap bridge: {e}")
            # Show user feedback
            self.insight_bar.setText("⚠️ Visualization interaction failed. Please refresh.")
            self.insight_bar.setStyleSheet("""
                background: #3a1a1a;
                color: #ef4444;
                padding: 8px 16px;
                font-size: 12px;
                font-family: 'Consolas', monospace;
                border-bottom: 1px solid #1c2535;
            """)
            return
        
        action = data.get("action")
        category = data.get("category", "")
        
        # Enhanced audit logging
        node = self.attack_nodes.get(category)
        audit = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "category": category,
            "category_name": CATEGORY_MAP.get(category).name if category in CATEGORY_MAP else "Unknown",
            "event_count": node.event_count if node else 0,
            "mean_risk": node.mean_risk if node else 0.0,
            "max_risk": node.max_risk if node else 0.0,
            "user": self.current_user,
            "session_id": self.session_id,
            "source": "attack_surface_map",
        }
        self.audit_event.emit(audit)
        self.logger.info("Attack Surface event: %s", audit)
        
        if action == "click":
            # Visual feedback
            cat_name = CATEGORY_MAP.get(category).name if category in CATEGORY_MAP else category
            self.insight_bar.setText(f"📍 Selected: {cat_name}")
            self.insight_bar.setStyleSheet("""
                background: #1a3a1a;
                color: #4ade80;
                padding: 8px 16px;
                font-size: 12px;
                font-family: 'Consolas', monospace;
                border-bottom: 1px solid #1c2535;
            """)
            
            # Show detail panel with artifacts for this category
            self._show_category_details(category)
            # Also send terminal command
            cmd = f"context attack-surface {category}"
            self.terminal_requested.emit(cmd)
            self.path_selected.emit(category)
        
        elif action == "doubleclick":
            # Filter timeline by category
            self.timeline_requested.emit(category)
        
        elif action == "context":
            option = data.get("option")
            if option == "timeline":
                self.timeline_requested.emit(category)
            elif option == "terminal":
                cmd = f"artifacts --category {category}"
                self.terminal_requested.emit(cmd)
            elif option == "artifacts":
                self.artifacts_requested.emit(category)
            elif option == "explain":
                self.explain_requested.emit(category)
    
    def _export_analysis(self, format: str = "json") -> Optional[str]:
        """Export attack surface analysis to file."""
        try:
            data = {
                'timestamp': datetime.utcnow().isoformat(),
                'user': self.current_user,
                'session_id': self.session_id,
                'total_events': sum(node.event_count for node in self.attack_nodes.values()),
                'categories': {
                    cat_id: {
                        'name': node.category.name,
                        'icon': node.category.icon,
                        'description': node.category.description,
                        'event_count': node.event_count,
                        'mean_risk': node.mean_risk,
                        'max_risk': node.max_risk,
                        'top_signal': node.top_signal,
                        'top_signal_score': node.top_signal_score,
                        'weighted_size': node.weighted_size,
                        'severity_factor': node.category.severity_factor,
                    }
                    for cat_id, node in self.attack_nodes.items()
                    if node.event_count > 0
                }
            }
            
            export_json = json.dumps(data, indent=2)
            
            # Save to file
            if WEB_ENGINE_AVAILABLE:
                from PyQt6.QtWidgets import QFileDialog
                filename, _ = QFileDialog.getSaveFileName(
                    self,
                    "Export Attack Surface Analysis",
                    f"attack_surface_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    "JSON Files (*.json)"
                )
                if filename:
                    with open(filename, 'w') as f:
                        f.write(export_json)
                    self.insight_bar.setText(f"✅ Exported to {filename}")
                    self.logger.info(f"Attack surface exported to {filename}")
            
            return export_json
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            self.insight_bar.setText(f"❌ Export failed: {str(e)}")
            return None
    
    def _show_category_details(self, category_id: str) -> None:
        """Show detail panel with artifacts for the selected category."""
        if not self.detail_panel:
            return
        
        # Get node for this category
        node = self.attack_nodes.get(category_id)
        if not node:
            self.logger.warning(f"No node found for category: {category_id}")
            return
        
        # Build artifacts list from events dataframe
        artifacts = self._get_artifacts_for_category(category_id)
        
        # Determine risk level
        mean_risk = node.mean_risk
        if mean_risk >= 0.8:
            risk_level = "Critical"
        elif mean_risk >= 0.6:
            risk_level = "High"
        elif mean_risk >= 0.4:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        # Load into detail panel
        self.detail_panel.load_category(
            category_id=category_id,
            category_name=node.category.name,
            artifacts=artifacts,
            risk_level=risk_level
        )
        
        # Show panel
        self.detail_panel.setVisible(True)
    
    def _get_artifacts_for_category(self, category_id: str) -> List[Dict]:
        """Extract artifacts from events dataframe for a specific category."""
        artifacts = []
        
        if self.events_df is None or self.events_df.empty:
            # Generate sample artifacts for demonstration
            return self._generate_sample_artifacts(category_id)
        
        # Filter events by category
        cat = CATEGORY_MAP.get(category_id)
        if not cat:
            return artifacts
        
        df = self.events_df.copy()
        
        # Try to detect categorization column
        cat_col = None
        for col in ['event_type', 'type', 'category', 'artifact_type']:
            if col in df.columns:
                cat_col = col
                break
        
        if cat_col:
            # Filter by category keywords
            mask = df[cat_col].str.lower().str.contains('|'.join(cat.keywords), na=False, regex=True)
            df = df[mask]
        
        # Extract artifact information
        for _, row in df.head(MAX_ARTIFACTS_PER_CATEGORY).iterrows():  # Limit to prevent UI overload
            artifact = {}
            
            # Name
            artifact['name'] = self._extract_field(row, df.columns, 
                ['name', 'artifact_name', 'file_name', 'process_name'], 'Unknown')
            
            # Path (VEOS path only)
            artifact['path'] = self._extract_field(row, df.columns,
                ['path', 'file_path', 'evidence_path', 'artifact_path'], '')
            
            # Modified timestamp
            for col in ['modified', 'timestamp', 'created', 'last_modified']:
                if col in df.columns and pd.notna(row.get(col)):
                    artifact['modified'] = row[col]
                    break
            else:
                artifact['modified'] = ''
            
            # Size
            for col in ['size', 'file_size', 'bytes']:
                if col in df.columns and pd.notna(row.get(col)):
                    try:
                        artifact['size'] = int(row[col])
                    except (ValueError, TypeError):
                        artifact['size'] = 0
                    break
            else:
                artifact['size'] = 0
            
            # Anomaly score
            for col in ['anomaly_score', 'risk_score', 'ml_score', 'score']:
                if col in df.columns and pd.notna(row.get(col)):
                    try:
                        artifact['anomaly_score'] = float(row[col])
                    except (ValueError, TypeError):
                        artifact['anomaly_score'] = 0.0
                    break
            else:
                artifact['anomaly_score'] = 0.0
            
            # Severity
            score = artifact['anomaly_score']
            if score >= 0.8:
                artifact['severity'] = 'Critical'
            elif score >= 0.6:
                artifact['severity'] = 'High'
            elif score >= 0.4:
                artifact['severity'] = 'Medium'
            else:
                artifact['severity'] = 'Low'
            
            artifacts.append(artifact)
        
        return artifacts if artifacts else self._generate_sample_artifacts(category_id)
    
    def _extract_field(self, row, columns, field_candidates: List[str], default: str = '') -> str:
        """Extract field from row using candidate column names."""
        for col in field_candidates:
            if col in columns and pd.notna(row.get(col)):
                return str(row[col])
        return default
    
    def _generate_sample_artifacts(self, category_id: str) -> List[Dict]:
        """Generate sample artifacts for demonstration."""
        from datetime import datetime, timedelta
        
        samples = {
            'ProcessExecution': [
                ('powershell.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 445952, 0.89, 'High'),
                ('cmd.exe', 'C:\\Windows\\System32\\cmd.exe', 289792, 0.32, 'Low'),
                ('evil.exe', 'C:\\Temp\\evil.exe', 102400, 0.95, 'Critical'),
                ('rundll32.exe', 'C:\\Windows\\System32\\rundll32.exe', 51712, 0.76, 'High'),
            ],
            'RegistryPersistence': [
                ('Run\\Backdoor', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 124, 0.91, 'Critical'),
                ('Services\\Malware', 'HKLM\\System\\CurrentControlSet\\Services\\Malware', 212, 0.88, 'High'),
                ('RunOnce\\Update', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 96, 0.45, 'Medium'),
            ],
            'FileDropped': [
                ('payload.exe', 'C:\\Users\\Public\\payload.exe', 524288, 0.87, 'High'),
                ('config.dat', 'C:\\Users\\Admin\\AppData\\Local\\Temp\\config.dat', 2048, 0.62, 'Medium'),
                ('malware.dll', 'C:\\Windows\\System32\\malware.dll', 98304, 0.94, 'Critical'),
            ],
            'NetworkActivity': [
                ('C2 Connection', '185.142.x.x:443', 0, 0.93, 'Critical'),
                ('DNS Query', 'malicious-domain.com', 0, 0.78, 'High'),
                ('HTTP Request', 'http://phishing-site.net', 0, 0.56, 'Medium'),
            ],
        }
        
        category_samples = samples.get(category_id, [
            ('Unknown', 'Unknown Path', 0, 0.5, 'Medium')
        ])
        
        artifacts = []
        base_time = datetime.now()
        
        for idx, (name, path, size, score, severity) in enumerate(category_samples):
            artifacts.append({
                'name': name,
                'path': path,
                'modified': base_time - timedelta(hours=idx),
                'size': size,
                'anomaly_score': score,
                'severity': severity
            })
        
        return artifacts
    
    def _close_detail_panel(self) -> None:
        """Hide the detail panel."""
        if self.detail_panel:
            self.detail_panel.setVisible(False)
            # Reset insight bar
            self._update_insight_summary()
    
    def _on_ml_navigation(self, category: str) -> None:
        """Handle navigation to ML Analytics tab."""
        # Emit signal that parent can connect to navigate tabs
        self.explain_requested.emit(category)
    
    # =========================================================================
    # LEGACY SUPPORT
    # =========================================================================
    
    def _build_from_legacy(self, root: TreemapNode) -> Dict[str, AttackSurfaceNode]:
        """Build attack nodes from legacy TreemapNode structure."""
        nodes = {}
        for cat in ATTACK_CATEGORIES:
            nodes[cat.id] = AttackSurfaceNode(category_id=cat.id, category=cat)
        
        def process_node(node: TreemapNode):
            label = node.label.lower()
            event_count = node.event_count or 1
            risk = node.combined_risk()
            
            # Classify based on label
            category_id = self._classify_event(label)
            
            for _ in range(event_count):
                nodes[category_id].add_event(risk, node.label)
            
            for child in node.children:
                process_node(child)
        
        process_node(root)
        return nodes
    
    def _build_from_json(self, tree_json: Dict) -> Dict[str, AttackSurfaceNode]:
        """Build attack nodes from legacy JSON format."""
        # Convert old tree format to new category-based format
        nodes = {}
        for cat in ATTACK_CATEGORIES:
            nodes[cat.id] = AttackSurfaceNode(category_id=cat.id, category=cat)
        
        def process_node(data: Dict):
            label = data.get("label", "").lower()
            event_count = data.get("event_count", 0) or 1
            ml_risk = data.get("ml_risk", 0.0)
            ueba_score = data.get("ueba_score", 0.0)
            risk = max(ml_risk, ueba_score)
            
            # Classify based on label
            category_id = self._classify_event(label)
            
            for _ in range(event_count):
                nodes[category_id].add_event(risk, label)
            
            for child in data.get("children", []):
                process_node(child)
        
        process_node(tree_json)
        return nodes
    
    # =========================================================================
    # SAMPLE DATA
    # =========================================================================
    
    def _sample_data(self) -> Dict[str, AttackSurfaceNode]:
        """Generate sample data for demonstration."""
        nodes = {}
        
        # Sample data representing a typical investigation
        sample_categories = [
            ("ProcessExecution", 161, 0.72, "powershell.exe"),
            ("RegistryPersistence", 23, 0.85, "Run\\Backdoor"),
            ("RegistryModified", 89, 0.45, "Services\\Malware"),
            ("FileDropped", 47, 0.68, "payload.exe"),
            ("NetworkActivity", 312, 0.78, "185.142.x.x:443"),
            ("BrowserArtifact", 1205, 0.31, "phishing-site.com"),
            ("WindowsEvent", 36300, 0.12, "Security.evtx"),
            ("MemoryArtifact", 8, 0.91, "Injected DLL"),
            ("Authentication", 156, 0.55, "Failed Logon 4625"),
            ("ScheduledTask", 12, 0.82, "UpdateTask"),
        ]
        
        for cat_id, count, avg_risk, top_signal in sample_categories:
            cat = CATEGORY_MAP.get(cat_id)
            if not cat:
                continue
            
            node = AttackSurfaceNode(category_id=cat_id, category=cat)
            for i in range(count):
                # Distribute risk scores around average
                risk = min(1.0, max(0.0, avg_risk + (i % 5 - 2) * 0.05))
                signal = top_signal if i == 0 else ""
                node.add_event(risk, signal)
            
            nodes[cat_id] = node
        
        return nodes
