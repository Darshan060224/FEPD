"""
FEPD - Timeline Tab
Interactive timeline visualization with multi-category events, zoom/pan, heatmap, and drill-down

Features:
- Multi-category horizontal timeline chart
- Time-range controls (zoom/pan)
- Artifact category filters
- Heatmap with drill-down to individual events
- Event detail/preview pane
- Linked filtering with global filters
- Export timeline data
"""

import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QSlider, QGroupBox, QTextEdit, QSplitter,
    QCheckBox, QScrollArea, QFrame, QDateEdit, QSpinBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QDate, QRectF, QPointF
from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QFont


class TimelineChart(QWidget):
    """
    Custom timeline chart widget with interactive features.
    """
    
    event_clicked = pyqtSignal(dict)  # Emits clicked event data
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        
        self._events = []  # All timeline events
        self._visible_events = []  # Events in current time range
        self._categories = set()  # Unique categories
        self._visible_categories = set()  # Currently visible categories
        
        # Time range
        self._min_time = None
        self._max_time = None
        self._view_start = None
        self._view_end = None
        
        # Zoom level (1.0 = full range, higher = more zoomed in)
        self._zoom_level = 1.0
        
        # Heatmap settings
        self._heatmap_threshold = 50  # Events per pixel to show heatmap
        self._show_heatmap = True
        
        # Time jump indicators
        self.time_jumps = []  # List of time gap dicts
        
        # Colors for categories
        self._category_colors = {
            'Media': QColor(52, 152, 219),       # Blue
            'Email': QColor(46, 204, 113),       # Green
            'Web': QColor(155, 89, 182),         # Purple
            'File System': QColor(241, 196, 15), # Yellow
            'Registry': QColor(231, 76, 60),     # Red
            'Chat': QColor(26, 188, 156),        # Teal
            'Documents': QColor(230, 126, 34),   # Orange
        }
        
        self.setMinimumHeight(400)
        self.setMouseTracking(True)
        
        # For dragging/panning
        self._dragging = False
        self._drag_start_x = 0
        self._drag_start_view = None
    
    def load_events(self, events: List[Dict[str, Any]]):
        """
        Load timeline events.
        
        Each event should have:
        - timestamp: datetime
        - category: str
        - name: str
        - description: str (optional)
        """
        self._events = sorted(events, key=lambda e: e['timestamp'])
        
        if not self._events:
            return
        
        # Calculate time range
        self._min_time = self._events[0]['timestamp']
        self._max_time = self._events[-1]['timestamp']
        self._view_start = self._min_time
        self._view_end = self._max_time
        
        # Extract categories
        self._categories = set(e['category'] for e in self._events)
        self._visible_categories = self._categories.copy()
        
        self._update_visible_events()
        self.update()
    
    def set_visible_categories(self, categories: set):
        """Set which categories are visible."""
        self._visible_categories = categories
        self._update_visible_events()
        self.update()
    
    def zoom_in(self):
        """Zoom in to the timeline."""
        self._zoom_level *= 1.5
        self._apply_zoom()
    
    def zoom_out(self):
        """Zoom out from the timeline."""
        self._zoom_level = max(1.0, self._zoom_level / 1.5)
        self._apply_zoom()
    
    def _apply_zoom(self):
        """Apply current zoom level."""
        if not self._min_time or not self._max_time:
            return
        
        # Calculate new view range centered on current view
        total_seconds = (self._max_time - self._min_time).total_seconds()
        view_seconds = total_seconds / self._zoom_level
        
        # Center on middle of current view
        if self._view_start is None or self._view_end is None or self._min_time is None:
            return
        current_center = self._view_start + (self._view_end - self._view_start) / 2
        center_offset = (current_center - self._min_time).total_seconds()
        
        # New range
        start_offset = max(0, center_offset - view_seconds / 2)
        end_offset = min(total_seconds, start_offset + view_seconds)
        
        self._view_start = self._min_time + timedelta(seconds=start_offset)
        self._view_end = self._min_time + timedelta(seconds=end_offset)
        
        self._update_visible_events()
        self.update()
    
    def _update_visible_events(self):
        """Update the list of visible events based on time range and category filters."""
        if not self._view_start or not self._view_end:
            self._visible_events = []
            return
        
        self._visible_events = [
            e for e in self._events
            if self._view_start <= e['timestamp'] <= self._view_end
            and e['category'] in self._visible_categories
        ]
    
    def paintEvent(self, event):
        """Paint the timeline."""
        if not self._visible_events:
            # No data
            painter = QPainter(self)
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No timeline data available")
            return
        
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw background
        painter.fillRect(self.rect(), QColor(30, 30, 30))
        
        # Draw timeline
        self._draw_timeline(painter)
    
    def _draw_timeline(self, painter: QPainter):
        """Draw the timeline chart."""
        width = self.width()
        height = self.height()
        
        margin_top = 50
        margin_bottom = 50
        margin_left = 80
        margin_right = 20
        
        chart_height = height - margin_top - margin_bottom
        chart_width = width - margin_left - margin_right
        
        # Draw time axis
        painter.setPen(QPen(QColor(200, 200, 200), 2))
        painter.drawLine(margin_left, height - margin_bottom, 
                        width - margin_right, height - margin_bottom)
        
        # Draw category rows
        categories = sorted(self._visible_categories)
        if not categories:
            return
        
        row_height = chart_height / len(categories)
        
        # Draw category labels and rows
        for i, category in enumerate(categories):
            y = margin_top + i * row_height
            
            # Category label
            painter.setPen(QPen(QColor(200, 200, 200)))
            painter.setFont(QFont("Arial", 10, QFont.Weight.Bold))
            painter.drawText(QRectF(0, y, margin_left - 10, row_height),
                           Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                           category)
            
            # Row separator
            painter.setPen(QPen(QColor(60, 60, 60), 1))
            painter.drawLine(margin_left, int(y + row_height), 
                           width - margin_right, int(y + row_height))
        
        # Calculate events per pixel for heatmap decision
        if self._view_start is None or self._view_end is None:
            return
        time_range = (self._view_end - self._view_start).total_seconds()
        if time_range == 0:
            return
        
        # Group events by category and time bucket
        category_events = {cat: [] for cat in categories}
        for event in self._visible_events:
            if event['category'] in category_events:
                category_events[event['category']].append(event)
        
        # Draw events for each category
        for i, category in enumerate(categories):
            y = margin_top + i * row_height
            cat_events = category_events[category]
            
            if not cat_events:
                continue
            
            # Decide: heatmap or individual dots?
            events_per_pixel = len(cat_events) / chart_width
            
            if events_per_pixel > 0.5 and self._show_heatmap:
                # Draw heatmap
                self._draw_heatmap(painter, cat_events, margin_left, y, 
                                 chart_width, row_height, time_range)
            else:
                # Draw individual dots
                self._draw_event_dots(painter, cat_events, margin_left, y,
                                    chart_width, row_height, time_range, category)
        
        # Draw time labels
        self._draw_time_labels(painter, margin_left, height - margin_bottom + 10,
                              chart_width, time_range)
        
        # Draw time jump indicators
        if hasattr(self, 'time_jumps') and self.time_jumps:
            self._draw_time_jumps(painter, margin_left, margin_top, 
                                chart_width, chart_height, time_range)
    
    def _draw_heatmap(self, painter: QPainter, events: List[Dict], 
                      x_offset: int, y_offset: float, width: int, height: float,
                      time_range: float):
        """Draw heatmap for dense event areas."""
        # Divide into buckets
        bucket_count = max(10, width // 5)
        bucket_width = width / bucket_count
        bucket_events = [0] * bucket_count
        
        # Count events per bucket
        for event in events:
            offset = (event['timestamp'] - self._view_start).total_seconds()
            bucket_index = int((offset / time_range) * bucket_count)
            bucket_index = min(bucket_count - 1, max(0, bucket_index))
            bucket_events[bucket_index] += 1
        
        max_count = max(bucket_events) if bucket_events else 1
        
        # Draw buckets
        for i, count in enumerate(bucket_events):
            if count == 0:
                continue
            
            # Intensity based on count
            intensity = min(255, int(255 * (count / max_count)))
            color = QColor(intensity, 0, 0, 150)
            
            x = x_offset + i * bucket_width
            painter.fillRect(QRectF(x, y_offset + 5, bucket_width, height - 10), color)
    
    def _draw_event_dots(self, painter: QPainter, events: List[Dict],
                        x_offset: int, y_offset: float, width: int, height: float,
                        time_range: float, category: str):
        """Draw individual event dots."""
        color = self._category_colors.get(category, QColor(128, 128, 128))
        painter.setBrush(QBrush(color))
        painter.setPen(QPen(color.darker(120), 1))
        
        dot_radius = 4
        center_y = y_offset + height / 2
        
        for event in events:
            offset = (event['timestamp'] - self._view_start).total_seconds()
            x = x_offset + (offset / time_range) * width
            
            painter.drawEllipse(QPointF(x, center_y), dot_radius, dot_radius)
    
    def _draw_time_labels(self, painter: QPainter, x_offset: int, y: int,
                         width: int, time_range: float):
        """Draw time axis labels."""
        painter.setPen(QPen(QColor(200, 200, 200)))
        painter.setFont(QFont("Arial", 9))
        
        # Draw 5-7 time labels
        if self._view_start is None:
            return
        label_count = 6
        for i in range(label_count + 1):
            offset = (i / label_count) * time_range
            time = self._view_start + timedelta(seconds=offset)
            x = x_offset + (i / label_count) * width
            
            # Format time based on range
            if time_range > 86400 * 365:  # > 1 year
                label = time.strftime("%Y-%m")
            elif time_range > 86400 * 30:  # > 1 month
                label = time.strftime("%Y-%m-%d")
            elif time_range > 86400:  # > 1 day
                label = time.strftime("%m-%d %H:%M")
            else:
                label = time.strftime("%H:%M:%S")
            
            painter.drawText(QRectF(x - 50, y, 100, 30),
                           Qt.AlignmentFlag.AlignCenter,
                           label)
    
    def _draw_time_jumps(self, painter: QPainter, x_offset: int, y_offset: int,
                        width: int, height: int, time_range: float):
        """Draw visual indicators for time gaps."""
        painter.setPen(QPen(QColor(255, 165, 0), 3, Qt.PenStyle.DashLine))  # Orange dashed line
        
        for jump in self.time_jumps:
            # Check if jump is visible in current view
            if not (self._view_start <= jump['from'] <= self._view_end or
                   self._view_start <= jump['to'] <= self._view_end):
                continue
            
            # Calculate position of gap start
            offset_from = (jump['from'] - self._view_start).total_seconds()
            x_from = x_offset + (offset_from / time_range) * width
            
            # Draw vertical line at gap start
            painter.drawLine(int(x_from), y_offset, int(x_from), y_offset + height)
            
            # Draw warning icon/text
            painter.setFont(QFont("Arial", 10, QFont.Weight.Bold))
            painter.setPen(QPen(QColor(255, 165, 0)))
            gap_text = f"⚠️ {jump['gap_days']:.1f}d gap"
            painter.drawText(QRectF(x_from - 40, y_offset - 20, 80, 15),
                           Qt.AlignmentFlag.AlignCenter,
                           gap_text)
    
    def mousePressEvent(self, event):
        """Handle mouse press for dragging."""
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = True
            self._drag_start_x = event.pos().x()
            self._drag_start_view = (self._view_start, self._view_end)
    
    def mouseMoveEvent(self, event):
        """Handle mouse move for panning."""
        if self._dragging and self._drag_start_view:
            if self._drag_start_view[0] is None or self._drag_start_view[1] is None:
                return
            dx = event.pos().x() - self._drag_start_x
            width = self.width() - 100  # Account for margins
            
            time_range = (self._drag_start_view[1] - self._drag_start_view[0]).total_seconds()
            time_shift = -(dx / width) * time_range
            
            self._view_start = self._drag_start_view[0] + timedelta(seconds=time_shift)
            self._view_end = self._drag_start_view[1] + timedelta(seconds=time_shift)
            
            # Clamp to valid range
            if self._view_start < self._min_time:
                diff = self._min_time - self._view_start
                self._view_start += diff
                self._view_end += diff
            if self._view_end > self._max_time:
                diff = self._view_end - self._max_time
                self._view_start -= diff
                self._view_end -= diff
            
            self._update_visible_events()
            self.update()
    
    def mouseReleaseEvent(self, event):
        """Handle mouse release."""
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = False
    
    def wheelEvent(self, event):
        """Handle mouse wheel for zooming."""
        if event.angleDelta().y() > 0:
            self.zoom_in()
        else:
            self.zoom_out()


class TimelineTab(QWidget):
    """
    Complete timeline tab with controls and visualization.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Controls panel
        controls = self._create_controls()
        layout.addWidget(controls)
        
        # Splitter: Timeline | Event Detail
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Timeline chart
        chart_container = QGroupBox("📊 Timeline Visualization")
        chart_layout = QVBoxLayout()
        
        self.timeline_chart = TimelineChart()
        self.timeline_chart.event_clicked.connect(self._on_event_clicked)
        chart_layout.addWidget(self.timeline_chart)
        
        chart_container.setLayout(chart_layout)
        splitter.addWidget(chart_container)
        
        # Event detail pane
        detail_pane = self._create_detail_pane()
        splitter.addWidget(detail_pane)
        
        splitter.setSizes([600, 200])
        layout.addWidget(splitter)
    
    def _create_controls(self) -> QGroupBox:
        """Create timeline controls panel."""
        controls = QGroupBox("Timeline Controls")
        layout = QVBoxLayout()
        
        # Row 1: Category filters
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("<b>Select Artifact Categories:</b>"))
        row1.addStretch()
        
        btn_select_all_cats = QPushButton("✓ All")
        btn_select_all_cats.clicked.connect(self._select_all_categories)
        row1.addWidget(btn_select_all_cats)
        
        btn_deselect_all_cats = QPushButton("✗ None")
        btn_deselect_all_cats.clicked.connect(self._deselect_all_categories)
        row1.addWidget(btn_deselect_all_cats)
        
        layout.addLayout(row1)
        
        # Category checkboxes
        cats_layout = QHBoxLayout()
        
        self.cat_checkboxes = {}
        categories = ['Media', 'Email', 'Web', 'File System', 'Registry', 'Chat', 'Documents']
        
        for cat in categories:
            chk = QCheckBox(cat)
            chk.setChecked(True)
            chk.toggled.connect(self._on_category_toggled)
            self.cat_checkboxes[cat] = chk
            cats_layout.addWidget(chk)
        
        cats_layout.addStretch()
        layout.addLayout(cats_layout)
        
        # NEW: Advanced Time Filters
        advanced_filters = self._create_advanced_filters()
        layout.addWidget(advanced_filters)
        
        # Row 2: Zoom and export
        row2 = QHBoxLayout()
        
        row2.addWidget(QLabel("<b>Zoom:</b>"))
        
        btn_zoom_in = QPushButton("🔍 Zoom In")
        btn_zoom_in.clicked.connect(self.timeline_chart.zoom_in)
        row2.addWidget(btn_zoom_in)
        
        btn_zoom_out = QPushButton("🔍 Zoom Out")
        btn_zoom_out.clicked.connect(self.timeline_chart.zoom_out)
        row2.addWidget(btn_zoom_out)
        
        btn_reset_zoom = QPushButton("🔄 Reset View")
        btn_reset_zoom.clicked.connect(self._reset_timeline)
        row2.addWidget(btn_reset_zoom)
        
        row2.addStretch()
        
        btn_export = QPushButton("📤 Export Timeline...")
        btn_export.clicked.connect(self._export_timeline)
        row2.addWidget(btn_export)
        
        layout.addLayout(row2)
        
        # Info label
        self.lbl_timeline_info = QLabel("No timeline data loaded")
        self.lbl_timeline_info.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(self.lbl_timeline_info)
        
        controls.setLayout(layout)
        return controls
    
    def _create_detail_pane(self) -> QGroupBox:
        """Create event detail pane."""
        detail = QGroupBox("📋 Event Details")
        layout = QVBoxLayout()
        
        self.txt_event_detail = QTextEdit()
        self.txt_event_detail.setReadOnly(True)
        self.txt_event_detail.setPlaceholderText("Click on an event to see details...")
        layout.addWidget(self.txt_event_detail)
        
        detail.setLayout(layout)
        return detail
    
    def _create_advanced_filters(self) -> QGroupBox:
        """Create advanced time filtering controls."""
        filters = QGroupBox("🔍 Advanced Time Filters")
        layout = QVBoxLayout()
        
        # Date range filter
        date_row = QHBoxLayout()
        date_row.addWidget(QLabel("<b>Date Range:</b>"))
        
        self.date_start = QDateEdit()
        self.date_start.setCalendarPopup(True)
        self.date_start.setDisplayFormat("yyyy-MM-dd")
        self.date_start.setDate(QDate.currentDate().addYears(-1))
        self.date_start.dateChanged.connect(self._apply_advanced_filters)
        date_row.addWidget(QLabel("From:"))
        date_row.addWidget(self.date_start)
        
        self.date_end = QDateEdit()
        self.date_end.setCalendarPopup(True)
        self.date_end.setDisplayFormat("yyyy-MM-dd")
        self.date_end.setDate(QDate.currentDate())
        self.date_end.dateChanged.connect(self._apply_advanced_filters)
        date_row.addWidget(QLabel("To:"))
        date_row.addWidget(self.date_end)
        
        self.chk_date_filter = QCheckBox("Enable Date Filter")
        self.chk_date_filter.toggled.connect(self._apply_advanced_filters)
        date_row.addWidget(self.chk_date_filter)
        
        date_row.addStretch()
        layout.addLayout(date_row)
        
        # Time of day filter
        time_row = QHBoxLayout()
        time_row.addWidget(QLabel("<b>Time of Day:</b>"))
        
        self.time_start_hour = QSpinBox()
        self.time_start_hour.setRange(0, 23)
        self.time_start_hour.setValue(0)
        self.time_start_hour.setSuffix(":00")
        self.time_start_hour.valueChanged.connect(self._apply_advanced_filters)
        time_row.addWidget(QLabel("From:"))
        time_row.addWidget(self.time_start_hour)
        
        self.time_end_hour = QSpinBox()
        self.time_end_hour.setRange(0, 23)
        self.time_end_hour.setValue(23)
        self.time_end_hour.setSuffix(":00")
        self.time_end_hour.valueChanged.connect(self._apply_advanced_filters)
        time_row.addWidget(QLabel("To:"))
        time_row.addWidget(self.time_end_hour)
        
        self.chk_time_filter = QCheckBox("Enable Time Filter")
        self.chk_time_filter.toggled.connect(self._apply_advanced_filters)
        time_row.addWidget(self.chk_time_filter)
        
        time_row.addStretch()
        layout.addLayout(time_row)
        
        # Weekday filter
        weekday_row = QHBoxLayout()
        weekday_row.addWidget(QLabel("<b>Weekdays:</b>"))
        
        self.weekday_checkboxes = {}
        weekdays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        for day in weekdays:
            chk = QCheckBox(day)
            chk.setChecked(True)
            chk.toggled.connect(self._apply_advanced_filters)
            self.weekday_checkboxes[day] = chk
            weekday_row.addWidget(chk)
        
        self.chk_weekday_filter = QCheckBox("Enable Weekday Filter")
        self.chk_weekday_filter.toggled.connect(self._apply_advanced_filters)
        weekday_row.addWidget(self.chk_weekday_filter)
        
        weekday_row.addStretch()
        layout.addLayout(weekday_row)
        
        # Time jump detection
        jump_row = QHBoxLayout()
        jump_row.addWidget(QLabel("<b>Time Gaps:</b>"))
        
        self.chk_show_time_jumps = QCheckBox("Highlight gaps >")
        self.chk_show_time_jumps.setChecked(True)
        self.chk_show_time_jumps.toggled.connect(self._on_time_jump_toggle)
        jump_row.addWidget(self.chk_show_time_jumps)
        
        self.spin_time_jump_threshold = QSpinBox()
        self.spin_time_jump_threshold.setRange(1, 365)
        self.spin_time_jump_threshold.setValue(1)
        self.spin_time_jump_threshold.setSuffix(" day(s)")
        self.spin_time_jump_threshold.valueChanged.connect(self._on_time_jump_threshold_changed)
        jump_row.addWidget(self.spin_time_jump_threshold)
        
        jump_row.addStretch()
        
        # Filter presets
        jump_row.addWidget(QLabel("<b>Presets:</b>"))
        
        btn_business_hours = QPushButton("Business Hours")
        btn_business_hours.setToolTip("Mon-Fri, 9:00-17:00")
        btn_business_hours.clicked.connect(self._preset_business_hours)
        jump_row.addWidget(btn_business_hours)
        
        btn_off_hours = QPushButton("Off-Hours")
        btn_off_hours.setToolTip("Weekdays 18:00-08:00 + Weekends")
        btn_off_hours.clicked.connect(self._preset_off_hours)
        jump_row.addWidget(btn_off_hours)
        
        btn_weekends = QPushButton("Weekends Only")
        btn_weekends.clicked.connect(self._preset_weekends)
        jump_row.addWidget(btn_weekends)
        
        btn_clear_filters = QPushButton("🔄 Clear All Filters")
        btn_clear_filters.clicked.connect(self._clear_all_filters)
        jump_row.addWidget(btn_clear_filters)
        
        layout.addLayout(jump_row)
        
        # Filter status
        self.lbl_filter_status = QLabel("No filters active")
        self.lbl_filter_status.setStyleSheet("color: #4CAF50; font-size: 10px; font-style: italic;")
        layout.addWidget(self.lbl_filter_status)
        
        filters.setLayout(layout)
        return filters
    
    def _on_category_toggled(self, checked: bool):
        """Handle category checkbox toggle."""
        visible_cats = {
            cat for cat, chk in self.cat_checkboxes.items()
            if chk.isChecked()
        }
        self.timeline_chart.set_visible_categories(visible_cats)
    
    def _select_all_categories(self):
        """Select all category checkboxes."""
        for chk in self.cat_checkboxes.values():
            chk.setChecked(True)
    
    def _deselect_all_categories(self):
        """Deselect all category checkboxes."""
        for chk in self.cat_checkboxes.values():
            chk.setChecked(False)
    
    def _reset_timeline(self):
        """Reset timeline to full view."""
        self.timeline_chart._zoom_level = 1.0
        self.timeline_chart._view_start = self.timeline_chart._min_time
        self.timeline_chart._view_end = self.timeline_chart._max_time
        self.timeline_chart._update_visible_events()
        self.timeline_chart.update()
    
    def _on_event_clicked(self, event_data: Dict[str, Any]):
        """Handle event click."""
        detail_text = f"""
<b>Event Details</b><br>
<hr>
<b>Time:</b> {event_data.get('timestamp', 'Unknown')}<br>
<b>Category:</b> {event_data.get('category', 'Unknown')}<br>
<b>Name:</b> {event_data.get('name', 'Unknown')}<br>
<b>Description:</b> {event_data.get('description', 'N/A')}<br>
        """
        self.txt_event_detail.setHtml(detail_text)
    
    def _export_timeline(self):
        """Export timeline data to CSV."""
        # TODO: Implement export
        self.logger.info("Export timeline requested")
    
    def _apply_advanced_filters(self):
        """Apply advanced time filters to timeline events."""
        if not hasattr(self, 'all_events') or not self.all_events:
            return
        
        filtered_events = self.all_events.copy()
        active_filters = []
        
        # Date range filter
        if hasattr(self, 'chk_date_filter') and self.chk_date_filter.isChecked():
            start_date = self.date_start.date().toPyDate()
            end_date = self.date_end.date().toPyDate()
            
            filtered_events = [
                e for e in filtered_events
                if start_date <= e['timestamp'].date() <= end_date
            ]
            active_filters.append(f"Date: {start_date} to {end_date}")
        
        # Time of day filter
        if hasattr(self, 'chk_time_filter') and self.chk_time_filter.isChecked():
            start_hour = self.time_start_hour.value()
            end_hour = self.time_end_hour.value()
            
            if start_hour <= end_hour:
                # Normal range (e.g., 9-17)
                filtered_events = [
                    e for e in filtered_events
                    if start_hour <= e['timestamp'].hour <= end_hour
                ]
            else:
                # Overnight range (e.g., 22-6)
                filtered_events = [
                    e for e in filtered_events
                    if e['timestamp'].hour >= start_hour or e['timestamp'].hour <= end_hour
                ]
            
            active_filters.append(f"Time: {start_hour:02d}:00-{end_hour:02d}:00")
        
        # Weekday filter
        if hasattr(self, 'chk_weekday_filter') and self.chk_weekday_filter.isChecked():
            weekday_map = {'Mon': 0, 'Tue': 1, 'Wed': 2, 'Thu': 3, 'Fri': 4, 'Sat': 5, 'Sun': 6}
            enabled_days = {
                weekday_map[day] for day, chk in self.weekday_checkboxes.items()
                if chk.isChecked()
            }
            
            filtered_events = [
                e for e in filtered_events
                if e['timestamp'].weekday() in enabled_days
            ]
            
            enabled_day_names = [day for day, chk in self.weekday_checkboxes.items() if chk.isChecked()]
            active_filters.append(f"Days: {', '.join(enabled_day_names)}")
        
        # Update filter status
        if active_filters:
            self.lbl_filter_status.setText(f"Active filters: {' | '.join(active_filters)}")
            self.lbl_filter_status.setStyleSheet("color: #FF9800; font-size: 10px; font-style: italic;")
        else:
            self.lbl_filter_status.setText("No filters active")
            self.lbl_filter_status.setStyleSheet("color: #4CAF50; font-size: 10px; font-style: italic;")
        
        # Load filtered events
        self.timeline_chart.load_events(filtered_events)
        
        # Detect and highlight time jumps
        if hasattr(self, 'chk_show_time_jumps') and self.chk_show_time_jumps.isChecked():
            self._detect_time_jumps(filtered_events)
        
        # Update info
        if filtered_events:
            original_count = len(self.all_events)
            filtered_count = len(filtered_events)
            pct = (filtered_count / original_count * 100) if original_count > 0 else 0
            
            self.lbl_timeline_info.setText(
                f"Showing {filtered_count:,} / {original_count:,} events ({pct:.1f}%) | "
                f"Range: {filtered_events[0]['timestamp'].strftime('%Y-%m-%d %H:%M')} to "
                f"{filtered_events[-1]['timestamp'].strftime('%Y-%m-%d %H:%M')}"
            )
        else:
            self.lbl_timeline_info.setText("No events match current filters")
    
    def _detect_time_jumps(self, events: List[Dict[str, Any]]):
        """Detect and log significant time gaps in events."""
        if len(events) < 2:
            return
        
        threshold_days = self.spin_time_jump_threshold.value()
        threshold_seconds = threshold_days * 86400
        
        jumps = []
        for i in range(1, len(events)):
            prev_time = events[i-1]['timestamp']
            curr_time = events[i]['timestamp']
            gap = (curr_time - prev_time).total_seconds()
            
            if gap > threshold_seconds:
                jumps.append({
                    'from': prev_time,
                    'to': curr_time,
                    'gap_days': gap / 86400
                })
        
        if jumps:
            self.logger.info(f"Detected {len(jumps)} time gaps > {threshold_days} day(s)")
            # Store jumps for visualization
            self.timeline_chart.time_jumps = jumps
        else:
            self.timeline_chart.time_jumps = []
    
    def _on_time_jump_toggle(self, checked: bool):
        """Handle time jump detection toggle."""
        if hasattr(self, 'all_events'):
            self._apply_advanced_filters()
    
    def _on_time_jump_threshold_changed(self, value: int):
        """Handle time jump threshold change."""
        if hasattr(self, 'all_events') and hasattr(self, 'chk_show_time_jumps'):
            if self.chk_show_time_jumps.isChecked():
                self._apply_advanced_filters()
    
    def _preset_business_hours(self):
        """Apply business hours preset (Mon-Fri, 9am-5pm)."""
        # Enable filters
        self.chk_weekday_filter.setChecked(True)
        self.chk_time_filter.setChecked(True)
        
        # Set weekdays
        weekday_map = {'Mon': True, 'Tue': True, 'Wed': True, 'Thu': True, 'Fri': True, 'Sat': False, 'Sun': False}
        for day, enabled in weekday_map.items():
            self.weekday_checkboxes[day].setChecked(enabled)
        
        # Set time range
        self.time_start_hour.setValue(9)
        self.time_end_hour.setValue(17)
        
        self._apply_advanced_filters()
    
    def _preset_off_hours(self):
        """Apply off-hours preset (weekday evenings + weekends)."""
        # Enable filters
        self.chk_weekday_filter.setChecked(True)
        self.chk_time_filter.setChecked(True)
        
        # Set all weekdays (will filter by time)
        for chk in self.weekday_checkboxes.values():
            chk.setChecked(True)
        
        # Set evening/night hours (18:00-08:00)
        self.time_start_hour.setValue(18)
        self.time_end_hour.setValue(8)
        
        self._apply_advanced_filters()
    
    def _preset_weekends(self):
        """Apply weekends-only preset."""
        # Enable weekday filter
        self.chk_weekday_filter.setChecked(True)
        self.chk_time_filter.setChecked(False)
        
        # Set only weekends
        weekday_map = {'Mon': False, 'Tue': False, 'Wed': False, 'Thu': False, 'Fri': False, 'Sat': True, 'Sun': True}
        for day, enabled in weekday_map.items():
            self.weekday_checkboxes[day].setChecked(enabled)
        
        self._apply_advanced_filters()
    
    def _clear_all_filters(self):
        """Clear all advanced filters."""
        # Disable all filter checkboxes
        if hasattr(self, 'chk_date_filter'):
            self.chk_date_filter.setChecked(False)
        if hasattr(self, 'chk_time_filter'):
            self.chk_time_filter.setChecked(False)
        if hasattr(self, 'chk_weekday_filter'):
            self.chk_weekday_filter.setChecked(False)
        
        # Reset weekdays to all
        if hasattr(self, 'weekday_checkboxes'):
            for chk in self.weekday_checkboxes.values():
                chk.setChecked(True)
        
        # Reset time range
        if hasattr(self, 'time_start_hour'):
            self.time_start_hour.setValue(0)
            self.time_end_hour.setValue(23)
        
        # Reload all events
        if hasattr(self, 'all_events'):
            self.timeline_chart.load_events(self.all_events)
            self.lbl_filter_status.setText("No filters active")
            self.lbl_filter_status.setStyleSheet("color: #4CAF50; font-size: 10px; font-style: italic;")
    
    def load_timeline_events(self, events: List[Dict[str, Any]]):
        """Load timeline events into the chart."""
        # Store original events for filtering
        self.all_events = events.copy()
        
        self.timeline_chart.load_events(events)
        
        if events:
            self.lbl_timeline_info.setText(
                f"Loaded {len(events):,} events | "
                f"Range: {events[0]['timestamp']} to {events[-1]['timestamp']}"
            )
            
            # Set date range picker bounds
            if hasattr(self, 'date_start'):
                min_date = QDate(events[0]['timestamp'].year, 
                               events[0]['timestamp'].month,
                               events[0]['timestamp'].day)
                max_date = QDate(events[-1]['timestamp'].year,
                               events[-1]['timestamp'].month,
                               events[-1]['timestamp'].day)
                
                self.date_start.setDateRange(min_date, max_date)
                self.date_end.setDateRange(min_date, max_date)
                self.date_start.setDate(min_date)
                self.date_end.setDate(max_date)
        else:
            self.lbl_timeline_info.setText("No timeline data")
