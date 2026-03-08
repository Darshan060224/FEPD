"""
FEPD UI Tabs Package

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

from .timeline_tab import TimelineTab
from .ml_analytics_tab import MLAnalyticsTab
from .visualizations_tab import VisualizationsTab
from .search_tab import SearchTab
from .platform_analysis_tab import PlatformAnalysisTab
from .configuration_tab import ConfigurationTab

__all__ = [
    'TimelineTab',
    'MLAnalyticsTab', 
    'VisualizationsTab',
    'SearchTab',
    'PlatformAnalysisTab',
    'ConfigurationTab',
]
