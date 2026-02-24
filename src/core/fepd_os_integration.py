"""
FEPD OS Integration Layer
=========================

Brings together all the new components:
- VEOS (Virtual Evidence OS)
- Evidence CMD (Terminal)
- Forensic ML Engine
- Investigative Visualizations

This module provides the glue that makes FEPD feel like
a "time-frozen OS built from evidence."

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import pandas as pd

# Local imports
try:
    from src.core.veos import (
        VirtualEvidenceOS, VEOSBuilder, VEOSFile, VEOSDrive,
        VEOSUserProfile, VEOSPathSanitizer, get_veos, set_veos, create_veos
    )
    VEOS_AVAILABLE = True
except ImportError:
    VEOS_AVAILABLE = False

try:
    from src.core.evidence_cmd import EvidenceCMD
    EVIDENCE_CMD_AVAILABLE = True
except ImportError:
    EVIDENCE_CMD_AVAILABLE = False

try:
    from src.ml.forensic_ml_engine import (
        ForensicMLEngine, ForensicAnomalyExplainer, 
        EventNormalizer, NormalizedEvent, Severity
    )
    ML_ENGINE_AVAILABLE = True
except ImportError:
    ML_ENGINE_AVAILABLE = False

try:
    from src.visualization.investigative_visualizations import (
        ActivityHeatmap, UserBehaviorGraph, AttackPathFlow,
        ArtifactTreemap, InvestigativeVisualizationGenerator
    )
    VISUALIZATIONS_AVAILABLE = True
except ImportError:
    VISUALIZATIONS_AVAILABLE = False

logger = logging.getLogger(__name__)


# ============================================================================
# FEPD OS ORCHESTRATOR
# ============================================================================

class FEPDOSOrchestrator:
    """
    Central orchestrator that coordinates all FEPD OS components.
    
    This is the main entry point for creating a "Forensic Operating System"
    experience from evidence.
    
    Usage:
        orchestrator = FEPDOSOrchestrator()
        orchestrator.initialize_case("cases/my_case")
        
        # Access components
        veos = orchestrator.veos
        cmd = orchestrator.cmd
        ml = orchestrator.ml_engine
    """
    
    def __init__(self):
        """Initialize the orchestrator."""
        self._veos: Optional[VirtualEvidenceOS] = None
        self._cmd: Optional[EvidenceCMD] = None
        self._ml_engine: Optional[ForensicMLEngine] = None
        self._case_path: Optional[Path] = None
        self._case_name: str = "unknown"
        
    @property
    def veos(self) -> Optional[VirtualEvidenceOS]:
        """Get the Virtual Evidence OS instance."""
        return self._veos
    
    @property
    def cmd(self) -> Optional[EvidenceCMD]:
        """Get the Evidence CMD instance."""
        return self._cmd
    
    @property
    def ml_engine(self) -> Optional[ForensicMLEngine]:
        """Get the Forensic ML Engine instance."""
        return self._ml_engine
    
    @property
    def case_name(self) -> str:
        """Get the current case name."""
        return self._case_name
    
    def initialize_case(self, case_path: str) -> bool:
        """
        Initialize all components for a case.
        
        Args:
            case_path: Path to the case directory
            
        Returns:
            True if initialization successful
        """
        self._case_path = Path(case_path)
        self._case_name = self._case_path.name
        
        success = True
        
        # 1. Initialize VEOS
        if VEOS_AVAILABLE:
            try:
                self._veos = create_veos(str(self._case_path))
                logger.info(f"VEOS initialized for case: {self._case_name}")
            except Exception as e:
                logger.error(f"Failed to initialize VEOS: {e}")
                success = False
        else:
            logger.warning("VEOS not available")
        
        # 2. Initialize Evidence CMD
        if EVIDENCE_CMD_AVAILABLE and self._veos:
            try:
                self._cmd = EvidenceCMD(self._veos, self._case_name)
                logger.info("Evidence CMD initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Evidence CMD: {e}")
                success = False
        
        # 3. Initialize ML Engine
        if ML_ENGINE_AVAILABLE:
            try:
                self._ml_engine = ForensicMLEngine(str(self._case_path))
                logger.info("Forensic ML Engine initialized")
            except Exception as e:
                logger.error(f"Failed to initialize ML Engine: {e}")
                success = False
        
        return success
    
    def get_drives(self) -> List[Dict]:
        """Get all drives in the evidence."""
        if not self._veos:
            return []
        return [
            {
                'letter': drive.letter,
                'label': drive.label,
                'fs_type': drive.fs_type,
                'total_size': drive.total_size,
                'used_size': drive.used_size,
                'user_count': len(drive.users)
            }
            for drive in self._veos.drives.values()
        ]
    
    def get_users(self) -> List[Dict]:
        """Get all detected users."""
        if not self._veos:
            return []
        return [
            {
                'username': user.username,
                'sid': user.sid,
                'home_path': user.home_path,
                'is_admin': user.is_admin
            }
            for user in self._veos.users.values()
        ]
    
    def execute_command(self, command: str) -> str:
        """
        Execute a command in the Evidence CMD.
        
        Args:
            command: Command to execute
            
        Returns:
            Command output
        """
        if not self._cmd:
            return "ERROR: Evidence CMD not initialized"
        
        return self._cmd.execute(command)
    
    def get_current_prompt(self) -> str:
        """Get the current Evidence CMD prompt."""
        if not self._cmd:
            return f"fepd:{self._case_name}> "
        return self._cmd.prompt
    
    def list_directory(self, path: str) -> List[VEOSFile]:
        """
        List contents of a directory.
        
        Args:
            path: Evidence-native path (e.g., "C:\\Users")
            
        Returns:
            List of VEOSFile objects
        """
        if not self._veos:
            return []
        return self._veos.list_directory(path)
    
    def get_file_info(self, path: str) -> Optional[VEOSFile]:
        """
        Get information about a file.
        
        Args:
            path: Evidence-native path
            
        Returns:
            VEOSFile object or None
        """
        if not self._veos:
            return None
        return self._veos.get_file(path)
    
    def search_files(self, pattern: str) -> List[VEOSFile]:
        """
        Search for files matching a pattern.
        
        Args:
            pattern: Search pattern (supports wildcards)
            
        Returns:
            List of matching VEOSFile objects
        """
        if not self._veos:
            return []
        return self._veos.search(pattern)
    
    def analyze_ml(self, events_df: pd.DataFrame = None) -> pd.DataFrame:
        """
        Run ML analysis on events.
        
        Args:
            events_df: DataFrame with events, or None to load from case
            
        Returns:
            DataFrame with anomaly scores and explanations
        """
        if not self._ml_engine:
            return pd.DataFrame()
        
        if events_df is None:
            # Try to load events from case
            events_df = self._load_case_events()
        
        if events_df is None or len(events_df) == 0:
            return pd.DataFrame()
        
        # Train and analyze
        self._ml_engine.train(events_df)
        return self._ml_engine.analyze(events_df)
    
    def _load_case_events(self) -> Optional[pd.DataFrame]:
        """Load events from case database."""
        if not self._case_path:
            return None
        
        # Try evidence.db
        db_path = self._case_path / "evidence.db"
        if db_path.exists():
            import sqlite3
            try:
                conn = sqlite3.connect(str(db_path))
                # Try common table names
                for table in ['events', 'timeline', 'artifacts']:
                    try:
                        df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
                        if len(df) > 0:
                            conn.close()
                            return df
                    except:
                        pass
                conn.close()
            except Exception as e:
                logger.error(f"Error loading events: {e}")
        
        return None
    
    def generate_visualizations(self, events_df: pd.DataFrame = None) -> Dict:
        """
        Generate all investigative visualizations.
        
        Args:
            events_df: DataFrame with events (with ML results)
            
        Returns:
            Dictionary of figure objects
        """
        if not VISUALIZATIONS_AVAILABLE:
            return {}
        
        if events_df is None:
            events_df = self._load_case_events()
        
        if events_df is None or len(events_df) == 0:
            return {}
        
        generator = InvestigativeVisualizationGenerator(events_df)
        return generator.generate_all()
    
    def get_forensic_report(self, events_df: pd.DataFrame = None, top_n: int = 10) -> str:
        """
        Generate forensic ML report.
        
        Args:
            events_df: DataFrame with events
            top_n: Number of top anomalies to include
            
        Returns:
            Markdown report string
        """
        if not self._ml_engine:
            return "ML Engine not available"
        
        if events_df is None:
            events_df = self._load_case_events()
        
        if events_df is None:
            return "No events found"
        
        # Ensure ML has been run
        self._ml_engine.train(events_df)
        analyzed = self._ml_engine.analyze(events_df)
        
        return self._ml_engine.generate_forensic_report(analyzed, top_n)
    
    def sanitize_path(self, path: str) -> str:
        """
        Sanitize a path for display.
        
        Converts internal paths to evidence-native paths.
        
        Args:
            path: Path to sanitize
            
        Returns:
            Sanitized path suitable for display
        """
        if self._veos and self._veos.path_sanitizer:
            return self._veos.path_sanitizer.sanitize(path)
        return path
    
    def get_platform(self) -> str:
        """Get detected platform (windows/linux/macos/android/ios)."""
        if self._veos:
            return self._veos.platform
        return "unknown"
    
    def get_status(self) -> Dict:
        """Get orchestrator status."""
        return {
            'case_name': self._case_name,
            'case_path': str(self._case_path) if self._case_path else None,
            'veos_available': VEOS_AVAILABLE,
            'veos_initialized': self._veos is not None,
            'cmd_available': EVIDENCE_CMD_AVAILABLE,
            'cmd_initialized': self._cmd is not None,
            'ml_available': ML_ENGINE_AVAILABLE,
            'ml_initialized': self._ml_engine is not None,
            'viz_available': VISUALIZATIONS_AVAILABLE,
            'platform': self.get_platform(),
            'drive_count': len(self._veos.drives) if self._veos else 0,
            'user_count': len(self._veos.users) if self._veos else 0
        }


# ============================================================================
# SINGLETON ACCESSOR
# ============================================================================

_orchestrator: Optional[FEPDOSOrchestrator] = None


def get_orchestrator() -> FEPDOSOrchestrator:
    """Get the global orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = FEPDOSOrchestrator()
    return _orchestrator


def initialize_fepd_os(case_path: str) -> FEPDOSOrchestrator:
    """
    Initialize the FEPD OS for a case.
    
    This is the main entry point for the new FEPD OS experience.
    
    Args:
        case_path: Path to the case directory
        
    Returns:
        Initialized FEPDOSOrchestrator
        
    Usage:
        from src.core.fepd_os_integration import initialize_fepd_os
        
        os = initialize_fepd_os("cases/my_investigation")
        
        # List files like a real OS
        files = os.list_directory("C:\\Users\\Alice\\Desktop")
        
        # Run commands
        output = os.execute_command("dir C:\\")
        
        # Analyze with ML
        results = os.analyze_ml()
        
        # Generate visualizations
        figures = os.generate_visualizations(results)
    """
    global _orchestrator
    _orchestrator = FEPDOSOrchestrator()
    _orchestrator.initialize_case(case_path)
    return _orchestrator


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def get_current_veos() -> Optional[VirtualEvidenceOS]:
    """Get the current VEOS instance."""
    return get_orchestrator().veos


def get_current_cmd() -> Optional[EvidenceCMD]:
    """Get the current Evidence CMD instance."""
    return get_orchestrator().cmd


def get_current_ml_engine() -> Optional[ForensicMLEngine]:
    """Get the current ML Engine instance."""
    return get_orchestrator().ml_engine


def sanitize_display_path(path: str) -> str:
    """
    Sanitize a path for display in the UI.
    
    NEVER shows:
    - cases/...
    - Evidence/...
    - tmp/...
    - Internal Python paths
    
    ALWAYS shows:
    - C:\\Users\\Alice\\Desktop\\note.txt
    - /home/bob/documents/file.txt
    """
    return get_orchestrator().sanitize_path(path)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Main class
    'FEPDOSOrchestrator',
    
    # Initialization
    'initialize_fepd_os',
    'get_orchestrator',
    
    # Component accessors
    'get_current_veos',
    'get_current_cmd',
    'get_current_ml_engine',
    
    # Utilities
    'sanitize_display_path',
    
    # Availability flags
    'VEOS_AVAILABLE',
    'EVIDENCE_CMD_AVAILABLE',
    'ML_ENGINE_AVAILABLE',
    'VISUALIZATIONS_AVAILABLE'
]
