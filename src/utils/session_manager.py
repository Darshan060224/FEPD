"""
Session Manager - Save and restore analysis session state.
Stores filters, UI state, scroll positions, and case context.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Manages session snapshots for FEPD analysis sessions.
    
    Features:
    - Save current analysis state (filters, UI layout, scroll position)
    - Restore previous session on case open
    - Store session metadata (timestamp, event count, etc.)
    - Auto-save on application close
    
    Example:
        >>> session_mgr = SessionManager(case_dir='cases/case1')
        >>> session_mgr.save_session(
        ...     filters={'start_date': '2024-01-01', 'keywords': 'chrome'},
        ...     scroll_position=150,
        ...     selected_tab=0
        ... )
        >>> # Later...
        >>> if session_mgr.has_snapshot():
        ...     state = session_mgr.load_session()
        ...     # Restore UI state
    """
    
    SNAPSHOT_FILENAME = 'session_snapshot.json'
    
    def __init__(self, case_dir: str):
        """
        Initialize session manager for a specific case.
        
        Args:
            case_dir: Path to case directory (e.g., 'cases/case1')
        """
        self.case_dir = Path(case_dir)
        self.snapshot_path = self.case_dir / self.SNAPSHOT_FILENAME
        
        logger.info(f"SessionManager initialized for case: {case_dir}")
    
    def save_session(
        self,
        filters: Optional[Dict[str, Any]] = None,
        scroll_position: int = 0,
        selected_tab: int = 0,
        ui_state: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        state_dict: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Save current session state to snapshot file.
        
        Args:
            filters: Timeline filters (date range, keywords, event types)
            scroll_position: Current scroll position in timeline
            selected_tab: Index of currently selected tab
            ui_state: Additional UI state (window size, splitter positions)
            metadata: Case metadata (event count, artifact count, etc.)
            state_dict: Complete state dictionary (if provided, overrides other params)
        
        Returns:
            True if save successful, False otherwise
        
        Example:
            >>> # Method 1: Individual parameters
            >>> session_mgr.save_session(
            ...     filters={
            ...         'start_date': '2024-01-01',
            ...         'end_date': '2024-12-31',
            ...         'keywords': ['chrome', 'firefox'],
            ...         'event_types': ['Registry', 'Prefetch']
            ...     },
            ...     scroll_position=250,
            ...     selected_tab=1
            ... )
            >>> 
            >>> # Method 2: Single state dict
            >>> session_mgr.save_session(state_dict={
            ...     'active_tab': 2,
            ...     'scroll_positions': {'timeline': 100}
            ... })
        """
        try:
            # Ensure case directory exists
            self.case_dir.mkdir(parents=True, exist_ok=True)
            
            # Build snapshot data - use state_dict if provided, otherwise use individual params
            if state_dict:
                snapshot = {
                    'version': '1.0',
                    'timestamp': datetime.now().isoformat(),
                    'case_dir': str(self.case_dir),
                    **state_dict  # Unpack the state dict directly
                }
            else:
                snapshot = {
                    'version': '1.0',
                    'timestamp': datetime.now().isoformat(),
                    'case_dir': str(self.case_dir),
                    'filters': filters or {},
                    'scroll_position': scroll_position,
                    'selected_tab': selected_tab,
                    'ui_state': ui_state or {},
                    'metadata': metadata or {}
                }
            
            # Write to file
            with open(self.snapshot_path, 'w', encoding='utf-8') as f:
                json.dump(snapshot, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Session snapshot saved to {self.snapshot_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save session snapshot: {e}", exc_info=True)
            return False
    
    def load_session(self) -> Optional[Dict[str, Any]]:
        """
        Load session snapshot from file.
        
        Returns:
            Session data dictionary, or None if no snapshot exists
        
        Example:
            >>> state = session_mgr.load_session()
            >>> if state:
            ...     filters = state.get('filters', {})
            ...     scroll_pos = state.get('scroll_position', 0)
            ...     # Restore UI state
        """
        if not self.snapshot_path.exists():
            logger.debug("No session snapshot found")
            return None
        
        try:
            with open(self.snapshot_path, 'r', encoding='utf-8') as f:
                snapshot = json.load(f)
            
            logger.info(f"Session snapshot loaded from {self.snapshot_path}")
            logger.debug(f"Snapshot timestamp: {snapshot.get('timestamp')}")
            
            return snapshot
            
        except Exception as e:
            logger.error(f"Failed to load session snapshot: {e}", exc_info=True)
            return None
    
    def has_snapshot(self) -> bool:
        """
        Check if a session snapshot exists for this case.
        
        Returns:
            True if snapshot file exists, False otherwise
        """
        exists = self.snapshot_path.exists()
        if exists:
            logger.debug(f"Session snapshot found at {self.snapshot_path}")
        return exists
    
    def delete_snapshot(self) -> bool:
        """
        Delete the session snapshot file.
        
        Returns:
            True if deletion successful or file doesn't exist, False on error
        
        Example:
            >>> # User chose "Start Fresh"
            >>> session_mgr.delete_snapshot()
        """
        if not self.snapshot_path.exists():
            return True
        
        try:
            self.snapshot_path.unlink()
            logger.info(f"Session snapshot deleted: {self.snapshot_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete snapshot: {e}", exc_info=True)
            return False
    
    def get_snapshot_metadata(self) -> Optional[Dict[str, Any]]:
        """
        Get snapshot metadata without loading full session.
        
        Returns:
            Dictionary with timestamp and basic metadata, or None if no snapshot
        
        Example:
            >>> meta = session_mgr.get_snapshot_metadata()
            >>> if meta:
            ...     print(f"Last saved: {meta['timestamp']}")
            ...     print(f"Events: {meta.get('total_events', 'unknown')}")
        """
        snapshot = self.load_session()
        if not snapshot:
            return None
        
        return {
            'timestamp': snapshot.get('timestamp'),
            'total_events': snapshot.get('metadata', {}).get('total_events'),
            'total_artifacts': snapshot.get('metadata', {}).get('total_artifacts'),
            'has_filters': bool(snapshot.get('filters')),
            'selected_tab': snapshot.get('selected_tab', 0)
        }
    
    def auto_save(
        self,
        timeline_filters: Optional[Dict[str, Any]] = None,
        current_tab: Optional[int] = None,
        scroll_position: Optional[int] = None,
        event_count: Optional[int] = None,
        artifact_count: Optional[int] = None,
        state_dict: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Convenience method for auto-saving on application close.
        
        Args:
            timeline_filters: Current timeline filter state
            current_tab: Currently selected tab index
            scroll_position: Timeline scroll position
            event_count: Total events in timeline
            artifact_count: Total artifacts extracted
            state_dict: Complete state dictionary (if provided, overrides other params)
        
        Returns:
            True if save successful
        
        Example:
            >>> # Method 1: Individual parameters
            >>> session_mgr.auto_save(
            ...     timeline_filters=self.get_current_filters(),
            ...     current_tab=self.tabs.currentIndex(),
            ...     scroll_position=self.timeline_table.verticalScrollBar().value(),
            ...     event_count=len(self.timeline_df),
            ...     artifact_count=len(self.artifacts_df)
            ... )
            >>> 
            >>> # Method 2: State dict
            >>> session_mgr.auto_save(state_dict=self._get_current_state())
        """
        if state_dict:
            return self.save_session(state_dict=state_dict)
        else:
            return self.save_session(
                filters=timeline_filters or {},
                selected_tab=current_tab or 0,
                scroll_position=scroll_position or 0,
                metadata={
                    'total_events': event_count or 0,
                    'total_artifacts': artifact_count or 0,
                    'auto_saved': True
                }
            )


if __name__ == '__main__':
    """Quick test of SessionManager."""
    import tempfile
    import shutil
    
    print("=" * 60)
    print("SessionManager Test")
    print("=" * 60)
    
    # Create temporary case directory
    temp_dir = Path(tempfile.mkdtemp(prefix='fepd_test_'))
    print(f"\n✓ Created temp directory: {temp_dir}")
    
    try:
        # Initialize session manager
        session_mgr = SessionManager(case_dir=temp_dir)
        
        # Test: No snapshot initially
        print(f"\n1. Has snapshot initially? {session_mgr.has_snapshot()}")
        assert not session_mgr.has_snapshot()
        
        # Test: Save session
        print("\n2. Saving session...")
        success = session_mgr.save_session(
            filters={
                'start_date': '2024-01-01',
                'end_date': '2024-12-31',
                'keywords': ['chrome', 'firefox']
            },
            scroll_position=150,
            selected_tab=1,
            metadata={
                'total_events': 465,
                'total_artifacts': 132
            }
        )
        assert success
        print("   ✓ Session saved")
        
        # Test: Snapshot exists now
        print(f"\n3. Has snapshot now? {session_mgr.has_snapshot()}")
        assert session_mgr.has_snapshot()
        
        # Test: Get metadata
        print("\n4. Getting snapshot metadata...")
        meta = session_mgr.get_snapshot_metadata()
        print(f"   Timestamp: {meta['timestamp']}")
        print(f"   Events: {meta['total_events']}")
        print(f"   Artifacts: {meta['total_artifacts']}")
        print(f"   Has filters: {meta['has_filters']}")
        
        # Test: Load session
        print("\n5. Loading session...")
        state = session_mgr.load_session()
        assert state is not None
        print(f"   Filters: {state['filters']}")
        print(f"   Scroll position: {state['scroll_position']}")
        print(f"   Selected tab: {state['selected_tab']}")
        
        # Test: Delete snapshot
        print("\n6. Deleting snapshot...")
        session_mgr.delete_snapshot()
        assert not session_mgr.has_snapshot()
        print("   ✓ Snapshot deleted")
        
        print("\n" + "=" * 60)
        print("✅ All SessionManager tests passed!")
        print("=" * 60)
        
    finally:
        # Cleanup
        shutil.rmtree(temp_dir)
        print(f"\n✓ Cleaned up temp directory")
