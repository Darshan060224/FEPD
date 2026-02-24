"""
Workflow Manager - Manage application startup workflow and case selection.
Handles case creation, disk image selection, and workflow state.
"""

import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime


logger = logging.getLogger(__name__)


class WorkflowManager:
    """
    Manages application workflow and case state.
    
    Features:
    - Track last opened case
    - Store disk image path
    - Manage workflow state
    - Auto-detect startup action
    
    Example:
        >>> workflow = WorkflowManager()
        >>> action = workflow.get_startup_action()
        >>> if action == 'open_last_case':
        ...     case_id = workflow.get_last_case_id()
    """
    
    WORKFLOW_FILE = 'workflow_state.json'
    
    def __init__(self, config_dir: str = 'config'):
        """
        Initialize workflow manager.
        
        Args:
            config_dir: Directory for configuration files
        """
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.workflow_file = self.config_dir / self.WORKFLOW_FILE
        self.state = self._load_state()
        
        logger.info(f"WorkflowManager initialized with config dir: {config_dir}")
    
    def _load_state(self) -> Dict[str, Any]:
        """Load workflow state from file."""
        if not self.workflow_file.exists():
            return {
                'last_case_id': None,
                'last_case_opened': None,
                'last_image_path': None,
                'startup_action': 'prompt'  # 'prompt', 'open_last', 'new_case'
            }
        
        try:
            with open(self.workflow_file, 'r', encoding='utf-8') as f:
                state = json.load(f)
            logger.info("Workflow state loaded")
            return state
        except Exception as e:
            logger.error(f"Failed to load workflow state: {e}")
            return {}
    
    def _save_state(self) -> bool:
        """Save workflow state to file."""
        try:
            with open(self.workflow_file, 'w', encoding='utf-8') as f:
                json.dump(self.state, f, indent=2, ensure_ascii=False)
            logger.info("Workflow state saved")
            return True
        except Exception as e:
            logger.error(f"Failed to save workflow state: {e}")
            return False
    
    def get_startup_action(self) -> str:
        """
        Determine what action to take on startup.
        
        Returns:
            'prompt' - Show case selection dialog
            'open_last_case' - Open last case automatically
            'new_case' - Create new case
        
        Example:
            >>> action = workflow.get_startup_action()
            >>> if action == 'open_last_case':
            ...     print("Opening last case...")
        """
        # Check if we have a last case
        if self.state.get('last_case_id') and self.state.get('last_case_opened'):
            # If last case was opened recently (within 24 hours), suggest reopening
            try:
                last_opened = datetime.fromisoformat(self.state['last_case_opened'])
                hours_since = (datetime.now() - last_opened).total_seconds() / 3600
                
                if hours_since < 24:
                    return 'open_last_case'
            except:
                pass
        
        return 'prompt'
    
    def get_last_case_id(self) -> Optional[str]:
        """
        Get ID of last opened case.
        
        Returns:
            Case ID string, or None
        """
        return self.state.get('last_case_id')
    
    def get_last_image_path(self) -> Optional[str]:
        """
        Get path of last selected disk image.
        
        Returns:
            Image file path, or None
        """
        return self.state.get('last_image_path')
    
    def store_case_opened(self, case_id: str) -> bool:
        """
        Store that a case was opened.
        
        Args:
            case_id: ID of opened case
        
        Returns:
            True if saved successfully
        
        Example:
            >>> workflow.store_case_opened('case1')
        """
        self.state['last_case_id'] = case_id
        self.state['last_case_opened'] = datetime.now().isoformat()
        
        logger.info(f"Case opened: {case_id}")
        return self._save_state()
    
    def store_image_path(self, image_path: str) -> bool:
        """
        Store disk image path for current case.
        
        Args:
            image_path: Path to disk image file
        
        Returns:
            True if saved successfully
        
        Example:
            >>> workflow.store_image_path('/path/to/image.E01')
        """
        self.state['last_image_path'] = image_path
        logger.info(f"Image path stored: {image_path}")
        return self._save_state()
    
    def get_image_path(self) -> Optional[str]:
        """
        Get stored disk image path.
        
        Returns:
            Image path or None
        """
        return self.state.get('last_image_path')
    
    def clear_workflow_state(self) -> bool:
        """
        Clear all workflow state (reset).
        
        Returns:
            True if cleared successfully
        """
        self.state = {
            'last_case_id': None,
            'last_case_opened': None,
            'last_image_path': None,
            'startup_action': 'prompt'
        }
        
        logger.info("Workflow state cleared")
        return self._save_state()
    
    def set_startup_preference(self, preference: str) -> bool:
        """
        Set startup action preference.
        
        Args:
            preference: 'prompt', 'open_last', or 'new_case'
        
        Returns:
            True if saved successfully
        """
        if preference not in ['prompt', 'open_last', 'new_case']:
            logger.warning(f"Invalid startup preference: {preference}")
            return False
        
        self.state['startup_action'] = preference
        return self._save_state()
    
    def get_workflow_summary(self) -> Dict[str, Any]:
        """
        Get summary of workflow state.
        
        Returns:
            Dictionary with workflow information
        
        Example:
            >>> summary = workflow.get_workflow_summary()
            >>> print(f"Last case: {summary['last_case_id']}")
        """
        summary = {
            'last_case_id': self.state.get('last_case_id'),
            'last_case_opened': self.state.get('last_case_opened'),
            'last_image_path': self.state.get('last_image_path'),
            'startup_action': self.state.get('startup_action', 'prompt'),
            'has_recent_case': False
        }
        
        # Check if case is recent
        if summary['last_case_opened']:
            try:
                last_opened = datetime.fromisoformat(summary['last_case_opened'])
                hours_since = (datetime.now() - last_opened).total_seconds() / 3600
                summary['has_recent_case'] = hours_since < 24
                summary['hours_since_last'] = round(hours_since, 1)
            except:
                pass
        
        return summary


if __name__ == '__main__':
    """Quick test of WorkflowManager."""
    import tempfile
    import shutil
    
    print("=" * 60)
    print("WorkflowManager Test")
    print("=" * 60)
    
    # Create temporary config directory
    temp_dir = Path(tempfile.mkdtemp(prefix='fepd_workflow_test_'))
    print(f"\n✓ Created temp directory: {temp_dir}")
    
    try:
        # Initialize workflow manager
        workflow = WorkflowManager(config_dir=temp_dir)
        print("✓ WorkflowManager initialized")
        
        # Test: Initial state
        print("\n1. Testing initial state...")
        action = workflow.get_startup_action()
        print(f"   Startup action: {action}")
        assert action == 'prompt'
        
        last_case = workflow.get_last_case_id()
        print(f"   Last case: {last_case}")
        assert last_case is None
        
        # Test: Store case opened
        print("\n2. Storing case opened...")
        success = workflow.store_case_opened('case1')
        assert success
        print(f"   ✓ Case 'case1' stored")
        
        # Test: Store image path
        print("\n3. Storing image path...")
        success = workflow.store_image_path('/path/to/image.E01')
        assert success
        print(f"   ✓ Image path stored")
        
        # Test: Get stored values
        print("\n4. Retrieving stored values...")
        case_id = workflow.get_last_case_id()
        image_path = workflow.get_image_path()
        print(f"   Case ID: {case_id}")
        print(f"   Image path: {image_path}")
        assert case_id == 'case1'
        assert image_path == '/path/to/image.E01'
        
        # Test: Startup action with recent case
        print("\n5. Testing startup action with recent case...")
        action = workflow.get_startup_action()
        print(f"   Startup action: {action}")
        assert action == 'open_last_case'  # Should suggest opening last case
        
        # Test: Workflow summary
        print("\n6. Getting workflow summary...")
        summary = workflow.get_workflow_summary()
        print(f"   Last case: {summary['last_case_id']}")
        print(f"   Has recent case: {summary['has_recent_case']}")
        print(f"   Hours since last: {summary.get('hours_since_last', 'N/A')}")
        assert summary['has_recent_case'] == True
        
        # Test: Clear state
        print("\n7. Clearing workflow state...")
        workflow.clear_workflow_state()
        case_id = workflow.get_last_case_id()
        print(f"   Last case after clear: {case_id}")
        assert case_id is None
        
        # Test: Set preference
        print("\n8. Setting startup preference...")
        workflow.set_startup_preference('new_case')
        state = workflow.state
        print(f"   Startup preference: {state['startup_action']}")
        assert state['startup_action'] == 'new_case'
        
        print("\n" + "=" * 60)
        print("✅ All WorkflowManager tests passed!")
        print("=" * 60)
        
    finally:
        # Cleanup
        shutil.rmtree(temp_dir)
        print(f"\n✓ Cleaned up temp directory")
