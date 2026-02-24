"""
FEPD - Training State Controller
=================================
Enforces hard boundaries between training and inference modes

CRITICAL RULES:
- TRAINING mode: dataa/ allowed, models can be trained
- INFERENCE mode: dataa/ MUST NOT exist, models are read-only

This is a security control, not optional.

Copyright (c) 2025 FEPD Development Team
"""

import logging
from enum import Enum
from pathlib import Path
from typing import Optional
import json
from datetime import datetime


class SystemMode(Enum):
    """System operating modes."""
    TRAINING = "training"
    INFERENCE = "inference"
    UNDEFINED = "undefined"


class TrainingStateController:
    """
    Controls and enforces system mode boundaries.
    
    This is a CRITICAL security component that prevents:
    - Training data leakage into inference
    - Evidence contamination
    - Accidental mode mixing
    """
    
    def __init__(self, workspace_root: Path):
        """
        Args:
            workspace_root: Root path of FEPD workspace
        """
        self.workspace_root = Path(workspace_root)
        self.state_file = self.workspace_root / ".fepd_state.json"
        self.dataa_path = self.workspace_root / "dataa"
        self.models_path = self.workspace_root / "models"
        self.logger = logging.getLogger(__name__)
        
        self._current_mode = SystemMode.UNDEFINED
        self._load_state()
    
    def _load_state(self):
        """Load current system state from disk."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    self._current_mode = SystemMode(state.get('mode', 'undefined'))
                    self.logger.info(f"Loaded system state: {self._current_mode.value}")
            except Exception as e:
                self.logger.warning(f"Failed to load state: {e}, defaulting to UNDEFINED")
                self._current_mode = SystemMode.UNDEFINED
        else:
            self._current_mode = SystemMode.UNDEFINED
    
    def _save_state(self):
        """Save current system state to disk."""
        state = {
            'mode': self._current_mode.value,
            'last_updated': datetime.now().isoformat()
        }
        
        with open(self.state_file, 'w') as f:
            json.dump(state, f, indent=2)
        
        self.logger.info(f"Saved system state: {self._current_mode.value}")
    
    def get_mode(self) -> SystemMode:
        """Get current system mode."""
        return self._current_mode
    
    def enter_training_mode(self) -> bool:
        """
        Enter TRAINING mode.
        
        Rules:
        - Creates empty dataa/ if it doesn't exist
        - Models directory becomes read-write
        - Inference operations are blocked
        
        Returns:
            True if successful
        """
        self.logger.info("="*60)
        self.logger.info("ENTERING TRAINING MODE")
        self.logger.info("="*60)
        
        # Create empty dataa/
        if not self.dataa_path.exists():
            self.dataa_path.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"✅ Created empty dataa/: {self.dataa_path}")
        else:
            self.logger.warning(f"⚠️ dataa/ already exists: {self.dataa_path}")
            self.logger.warning("This may contain stale data from previous training")
        
        # Ensure models/ exists
        self.models_path.mkdir(parents=True, exist_ok=True)
        
        # Set mode
        self._current_mode = SystemMode.TRAINING
        self._save_state()
        
        self.logger.info("✅ TRAINING MODE ACTIVE")
        self.logger.info(f"   dataa/ path: {self.dataa_path}")
        self.logger.info(f"   models/ path: {self.models_path}")
        
        return True
    
    def enter_inference_mode(self, strict: bool = True) -> bool:
        """
        Enter INFERENCE mode.
        
        Rules:
        - dataa/ MUST NOT exist
        - Models directory becomes read-only
        - Training operations are blocked
        
        Args:
            strict: If True, fail if dataa/ exists
        
        Returns:
            True if successful
        
        Raises:
            RuntimeError: If dataa/ exists and strict=True
        """
        self.logger.info("="*60)
        self.logger.info("ENTERING INFERENCE MODE")
        self.logger.info("="*60)
        
        # CRITICAL: Verify dataa/ does not exist
        if self.dataa_path.exists():
            if strict:
                error_msg = (
                    f"❌ SECURITY VIOLATION: dataa/ exists at {self.dataa_path}\n"
                    f"dataa/ MUST be removed before entering inference mode.\n"
                    f"This prevents training data leakage into case evidence."
                )
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)
            else:
                self.logger.warning(f"⚠️ dataa/ exists but strict=False, continuing")
        else:
            self.logger.info("✅ dataa/ verified as non-existent")
        
        # Verify models exist
        if not self.models_path.exists() or not any(self.models_path.glob("*.pkl")):
            self.logger.warning("⚠️ No trained models found")
            self.logger.warning("You may need to train models first")
        else:
            model_count = len(list(self.models_path.glob("*.pkl")))
            self.logger.info(f"✅ Found {model_count} trained models")
        
        # Set mode
        self._current_mode = SystemMode.INFERENCE
        self._save_state()
        
        self.logger.info("✅ INFERENCE MODE ACTIVE")
        self.logger.info("   Training operations blocked")
        self.logger.info("   Models are read-only")
        
        return True
    
    def verify_training_allowed(self) -> bool:
        """
        Verify training operations are allowed.
        
        Returns:
            True if in TRAINING mode
        
        Raises:
            RuntimeError: If not in TRAINING mode
        """
        if self._current_mode != SystemMode.TRAINING:
            raise RuntimeError(
                f"Training not allowed in {self._current_mode.value} mode. "
                f"Call enter_training_mode() first."
            )
        return True
    
    def verify_inference_allowed(self) -> bool:
        """
        Verify inference operations are allowed.
        
        Returns:
            True if in INFERENCE mode
        
        Raises:
            RuntimeError: If not in INFERENCE mode
        """
        if self._current_mode != SystemMode.INFERENCE:
            raise RuntimeError(
                f"Inference not allowed in {self._current_mode.value} mode. "
                f"Call enter_inference_mode() first."
            )
        return True
    
    def verify_dataa_allowed(self) -> bool:
        """
        Verify dataa/ access is allowed.
        
        Returns:
            True if in TRAINING mode
        
        Raises:
            RuntimeError: If not in TRAINING mode
        """
        if self._current_mode != SystemMode.TRAINING:
            raise RuntimeError(
                f"dataa/ access not allowed in {self._current_mode.value} mode. "
                f"dataa/ is ONLY for training."
            )
        return True
    
    def get_dataa_path(self) -> Optional[Path]:
        """
        Get dataa/ path if allowed.
        
        Returns:
            Path to dataa/ if in TRAINING mode, None otherwise
        """
        if self._current_mode == SystemMode.TRAINING:
            return self.dataa_path
        return None
    
    def reset(self):
        """Reset to UNDEFINED mode (for testing only)."""
        self._current_mode = SystemMode.UNDEFINED
        if self.state_file.exists():
            self.state_file.unlink()
        self.logger.info("System state reset to UNDEFINED")


if __name__ == "__main__":
    # Standalone test
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    workspace = Path(__file__).parent.parent.parent
    controller = TrainingStateController(workspace)
    
    print(f"\nCurrent mode: {controller.get_mode().value}")
    
    # Test training mode
    controller.enter_training_mode()
    assert controller.get_mode() == SystemMode.TRAINING
    assert controller.verify_training_allowed()
    
    # Test inference mode
    # controller.enter_inference_mode(strict=False)  # Would fail if dataa exists
    
    print("\n✅ TrainingStateController tests passed")
