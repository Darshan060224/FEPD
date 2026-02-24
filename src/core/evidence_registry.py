"""
FEPD - Duplicate Evidence Detection
Global evidence registry to prevent duplicate case creation with same evidence.
"""

import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timezone


logger = logging.getLogger(__name__)


class EvidenceRegistry:
    """
    Global registry to track evidence usage across cases.
    Prevents duplicate evidence ingestion and maintains chain of custody.
    """
    
    def __init__(self, cases_dir: Path):
        """
        Initialize evidence registry.
        
        Args:
            cases_dir: Base directory containing all cases
        """
        self.cases_dir = cases_dir
        self.registry_file = cases_dir / ".evidence_registry.json"
        self.logger = logging.getLogger(__name__)
        
        # Create registry file if it doesn't exist
        if not self.registry_file.exists():
            self._init_registry()
    
    def _init_registry(self):
        """Initialize empty registry file."""
        registry = {
            "version": "1.0.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "evidence": {}
        }
        with open(self.registry_file, 'w') as f:
            json.dump(registry, f, indent=2)
        self.logger.info(f"Initialized evidence registry: {self.registry_file}")
    
    def _load_registry(self) -> Dict[str, Any]:
        """Load registry from disk."""
        try:
            with open(self.registry_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load registry: {e}")
            return {"version": "1.0.0", "evidence": {}}
    
    def _save_registry(self, registry: Dict[str, Any]):
        """Save registry to disk."""
        try:
            with open(self.registry_file, 'w') as f:
                json.dump(registry, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save registry: {e}")
    
    def check_duplicate(self, evidence_hash: str) -> Optional[Dict[str, str]]:
        """
        Check if evidence hash already exists in another case.
        
        Args:
            evidence_hash: SHA-256 hash of primary evidence file
        
        Returns:
            Dict with case info if duplicate found, None otherwise
        """
        registry = self._load_registry()
        
        if evidence_hash in registry.get("evidence", {}):
            return registry["evidence"][evidence_hash]
        
        return None
    
    def register_evidence(
        self, 
        evidence_hash: str, 
        case_id: str,
        evidence_name: str,
        evidence_type: str
    ):
        """
        Register evidence in the global registry.
        
        Args:
            evidence_hash: SHA-256 hash of primary evidence file
            case_id: Case identifier
            evidence_name: Evidence file/set name
            evidence_type: "single" or "multi_part_disk"
        """
        registry = self._load_registry()
        
        registry["evidence"][evidence_hash] = {
            "case_id": case_id,
            "evidence_name": evidence_name,
            "evidence_type": evidence_type,
            "registered_at": datetime.now(timezone.utc).isoformat()
        }
        
        self._save_registry(registry)
        self.logger.info(f"Registered evidence {evidence_hash[:16]}... in case {case_id}")
    
    def unregister_evidence(self, evidence_hash: str):
        """
        Remove evidence from registry (e.g., when case is deleted).
        
        Args:
            evidence_hash: SHA-256 hash to remove
        """
        registry = self._load_registry()
        
        if evidence_hash in registry.get("evidence", {}):
            del registry["evidence"][evidence_hash]
            self._save_registry(registry)
            self.logger.info(f"Unregistered evidence {evidence_hash[:16]}...")
    
    def get_all_registered_evidence(self) -> Dict[str, Dict[str, str]]:
        """
        Get all registered evidence.
        
        Returns:
            Dict mapping evidence hashes to case info
        """
        registry = self._load_registry()
        return registry.get("evidence", {})
