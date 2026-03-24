"""
Case Manager Module for FEPD
Handles case creation, loading, and metadata management.
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Any

from .chain_of_custody import ChainLogger, CoC_Actions

logger = logging.getLogger(__name__)


class CaseManager:
    """
    Manages forensic case operations including:
    - Case creation and initialization
    - Case metadata management
    - Chain of custody logging
    - Evidence image hashing
    - Shared registry synchronization (for Terminal/UI sync)
    """
    
    def __init__(self, base_cases_dir: str = "cases"):
        """
        Initialize the Case Manager.
        
        Args:
            base_cases_dir: Base directory for all cases
        """
        self.base_cases_dir = Path(base_cases_dir)
        self.registry_path = self.base_cases_dir / "index.json"
        self.current_case: Optional[Dict[str, Any]] = None
        self.case_path: Optional[Path] = None
        
        # Ensure base cases directory exists
        self.base_cases_dir.mkdir(exist_ok=True, parents=True)
        logger.info(f"Case Manager initialized with base directory: {self.base_cases_dir}")
    
    def _update_registry(self, case_id: str, case_metadata: Dict[str, Any]) -> None:
        """
        Update the shared case registry for Terminal/UI synchronization.
        This ensures 'use case <name>' works in the terminal.
        """
        registry = {"version": "1.0", "cases": {}}
        
        # Load existing registry
        if self.registry_path.exists():
            try:
                with open(self.registry_path, 'r', encoding='utf-8') as f:
                    registry = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        
        # Add/update case entry
        registry.setdefault("cases", {})[case_id] = {
            "name": case_metadata.get("case_name", case_id),
            "created": case_metadata.get("created_date", datetime.now().isoformat()),
            "path": str(self.base_cases_dir / case_id),
            "investigator": case_metadata.get("investigator", "N/A"),
            "status": case_metadata.get("status", "open")
        }
        registry["last_updated"] = datetime.now().isoformat()
        
        # Save registry
        with open(self.registry_path, 'w', encoding='utf-8') as f:
            json.dump(registry, f, indent=2)
        
        logger.info(f"Updated shared case registry with case: {case_id}")
    
    def create_case(
        self,
        case_id: str,
        case_name: str,
        investigator: str,
        image_path: str,
        precomputed_hash: Optional[str] = None,
        memory_dump_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a new forensic case with proper folder structure and metadata.
        
        Args:
            case_id: Unique identifier for the case (e.g., "CASE-2024-001")
            case_name: Descriptive name of the case
            investigator: Name of the investigator
            image_path: Path to the evidence image file (.E01, .dd, etc.)
            precomputed_hash: Optional pre-computed SHA-256 hash from evidence validator
                             (avoids double hashing - CRITICAL performance fix)
            memory_dump_path: Optional memory dump path associated with this case
        
        Returns:
            Dictionary containing case metadata
        
        Raises:
            ValueError: If case already exists or image path is invalid
            FileNotFoundError: If image file doesn't exist
        """
        # Validate inputs
        if not case_id or not case_id.strip():
            raise ValueError("Case ID cannot be empty")
        
        if not case_name or not case_name.strip():
            raise ValueError("Case Name cannot be empty")
        
        if not investigator or not investigator.strip():
            raise ValueError("Investigator Name cannot be empty")
        
        image_path_obj = Path(image_path)
        if not image_path_obj.exists():
            raise FileNotFoundError(f"Image file not found: {image_path}")
        
        # Check if case already exists
        case_dir = self.base_cases_dir / case_id
        if case_dir.exists():
            raise ValueError(f"Case '{case_id}' already exists")
        
        logger.info(f"Creating new case: {case_id}")
        
        # CRITICAL FIX: Wrap entire case creation in try-except with cleanup (HIGH-001)
        try:
            # Create case directory structure
            case_dir.mkdir(parents=True)
            artifacts_dir = case_dir / "artifacts"
            artifacts_dir.mkdir()
            
            logger.info(f"Created case directory: {case_dir}")
            
            # CRITICAL FIX: Use pre-computed hash if available (CRITICAL-002)
            if precomputed_hash:
                logger.info(f"Using pre-computed hash from evidence validator")
                image_hash = precomputed_hash
            else:
                logger.info(f"Calculating SHA-256 hash for: {image_path}")
                image_hash = self._calculate_file_hash(str(image_path))
                logger.info(f"Image hash calculated: {image_hash}")
            
            # Get file metadata
            image_size = image_path_obj.stat().st_size
            image_filename = image_path_obj.name
            
            # Create case metadata
            timestamp = datetime.now().isoformat()
            case_metadata = {
                "case_id": case_id,
                "case_name": case_name,
                "investigator": investigator,
                "created_date": timestamp,
                "last_modified": timestamp,
                "evidence_image": {
                    "path": str(image_path_obj.absolute()),
                    "filename": image_filename,
                    "size_bytes": image_size,
                    "sha256_hash": image_hash
                },
                "memory_dump": {
                    "path": str(Path(memory_dump_path).absolute()) if memory_dump_path else "",
                    "filename": Path(memory_dump_path).name if memory_dump_path else "",
                },
                "status": "open",
                "version": "1.0"
            }
            
            # Save case metadata to JSON
            case_json_path = case_dir / "case.json"
            with open(case_json_path, 'w', encoding='utf-8') as f:
                json.dump(case_metadata, f, indent=4)
            logger.info(f"Case metadata saved: {case_json_path}")
            
            # Initialize blockchain-style chain of custody
            chain_logger = ChainLogger(str(case_dir))
            chain_logger.append(
                user=investigator,
                action=CoC_Actions.CASE_CREATED,
                details=f"Case '{case_name}' created with evidence: {image_filename}"
            )
            
            # Log evidence verification
            chain_logger.append(
                user=investigator,
                action=CoC_Actions.EVIDENCE_VERIFIED,
                details=f"Evidence hash verified: {image_hash[:16]}... ({image_size} bytes)"
            )
            
            logger.info(f"Chain of custody initialized with {chain_logger.verify_chain()['total_entries']} entries")
            
            # Set as current case
            self.current_case = case_metadata
            self.case_path = case_dir
            
            # Update shared registry for Terminal/UI sync
            self._update_registry(case_id, case_metadata)
            
            logger.info(f"Case '{case_id}' created successfully")
            return case_metadata
            
        except Exception as e:
            # CRITICAL FIX: Cleanup on failure (HIGH-001)
            if case_dir.exists():
                import shutil
                shutil.rmtree(case_dir)
                logger.error(f"Case creation failed, cleaned up: {case_dir}")
            raise
    
    def open_case(self, case_dir_path: str) -> Dict[str, Any]:
        """
        Open an existing case and load its metadata.
        
        Args:
            case_dir_path: Path to the case directory
        
        Returns:
            Dictionary containing case metadata
        
        Raises:
            FileNotFoundError: If case directory or case.json doesn't exist
            ValueError: If case.json is invalid
        """
        case_dir = Path(case_dir_path)
        
        if not case_dir.exists():
            raise FileNotFoundError(f"Case directory not found: {case_dir_path}")
        
        case_json_path = case_dir / "case.json"
        if not case_json_path.exists():
            raise FileNotFoundError(f"case.json not found in: {case_dir_path}")
        
        logger.info(f"Opening case from: {case_dir_path}")
        
        # Load case metadata
        try:
            with open(case_json_path, 'r', encoding='utf-8') as f:
                case_metadata = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid case.json format: {e}")
        
        # Validate required fields
        required_fields = ["case_id", "case_name", "investigator", "evidence_image"]
        for field in required_fields:
            if field not in case_metadata:
                raise ValueError(f"Missing required field in case.json: {field}")
        
        # Update last modified timestamp
        case_metadata["last_modified"] = datetime.now().isoformat()
        with open(case_json_path, 'w', encoding='utf-8') as f:
            json.dump(case_metadata, f, indent=4)
        
        # Log to blockchain-style chain of custody
        chain_logger = ChainLogger(str(case_dir))
        chain_logger.append(
            user=case_metadata['investigator'],
            action=CoC_Actions.CASE_ACCESSED,
            details="Case opened for investigation"
        )
        
        # Set as current case
        self.current_case = case_metadata
        self.case_path = case_dir
        
        logger.info(f"Case '{case_metadata['case_id']}' opened successfully")
        return case_metadata
    
    def get_case_list(self) -> list:
        """
        Get list of all available cases.
        
        Returns:
            List of dictionaries containing case information
        """
        cases = []
        
        if not self.base_cases_dir.exists():
            return cases
        
        for case_dir in self.base_cases_dir.iterdir():
            if case_dir.is_dir():
                case_json_path = case_dir / "case.json"
                if case_json_path.exists():
                    try:
                        with open(case_json_path, 'r', encoding='utf-8') as f:
                            case_metadata = json.load(f)
                            cases.append({
                                "case_id": case_metadata.get("case_id", case_dir.name),
                                "case_name": case_metadata.get("case_name", case_dir.name),
                                "investigator": case_metadata.get("investigator", "N/A"),
                                "created_date": case_metadata.get("created_date", "N/A"),
                                "path": str(case_dir)
                            })
                    except Exception as e:
                        logger.warning(f"Failed to load case metadata from {case_dir}: {e}")
        
        return cases
    
    def log_chain_of_custody(self, user: str, event_type: str, description: str) -> None:
        """
        Log an event to the blockchain-style chain of custody.
        
        Args:
            user: Username performing the action
            event_type: Type of event (use CoC_Actions constants)
            description: Detailed description of the event
        """
        if not self.case_path:
            logger.warning("No active case for chain of custody logging")
            return
        
        chain_logger = ChainLogger(str(self.case_path))
        chain_logger.append(user=user, action=event_type, details=description)
        logger.debug(f"CoC logged: {event_type}")
    
    def _calculate_file_hash(self, file_path: str, algorithm: str = "sha256") -> str:
        """
        Calculate cryptographic hash of a file.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm (default: sha256)
        
        Returns:
            Hexadecimal hash string
        """
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            # Read file in chunks for memory efficiency
            chunk_size = 8192
            while chunk := f.read(chunk_size):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    def verify_chain_of_custody(self) -> Optional[Dict[str, Any]]:
        """
        Verify integrity of chain of custody for current case.
        
        Returns:
            Verification result dict or None if no active case
        """
        if not self.case_path:
            return None
        
        chain_logger = ChainLogger(str(self.case_path))
        return chain_logger.verify_chain()
    
    def get_current_case(self) -> Optional[Dict[str, Any]]:
        """Get the currently active case metadata."""
        return self.current_case
    
    def get_case_path(self) -> Optional[Path]:
        """Get the path to the currently active case directory."""
        return self.case_path
    
    def close_case(self) -> None:
        """Close the current case."""
        if self.current_case:
            case_id = self.current_case.get('case_id', 'N/A')
            investigator = self.current_case.get('investigator', 'N/A')
            logger.info(f"Closing case: {case_id}")
            
            # Log to blockchain-style chain of custody
            if self.case_path:
                chain_logger = ChainLogger(str(self.case_path))
                chain_logger.append(
                    user=investigator,
                    action="CASE_CLOSED",
                    details=f"Case {case_id} closed"
                )
            
            self.current_case = None
            self.case_path = None
