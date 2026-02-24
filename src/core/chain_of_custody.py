"""
Chain of Custody - File-Based Tamper-Evident Ledger

Blockchain-like append-only logging system for forensic actions.
Each entry contains hash of previous entry, creating verifiable chain.
"""

import json
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any


class ChainOfCustodyError(Exception):
    """Chain of custody verification or operation error"""
    pass


class ChainLogger:
    """
    Append-only ledger for forensic chain of custody.
    
    Features:
    - Hash chaining (each entry hashes previous entry)
    - Tamper detection
    - Blockchain-like immutability
    - Court-defensible audit trail
    """
    
    def __init__(self, case_path: str):
        """
        Initialize chain logger for a case.
        
        Args:
            case_path: Absolute path to case directory
        """
        self.case_path = Path(case_path)
        self.log_file = self.case_path / "chain_of_custody.log"
        
        # Ensure case directory exists
        self.case_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize log file if it doesn't exist
        if not self.log_file.exists():
            self._initialize_log()
    
    def _initialize_log(self):
        """Create initial genesis entry"""
        genesis = {
            "id": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": "SYSTEM",
            "action": "CHAIN_INITIALIZED",
            "details": f"Chain of custody initialized for {self.case_path.name}",
            "prev_hash": "0" * 64,  # Genesis has no previous hash
            "self_hash": ""
        }
        
        # Compute self hash
        genesis["self_hash"] = self._compute_entry_hash(genesis)
        
        # Write genesis entry
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write(json.dumps(genesis) + "\n")
    
    def _compute_entry_hash(self, entry: Dict[str, Any]) -> str:
        """
        Compute SHA-256 hash of an entry.
        
        Args:
            entry: Entry dictionary (self_hash should be empty string)
        
        Returns:
            64-character hex hash
        """
        # Create canonical JSON (sorted keys, no whitespace)
        entry_copy = entry.copy()
        entry_copy["self_hash"] = ""  # Exclude self_hash from computation
        
        canonical = json.dumps(entry_copy, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    
    def _get_last_entry(self) -> Optional[Dict[str, Any]]:
        """
        Get the last entry in the chain.
        
        Returns:
            Last entry dict or None if only genesis exists
        """
        if not self.log_file.exists():
            return None
        
        with open(self.log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        if not lines:
            return None
        
        return json.loads(lines[-1].strip())
    
    def append(self, user: str, action: str, details: str) -> int:
        """
        Append a new entry to the chain.
        
        Args:
            user: Username performing the action
            action: Action type (e.g., EVIDENCE_IMPORTED, ARTIFACT_EXTRACTED)
            details: Human-readable description of the action
        
        Returns:
            Entry ID
        
        Raises:
            ChainOfCustodyError: If chain is broken or file is corrupted
        """
        # Get last entry
        last_entry = self._get_last_entry()
        
        if last_entry is None:
            raise ChainOfCustodyError("Chain not initialized")
        
        # Create new entry
        new_entry = {
            "id": last_entry["id"] + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": user,
            "action": action,
            "details": details,
            "prev_hash": last_entry["self_hash"],
            "self_hash": ""
        }
        
        # Compute self hash
        new_entry["self_hash"] = self._compute_entry_hash(new_entry)
        
        # Append to file
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(new_entry) + "\n")
        
        return new_entry["id"]
    
    def verify_chain(self) -> Dict[str, Any]:
        """
        Verify integrity of the entire chain.
        
        Returns:
            {
                "valid": bool,
                "total_entries": int,
                "first_action": str,
                "last_action": str,
                "broken_at": int or None,
                "error": str or None
            }
        """
        if not self.log_file.exists():
            return {
                "valid": False,
                "total_entries": 0,
                "first_action": None,
                "last_action": None,
                "broken_at": None,
                "error": "Chain file does not exist"
            }
        
        with open(self.log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        if not lines:
            return {
                "valid": False,
                "total_entries": 0,
                "first_action": None,
                "last_action": None,
                "broken_at": None,
                "error": "Chain file is empty"
            }
        
        entries = []
        for line in lines:
            try:
                entries.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                return {
                    "valid": False,
                    "total_entries": len(entries),
                    "first_action": entries[0]["action"] if entries else None,
                    "last_action": None,
                    "broken_at": len(entries),
                    "error": f"Invalid JSON at entry {len(entries)}"
                }
        
        # Verify each entry
        for i, entry in enumerate(entries):
            # Verify self hash
            expected_hash = self._compute_entry_hash(entry)
            if entry["self_hash"] != expected_hash:
                return {
                    "valid": False,
                    "total_entries": len(entries),
                    "first_action": entries[0]["action"],
                    "last_action": entries[i-1]["action"] if i > 0 else None,
                    "broken_at": i,
                    "error": f"Hash mismatch at entry {i}: expected {expected_hash}, found {entry['self_hash']}"
                }
            
            # Verify prev_hash links to previous entry
            if i > 0:
                expected_prev = entries[i-1]["self_hash"]
                if entry["prev_hash"] != expected_prev:
                    return {
                        "valid": False,
                        "total_entries": len(entries),
                        "first_action": entries[0]["action"],
                        "last_action": entries[i-1]["action"],
                        "broken_at": i,
                        "error": f"Chain broken at entry {i}: expected prev_hash {expected_prev}, found {entry['prev_hash']}"
                    }
        
        return {
            "valid": True,
            "total_entries": len(entries),
            "first_action": entries[0]["action"],
            "last_action": entries[-1]["action"],
            "broken_at": None,
            "error": None
        }
    
    def get_entries(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get all entries in the chain.
        
        Args:
            limit: Maximum number of entries to return (most recent first)
        
        Returns:
            List of entry dictionaries
        """
        if not self.log_file.exists():
            return []
        
        with open(self.log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        entries = [json.loads(line.strip()) for line in lines if line.strip()]
        
        if limit:
            entries = entries[-limit:]
        
        return entries
    
    def export_chain_hash(self) -> str:
        """
        Compute hash of entire chain file.
        Used for sealed case transfers.
        
        Returns:
            SHA-256 hex hash of chain file
        """
        if not self.log_file.exists():
            return "0" * 64
        
        with open(self.log_file, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    def get_summary(self) -> str:
        """
        Get human-readable summary of the chain.
        
        Returns:
            Multi-line summary string
        """
        result = self.verify_chain()
        
        if not result["valid"]:
            return f"""[ERROR] Chain broken at entry #{result['broken_at']}
{result['error']}
Total entries: {result['total_entries']}
"""
        
        entries = self.get_entries()
        
        summary = f"""[OK] Chain intact.
Entries: {result['total_entries']}
First: {result['first_action']}
Last: {result['last_action']}
Chain Hash: {self.export_chain_hash()[:16]}...
"""
        
        # Add last 5 actions
        if len(entries) > 1:
            summary += "\nRecent Actions:\n"
            for entry in entries[-5:]:
                summary += f"  [{entry['id']}] {entry['timestamp'][:19]} | {entry['user']} | {entry['action']}\n"
        
        return summary


# Action type constants
class CoC_Actions:
    """Standard chain of custody action types"""
    # Chain management
    CHAIN_INITIALIZED = "CHAIN_INITIALIZED"
    
    # Case lifecycle
    CASE_CREATED = "CASE_CREATED"
    CASE_ACCESSED = "CASE_ACCESSED"
    CASE_EXPORTED = "CASE_EXPORTED"
    CASE_IMPORTED = "CASE_IMPORTED"
    CASE_SEALED = "CASE_SEALED"
    CASE_ERROR = "CASE_ERROR"
    
    # Evidence handling
    EVIDENCE_IMPORTED = "EVIDENCE_IMPORTED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    EVIDENCE_MOUNTED = "EVIDENCE_MOUNTED"
    EVIDENCE_HASH_VERIFIED = "EVIDENCE_HASH_VERIFIED"
    
    # Pipeline phases
    PIPELINE_STARTED = "PIPELINE_STARTED"
    PIPELINE_STEP_STARTED = "PIPELINE_STEP_STARTED"
    PIPELINE_STEP_COMPLETED = "PIPELINE_STEP_COMPLETED"
    PIPELINE_ERROR = "PIPELINE_ERROR"
    PIPELINE_COMPLETE = "PIPELINE_COMPLETE"
    
    # Artifact processing
    ARTIFACT_DISCOVERED = "ARTIFACT_DISCOVERED"
    ARTIFACT_EXTRACTED = "ARTIFACT_EXTRACTED"
    ARTIFACT_PARSED = "ARTIFACT_PARSED"
    
    # Analysis
    ML_ANALYSIS_START = "ML_ANALYSIS_START"
    ML_ANALYSIS_COMPLETE = "ML_ANALYSIS_COMPLETE"
    UEBA_ANALYSIS_START = "UEBA_ANALYSIS_START"
    UEBA_ANALYSIS_COMPLETE = "UEBA_ANALYSIS_COMPLETE"
    TIMELINE_BUILT = "TIMELINE_BUILT"
    
    # Memory Analysis
    MEMORY_ANALYSIS_START = "MEMORY_ANALYSIS_START"
    MEMORY_ANALYSIS_COMPLETE = "MEMORY_ANALYSIS_COMPLETE"
    MEMORY_PROCESSES_FOUND = "MEMORY_PROCESSES_FOUND"
    MEMORY_NETWORK_FOUND = "MEMORY_NETWORK_FOUND"
    MEMORY_STRINGS_EXTRACTED = "MEMORY_STRINGS_EXTRACTED"
    
    # Reporting
    REPORT_GENERATED = "REPORT_GENERATED"
    VISUALIZATION_GENERATED = "VISUALIZATION_GENERATED"
    
    # User actions
    USER_CHANGED = "USER_CHANGED"
    QUERY_EXECUTED = "QUERY_EXECUTED"
    TERMINAL_COMMAND = "TERMINAL_COMMAND"

