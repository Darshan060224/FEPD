"""
Chain of Custody Management Module
Maintains tamper-evident log of all forensic operations
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any
import logging


class ChainOfCustody:
    """
    Chain of Custody Logger - Forensic Grade
    
    Maintains an append-only, cryptographically linked log of all
    evidence handling operations for legal admissibility.
    """
    
    def __init__(self, config):
        """
        Initialize Chain of Custody logging.
        
        Args:
            config: Configuration object
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.enabled = config.get_bool('COC_ENABLED', True)
        
        # Get CoC log path
        self.log_path = config.get_path('COC_LOG_PATH', Path('logs/chain_of_custody.log'))
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Previous entry hash for chaining
        self.previous_hash: Optional[str] = None
        
        # Load existing chain
        self._load_existing_chain()
        
        if self.enabled:
            self.logger.info(f"Chain of Custody initialized: {self.log_path}")
    
    def _load_existing_chain(self):
        """Load existing chain to get last hash."""
        if not self.log_path.exists():
            return
        
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                if lines:
                    # Get last entry
                    last_entry = json.loads(lines[-1])
                    self.previous_hash = last_entry.get('entry_hash')
                    self.logger.info(f"Resuming chain from hash: {self.previous_hash[:16]}...")
        except Exception as e:
            self.logger.error(f"Failed to load existing chain: {e}")
    
    def log_event(
        self,
        event_type: str,
        description: str,
        hash_value: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        severity: str = "INFO"
    ) -> str:
        """
        Log a chain of custody event.
        
        Args:
            event_type: Type of event (IMAGE_INGESTED, ARTIFACT_EXTRACTED, etc.)
            description: Human-readable description
            hash_value: SHA-256 hash of evidence (if applicable)
            metadata: Additional structured data
            severity: Event severity (INFO, WARNING, ERROR, CRITICAL)
            
        Returns:
            Entry hash (cryptographic fingerprint of this entry)
        """
        if not self.enabled:
            return ""
        
        # Create CoC entry
        entry = {
            'coc_id': str(uuid.uuid4()),
            'timestamp_utc': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'description': description,
            'severity': severity,
            'hash_value': hash_value,
            'metadata': metadata or {},
            'previous_hash': self.previous_hash
        }
        
        # Compute entry hash (makes chain tamper-evident)
        entry_hash = self._compute_entry_hash(entry)
        entry['entry_hash'] = entry_hash
        
        # Write to append-only log
        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
            
            # Update chain
            self.previous_hash = entry_hash
            
            self.logger.debug(f"CoC logged: {event_type} - {entry_hash[:16]}...")
            return entry_hash
            
        except Exception as e:
            self.logger.error(f"Failed to write CoC entry: {e}")
            return ""
    
    def _compute_entry_hash(self, entry: Dict[str, Any]) -> str:
        """
        Compute SHA-256 hash of entry.
        
        Creates a cryptographic fingerprint that links this entry to the chain.
        Any tampering will break the chain verification.
        
        Args:
            entry: CoC entry dictionary
            
        Returns:
            SHA-256 hash (hex string)
        """
        # Create deterministic representation
        hash_input = (
            f"{entry['coc_id']}"
            f"{entry['timestamp_utc']}"
            f"{entry['event_type']}"
            f"{entry['description']}"
            f"{entry.get('hash_value', '')}"
            f"{json.dumps(entry.get('metadata', {}), sort_keys=True)}"
            f"{entry.get('previous_hash', '')}"
        )
        
        return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    
    def verify_chain(self) -> bool:
        """
        Verify integrity of entire chain of custody log.
        
        Recomputes all hashes and checks linkage.
        If any entry was tampered, verification fails.
        
        Returns:
            True if chain is intact, False if tampered
        """
        if not self.log_path.exists():
            self.logger.warning("No CoC log exists to verify")
            return True
        
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            previous_hash = None
            for i, line in enumerate(lines, 1):
                entry = json.loads(line)
                
                # Verify previous hash linkage
                if entry.get('previous_hash') != previous_hash:
                    self.logger.error(f"Chain broken at entry {i}: hash mismatch")
                    return False
                
                # Verify entry hash
                stored_hash = entry.pop('entry_hash')
                computed_hash = self._compute_entry_hash(entry)
                
                if stored_hash != computed_hash:
                    self.logger.error(f"Entry {i} tampered: hash mismatch")
                    return False
                
                previous_hash = stored_hash
            
            self.logger.info(f"Chain of custody verified: {len(lines)} entries intact")
            return True
            
        except Exception as e:
            self.logger.error(f"Chain verification failed: {e}")
            return False
    
    def export_coc(self, output_path: Path) -> bool:
        """
        Export chain of custody log to separate file.
        
        Args:
            output_path: Destination file path
            
        Returns:
            True if exported successfully
        """
        try:
            if not self.log_path.exists():
                self.logger.warning("No CoC log to export")
                return False
            
            # Copy log file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, 'r', encoding='utf-8') as src:
                with open(output_path, 'w', encoding='utf-8') as dst:
                    dst.write(src.read())
            
            self.logger.info(f"CoC exported to: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export CoC: {e}")
            return False

    @property
    def log(self):
        """Return the list of CoC entries as dictionaries."""
        if not self.log_path.exists():
            return []
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                return [json.loads(line) for line in f.readlines() if line.strip()]
        except Exception:
            return []

    def log_entry(self, event: str, hash_value: Optional[str] = None, reason: str = "", metadata: Optional[Dict[str, Any]] = None, severity: str = "INFO") -> str:
        """Backward-compatible wrapper for older API naming (log_entry -> log_event).

        Many modules historically used `log_entry(...)`. Keep that API to avoid
        widespread changes and forward to the new `log_event` method.
        """
        return self.log_event(event_type=event, description=reason, hash_value=hash_value, metadata=metadata, severity=severity)
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of chain of custody log.
        
        Returns:
            Dictionary with statistics
        """
        if not self.log_path.exists():
            return {'total_entries': 0, 'chain_valid': None}
        
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                entries = [json.loads(line) for line in f]
            
            # Count by event type
            event_counts = {}
            for entry in entries:
                event_type = entry['event_type']
                event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            return {
                'total_entries': len(entries),
                'first_entry': entries[0]['timestamp_utc'] if entries else None,
                'last_entry': entries[-1]['timestamp_utc'] if entries else None,
                'event_counts': event_counts,
                'chain_valid': self.verify_chain()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get CoC summary: {e}")
            return {'error': str(e)}
