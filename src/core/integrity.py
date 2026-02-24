"""
FEPD - Forensic Integrity Verification
========================================
SHA-256 hashing, integrity verification, and chain of custody tracking.

Principles:
- All evidence is hashed on upload
- Hashes are verified before processing
- Evidence files are read-only
- All operations are logged for chain of custody

Copyright (c) 2026 FEPD Development Team
"""

import hashlib
import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict
import shutil


@dataclass
class IntegrityRecord:
    """Record of file integrity check"""
    file_path: str
    sha256: str
    size_bytes: int
    timestamp: str
    verified: bool
    operation: str  # "upload", "verify", "process"
    operator: str
    notes: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


class IntegrityManager:
    """
    Manages forensic integrity of evidence files.
    
    Responsibilities:
    - Calculate SHA-256 hashes
    - Verify file integrity
    - Track chain of custody
    - Enforce read-only evidence
    - Maintain audit logs
    """
    
    def __init__(self, case_path: Path, operator: str = "system", logger: Optional[logging.Logger] = None):
        self.case_path = Path(case_path)
        self.operator = operator
        self.logger = logger or logging.getLogger(__name__)
        
        # Create integrity tracking directory
        self.integrity_path = self.case_path / "integrity"
        self.integrity_path.mkdir(parents=True, exist_ok=True)
        
        # Integrity log file
        self.log_file = self.integrity_path / "integrity_log.jsonl"
    
    def hash_file(self, file_path: Path, algorithm: str = "sha256") -> str:
        """
        Calculate cryptographic hash of file.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, sha1, md5)
            
        Returns:
            Hexadecimal hash string
        """
        if algorithm == "sha256":
            hasher = hashlib.sha256()
        elif algorithm == "sha1":
            hasher = hashlib.sha1()
        elif algorithm == "md5":
            hasher = hashlib.md5()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        self.logger.info(f"Calculating {algorithm.upper()} hash: {file_path.name}")
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(1048576):  # 1MB chunks
                hasher.update(chunk)
        
        hash_value = hasher.hexdigest()
        self.logger.info(f"{algorithm.upper()}: {hash_value}")
        
        return hash_value
    
    def register_evidence(self, file_path: Path, operation: str = "upload", notes: str = "") -> IntegrityRecord:
        """
        Register new evidence file and calculate initial hash.
        
        Args:
            file_path: Path to evidence file
            operation: Type of operation (upload, import, extract)
            notes: Additional notes
            
        Returns:
            IntegrityRecord with hash and metadata
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Evidence file not found: {file_path}")
        
        # Calculate SHA-256
        sha256 = self.hash_file(file_path, "sha256")
        
        # Get file size
        size_bytes = file_path.stat().st_size
        
        # Create integrity record
        record = IntegrityRecord(
            file_path=str(file_path),
            sha256=sha256,
            size_bytes=size_bytes,
            timestamp=datetime.now().isoformat(),
            verified=True,
            operation=operation,
            operator=self.operator,
            notes=notes
        )
        
        # Log to integrity file
        self._log_record(record)
        
        # Save hash file alongside evidence
        self._save_hash_file(file_path, sha256)
        
        # Make evidence read-only (forensic best practice)
        self._make_readonly(file_path)
        
        self.logger.info(f"✓ Evidence registered: {file_path.name}")
        self.logger.info(f"  SHA-256: {sha256}")
        self.logger.info(f"  Size: {size_bytes:,} bytes")
        
        return record
    
    def verify_integrity(self, file_path: Path, expected_hash: Optional[str] = None) -> bool:
        """
        Verify file integrity by comparing current hash with expected hash.
        
        Args:
            file_path: Path to file
            expected_hash: Expected SHA-256 hash (if None, loads from .sha256 file)
            
        Returns:
            True if integrity verified, False otherwise
        """
        if not file_path.exists():
            self.logger.error(f"File not found for verification: {file_path}")
            return False
        
        # Calculate current hash
        current_hash = self.hash_file(file_path, "sha256")
        
        # Get expected hash
        if expected_hash is None:
            hash_file = file_path.with_suffix(file_path.suffix + '.sha256')
            if hash_file.exists():
                expected_hash = hash_file.read_text().strip().split()[0]
            else:
                self.logger.warning(f"No hash file found: {hash_file}")
                return False
        
        # Compare hashes
        verified = current_hash.lower() == expected_hash.lower()
        
        # Log verification
        record = IntegrityRecord(
            file_path=str(file_path),
            sha256=current_hash,
            size_bytes=file_path.stat().st_size,
            timestamp=datetime.now().isoformat(),
            verified=verified,
            operation="verify",
            operator=self.operator,
            notes=f"Expected: {expected_hash}" if not verified else "Integrity confirmed"
        )
        self._log_record(record)
        
        if verified:
            self.logger.info(f"✓ Integrity verified: {file_path.name}")
        else:
            self.logger.error(f"✗ INTEGRITY FAILURE: {file_path.name}")
            self.logger.error(f"  Expected: {expected_hash}")
            self.logger.error(f"  Current:  {current_hash}")
        
        return verified
    
    def get_integrity_log(self) -> List[IntegrityRecord]:
        """
        Retrieve all integrity records for case.
        
        Returns:
            List of IntegrityRecord objects
        """
        if not self.log_file.exists():
            return []
        
        records = []
        with open(self.log_file, 'r') as f:
            for line in f:
                data = json.loads(line)
                records.append(IntegrityRecord(**data))
        
        return records
    
    def export_chain_of_custody(self, output_path: Optional[Path] = None) -> Path:
        """
        Export complete chain of custody report.
        
        Args:
            output_path: Where to save report (defaults to case integrity folder)
            
        Returns:
            Path to generated report
        """
        if output_path is None:
            output_path = self.integrity_path / f"chain_of_custody_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        records = self.get_integrity_log()
        
        report = {
            "case_path": str(self.case_path),
            "generated": datetime.now().isoformat(),
            "total_operations": len(records),
            "records": [r.to_dict() for r in records]
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Chain of custody exported: {output_path}")
        
        return output_path
    
    def _log_record(self, record: IntegrityRecord):
        """Append integrity record to log file"""
        with open(self.log_file, 'a') as f:
            f.write(record.to_json() + '\n')
    
    def _save_hash_file(self, file_path: Path, sha256: str):
        """Save hash to .sha256 file alongside evidence"""
        hash_file = file_path.with_suffix(file_path.suffix + '.sha256')
        with open(hash_file, 'w') as f:
            f.write(f"{sha256}  {file_path.name}\n")
    
    def _make_readonly(self, file_path: Path):
        """Make file read-only (forensic best practice)"""
        import stat
        
        # Get current permissions
        current_mode = file_path.stat().st_mode
        
        # Remove write permissions
        readonly_mode = current_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH
        
        # Apply read-only permissions
        file_path.chmod(readonly_mode)
        
        self.logger.debug(f"Set read-only: {file_path.name}")


class SecureEvidenceStorage:
    """
    Manages secure storage of evidence in dataa/incoming.
    
    Features:
    - Immutable storage
    - Automatic hashing
    - Chain of custody
    - Read-only enforcement
    """
    
    def __init__(self, storage_path: Path = None, logger: Optional[logging.Logger] = None):
        self.storage_path = Path(storage_path or "dataa/incoming")
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.logger = logger or logging.getLogger(__name__)
    
    def store_evidence(self, source_path: Path, case_id: str, operator: str = "system") -> Dict:
        """
        Store evidence file in secure incoming storage.
        
        Args:
            source_path: Path to evidence file to store
            case_id: Case identifier
            operator: Who uploaded the evidence
            
        Returns:
            Dictionary with storage details
        """
        if not source_path.exists():
            raise FileNotFoundError(f"Source evidence not found: {source_path}")
        
        # Create case folder in incoming
        case_folder = self.storage_path / case_id
        case_folder.mkdir(exist_ok=True)
        
        # Generate unique filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dest_name = f"{timestamp}_{source_path.name}"
        dest_path = case_folder / dest_name
        
        self.logger.info(f"Storing evidence: {source_path.name}")
        self.logger.info(f"Destination: {dest_path}")
        
        # Copy file to secure storage
        shutil.copy2(source_path, dest_path)
        
        # Initialize integrity manager for this case
        integrity_mgr = IntegrityManager(case_folder, operator, self.logger)
        
        # Register evidence and calculate hash
        record = integrity_mgr.register_evidence(
            dest_path,
            operation="upload",
            notes=f"Uploaded from: {source_path}"
        )
        
        return {
            "success": True,
            "stored_path": str(dest_path),
            "sha256": record.sha256,
            "size_bytes": record.size_bytes,
            "timestamp": record.timestamp,
            "case_id": case_id
        }


if __name__ == "__main__":
    # Test integrity management
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) > 1:
        test_file = Path(sys.argv[1])
        
        # Test hashing
        mgr = IntegrityManager(Path("test_case"))
        record = mgr.register_evidence(test_file, operation="test")
        
        print(f"\n=== Integrity Record ===")
        print(record.to_json())
        
        # Test verification
        verified = mgr.verify_integrity(test_file)
        print(f"\nVerification: {'PASS' if verified else 'FAIL'}")
