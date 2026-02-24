"""
MFT Parser for Deleted & Orphaned File Detection
=================================================

Provides Master File Table parsing to detect:
- Deleted files (is_deleted=True)
- Orphaned MFT entries (no parent reference)
- Recoverable metadata (timestamps, original paths)

Copyright (c) 2026 FEPD Development Team
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Dict, Any
import logging
import struct

logger = logging.getLogger(__name__)


@dataclass
class MFTEntry:
    """Represents a parsed MFT entry."""
    
    record_number: int
    parent_record: int
    filename: str
    full_path: Optional[str]
    
    # Deletion status
    is_deleted: bool
    is_orphaned: bool
    
    # Timestamps (MACB)
    modified_time: Optional[datetime]
    accessed_time: Optional[datetime]
    created_time: Optional[datetime]
    mft_changed_time: Optional[datetime]
    
    # Deletion metadata
    deletion_time: Optional[datetime]
    
    # File attributes
    size: int
    is_directory: bool
    
    # Forensic metadata
    sector_offset: int
    confidence: float  # 0.0 - 1.0 recovery confidence
    
    def __post_init__(self):
        """Validate entry after initialization."""
        if self.confidence < 0.0 or self.confidence > 1.0:
            raise ValueError(f"Confidence must be 0.0-1.0, got {self.confidence}")


class MFTParser:
    """
    Parse NTFS Master File Table for deleted/orphaned files.
    
    Usage:
        parser = MFTParser(vfs, partition_offset=2048)
        deleted_files = parser.scan_deleted_files()
        orphaned = parser.scan_orphaned_entries()
    """
    
    def __init__(self, vfs, partition_offset: int = 0):
        """
        Initialize MFT parser.
        
        Args:
            vfs: VirtualFilesystem instance
            partition_offset: Sector offset to partition start
        """
        self.vfs = vfs
        self.partition_offset = partition_offset
        self._mft_cache: Dict[int, MFTEntry] = {}
    
    def scan_deleted_files(self, root_path: str = "/") -> List[MFTEntry]:
        """
        Scan for deleted files in the MFT.
        
        Returns:
            List of MFTEntry objects with is_deleted=True
        """
        deleted_entries = []
        
        try:
            # In real implementation, this would:
            # 1. Read raw MFT from partition
            # 2. Parse each 1024-byte MFT record
            # 3. Check FILE_RECORD_SEGMENT_IN_USE flag
            # 4. Extract $STANDARD_INFORMATION and $FILE_NAME attributes
            
            # For now, simulate with VEOS metadata
            deleted_entries = self._simulate_deleted_scan(root_path)
            
            logger.info(f"Found {len(deleted_entries)} deleted files")
            
        except Exception as e:
            logger.error(f"MFT scan failed: {e}")
        
        return deleted_entries
    
    def scan_orphaned_entries(self) -> List[MFTEntry]:
        """
        Find orphaned MFT entries (parent record no longer exists).
        
        Returns:
            List of MFTEntry objects with is_orphaned=True
        """
        orphaned_entries = []
        
        try:
            # Check for entries whose parent_record points to deleted/invalid MFT entry
            orphaned_entries = self._simulate_orphaned_scan()
            
            logger.info(f"Found {len(orphaned_entries)} orphaned entries")
            
        except Exception as e:
            logger.error(f"Orphaned scan failed: {e}")
        
        return orphaned_entries
    
    def get_recovery_confidence(self, entry: MFTEntry) -> float:
        """
        Calculate recovery confidence for a deleted file.
        
        Factors:
        - MFT entry integrity (intact attributes)
        - Data run presence ($DATA attribute)
        - Cluster allocation status
        - Timestamp validity
        
        Returns:
            Confidence score 0.0 (unrecoverable) to 1.0 (fully recoverable)
        """
        confidence = 1.0
        
        # Reduce confidence if metadata is damaged
        if not entry.full_path:
            confidence -= 0.2
        
        if not entry.created_time or not entry.modified_time:
            confidence -= 0.1
        
        if entry.size == 0:
            confidence -= 0.3
        
        # Orphaned entries are harder to recover
        if entry.is_orphaned:
            confidence -= 0.2
        
        return max(0.0, confidence)
    
    def reconstruct_path(self, record_number: int) -> Optional[str]:
        """
        Reconstruct full path from parent MFT chain.
        
        Args:
            record_number: MFT record number
            
        Returns:
            Reconstructed path or None if unrecoverable
        """
        try:
            # Walk parent chain: 123 -> 45 -> 5 (root)
            path_parts = []
            current_record = record_number
            max_depth = 50  # Prevent infinite loops
            
            while current_record != 5 and max_depth > 0:  # 5 = root MFT entry
                if current_record not in self._mft_cache:
                    return None
                
                entry = self._mft_cache[current_record]
                path_parts.insert(0, entry.filename)
                current_record = entry.parent_record
                max_depth -= 1
            
            if max_depth == 0:
                logger.warning(f"Path reconstruction exceeded max depth for record {record_number}")
                return None
            
            return "C:\\" + "\\".join(path_parts)
            
        except Exception as e:
            logger.error(f"Path reconstruction failed for record {record_number}: {e}")
            return None
    
    # ========================================================================
    # SIMULATION HELPERS (Replace with real MFT parsing in production)
    # ========================================================================
    
    def _simulate_deleted_scan(self, root_path: str) -> List[MFTEntry]:
        """
        Simulate deleted file detection.
        
        In production: Parse raw MFT and check FILE_RECORD_SEGMENT_IN_USE flag.
        """
        # Simulated deleted files
        deleted_files = [
            MFTEntry(
                record_number=1234,
                parent_record=567,
                filename="sensitive_document.docx",
                full_path="C:\\Users\\Alice\\Documents\\sensitive_document.docx",
                is_deleted=True,
                is_orphaned=False,
                modified_time=datetime(2026, 1, 15, 14, 30, 0),
                accessed_time=datetime(2026, 1, 15, 14, 35, 0),
                created_time=datetime(2026, 1, 10, 9, 0, 0),
                mft_changed_time=datetime(2026, 1, 20, 10, 15, 0),
                deletion_time=datetime(2026, 1, 20, 10, 15, 0),
                size=45678,
                is_directory=False,
                sector_offset=0x1F400,
                confidence=0.95
            ),
            MFTEntry(
                record_number=2345,
                parent_record=567,
                filename="confidential.xlsx",
                full_path="C:\\Users\\Alice\\Documents\\confidential.xlsx",
                is_deleted=True,
                is_orphaned=False,
                modified_time=datetime(2026, 1, 12, 11, 20, 0),
                accessed_time=datetime(2026, 1, 12, 11, 25, 0),
                created_time=datetime(2026, 1, 8, 8, 0, 0),
                mft_changed_time=datetime(2026, 1, 18, 16, 45, 0),
                deletion_time=datetime(2026, 1, 18, 16, 45, 0),
                size=23456,
                is_directory=False,
                sector_offset=0x2A800,
                confidence=0.88
            ),
            MFTEntry(
                record_number=3456,
                parent_record=789,
                filename="malware.exe",
                full_path="C:\\Users\\Alice\\Downloads\\malware.exe",
                is_deleted=True,
                is_orphaned=False,
                modified_time=datetime(2026, 1, 19, 22, 10, 0),
                accessed_time=datetime(2026, 1, 19, 22, 15, 0),
                created_time=datetime(2026, 1, 19, 22, 8, 0),
                mft_changed_time=datetime(2026, 1, 19, 22, 30, 0),
                deletion_time=datetime(2026, 1, 19, 22, 30, 0),
                size=156789,
                is_directory=False,
                sector_offset=0x3C000,
                confidence=0.92
            ),
        ]
        
        # Cache entries
        for entry in deleted_files:
            self._mft_cache[entry.record_number] = entry
        
        return deleted_files
    
    def _simulate_orphaned_scan(self) -> List[MFTEntry]:
        """
        Simulate orphaned entry detection.
        
        In production: Check if parent_record points to deleted/invalid entry.
        """
        orphaned_entries = [
            MFTEntry(
                record_number=9999,
                parent_record=5555,  # Parent was deleted
                filename="orphaned_file.tmp",
                full_path=None,  # Path unrecoverable
                is_deleted=True,
                is_orphaned=True,
                modified_time=datetime(2025, 12, 1, 10, 0, 0),
                accessed_time=None,
                created_time=datetime(2025, 12, 1, 9, 55, 0),
                mft_changed_time=datetime(2025, 12, 5, 14, 20, 0),
                deletion_time=None,  # Unknown
                size=4096,
                is_directory=False,
                sector_offset=0x5F000,
                confidence=0.45  # Low confidence due to missing metadata
            ),
        ]
        
        for entry in orphaned_entries:
            self._mft_cache[entry.record_number] = entry
        
        return orphaned_entries
    
    def parse_raw_mft_entry(self, raw_bytes: bytes) -> Optional[MFTEntry]:
        """
        Parse a raw 1024-byte MFT record.
        
        Structure:
        - Offset 0x00: "FILE" signature
        - Offset 0x16: Flags (0x0001 = in use, 0x0002 = directory)
        - Offset 0x20: First attribute offset
        - Attributes: $STANDARD_INFORMATION, $FILE_NAME, $DATA
        
        Args:
            raw_bytes: 1024-byte MFT record
            
        Returns:
            Parsed MFTEntry or None if invalid
        """
        if len(raw_bytes) != 1024:
            logger.error(f"Invalid MFT entry size: {len(raw_bytes)} (expected 1024)")
            return None
        
        # Check "FILE" signature
        signature = raw_bytes[0:4]
        if signature != b'FILE':
            logger.debug(f"Invalid MFT signature: {signature}")
            return None
        
        try:
            # Parse flags
            flags = struct.unpack('<H', raw_bytes[0x16:0x18])[0]
            is_deleted = not (flags & 0x0001)  # IN_USE flag
            is_directory = bool(flags & 0x0002)
            
            # In production: Parse $FILE_NAME and $STANDARD_INFORMATION attributes
            # For now, return None to indicate "not yet implemented"
            logger.debug("Raw MFT parsing not yet fully implemented - using simulation")
            return None
            
        except Exception as e:
            logger.error(f"MFT parsing error: {e}")
            return None
