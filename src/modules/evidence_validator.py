"""
FEPD - Evidence Validator Module
Multi-part forensic image detection and validation

Handles:
- Single file evidence validation (.img, .dd, .mem, .dmp, .raw, .aff, .log, .zip)
- Multi-part forensic image detection (E01, E02, E03...)
- Naming pattern detection and validation
- Sequence continuity verification
- Evidence integrity checking

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import re
import logging
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone

from src.core.forensic_audit_logger import ForensicAuditLogger, AuditEventType


logger = logging.getLogger(__name__)

# E01 File Format Magic Bytes
E01_MAGIC_BYTES = b'EVF\x09\x0d\x0a\xff\x00'  # EnCase Evidence File Format
L01_MAGIC_BYTES = b'LEF'  # Logical Evidence File (first 3 bytes)


class EvidenceType(Enum):
    """Evidence type classification."""
    SINGLE = "single"                    # Single file evidence
    MULTI_PART_DISK = "multi_part_disk"  # Multi-part disk image (E01, E02, ...)
    UNKNOWN = "unknown"


class EvidenceFormat(Enum):
    """Supported evidence formats."""
    # Single file formats
    RAW = "raw"          # .img, .dd, .raw
    MEMORY = "memory"    # .mem, .dmp
    AFF = "aff"          # Advanced Forensic Format
    LOG = "log"          # Log file
    ARCHIVE = "archive"  # .zip
    
    # Multi-part formats
    E01_MULTI = "E01_MULTI"  # Expert Witness Format (EnCase) - multi-part
    L01_MULTI = "L01_MULTI"  # Logical Evidence File - multi-part
    
    UNKNOWN = "unknown"


@dataclass
class EvidenceSegment:
    """Represents a single segment of a multi-part image."""
    path: Path
    sequence_number: int
    extension: str
    size_bytes: int
    sha256_hash: Optional[str] = None
    validated_at: Optional[str] = None
    file_mtime: Optional[float] = None


@dataclass
class EvidenceObject:
    """
    Unified representation of forensic evidence.
    Can represent either single file or multi-part image.
    """
    id: str                                  # Base name (e.g., "LoneWolf")
    type: EvidenceType
    format: EvidenceFormat
    
    # Single file evidence
    single_path: Optional[Path] = None
    
    # Multi-part evidence
    parts: Optional[List[EvidenceSegment]] = None
    base_name: Optional[str] = None
    total_parts: int = 0
    total_size_bytes: int = 0
    
    # Validation
    is_complete: bool = False
    missing_parts: Optional[List[int]] = None
    integrity_verified: bool = False
    validation_timestamp: Optional[str] = None
    
    def __post_init__(self):
        """Initialize default values."""
        if self.parts is None:
            self.parts = []
        if self.missing_parts is None:
            self.missing_parts = []
    
    def get_primary_path(self) -> Path:
        """
        Get the primary path for this evidence.
        For single files: returns the file path
        For multi-part: returns the first part (E01)
        """
        if self.type == EvidenceType.SINGLE:
            return self.single_path
        elif self.type == EvidenceType.MULTI_PART_DISK:
            if self.parts:
                return self.parts[0].path
        return None
    
    def get_all_paths(self) -> List[Path]:
        """
        Get all file paths associated with this evidence.
        """
        if self.type == EvidenceType.SINGLE:
            return [self.single_path] if self.single_path else []
        elif self.type == EvidenceType.MULTI_PART_DISK:
            return [part.path for part in self.parts] if self.parts else []
        return []
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            'id': self.id,
            'type': self.type.value,
            'format': self.format.value,
            'single_path': str(self.single_path) if self.single_path else None,
            'parts': [
                {
                    'path': str(part.path),
                    'sequence': part.sequence_number,
                    'extension': part.extension,
                    'size': part.size_bytes
                }
                for part in self.parts
            ] if self.parts else [],
            'base_name': self.base_name,
            'total_parts': self.total_parts,
            'total_size_bytes': self.total_size_bytes,
            'is_complete': self.is_complete,
            'missing_parts': self.missing_parts,
            'integrity_verified': self.integrity_verified
        }


class EvidenceValidator:
    """
    Validates and classifies forensic evidence.
    Handles both single files and multi-part forensic images.
    
    Comprehensive support for:
    - Disk Images: E01, DD, RAW, IMG, AFF, VMDK, VHD, VHDX, QCOW2
    - Memory Dumps: MEM, DMP, RAW, DUMP, MEMORY, HIBERFIL, PAGEFILE
    - Mobile: TAR, AB (Android Backup), UFED, GrayKey, Cellebrite
    - Archives: ZIP, 7Z, RAR, TAR, GZ, BZ2, XZ
    - Logs: LOG, EVT, EVTX, PCAP, PCAPNG
    - Documents: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX
    - Email: PST, OST, MBOX, EML, MSG
    - Database: DB, SQLITE, MDB, ACCDB
    - Registry: REG, DAT (NTUSER.DAT, SAM, SYSTEM, etc.)
    - Browser: SQLITE (History, Cookies, etc.)
    - Other: BIN, ISO, DMG
    """
    
    # Supported single file extensions - COMPREHENSIVE FORENSIC FORMATS
    SINGLE_FILE_EXTENSIONS = {
        # Disk Image Formats
        '.e01', '.e02',     # EnCase (can be single or multi-part)
        '.img', '.dd', '.raw', '.bin', '.iso', '.dmg',
        '.aff', '.aff4',  # Advanced Forensic Format
        '.vmdk',          # VMware
        '.vhd', '.vhdx',  # Hyper-V
        '.qcow', '.qcow2',# QEMU
        '.vdi',           # VirtualBox
        '.001',           # Split raw (can be multi-part)
        
        # Memory Dump Formats
        '.mem', '.dmp', '.dump', '.memory',
        '.hiberfil', '.pagefile',
        '.crash', '.core',  # Linux/macOS crash dumps
        '.vmem', '.vmsn',   # VMware memory
        
        # Mobile Forensics
        '.tar', '.ab',      # Android backup
        '.ufed', '.ufd',    # Cellebrite UFED
        '.graykey',         # GrayKey
        '.ipa', '.apk',     # iOS/Android apps
        '.ipsw',            # iOS firmware
        '.backup',          # iTunes backup
        
        # Archive Formats
        '.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz',
        '.tgz', '.tbz2', '.txz',
        
        # Log Formats
        '.log', '.txt', '.csv', '.json', '.xml',
        '.evt', '.evtx',    # Windows Event Logs
        '.pcap', '.pcapng', # Network captures
        '.cap', '.eth', '.netmon',  # Additional network captures
        '.syslog',          # Syslog format
        '.etl',             # Windows Event Trace
        
        # Email Formats
        '.pst', '.ost',     # Outlook
        '.mbox', '.eml', '.msg',
        
        # Document Formats
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.odt', '.ods', '.odp',  # OpenDocument
        '.rtf',
        
        # Database Formats
        '.db', '.sqlite', '.sqlite3',
        '.mdb', '.accdb',   # MS Access
        '.sql',
        
        # Registry/System Files
        '.reg', '.dat',     # Windows Registry
        '.lnk',             # Shortcuts
        '.pf',              # Prefetch
        '.sdb',             # Shim cache
        
        # Browser Artifacts
        '.cookie', '.history',
        
        # Encryption Containers
        '.tc', '.hc',       # TrueCrypt/VeraCrypt
        '.bitlocker',
        '.luks',
        
        # Forensic Tool Outputs
        '.ad1',             # AccessData
        '.l01',             # EnCase Logical
        '.lef',             # Logical Evidence File
    }
    
    # Multi-part naming patterns - Extended support
    MULTIPART_PATTERNS = {
        'E01': re.compile(r'^(.+)\.E(\d{2})$', re.IGNORECASE),  # LoneWolf.E01, LoneWolf.E02
        'L01': re.compile(r'^(.+)\.L(\d{2})$', re.IGNORECASE),  # Evidence.L01, Evidence.L02
        'Ex01': re.compile(r'^(.+)\.Ex(\d{2})$', re.IGNORECASE),  # Extended E01 format
        'S01': re.compile(r'^(.+)\.S(\d{2})$', re.IGNORECASE),  # SMART format
        '001': re.compile(r'^(.+)\.(\d{3})$'),                  # Image.001, Image.002 (split raw)
        'part': re.compile(r'^(.+)\.part(\d+)$', re.IGNORECASE),  # archive.part1, archive.part2
        'z01': re.compile(r'^(.+)\.z(\d{2})$', re.IGNORECASE),   # Split ZIP: file.z01, file.z02
        'r00': re.compile(r'^(.+)\.r(\d{2})$', re.IGNORECASE),   # Split RAR: file.r00, file.r01
        'aa': re.compile(r'^(.+)\.([a-z]{2})$'),                 # Split: file.aa, file.ab
    }
    
    # Format descriptions for user-friendly error messages
    FORMAT_DESCRIPTIONS = {
        '.e01': 'EnCase Evidence File (Expert Witness Format)',
        '.l01': 'EnCase Logical Evidence File',
        '.dd': 'Raw Disk Image (dd format)',
        '.raw': 'Raw Disk Image',
        '.img': 'Disk Image',
        '.aff': 'Advanced Forensic Format',
        '.aff4': 'Advanced Forensic Format 4',
        '.vmdk': 'VMware Virtual Disk',
        '.vhd': 'Hyper-V Virtual Hard Disk',
        '.vhdx': 'Hyper-V Virtual Hard Disk (Extended)',
        '.qcow2': 'QEMU Copy-On-Write Disk',
        '.mem': 'Memory Dump',
        '.dmp': 'Windows Memory Dump',
        '.pcap': 'Network Packet Capture',
        '.pcapng': 'Network Packet Capture (Next Gen)',
        '.evtx': 'Windows Event Log',
        '.pst': 'Outlook Personal Folders',
        '.sqlite': 'SQLite Database',
        '.ad1': 'AccessData Evidence File',
    }
    
    def __init__(self, user: str = "system"):
        """
        Initialize the evidence validator.
        
        Args:
            user: User/investigator performing validation
        """
        self.logger = logging.getLogger(__name__)
        self.user = user
        self.audit_logger = ForensicAuditLogger()  # Global audit logger
    
    def validate_e01_header(self, file_path: Path) -> Tuple[bool, str]:
        """
        Validate E01 file has correct header magic bytes.
        
        Args:
            file_path: Path to potential E01 file
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(8)
                if magic == E01_MAGIC_BYTES:
                    return True, ""
                else:
                    return False, f"Invalid E01 header: Expected EVF signature, got {magic[:8].hex()}"
        except Exception as e:
            return False, f"Cannot read E01 header: {e}"
    
    def calculate_file_hash(self, file_path: Path) -> str:
        """
        Calculate SHA-256 hash of file.
        Immediate calculation to prevent TOCTOU attacks.
        
        Args:
            file_path: Path to file
        
        Returns:
            SHA-256 hex digest
        """
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192 * 1024):  # 8MB chunks
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Hash calculation failed for {file_path}: {e}")
            raise
    
    def validate_single_file(self, file_path: Path) -> Tuple[bool, str]:
        """
        Validate a single file evidence.
        
        Args:
            file_path: Path to the evidence file
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not file_path.exists():
            return False, f"File does not exist: {file_path}"
        
        if not file_path.is_file():
            return False, f"Path is not a file: {file_path}"
        
        extension = file_path.suffix.lower()
        
        if extension not in self.SINGLE_FILE_EXTENSIONS:
            return False, f"Unsupported file format: {extension}\nAllowed: {', '.join(sorted(self.SINGLE_FILE_EXTENSIONS))}"
        
        # Check file is readable
        try:
            file_path.stat()
        except Exception as e:
            return False, f"Cannot access file: {e}"
        
        return True, ""
    
    def detect_multipart_pattern(self, file_paths: List[Path]) -> Optional[Tuple[str, str, Dict[int, Path]]]:
        """
        Detect if files follow a multi-part naming pattern.
        
        Args:
            file_paths: List of file paths to analyze
        
        Returns:
            Tuple of (base_name, pattern_type, {sequence: path}) or None
        """
        if not file_paths:
            return None
        
        # CRITICAL: Detect mixed evidence sets
        all_base_names = set()
        for file_path in file_paths:
            for pattern_name, pattern_regex in self.MULTIPART_PATTERNS.items():
                match = pattern_regex.match(file_path.name)
                if match:
                    all_base_names.add(match.group(1))
        
        if len(all_base_names) > 1:
            self.logger.error(f"Mixed evidence sets detected: {all_base_names}")
            raise ValueError(
                f"Mixed evidence sets detected: {', '.join(sorted(all_base_names))}\n\n"
                "All files must belong to the same evidence set.\n"
                "Please select files from only one evidence collection."
            )
        
        # Group files by potential patterns
        for pattern_name, pattern_regex in self.MULTIPART_PATTERNS.items():
            grouped = {}
            base_name = None
            
            for file_path in file_paths:
                match = pattern_regex.match(file_path.name)
                if match:
                    current_base = match.group(1)
                    sequence = int(match.group(2))
                    
                    if base_name is None:
                        base_name = current_base
                    elif base_name != current_base:
                        # Should never reach here due to check above
                        continue
                    
                    grouped[sequence] = file_path
            
            if grouped and len(grouped) > 1:  # At least 2 parts
                return base_name, pattern_name, grouped
        
        return None
    
    def validate_multipart_sequence(
        self, 
        sequence_dict: Dict[int, Path], 
        pattern_type: str
    ) -> Tuple[bool, List[int], str]:
        """
        Validate that multi-part sequence is complete and continuous.
        
        Args:
            sequence_dict: Dictionary mapping sequence numbers to file paths
            pattern_type: Type of pattern (E01, L01, 001)
        
        Returns:
            Tuple of (is_complete, missing_parts, error_message)
        """
        if not sequence_dict:
            return False, [], "No parts provided"
        
        sequence_numbers = sorted(sequence_dict.keys())
        
        # Determine expected starting number based on pattern
        if pattern_type in ['E01', 'L01']:
            expected_start = 1
        elif pattern_type == '001':
            expected_start = 1
        else:
            expected_start = min(sequence_numbers)
        
        # Check for continuous sequence
        expected_end = max(sequence_numbers)
        expected_sequence = set(range(expected_start, expected_end + 1))
        actual_sequence = set(sequence_numbers)
        
        missing = sorted(expected_sequence - actual_sequence)
        
        if missing:
            missing_str = ", ".join(str(n) for n in missing)
            return False, missing, f"Incomplete sequence - missing parts: {missing_str}"
        
        # Check that sequence starts at expected number
        if min(sequence_numbers) != expected_start:
            return False, [], f"Sequence should start at {expected_start}, but starts at {min(sequence_numbers)}"
        
        return True, [], ""
    
    def validate_multipart_files(
        self, 
        file_paths: List[Path]
    ) -> Tuple[bool, Optional[EvidenceObject], str]:
        """
        Validate multiple files as a multi-part forensic image.
        
        Args:
            file_paths: List of file paths to validate as multi-part evidence
        
        Returns:
            Tuple of (is_valid, EvidenceObject, error_message)
        """
        if not file_paths:
            return False, None, "No files provided"
        
        # Detect naming pattern
        pattern_result = self.detect_multipart_pattern(file_paths)
        
        if not pattern_result:
            return False, None, (
                "Could not detect multi-part naming pattern.\n"
                "Expected formats:\n"
                "  • E01 format: BaseName.E01, BaseName.E02, ...\n"
                "  • L01 format: BaseName.L01, BaseName.L02, ...\n"
                "  • Numbered: BaseName.001, BaseName.002, ..."
            )
        
        base_name, pattern_type, sequence_dict = pattern_result
        
        # Validate sequence continuity
        is_complete, missing, error_msg = self.validate_multipart_sequence(
            sequence_dict, pattern_type
        )
        
        # Create evidence segments with immediate integrity verification
        segments = []
        total_size = 0
        validation_time = datetime.now(timezone.utc).isoformat()
        
        self.logger.info("Performing integrity verification...")
        
        for seq_num in sorted(sequence_dict.keys()):
            file_path = sequence_dict[seq_num]
            try:
                file_stat = file_path.stat()
                file_size = file_stat.st_size
                file_mtime = file_stat.st_mtime
            except Exception as e:
                return False, None, f"Cannot access {file_path.name}: {e}"
            
            # CRITICAL: E01 header validation for first segment
            if pattern_type == 'E01' and seq_num == min(sequence_dict.keys()):
                is_valid_header, header_error = self.validate_e01_header(file_path)
                if not is_valid_header:
                    self.logger.error(f"E01 header validation failed: {header_error}")
                    return False, None, (
                        f"Invalid E01 format detected.\n\n"
                        f"{header_error}\n\n"
                        f"This file does not appear to be a valid EnCase Evidence File.\n"
                        f"Forensic integrity cannot be guaranteed."
                    )
            
            # CRITICAL: Calculate hash immediately (TOCTOU protection)
            self.logger.info(f"Hashing {file_path.name}...")
            try:
                file_hash = self.calculate_file_hash(file_path)
            except Exception as e:
                return False, None, f"Hash calculation failed for {file_path.name}: {e}"
            
            segments.append(EvidenceSegment(
                path=file_path,
                sequence_number=seq_num,
                extension=file_path.suffix,
                size_bytes=file_size,
                sha256_hash=file_hash,
                validated_at=validation_time,
                file_mtime=file_mtime
            ))
            total_size += file_size
            
            self.logger.info(f"✓ {file_path.name}: {file_hash[:16]}...")
        
        # Determine evidence format
        if pattern_type == 'E01':
            evidence_format = EvidenceFormat.E01_MULTI
        elif pattern_type == 'L01':
            evidence_format = EvidenceFormat.L01_MULTI
        else:
            evidence_format = EvidenceFormat.UNKNOWN
        
        # Create evidence object
        evidence_obj = EvidenceObject(
            id=base_name,
            type=EvidenceType.MULTI_PART_DISK,
            format=evidence_format,
            base_name=base_name,
            parts=segments,
            total_parts=len(segments),
            total_size_bytes=total_size,
            is_complete=is_complete,
            missing_parts=missing,
            integrity_verified=True,  # Set to True after hash verification
            validation_timestamp=validation_time
        )
        
        if not is_complete:
            self.logger.warning(f"Validation failed: {error_msg}")
            return False, evidence_obj, error_msg
        
        self.logger.info(f"✓ Validation PASSED: {base_name} ({len(segments)} parts, {total_size / (1024**3):.2f} GB)")
        return True, evidence_obj, ""
    
    def create_single_evidence_object(self, file_path: Path) -> EvidenceObject:
        """
        Create an EvidenceObject for a single file.
        
        Args:
            file_path: Path to the single evidence file
        
        Returns:
            EvidenceObject representing the single file
        """
        # Determine format
        extension = file_path.suffix.lower()
        
        if extension in ['.mem', '.dmp']:
            evidence_format = EvidenceFormat.MEMORY
        elif extension in ['.img', '.dd', '.raw']:
            evidence_format = EvidenceFormat.RAW
        elif extension == '.aff':
            evidence_format = EvidenceFormat.AFF
        elif extension == '.log':
            evidence_format = EvidenceFormat.LOG
        elif extension == '.zip':
            evidence_format = EvidenceFormat.ARCHIVE
        else:
            evidence_format = EvidenceFormat.UNKNOWN
        
        try:
            file_size = file_path.stat().st_size
        except Exception:
            file_size = 0
        
        return EvidenceObject(
            id=file_path.stem,
            type=EvidenceType.SINGLE,
            format=evidence_format,
            single_path=file_path,
            total_size_bytes=file_size,
            is_complete=True,
            integrity_verified=False
        )
    
    def validate_evidence(
        self, 
        file_paths: List[Path], 
        is_multipart_mode: bool
    ) -> Tuple[bool, Optional[EvidenceObject], str]:
        """
        Main validation method - validates evidence based on mode.
        
        Args:
            file_paths: List of file paths (can be single or multiple)
            is_multipart_mode: True if user selected multi-part mode
        
        Returns:
            Tuple of (is_valid, EvidenceObject, error_message)
        """
        # LOG: Validation attempt
        self.logger.info(f"Evidence validation started: {len(file_paths)} file(s)")
        self.logger.info(f"Mode: {'MULTI-PART' if is_multipart_mode else 'SINGLE'}")
        for fp in file_paths:
            self.logger.info(f"  File: {fp.name}")
        
        # AUDIT: Log validation start
        self.audit_logger.log_validation_started(file_paths, self.user)
        
        if not file_paths:
            self.logger.warning("Validation failed: No files selected")
            self.audit_logger.log_validation_failed(
                file_paths, 
                "No files selected", 
                self.user
            )
            return False, None, "No files selected"
        
        # CASE 1: Single File Mode
        if not is_multipart_mode:
            if len(file_paths) > 1:
                error_msg = (
                    "You selected multiple files.\n\n"
                    "Enable 'Multi-part forensic image' to upload split disks (E01, E02, ...)."
                )
                self.audit_logger.log_validation_failed(file_paths, error_msg, self.user)
                return False, None, error_msg
            
            file_path = file_paths[0]
            is_valid, error_msg = self.validate_single_file(file_path)
            
            if not is_valid:
                self.audit_logger.log_validation_failed([file_path], error_msg, self.user)
                return False, None, error_msg
            
            evidence_obj = self.create_single_evidence_object(file_path)
            evidence_obj.validation_timestamp = datetime.now(timezone.utc).isoformat()
            self.logger.info(f"✓ Single file validation PASSED: {file_path.name}")
            
            # AUDIT: Log success
            primary_hash = evidence_obj.parts[0].sha256_hash if evidence_obj.parts else "N/A"
            self.audit_logger.log_validation_success(
                [file_path],
                evidence_obj.type.value,
                primary_hash,
                self.user
            )
            
            return True, evidence_obj, ""
        
        # CASE 2: Multi-Part Mode
        else:
            try:
                result = self.validate_multipart_files(file_paths)
                
                # AUDIT: Log result
                if result[0]:  # success
                    evidence_obj = result[1]
                    primary_hash = evidence_obj.parts[0].sha256_hash if evidence_obj.parts else "N/A"
                    self.audit_logger.log_validation_success(
                        file_paths,
                        evidence_obj.type.value,
                        primary_hash,
                        self.user
                    )
                else:
                    self.audit_logger.log_validation_failed(
                        file_paths,
                        result[2],  # error message
                        self.user
                    )
                
                return result
                
            except ValueError as e:
                # Mixed evidence sets or validation errors
                self.logger.error(f"Validation error: {e}")
                self.audit_logger.log_validation_failed(file_paths, str(e), self.user)
                return False, None, str(e)
            except Exception as e:
                self.logger.exception(f"Unexpected validation error: {e}")
                self.audit_logger.log_validation_failed(file_paths, str(e), self.user)
                return False, None, f"Validation error: {e}"
    
    def format_evidence_summary(self, evidence: EvidenceObject) -> str:
        """
        Format a human-readable summary of the evidence.
        
        Args:
            evidence: EvidenceObject to summarize
        
        Returns:
            Formatted string describing the evidence
        """
        if evidence.type == EvidenceType.SINGLE:
            size_mb = evidence.total_size_bytes / (1024 * 1024)
            return (
                f"✓ Single file evidence detected:\n"
                f"  File: {evidence.single_path.name}\n"
                f"  Format: {evidence.format.value.upper()}\n"
                f"  Size: {size_mb:.2f} MB\n"
                f"  Status: READY"
            )
        
        elif evidence.type == EvidenceType.MULTI_PART_DISK:
            size_gb = evidence.total_size_bytes / (1024 ** 3)
            
            if evidence.is_complete:
                ext = evidence.parts[0].extension.upper() if evidence.parts else "E"
                return (
                    f"✓ Detected multi-part forensic image:\n"
                    f"  Base name: {evidence.base_name}\n"
                    f"  Parts: {ext}01 → {ext}{evidence.total_parts:02d}\n"
                    f"  Total size: {size_gb:.2f} GB\n"
                    f"  Status: COMPLETE"
                )
            else:
                missing_str = ", ".join(str(n) for n in evidence.missing_parts) if evidence.missing_parts else "Unknown"
                return (
                    f"❌ Incomplete evidence set:\n"
                    f"  Base name: {evidence.base_name}\n"
                    f"  Missing: {missing_str}\n\n"
                    f"Forensic integrity requires ALL segments.\n"
                    f"Please provide the missing parts."
                )
        
        return "Unknown evidence type"


# Singleton instance
_validator_instance = None


def get_evidence_validator() -> EvidenceValidator:
    """Get the singleton evidence validator instance."""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = EvidenceValidator()
    return _validator_instance
