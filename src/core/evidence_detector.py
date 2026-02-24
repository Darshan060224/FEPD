"""
FEPD - Evidence Type Detection
================================
Automatic evidence type identification using magic numbers and structure validation.

NO file extensions are trusted. All detection is based on:
- Magic bytes (file signatures)
- Internal structure validation
- Format-specific header checks

Supported Evidence Types:
- Disk Images: E01, DD, IMG, VHD, VMDK
- Memory Dumps: Windows, Linux crash dumps
- Network: PCAP, PCAPNG
- Logs: EVTX, syslog, JSON logs
- Databases: SQLite, registry hives
- Mobile: iOS backups, Android images
- Archives: ZIP, TAR, 7Z

Copyright (c) 2026 FEPD Development Team
"""

import struct
import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


class EvidenceType(Enum):
    """Enumeration of supported evidence types"""
    # Disk Images
    E01 = "e01"
    DD = "dd"
    IMG = "img"
    VHD = "vhd"
    VMDK = "vmdk"
    
    # Memory
    WINDOWS_MEMORY = "windows_memory"
    LINUX_MEMORY = "linux_memory"
    
    # Network
    PCAP = "pcap"
    PCAPNG = "pcapng"
    
    # Logs
    EVTX = "evtx"
    SYSLOG = "syslog"
    CLOUDTRAIL = "cloudtrail"
    
    # Databases
    SQLITE = "sqlite"
    REGISTRY = "registry"
    
    # Mobile
    IOS_BACKUP = "ios_backup"
    ANDROID_IMAGE = "android_image"
    
    # Archives
    ZIP = "zip"
    TAR = "tar"
    GZIP = "gzip"
    
    # Unknown
    UNKNOWN = "unknown"


@dataclass
class EvidenceSignature:
    """Evidence type signature definition"""
    magic_bytes: bytes
    offset: int = 0
    name: str = ""
    evidence_type: EvidenceType = EvidenceType.UNKNOWN
    
    def matches(self, file_bytes: bytes) -> bool:
        """Check if file matches this signature"""
        if len(file_bytes) < self.offset + len(self.magic_bytes):
            return False
        return file_bytes[self.offset:self.offset + len(self.magic_bytes)] == self.magic_bytes


# Magic Number Database
EVIDENCE_SIGNATURES = [
    # Disk Images
    EvidenceSignature(b"EVF\x09\x0d\x0a\xff\x00", 0, "EnCase E01", EvidenceType.E01),
    EvidenceSignature(b"EVF2\x0d\x0a\x81\x00", 0, "EnCase E02", EvidenceType.E01),
    EvidenceSignature(b"conectix", 0, "VHD", EvidenceType.VHD),
    EvidenceSignature(b"KDMV", 0, "VMDK", EvidenceType.VMDK),
    
    # Network
    EvidenceSignature(b"\xd4\xc3\xb2\xa1", 0, "PCAP", EvidenceType.PCAP),
    EvidenceSignature(b"\xa1\xb2\xc3\xd4", 0, "PCAP (LE)", EvidenceType.PCAP),
    EvidenceSignature(b"\x0a\x0d\x0d\x0a", 0, "PCAPNG", EvidenceType.PCAPNG),
    
    # Logs
    EvidenceSignature(b"ElfFile\x00", 0, "EVTX", EvidenceType.EVTX),
    
    # Databases
    EvidenceSignature(b"SQLite format 3\x00", 0, "SQLite", EvidenceType.SQLITE),
    EvidenceSignature(b"regf", 0, "Registry Hive", EvidenceType.REGISTRY),
    
    # Archives
    EvidenceSignature(b"PK\x03\x04", 0, "ZIP", EvidenceType.ZIP),
    EvidenceSignature(b"\x1f\x8b", 0, "GZIP", EvidenceType.GZIP),
    EvidenceSignature(b"ustar", 257, "TAR", EvidenceType.TAR),
]


@dataclass
class DetectionResult:
    """Result of evidence type detection"""
    evidence_type: EvidenceType
    confidence: float  # 0.0 to 1.0
    detected_by: str  # "magic_number", "structure", "heuristic"
    details: Dict
    sha256: str


class EvidenceDetector:
    """
    Automatic evidence type detection using magic numbers and structure validation.
    
    Detection Process:
    1. Calculate SHA-256 hash
    2. Read file header
    3. Check magic numbers
    4. Validate internal structure
    5. Apply heuristics if needed
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.signatures = EVIDENCE_SIGNATURES
    
    def detect(self, file_path: Path, calculate_hash: bool = True) -> DetectionResult:
        """
        Detect evidence type from file.
        
        Args:
            file_path: Path to evidence file
            calculate_hash: Whether to calculate SHA-256 (slower but forensically required)
            
        Returns:
            DetectionResult with type, confidence, and hash
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Evidence file not found: {file_path}")
        
        # Calculate SHA-256 hash (forensic integrity)
        sha256 = self._calculate_sha256(file_path) if calculate_hash else "not_calculated"
        
        self.logger.info(f"Detecting evidence type: {file_path.name}")
        self.logger.info(f"SHA-256: {sha256}")
        
        # Read file header for magic number detection
        with open(file_path, 'rb') as f:
            header = f.read(8192)  # Read first 8KB
        
        # Try magic number detection first
        magic_result = self._detect_by_magic(header, file_path)
        if magic_result:
            return DetectionResult(
                evidence_type=magic_result[0],
                confidence=1.0,
                detected_by="magic_number",
                details={"signature": magic_result[1]},
                sha256=sha256
            )
        
        # Try structure validation
        structure_result = self._detect_by_structure(file_path)
        if structure_result:
            return DetectionResult(
                evidence_type=structure_result[0],
                confidence=0.9,
                detected_by="structure_validation",
                details=structure_result[1],
                sha256=sha256
            )
        
        # Try heuristics
        heuristic_result = self._detect_by_heuristics(file_path, header)
        if heuristic_result:
            return DetectionResult(
                evidence_type=heuristic_result[0],
                confidence=0.7,
                detected_by="heuristic",
                details=heuristic_result[1],
                sha256=sha256
            )
        
        # Unknown type
        return DetectionResult(
            evidence_type=EvidenceType.UNKNOWN,
            confidence=0.0,
            detected_by="none",
            details={"reason": "No matching signature or structure"},
            sha256=sha256
        )
    
    def _calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file (for forensic integrity)"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(1048576):  # 1MB chunks
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _detect_by_magic(self, header: bytes, file_path: Path) -> Optional[Tuple[EvidenceType, str]]:
        """Detect using magic numbers (most reliable)"""
        for sig in self.signatures:
            if sig.matches(header):
                self.logger.info(f"✓ Magic number match: {sig.name}")
                return (sig.evidence_type, sig.name)
        return None
    
    def _detect_by_structure(self, file_path: Path) -> Optional[Tuple[EvidenceType, Dict]]:
        """Detect using internal structure validation"""
        
        # Check for raw disk image (MBR/GPT)
        with open(file_path, 'rb') as f:
            # Check for MBR signature
            f.seek(510)
            mbr_sig = f.read(2)
            if mbr_sig == b'\x55\xAA':
                self.logger.info("✓ Structure validation: MBR signature found (raw disk)")
                return (EvidenceType.DD, {"structure": "MBR", "offset": 510})
            
            # Check for GPT
            f.seek(512)
            gpt_sig = f.read(8)
            if gpt_sig == b'EFI PART':
                self.logger.info("✓ Structure validation: GPT signature found (raw disk)")
                return (EvidenceType.DD, {"structure": "GPT", "offset": 512})
        
        return None
    
    def _detect_by_heuristics(self, file_path: Path, header: bytes) -> Optional[Tuple[EvidenceType, Dict]]:
        """Detect using heuristics (least reliable)"""
        
        file_size = file_path.stat().st_size
        
        # Memory dumps are typically large and have high entropy
        if file_size > 100 * 1024 * 1024:  # > 100MB
            entropy = self._calculate_entropy(header[:4096])
            if entropy > 7.5:  # High entropy suggests memory dump
                # Check for Windows kernel structures
                if b'KDBG' in header or b'MmPf' in header:
                    self.logger.info("✓ Heuristic: Windows memory dump")
                    return (EvidenceType.WINDOWS_MEMORY, {"entropy": entropy, "size_mb": file_size / 1024 / 1024})
        
        # Text-based logs
        if self._is_text(header):
            if b'syslog' in header.lower() or b'kernel' in header.lower():
                self.logger.info("✓ Heuristic: Syslog")
                return (EvidenceType.SYSLOG, {"text_based": True})
        
        return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy -= p_x * (p_x.bit_length() - 1)
        return entropy
    
    def _is_text(self, data: bytes) -> bool:
        """Check if data appears to be text"""
        try:
            data.decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False
    
    def get_supported_types(self) -> List[str]:
        """Return list of supported evidence types"""
        return [et.value for et in EvidenceType if et != EvidenceType.UNKNOWN]


if __name__ == "__main__":
    # Test the detector
    import sys
    
    logging.basicConfig(level=logging.INFO)
    detector = EvidenceDetector()
    
    if len(sys.argv) > 1:
        test_file = Path(sys.argv[1])
        result = detector.detect(test_file)
        print(f"\n=== Detection Result ===")
        print(f"Type: {result.evidence_type.value}")
        print(f"Confidence: {result.confidence:.2%}")
        print(f"Detected by: {result.detected_by}")
        print(f"SHA-256: {result.sha256}")
        print(f"Details: {result.details}")
    else:
        print("Supported evidence types:")
        for et in detector.get_supported_types():
            print(f"  - {et}")
