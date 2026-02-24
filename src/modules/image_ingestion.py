"""
Image Ingestion Module
Handles forensic disk image loading and validation
"""

import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass
from datetime import datetime, timezone

# Forensic image libraries
try:
    import pyewf
    PYEWF_AVAILABLE = True
except ImportError:
    PYEWF_AVAILABLE = False

try:
    import pytsk3
    PYTSK3_AVAILABLE = True
except ImportError:
    PYTSK3_AVAILABLE = False

from ..utils.hash_utils import ForensicHasher
from ..utils.chain_of_custody import ChainOfCustody
from ..utils.logger import ForensicLogger


@dataclass
class ImageMetadata:
    """Metadata for forensic disk image."""
    image_id: str
    file_path: Path
    image_type: str  # E01, RAW, DD
    file_size: int
    sha256_hash: str
    ingested_at: datetime
    read_only: bool
    sector_count: Optional[int] = None
    sector_size: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None


class EWFImgInfo(pytsk3.Img_Info if PYTSK3_AVAILABLE else object):
    """
    Wrapper class for pyewf handle to work with pytsk3.
    Allows pytsk3 to read from EWF/E01 images.
    """
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        if PYTSK3_AVAILABLE:
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    
    def close(self):
        self._ewf_handle.close()
    
    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)
    
    def get_size(self):
        return self._ewf_handle.get_media_size()


class ImageIngestionModule:
    """
    Image Ingestion Module - FR-01 to FR-04
    
    Handles:
    - FR-01: Ingest E01/RAW/DD forensic images
    - FR-02: Compute SHA-256 hash of image
    - FR-03: Record chain-of-custody entry
    - FR-04: Read-only access enforcement
    
    Comprehensive format support:
    - Expert Witness: E01, Ex01, L01, Lx01
    - Raw Images: DD, RAW, IMG, BIN
    - Virtual Disks: VMDK, VHD, VHDX, QCOW2, VDI
    - Advanced: AFF, AFF4, AD1
    - Split Images: 001, 002, etc.
    - Memory: MEM, DMP, VMEM
    - Mobile: TAR, AB, UFED
    - Archives: ZIP, 7Z, TAR.GZ
    - Other: ISO, DMG
    """
    
    SUPPORTED_FORMATS = {
        # Expert Witness Format (EnCase)
        '.e01': 'E01',
        '.E01': 'E01',
        '.ex01': 'Ex01',
        '.l01': 'L01',
        '.lx01': 'Lx01',
        
        # Split Image Formats
        '.001': 'SPLIT',
        '.002': 'SPLIT',
        
        # Raw Disk Image Formats
        '.raw': 'RAW',
        '.dd': 'DD',
        '.img': 'IMG',
        '.bin': 'BIN',
        '.iso': 'ISO',
        '.dmg': 'DMG',
        
        # Virtual Machine Disk Formats
        '.vmdk': 'VMDK',
        '.vhd': 'VHD',
        '.vhdx': 'VHDX',
        '.qcow': 'QCOW',
        '.qcow2': 'QCOW2',
        '.vdi': 'VDI',
        
        # Advanced Forensic Formats
        '.aff': 'AFF',
        '.aff4': 'AFF4',
        '.ad1': 'AD1',
        '.lef': 'LEF',
        
        # Memory Dump Formats
        '.mem': 'MEMORY',
        '.dmp': 'MEMORY',
        '.dump': 'MEMORY',
        '.memory': 'MEMORY',
        '.vmem': 'VMEM',
        '.vmsn': 'VMEM',
        '.hiberfil': 'HIBERFIL',
        '.core': 'CORE',
        
        # Mobile Forensic Formats
        '.tar': 'TAR',
        '.ab': 'ANDROID_BACKUP',
        '.ufed': 'UFED',
        '.ufd': 'UFED',
        '.backup': 'IOS_BACKUP',
        
        # Archive Formats (for logical evidence)
        '.zip': 'ZIP',
        '.7z': 'SEVENZIP',
        '.rar': 'RAR',
        '.gz': 'GZIP',
        '.tgz': 'TARGZ',
        '.bz2': 'BZIP2',
        '.xz': 'XZ',
        
        # Network Capture
        '.pcap': 'PCAP',
        '.pcapng': 'PCAPNG',
        
        # Log Files
        '.evtx': 'EVTX',
        '.evt': 'EVT',
        '.etl': 'ETL',
        '.log': 'LOG',
        
        # Database/Artifact Containers
        '.sqlite': 'SQLITE',
        '.db': 'SQLITE',
        '.pst': 'PST',
        '.ost': 'OST',
    }
    
    # Format categories for specialized processing
    DISK_IMAGE_FORMATS = {'E01', 'Ex01', 'L01', 'RAW', 'DD', 'IMG', 'SPLIT', 'VMDK', 'VHD', 'VHDX', 'QCOW2', 'AFF', 'AFF4', 'AD1', 'ISO', 'DMG', 'VDI'}
    MEMORY_FORMATS = {'MEMORY', 'VMEM', 'HIBERFIL', 'CORE'}
    MOBILE_FORMATS = {'TAR', 'ANDROID_BACKUP', 'UFED', 'IOS_BACKUP'}
    ARCHIVE_FORMATS = {'ZIP', 'SEVENZIP', 'RAR', 'GZIP', 'TARGZ', 'BZIP2', 'XZ'}
    NETWORK_FORMATS = {'PCAP', 'PCAPNG'}
    LOG_FORMATS = {'EVTX', 'EVT', 'ETL', 'LOG'}
    DATABASE_FORMATS = {'SQLITE', 'PST', 'OST'}
    
    def __init__(self, config, chain_of_custody: ChainOfCustody):
        """
        Initialize image ingestion module.
        
        Args:
            config: Configuration object
            chain_of_custody: CoC logger instance
        """
        self.config = config
        self.coc = chain_of_custody
        self.logger = ForensicLogger('image_ingestion')
        self.hasher = ForensicHasher()
        
        # Enforce read-only setting
        self.readonly_enforcement = config.get_bool('READONLY_ENFORCEMENT', True)
        
        self.logger.logger.info("Image Ingestion Module initialized")
    
    def ingest_image(
        self,
        image_path: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> ImageMetadata:
        """
        Ingest forensic disk image (FR-01, FR-02, FR-03, FR-04).
        
        Args:
            image_path: Path to forensic disk image
            progress_callback: Optional callback for hash progress
            
        Returns:
            ImageMetadata object
            
        Raises:
            FileNotFoundError: If image file doesn't exist
            ValueError: If image format not supported
            RuntimeError: If read-only access cannot be enforced
        """
        self.logger.logger.info(f"Starting image ingestion: {image_path}")
        
        # Validate image file exists
        if not image_path.exists():
            raise FileNotFoundError(f"Image file not found: {image_path}")
        
        # Validate image format (FR-01)
        image_type = self._detect_image_type(image_path)
        if not image_type:
            raise ValueError(
                f"Unsupported image format: {image_path.suffix}. "
                f"Supported: {', '.join(self.SUPPORTED_FORMATS.keys())}"
            )
        
        self.logger.logger.info(f"Detected image type: {image_type}")
        
        # Enforce read-only access (FR-04)
        if self.readonly_enforcement:
            self._enforce_readonly_access(image_path)
        
        # Compute SHA-256 hash (FR-02)
        self.logger.logger.info("Computing SHA-256 hash...")
        hash_value = self.hasher.hash_file(image_path, callback=progress_callback)
        self.logger.logger.info(f"Hash computed: {hash_value}")
        
        # Create metadata
        metadata = ImageMetadata(
            image_id=self._generate_image_id(),
            file_path=image_path,
            image_type=image_type,
            file_size=image_path.stat().st_size,
            sha256_hash=hash_value,
            ingested_at=datetime.now(timezone.utc),
            read_only=True
        )
        
        # Record in Chain of Custody (FR-03)
        self.coc.log_event(
            event_type='IMAGE_INGESTED',
            description=f'Forensic image ingested: {image_path.name}',
            hash_value=hash_value,
            metadata={
                'image_id': metadata.image_id,
                'image_type': image_type,
                'file_size': metadata.file_size,
                'file_path': str(image_path)
            },
            severity='INFO'
        )
        
        self.logger.log_evidence_access(
            image_path=str(image_path),
            operation='INGEST',
            hash_value=hash_value
        )
        
        self.logger.logger.info(f"Image ingestion complete: {metadata.image_id}")
        return metadata
    
    def _detect_image_type(self, image_path: Path) -> Optional[str]:
        """
        Detect forensic image type from file extension.
        
        Args:
            image_path: Path to image file
            
        Returns:
            Image type string or None if unsupported
        """
        suffix = image_path.suffix
        return self.SUPPORTED_FORMATS.get(suffix)
    
    def _enforce_readonly_access(self, image_path: Path):
        """
        Enforce read-only access to image file (FR-04).
        
        Args:
            image_path: Path to image file
            
        Raises:
            RuntimeError: If file is writable and cannot be made read-only
        """
        import stat
        
        # Check if file is writable
        file_stat = image_path.stat()
        is_writable = bool(file_stat.st_mode & stat.S_IWUSR)
        
        if is_writable:
            self.logger.logger.warning(
                f"Image file is writable: {image_path}. "
                "Read-only enforcement is active."
            )
            
            # Attempt to make read-only (cross-platform)
            try:
                if os.name == 'nt':  # Windows
                    # Use Windows file attributes
                    import subprocess
                    subprocess.run(['attrib', '+R', str(image_path)], check=True, capture_output=True)
                    self.logger.logger.info("Image file set to read-only (Windows)")
                else:  # Unix/Linux/macOS
                    image_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
                    self.logger.logger.info("Image file set to read-only (Unix)")
            except Exception as e:
                raise RuntimeError(
                    f"Cannot enforce read-only access: {e}. "
                    "Forensic integrity cannot be guaranteed."
                )
    
    def _generate_image_id(self) -> str:
        """
        Generate unique image ID.
        
        Returns:
            UUID string
        """
        import uuid
        return str(uuid.uuid4())
    
    def verify_image_integrity(self, metadata: ImageMetadata) -> bool:
        """
        Verify image integrity by re-computing hash.
        
        Args:
            metadata: Image metadata with original hash
            
        Returns:
            True if hash matches, False otherwise
        """
        self.logger.logger.info(f"Verifying image integrity: {metadata.image_id}")
        
        try:
            match = self.hasher.verify_hash(
                metadata.file_path,
                metadata.sha256_hash
            )
            
            if match:
                self.logger.logger.info("Image integrity verified")
                self.coc.log_event(
                    event_type='IMAGE_VERIFIED',
                    description=f'Image integrity verified: {metadata.file_path.name}',
                    hash_value=metadata.sha256_hash,
                    metadata={'image_id': metadata.image_id},
                    severity='INFO'
                )
            else:
                self.logger.log_integrity_violation(
                    f"Image hash mismatch: {metadata.file_path}"
                )
                self.coc.log_event(
                    event_type='INTEGRITY_VIOLATION',
                    description=f'Image hash mismatch: {metadata.file_path.name}',
                    hash_value=metadata.sha256_hash,
                    metadata={'image_id': metadata.image_id},
                    severity='CRITICAL'
                )
            
            return match
            
        except Exception as e:
            self.logger.log_error('IMAGE_VERIFICATION', str(e))
            return False
    
    def open_image_readonly(self, metadata: ImageMetadata):
        """
        Open image for read-only forensic analysis using pyewf/pytsk3.
        
        Args:
            metadata: Image metadata
            
        Returns:
            pytsk3.Img_Info object for filesystem access, or None if not available
        """
        self.logger.logger.info(f"Opening image read-only: {metadata.image_id}")
        
        try:
            # Open E01 image with pyewf
            if metadata.image_type.upper() == 'E01' and PYEWF_AVAILABLE and PYTSK3_AVAILABLE:
                # Create EWF handle
                filenames = pyewf.glob(str(metadata.file_path))
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                
                # Create pytsk3 image from EWF handle
                img_info = EWFImgInfo(ewf_handle)
                
                self.coc.log_event(
                    event_type='IMAGE_OPENED',
                    description=f'E01 image mounted for analysis: {metadata.file_path.name}',
                    hash_value=metadata.sha256_hash,
                    metadata={'image_id': metadata.image_id, 'size_bytes': ewf_handle.get_media_size()},
                    severity='INFO'
                )
                
                return img_info
            
            # Fallback for RAW/DD images
            elif PYTSK3_AVAILABLE:
                img_info = pytsk3.Img_Info(str(metadata.file_path))
                
                self.coc.log_event(
                    event_type='IMAGE_OPENED',
                    description=f'RAW image opened for analysis: {metadata.file_path.name}',
                    hash_value=metadata.sha256_hash,
                    metadata={'image_id': metadata.image_id},
                    severity='INFO'
                )
                
                return img_info
            
            else:
                self.logger.logger.warning("pyewf/pytsk3 not available - image mounting disabled")
                return None
                
        except Exception as e:
            self.logger.logger.error(f"Failed to open image: {e}")
            self.coc.log_event(
                event_type='IMAGE_OPEN_FAILED',
                description=f'Failed to open image: {str(e)}',
                metadata={'image_id': metadata.image_id},
                severity='ERROR'
            )
            return None
