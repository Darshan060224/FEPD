"""
FEPD VFS Builder
================

Builds the Virtual Filesystem from evidence images.
Integrates with pytsk3/libewf for E01/DD/IMG parsing.

Flow:
    Evidence Image → ImageHandler → Partition Walk → VFS Database
"""

import os
import hashlib
import mimetypes
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable, Generator
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import struct
import logging

# Local imports
from .virtual_fs import (
    VirtualFilesystem, VFSNode, VFSNodeType,
    create_disk_node, create_drive_node, create_folder_node, create_file_node
)

# Try to import forensic libraries
try:
    import pytsk3
    PYTSK3_AVAILABLE = True
except ImportError:
    PYTSK3_AVAILABLE = False

try:
    import pyewf
    PYEWF_AVAILABLE = True
except ImportError:
    PYEWF_AVAILABLE = False

logger = logging.getLogger(__name__)


class ImageType(Enum):
    """Supported evidence image types - Comprehensive forensic format support."""
    # Raw/Basic Formats
    RAW = "raw"              # DD/RAW image
    BIN = "bin"              # Binary image
    IMG = "img"              # Generic image
    
    # Expert Witness Formats
    EWF = "ewf"              # E01/EWF image (EnCase)
    LEF = "lef"              # L01/Logical Evidence File
    
    # Virtual Machine Disk Formats
    VMDK = "vmdk"            # VMware disk
    VHD = "vhd"              # Hyper-V disk
    VHDX = "vhdx"            # Hyper-V Extended disk
    QCOW2 = "qcow2"          # QEMU disk
    VDI = "vdi"              # VirtualBox disk
    
    # Advanced Forensic Formats
    AFF = "aff"              # Advanced Forensic Format
    AFF4 = "aff4"            # Advanced Forensic Format 4
    AD1 = "ad1"              # AccessData
    
    # Optical/Container Formats
    ISO = "iso"              # ISO image
    DMG = "dmg"              # macOS disk image
    
    # Memory Formats
    MEMORY = "memory"        # Memory dump (.mem, .dmp)
    VMEM = "vmem"            # VMware memory
    HIBERFIL = "hiberfil"    # Windows hibernation
    CORE = "core"            # Unix core dump
    
    # Mobile Forensics
    TAR = "tar"              # TAR archive (Android backup)
    AB = "android_backup"    # Android backup
    UFED = "ufed"            # Cellebrite UFED
    IOS_BACKUP = "ios_backup" # iOS backup
    
    # Archive Formats
    ZIP = "zip"              # ZIP archive
    SEVENZIP = "7z"          # 7-Zip
    RAR = "rar"              # RAR archive
    
    # Network Captures
    PCAP = "pcap"            # PCAP capture
    PCAPNG = "pcapng"        # PCAP-NG capture
    
    # Log/Event Formats
    EVTX = "evtx"            # Windows Event Log
    ETL = "etl"              # Windows Event Trace
    
    # Database Formats
    SQLITE = "sqlite"        # SQLite database
    PST = "pst"              # Outlook PST
    
    UNKNOWN = "unknown"


@dataclass
class PartitionInfo:
    """Information about a disk partition."""
    index: int
    start_offset: int
    length: int
    description: str
    filesystem_type: str
    is_allocated: bool = True
    slot: int = 0
    

@dataclass
class BuildProgress:
    """Progress information during VFS build."""
    phase: str
    current: int
    total: int
    message: str
    evidence_id: str = ""


class EWFImageInfo:
    """PyTSK3 img_info wrapper for E01/EWF images."""
    
    def __init__(self, ewf_handle):
        self._handle = ewf_handle
        self._size = ewf_handle.get_media_size()
    
    def read(self, offset: int, size: int) -> bytes:
        """Read bytes from EWF image."""
        self._handle.seek(offset)
        return self._handle.read(size)
    
    def get_size(self) -> int:
        """Get total image size."""
        return self._size
    
    def close(self):
        """Close handle."""
        self._handle.close()


class RawImageInfo:
    """PyTSK3 img_info wrapper for raw/DD images."""
    
    def __init__(self, file_paths: List[str]):
        """
        Initialize with one or more raw image files.
        For split images, provide all parts in order.
        """
        self._files = []
        self._total_size = 0
        self._file_offsets = []  # (start_offset, file_handle, file_size)
        
        current_offset = 0
        for fp in sorted(file_paths):
            f = open(fp, 'rb')
            f.seek(0, 2)  # Seek to end
            size = f.tell()
            f.seek(0)
            
            self._file_offsets.append((current_offset, f, size))
            current_offset += size
            self._files.append(f)
        
        self._total_size = current_offset
    
    def read(self, offset: int, size: int) -> bytes:
        """Read bytes from raw image, handling split files."""
        result = b''
        remaining = size
        current_offset = offset
        
        for start_off, fh, fsize in self._file_offsets:
            if current_offset >= start_off + fsize:
                continue
            if current_offset < start_off:
                continue
            
            # Calculate position within this file
            file_pos = current_offset - start_off
            readable = min(remaining, fsize - file_pos)
            
            fh.seek(file_pos)
            data = fh.read(readable)
            result += data
            
            remaining -= len(data)
            current_offset += len(data)
            
            if remaining <= 0:
                break
        
        return result
    
    def get_size(self) -> int:
        return self._total_size
    
    def close(self):
        for f in self._files:
            f.close()
        self._files = []


class VFSBuilder:
    """
    Builds VFS from evidence images.
    
    Supports:
    - E01/EWF (Expert Witness Format)
    - DD/RAW (Raw disk images)
    - Split images (E01, E02, ... or image.001, image.002, ...)
    """
    
    # Windows system folders
    WINDOWS_SYSTEM_FOLDERS = {
        'Windows', 'Program Files', 'Program Files (x86)', 
        'ProgramData', 'System Volume Information', '$Recycle.Bin',
        'Recovery', 'Boot', 'PerfLogs'
    }
    
    # User profile folders to detect
    USER_PROFILE_INDICATORS = {
        'Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos',
        'Music', 'AppData', 'NTUSER.DAT'
    }
    
    def __init__(
        self,
        vfs: VirtualFilesystem,
        progress_callback: Optional[Callable[[BuildProgress], None]] = None
    ):
        """
        Initialize VFS builder.
        
        Args:
            vfs: VirtualFilesystem instance
            progress_callback: Optional callback for progress updates
        """
        self.vfs = vfs
        self.progress_callback = progress_callback
        self._nodes_batch: List[VFSNode] = []
        self._batch_size = 1000
        self._file_count = 0
        self._folder_count = 0
    
    def _report_progress(self, phase: str, current: int, total: int, message: str, evidence_id: str = ""):
        """Report build progress."""
        if self.progress_callback:
            self.progress_callback(BuildProgress(
                phase=phase,
                current=current,
                total=total,
                message=message,
                evidence_id=evidence_id
            ))
    
    def detect_image_type(self, file_path: Path) -> ImageType:
        """Detect evidence image type from file - Comprehensive format detection."""
        suffix = file_path.suffix.lower()
        
        # Expert Witness Formats
        if suffix in ('.e01', '.ex01', '.s01'):
            return ImageType.EWF
        elif suffix in ('.l01', '.lx01', '.lef'):
            return ImageType.LEF
        
        # Raw/Basic Formats
        elif suffix in ('.dd', '.raw', '.001'):
            return ImageType.RAW
        elif suffix == '.img':
            return ImageType.IMG
        elif suffix == '.bin':
            return ImageType.BIN
        
        # Virtual Machine Disk Formats
        elif suffix == '.vmdk':
            return ImageType.VMDK
        elif suffix == '.vhd':
            return ImageType.VHD
        elif suffix == '.vhdx':
            return ImageType.VHDX
        elif suffix in ('.qcow', '.qcow2'):
            return ImageType.QCOW2
        elif suffix == '.vdi':
            return ImageType.VDI
        
        # Advanced Forensic Formats
        elif suffix == '.aff':
            return ImageType.AFF
        elif suffix == '.aff4':
            return ImageType.AFF4
        elif suffix == '.ad1':
            return ImageType.AD1
        
        # Optical/Container Formats
        elif suffix == '.iso':
            return ImageType.ISO
        elif suffix == '.dmg':
            return ImageType.DMG
        
        # Memory Formats
        elif suffix in ('.mem', '.dmp', '.dump', '.memory', '.mddramimage'):
            return ImageType.MEMORY
        elif suffix in ('.vmem', '.vmsn'):
            return ImageType.VMEM
        elif suffix == '.hiberfil':
            return ImageType.HIBERFIL
        elif suffix == '.core':
            return ImageType.CORE
        
        # Mobile Forensics
        elif suffix == '.tar':
            return ImageType.TAR
        elif suffix == '.ab':
            return ImageType.AB
        elif suffix in ('.ufed', '.ufd'):
            return ImageType.UFED
        elif suffix == '.backup':
            return ImageType.IOS_BACKUP
        
        # Archive Formats
        elif suffix == '.zip':
            return ImageType.ZIP
        elif suffix == '.7z':
            return ImageType.SEVENZIP
        elif suffix == '.rar':
            return ImageType.RAR
        
        # Network Captures
        elif suffix == '.pcap':
            return ImageType.PCAP
        elif suffix == '.pcapng':
            return ImageType.PCAPNG
        
        # Log/Event Formats
        elif suffix == '.evtx':
            return ImageType.EVTX
        elif suffix == '.etl':
            return ImageType.ETL
        
        # Database Formats
        elif suffix in ('.sqlite', '.sqlite3', '.db'):
            return ImageType.SQLITE
        elif suffix == '.pst':
            return ImageType.PST
        
        # Try to detect by magic bytes
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(16)
                # EVF/E01 signature
                if magic[:3] == b'EVF':
                    return ImageType.EWF
                # VMDK signature
                elif magic[:4] == b'KDMV':
                    return ImageType.VMDK
                # VHD signature
                elif magic[:8] == b'conectix':
                    return ImageType.VHD
                # VHDX signature
                elif magic[:8] == b'vhdxfile':
                    return ImageType.VHDX
                # QCOW2 signature
                elif magic[:4] == b'QFI\xfb':
                    return ImageType.QCOW2
                # ZIP signature
                elif magic[:4] == b'PK\x03\x04':
                    return ImageType.ZIP
                # 7z signature
                elif magic[:6] == b"7z\xbc\xaf'\x1c":
                    return ImageType.SEVENZIP
                # SQLite signature
                elif magic[:16] == b'SQLite format 3\x00':
                    return ImageType.SQLITE
                # PCAP signature
                elif magic[:4] in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'):
                    return ImageType.PCAP
                # PCAPNG signature
                elif magic[:4] == b'\x0a\x0d\x0d\x0a':
                    return ImageType.PCAPNG
        except:
            pass
        
        return ImageType.RAW  # Default to raw
    
    def find_image_segments(self, file_path: Path) -> List[Path]:
        """
        Find all segments of a split image.
        
        E01 → E01, E02, E03, ...
        001 → 001, 002, 003, ...
        """
        segments = []
        base = file_path.stem
        parent = file_path.parent
        suffix = file_path.suffix.lower()
        
        if suffix == '.e01':
            # Find E01, E02, ..., EAA, EAB, ...
            for ext in self._generate_ewf_extensions():
                seg = parent / f"{base}.{ext}"
                if seg.exists():
                    segments.append(seg)
                else:
                    break
        elif suffix == '.001':
            # Find 001, 002, ...
            for i in range(1, 1000):
                seg = parent / f"{base}.{i:03d}"
                if seg.exists():
                    segments.append(seg)
                else:
                    break
        else:
            segments = [file_path]
        
        return sorted(segments) if segments else [file_path]
    
    def _generate_ewf_extensions(self) -> Generator[str, None, None]:
        """Generate EWF extension sequence: E01-E99, EAA-EZZ."""
        # E01 through E99
        for i in range(1, 100):
            yield f"E{i:02d}"
        
        # EAA through EZZ
        for c1 in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            for c2 in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                yield f"E{c1}{c2}"
    
    def open_image(self, file_path: Path) -> Optional[Any]:
        """
        Open evidence image and return a readable handle.
        
        Returns:
            Image handle compatible with pytsk3 or None
        """
        image_type = self.detect_image_type(file_path)
        segments = self.find_image_segments(file_path)
        
        logger.info(f"Opening {image_type.value} image with {len(segments)} segment(s)")
        
        if image_type == ImageType.EWF:
            if not PYEWF_AVAILABLE:
                logger.error("pyewf not available for E01 images")
                return None
            
            try:
                ewf_handle = pyewf.handle()
                ewf_handle.open([str(s) for s in segments])
                return EWFImageInfo(ewf_handle)
            except Exception as e:
                logger.error(f"Failed to open EWF: {e}")
                return None
        
        elif image_type == ImageType.RAW:
            try:
                return RawImageInfo([str(s) for s in segments])
            except Exception as e:
                logger.error(f"Failed to open raw image: {e}")
                return None
        
        else:
            logger.warning(f"Unsupported image type: {image_type.value}")
            return None
    
    def build_from_image(
        self,
        image_path: Path,
        evidence_id: str,
        disk_name: str = None,
        compute_hashes: bool = False,
        max_file_size_for_hash: int = 100 * 1024 * 1024  # 100MB
    ) -> bool:
        """
        Build VFS from an evidence image.
        
        Args:
            image_path: Path to evidence image
            evidence_id: Unique evidence identifier
            disk_name: Display name for disk (default: filename)
            compute_hashes: Whether to compute file hashes
            max_file_size_for_hash: Max file size to hash
            
        Returns:
            True if successful
        """
        if not PYTSK3_AVAILABLE:
            logger.error("pytsk3 not available - cannot parse filesystem")
            return self._build_fallback(image_path, evidence_id, disk_name)
        
        self._report_progress("opening", 0, 100, f"Opening {image_path.name}...", evidence_id)
        
        # Open image
        img_handle = self.open_image(image_path)
        if not img_handle:
            return False
        
        try:
            disk_name = disk_name or image_path.stem
            
            # Ensure "This PC" root node exists
            self._ensure_root_node(evidence_id)
            
            # Create disk node under root
            disk_node = create_disk_node(
                disk_name=disk_name,
                disk_info=f"Evidence: {evidence_id}",
                evidence_id=evidence_id
            )
            self.vfs.add_node(disk_node)
            
            self._report_progress("partitions", 10, 100, "Detecting partitions...", evidence_id)
            
            # Get partitions using pytsk3
            partitions = self._get_partitions(img_handle)
            
            if not partitions:
                # Try as single filesystem
                logger.info("No partition table found, treating as single filesystem")
                self._process_filesystem(
                    img_handle, 0, disk_name, "Partition0", "NTFS", evidence_id, compute_hashes
                )
            else:
                # Process each partition
                for i, part in enumerate(partitions):
                    self._report_progress(
                        "partitions",
                        20 + (i * 60 // len(partitions)),
                        100,
                        f"Processing partition {i+1}/{len(partitions)}: {part.description}",
                        evidence_id
                    )
                    
                    if part.is_allocated and part.filesystem_type not in ('Unallocated', 'Extended'):
                        self._process_filesystem(
                            img_handle,
                            part.start_offset,
                            disk_name,
                            f"Partition{part.index}",
                            part.filesystem_type,
                            evidence_id,
                            compute_hashes
                        )
            
            # Flush remaining nodes
            self._flush_nodes()
            
            self._report_progress(
                "complete", 100, 100,
                f"Built VFS: {self._folder_count} folders, {self._file_count} files",
                evidence_id
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error building VFS: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            img_handle.close()
    
    def _get_partitions(self, img_handle) -> List[PartitionInfo]:
        """Get partition information using pytsk3."""
        partitions = []
        
        try:
            # Create pytsk3 Img_Info from our handle
            class TSKImgInfo(pytsk3.Img_Info):
                def __init__(self, handle):
                    self._handle = handle
                    super().__init__()
                
                def read(self, offset, size):
                    return self._handle.read(offset, size)
                
                def get_size(self):
                    return self._handle.get_size()
            
            tsk_img = TSKImgInfo(img_handle)
            volume = pytsk3.Volume_Info(tsk_img)
            
            for part in volume:
                partitions.append(PartitionInfo(
                    index=part.addr,
                    start_offset=part.start * 512,  # Convert sectors to bytes
                    length=part.len * 512,
                    description=part.desc.decode('utf-8', errors='replace'),
                    filesystem_type=self._detect_fs_type(part.desc.decode('utf-8', errors='replace')),
                    is_allocated=(part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC) != 0,
                    slot=part.slot_num
                ))
        except Exception as e:
            logger.warning(f"Could not read partition table: {e}")
        
        return partitions
    
    def _detect_fs_type(self, description: str) -> str:
        """Detect filesystem type from partition description."""
        desc = description.upper()
        
        if 'NTFS' in desc or 'MICROSOFT' in desc or 'WIN' in desc:
            return 'NTFS'
        elif 'FAT32' in desc:
            return 'FAT32'
        elif 'FAT16' in desc or 'FAT12' in desc:
            return 'FAT'
        elif 'EXFAT' in desc:
            return 'exFAT'
        elif 'EXT' in desc or 'LINUX' in desc:
            return 'ext4'
        elif 'HFS' in desc or 'APPLE' in desc:
            return 'HFS+'
        elif 'SWAP' in desc:
            return 'Swap'
        elif 'UNALLOC' in desc:
            return 'Unallocated'
        elif 'EXTEND' in desc:
            return 'Extended'
        
        return 'Unknown'
    
    def _process_filesystem(
        self,
        img_handle,
        offset: int,
        disk_name: str,
        partition_name: str,
        fs_type: str,
        evidence_id: str,
        compute_hashes: bool
    ):
        """Process a filesystem and add entries to VFS."""
        try:
            class TSKImgInfo(pytsk3.Img_Info):
                def __init__(self, handle):
                    self._handle = handle
                    super().__init__()
                
                def read(self, off, size):
                    return self._handle.read(off, size)
                
                def get_size(self):
                    return self._handle.get_size()
            
            tsk_img = TSKImgInfo(img_handle)
            fs = pytsk3.FS_Info(tsk_img, offset=offset)
            
            # Detect drive letter for Windows
            drive_letter = self._detect_drive_letter(fs, fs_type)
            
            if drive_letter:
                # Windows-style: Create drive node
                drive_node = create_drive_node(
                    parent_disk=disk_name,
                    drive_letter=drive_letter,
                    partition_info=f"{fs_type} ({partition_name})",
                    evidence_id=evidence_id
                )
                self.vfs.add_node(drive_node)
                base_path = f"/{disk_name}/{drive_letter}:"
            else:
                # Linux-style: Use partition name
                part_node = VFSNode(
                    id=0,
                    path=f"/{disk_name}/{partition_name}",
                    name=partition_name,
                    parent_path=f"/{disk_name}",
                    node_type=VFSNodeType.PARTITION,
                    evidence_id=evidence_id,
                    partition_info=fs_type
                )
                self.vfs.add_node(part_node)
                base_path = f"/{disk_name}/{partition_name}"
            
            # Walk filesystem
            self._walk_directory(fs, fs.info.root_inum, base_path, evidence_id, fs_type)
            
        except Exception as e:
            logger.error(f"Error processing filesystem at offset {offset}: {e}")
    
    def _detect_drive_letter(self, fs, fs_type: str) -> Optional[str]:
        """Try to detect Windows drive letter."""
        if fs_type not in ('NTFS', 'FAT32', 'FAT', 'exFAT'):
            return None
        
        try:
            # Check for Windows folder
            root = fs.open_dir("/")
            for entry in root:
                name = entry.info.name.name.decode('utf-8', errors='replace')
                if name.lower() == 'windows':
                    return 'C'  # Windows partition is usually C:
        except:
            pass
        
        return 'C'  # Default to C: for Windows filesystems
    
    def _walk_directory(
        self,
        fs,
        inode: int,
        parent_path: str,
        evidence_id: str,
        fs_type: str,
        depth: int = 0
    ):
        """Recursively walk directory and add nodes to VFS."""
        if depth > 100:  # Prevent infinite recursion
            return
        
        try:
            directory = fs.open_dir(inode=inode)
        except Exception as e:
            logger.debug(f"Could not open directory inode {inode}: {e}")
            return
        
        for entry in directory:
            try:
                name = entry.info.name.name.decode('utf-8', errors='replace')
                
                # Skip special entries
                if name in ('.', '..'):
                    continue
                
                # Skip system metafiles
                if name.startswith('$') and fs_type == 'NTFS':
                    continue
                
                meta = entry.info.meta
                if meta is None:
                    continue
                
                # Determine node type
                is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                is_deleted = entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC
                is_allocated = meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC
                
                # Detect special folder types
                is_user = False
                is_system = False
                
                if is_dir and parent_path.endswith('/Users'):
                    is_user = name not in ('Default', 'Default User', 'All Users', 'desktop.ini')
                elif is_dir and name in self.WINDOWS_SYSTEM_FOLDERS:
                    is_system = True
                
                # Create timestamps
                created = None
                modified = None
                accessed = None
                
                if meta.crtime:
                    try:
                        created = datetime.fromtimestamp(meta.crtime)
                    except:
                        pass
                if meta.mtime:
                    try:
                        modified = datetime.fromtimestamp(meta.mtime)
                    except:
                        pass
                if meta.atime:
                    try:
                        accessed = datetime.fromtimestamp(meta.atime)
                    except:
                        pass
                
                # Create node
                full_path = f"{parent_path}/{name}"
                
                if is_dir:
                    node_type = VFSNodeType.FOLDER
                    if is_user:
                        node_type = VFSNodeType.USER
                    elif is_system:
                        node_type = VFSNodeType.SYSTEM
                    elif is_deleted:
                        node_type = VFSNodeType.DELETED
                    
                    node = VFSNode(
                        id=0,
                        path=full_path,
                        name=name,
                        parent_path=parent_path,
                        node_type=node_type,
                        created=created,
                        modified=modified,
                        accessed=accessed,
                        evidence_id=evidence_id,
                        inode=meta.addr,
                        is_deleted=bool(is_deleted),
                        is_allocated=bool(is_allocated),
                    )
                    self._add_node(node)
                    self._folder_count += 1
                    
                    # Recurse into directory
                    self._walk_directory(fs, meta.addr, full_path, evidence_id, fs_type, depth + 1)
                else:
                    # File
                    node = VFSNode(
                        id=0,
                        path=full_path,
                        name=name,
                        parent_path=parent_path,
                        node_type=VFSNodeType.DELETED if is_deleted else VFSNodeType.FILE,
                        size=meta.size,
                        created=created,
                        modified=modified,
                        accessed=accessed,
                        mime_type=VirtualFilesystem.guess_mime_type(name),
                        evidence_id=evidence_id,
                        inode=meta.addr,
                        is_deleted=bool(is_deleted),
                        is_allocated=bool(is_allocated),
                    )
                    self._add_node(node)
                    self._file_count += 1
                    
            except Exception as e:
                logger.debug(f"Error processing entry: {e}")
                continue
    
    def _ensure_root_node(self, evidence_id: str = None):
        """Ensure 'This PC' root node exists in the VFS."""
        existing = self.vfs.get_node("/")
        if not existing:
            root_node = VFSNode(
                id=0,
                path="/",
                name="This PC",
                parent_path="",
                node_type=VFSNodeType.ROOT,
                evidence_id=evidence_id,
            )
            self.vfs.add_node(root_node)

    def _add_node(self, node: VFSNode):
        """Add node to batch, flush if batch is full."""
        self._nodes_batch.append(node)
        if len(self._nodes_batch) >= self._batch_size:
            self._flush_nodes()
    
    def _flush_nodes(self):
        """Flush batch of nodes to database."""
        if self._nodes_batch:
            self.vfs.add_nodes_batch(self._nodes_batch)
            self._nodes_batch = []
    
    def _build_fallback(
        self,
        image_path: Path,
        evidence_id: str,
        disk_name: str = None
    ) -> bool:
        """
        Fallback VFS builder when pytsk3 is not available.
        Creates a placeholder structure.
        """
        logger.warning("Using fallback VFS builder (pytsk3 not available)")
        
        disk_name = disk_name or image_path.stem
        
        # Ensure "This PC" root node exists
        self._ensure_root_node(evidence_id)
        
        # Create basic structure
        disk_node = create_disk_node(
            disk_name=disk_name,
            disk_info=f"Evidence: {evidence_id} (Limited parsing)",
            evidence_id=evidence_id
        )
        self.vfs.add_node(disk_node)
        
        # Create placeholder drive
        drive_node = create_drive_node(
            parent_disk=disk_name,
            drive_letter="C",
            partition_info="Requires pytsk3 for full parsing",
            evidence_id=evidence_id
        )
        self.vfs.add_node(drive_node)
        
        # Add info node
        info_node = VFSNode(
            id=0,
            path=f"/{disk_name}/C:/_FEPD_INFO.txt",
            name="_FEPD_INFO.txt",
            parent_path=f"/{disk_name}/C:",
            node_type=VFSNodeType.FILE,
            size=0,
            mime_type="text/plain",
            evidence_id=evidence_id,
            metadata={"info": "Install pytsk3 and pyewf for full filesystem parsing"}
        )
        self.vfs.add_node(info_node)
        
        return True
    
    def build_from_directory(
        self,
        directory_path: Path,
        evidence_id: str,
        disk_name: str = None
    ) -> bool:
        """
        Build VFS from a directory (for testing or extracted evidence).
        
        Args:
            directory_path: Path to directory
            evidence_id: Evidence identifier
            disk_name: Display name
            
        Returns:
            True if successful
        """
        if not directory_path.is_dir():
            logger.error(f"Not a directory: {directory_path}")
            return False
        
        disk_name = disk_name or directory_path.name
        
        # Create disk node
        disk_node = create_disk_node(
            disk_name=disk_name,
            disk_info=f"Directory: {directory_path}",
            evidence_id=evidence_id
        )
        self.vfs.add_node(disk_node)
        
        base_path = f"/{disk_name}"
        
        # Walk directory
        for root, dirs, files in os.walk(directory_path):
            rel_root = Path(root).relative_to(directory_path)
            current_path = f"{base_path}/{str(rel_root).replace(os.sep, '/')}"
            if current_path.endswith('/.'):
                current_path = current_path[:-2]
            
            # Create folder nodes
            for d in dirs:
                folder_path = f"{current_path}/{d}"
                is_user = current_path.endswith('/Users') and d not in ('Default', 'Public')
                
                node = VFSNode(
                    id=0,
                    path=folder_path,
                    name=d,
                    parent_path=current_path,
                    node_type=VFSNodeType.USER if is_user else VFSNodeType.FOLDER,
                    evidence_id=evidence_id
                )
                self._add_node(node)
                self._folder_count += 1
            
            # Create file nodes
            for f in files:
                file_path = f"{current_path}/{f}"
                full_path = Path(root) / f
                
                try:
                    stat = full_path.stat()
                    size = stat.st_size
                    modified = datetime.fromtimestamp(stat.st_mtime)
                except:
                    size = 0
                    modified = None
                
                node = VFSNode(
                    id=0,
                    path=file_path,
                    name=f,
                    parent_path=current_path,
                    node_type=VFSNodeType.FILE,
                    size=size,
                    modified=modified,
                    mime_type=VirtualFilesystem.guess_mime_type(f),
                    evidence_id=evidence_id
                )
                self._add_node(node)
                self._file_count += 1
        
        self._flush_nodes()
        
        logger.info(f"Built VFS from directory: {self._folder_count} folders, {self._file_count} files")
        return True
