"""
FEPD Virtual Evidence File System (VEFS) Builder
=================================================

Reconstructs the original operating system filesystem from forensic images.
After evidence ingestion, FEPD becomes "the victim's file system — frozen in time,
navigable like Windows Explorer, but immune to change."

Architecture:
    E01/DD/IMG → DiskImageHandler → VEFS Builder → VFS Database → Files Tab

The VEFS maps each file/folder to:
    (image_path, partition_index, offset, inode/MFT_ref)

This enables reading file contents directly from the forensic image without
extracting or modifying the evidence.
"""

import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple, Generator
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json
import mimetypes

try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    TSK_AVAILABLE = False
    pytsk3 = None

from .virtual_fs import VirtualFilesystem, VFSNode, VFSNodeType


class OSType(Enum):
    """Detected operating system type."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    UNKNOWN = "unknown"


@dataclass
class PartitionInfo:
    """Information about a disk partition."""
    index: int
    description: str
    start_sector: int
    length_sectors: int
    fs_type: str
    offset_bytes: int
    size_bytes: int
    drive_letter: Optional[str] = None  # For Windows: C:, D:, etc.
    mount_point: Optional[str] = None   # For Linux/macOS: /, /home, etc.
    os_type: OSType = OSType.UNKNOWN
    is_bootable: bool = False
    is_system: bool = False
    
    @property
    def display_name(self) -> str:
        """Get display name for UI."""
        if self.drive_letter:
            return f"{self.drive_letter}"
        elif self.mount_point:
            return self.mount_point
        elif "EFI" in self.description.upper():
            return "EFI System"
        elif "RESERVED" in self.description.upper():
            return "System Reserved"
        elif "RECOVERY" in self.description.upper():
            return "Recovery"
        else:
            return f"Partition {self.index}"


@dataclass
class VEFSFileEntry:
    """
    Entry in the Virtual Evidence File System.
    
    Maps a file/folder to its location in the forensic image for direct reading.
    """
    path: str                           # VFS path: /C:/Users/John/Desktop/file.txt
    name: str                           # File name: file.txt
    parent_path: str                    # Parent: /C:/Users/John/Desktop
    is_directory: bool
    size: int = 0
    
    # Image location (for reading file contents)
    image_path: Optional[str] = None    # Path to E01/DD image
    partition_index: int = 0            # Partition index
    inode: Optional[int] = None         # Inode/MFT entry number
    
    # Timestamps (MACB)
    modified: Optional[datetime] = None
    accessed: Optional[datetime] = None
    created: Optional[datetime] = None
    changed: Optional[datetime] = None  # Metadata change time
    
    # Metadata
    is_deleted: bool = False
    is_allocated: bool = True
    owner: Optional[str] = None
    permissions: Optional[str] = None
    
    def to_vfs_node(self, evidence_id: str = None) -> VFSNode:
        """Convert to VFSNode for database storage."""
        # Determine node type
        if self.is_directory:
            # Check for special folder types
            name_lower = self.name.lower()
            path_lower = self.path.lower()
            
            if '/users/' in path_lower and name_lower not in ('users', 'public', 'default', 'all users'):
                node_type = VFSNodeType.USER
            elif name_lower in ('windows', 'winnt', 'system32', 'program files', 'program files (x86)'):
                node_type = VFSNodeType.SYSTEM
            elif len(self.path.split('/')) == 2 and ':' in self.name:
                node_type = VFSNodeType.DRIVE
            else:
                node_type = VFSNodeType.FOLDER
        else:
            node_type = VFSNodeType.DELETED if self.is_deleted else VFSNodeType.FILE
        
        # Build metadata for image location
        metadata = {
            'image_path': self.image_path,
            'partition_index': self.partition_index,
            'inode': self.inode,
            'owner': self.owner,
            'permissions': self.permissions,
        }
        
        return VFSNode(
            id=0,
            path=self.path,
            name=self.name,
            parent_path=self.parent_path,
            node_type=node_type,
            size=self.size,
            created=self.created,
            modified=self.modified,
            accessed=self.accessed,
            inode=self.inode,
            is_deleted=self.is_deleted,
            is_allocated=self.is_allocated,
            evidence_id=evidence_id,
            metadata=metadata,
        )


class VEFSBuilder:
    """
    Virtual Evidence File System Builder.
    
    Constructs a complete filesystem tree from forensic images, enabling
    Explorer-like navigation of the victim's machine.
    
    Features:
    - Auto-detect OS type (Windows/Linux/macOS)
    - Reconstruct drive letters and mount points
    - Full directory tree with proper hierarchy
    - Map files to image offsets for direct reading
    - User profile detection
    - System folder identification
    """
    
    # Windows system folders to detect
    WINDOWS_SYSTEM_FOLDERS = {
        'windows', 'winnt', 'program files', 'program files (x86)',
        'programdata', 'system volume information', '$recycle.bin',
        'recovery', 'perflogs', 'msocache'
    }
    
    # Linux system directories
    LINUX_SYSTEM_DIRS = {
        'bin', 'sbin', 'usr', 'var', 'etc', 'lib', 'lib64',
        'opt', 'boot', 'dev', 'proc', 'sys', 'tmp', 'run'
    }
    
    def __init__(self, image_handler, vfs: VirtualFilesystem, logger=None):
        """
        Initialize VEFS Builder.
        
        Args:
            image_handler: DiskImageHandler instance (already opened)
            vfs: VirtualFilesystem database to populate
            logger: Optional logger instance
        """
        self.handler = image_handler
        self.vfs = vfs
        self.logger = logger or logging.getLogger(__name__)
        
        self.partitions: List[PartitionInfo] = []
        self.os_type = OSType.UNKNOWN
        self.evidence_id = Path(image_handler.image_path).name
        
        # Statistics
        self.stats = {
            'total_files': 0,
            'total_folders': 0,
            'total_size': 0,
            'deleted_files': 0,
            'user_profiles': [],
        }
    
    def build(self, progress_callback=None) -> bool:
        """
        Build the complete VEFS from the forensic image.
        
        Args:
            progress_callback: Optional callback(current, total, message)
            
        Returns:
            True if successful
        """
        self.logger.info("Building VEFS...")
        
        try:
            # Step 1: Enumerate and analyze partitions
            self._report_progress(progress_callback, 0, 100, "Analyzing partitions...")
            self._analyze_partitions()
            
            # Step 2: Clear existing VFS for this evidence
            self.vfs.clear_evidence(self.evidence_id)
            
            # Step 3: Create root structure
            self._report_progress(progress_callback, 5, 100, "Creating filesystem...")
            self._create_root_structure()
            
            # Step 4: Walk each partition and build tree
            total_partitions = len(self.partitions)
            for i, partition in enumerate(self.partitions):
                progress_base = 10 + int((i / total_partitions) * 85)
                progress_end = 10 + int(((i + 1) / total_partitions) * 85)
                
                self._report_progress(
                    progress_callback, 
                    progress_base, 
                    100, 
                    f"Scanning {partition.display_name}..."
                )
                
                self._build_partition_tree(
                    partition, 
                    lambda cur, tot, msg: self._report_progress(
                        progress_callback,
                        progress_base + int((cur / max(tot, 1)) * (progress_end - progress_base)),
                        100,
                        msg
                    )
                )
            
            # Step 5: Finalize
            self._report_progress(progress_callback, 95, 100, "Finalizing...")
            self._detect_user_profiles()
            
            self._report_progress(progress_callback, 100, 100, "Complete")
            
            self.logger.info(f"VEFS: {self.stats['total_files']:,} files, {self.stats['total_folders']:,} folders")
            
            return True
            
        except Exception as e:
            self.logger.error(f"VEFS build failed: {e}")
            return False
    
    def _analyze_partitions(self):
        """Analyze disk partitions and detect OS type."""
        raw_partitions = self.handler.enumerate_partitions()
        
        self.partitions = []
        drive_letter_counter = ord('C')  # Start with C:
        
        for part in raw_partitions:
            partition = PartitionInfo(
                index=part['index'],
                description=part['description'],
                start_sector=part['start'],
                length_sectors=part['length'],
                fs_type=part['type'],
                offset_bytes=part['start'] * 512,
                size_bytes=part['length'] * 512,
            )
            
            # Detect partition purpose
            desc_upper = part['description'].upper()
            
            if 'EFI' in desc_upper:
                partition.is_system = True
            elif 'RESERVED' in desc_upper or 'MSR' in desc_upper:
                partition.is_system = True
            elif 'RECOVERY' in desc_upper:
                partition.is_system = True
            elif 'BOOT' in desc_upper:
                partition.is_bootable = True
            
            # Try to detect OS from filesystem content
            if not partition.is_system:
                os_type, drive_letter = self._detect_partition_os(partition)
                partition.os_type = os_type
                
                if os_type == OSType.WINDOWS:
                    # Assign drive letter
                    partition.drive_letter = f"{chr(drive_letter_counter)}:"
                    drive_letter_counter += 1
                    self.os_type = OSType.WINDOWS
                elif os_type == OSType.LINUX:
                    partition.mount_point = drive_letter or "/"
                    self.os_type = OSType.LINUX
                elif os_type == OSType.MACOS:
                    partition.mount_point = drive_letter or "/"
                    self.os_type = OSType.MACOS
            
            self.partitions.append(partition)
            self.logger.info(
                f"Partition {partition.index}: {partition.display_name} "
                f"({partition.fs_type}, {self._format_size(partition.size_bytes)})"
            )
        
        self.logger.info(f"Detected OS: {self.os_type.value}")
    
    def _detect_partition_os(self, partition: PartitionInfo) -> Tuple[OSType, Optional[str]]:
        """
        Detect OS type by examining partition contents.
        
        Returns:
            Tuple of (OSType, drive_letter_or_mount_point)
        """
        try:
            fs_info = self.handler.open_filesystem(partition.index)
            if not fs_info:
                return OSType.UNKNOWN, None
            
            # Check for Windows indicators
            windows_markers = ['Windows', 'WINDOWS', 'Program Files', 'Users', 'ProgramData']
            linux_markers = ['etc', 'var', 'usr', 'home', 'bin']
            macos_markers = ['Applications', 'Library', 'System', 'Users', 'private']
            
            root_entries = self.handler.list_directory(fs_info, "/")
            entry_names = {e['name'] for e in root_entries}
            
            # Check Windows
            if any(m in entry_names for m in windows_markers):
                return OSType.WINDOWS, None
            
            # Check Linux
            linux_matches = sum(1 for m in linux_markers if m in entry_names)
            if linux_matches >= 3:
                return OSType.LINUX, "/"
            
            # Check macOS
            macos_matches = sum(1 for m in macos_markers if m in entry_names)
            if macos_matches >= 3:
                return OSType.MACOS, "/"
            
            return OSType.UNKNOWN, None
            
        except Exception as e:
            self.logger.debug(f"Could not detect OS for partition {partition.index}: {e}")
            return OSType.UNKNOWN, None
    
    def _create_root_structure(self):
        """
        Create the root VFS structure - Windows Explorer "This PC" style.
        
        Structure:
            🖥️ This PC (Evidence)
            ├── 💾 Local Disk (C:)
            ├── 💾 Local Disk (D:)
            ├── ⚙️ EFI System
            ├── ⚙️ Recovery
            └── ⚙️ System Reserved
        """
        nodes = []
        
        # Create "This PC" root node - the top-level entry point
        this_pc_node = VFSNode(
            id=0,
            path="/This PC",
            name="This PC",
            parent_path="/",
            node_type=VFSNodeType.ROOT,
            size=0,
            evidence_id=self.evidence_id,
            partition_info=f"Evidence: {self.evidence_id}",
            metadata={
                'os_type': self.os_type.value,
                'evidence_source': str(self.handler.image_path),
                'is_this_pc': True,
            }
        )
        nodes.append(this_pc_node)
        
        # Create nodes for each partition under "This PC"
        for partition in self.partitions:
            if partition.drive_letter:
                # Windows drive: /This PC/C:
                # Display as "Local Disk (C:)" for Windows Explorer feel
                part_path = f"/This PC/{partition.drive_letter}"
                part_name = f"Local Disk ({partition.drive_letter})"
                node_type = VFSNodeType.DRIVE
            elif partition.mount_point:
                # Unix mount point
                if partition.mount_point == "/":
                    part_path = "/This PC/root"
                    part_name = "Root Filesystem (/)"
                else:
                    mount_name = partition.mount_point.strip('/')
                    part_path = f"/This PC/{mount_name}"
                    part_name = mount_name
                node_type = VFSNodeType.PARTITION
            elif partition.is_system:
                # System partition (EFI, Recovery, etc.)
                safe_name = partition.display_name.replace(' ', '_')
                part_path = f"/This PC/{safe_name}"
                part_name = partition.display_name
                node_type = VFSNodeType.PARTITION
            else:
                # Generic partition
                part_path = f"/This PC/Partition_{partition.index}"
                part_name = f"Partition {partition.index}"
                node_type = VFSNodeType.PARTITION
            
            # Create partition info string like Windows shows
            size_str = self._format_size(partition.size_bytes)
            if partition.drive_letter:
                part_info = f"{partition.fs_type} • {size_str}"
            else:
                part_info = f"{partition.fs_type}, {size_str}"
            
            part_node = VFSNode(
                id=0,
                path=part_path,
                name=part_name,
                parent_path="/This PC",
                node_type=node_type,
                size=partition.size_bytes,
                evidence_id=self.evidence_id,
                partition_info=part_info,
                metadata={
                    'partition_index': partition.index,
                    'fs_type': partition.fs_type,
                    'offset_bytes': partition.offset_bytes,
                    'size_bytes': partition.size_bytes,
                    'drive_letter': partition.drive_letter,
                    'is_system_partition': partition.is_system,
                }
            )
            nodes.append(part_node)
        
        if nodes:
            self.vfs.add_nodes_batch(nodes)
            self.logger.info(f"Created 'This PC' root with {len(nodes) - 1} partitions")
    
    def _build_partition_tree(self, partition: PartitionInfo, progress_callback=None):
        """
        Build filesystem tree for a partition.
        
        Args:
            partition: PartitionInfo object
            progress_callback: Progress callback
        """
        try:
            fs_info = self.handler.open_filesystem(partition.index)
            if not fs_info:
                self.logger.warning(f"Cannot open filesystem on partition {partition.index}")
                return
            
            # Determine base path - matches the structure from _create_root_structure
            if partition.drive_letter:
                base_path = f"/This PC/{partition.drive_letter}"
            elif partition.mount_point:
                if partition.mount_point == "/":
                    base_path = "/This PC/root"
                else:
                    base_path = f"/This PC/{partition.mount_point.strip('/')}"
            elif partition.is_system:
                base_path = f"/This PC/{partition.display_name.replace(' ', '_')}"
            else:
                base_path = f"/This PC/Partition_{partition.index}"
            
            # Walk the filesystem with limits to prevent UI freeze
            nodes_batch = []
            batch_size = 1000  # Larger batch for less frequent DB writes
            processed = 0
            last_progress_call = 0
            MAX_ITEMS_PER_PARTITION = 25000  # Reduced limit for faster UI
            
            for vfs_path, entries in self._walk_filesystem(fs_info, "/", base_path, partition):
                for entry in entries:
                    # Stop if we've processed too many items
                    if processed >= MAX_ITEMS_PER_PARTITION:
                        self.logger.warning(f"Reached max items limit ({MAX_ITEMS_PER_PARTITION}) for partition {partition.display_name}")
                        break
                    
                    node = entry.to_vfs_node(self.evidence_id)
                    nodes_batch.append(node)
                    
                    # Update stats
                    if entry.is_directory:
                        self.stats['total_folders'] += 1
                    else:
                        self.stats['total_files'] += 1
                        self.stats['total_size'] += entry.size
                        if entry.is_deleted:
                            self.stats['deleted_files'] += 1
                    
                    # Batch insert with more frequent progress
                    if len(nodes_batch) >= batch_size:
                        self.vfs.add_nodes_batch(nodes_batch)
                        processed += len(nodes_batch)
                        nodes_batch = []
                        
                        # Call progress callback every 2000 items for less UI overhead
                        if progress_callback and (processed - last_progress_call) >= 2000:
                            progress_callback(processed, processed + 2000, f"Indexed {processed:,} items...")
                            last_progress_call = processed
                
                # Check limit in outer loop too
                if processed >= MAX_ITEMS_PER_PARTITION:
                    break
            
            # Insert remaining
            if nodes_batch:
                self.vfs.add_nodes_batch(nodes_batch)
                processed += len(nodes_batch)
            
            # Final progress callback
            if progress_callback:
                progress_callback(processed, processed, f"Completed {processed:,} items")
            
            self.logger.info(f"Indexed {processed:,} items from {partition.display_name}")
            
        except Exception as e:
            self.logger.error(f"Error building tree for partition {partition.index}: {e}")
    
    def _walk_filesystem(
        self, 
        fs_info, 
        fs_path: str, 
        vfs_base: str, 
        partition: PartitionInfo,
        max_depth: int = 50
    ) -> Generator[Tuple[str, List[VEFSFileEntry]], None, None]:
        """
        Walk a filesystem recursively, yielding entries.
        
        Args:
            fs_info: pytsk3.FS_Info object
            fs_path: Current path in filesystem
            vfs_base: Base path in VFS
            partition: Partition info
            max_depth: Maximum recursion depth
            
        Yields:
            Tuples of (vfs_path, list of VEFSFileEntry)
        """
        if max_depth <= 0:
            return
        
        try:
            directory = fs_info.open_dir(fs_path)
        except Exception as e:
            self.logger.debug(f"Cannot open directory {fs_path}: {e}")
            return
        
        entries = []
        subdirs = []
        
        for entry in directory:
            try:
                # Get name
                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode('utf-8', errors='replace')
                
                # Skip . and ..
                if name in ('.', '..'):
                    continue
                
                # Skip entries without metadata
                if not entry.info.meta:
                    continue
                
                # Build paths
                entry_fs_path = f"{fs_path}/{name}".replace('//', '/')
                entry_vfs_path = f"{vfs_base}/{name}".replace('//', '/')
                parent_vfs_path = vfs_base
                
                # Get entry type
                is_dir = entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                
                # Get timestamps
                modified = None
                accessed = None
                created = None
                changed = None
                
                if hasattr(entry.info.meta, 'mtime') and entry.info.meta.mtime:
                    try:
                        modified = datetime.fromtimestamp(entry.info.meta.mtime)
                    except:
                        pass
                
                if hasattr(entry.info.meta, 'atime') and entry.info.meta.atime:
                    try:
                        accessed = datetime.fromtimestamp(entry.info.meta.atime)
                    except:
                        pass
                
                if hasattr(entry.info.meta, 'crtime') and entry.info.meta.crtime:
                    try:
                        created = datetime.fromtimestamp(entry.info.meta.crtime)
                    except:
                        pass
                
                if hasattr(entry.info.meta, 'ctime') and entry.info.meta.ctime:
                    try:
                        changed = datetime.fromtimestamp(entry.info.meta.ctime)
                    except:
                        pass
                
                # Check deleted/allocated status
                is_deleted = False
                is_allocated = True
                if hasattr(entry.info.name, 'flags'):
                    if entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC:
                        is_deleted = True
                        is_allocated = False
                
                # Get size
                size = entry.info.meta.size if hasattr(entry.info.meta, 'size') else 0
                
                # Get inode
                inode = entry.info.meta.addr if hasattr(entry.info.meta, 'addr') else None
                
                # Create entry
                vefs_entry = VEFSFileEntry(
                    path=entry_vfs_path,
                    name=name,
                    parent_path=parent_vfs_path,
                    is_directory=is_dir,
                    size=size if not is_dir else 0,
                    image_path=str(self.handler.image_path),
                    partition_index=partition.index,
                    inode=inode,
                    modified=modified,
                    accessed=accessed,
                    created=created,
                    changed=changed,
                    is_deleted=is_deleted,
                    is_allocated=is_allocated,
                )
                
                entries.append(vefs_entry)
                
                if is_dir and not is_deleted:
                    subdirs.append((entry_fs_path, entry_vfs_path))
                    
            except Exception as e:
                self.logger.debug(f"Error processing entry in {fs_path}: {e}")
                continue
        
        # Yield current directory's entries
        if entries:
            yield (vfs_base, entries)
        
        # Recurse into subdirectories
        for sub_fs_path, sub_vfs_path in subdirs:
            yield from self._walk_filesystem(
                fs_info, sub_fs_path, sub_vfs_path, partition, max_depth - 1
            )
    
    def _detect_user_profiles(self):
        """Detect and mark user profile folders."""
        # Search for Users folder (Windows) or home directory (Linux/macOS)
        user_paths = []
        
        if self.os_type == OSType.WINDOWS:
            # Check all drive letters for Users folder
            for partition in self.partitions:
                if partition.drive_letter:
                    # Use new /This PC/ path structure
                    users_path = f"/This PC/{partition.drive_letter}/Users"
                    users_node = self.vfs.get_node(users_path)
                    if users_node:
                        # Get all children except system users
                        children = self.vfs.get_children(users_path)
                        for child in children:
                            if child.is_directory:
                                name_lower = child.name.lower()
                                if name_lower not in ('public', 'default', 'default user', 'all users'):
                                    user_paths.append(child.name)
                    
                    # Also check Documents and Settings (XP)
                    docs_path = f"/This PC/{partition.drive_letter}/Documents and Settings"
                    docs_node = self.vfs.get_node(docs_path)
                    if docs_node:
                        children = self.vfs.get_children(docs_path)
                        for child in children:
                            if child.is_directory:
                                name_lower = child.name.lower()
                                if name_lower not in ('all users', 'default user', 'localservice', 'networkservice'):
                                    if child.name not in user_paths:
                                        user_paths.append(child.name)
        
        elif self.os_type in (OSType.LINUX, OSType.MACOS):
            # Check /home directory with new path structure
            home_path = "/This PC/root/home"
            home_node = self.vfs.get_node(home_path)
            if home_node:
                children = self.vfs.get_children(home_path)
                for child in children:
                    if child.is_directory:
                        user_paths.append(child.name)
        
        self.stats['user_profiles'] = user_paths
        self.logger.info(f"Detected {len(user_paths)} user profile(s): {', '.join(user_paths)}")
    
    def read_file(self, vfs_path: str) -> Optional[bytes]:
        """
        Read file contents directly from the forensic image.
        
        This is the key function that allows file viewing without extraction.
        
        Args:
            vfs_path: Path in VFS (e.g., /C:/Users/John/document.txt)
            
        Returns:
            File contents as bytes, or None if failed
        """
        node = self.vfs.get_node(vfs_path)
        if not node:
            self.logger.warning(f"VFS node not found: {vfs_path}")
            return None
        
        if node.is_directory:
            self.logger.warning(f"Cannot read directory as file: {vfs_path}")
            return None
        
        # Get image location from metadata
        metadata = node.metadata or {}
        partition_index = metadata.get('partition_index', 0)
        inode = metadata.get('inode') or node.inode
        
        try:
            fs_info = self.handler.open_filesystem(partition_index)
            if not fs_info:
                self.logger.error(f"Cannot open filesystem for partition {partition_index}")
                return None
            
            # Open file by inode if available, otherwise by path
            if inode:
                file_obj = fs_info.open_meta(inode)
            else:
                # Reconstruct filesystem path from VFS path
                fs_path = self._vfs_path_to_fs_path(vfs_path)
                file_obj = fs_info.open(fs_path)
            
            if not file_obj:
                return None
            
            # Read file contents
            size = file_obj.info.meta.size if hasattr(file_obj.info.meta, 'size') else 0
            if size == 0:
                return b''
            
            # Read in chunks to avoid memory issues
            data = b''
            offset = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            
            while offset < size:
                read_size = min(chunk_size, size - offset)
                chunk = file_obj.read_random(offset, read_size)
                if not chunk:
                    break
                data += chunk
                offset += len(chunk)
            
            return data
            
        except Exception as e:
            self.logger.error(f"Error reading file {vfs_path}: {e}")
            return None
    
    def _vfs_path_to_fs_path(self, vfs_path: str) -> str:
        """
        Convert VFS path to filesystem path for reading from evidence.
        
        /This PC/C:/Users/John/file.txt → /Users/John/file.txt
        /This PC/root/home/user/file.txt → /home/user/file.txt
        /This PC/Local Disk (C:)/Users/John/file.txt → /Users/John/file.txt
        
        The VFS path starts with /This PC/{partition}/ and we need to strip
        that prefix to get the actual filesystem path.
        """
        parts = vfs_path.split('/')
        
        # Handle /This PC/... structure
        if len(parts) > 2 and parts[1] == 'This PC':
            # Skip /This PC/partition_name/ - get everything after that
            partition_part = parts[2]  # e.g., "C:", "Local Disk (C:)", "root", "Recovery"
            
            # Return the rest as filesystem path
            if len(parts) > 3:
                return '/' + '/'.join(parts[3:])
            else:
                return '/'
        
        # Handle old-style paths for backward compatibility
        if len(parts) > 1:
            first_part = parts[1]
            # Check if it's a drive letter (C:) or partition name
            if ':' in first_part or first_part in ('root_fs', 'root', 'home'):
                return '/' + '/'.join(parts[2:]) if len(parts) > 2 else '/'
        
        return vfs_path
    
    def _report_progress(self, callback, current: int, total: int, message: str):
        """Report progress if callback provided."""
        if callback:
            callback(current, total, message)
        self.logger.debug(f"Progress: {current}/{total} - {message}")
    
    @staticmethod
    def _format_size(size: int) -> str:
        """Format size in human-readable form."""
        size_float = float(size)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_float < 1024:
                return f"{size_float:.1f} {unit}"
            size_float /= 1024
        return f"{size_float:.1f} PB"


def build_vefs_from_image(
    image_path: str,
    vfs_db_path: str,
    progress_callback=None,
    logger=None
) -> bool:
    """
    Convenience function to build VEFS from a forensic image.
    
    Args:
        image_path: Path to E01/DD/IMG file
        vfs_db_path: Path to VFS SQLite database
        progress_callback: Optional callback(current, total, message)
        logger: Optional logger
        
    Returns:
        True if successful
    """
    from ..modules.image_handler import DiskImageHandler
    
    log = logger or logging.getLogger(__name__)
    
    try:
        # Open image
        handler = DiskImageHandler(image_path, verify_hash=False)
        if not handler.open_image():
            log.error(f"Failed to open image: {image_path}")
            return False
        
        # Create VFS
        vfs = VirtualFilesystem(Path(vfs_db_path))
        
        # Build VEFS
        builder = VEFSBuilder(handler, vfs, log)
        result = builder.build(progress_callback)
        
        # Cleanup
        handler.close()
        
        return result
        
    except Exception as e:
        log.error(f"VEFS build failed: {e}", exc_info=True)
        return False
