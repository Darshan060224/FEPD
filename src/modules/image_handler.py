"""
FEPD - Disk Image Handler
Forensically-sound mounting and parsing of E01/DD disk images

Features:
- Read-only E01 (Expert Witness) and raw DD image support
- Partition and file system enumeration
- NTFS/FAT file system navigation
- Artifact extraction without modification
- Cryptographic hash verification
- Court-admissible evidence handling

Libraries:
- pyewf: E01 image handling (libewf wrapper)
- pytsk3: The Sleuth Kit for file system parsing
- hashlib: Cryptographic hashing (MD5, SHA-256)
"""

import logging
import hashlib
import os
import re
from pathlib import Path
from typing import Optional, List, Dict, Any, BinaryIO
from datetime import datetime

try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    TSK_AVAILABLE = False
    pytsk3 = None
    logging.warning("pytsk3 not available - disk image parsing disabled")

try:
    import pyewf
    EWF_AVAILABLE = True
except ImportError:
    EWF_AVAILABLE = False
    pyewf = None
    logging.warning("pyewf not available - E01 image support disabled")


# Define EwfImgInfo only if pytsk3 is available
if TSK_AVAILABLE and pytsk3 is not None:
    class EwfImgInfo(pytsk3.Img_Info):  # type: ignore[no-redef]
        """
        Wrapper class for pyewf handle to work with pytsk3.
        Provides read-only access to E01 images via The Sleuth Kit.
        """
        
        def __init__(self, ewf_handle):
            """
            Initialize wrapper around pyewf handle.
            
            Args:
                ewf_handle: pyewf.handle() object with opened E01 segments
            """
            self._ewf_handle = ewf_handle
            super(EwfImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
        
        def close(self):
            """Close the EWF handle."""
            self._ewf_handle.close()
        
        def read(self, offset: int, size: int) -> bytes:
            """
            Read bytes from the image at specified offset.
            
            Args:
                offset: Byte offset to read from
                size: Number of bytes to read
                
            Returns:
                Bytes read from image
            """
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)
        
        def get_size(self) -> int:
            """
            Get total size of the image in bytes.
            
            Returns:
                Image size in bytes
            """
            return self._ewf_handle.get_media_size()
else:
    # Define a placeholder if pytsk3 is not available
    class EwfImgInfo:  # type: ignore[no-redef]
        """Placeholder class when pytsk3 is not available."""
        def __init__(self, *args, **kwargs):
            raise ImportError("pytsk3 is not available - EwfImgInfo requires pytsk3")


class DiskImageHandler:
    """
    Forensically-sound disk image handler for E01 and raw images.
    Provides read-only access to artifacts within disk images.
    """
    
    def __init__(self, image_path: str, verify_hash: bool = True):
        """
        Initialize disk image handler.
        
        Args:
            image_path: Path to disk image (E01 or raw DD)
            verify_hash: Whether to verify image hash on load
        """
        self.logger = logging.getLogger(__name__)
        self.image_path = Path(image_path)
        self.verify_hash = verify_hash
        
        self.image_handle = None
        self.volume_info = None
        self.partitions = []
        self.file_systems = {}
        
        self.image_type = None  # 'ewf' or 'raw'
        self.image_hash = None
        self.image_size = 0
        
        # Check library availability
        if not TSK_AVAILABLE:
            raise RuntimeError("pytsk3 is required for disk image parsing")
    
    def open_image(self) -> bool:
        """
        Open disk image in read-only mode.
        Detects image type (E01 or raw) and creates appropriate handle.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Detect image type by extension
            ext = self.image_path.suffix.lower()
            
            if ext in ['.e01', '.ex01']:
                return self._open_ewf_image()
            elif ext in ['.dd', '.raw', '.img', '.001', '.mddramimage']:
                return self._open_raw_image()
            else:
                self.logger.warning(f"Unknown image extension: {ext}, attempting raw")
                return self._open_raw_image()
                
        except Exception as e:
            self.logger.error(f"Failed to open image {self.image_path}: {e}")
            return False
    
    def _open_ewf_image(self) -> bool:
        """
        Open E01 (Expert Witness) image using pyewf.
        Supports segmented images (E01, E02, E03...).
        
        Returns:
            True if successful
        """
        # Import pyewf - try multiple times to handle import issues
        self.logger.info(f"Attempting to import pyewf for E01 support...")
        
        # First try: use global import
        if EWF_AVAILABLE:
            self.logger.info("Using global pyewf import")
            pyewf_module = pyewf
        else:
            # Second try: local import
            try:
                import pyewf as pyewf_module
                self.logger.info("Successfully imported pyewf locally")
            except ImportError as e:
                self.logger.error(f"Cannot import pyewf: {e}")
                self.logger.error(f"EWF_AVAILABLE={EWF_AVAILABLE}")
                import sys
                self.logger.error(f"Python path: {sys.path}")
                raise RuntimeError("pyewf is required for E01 image support")
        
        self.logger.info(f"Opening E01 image: {self.image_path}")
        
        # Glob all segments (E01, E02, E03...)
        # Try pyewf.glob() first, but handle Windows path issues
        filenames = None
        try:
            filenames = pyewf_module.glob(str(self.image_path))
        except Exception as glob_error:
            self.logger.warning(f"pyewf.glob() failed: {glob_error}")
            self.logger.info("Falling back to manual segment detection")
            
            # Manual fallback: detect segments by checking for E01, E02, E03...
            filenames = []
            parent_dir = self.image_path.parent
            base_name = self.image_path.stem
            
            # Check for .E01, .E02, .E03... segments
            for i in range(1, 100):  # Check up to 99 segments
                segment_ext = f".E{i:02d}"
                segment_path = parent_dir / f"{base_name}{segment_ext}"
                
                if segment_path.exists():
                    filenames.append(str(segment_path))
                    self.logger.debug(f"Found segment: {segment_path.name}")
                else:
                    break  # Stop when we don't find the next segment
            
            # If no .E01+ format, try the original file
            if not filenames and self.image_path.exists():
                filenames = [str(self.image_path)]
        
        if not filenames:
            self.logger.error(f"No E01 segments found for {self.image_path}")
            return False

        filenames = self._augment_ewf_segments(filenames)
        
        self.logger.info(f"Found {len(filenames)} E01 segment(s)")
        
        # Open EWF handle
        ewf_handle = pyewf_module.handle()
        
        try:
            ewf_handle.open(filenames)
        except Exception as open_error:
            self.logger.error(f"Failed to open E01 segments: {open_error}")
            raise RuntimeError(f"Failed to open E01 image: {open_error}")
        
        # Get image metadata
        self.image_size = ewf_handle.get_media_size()
        self.image_type = 'ewf'

        # Fail fast for incomplete segment sets: touch the tail byte now so we don't
        # discover missing segments much later during filesystem traversal.
        if self.image_size > 0:
            try:
                ewf_handle.seek(self.image_size - 1)
                _ = ewf_handle.read(1)
            except Exception as tail_error:
                self.logger.error(
                    "E01/EWF image appears incomplete. Required segment(s) are missing. "
                    "Ensure all split parts (E01, E02, ...) are present in one folder. Details: %s",
                    tail_error,
                )
                try:
                    ewf_handle.close()
                except Exception:
                    pass
                return False
        
        # Verify hash if requested
        if self.verify_hash:
            stored_hash = ewf_handle.get_hash_value("MD5")
            if stored_hash:
                # Handle both bytes and string return types
                if isinstance(stored_hash, bytes):
                    self.image_hash = stored_hash.decode('utf-8')
                else:
                    self.image_hash = str(stored_hash)
                self.logger.info(f"E01 stored MD5: {self.image_hash}")
            else:
                self.logger.warning("No MD5 hash found in E01 metadata")
        
        # Create pytsk3 wrapper
        self.image_handle = EwfImgInfo(ewf_handle)
        
        self.logger.info(f"E01 image opened: {self.image_size:,} bytes")
        return True

    def _augment_ewf_segments(self, filenames: List[str]) -> List[str]:
        """Augment pyewf-discovered segment list with additional E?? files in common roots."""
        if not filenames:
            return filenames

        first = Path(filenames[0])
        base = first.stem
        seg_re = re.compile(rf"^{re.escape(base)}\.E(\d{{2,3}})$", re.IGNORECASE)

        discovered: Dict[str, Path] = {}
        for raw in filenames:
            p = Path(raw)
            m = seg_re.match(p.name)
            if not m:
                continue
            discovered[m.group(1)] = p

        search_roots: List[Path] = [
            first.parent,
            Path.cwd() / "data" / "LoneWolf_Image_Files",
            Path.cwd() / "data",
            Path.cwd() / "cases",
        ]

        for root in search_roots:
            if not root.exists() or not root.is_dir():
                continue
            try:
                for candidate in root.glob(f"{base}.E*"):
                    if not candidate.is_file():
                        continue
                    m = seg_re.match(candidate.name)
                    if not m:
                        continue
                    discovered[m.group(1)] = candidate
            except Exception:
                continue

        if len(discovered) <= len(filenames):
            return filenames

        ordered = [str(discovered[k]) for k in sorted(discovered.keys(), key=lambda s: int(s))]
        self.logger.info(
            "Augmented EWF segment set from %s to %s part(s)",
            len(filenames),
            len(ordered),
        )
        return ordered
    
    def _open_raw_image(self) -> bool:
        """
        Open raw DD image using pytsk3 directly.
        
        Returns:
            True if successful
        """
        self.logger.info(f"Opening raw image: {self.image_path}")
        
        # Open raw image
        self.image_handle = pytsk3.Img_Info(str(self.image_path))
        self.image_size = self.image_handle.get_size()
        self.image_type = 'raw'
        
        # Calculate hash if requested
        if self.verify_hash:
            self.logger.info("Calculating MD5 hash of raw image...")
            self.image_hash = self._calculate_image_hash()
            self.logger.info(f"Raw image MD5: {self.image_hash}")
        
        self.logger.info(f"Raw image opened: {self.image_size:,} bytes")
        return True
    
    def _calculate_image_hash(self, algorithm: str = 'md5') -> str:
        """
        Calculate cryptographic hash of the image.
        
        Args:
            algorithm: Hash algorithm ('md5' or 'sha256')
            
        Returns:
            Hex digest of hash
        """
        if algorithm == 'md5':
            hasher = hashlib.md5()
        elif algorithm == 'sha256':
            hasher = hashlib.sha256()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        # Read image in chunks to avoid memory issues
        chunk_size = 1024 * 1024  # 1 MB chunks
        offset = 0
        
        while offset < self.image_size:
            size = min(chunk_size, self.image_size - offset)
            data = self.image_handle.read(offset, size)
            hasher.update(data)
            offset += size
        
        return hasher.hexdigest()
    
    def enumerate_partitions(self) -> List[Dict[str, Any]]:
        """
        Enumerate partitions in the disk image.
        
        Returns:
            List of partition information dictionaries
        """
        if not self.image_handle:
            raise RuntimeError("Image not opened")
        
        self.logger.info("Enumerating partitions...")
        
        try:
            self.volume_info = pytsk3.Volume_Info(self.image_handle)
        except Exception as e:
            self.logger.warning(f"No volume info found (raw filesystem?): {e}")
            # Single partition, treat entire image as filesystem
            self.partitions = [{
                'index': 0,
                'description': 'Raw Filesystem',
                'start': 0,
                'length': self.image_size,
                'type': 'raw'
            }]
            return self.partitions
        
        self.partitions = []
        
        for partition in self.volume_info:
            # Skip unallocated and metadata partitions
            if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                # Handle both bytes and string for partition description
                desc = partition.desc
                if isinstance(desc, bytes):
                    desc_str = desc.decode('utf-8', errors='ignore')
                else:
                    desc_str = str(desc)
                
                partition_info = {
                    'index': partition.addr,
                    'description': desc_str,
                    'start': partition.start,
                    'length': partition.len,
                    'type': self._identify_fs_type(partition.desc)
                }
                
                self.partitions.append(partition_info)
                self.logger.info(
                    f"Partition {partition.addr}: {partition_info['description']} "
                    f"at sector {partition.start} (size: {partition.len * 512:,} bytes)"
                )
        
        return self.partitions
    
    def _identify_fs_type(self, description) -> str:
        """
        Identify file system type from partition description.
        
        Args:
            description: Partition description (bytes or string)
            
        Returns:
            File system type string
        """
        # Handle both bytes and string
        if isinstance(description, bytes):
            desc = description.decode('utf-8', errors='ignore').upper()
        else:
            desc = str(description).upper()
        
        if 'NTFS' in desc:
            return 'ntfs'
        elif 'FAT32' in desc or 'FAT 32' in desc:
            return 'fat32'
        elif 'FAT16' in desc or 'FAT 16' in desc:
            return 'fat16'
        elif 'FAT12' in desc or 'FAT 12' in desc:
            return 'fat12'
        elif 'EXT4' in desc:
            return 'ext4'
        elif 'EXT3' in desc:
            return 'ext3'
        elif 'EXT2' in desc:
            return 'ext2'
        else:
            return 'unknown'
    
    def open_filesystem(self, partition_index: int = 0) -> Optional[pytsk3.FS_Info]:
        """
        Open file system for a specific partition.
        
        Args:
            partition_index: Index of partition to open (can be the partition addr
                            or the list index - both are supported)
            
        Returns:
            pytsk3.FS_Info object or None if failed
        """
        if not self.image_handle:
            raise RuntimeError("Image not opened")
        
        # Find partition by index - support both list index and partition addr
        partition = None
        
        # First try: direct list index (for backward compatibility)
        if partition_index < len(self.partitions):
            partition = self.partitions[partition_index]
        else:
            # Second try: look up by partition addr (from enumerate_partitions)
            for p in self.partitions:
                if p.get('index') == partition_index:
                    partition = p
                    break
        
        if partition is None:
            self.logger.error(f"Invalid partition index: {partition_index}")
            return None
        
        try:
            # Calculate byte offset (partitions use 512-byte sectors)
            offset = partition['start'] * 512
            
            self.logger.info(
                f"Opening filesystem on partition {partition_index} "
                f"({partition['type']}) at offset {offset:,}"
            )
            
            fs_info = pytsk3.FS_Info(self.image_handle, offset=offset)
            self.file_systems[partition_index] = fs_info
            
            return fs_info
            
        except Exception as e:
            self.logger.error(f"Failed to open filesystem: {e}")
            return None
    
    def extract_file(self, fs_info: pytsk3.FS_Info, path: str, 
                     output_path: Path, calculate_hash: bool = True) -> Optional[Dict[str, Any]]:
        """
        Extract a file from the image to local filesystem.
        Maintains read-only access and calculates hash for chain of custody.
        
        Args:
            fs_info: File system info object
            path: Path to file in image (e.g., "/Windows/System32/config/SYSTEM")
            output_path: Local path to write extracted file
            calculate_hash: Whether to calculate MD5/SHA256
            
        Returns:
            Dictionary with extraction metadata (size, hashes, timestamps)
        """
        try:
            # Open file in image
            file_obj = fs_info.open(path)
            
            if not file_obj:
                self.logger.error(f"File not found: {path}")
                return None
            
            # Get file metadata
            file_size = file_obj.info.meta.size
            
            # Only log for larger files (reduces log spam)
            if file_size > 1024 * 1024:  # > 1MB
                self.logger.info(f"Extracting {path} ({file_size:,} bytes) to {output_path}")
            
            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Read file data in chunks and calculate hashes
            md5_hasher = hashlib.md5() if calculate_hash else None
            sha256_hasher = hashlib.sha256() if calculate_hash else None
            
            # Use larger chunks for faster I/O (4MB instead of 1MB)
            chunk_size = 4 * 1024 * 1024  # 4 MB chunks
            offset = 0
            
            with open(output_path, 'wb') as out_file:
                while offset < file_size:
                    size = min(chunk_size, file_size - offset)
                    data = file_obj.read_random(offset, size)
                    
                    if not data:
                        break
                    
                    out_file.write(data)
                    
                    if calculate_hash:
                        md5_hasher.update(data)
                        sha256_hasher.update(data)
                    
                    offset += len(data)
            
            # Gather metadata
            metadata = {
                'source_path': path,
                'output_path': str(output_path),
                'size': file_size,
                'extracted_at': datetime.now().isoformat(),
                'md5': md5_hasher.hexdigest() if calculate_hash else None,
                'sha256': sha256_hasher.hexdigest() if calculate_hash else None,
            }
            
            # Get timestamps (MACB times)
            if hasattr(file_obj.info.meta, 'mtime'):
                metadata['mtime'] = file_obj.info.meta.mtime
            if hasattr(file_obj.info.meta, 'atime'):
                metadata['atime'] = file_obj.info.meta.atime
            if hasattr(file_obj.info.meta, 'ctime'):
                metadata['ctime'] = file_obj.info.meta.ctime
            if hasattr(file_obj.info.meta, 'crtime'):
                metadata['crtime'] = file_obj.info.meta.crtime
            
            # Only log hash for larger files
            if file_size > 1024 * 1024 and calculate_hash:
                self.logger.info(
                    f"Extracted successfully: MD5={metadata['md5']}, "
                    f"SHA256={metadata['sha256'][:16]}..."
                )
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Failed to extract {path}: {e}")
            return None
    
    def list_directory(self, fs_info: pytsk3.FS_Info, path: str = "/") -> List[Dict[str, Any]]:
        """
        List contents of a directory in the image.
        
        Args:
            fs_info: File system info object
            path: Directory path to list
            
        Returns:
            List of file/directory information dictionaries
        """
        try:
            directory = fs_info.open_dir(path)
            
            entries = []
            
            for entry in directory:
                # Skip . and .. entries
                if entry.info.name.name in [b'.', b'..']:
                    continue
                
                # Skip entries with no metadata (deleted/damaged files)
                if not entry.info.meta:
                    continue
                
                # Handle both bytes and string for file names
                file_name = entry.info.name.name
                if isinstance(file_name, bytes):
                    name = file_name.decode('utf-8', errors='ignore')
                else:
                    name = str(file_name)
                
                # Get file metadata
                entry_info = {
                    'name': name,
                    'type': 'dir' if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR else 'file',
                    'size': entry.info.meta.size if hasattr(entry.info.meta, 'size') else 0,
                }
                
                # Get timestamps if available
                if hasattr(entry.info.meta, 'mtime'):
                    entry_info['mtime'] = entry.info.meta.mtime
                
                entries.append(entry_info)
            
            return entries
            
        except Exception as e:
            # Path probing across heterogeneous partitions is expected to miss often.
            # Keep truly unexpected failures as warnings and suppress routine misses.
            msg = str(e)
            if "path not found" in msg.lower() or "unable to open directory" in msg.lower():
                self.logger.debug(f"Directory not present on this partition: {path}")
            else:
                self.logger.warning(f"Failed to list directory {path}: {e}")
            return []
    
    def find_file(self, fs_info: pytsk3.FS_Info, filename: str, 
                  start_path: str = "/") -> List[str]:
        """
        Recursively search for files by name.
        Useful for locating artifacts when default paths have changed.
        
        Args:
            fs_info: File system info object
            filename: Filename to search for (case-insensitive)
            start_path: Directory to start search from
            
        Returns:
            List of full paths where file was found
        """
        found_paths = []
        filename_lower = filename.lower()
        
        def search_recursive(current_path: str):
            try:
                entries = self.list_directory(fs_info, current_path)
                
                for entry in entries:
                    full_path = f"{current_path}/{entry['name']}".replace('//', '/')
                    
                    # Check if filename matches
                    if entry['name'].lower() == filename_lower:
                        found_paths.append(full_path)
                    
                    # Recurse into directories
                    if entry['type'] == 'dir':
                        search_recursive(full_path)
                        
            except Exception as e:
                # Skip directories we can't access
                pass
        
        self.logger.info(f"Searching for '{filename}' starting from {start_path}...")
        search_recursive(start_path)
        self.logger.info(f"Found {len(found_paths)} match(es)")
        
        return found_paths
    
    def extract_raw_partition_data(
        self,
        partition_index: int,
        output_path: Path,
        max_size: Optional[int] = None,
    ) -> bool:
        """
        Extract raw binary data from a partition when filesystem can't be mounted.
        Useful for Android/mobile images or corrupted filesystems.
        
        Args:
            partition_index: Index of partition to extract
            output_path: Path to write raw partition data
            max_size: Maximum bytes to extract; None means full partition
            
        Returns:
            True if successful
        """
        if not self.image_handle:
            raise RuntimeError("Image not opened")
        
        # Find partition by index - support both list index and partition addr
        partition = None
        if partition_index < len(self.partitions):
            partition = self.partitions[partition_index]
        else:
            for p in self.partitions:
                if p.get('index') == partition_index:
                    partition = p
                    break
        
        if partition is None:
            self.logger.error(f"Invalid partition index: {partition_index}")
            return False
        
        offset = partition['start'] * 512
        length = partition['length'] * 512
        if max_size and max_size > 0:
            length = min(length, max_size)
        
        self.logger.info(f"Extracting raw data from partition {partition_index}: {length:,} bytes")
        
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            chunk_size = 1024 * 1024  # 1MB chunks
            bytes_written = 0
            
            with open(output_path, 'wb') as f:
                while bytes_written < length:
                    read_size = min(chunk_size, length - bytes_written)
                    data = self.image_handle.read(offset + bytes_written, read_size)
                    
                    if not data:
                        break
                    
                    f.write(data)
                    bytes_written += len(data)
            
            self.logger.info(f"Extracted {bytes_written:,} bytes to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to extract raw partition data: {e}")
            return False
    
    def carve_files_from_partition(self, partition_index: int, output_dir: Path,
                                  file_signatures: Dict[str, bytes] = None,
                                  progress_callback=None,
                                  max_bytes: Optional[int] = None,
                                  max_files: Optional[int] = None) -> int:
        """
        Carve files from raw partition data using file signatures.
        Useful when filesystem can't be mounted (Android/mobile images).
        
        Args:
            partition_index: Index of partition to carve from
            output_dir: Directory to save carved files
            file_signatures: Dict of {extension: signature_bytes}
            progress_callback: Optional callback(current_bytes, total_bytes)
            
        Returns:
            Number of files carved
        """
        if file_signatures is None:
            # Common file signatures for mobile forensics (reduced set)
            file_signatures = {
                'jpg': b'\xFF\xD8\xFF',
                'png': b'\x89PNG\r\n\x1a\n',
                'sqlite': b'SQLite format 3\x00',
            }
        
        if not self.image_handle or partition_index >= len(self.partitions):
            return 0
        
        partition = self.partitions[partition_index]
        offset = partition['start'] * 512
        length = partition['length'] * 512

        env_max_bytes_raw = os.getenv("FEPD_CARVE_MAX_BYTES", "").strip()
        env_max_bytes: Optional[int] = None
        if env_max_bytes_raw:
            try:
                parsed = int(env_max_bytes_raw)
                env_max_bytes = parsed if parsed > 0 else None
            except ValueError:
                env_max_bytes = None

        effective_max_bytes = max_bytes if max_bytes is not None else env_max_bytes
        if effective_max_bytes and effective_max_bytes > 0 and length > effective_max_bytes:
            self.logger.warning(
                "Partition too large (%s bytes), limiting carve scan to %s bytes",
                f"{length:,}",
                f"{effective_max_bytes:,}",
            )
            length = effective_max_bytes
        
        self.logger.info(f"Carving files from partition {partition_index}: {length:,} bytes")
        
        output_dir.mkdir(parents=True, exist_ok=True)
        carved_count = 0
        
        try:
            # Read partition data in larger chunks for speed
            chunk_size = 5 * 1024 * 1024  # 5MB chunks (faster)
            buffer = b''
            bytes_read = 0
            env_max_files_raw = os.getenv("FEPD_CARVE_MAX_FILES", "").strip()
            env_max_files: Optional[int] = None
            if env_max_files_raw:
                try:
                    parsed = int(env_max_files_raw)
                    env_max_files = parsed if parsed > 0 else None
                except ValueError:
                    env_max_files = None

            max_files_limit = max_files if max_files is not None else env_max_files
            
            while bytes_read < length and (max_files_limit is None or carved_count < max_files_limit):
                read_size = min(chunk_size, length - bytes_read)
                
                # Report progress
                if progress_callback:
                    progress_callback(bytes_read, length)
                
                try:
                    data = self.image_handle.read(offset + bytes_read, read_size)
                except Exception as e:
                    self.logger.error(f"Read error at offset {offset + bytes_read}: {e}")
                    break
                
                if not data:
                    break
                
                buffer += data
                bytes_read += len(data)
                
                # Search for file signatures in buffer (only process new data)
                search_start = max(0, len(buffer) - len(data) - 1024)  # Overlap for signatures at chunk boundary
                
                for ext, signature in file_signatures.items():
                    pos = search_start
                    while max_files_limit is None or carved_count < max_files_limit:
                        pos = buffer.find(signature, pos)
                        if pos == -1:
                            break
                        
                        # Found a file signature - extract small chunk (max 5MB per file)
                        file_start = pos
                        file_end = min(pos + 5 * 1024 * 1024, len(buffer))
                        
                        # Try to find end of file (simple heuristic)
                        if ext == 'jpg':
                            # Look for JPEG EOI marker
                            eoi = buffer.find(b'\xFF\xD9', file_start, file_end)
                            if eoi != -1:
                                file_end = eoi + 2
                        elif ext == 'png':
                            # Look for PNG IEND chunk
                            iend = buffer.find(b'IEND', file_start, file_end)
                            if iend != -1:
                                file_end = iend + 8
                        
                        file_data = buffer[file_start:file_end]
                        
                        # Only save if reasonable size (1KB to 5MB)
                        if 1024 < len(file_data) < 5 * 1024 * 1024:
                            carved_file = output_dir / f"carved_{carved_count:05d}.{ext}"
                            with open(carved_file, 'wb') as f:
                                f.write(file_data)
                            
                            carved_count += 1
                            self.logger.debug(f"Carved {ext} file: {carved_file.name} ({len(file_data):,} bytes)")
                        
                        pos += len(signature)
                
                # Keep only last 1MB in buffer for files spanning chunks
                if len(buffer) > 1 * 1024 * 1024:
                    buffer = buffer[-1 * 1024 * 1024:]
                
                # Log progress every 20MB
                if bytes_read % (20 * 1024 * 1024) < chunk_size:
                    self.logger.info(f"Carving progress: {bytes_read:,} / {length:,} bytes ({carved_count} files found)")
            
            self.logger.info(f"Carved {carved_count} files from partition {partition_index}")
            return carved_count
            
        except Exception as e:
            self.logger.error(f"File carving failed: {e}", exc_info=True)
            return carved_count
    
    def close(self):
        """Close all open handles and release resources."""
        if self.image_handle:
            try:
                self.image_handle.close()
            except Exception as e:
                self.logger.warning(f"Failed to close image handle: {e}")
            self.image_handle = None
        
        self.file_systems.clear()
        self.logger.info("Image closed")
    
    def extract_file_fast(self, fs_info: 'pytsk3.FS_Info', path: str, 
                          output_path: Path, calculate_hash: bool = False,
                          max_file_size: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Fast file extraction without logging each file (for batch operations).
        Skips hash calculation by default for speed.
        
        Args:
            fs_info: File system info object
            path: Path to file in image
            output_path: Local path to write extracted file
            calculate_hash: Whether to calculate hashes (default False for speed)
            max_file_size: Maximum file size to extract; None means no cap
            
        Returns:
            Dictionary with extraction metadata or None on failure
        """
        try:
            file_obj = fs_info.open(path)
            if not file_obj or not file_obj.info or not file_obj.info.meta:
                return None
            
            file_size = file_obj.info.meta.size
            if file_size <= 0:
                return None
            if max_file_size and max_file_size > 0 and file_size > max_file_size:
                return None
            
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Use larger chunks for faster I/O, but limit for memory safety
            chunk_size = min(4 * 1024 * 1024, file_size)  # 4 MB chunks max
            offset = 0
            bytes_written = 0
            
            md5_hasher = hashlib.md5() if calculate_hash else None
            sha256_hasher = hashlib.sha256() if calculate_hash else None
            
            try:
                with open(output_path, 'wb') as out_file:
                    while offset < file_size:
                        size = min(chunk_size, file_size - offset)
                        try:
                            data = file_obj.read_random(offset, size)
                        except Exception:
                            break  # Stop on read error but keep what we have
                        
                        if not data:
                            break
                        
                        out_file.write(data)
                        bytes_written += len(data)
                        
                        if calculate_hash:
                            md5_hasher.update(data)
                            sha256_hasher.update(data)
                        
                        offset += len(data)
                        
                        # Memory safety: clear data reference
                        data = None
            except (IOError, OSError) as e:
                # Disk write error - remove partial file
                try:
                    output_path.unlink()
                except:
                    pass
                return None
            
            # Only return success if we wrote something
            if bytes_written > 0:
                return {
                    'source_path': path,
                    'output_path': str(output_path),
                    'size': bytes_written,
                    'md5': md5_hasher.hexdigest() if calculate_hash else None,
                    'sha256': sha256_hasher.hexdigest() if calculate_hash else None,
                }
            return None
            
        except Exception:
            return None
    
    def extract_files_batch(self, fs_info: 'pytsk3.FS_Info', file_list: List[tuple], 
                           progress_callback=None) -> Dict[str, Any]:
        """
        Extract multiple files in batch for faster processing.
        
        Args:
            fs_info: File system info object
            file_list: List of (source_path, output_path) tuples
            progress_callback: Optional callback(current, total, message)
            
        Returns:
            Dictionary with extraction results
        """
        results = {
            'extracted': 0,
            'failed': 0,
            'skipped': 0,
            'files': []
        }
        
        total = len(file_list)
        if total == 0:
            return results
        
        for i, (source_path, output_path) in enumerate(file_list):
            # Update progress every 10 files for less overhead
            if progress_callback and i % 10 == 0:
                try:
                    progress_callback(i, total, f"Extracting {i}/{total}...")
                except:
                    pass  # Don't crash if callback fails
            
            try:
                metadata = self.extract_file_fast(fs_info, source_path, Path(output_path), calculate_hash=False)
                
                if metadata:
                    results['extracted'] += 1
                    results['files'].append(metadata)
                else:
                    results['skipped'] += 1
            except Exception:
                results['failed'] += 1
                continue
        
        if progress_callback:
            try:
                progress_callback(total, total, f"Done: {results['extracted']} files")
            except:
                pass
        
        return results
    
    def __enter__(self):
        """Context manager entry."""
        self.open_image()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
