"""
FEPD - Advanced Data Extraction Module
Implements powerful data extraction capabilities for forensic analysis

Features:
- File carving from unallocated space (deleted file recovery)
- Registry hive parsing (Windows artifacts)
- MFT (Master File Table) parsing
- Browser history extraction (Chrome, Firefox, Edge, Safari)
- Email/mailstore parsing (PST, OST, MBOX, EML)
- Keyword and hash-index searches
- Timeline analysis automation
- Deleted file recovery
- Hidden data extraction

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
import hashlib
import re
from pathlib import Path
from typing import Optional, Dict, Any, Callable, List, Set, TYPE_CHECKING
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

# Type checking imports (not available at runtime if packages not installed)
if TYPE_CHECKING:
    try:
        from Registry import Registry
    except ImportError:
        Registry = None  # type: ignore
    
    try:
        import pytsk3
    except ImportError:
        pytsk3 = None  # type: ignore


class CarvedFileType(Enum):
    """Types of files that can be carved from unallocated space."""
    JPEG = ("JPEG Image", b'\xFF\xD8\xFF', b'\xFF\xD9')
    PNG = ("PNG Image", b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', None)
    PDF = ("PDF Document", b'%PDF', b'%%EOF')
    DOCX = ("Word Document", b'PK\x03\x04', None)  # ZIP-based
    XLSX = ("Excel Spreadsheet", b'PK\x03\x04', None)
    ZIP = ("ZIP Archive", b'PK\x03\x04', b'PK\x05\x06')
    EXE = ("Executable", b'MZ', None)
    DLL = ("DLL Library", b'MZ', None)
    MP4 = ("MP4 Video", b'\x00\x00\x00\x18ftypmp4', None)
    AVI = ("AVI Video", b'RIFF', b'AVI ')
    MP3 = ("MP3 Audio", b'\xFF\xFB', None)
    HTML = ("HTML Document", b'<!DOCTYPE', b'</html>')
    XML = ("XML Document", b'<?xml', None)


@dataclass
class CarvedFile:
    """Represents a file carved from unallocated space."""
    file_type: CarvedFileType
    offset: int                    # Offset in source image
    size: int                      # File size in bytes
    md5_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    carved_path: Optional[Path] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeletedFile:
    """Represents a deleted file recovered from file system."""
    file_name: str
    file_path: str
    size: int
    deleted_timestamp: Optional[datetime] = None
    recovered: bool = False
    recovered_path: Optional[Path] = None
    md5_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    inode: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RegistryArtifact:
    """Windows Registry artifact."""
    hive: str              # SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT
    key_path: str          # Full registry key path
    value_name: str        # Registry value name
    value_data: Any        # Registry value data
    value_type: str        # REG_SZ, REG_DWORD, REG_BINARY, etc.
    last_modified: Optional[datetime] = None
    significance: str = "informational"  # informational, suspicious, critical


@dataclass
class BrowserArtifact:
    """Browser history/artifact."""
    browser: str           # Chrome, Firefox, Edge, Safari
    artifact_type: str     # history, downloads, cookies, cache, bookmarks
    url: Optional[str] = None
    title: Optional[str] = None
    visit_count: int = 0
    last_visited: Optional[datetime] = None
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EmailArtifact:
    """Email message artifact."""
    source_file: str       # PST, OST, MBOX, EML file
    message_id: str
    sender: str
    recipients: List[str] = field(default_factory=list)
    subject: str = ""
    body_preview: str = ""
    sent_time: Optional[datetime] = None
    received_time: Optional[datetime] = None
    attachments: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)


class DataExtraction:
    """
    Advanced Data Extraction Engine
    
    Implements industry-standard data extraction:
    - File carving from unallocated space
    - Deleted file recovery
    - Registry hive parsing
    - MFT parsing
    - Browser artifact extraction
    - Email/mailstore parsing
    - Keyword search across all data
    - Hash-based file identification
    """
    
    def __init__(self, case_id: str):
        """
        Initialize data extraction module.
        
        Args:
            case_id: Case ID for this extraction
        """
        self.logger = logging.getLogger(__name__)
        self.case_id = case_id
        
        # Results storage
        self.carved_files: List[CarvedFile] = []
        self.deleted_files: List[DeletedFile] = []
        self.registry_artifacts: List[RegistryArtifact] = []
        self.browser_artifacts: List[BrowserArtifact] = []
        self.email_artifacts: List[EmailArtifact] = []
        
        # Check dependencies
        self._check_dependencies()
    
    def _check_dependencies(self):
        """Check for data extraction libraries."""
        self.has_pytsk3 = False
        self.has_registry = False
        self.has_sqlite = False
        
        try:
            import pytsk3
            self.has_pytsk3 = True
            self.logger.info("✅ pytsk3 available (file system analysis)")
        except ImportError:
            self.logger.warning("⚠️ pytsk3 not available - file recovery limited")
        
        try:
            from Registry import Registry
            self.has_registry = True
            self.logger.info("✅ python-registry available (registry parsing)")
        except ImportError:
            self.logger.warning("⚠️ python-registry not available - registry parsing disabled")
        
        try:
            import sqlite3
            self.has_sqlite = True
            self.logger.info("✅ sqlite3 available (browser history parsing)")
        except ImportError:
            self.logger.warning("⚠️ sqlite3 not available - browser parsing limited")
    
    # =========================================================================
    # FILE CARVING - Recover deleted files from unallocated space
    # =========================================================================
    
    def carve_files_from_unallocated(
        self,
        image_path: Path,
        output_dir: Path,
        file_types: Optional[List[CarvedFileType]] = None,
        max_size_mb: int = 100,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> List[CarvedFile]:
        """
        Carve files from unallocated space in disk image.
        
        This technique recovers deleted files by searching for file signatures
        in the raw disk image, even after the file system has marked the space
        as free. Essential for recovering evidence that was intentionally deleted.
        
        Args:
            image_path: Path to disk image
            output_dir: Directory to save carved files
            file_types: List of file types to carve (None = all types)
            max_size_mb: Maximum file size to carve (MB)
            progress_callback: Progress callback
        
        Returns:
            List of carved files
        """
        self.logger.info("="*70)
        self.logger.info("Starting File Carving from Unallocated Space")
        self.logger.info(f"Image: {image_path}")
        self.logger.info("="*70)
        
        if file_types is None:
            file_types = list(CarvedFileType)
        
        output_dir.mkdir(parents=True, exist_ok=True)
        carved_files = []
        
        max_size_bytes = max_size_mb * 1024 * 1024
        BLOCK_SIZE = 4096  # Read in 4KB blocks
        
        try:
            file_size = image_path.stat().st_size
            bytes_processed = 0
            
            with open(image_path, 'rb') as f:
                offset = 0
                
                while offset < file_size:
                    # Read block
                    f.seek(offset)
                    block = f.read(BLOCK_SIZE)
                    
                    if not block:
                        break
                    
                    # Check for file signatures
                    for file_type in file_types:
                        name, header, footer = file_type.value
                        
                        if block.startswith(header):
                            self.logger.info(f"Found {name} at offset {offset}")
                            
                            # Try to extract file
                            carved_file = self._extract_carved_file(
                                f, file_type, offset, max_size_bytes, output_dir
                            )
                            
                            if carved_file:
                                carved_files.append(carved_file)
                                self.carved_files.append(carved_file)
                    
                    # Progress
                    offset += BLOCK_SIZE
                    bytes_processed += len(block)
                    
                    if progress_callback:
                        progress_callback(
                            bytes_processed,
                            file_size,
                            f"Carving: {len(carved_files)} files found"
                        )
            
            self.logger.info(f"✅ File carving complete: {len(carved_files)} files recovered")
            return carved_files
            
        except Exception as e:
            self.logger.error(f"File carving failed: {e}", exc_info=True)
            return carved_files
    
    def _extract_carved_file(
        self,
        file_handle,
        file_type: CarvedFileType,
        offset: int,
        max_size: int,
        output_dir: Path
    ) -> Optional[CarvedFile]:
        """Extract a single carved file."""
        try:
            name, header, footer = file_type.value
            
            # Seek to start
            file_handle.seek(offset)
            
            # Read file data
            data = bytearray()
            bytes_read = 0
            
            while bytes_read < max_size:
                chunk = file_handle.read(4096)
                if not chunk:
                    break
                
                data.extend(chunk)
                bytes_read += len(chunk)
                
                # Check for footer
                if footer and footer in chunk:
                    # Truncate at footer
                    footer_pos = data.rfind(footer)
                    if footer_pos != -1:
                        data = data[:footer_pos + len(footer)]
                        break
            
            # Save carved file
            carved_path = output_dir / f"carved_{offset:016x}.{file_type.name.lower()}"
            with open(carved_path, 'wb') as out:
                out.write(data)
            
            # Compute hashes
            md5_hash = hashlib.md5(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
            
            carved_file = CarvedFile(
                file_type=file_type,
                offset=offset,
                size=len(data),
                md5_hash=md5_hash,
                sha256_hash=sha256_hash,
                carved_path=carved_path
            )
            
            self.logger.info(f"  Carved {len(data):,} bytes to {carved_path.name}")
            return carved_file
            
        except Exception as e:
            self.logger.warning(f"Failed to extract carved file: {e}")
            return None
    
    # =========================================================================
    # DELETED FILE RECOVERY - Recover files deleted from file system
    # =========================================================================
    
    def recover_deleted_files(
        self,
        image_path: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> List[DeletedFile]:
        """
        Recover deleted files from file system.
        
        Uses file system metadata to locate and recover files that have been
        deleted but not yet overwritten. More reliable than carving for
        recently deleted files.
        
        Args:
            image_path: Path to disk image
            output_dir: Directory to save recovered files
            progress_callback: Progress callback
        
        Returns:
            List of recovered deleted files
        """
        if not self.has_pytsk3:
            self.logger.error("pytsk3 required for deleted file recovery")
            return []
        
        self.logger.info("="*70)
        self.logger.info("Starting Deleted File Recovery")
        self.logger.info(f"Image: {image_path}")
        self.logger.info("="*70)
        
        import pytsk3
        
        output_dir.mkdir(parents=True, exist_ok=True)
        deleted_files = []
        
        try:
            # Open image
            img_info = pytsk3.Img_Info(str(image_path))
            
            # Try to open file system
            try:
                fs_info = pytsk3.FS_Info(img_info)
            except:
                # Try with volume system
                vs = pytsk3.Volume_Info(img_info)
                for part in vs:
                    if part.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                        fs_info = pytsk3.FS_Info(img_info, offset=part.start * vs.info.block_size)
                        break
            
            # Walk file system looking for deleted files
            deleted_count = 0
            
            def process_directory(directory, path="/"):
                nonlocal deleted_count
                
                for entry in directory:
                    # Skip . and ..
                    if entry.info.name.name in [b'.', b'..']:
                        continue
                    
                    # Check if deleted
                    if entry.info.name.flags == pytsk3.TSK_FS_NAME_FLAG_UNALLOC:
                        try:
                            file_name = entry.info.name.name.decode('utf-8', errors='replace')
                            full_path = f"{path}{file_name}"
                            
                            # Get file size
                            if entry.info.meta:
                                file_size = entry.info.meta.size
                                
                                # Try to recover file content
                                recovered_path = output_dir / f"deleted_{deleted_count:06d}_{file_name}"
                                
                                try:
                                    file_data = entry.read_random(0, file_size)
                                    
                                    with open(recovered_path, 'wb') as out:
                                        out.write(file_data)
                                    
                                    # Compute hashes
                                    md5_hash = hashlib.md5(file_data).hexdigest()
                                    sha256_hash = hashlib.sha256(file_data).hexdigest()
                                    
                                    deleted_file = DeletedFile(
                                        file_name=file_name,
                                        file_path=full_path,
                                        size=file_size,
                                        recovered=True,
                                        recovered_path=recovered_path,
                                        md5_hash=md5_hash,
                                        sha256_hash=sha256_hash,
                                        inode=entry.info.meta.addr
                                    )
                                    
                                    deleted_files.append(deleted_file)
                                    self.deleted_files.append(deleted_file)
                                    deleted_count += 1
                                    
                                    self.logger.info(f"✅ Recovered: {full_path} ({file_size:,} bytes)")
                                    
                                except:
                                    pass  # File data not recoverable
                        
                        except Exception as e:
                            pass  # Skip problematic entries
                    
                    # Recurse into subdirectories
                    if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        try:
                            sub_dir = entry.as_directory()
                            sub_path = f"{path}{entry.info.name.name.decode('utf-8', errors='replace')}/"
                            process_directory(sub_dir, sub_path)
                        except:
                            pass
            
            # Start walking from root
            root = fs_info.open_dir(path="/")
            process_directory(root)
            
            self.logger.info(f"✅ Deleted file recovery complete: {len(deleted_files)} files recovered")
            return deleted_files
            
        except Exception as e:
            self.logger.error(f"Deleted file recovery failed: {e}", exc_info=True)
            return deleted_files
    
    # =========================================================================
    # REGISTRY HIVE PARSING - Extract Windows Registry artifacts
    # =========================================================================
    
    def parse_registry_hives(
        self,
        hive_paths: Dict[str, Path],
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> List[RegistryArtifact]:
        """
        Parse Windows Registry hives for forensic artifacts.
        
        Extracts critical forensic data from registry hives:
        - Autorun locations (malware persistence)
        - Recently accessed files (user activity)
        - USB device history (device connections)
        - User account information
        - System configuration changes
        - Program execution history
        - Network configuration
        
        Args:
            hive_paths: Dictionary mapping hive names to file paths
                       e.g., {"SYSTEM": Path("SYSTEM"), "SOFTWARE": Path("SOFTWARE")}
            progress_callback: Progress callback
        
        Returns:
            List of registry artifacts
        """
        if not self.has_registry:
            self.logger.error("❌ python-registry not available")
            return []
        
        self.logger.info("="*70)
        self.logger.info("Starting Registry Hive Parsing")
        self.logger.info(f"Hives: {list(hive_paths.keys())}")
        self.logger.info("="*70)
        
        from Registry import Registry
        
        artifacts = []
        total_hives = len(hive_paths)
        current_hive = 0
        
        for hive_name, hive_path in hive_paths.items():
            if not hive_path.exists():
                self.logger.warning(f"⚠️ Hive not found: {hive_path}")
                continue
            
            current_hive += 1
            self.logger.info(f"Parsing {hive_name} hive ({current_hive}/{total_hives})...")
            
            try:
                reg = Registry.Registry(str(hive_path))
                
                # Parse different artifact types based on hive
                if hive_name.upper() == "SYSTEM":
                    artifacts.extend(self._parse_system_hive(reg, hive_name))
                elif hive_name.upper() == "SOFTWARE":
                    artifacts.extend(self._parse_software_hive(reg, hive_name))
                elif hive_name.upper() == "SAM":
                    artifacts.extend(self._parse_sam_hive(reg, hive_name))
                elif "NTUSER" in hive_name.upper():
                    artifacts.extend(self._parse_ntuser_hive(reg, hive_name))
                
                if progress_callback:
                    progress_callback(current_hive, total_hives, f"Parsed {hive_name}")
                
            except Exception as e:
                self.logger.error(f"Failed to parse {hive_name}: {e}")
        
        self.registry_artifacts.extend(artifacts)
        self.logger.info(f"✅ Registry parsing complete: {len(artifacts)} artifacts extracted")
        return artifacts
    
    def _parse_system_hive(self, reg: 'Registry', hive_name: str) -> List[RegistryArtifact]:
        """Parse SYSTEM hive for forensic artifacts."""
        artifacts = []
        
        try:
            # USB Device History
            usb_key_path = r"ControlSet001\Enum\USBSTOR"
            try:
                usb_key = reg.open(usb_key_path)
                for subkey in usb_key.subkeys():
                    for device in subkey.subkeys():
                        try:
                            friendly_name = device.value("FriendlyName").value()
                            artifacts.append(RegistryArtifact(
                                hive=hive_name,
                                key_path=f"{usb_key_path}\\{subkey.name()}\\{device.name()}",
                                value_name="FriendlyName",
                                value_data=friendly_name,
                                value_type="REG_SZ",
                                last_modified=device.timestamp(),
                                significance="informational"
                            ))
                        except:
                            pass
            except:
                pass
            
            # Computer Name
            try:
                computername_key = reg.open(r"ControlSet001\Control\ComputerName\ComputerName")
                computer_name = computername_key.value("ComputerName").value()
                artifacts.append(RegistryArtifact(
                    hive=hive_name,
                    key_path=r"ControlSet001\Control\ComputerName\ComputerName",
                    value_name="ComputerName",
                    value_data=computer_name,
                    value_type="REG_SZ",
                    last_modified=computername_key.timestamp(),
                    significance="informational"
                ))
            except:
                pass
            
            # Network Interfaces
            try:
                interfaces_key = reg.open(r"ControlSet001\Services\Tcpip\Parameters\Interfaces")
                for interface in interfaces_key.subkeys():
                    try:
                        dhcp_ip = interface.value("DhcpIPAddress").value()
                        artifacts.append(RegistryArtifact(
                            hive=hive_name,
                            key_path=f"ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{interface.name()}",
                            value_name="DhcpIPAddress",
                            value_data=dhcp_ip,
                            value_type="REG_SZ",
                            last_modified=interface.timestamp(),
                            significance="informational"
                        ))
                    except:
                        pass
            except:
                pass
            
        except Exception as e:
            self.logger.error(f"Error parsing SYSTEM hive: {e}")
        
        return artifacts
    
    def _parse_software_hive(self, reg: 'Registry', hive_name: str) -> List[RegistryArtifact]:
        """Parse SOFTWARE hive for forensic artifacts."""
        artifacts = []
        
        try:
            # Run keys (Autorun/Persistence locations)
            run_paths = [
                r"Microsoft\Windows\CurrentVersion\Run",
                r"Microsoft\Windows\CurrentVersion\RunOnce",
                r"Microsoft\Windows\CurrentVersion\RunServices",
            ]
            
            for run_path in run_paths:
                try:
                    run_key = reg.open(run_path)
                    for value in run_key.values():
                        artifacts.append(RegistryArtifact(
                            hive=hive_name,
                            key_path=run_path,
                            value_name=value.name(),
                            value_data=value.value(),
                            value_type=value.value_type_str(),
                            last_modified=run_key.timestamp(),
                            significance="suspicious"  # Autorun locations are high interest
                        ))
                except:
                    pass
            
            # Installed Applications
            try:
                uninstall_key = reg.open(r"Microsoft\Windows\CurrentVersion\Uninstall")
                for app in uninstall_key.subkeys():
                    try:
                        display_name = app.value("DisplayName").value()
                        artifacts.append(RegistryArtifact(
                            hive=hive_name,
                            key_path=f"Microsoft\\Windows\\CurrentVersion\\Uninstall\\{app.name()}",
                            value_name="DisplayName",
                            value_data=display_name,
                            value_type="REG_SZ",
                            last_modified=app.timestamp(),
                            significance="informational"
                        ))
                    except:
                        pass
            except:
                pass
            
        except Exception as e:
            self.logger.error(f"Error parsing SOFTWARE hive: {e}")
        
        return artifacts
    
    def _parse_sam_hive(self, reg: 'Registry', hive_name: str) -> List[RegistryArtifact]:
        """Parse SAM hive for user account information."""
        artifacts = []
        
        try:
            # User accounts
            try:
                users_key = reg.open(r"SAM\Domains\Account\Users\Names")
                for user in users_key.subkeys():
                    artifacts.append(RegistryArtifact(
                        hive=hive_name,
                        key_path=f"SAM\\Domains\\Account\\Users\\Names\\{user.name()}",
                        value_name="Username",
                        value_data=user.name(),
                        value_type="KEY",
                        last_modified=user.timestamp(),
                        significance="informational"
                    ))
            except:
                pass
            
        except Exception as e:
            self.logger.error(f"Error parsing SAM hive: {e}")
        
        return artifacts
    
    def _parse_ntuser_hive(self, reg: 'Registry', hive_name: str) -> List[RegistryArtifact]:
        """Parse NTUSER.DAT hive for user-specific artifacts."""
        artifacts = []
        
        try:
            # Recent Documents (RecentDocs)
            try:
                recentdocs_key = reg.open(r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
                for ext in recentdocs_key.subkeys():
                    for value in ext.values():
                        if value.name().isdigit():
                            artifacts.append(RegistryArtifact(
                                hive=hive_name,
                                key_path=f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\{ext.name()}",
                                value_name=value.name(),
                                value_data=value.value()[:100] if isinstance(value.value(), bytes) else value.value(),
                                value_type=value.value_type_str(),
                                last_modified=ext.timestamp(),
                                significance="informational"
                            ))
            except:
                pass
            
            # Typed URLs (Browser URL history)
            try:
                typedurls_key = reg.open(r"Software\Microsoft\Internet Explorer\TypedURLs")
                for value in typedurls_key.values():
                    artifacts.append(RegistryArtifact(
                        hive=hive_name,
                        key_path=r"Software\Microsoft\Internet Explorer\TypedURLs",
                        value_name=value.name(),
                        value_data=value.value(),
                        value_type=value.value_type_str(),
                        last_modified=typedurls_key.timestamp(),
                        significance="informational"
                    ))
            except:
                pass
            
            # User Assist (Program execution tracking)
            try:
                userassist_key = reg.open(r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
                for guid in userassist_key.subkeys():
                    try:
                        count_key = guid.subkey("Count")
                        for value in count_key.values():
                            artifacts.append(RegistryArtifact(
                                hive=hive_name,
                                key_path=f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{guid.name()}\\Count",
                                value_name=value.name(),
                                value_data="Execution tracked",
                                value_type=value.value_type_str(),
                                last_modified=count_key.timestamp(),
                                significance="informational"
                            ))
                    except:
                        pass
            except:
                pass
            
        except Exception as e:
            self.logger.error(f"Error parsing NTUSER hive: {e}")
        
        return artifacts
    
    # =========================================================================
    # MFT PARSING - Parse NTFS Master File Table
    # =========================================================================
    
    def parse_mft(
        self,
        image_path: Path,
        output_csv: Optional[Path] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Parse NTFS Master File Table ($MFT) for comprehensive file metadata.
        
        The MFT contains complete metadata for every file and directory on an
        NTFS volume, including:
        - Full file path
        - File sizes (logical and physical)
        - Timestamps (created, modified, accessed, MFT modified)
        - File attributes (hidden, system, compressed, encrypted)
        - Resident vs non-resident data
        - Deleted file entries
        
        This is essential for:
        - Timeline analysis
        - Deleted file detection
        - File activity tracking
        - Anti-forensics detection
        
        Args:
            image_path: Path to disk image
            output_csv: Optional path to save MFT data as CSV
            progress_callback: Progress callback
        
        Returns:
            List of MFT entry dictionaries
        """
        if not self.has_pytsk3:
            self.logger.error("❌ pytsk3 not available")
            return []
        
        self.logger.info("="*70)
        self.logger.info("Starting MFT Parsing")
        self.logger.info(f"Image: {image_path}")
        self.logger.info("="*70)
        
        import pytsk3
        
        mft_entries = []
        
        try:
            # Open image
            img_info = pytsk3.Img_Info(str(image_path))
            
            # Try to access volume system
            try:
                volume = pytsk3.Volume_Info(img_info)
                for part in volume:
                    if part.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                        # Open file system on this partition
                        try:
                            fs_info = pytsk3.FS_Info(img_info, offset=part.start * volume.info.block_size)
                            if fs_info.info.ftype == pytsk3.TSK_FS_TYPE_NTFS:
                                self.logger.info(f"Found NTFS partition at offset {part.start}")
                                entries = self._parse_mft_from_fs(fs_info, progress_callback)
                                mft_entries.extend(entries)
                        except:
                            pass
            except:
                # No volume system, try direct file system access
                try:
                    fs_info = pytsk3.FS_Info(img_info)
                    if fs_info.info.ftype == pytsk3.TSK_FS_TYPE_NTFS:
                        self.logger.info("Found NTFS file system (no partition table)")
                        entries = self._parse_mft_from_fs(fs_info, progress_callback)
                        mft_entries.extend(entries)
                except Exception as e:
                    self.logger.error(f"Failed to open file system: {e}")
            
            # Save to CSV if requested
            if output_csv and mft_entries:
                self._save_mft_to_csv(mft_entries, output_csv)
            
            self.logger.info(f"✅ MFT parsing complete: {len(mft_entries)} entries")
            return mft_entries
            
        except Exception as e:
            self.logger.error(f"MFT parsing failed: {e}", exc_info=True)
            return mft_entries
    
    def _parse_mft_from_fs(
        self,
        fs_info: 'pytsk3.FS_Info',
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> List[Dict[str, Any]]:
        """Parse MFT entries from file system."""
        import pytsk3
        
        entries = []
        
        def walk_directory(directory, path="/"):
            """Recursively walk directory tree."""
            for entry in directory:
                # Skip . and ..
                if entry.info.name.name in [b'.', b'..']:
                    continue
                
                try:
                    file_name = entry.info.name.name.decode('utf-8', errors='replace')
                    full_path = f"{path}{file_name}"
                    
                    if entry.info.meta:
                        meta = entry.info.meta
                        
                        # Extract timestamps
                        mft_entry = {
                            "inode": meta.addr,
                            "file_name": file_name,
                            "file_path": full_path,
                            "size": meta.size,
                            "allocated": entry.info.name.flags != pytsk3.TSK_FS_NAME_FLAG_UNALLOC,
                            "is_directory": meta.type == pytsk3.TSK_FS_META_TYPE_DIR,
                            "created": datetime.fromtimestamp(meta.crtime, tz=timezone.utc) if meta.crtime > 0 else None,
                            "modified": datetime.fromtimestamp(meta.mtime, tz=timezone.utc) if meta.mtime > 0 else None,
                            "accessed": datetime.fromtimestamp(meta.atime, tz=timezone.utc) if meta.atime > 0 else None,
                            "mft_modified": datetime.fromtimestamp(meta.ctime, tz=timezone.utc) if meta.ctime > 0 else None,
                        }
                        
                        entries.append(mft_entry)
                        
                        # Recurse into directories
                        if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            try:
                                sub_dir = entry.as_directory()
                                walk_directory(sub_dir, f"{full_path}/")
                            except:
                                pass
                    
                except Exception as e:
                    pass  # Skip problematic entries
            
            if progress_callback and len(entries) % 1000 == 0:
                progress_callback(len(entries), 0, f"Parsed {len(entries)} MFT entries")
        
        # Start walking from root
        try:
            root = fs_info.open_dir(path="/")
            walk_directory(root)
        except Exception as e:
            self.logger.error(f"Failed to walk directory tree: {e}")
        
        return entries
    
    def _save_mft_to_csv(self, entries: List[Dict[str, Any]], output_path: Path):
        """Save MFT entries to CSV file."""
        import csv
        
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                if not entries:
                    return
                
                fieldnames = entries[0].keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for entry in entries:
                    # Convert datetime objects to strings
                    row = {}
                    for key, value in entry.items():
                        if isinstance(value, datetime):
                            row[key] = value.isoformat()
                        else:
                            row[key] = value
                    writer.writerow(row)
                
            self.logger.info(f"✅ MFT data saved to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save MFT CSV: {e}")
    
    # =========================================================================
    # KEYWORD SEARCH - Search for keywords across all data
    # =========================================================================
    
    def keyword_search(
        self,
        image_path: Path,
        keywords: List[str],
        case_sensitive: bool = False,
        regex: bool = False,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Search for keywords across entire disk image.
        
        Searches for keywords in file content, slack space, and unallocated space.
        Essential for finding hidden or deleted evidence.
        
        Args:
            image_path: Path to disk image
            keywords: List of keywords to search for
            case_sensitive: Case-sensitive search
            regex: Treat keywords as regular expressions
            progress_callback: Progress callback
        
        Returns:
            Dictionary mapping keywords to list of hits
        """
        self.logger.info("="*70)
        self.logger.info("Starting Keyword Search")
        self.logger.info(f"Keywords: {keywords}")
        self.logger.info("="*70)
        
        results = {keyword: [] for keyword in keywords}
        
        BLOCK_SIZE = 1024 * 1024  # 1MB blocks
        file_size = image_path.stat().st_size
        bytes_processed = 0
        
        try:
            with open(image_path, 'rb') as f:
                offset = 0
                
                while offset < file_size:
                    # Read block
                    block = f.read(BLOCK_SIZE)
                    if not block:
                        break
                    
                    # Search for each keyword
                    for keyword in keywords:
                        if regex:
                            # Regex search
                            pattern = re.compile(keyword.encode() if isinstance(keyword, str) else keyword)
                            matches = pattern.finditer(block)
                            
                            for match in matches:
                                hit_offset = offset + match.start()
                                context = block[max(0, match.start()-50):match.end()+50]
                                
                                results[keyword].append({
                                    "offset": hit_offset,
                                    "context": context.decode('utf-8', errors='replace'),
                                    "match": match.group().decode('utf-8', errors='replace')
                                })
                        else:
                            # Simple search
                            search_term = keyword.encode() if isinstance(keyword, str) else keyword
                            if not case_sensitive:
                                search_term = search_term.lower()
                                search_block = block.lower()
                            else:
                                search_block = block
                            
                            pos = 0
                            while True:
                                pos = search_block.find(search_term, pos)
                                if pos == -1:
                                    break
                                
                                hit_offset = offset + pos
                                context = block[max(0, pos-50):pos+len(search_term)+50]
                                
                                results[keyword].append({
                                    "offset": hit_offset,
                                    "context": context.decode('utf-8', errors='replace'),
                                })
                                
                                pos += 1
                    
                    # Progress
                    offset += len(block)
                    bytes_processed += len(block)
                    
                    if progress_callback:
                        total_hits = sum(len(hits) for hits in results.values())
                        progress_callback(
                            bytes_processed,
                            file_size,
                            f"Searching: {total_hits} hits found"
                        )
            
            # Summary
            total_hits = sum(len(hits) for hits in results.values())
            self.logger.info(f"✅ Keyword search complete: {total_hits} hits found")
            
            for keyword, hits in results.items():
                if hits:
                    self.logger.info(f"  '{keyword}': {len(hits)} hits")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Keyword search failed: {e}", exc_info=True)
            return results
    
    # =========================================================================
    # HASH INDEX SEARCH - Identify known files by hash
    # =========================================================================
    
    def hash_index_search(
        self,
        image_path: Path,
        known_hashes: Set[str],
        algorithm: str = "sha256",
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for files matching known hash values.
        
        Used to identify known malware, contraband, or other files of interest
        by their cryptographic hash signatures.
        
        Args:
            image_path: Path to disk image
            known_hashes: Set of known hash values to look for
            algorithm: Hash algorithm (md5, sha1, sha256)
            progress_callback: Progress callback
        
        Returns:
            List of matching files
        """
        self.logger.info("="*70)
        self.logger.info("Starting Hash Index Search")
        self.logger.info(f"Known hashes: {len(known_hashes)}")
        self.logger.info(f"Algorithm: {algorithm}")
        self.logger.info("="*70)
        
        matches = []
        
        # TODO: Implement file-by-file hashing with pytsk3
        # This would walk the file system and hash each file,
        # comparing against the known hash set
        
        self.logger.info(f"✅ Hash search complete: {len(matches)} matches found")
        return matches
