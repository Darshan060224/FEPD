"""
FEPD - Forensic Evidence Parser Dashboard
Artifact Discovery Module

Automatically discovers Windows forensic artifacts inside mounted disk images.
Scans known artifact locations and identifies evidence files for extraction.

Implements FR-05, FR-06: Auto-scan default Windows artifact paths inside the image

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum


class ArtifactType(Enum):
    """Types of forensic artifacts that can be discovered."""
    EVTX = "EVTX"
    REGISTRY = "Registry"
    PREFETCH = "Prefetch"
    MFT = "MFT"
    BROWSER = "Browser"
    LNK = "LNK"
    DATABASE = "Database"
    LOG = "Log"
    LINUX_CONFIG = "Linux Config"
    LINUX_LOG = "Linux Log"
    SCRIPT = "Script"
    BINARY = "Binary"
    # Mobile artifact types
    MOBILE_SMS = "Mobile SMS"
    MOBILE_CALL = "Mobile Call Log"
    MOBILE_CONTACT = "Mobile Contacts"
    MOBILE_APP = "Mobile App"
    MOBILE_MEDIA = "Mobile Media"
    MOBILE_DATABASE = "Mobile Database"
    MOBILE_LOG = "Mobile Log"
    UNKNOWN = "Unknown"


@dataclass
class DiscoveredArtifact:
    """
    Represents a discovered forensic artifact.
    
    Attributes:
        artifact_type: Type of artifact
        internal_path: Path inside the forensic image
        size_bytes: File size in bytes
        description: Human-readable description
    """
    artifact_type: ArtifactType
    internal_path: str
    size_bytes: int
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'artifact_type': self.artifact_type.value,
            'internal_path': self.internal_path,
            'size_bytes': self.size_bytes,
            'description': self.description
        }


class ArtifactDiscovery:
    """
    Artifact Discovery Engine for forensic disk images.
    
    Scans mounted images for known Windows artifact locations:
    - Event Logs (EVTX)
    - Registry Hives
    - Prefetch Files
    - Browser History Databases
    - NTFS MFT
    - LNK Files (optional)
    """
    
    # Known Windows artifact paths (relative to mounted image root)
    ARTIFACT_PATHS = {
        # Windows Event Logs
        'evtx': [
            'Windows/System32/winevt/Logs',  # Vista+
            'Windows/System32/config',       # Vista+
            'WINDOWS/system32/config',       # Windows XP (.evt files)
        ],
        
        # Registry Hives
        'registry': [
            'Windows/System32/config',  # SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT
            'WINDOWS/system32/config',  # Windows XP (case-insensitive fallback)
        ],
        
        # Prefetch Files
        'prefetch': [
            'Windows/Prefetch',
            'WINDOWS/Prefetch',  # Windows XP
        ],
        
        # Browser Profiles (Modern Windows)
        'browser_chrome': [
            'Users/*/AppData/Local/Google/Chrome/User Data/Default',
            'Users/*/AppData/Local/Google/Chrome/User Data/Profile *',
        ],
        
        'browser_edge': [
            'Users/*/AppData/Local/Microsoft/Edge/User Data/Default',
            'Users/*/AppData/Local/Microsoft/Edge/User Data/Profile *',
        ],
        
        'browser_firefox': [
            'Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*',
        ],
        
        # LNK Files (Recent Documents)
        'lnk': [
            'Users/*/AppData/Roaming/Microsoft/Windows/Recent',
        ],
        
        # User NTUSER.DAT (Modern Windows)
        'user_registry': [
            'Users/*/NTUSER.DAT',
            'Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat',
            # Windows XP paths
            'Documents and Settings/*/NTUSER.DAT',
            'Documents and Settings/*/ntuser.dat',
        ]
    }
    
    # Specific registry hive filenames
    REGISTRY_HIVES = ['SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT', 'NTUSER.DAT', 'UsrClass.dat']
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize Artifact Discovery engine.
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self.discovered_artifacts: List[DiscoveredArtifact] = []
    
    def discover(
        self,
        mount_point: Path,
        artifact_types: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> List[DiscoveredArtifact]:
        """
        Discover forensic artifacts in a mounted disk image.
        
        Args:
            mount_point: Path to mounted image root
            artifact_types: Optional list of artifact types to discover (default: all)
            progress_callback: Optional callback(current, total, message)
            
        Returns:
            List of discovered artifacts
        """
        mount_point = Path(mount_point)
        
        if not mount_point.exists():
            raise FileNotFoundError(f"Mount point does not exist: {mount_point}")
        
        self.logger.info(f"Starting artifact discovery at: {mount_point}")
        self.discovered_artifacts = []
        
        # Store original mount point for relative path calculations
        self.original_mount_point = mount_point
        
        # Log directory structure for debugging
        self.logger.info("📂 Mount point contents:")
        try:
            items = list(mount_point.iterdir())
            if not items:
                self.logger.warning(f"⚠ Mount point is EMPTY: {mount_point}")
            else:
                for item in items[:20]:  # Show first 20 items
                    item_type = "DIR" if item.is_dir() else "FILE"
                    self.logger.info(f"  [{item_type}] {item.name}")
                if len(items) > 20:
                    self.logger.info(f"  ... and {len(items) - 20} more items")
        except Exception as e:
            self.logger.error(f"❌ Cannot list mount point contents: {e}")
        
        # Detect system type (Windows vs Linux/Unix vs macOS)
        is_windows = self._detect_windows_system(mount_point)
        is_linux = self._detect_linux_system(mount_point)
        is_macos = self._detect_macos_system(mount_point)
        is_category_organized = self._detect_category_organized(mount_point)
        
        # Handle category-organized extraction (from fast extraction mode)
        if is_category_organized:
            self.logger.info("✅ Detected category-organized artifact structure")
            self._discover_from_categories(mount_point, artifact_types, progress_callback)
            self.logger.info(f"Discovery complete: {len(self.discovered_artifacts)} artifacts found in categories")
            return self.discovered_artifacts
        
        # Check if NO filesystem was detected
        if not is_windows and not is_linux and not is_macos:
            self.logger.error("❌ CRITICAL: No filesystem detected (not Windows, Linux, or macOS)")
            self.logger.error("This may indicate:")
            self.logger.error("  1. Image is corrupted or incomplete")
            self.logger.error("  2. Filesystem extraction failed")
            self.logger.error("  3. Unsupported filesystem (e.g., exFAT, FAT32, other)")
            self.logger.error("  4. Image is empty or unpartitioned")
            self.logger.error("  5. Wrong mount point or partition offset")
            
            # Try to provide more context
            self.logger.info("🔍 Attempting generic file scan...")
            try:
                all_files = list(mount_point.rglob('*'))
                file_count = sum(1 for f in all_files if f.is_file())
                dir_count = sum(1 for f in all_files if f.is_dir())
                self.logger.info(f"  Found {file_count} files and {dir_count} directories")
                
                if file_count == 0:
                    self.logger.error("  ⚠ Mount point contains NO FILES - likely empty or corrupted image")
                else:
                    # Show some file examples
                    files_sample = [f for f in all_files if f.is_file()][:10]
                    self.logger.info("  Sample files found:")
                    for f in files_sample:
                        self.logger.info(f"    - {f.relative_to(mount_point)}")
            except Exception as e:
                self.logger.error(f"  Generic scan failed: {e}")
            
            self.logger.warning("⚠ Returning empty artifact list")
            return []
        
        if is_macos:
            self.logger.info("✓ Detected macOS system (HFS+/APFS) - using macOS artifact discovery")
            # Discover macOS artifacts
            if progress_callback:
                progress_callback(0, 4, "Discovering macOS FSEvents...")
            self._discover_macos_fseventsd(mount_point)
            
            if progress_callback:
                progress_callback(1, 4, "Discovering shell history...")
            self._discover_macos_shell_history(mount_point)
            
            if progress_callback:
                progress_callback(2, 4, "Discovering system logs...")
            self._discover_macos_logs(mount_point)
            
            if progress_callback:
                progress_callback(3, 4, "Discovering user files...")
            self._discover_macos_user_files(mount_point)
            
            if progress_callback:
                progress_callback(4, 4, "macOS discovery complete")
            
            self.logger.info(f"✓ Discovery complete: {len(self.discovered_artifacts)} macOS artifacts found")
            return self.discovered_artifacts
        
        if is_linux:
            self.logger.info("Detected Linux/Unix system - using Linux artifact discovery")
            # Discover Linux artifacts
            if progress_callback:
                progress_callback(0, 3, "Discovering Linux configuration files...")
            self._discover_linux_configs(mount_point)
            
            if progress_callback:
                progress_callback(1, 3, "Discovering Linux logs...")
            self._discover_linux_logs(mount_point)
            
            if progress_callback:
                progress_callback(2, 3, "Discovering scripts and binaries...")
            self._discover_linux_scripts(mount_point)
            
            if progress_callback:
                progress_callback(3, 3, "Discovery complete")
            
            self.logger.info(f"Discovery complete. Found {len(self.discovered_artifacts)} artifacts")
            return self.discovered_artifacts
        
        # Windows artifact discovery (original code)
        # Determine which artifact types to discover
        if artifact_types is None:
            artifact_types = ['evtx', 'registry', 'prefetch', 'browser', 'mft']
        
        self.logger.info(f"🔍 Starting Windows artifact discovery for types: {artifact_types}")
        
        # Check if we need to search in partition subdirectories
        partition_dirs = list(mount_point.glob('partition_*'))
        if partition_dirs:
            self.logger.info(f"📦 Found {len(partition_dirs)} partition directories, will search in each")
            search_roots = partition_dirs
        else:
            self.logger.info(f"📂 Searching in root mount point: {mount_point}")
            search_roots = [mount_point]
        
        total_steps = len(artifact_types) + 1  # +1 for MFT
        current_step = 0
        
        # Discover each artifact type in each search root
        for search_root in search_roots:
            self.logger.info(f"🔍 Scanning: {search_root.name if search_root != mount_point else 'root'}")
            
            if 'evtx' in artifact_types:
                current_step += 1
                if progress_callback:
                    progress_callback(current_step, total_steps, f"Discovering Event Logs in {search_root.name}...")
                self._discover_evtx(search_root)
            
            if 'registry' in artifact_types:
                current_step += 1
                if progress_callback:
                    progress_callback(current_step, total_steps, f"Discovering Registry Hives in {search_root.name}...")
                self._discover_registry(search_root)
            
            if 'prefetch' in artifact_types:
                current_step += 1
                if progress_callback:
                    progress_callback(current_step, total_steps, f"Discovering Prefetch Files in {search_root.name}...")
                self._discover_prefetch(search_root)
            
            if 'browser' in artifact_types:
                current_step += 1
                if progress_callback:
                    progress_callback(current_step, total_steps, f"Discovering Browser History in {search_root.name}...")
                self._discover_browser(search_root)
            
            if 'mft' in artifact_types:
                current_step += 1
                if progress_callback:
                    progress_callback(current_step, total_steps, f"Discovering MFT in {search_root.name}...")
                self._discover_mft(search_root)
        
        # Final callback
        if progress_callback:
            progress_callback(total_steps, total_steps, "Discovery complete")
        
        self.logger.info(f"Discovery complete. Found {len(self.discovered_artifacts)} artifacts")
        return self.discovered_artifacts
    
    def _discover_evtx(self, mount_point: Path) -> None:
        """Discover Windows Event Log files (.evtx)."""
        for path_pattern in self.ARTIFACT_PATHS['evtx']:
            search_path = mount_point / path_pattern
            
            if not search_path.exists():
                continue
            
            # Find all .evtx files
            try:
                for evtx_file in search_path.glob('*.evtx'):
                    if evtx_file.is_file():
                        # Calculate path relative to original mount point
                        try:
                            internal_path = str(evtx_file.relative_to(self.original_mount_point))
                        except ValueError:
                            # Fallback if not relative
                            internal_path = str(evtx_file.relative_to(mount_point))
                        
                        artifact = DiscoveredArtifact(
                            artifact_type=ArtifactType.EVTX,
                            internal_path=internal_path,
                            size_bytes=evtx_file.stat().st_size,
                            description=f"Event Log: {evtx_file.name}"
                        )
                        self.discovered_artifacts.append(artifact)
                        self.logger.debug(f"Found EVTX: {evtx_file.name}")
            
            except Exception as e:
                self.logger.warning(f"Error scanning {search_path}: {e}")
    
    def _discover_registry(self, mount_point: Path) -> None:
        """Discover Windows Registry hive files."""
        # System hives
        for path_pattern in self.ARTIFACT_PATHS['registry']:
            search_path = mount_point / path_pattern
            
            if not search_path.exists():
                continue
            
            try:
                for hive_name in self.REGISTRY_HIVES:
                    hive_file = search_path / hive_name
                    
                    if hive_file.exists() and hive_file.is_file():
                        # Calculate path relative to original mount point
                        try:
                            internal_path = str(hive_file.relative_to(self.original_mount_point))
                        except ValueError:
                            internal_path = str(hive_file.relative_to(mount_point))
                        
                        artifact = DiscoveredArtifact(
                            artifact_type=ArtifactType.REGISTRY,
                            internal_path=internal_path,
                            size_bytes=hive_file.stat().st_size,
                            description=f"Registry Hive: {hive_name}"
                        )
                        self.discovered_artifacts.append(artifact)
                        self.logger.debug(f"Found Registry Hive: {hive_name}")
            
            except Exception as e:
                self.logger.warning(f"Error scanning {search_path}: {e}")
        
        # User registry hives
        for path_pattern in self.ARTIFACT_PATHS['user_registry']:
            try:
                # Handle wildcard paths
                parts = path_pattern.split('/')
                if '*' in path_pattern:
                    # Build search path up to wildcard
                    base_parts = []
                    for part in parts:
                        if '*' in part:
                            break
                        base_parts.append(part)
                    
                    base_path = mount_point / Path(*base_parts)
                    if not base_path.exists():
                        continue
                    
                    # Search with pattern
                    pattern = '/'.join(parts[len(base_parts):])
                    for user_hive in base_path.glob(pattern):
                        if user_hive.is_file():
                            # Calculate path relative to original mount point
                            try:
                                internal_path = str(user_hive.relative_to(self.original_mount_point))
                            except ValueError:
                                internal_path = str(user_hive.relative_to(mount_point))
                            
                            artifact = DiscoveredArtifact(
                                artifact_type=ArtifactType.REGISTRY,
                                internal_path=internal_path,
                                size_bytes=user_hive.stat().st_size,
                                description=f"User Registry: {user_hive.name}"
                            )
                            self.discovered_artifacts.append(artifact)
                            self.logger.debug(f"Found User Registry: {user_hive.name}")
            
            except Exception as e:
                self.logger.warning(f"Error scanning user registry pattern {path_pattern}: {e}")
    
    def _discover_prefetch(self, mount_point: Path) -> None:
        """Discover Windows Prefetch files (.pf)."""
        for path_pattern in self.ARTIFACT_PATHS['prefetch']:
            search_path = mount_point / path_pattern
            
            if not search_path.exists():
                continue
            
            try:
                for pf_file in search_path.glob('*.pf'):
                    if pf_file.is_file():
                        # Calculate path relative to original mount point
                        try:
                            internal_path = str(pf_file.relative_to(self.original_mount_point))
                        except ValueError:
                            internal_path = str(pf_file.relative_to(mount_point))
                        
                        artifact = DiscoveredArtifact(
                            artifact_type=ArtifactType.PREFETCH,
                            internal_path=internal_path,
                            size_bytes=pf_file.stat().st_size,
                            description=f"Prefetch: {pf_file.name}"
                        )
                        self.discovered_artifacts.append(artifact)
                        self.logger.debug(f"Found Prefetch: {pf_file.name}")
            
            except Exception as e:
                self.logger.warning(f"Error scanning {search_path}: {e}")
    
    def _discover_browser(self, mount_point: Path) -> None:
        """Discover browser history database files."""
        # Chrome/Edge
        for browser_type in ['browser_chrome', 'browser_edge']:
            for path_pattern in self.ARTIFACT_PATHS[browser_type]:
                try:
                    # Handle wildcard user paths
                    parts = path_pattern.split('/')
                    base_parts = []
                    for part in parts:
                        if '*' in part:
                            break
                        base_parts.append(part)
                    
                    base_path = mount_point / Path(*base_parts)
                    if not base_path.exists():
                        continue
                    
                    pattern = '/'.join(parts[len(base_parts):])
                    for profile_dir in base_path.glob(pattern):
                        if profile_dir.is_dir():
                            # Look for History database
                            history_db = profile_dir / 'History'
                            if history_db.exists() and history_db.is_file():
                                browser_name = "Chrome" if "Chrome" in path_pattern else "Edge"
                                # Calculate path relative to original mount point
                                try:
                                    internal_path = str(history_db.relative_to(self.original_mount_point))
                                except ValueError:
                                    internal_path = str(history_db.relative_to(mount_point))
                                
                                artifact = DiscoveredArtifact(
                                    artifact_type=ArtifactType.BROWSER,
                                    internal_path=internal_path,
                                    size_bytes=history_db.stat().st_size,
                                    description=f"{browser_name} History Database"
                                )
                                self.discovered_artifacts.append(artifact)
                                self.logger.debug(f"Found {browser_name} History")
                
                except Exception as e:
                    self.logger.warning(f"Error scanning browser pattern {path_pattern}: {e}")
        
        # Firefox
        for path_pattern in self.ARTIFACT_PATHS['browser_firefox']:
            try:
                parts = path_pattern.split('/')
                base_parts = []
                for part in parts:
                    if '*' in part:
                        break
                    base_parts.append(part)
                
                base_path = mount_point / Path(*base_parts)
                if not base_path.exists():
                    continue
                
                pattern = '/'.join(parts[len(base_parts):])
                for profile_dir in base_path.glob(pattern):
                    if profile_dir.is_dir():
                        # Look for places.sqlite
                        places_db = profile_dir / 'places.sqlite'
                        if places_db.exists() and places_db.is_file():
                            # Calculate path relative to original mount point
                            try:
                                internal_path = str(places_db.relative_to(self.original_mount_point))
                            except ValueError:
                                internal_path = str(places_db.relative_to(mount_point))
                            
                            artifact = DiscoveredArtifact(
                                artifact_type=ArtifactType.BROWSER,
                                internal_path=internal_path,
                                size_bytes=places_db.stat().st_size,
                                description="Firefox places.sqlite Database"
                            )
                            self.discovered_artifacts.append(artifact)
                            self.logger.debug("Found Firefox places.sqlite")
            
            except Exception as e:
                self.logger.warning(f"Error scanning Firefox pattern {path_pattern}: {e}")
    
    def _discover_mft(self, mount_point: Path) -> None:
        """Discover NTFS Master File Table ($MFT)."""
        # MFT is typically at root of NTFS volume
        mft_path = mount_point / '$MFT'
        
        if mft_path.exists() and mft_path.is_file():
            # Construct internal_path relative to the original mount point
            # If mount_point is like "C:/Temp/mount/partition_0", internal_path should be "partition_0/$MFT"
            if 'partition_' in str(mount_point):
                internal_path = f"{mount_point.name}/$MFT"
            else:
                internal_path = '$MFT'
            
            artifact = DiscoveredArtifact(
                artifact_type=ArtifactType.MFT,
                internal_path=internal_path,
                size_bytes=mft_path.stat().st_size,
                description="NTFS Master File Table"
            )
            self.discovered_artifacts.append(artifact)
            self.logger.info(f"Found $MFT at: {internal_path}")
        else:
            self.logger.debug(f"$MFT not found at: {mft_path}")
    
    def get_artifacts_by_type(self, artifact_type: ArtifactType) -> List[DiscoveredArtifact]:
        """
        Get all discovered artifacts of a specific type.
        
        Args:
            artifact_type: Type of artifact to filter
            
        Returns:
            List of artifacts matching the type
        """
        return [a for a in self.discovered_artifacts if a.artifact_type == artifact_type]
    
    def get_summary(self) -> Dict[str, int]:
        """
        Get summary statistics of discovered artifacts.
        
        Returns:
            Dictionary with artifact counts by type
        """
        summary = {}
        for artifact_type in ArtifactType:
            count = len(self.get_artifacts_by_type(artifact_type))
            if count > 0:
                summary[artifact_type.value] = count
        return summary
    
    def export_to_list(self) -> List[Dict[str, Any]]:
        """
        Export discovered artifacts to list of dictionaries.
        
        Returns:
            List of artifact dictionaries
        """
        return [artifact.to_dict() for artifact in self.discovered_artifacts]
    
    def _detect_windows_system(self, mount_point: Path) -> bool:
        """Detect if this is a Windows system."""
        windows_indicators = [
            mount_point / 'Windows',
            mount_point / 'Program Files',
            mount_point / 'Users',
        ]
        
        # Log what we're checking
        self.logger.debug(f"Checking for Windows system at: {mount_point}")
        for indicator in windows_indicators:
            if indicator.exists():
                self.logger.info(f"✓ Found Windows indicator: {indicator}")
                return True
            else:
                self.logger.debug(f"✗ Windows indicator not found: {indicator}")
        
        # Check inside partition subdirectories (multi-partition images)
        for partition_dir in mount_point.glob('partition_*'):
            self.logger.debug(f"Checking partition: {partition_dir}")
            for subdir in ['Windows', 'Program Files', 'Users']:
                indicator = partition_dir / subdir
                if indicator.exists():
                    self.logger.info(f"✓ Found Windows indicator in partition: {indicator}")
                    return True
        
        self.logger.warning(f"⚠ No Windows filesystem indicators found at {mount_point}")
        return False
    
    def _detect_linux_system(self, mount_point: Path) -> bool:
        """Detect if this is a Linux/Unix system."""
        # Check for common Linux directories or partitions containing Linux files
        linux_indicators = []
        
        # Check root-level Linux directories
        for subdir in ['etc', 'usr', 'var', 'opt', 'bin', 'sbin', 'home']:
            linux_indicators.append(mount_point / subdir)
        
        # Check partition subdirectories (for multi-partition extractions)
        for partition_dir in mount_point.glob('partition_*'):
            for subdir in ['etc', 'usr', 'var', 'opt', 'bin', 'sbin']:
                linux_indicators.append(partition_dir / subdir)
        
        found = any(p.exists() and p.is_dir() for p in linux_indicators)
        if found:
            self.logger.info(f"✓ Detected Linux/Unix system at {mount_point}")
        else:
            self.logger.debug(f"✗ No Linux indicators found at {mount_point}")
        
        return found
    
    def _detect_macos_system(self, mount_point: Path) -> bool:
        """Detect if this is a macOS system (HFS+/APFS)."""
        # Check for macOS-specific directories and files
        macos_indicators = [
            mount_point / '.fseventsd',           # FSEvents directory
            mount_point / '.Trashes',             # macOS trash
            mount_point / '.journal',             # HFS+ journal
            mount_point / '.journal_info_block',  # HFS+ journal info
            mount_point / '$CatalogFile',         # HFS+ catalog
            mount_point / '$ExtentsFile',         # HFS+ extents
            mount_point / 'Library',              # macOS library folder
            mount_point / 'System',               # macOS system folder
            mount_point / 'Applications',         # macOS apps folder
            mount_point / 'Users',                # Users directory (combined check)
        ]
        
        # Count how many indicators exist
        found_indicators = [ind for ind in macos_indicators if ind.exists()]
        
        # Need at least 2 indicators for positive detection
        is_macos = len(found_indicators) >= 2
        
        if is_macos:
            indicator_names = [ind.name for ind in found_indicators]
            self.logger.info(f"✓ Detected macOS filesystem (HFS+/APFS) at {mount_point}")
            self.logger.info(f"  Found indicators: {', '.join(indicator_names[:5])}")
        else:
            self.logger.debug(f"✗ No macOS indicators found at {mount_point}")
        
        return is_macos
    
    def _detect_category_organized(self, mount_point: Path) -> bool:
        """Detect if artifacts are already organized into category directories."""
        # Check for category subdirectories created by fast extraction
        category_indicators = ['registry', 'prefetch', 'evtx', 'mft', 'browser', 'user_registry',
                             'android_db', 'android_logs', 'android_apps', 'android_media',
                             'carved_files', 'partition_raw.bin']
        
        # Check root level or partition subdirectories
        for partition_dir in [mount_point] + list(mount_point.glob('partition_*')):
            category_count = sum(1 for cat in category_indicators 
                               if (partition_dir / cat).exists() or (partition_dir / cat).is_file())
            if category_count >= 1:  # At least 1 category directory/file = organized structure
                self.logger.info(f"✓ Detected category-organized structure in {partition_dir}")
                return True
        
        self.logger.debug(f"✗ No category-organized structure found")
        return False
    
    def _discover_from_categories(self, mount_point: Path, artifact_types: Optional[List[str]], progress_callback) -> None:
        """Discover artifacts from category-organized directories (fast extraction mode)."""
        # Map category directories to artifact types
        category_map = {
            'registry': ArtifactType.REGISTRY,
            'user_registry': ArtifactType.REGISTRY,  # User registry is also REGISTRY type
            'prefetch': ArtifactType.PREFETCH,
            'evtx': ArtifactType.EVTX,
            'mft': ArtifactType.MFT,
            'browser': ArtifactType.BROWSER,  # Generic browser type
            'android_db': ArtifactType.MOBILE_DATABASE,  # Android databases
            'android_logs': ArtifactType.MOBILE_LOG,  # Android logs
            'android_apps': ArtifactType.MOBILE_APP,  # Android apps (APKs)
            'android_media': ArtifactType.MOBILE_MEDIA,  # Android media files
            'carved_files': ArtifactType.UNKNOWN,  # Carved files from raw extraction
        }
        
        # Scan each partition directory
        partition_dirs = list(mount_point.glob('partition_*'))
        if not partition_dirs:
            partition_dirs = [mount_point]  # Use root if no partitions
        
        total_steps = len(category_map) * len(partition_dirs)
        current_step = 0
        
        for partition_dir in partition_dirs:
            partition_name = partition_dir.name if partition_dir != mount_point else "root"
            
            # Check for raw partition data file
            raw_file = partition_dir / 'partition_raw.bin'
            if raw_file.exists() and raw_file.is_file():
                try:
                    rel_path = str(raw_file.relative_to(mount_point))
                except ValueError:
                    rel_path = str(raw_file)
                
                artifact = DiscoveredArtifact(
                    artifact_type=ArtifactType.UNKNOWN,
                    internal_path=rel_path,
                    size_bytes=raw_file.stat().st_size,
                    description=f"Raw partition data: {raw_file.name}"
                )
                self.discovered_artifacts.append(artifact)
                self.logger.info(f"Found raw partition data: {raw_file.name}")
            
            for category, artifact_type in category_map.items():
                current_step += 1
                
                # Check if this artifact type is requested
                if artifact_types and category.replace('user_', '').replace('android_', '').replace('carved_', '') not in artifact_types:
                    continue
                
                if progress_callback:
                    progress_callback(current_step, total_steps, f"Scanning {category} in {partition_name}...")
                
                category_dir = partition_dir / category
                if not category_dir.exists():
                    continue
                
                # Scan all files in the category directory
                try:
                    for artifact_file in category_dir.rglob('*'):
                        if not artifact_file.is_file():
                            continue
                        
                        # Calculate relative path
                        try:
                            rel_path = str(artifact_file.relative_to(mount_point))
                        except ValueError:
                            rel_path = str(artifact_file)
                        
                        artifact = DiscoveredArtifact(
                            artifact_type=artifact_type,
                            internal_path=rel_path,
                            size_bytes=artifact_file.stat().st_size,
                            description=f"{category.capitalize()}: {artifact_file.name}"
                        )
                        self.discovered_artifacts.append(artifact)
                        self.logger.debug(f"Found {category}: {artifact_file.name}")
                
                except Exception as e:
                    self.logger.warning(f"Error scanning category {category}: {e}")
    
    def _discover_linux_configs(self, mount_point: Path) -> None:
        """Discover Linux configuration files."""
        config_patterns = [
            '**/*.conf',
            '**/*.cfg',
            '**/*.config',
            '**/*.json',
            '**/*.xml',
            '**/*.ini',
            '**/config/**/*',
        ]
        
        for pattern in config_patterns:
            try:
                for config_file in mount_point.glob(pattern):
                    if config_file.is_file() and config_file.stat().st_size > 0:
                        # Get relative path
                        try:
                            rel_path = str(config_file.relative_to(mount_point))
                        except ValueError:
                            rel_path = str(config_file)
                        
                        artifact = DiscoveredArtifact(
                            artifact_type=ArtifactType.LINUX_CONFIG,
                            internal_path=rel_path,
                            size_bytes=config_file.stat().st_size,
                            description=f"Linux configuration file: {config_file.name}"
                        )
                        self.discovered_artifacts.append(artifact)
            except Exception as e:
                self.logger.debug(f"Error scanning config pattern {pattern}: {e}")
        
        self.logger.info(f"Found {len([a for a in self.discovered_artifacts if a.artifact_type == ArtifactType.LINUX_CONFIG])} configuration files")
    
    def _discover_linux_logs(self, mount_point: Path) -> None:
        """Discover Linux log files."""
        log_patterns = [
            '**/var/log/**/*.log',
            '**/var/log/**/*.log.*',
            '**/*.log',
        ]
        
        for pattern in log_patterns:
            try:
                for log_file in mount_point.glob(pattern):
                    if log_file.is_file() and log_file.stat().st_size > 0:
                        try:
                            rel_path = str(log_file.relative_to(mount_point))
                        except ValueError:
                            rel_path = str(log_file)
                        
                        artifact = DiscoveredArtifact(
                            artifact_type=ArtifactType.LINUX_LOG,
                            internal_path=rel_path,
                            size_bytes=log_file.stat().st_size,
                            description=f"Linux log file: {log_file.name}"
                        )
                        self.discovered_artifacts.append(artifact)
            except Exception as e:
                self.logger.debug(f"Error scanning log pattern {pattern}: {e}")
        
        self.logger.info(f"Found {len([a for a in self.discovered_artifacts if a.artifact_type == ArtifactType.LINUX_LOG])} log files")
    
    def _discover_linux_scripts(self, mount_point: Path) -> None:
        """Discover shell scripts, Python scripts, and binaries."""
        script_patterns = [
            '**/*.sh',
            '**/*.bash',
            '**/*.py',
            '**/*.pl',
            '**/*.rb',
        ]
        
        for pattern in script_patterns:
            try:
                for script_file in mount_point.glob(pattern):
                    if script_file.is_file() and script_file.stat().st_size > 0:
                        try:
                            rel_path = str(script_file.relative_to(mount_point))
                        except ValueError:
                            rel_path = str(script_file)
                        
                        artifact = DiscoveredArtifact(
                            artifact_type=ArtifactType.SCRIPT,
                            internal_path=rel_path,
                            size_bytes=script_file.stat().st_size,
                            description=f"Script file: {script_file.name}"
                        )
                        self.discovered_artifacts.append(artifact)
            except Exception as e:
                self.logger.debug(f"Error scanning script pattern {pattern}: {e}")
        
        self.logger.info(f"Found {len([a for a in self.discovered_artifacts if a.artifact_type == ArtifactType.SCRIPT])} script files")
    
    def _discover_macos_fseventsd(self, mount_point: Path) -> None:
        """Discover FSEvents (file system events) on macOS."""
        fseventsd_dir = mount_point / '.fseventsd'
        
        if not fseventsd_dir.exists():
            self.logger.debug("No .fseventsd directory found")
            return
        
        try:
            for fsevent_file in fseventsd_dir.glob('*'):
                if fsevent_file.is_file():
                    try:
                        rel_path = str(fsevent_file.relative_to(mount_point))
                    except ValueError:
                        rel_path = str(fsevent_file)
                    
                    artifact = DiscoveredArtifact(
                        artifact_type=ArtifactType.SYSTEM_LOG,
                        internal_path=rel_path,
                        size_bytes=fsevent_file.stat().st_size,
                        description=f"macOS FSEvents file: {fsevent_file.name}"
                    )
                    self.discovered_artifacts.append(artifact)
                    
            self.logger.info(f"Found {len(list(fseventsd_dir.glob('*')))} FSEvents files")
        except Exception as e:
            self.logger.error(f"Error discovering FSEvents: {e}")
    
    def _discover_macos_shell_history(self, mount_point: Path) -> None:
        """Discover bash/zsh history files on macOS."""
        history_patterns = [
            'Users/*/.bash_history',
            'Users/*/.zsh_history',
            'Users/*/.sh_history',
        ]
        
        history_count = 0
        for pattern in history_patterns:
            try:
                for hist_file in mount_point.glob(pattern):
                    if hist_file.is_file():
                        try:
                            rel_path = str(hist_file.relative_to(mount_point))
                        except ValueError:
                            rel_path = str(hist_file)
                        
                        artifact = DiscoveredArtifact(
                            artifact_type=ArtifactType.SHELL_HISTORY,
                            internal_path=rel_path,
                            size_bytes=hist_file.stat().st_size,
                            description=f"macOS shell history: {hist_file.name}"
                        )
                        self.discovered_artifacts.append(artifact)
                        history_count += 1
            except Exception as e:
                self.logger.debug(f"Error scanning history pattern {pattern}: {e}")
        
        self.logger.info(f"Found {history_count} shell history files")
    
    def _discover_macos_logs(self, mount_point: Path) -> None:
        """Discover macOS system logs."""
        log_paths = [
            'var/log',
            'private/var/log',
            'Library/Logs',
        ]
        
        log_count = 0
        for log_path in log_paths:
            log_dir = mount_point / log_path
            if not log_dir.exists():
                continue
            
            try:
                # Look for .log and .asl files
                for log_file in log_dir.rglob('*.log'):
                    if log_file.is_file():
                        try:
                            rel_path = str(log_file.relative_to(mount_point))
                        except ValueError:
                            rel_path = str(log_file)
                        
                        artifact = DiscoveredArtifact(
                            artifact_type=ArtifactType.SYSTEM_LOG,
                            internal_path=rel_path,
                            size_bytes=log_file.stat().st_size,
                            description=f"macOS log file: {log_file.name}"
                        )
                        self.discovered_artifacts.append(artifact)
                        log_count += 1
            except Exception as e:
                self.logger.debug(f"Error scanning log directory {log_path}: {e}")
        
        self.logger.info(f"Found {log_count} macOS log files")
    
    def _discover_macos_user_files(self, mount_point: Path) -> None:
        """Discover user documents and files on macOS."""
        users_dir = mount_point / 'Users'
        
        if not users_dir.exists():
            self.logger.debug("No Users directory found")
            return
        
        file_count = 0
        for user_path in users_dir.iterdir():
            if not user_path.is_dir() or user_path.name in ['Shared', '.localized']:
                continue
            
            # Common user document directories
            for doc_dir_name in ['Documents', 'Desktop', 'Downloads']:
                doc_path = user_path / doc_dir_name
                if not doc_path.exists():
                    continue
                
                try:
                    # Discover text files and documents (limit per directory)
                    for pattern in ['*.txt', '*.pdf', '*.doc*']:
                        for doc_file in doc_path.rglob(pattern):
                            if doc_file.is_file() and file_count < 100:  # Limit total
                                try:
                                    rel_path = str(doc_file.relative_to(mount_point))
                                except ValueError:
                                    rel_path = str(doc_file)
                                
                                artifact = DiscoveredArtifact(
                                    artifact_type=ArtifactType.USER_FILE,
                                    internal_path=rel_path,
                                    size_bytes=doc_file.stat().st_size,
                                    description=f"macOS user file: {doc_file.name}"
                                )
                                self.discovered_artifacts.append(artifact)
                                file_count += 1
                except Exception as e:
                    self.logger.debug(f"Error scanning {doc_path}: {e}")
        
        self.logger.info(f"Found {file_count} user files")
