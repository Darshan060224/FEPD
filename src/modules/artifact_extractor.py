"""
FEPD - Artifact Extractor
Automated extraction of Windows forensic artifacts from disk images

Extracts artifacts from known default locations:
- Event logs (EVTX)
- Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT)
- Prefetch files
- Master File Table ($MFT)
- Browser history databases (Chrome, Edge, Firefox)
- User files and documents

Maintains chain of custody with cryptographic hashing.
"""

import logging
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from src.modules.image_handler import DiskImageHandler


class ArtifactExtractor:
    """
    Automated forensic artifact extractor for Windows disk images.
    """
    
    # Default artifact locations in Windows
    ARTIFACT_PATHS = {
        'event_logs': [
            '/Windows/System32/winevt/Logs/Application.evtx',
            '/Windows/System32/winevt/Logs/Security.evtx',
            '/Windows/System32/winevt/Logs/System.evtx',
            '/Windows/System32/winevt/Logs/Setup.evtx',
            '/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx',
            '/Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx',
        ],
        'registry_system': [
            '/Windows/System32/config/SYSTEM',
            '/Windows/System32/config/SOFTWARE',
            '/Windows/System32/config/SAM',
            '/Windows/System32/config/SECURITY',
            '/Windows/System32/config/DEFAULT',
        ],
        'registry_system_logs': [
            '/Windows/System32/config/SYSTEM.LOG1',
            '/Windows/System32/config/SYSTEM.LOG2',
            '/Windows/System32/config/SOFTWARE.LOG1',
            '/Windows/System32/config/SOFTWARE.LOG2',
            '/Windows/System32/config/SAM.LOG1',
            '/Windows/System32/config/SAM.LOG2',
        ],
        'prefetch': [
            '/Windows/Prefetch/*.pf',
        ],
        'mft': [
            '/$MFT',
        ],
    }
    
    # User-specific artifact patterns
    USER_ARTIFACT_PATTERNS = {
        'ntuser_dat': 'NTUSER.DAT',
        'usrclass_dat': 'AppData/Local/Microsoft/Windows/UsrClass.dat',
        'chrome_history': 'AppData/Local/Google/Chrome/User Data/Default/History',
        'chrome_cookies': 'AppData/Local/Google/Chrome/User Data/Default/Cookies',
        'edge_history': 'AppData/Local/Microsoft/Edge/User Data/Default/History',
        'edge_cookies': 'AppData/Local/Microsoft/Edge/User Data/Default/Cookies',
        'firefox_places': 'AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite',
    }
    
    def __init__(self, image_path: str, output_dir: Path, verify_hash: bool = True,
                 progress_callback=None):
        """
        Initialize artifact extractor.
        
        Args:
            image_path: Path to disk image (E01 or DD)
            output_dir: Directory to extract artifacts to
            verify_hash: Whether to verify image and calculate artifact hashes
            progress_callback: Optional callback function(message, percentage) for progress updates
        """
        self.logger = logging.getLogger(__name__)
        self.image_path = image_path
        self.output_dir = Path(output_dir)
        self.verify_hash = verify_hash
        self.progress_callback = progress_callback
        
        self.image_handler = None
        self.extraction_log = []
        
        # Create output directory structure
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _report_progress(self, message: str, percentage: int):
        """Report progress if callback is set."""
        if self.progress_callback:
            try:
                self.progress_callback(message, percentage)
            except Exception as e:
                self.logger.warning(f"Progress callback error: {e}")
    
    def extract_all_artifacts(self) -> Dict[str, Any]:
        """
        Extract all artifacts from the disk image.
        
        Returns:
            Dictionary containing extraction results and metadata
        """
        self.logger.info(f"Starting artifact extraction from {self.image_path}")
        self._report_progress("Starting artifact extraction...", 5)
        
        results = {
            'image_path': self.image_path,
            'output_dir': str(self.output_dir),
            'start_time': datetime.now().isoformat(),
            'artifacts': {},
            'errors': [],
            'image_metadata': {}
        }
        
        try:
            # Open image
            self._report_progress("Opening disk image...", 10)
            self.image_handler = DiskImageHandler(self.image_path, self.verify_hash)
            
            if not self.image_handler.open_image():
                raise RuntimeError("Failed to open disk image")
            
            self._report_progress("Image opened, reading metadata...", 15)
            
            # Store image metadata
            results['image_metadata'] = {
                'type': self.image_handler.image_type,
                'size': self.image_handler.image_size,
                'hash': self.image_handler.image_hash,
            }
            
            # Enumerate partitions
            self._report_progress("Enumerating partitions...", 20)
            partitions = self.image_handler.enumerate_partitions()
            self.logger.info(f"Found {len(partitions)} partition(s)")
            self._report_progress(f"Found {len(partitions)} partition(s)", 25)
            
            # Process each partition (typically focus on NTFS partitions)
            total_partitions = max(len(partitions), 1)
            for i, partition in enumerate(partitions):
                self.logger.info(f"Processing partition {i}: {partition['description']}")
                
                # Calculate progress: 25% to 90% for partition processing
                partition_base_progress = 25 + int((i / total_partitions) * 65)
                partition_end_progress = 25 + int(((i + 1) / total_partitions) * 65)
                
                self._report_progress(f"Processing partition {i+1}/{total_partitions}: {partition['description']}", partition_base_progress)
                
                # Open filesystem
                fs_info = self.image_handler.open_filesystem(i)
                
                if not fs_info:
                    self.logger.warning(f"Skipping partition {i} (filesystem not accessible)")
                    continue
                
                # Extract system artifacts (first half of partition progress)
                system_progress = partition_base_progress + int((partition_end_progress - partition_base_progress) * 0.3)
                self._report_progress(f"Partition {i+1}: Extracting system artifacts...", system_progress)
                self._extract_system_artifacts(fs_info, i, results)
                
                # Extract user artifacts (second half of partition progress)
                user_progress = partition_base_progress + int((partition_end_progress - partition_base_progress) * 0.7)
                self._report_progress(f"Partition {i+1}: Extracting user artifacts...", user_progress)
                self._extract_user_artifacts(fs_info, i, results)
                
                self._report_progress(f"Partition {i+1}/{total_partitions} complete", partition_end_progress)
            
            self._report_progress("Finalizing extraction...", 92)
            results['end_time'] = datetime.now().isoformat()
            results['success'] = True
            self._report_progress("Extraction complete!", 95)
            
        except Exception as e:
            self.logger.error(f"Artifact extraction failed: {e}", exc_info=True)
            results['errors'].append(str(e))
            results['success'] = False
            
        finally:
            if self.image_handler:
                self.image_handler.close()
            
            # Save extraction log
            self._save_extraction_log(results)
        
        return results
    
    def _extract_system_artifacts(self, fs_info, partition_index: int, 
                                  results: Dict[str, Any]):
        """
        Extract system-level artifacts (event logs, registry, prefetch, MFT).
        
        Args:
            fs_info: File system info object
            partition_index: Index of current partition
            results: Results dictionary to update
        """
        # Create output subdirectories
        partition_dir = self.output_dir / f"partition_{partition_index}"
        
        # Extract event logs
        self._extract_artifact_group(
            fs_info, 
            self.ARTIFACT_PATHS['event_logs'],
            partition_dir / "EventLogs",
            results,
            'event_logs'
        )
        
        # Extract registry hives
        self._extract_artifact_group(
            fs_info,
            self.ARTIFACT_PATHS['registry_system'],
            partition_dir / "Registry",
            results,
            'registry_hives'
        )
        
        # Extract registry transaction logs
        self._extract_artifact_group(
            fs_info,
            self.ARTIFACT_PATHS['registry_system_logs'],
            partition_dir / "Registry",
            results,
            'registry_logs'
        )
        
        # Extract MFT
        self._extract_artifact_group(
            fs_info,
            self.ARTIFACT_PATHS['mft'],
            partition_dir / "MFT",
            results,
            'mft'
        )
        
        # Extract prefetch files
        self._extract_prefetch_files(fs_info, partition_dir / "Prefetch", results)
    
    def _extract_user_artifacts(self, fs_info, partition_index: int,
                               results: Dict[str, Any]):
        """
        Extract user-specific artifacts (NTUSER.DAT, browser history, etc.).
        
        Args:
            fs_info: File system info object
            partition_index: Index of current partition
            results: Results dictionary to update
        """
        partition_dir = self.output_dir / f"partition_{partition_index}"
        users_dir = partition_dir / "Users"
        
        # Find all user directories
        user_dirs = self._find_user_directories(fs_info)
        
        for username, user_path in user_dirs:
            self.logger.info(f"Processing user: {username}")
            
            user_output_dir = users_dir / username
            
            # Extract NTUSER.DAT
            ntuser_path = f"{user_path}/NTUSER.DAT"
            self._extract_single_artifact(
                fs_info,
                ntuser_path,
                user_output_dir / "NTUSER.DAT",
                results,
                f'user_{username}_ntuser'
            )
            
            # Extract UsrClass.dat
            usrclass_path = f"{user_path}/AppData/Local/Microsoft/Windows/UsrClass.dat"
            self._extract_single_artifact(
                fs_info,
                usrclass_path,
                user_output_dir / "UsrClass.dat",
                results,
                f'user_{username}_usrclass'
            )
            
            # Extract browser history
            self._extract_browser_artifacts(fs_info, user_path, user_output_dir, username, results)
    
    def _extract_browser_artifacts(self, fs_info, user_path: str, 
                                   output_dir: Path, username: str,
                                   results: Dict[str, Any]):
        """
        Extract browser history databases.
        
        Args:
            fs_info: File system info object
            user_path: Path to user directory
            output_dir: Output directory for this user
            username: Username for logging
            results: Results dictionary to update
        """
        browser_dir = output_dir / "BrowserHistory"
        
        # Chrome
        chrome_history = f"{user_path}/AppData/Local/Google/Chrome/User Data/Default/History"
        self._extract_single_artifact(
            fs_info, chrome_history, browser_dir / "Chrome_History",
            results, f'user_{username}_chrome_history'
        )
        
        # Edge
        edge_history = f"{user_path}/AppData/Local/Microsoft/Edge/User Data/Default/History"
        self._extract_single_artifact(
            fs_info, edge_history, browser_dir / "Edge_History",
            results, f'user_{username}_edge_history'
        )
        
        # Firefox - need to find profile directory
        firefox_profiles = self._find_firefox_profiles(fs_info, user_path)
        for profile_name, profile_path in firefox_profiles:
            places_path = f"{profile_path}/places.sqlite"
            self._extract_single_artifact(
                fs_info, places_path, 
                browser_dir / f"Firefox_{profile_name}_places.sqlite",
                results, f'user_{username}_firefox_{profile_name}'
            )
    
    def _extract_artifact_group(self, fs_info, paths: List[str], 
                               output_dir: Path, results: Dict[str, Any],
                               group_name: str):
        """
        Extract a group of artifacts from specified paths.
        
        Args:
            fs_info: File system info object
            paths: List of artifact paths in image
            output_dir: Output directory for artifacts
            results: Results dictionary to update
            group_name: Name for this artifact group
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_count = 0
        
        for path in paths:
            # Handle wildcard paths
            if '*' in path:
                # Extract directory path and pattern
                dir_path = str(Path(path).parent)
                pattern = Path(path).name
                
                # List directory and match pattern
                try:
                    entries = self.image_handler.list_directory(fs_info, dir_path)
                    for entry in entries:
                        if entry['type'] == 'file':
                            # Simple pattern matching
                            if pattern.replace('*', '') in entry['name']:
                                file_path = f"{dir_path}/{entry['name']}"
                                output_file = output_dir / entry['name']
                                
                                metadata = self.image_handler.extract_file(
                                    fs_info, file_path, output_file, self.verify_hash
                                )
                                
                                if metadata:
                                    extracted_count += 1
                                    self.extraction_log.append(metadata)
                except Exception as e:
                    self.logger.warning(f"Failed to process wildcard path {path}: {e}")
            else:
                # Direct file extraction
                output_file = output_dir / Path(path).name
                
                metadata = self.image_handler.extract_file(
                    fs_info, path, output_file, self.verify_hash
                )
                
                if metadata:
                    extracted_count += 1
                    self.extraction_log.append(metadata)
        
        results['artifacts'][group_name] = {
            'count': extracted_count,
            'output_dir': str(output_dir)
        }
        
        self.logger.info(f"Extracted {extracted_count} artifact(s) for {group_name}")
    
    def _extract_single_artifact(self, fs_info, path: str, output_path: Path,
                                results: Dict[str, Any], artifact_name: str):
        """
        Extract a single artifact file.
        
        Args:
            fs_info: File system info object
            path: Path to artifact in image
            output_path: Output file path
            results: Results dictionary to update
            artifact_name: Name for logging
        """
        metadata = self.image_handler.extract_file(
            fs_info, path, output_path, self.verify_hash
        )
        
        if metadata:
            self.extraction_log.append(metadata)
            results['artifacts'][artifact_name] = metadata
    
    def _extract_prefetch_files(self, fs_info, output_dir: Path, 
                               results: Dict[str, Any]):
        """
        Extract all prefetch files from Windows/Prefetch directory.
        
        Args:
            fs_info: File system info object
            output_dir: Output directory
            results: Results dictionary to update
        """
        prefetch_path = "/Windows/Prefetch"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            entries = self.image_handler.list_directory(fs_info, prefetch_path)
            
            extracted_count = 0
            
            for entry in entries:
                if entry['type'] == 'file' and entry['name'].endswith('.pf'):
                    file_path = f"{prefetch_path}/{entry['name']}"
                    output_file = output_dir / entry['name']
                    
                    metadata = self.image_handler.extract_file(
                        fs_info, file_path, output_file, self.verify_hash
                    )
                    
                    if metadata:
                        extracted_count += 1
                        self.extraction_log.append(metadata)
            
            results['artifacts']['prefetch'] = {
                'count': extracted_count,
                'output_dir': str(output_dir)
            }
            
            self.logger.info(f"Extracted {extracted_count} prefetch file(s)")
            
        except Exception as e:
            self.logger.warning(f"Failed to extract prefetch files: {e}")
    
    def _find_user_directories(self, fs_info) -> List[tuple]:
        """
        Find all user directories under /Users.
        
        Args:
            fs_info: File system info object
            
        Returns:
            List of (username, path) tuples
        """
        user_dirs = []
        users_path = "/Users"
        
        try:
            entries = self.image_handler.list_directory(fs_info, users_path)
            
            for entry in entries:
                if entry['type'] == 'dir':
                    # Skip system directories
                    if entry['name'] not in ['Public', 'Default', 'Default User', 'All Users']:
                        user_path = f"{users_path}/{entry['name']}"
                        user_dirs.append((entry['name'], user_path))
                        
        except Exception as e:
            self.logger.warning(f"Failed to enumerate user directories: {e}")
        
        return user_dirs
    
    def _find_firefox_profiles(self, fs_info, user_path: str) -> List[tuple]:
        """
        Find Firefox profile directories for a user.
        
        Args:
            fs_info: File system info object
            user_path: Path to user directory
            
        Returns:
            List of (profile_name, path) tuples
        """
        profiles = []
        firefox_path = f"{user_path}/AppData/Roaming/Mozilla/Firefox/Profiles"
        
        try:
            entries = self.image_handler.list_directory(fs_info, firefox_path)
            
            for entry in entries:
                if entry['type'] == 'dir':
                    profile_path = f"{firefox_path}/{entry['name']}"
                    profiles.append((entry['name'], profile_path))
                    
        except Exception as e:
            # Firefox may not be installed
            pass
        
        return profiles
    
    def _save_extraction_log(self, results: Dict[str, Any]):
        """
        Save extraction log with all artifact metadata and hashes.
        
        Args:
            results: Extraction results dictionary
        """
        log_file = self.output_dir / "extraction_log.json"
        
        log_data = {
            'extraction_summary': results,
            'extracted_artifacts': self.extraction_log,
            'chain_of_custody': {
                'image_hash': results['image_metadata'].get('hash'),
                'extraction_time': results.get('start_time'),
                'tool': 'FEPD Artifact Extractor',
                'verify_hash': self.verify_hash
            }
        }
        
        with open(log_file, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        self.logger.info(f"Extraction log saved to {log_file}")
        
        # Also create a simple CSV log
        csv_file = self.output_dir / "extraction_log.csv"
        with open(csv_file, 'w') as f:
            f.write("Source Path,Output Path,Size,MD5,SHA256,Extracted At\n")
            for artifact in self.extraction_log:
                f.write(
                    f'"{artifact["source_path"]}","'
                    f'{artifact["output_path"]}",'
                    f'{artifact["size"]},'
                    f'{artifact.get("md5", "")},'
                    f'{artifact.get("sha256", "")},'
                    f'"{artifact["extracted_at"]}"\n'
                )
        
        self.logger.info(f"Extraction CSV saved to {csv_file}")


def extract_artifacts_from_image(image_path: str, output_dir: str, 
                                verify_hash: bool = True,
                                progress_callback=None) -> Dict[str, Any]:
    """
    Convenience function to extract all artifacts from a disk image.
    
    Args:
        image_path: Path to disk image (E01 or DD)
        output_dir: Directory to extract artifacts to
        verify_hash: Whether to verify image and calculate artifact hashes
        progress_callback: Optional callback function(message, percentage) for progress updates
        
    Returns:
        Dictionary containing extraction results
        
    Example:
        >>> results = extract_artifacts_from_image("case.E01", "extracted_artifacts")
        >>> print(f"Extracted {len(results['artifacts'])} artifact groups")
    """
    extractor = ArtifactExtractor(image_path, Path(output_dir), verify_hash, progress_callback)
    return extractor.extract_all_artifacts()
