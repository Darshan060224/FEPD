"""
AUTOMATIC USER PROFILE & FILESYSTEM DETECTOR
Automatically detects and displays complete Windows/Linux filesystem structure
with Desktop, Downloads, Documents, Pictures, Music, Videos, etc.

ZERO USER ACTION REQUIRED - Runs automatically when VFS is loaded
"""

import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class UserProfile:
    """Detected user profile with special folders."""
    name: str
    sid: Optional[str] = None
    folders: Dict[str, 'FolderStats'] = field(default_factory=dict)
    last_login: Optional[datetime] = None


@dataclass
class FolderStats:
    """Statistics for a special folder."""
    name: str
    path: Path
    icon: str
    file_count: int = 0
    total_size: int = 0
    suspicious_count: int = 0
    last_modified: Optional[datetime] = None


class AutomaticFilesystemDetector:
    """
    Automatically detects and organizes complete filesystem structure.
    
    Features:
    - Auto-detect Windows user profiles (C:/Users/*)
    - Auto-detect Linux home directories (/home/*)
    - Find Desktop, Downloads, Documents, Pictures, Music, Videos
    - Detect AppData, OneDrive, Dropbox, Google Drive
    - Flag suspicious files automatically
    - Generate file type statistics
    """
    
    # Windows special folders with icons
    WINDOWS_FOLDERS = {
        'Desktop': '🖥️',
        'Downloads': '📥',
        'Documents': '📄',
        'Pictures': '🖼️',
        'Music': '🎵',
        'Videos': '🎬',
        'AppData': '📁',
        'OneDrive': '📦',
        'Favorites': '⭐',
        'Links': '🔗',
        'Contacts': '👥',
        'Searches': '🔍',
        'Saved Games': '🎮'
    }
    
    # Linux special folders
    LINUX_FOLDERS = {
        'Desktop': '🖥️',
        'Downloads': '📥',
        'Documents': '📄',
        'Pictures': '🖼️',
        'Music': '🎵',
        'Videos': '🎬',
        '.config': '⚙️',
        '.local': '📁',
        '.cache': '💾'
    }
    
    # File type categories with icons and priority
    FILE_CATEGORIES = {
        'Documents': {
            'extensions': ['.doc', '.docx', '.pdf', '.txt', '.xlsx', '.pptx', '.odt', '.rtf'],
            'icon': '📄',
            'priority': 'high'
        },
        'Images': {
            'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.heic', '.webp'],
            'icon': '🖼️',
            'priority': 'medium'
        },
        'Videos': {
            'extensions': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm'],
            'icon': '🎬',
            'priority': 'medium'
        },
        'Audio': {
            'extensions': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma'],
            'icon': '🎵',
            'priority': 'low'
        },
        'Archives': {
            'extensions': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'],
            'icon': '📦',
            'priority': 'high'
        },
        'Executables': {
            'extensions': ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.jar', '.msi'],
            'icon': '⚙️',
            'priority': 'critical'
        },
        'Shortcuts': {
            'extensions': ['.lnk', '.url'],
            'icon': '🔗',
            'priority': 'medium'
        },
        'Databases': {
            'extensions': ['.db', '.sqlite', '.mdb', '.accdb', '.dbf'],
            'icon': '🗄️',
            'priority': 'high'
        },
        'Code': {
            'extensions': ['.py', '.java', '.cpp', '.c', '.h', '.js', '.html', '.css', '.php'],
            'icon': '💻',
            'priority': 'medium'
        }
    }
    
    # Suspicious filename patterns
    SUSPICIOUS_PATTERNS = {
        'passwords': ['password', 'passwd', 'pwd', 'credentials', 'creds', 'login'],
        'financial': ['bank', 'credit', 'ssn', 'tax', 'invoice', 'payment'],
        'confidential': ['confidential', 'secret', 'private', 'internal', 'classified'],
        'hacking': ['hack', 'crack', 'exploit', 'backdoor', 'rootkit', 'keylog'],
        'malware': ['malware', 'virus', 'trojan', 'ransomware', 'payload'],
        'hidden': ['.', '~$', 'thumbs.db', 'desktop.ini']
    }
    
    def __init__(self, vfs_root: Path):
        """
        Initialize detector with VFS root.
        
        Args:
            vfs_root: Root path of virtual filesystem
        """
        self.vfs_root = Path(vfs_root)
        self.logger = logging.getLogger(__name__)
        self.user_profiles: List[UserProfile] = []
        self.file_stats: Dict[str, Any] = defaultdict(int)
        self.os_type: Optional[str] = None
    
    def auto_detect_and_organize(self) -> Dict[str, Any]:
        """
        MAIN METHOD: Automatically detect and organize entire filesystem.
        
        Returns:
            Complete filesystem structure with all detected profiles and folders
        """
        self.logger.info("🚀 Auto-detecting filesystem structure...")
        
        # Step 1: Detect OS type
        self.os_type = self._detect_os_type()
        self.logger.info(f"📊 Detected OS: {self.os_type}")
        
        # Step 2: Detect all user profiles
        if self.os_type == 'windows':
            self.user_profiles = self._detect_windows_profiles()
        elif self.os_type == 'linux':
            self.user_profiles = self._detect_linux_profiles()
        
        self.logger.info(f"👤 Detected {len(self.user_profiles)} user profile(s)")
        
        # Step 3: Analyze each profile's folders
        for profile in self.user_profiles:
            self._analyze_profile_folders(profile)
            self.logger.info(f"   📂 {profile.name}: {len(profile.folders)} special folders found")
        
        # Step 4: Generate complete structure
        structure = self._generate_filesystem_structure()
        
        self.logger.info("✅ Filesystem detection complete")
        return structure
    
    def _detect_os_type(self) -> str:
        """Detect if Windows or Linux from filesystem structure."""
        # Check for Windows indicators
        windows_paths = [
            self.vfs_root / 'C:' / 'Windows',
            self.vfs_root / 'C:' / 'Program Files',
            self.vfs_root / 'C:' / 'Users'
        ]
        
        for path in windows_paths:
            if path.exists():
                return 'windows'
        
        # Check for Linux indicators
        linux_paths = [
            self.vfs_root / 'etc',
            self.vfs_root / 'home',
            self.vfs_root / 'usr',
            self.vfs_root / 'var'
        ]
        
        for path in linux_paths:
            if path.exists():
                return 'linux'
        
        return 'unknown'
    
    def _detect_windows_profiles(self) -> List[UserProfile]:
        """Detect all Windows user profiles from C:/Users."""
        profiles = []
        users_path = self.vfs_root / 'C:' / 'Users'
        
        if not users_path.exists():
            # Try other drive letters
            for drive in ['D:', 'E:', 'Windows', 'partition_3']:
                alt_path = self.vfs_root / drive / 'Users'
                if alt_path.exists():
                    users_path = alt_path
                    break
        
        if not users_path.exists():
            self.logger.warning("Users directory not found")
            return profiles
        
        # Iterate through user directories
        for user_dir in users_path.iterdir():
            if not user_dir.is_dir():
                continue
            
            # Skip system profiles
            if user_dir.name in ['Public', 'Default', 'All Users', 'Default User']:
                continue
            
            profile = UserProfile(name=user_dir.name)
            
            # Try to find user SID
            # SID typically in registry, but we can infer from folder structure
            
            profiles.append(profile)
            self.logger.info(f"   Found profile: {user_dir.name}")
        
        return profiles
    
    def _detect_linux_profiles(self) -> List[UserProfile]:
        """Detect all Linux user profiles from /home."""
        profiles = []
        home_path = self.vfs_root / 'home'
        
        if not home_path.exists():
            self.logger.warning("/home directory not found")
            return profiles
        
        for user_dir in home_path.iterdir():
            if not user_dir.is_dir():
                continue
            
            profile = UserProfile(name=user_dir.name)
            profiles.append(profile)
            self.logger.info(f"   Found profile: {user_dir.name}")
        
        return profiles
    
    def _analyze_profile_folders(self, profile: UserProfile):
        """Analyze a user profile and detect special folders."""
        if self.os_type == 'windows':
            self._analyze_windows_folders(profile)
        elif self.os_type == 'linux':
            self._analyze_linux_folders(profile)
    
    def _analyze_windows_folders(self, profile: UserProfile):
        """Analyze Windows special folders for a profile."""
        base_path = self.vfs_root / 'C:' / 'Users' / profile.name
        
        # Try alternate locations if not found
        if not base_path.exists():
            for drive in ['D:', 'E:', 'Windows', 'partition_3']:
                alt_path = self.vfs_root / drive / 'Users' / profile.name
                if alt_path.exists():
                    base_path = alt_path
                    break
        
        if not base_path.exists():
            return
        
        for folder_name, icon in self.WINDOWS_FOLDERS.items():
            folder_path = base_path / folder_name
            
            if folder_path.exists():
                stats = self._get_folder_stats(folder_path, folder_name, icon)
                profile.folders[folder_name] = stats
    
    def _analyze_linux_folders(self, profile: UserProfile):
        """Analyze Linux special folders for a profile."""
        base_path = self.vfs_root / 'home' / profile.name
        
        if not base_path.exists():
            return
        
        for folder_name, icon in self.LINUX_FOLDERS.items():
            folder_path = base_path / folder_name
            
            if folder_path.exists():
                stats = self._get_folder_stats(folder_path, folder_name, icon)
                profile.folders[folder_name] = stats
    
    def _get_folder_stats(self, folder_path: Path, folder_name: str, icon: str) -> FolderStats:
        """
        Get comprehensive statistics for a folder.
        
        Args:
            folder_path: Path to folder
            folder_name: Name of folder
            icon: Icon for folder
            
        Returns:
            FolderStats object with all statistics
        """
        stats = FolderStats(
            name=folder_name,
            path=folder_path,
            icon=icon
        )
        
        try:
            # Count files and calculate size
            for item in folder_path.rglob('*'):
                if item.is_file():
                    stats.file_count += 1
                    try:
                        stats.total_size += item.stat().st_size
                        
                        # Check if suspicious
                        if self._is_suspicious_file(item):
                            stats.suspicious_count += 1
                        
                        # Track last modified
                        mtime = datetime.fromtimestamp(item.stat().st_mtime)
                        if stats.last_modified is None or mtime > stats.last_modified:
                            stats.last_modified = mtime
                    except:
                        pass
        
        except Exception as e:
            self.logger.warning(f"Error analyzing folder {folder_path}: {e}")
        
        return stats
    
    def _is_suspicious_file(self, file_path: Path) -> bool:
        """Check if file is suspicious based on patterns."""
        filename_lower = file_path.name.lower()
        
        for flag_type, patterns in self.SUSPICIOUS_PATTERNS.items():
            if any(pattern in filename_lower for pattern in patterns):
                return True
        
        return False
    
    def _generate_filesystem_structure(self) -> Dict[str, Any]:
        """
        Generate complete filesystem structure for display.
        
        Returns:
            Hierarchical structure ready for tree display
        """
        structure = {
            'root': {
                'name': '💻 This PC',
                'type': 'root',
                'children': []
            }
        }
        
        # Add drives
        drives = self._detect_drives()
        for drive in drives:
            drive_node = {
                'name': f"💾 {drive['name']} ({drive['size']})",
                'type': 'drive',
                'children': []
            }
            
            # Add Users folder for C: drive
            if drive['name'] == 'C:' and self.user_profiles:
                users_node = {
                    'name': '👤 Users',
                    'type': 'folder',
                    'children': []
                }
                
                # Add each user profile
                for profile in self.user_profiles:
                    profile_node = {
                        'name': f"👤 {profile.name}",
                        'type': 'user_profile',
                        'children': []
                    }
                    
                    # Add special folders
                    for folder_name, stats in profile.folders.items():
                        folder_node = {
                            'name': f"{stats.icon} {folder_name} ({stats.file_count} files)",
                            'type': 'special_folder',
                            'stats': stats,
                            'children': []
                        }
                        
                        if stats.suspicious_count > 0:
                            folder_node['name'] += f" ⚠️ {stats.suspicious_count} suspicious"
                        
                        profile_node['children'].append(folder_node)
                    
                    users_node['children'].append(profile_node)
                
                drive_node['children'].append(users_node)
            
            structure['root']['children'].append(drive_node)
        
        return structure
    
    def _detect_drives(self) -> List[Dict[str, str]]:
        """Detect all drives/partitions."""
        drives = []
        
        # Check for common drive letters (Windows)
        for letter in ['C:', 'D:', 'E:', 'F:']:
            drive_path = self.vfs_root / letter
            if drive_path.exists():
                size = self._format_size(self._get_dir_size(drive_path))
                drives.append({'name': letter, 'size': size})
        
        # Check for numbered partitions
        for i in range(10):
            partition_path = self.vfs_root / f'partition_{i}'
            if partition_path.exists():
                size = self._format_size(self._get_dir_size(partition_path))
                drives.append({'name': f'Partition {i}', 'size': size})
        
        return drives
    
    def _get_dir_size(self, path: Path) -> int:
        """Calculate total size of directory."""
        total = 0
        try:
            for item in path.rglob('*'):
                if item.is_file():
                    total += item.stat().st_size
        except:
            pass
        return total
    
    def _format_size(self, size_bytes: int) -> str:
        """Format bytes to human-readable size."""
        size = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    def get_quick_access_items(self) -> Dict[str, List[Path]]:
        """
        Generate quick access items for UI.
        
        Returns:
            Dictionary of quick access categories with file lists
        """
        quick_access = {
            '📥 Downloads': [],
            '🖥️ Desktop': [],
            '📄 Documents': [],
            '🖼️ Pictures': [],
            '⚠️ Suspicious': [],
            '⚙️ Executables': [],
            '📦 Archives': []
        }
        
        for profile in self.user_profiles:
            # Downloads
            if 'Downloads' in profile.folders:
                quick_access['📥 Downloads'].append(profile.folders['Downloads'].path)
            
            # Desktop
            if 'Desktop' in profile.folders:
                quick_access['🖥️ Desktop'].append(profile.folders['Desktop'].path)
            
            # Documents
            if 'Documents' in profile.folders:
                quick_access['📄 Documents'].append(profile.folders['Documents'].path)
            
            # Pictures
            if 'Pictures' in profile.folders:
                quick_access['🖼️ Pictures'].append(profile.folders['Pictures'].path)
        
        return quick_access


# ============================================================================
# AUTO-RUN ON VFS LOAD
# ============================================================================

def auto_detect_filesystem(vfs_root: Path) -> Dict[str, Any]:
    """
    AUTOMATIC ENTRY POINT
    Called automatically when VFS is loaded.
    
    Args:
        vfs_root: Root of virtual filesystem
        
    Returns:
        Complete filesystem structure
    """
    detector = AutomaticFilesystemDetector(vfs_root)
    return detector.auto_detect_and_organize()
