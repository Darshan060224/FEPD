# Files Tab: Complete Filesystem View
**Goal: Transform Files tab into full file manager showing victim's complete filesystem**

## Current State
- Shows forensic artifacts in category structure
- Missing user-friendly folder organization
- No Desktop, Downloads, Documents, Pictures, etc.

## Target State
```
📂 This PC
  ├── 💻 C: (476.3 GB)
  │   ├── 👤 Users
  │   │   ├── John.Doe
  │   │   │   ├── 🖥️ Desktop
  │   │   │   │   ├── Important_Document.docx
  │   │   │   │   ├── Screenshot_2024.png
  │   │   │   │   └── Shortcut to Project.lnk
  │   │   │   ├── 📥 Downloads
  │   │   │   │   ├── malware.exe ⚠️
  │   │   │   │   ├── invoice.pdf
  │   │   │   │   └── photo.jpg
  │   │   │   ├── 📄 Documents
  │   │   │   │   ├── Work
  │   │   │   │   ├── Personal
  │   │   │   │   └── passwords.txt ⚠️
  │   │   │   ├── 🖼️ Pictures
  │   │   │   │   ├── 2024
  │   │   │   │   └── Screenshots
  │   │   │   ├── 🎵 Music
  │   │   │   ├── 🎬 Videos
  │   │   │   ├── 📁 AppData
  │   │   │   │   ├── Local
  │   │   │   │   ├── Roaming
  │   │   │   │   └── LocalLow
  │   │   │   └── 📦 OneDrive
  │   │   └── Public
  │   ├── 📂 Program Files
  │   ├── 📂 Program Files (x86)
  │   ├── 🪟 Windows
  │   │   ├── System32
  │   │   ├── Temp
  │   │   └── Prefetch
  │   └── 🗑️ $Recycle.Bin
  ├── 📀 D: (Data Drive)
  └── 💾 E: (Backup)
```

## Implementation Strategy

### Phase 1: User Profile Detection
**Automatically detect all user profiles in evidence:**

```python
class UserProfileDetector:
    """Detect Windows user profiles from filesystem."""
    
    KNOWN_FOLDERS = {
        'Desktop': '🖥️',
        'Downloads': '📥',
        'Documents': '📄',
        'Pictures': '🖼️',
        'Music': '🎵',
        'Videos': '🎬',
        'AppData': '📁',
        'OneDrive': '📦',
        'Favorites': '⭐',
        'Links': '🔗'
    }
    
    def detect_profiles(self, vfs_root) -> List[UserProfile]:
        """Scan C:/Users and detect all user profiles."""
        profiles = []
        users_path = vfs_root / "C:" / "Users"
        
        if users_path.exists():
            for user_dir in users_path.iterdir():
                if user_dir.is_dir() and user_dir.name not in ['Public', 'Default', 'All Users']:
                    profile = self._analyze_profile(user_dir)
                    profiles.append(profile)
        
        return profiles
    
    def _analyze_profile(self, user_dir) -> UserProfile:
        """Analyze user profile and detect special folders."""
        profile = UserProfile(name=user_dir.name)
        
        # Detect standard folders
        for folder_name, icon in self.KNOWN_FOLDERS.items():
            folder_path = user_dir / folder_name
            if folder_path.exists():
                stats = self._get_folder_stats(folder_path)
                profile.add_folder(folder_name, icon, stats)
        
        return profile
```

### Phase 2: Smart File Categorization
**Auto-categorize files by type with appropriate icons:**

```python
FILE_TYPE_CATEGORIES = {
    # Documents
    'Documents': {
        'extensions': ['.doc', '.docx', '.pdf', '.txt', '.xlsx', '.pptx', '.odt'],
        'icon': '📄',
        'priority': 'high'  # Show in findings
    },
    
    # Images
    'Images': {
        'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.heic'],
        'icon': '🖼️',
        'priority': 'medium'
    },
    
    # Videos
    'Videos': {
        'extensions': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv'],
        'icon': '🎬',
        'priority': 'medium'
    },
    
    # Audio
    'Audio': {
        'extensions': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a'],
        'icon': '🎵',
        'priority': 'low'
    },
    
    # Archives
    'Archives': {
        'extensions': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'],
        'icon': '📦',
        'priority': 'high'  # Could contain hidden data
    },
    
    # Executables
    'Executables': {
        'extensions': ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.jar'],
        'icon': '⚙️',
        'priority': 'critical'  # Potential malware
    },
    
    # Shortcuts
    'Shortcuts': {
        'extensions': ['.lnk', '.url'],
        'icon': '🔗',
        'priority': 'medium'  # Track user activity
    },
    
    # Databases
    'Databases': {
        'extensions': ['.db', '.sqlite', '.mdb', '.accdb'],
        'icon': '🗄️',
        'priority': 'high'  # Often contain valuable data
    }
}

def get_file_icon_and_category(filename: str) -> tuple:
    """Get appropriate icon and category for file."""
    ext = Path(filename).suffix.lower()
    
    for category, info in FILE_TYPE_CATEGORIES.items():
        if ext in info['extensions']:
            return info['icon'], category, info['priority']
    
    return '📄', 'Other', 'low'
```

### Phase 3: Suspicious File Detection
**Auto-flag suspicious files:**

```python
SUSPICIOUS_PATTERNS = {
    'passwords': ['password', 'passwd', 'pwd', 'credentials', 'creds'],
    'financial': ['bank', 'credit', 'ssn', 'tax', 'invoice'],
    'confidential': ['confidential', 'secret', 'private', 'internal'],
    'hacking': ['hack', 'crack', 'exploit', 'backdoor', 'rootkit'],
    'hidden': ['.', '~$', 'thumbs.db', 'desktop.ini'],
    'temp': ['tmp', 'temp', 'cache']
}

def detect_suspicious_files(file_path: Path) -> List[str]:
    """Detect if file is suspicious and return flags."""
    flags = []
    filename_lower = file_path.name.lower()
    
    # Check filename patterns
    for flag_type, patterns in SUSPICIOUS_PATTERNS.items():
        if any(pattern in filename_lower for pattern in patterns):
            flags.append(flag_type)
    
    # Check file size anomalies
    if file_path.stat().st_size == 0:
        flags.append('empty_file')
    elif file_path.stat().st_size > 1_000_000_000:  # >1GB
        flags.append('large_file')
    
    # Check hidden attribute
    if file_path.name.startswith('.'):
        flags.append('hidden')
    
    return flags
```

### Phase 4: Enhanced Tree View
**Multi-panel file explorer:**

```python
class EnhancedFilesTab(QWidget):
    """Complete filesystem view with explorer-like interface."""
    
    def _init_ui(self):
        # Main layout: 3 panels
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # LEFT: Folder tree (like Windows Explorer)
        self.folder_tree = self._create_folder_tree()
        
        # MIDDLE: File list (details view)
        self.file_list = self._create_file_list()
        
        # RIGHT: Preview pane
        self.preview_pane = self._create_preview_pane()
        
        splitter.addWidget(self.folder_tree)
        splitter.addWidget(self.file_list)
        splitter.addWidget(self.preview_pane)
        splitter.setSizes([250, 500, 250])
    
    def _create_folder_tree(self) -> QTreeWidget:
        """Create Windows Explorer-style folder tree."""
        tree = QTreeWidget()
        tree.setHeaderLabel("📂 Filesystem")
        tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        
        # Root: This PC
        root = QTreeWidgetItem(tree, ["💻 This PC"])
        
        # Auto-populate drives
        for drive in self.detected_drives:
            drive_item = QTreeWidgetItem(root, [f"💾 {drive['name']} ({drive['size']})"])
            
            # Add user profiles
            if drive['name'] == 'C:':
                users = QTreeWidgetItem(drive_item, ["👤 Users"])
                for profile in self.user_profiles:
                    profile_item = QTreeWidgetItem(users, [f"👤 {profile.name}"])
                    
                    # Add special folders
                    for folder in profile.folders:
                        QTreeWidgetItem(profile_item, [f"{folder.icon} {folder.name}"])
        
        tree.expandAll()
        return tree
    
    def _create_file_list(self) -> QTableWidget:
        """Create file list with columns."""
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels([
            "Name", "Type", "Size", "Modified", "Path", "Flags", "Hash"
        ])
        
        # Enable sorting
        table.setSortingEnabled(True)
        
        # Double-click to preview
        table.cellDoubleClicked.connect(self._preview_file)
        
        return table
```

### Phase 5: Quick Access & Filters
**Add quick access for common investigative needs:**

```python
class QuickAccessPanel(QWidget):
    """Quick access to important file locations."""
    
    QUICK_ACCESS = {
        '🔍 Recent Files': lambda: self._show_recent_files(),
        '📥 Downloads': lambda: self._show_downloads(),
        '🖥️ Desktop': lambda: self._show_desktop(),
        '⚠️ Suspicious Files': lambda: self._show_suspicious(),
        '⚙️ Executables': lambda: self._show_executables(),
        '📄 Documents': lambda: self._show_documents(),
        '🖼️ Pictures': lambda: self._show_pictures(),
        '🗑️ Recycle Bin': lambda: self._show_recycle_bin(),
        '📦 Archives': lambda: self._show_archives(),
        '🔐 Encrypted': lambda: self._show_encrypted()
    }
    
    def _show_suspicious(self):
        """Filter to suspicious files only."""
        self.file_list.clear()
        
        for file in self.all_files:
            if file.flags:  # Has suspicious flags
                self._add_file_to_list(file, highlight=True)
```

## Implementation Checklist

✅ Phase 1: User Profile Detection
  - Scan C:/Users for all profiles
  - Detect Desktop, Downloads, Documents, Pictures, Music, Videos
  - Map AppData, OneDrive, Favorites
  - Count files in each folder

✅ Phase 2: File Categorization
  - Auto-categorize by extension
  - Assign appropriate icons
  - Set priority levels

✅ Phase 3: Suspicious Detection
  - Flag password files
  - Flag executables
  - Flag hidden files
  - Flag large files

✅ Phase 4: Enhanced UI
  - Three-panel layout (tree, list, preview)
  - Windows Explorer-style navigation
  - Sortable columns
  - Context menus

✅ Phase 5: Quick Access
  - Recent files button
  - Downloads folder button
  - Suspicious files filter
  - Executables filter

## Expected Result

### Before:
```
Files Tab:
  - Forensic artifacts listed
  - No user context
  - Hard to navigate
```

### After:
```
Files Tab:
  💻 This PC
    └── 💾 C: (476.3 GB)
        └── 👤 Users
            └── 👤 John.Doe
                ├── 🖥️ Desktop (15 files)
                ├── 📥 Downloads (47 files) ⚠️ 3 suspicious
                ├── 📄 Documents (234 files)
                ├── 🖼️ Pictures (1,247 files)
                └── 📁 AppData (8,542 files)

[Quick Access Bar]
[🔍 Recent] [📥 Downloads] [⚠️ Suspicious] [⚙️ Executables]

[File List - Details View]
Name                Type        Size      Modified      Flags
malware.exe        ⚙️ EXE      1.2 MB    2024-01-15    ⚠️ suspicious
passwords.txt      📄 TXT      8 KB      2024-01-20    ⚠️ passwords
hack_tools.zip     📦 ZIP      45 MB     2024-01-18    ⚠️ suspicious
```

## Performance Considerations
- Lazy loading: Only load visible folders
- Virtual scrolling: Handle 100K+ files
- Background indexing: Build search index
- Caching: Remember expanded folders
- Thumbnails: Generate on-demand

## Integration Points
- Artifacts tab: Link to extracted artifacts
- Timeline: Show file access timeline
- ML Analytics: Feed file metadata
- Reports: Include file inventory
