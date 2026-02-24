"""
FEPD Windows Forensic Paths Knowledge Base
============================================

Complete mapping of all forensically relevant Windows paths.
This module provides comprehensive path definitions for:
- Evidence location in forensic investigations
- File Manager reconstruction in the Files Tab
- Artifact classification and categorization

Based on Windows 10/11 filesystem structure with backward compatibility.

Path Categories:
1. Core OS Paths - System essentials
2. User Data Paths - Per-user artifacts
3. Security & Logs - Audit/event evidence
4. Application Data - Installed app artifacts
5. Volatile Data - Temp/cache locations
6. Recovery/System - Restore points & system data
7. Mobile/Virtualization - Container paths

Copyright (c) 2026 FEPD Development Team
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from enum import Enum


class PathCategory(Enum):
    """Categories of forensic paths."""
    CORE_OS = "core_os"
    USER_DATA = "user_data"
    SECURITY_LOGS = "security_logs"
    APP_DATA = "app_data"
    VOLATILE = "volatile"
    RECOVERY = "recovery"
    MOBILE = "mobile"
    NETWORK = "network"
    PERSISTENCE = "persistence"
    EVIDENCE = "evidence"


class ForensicRelevance(Enum):
    """Forensic relevance level."""
    CRITICAL = "critical"       # Must examine in any investigation
    HIGH = "high"              # Important for most investigations
    MEDIUM = "medium"          # Useful for specific cases
    LOW = "low"                # Background/supporting evidence
    VARIABLE = "variable"      # Depends on investigation type


@dataclass
class ForensicPath:
    """Represents a forensically relevant Windows path."""
    path: str                           # The actual path pattern
    description: str                    # What this path contains
    category: PathCategory              # Category of path
    relevance: ForensicRelevance        # How important for investigations
    artifacts: List[str] = field(default_factory=list)  # Specific artifacts found here
    evidence_types: List[str] = field(default_factory=list)  # Types of evidence
    notes: str = ""                     # Additional investigator notes


# =============================================================================
# CORE WINDOWS PATHS - The mandatory skeleton every Windows system has
# =============================================================================

CORE_OS_PATHS = [
    # Root Drive Structure
    ForensicPath(
        path="C:\\",
        description="Primary system drive root",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["boot files", "pagefile.sys", "hiberfil.sys", "swapfile.sys"],
        evidence_types=["system", "hibernation", "memory"],
        notes="Root may contain encrypted volumes, look for BitLocker metadata"
    ),
    
    # Windows Directory Tree
    ForensicPath(
        path="C:\\Windows\\",
        description="Windows Operating System core directory",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["ntoskrnl.exe", "explorer.exe", "win.ini", "system.ini"],
        evidence_types=["os_config", "kernel"],
        notes="The OS brain - kernel, drivers, system binaries"
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\",
        description="Core system executables and DLLs (64-bit)",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["cmd.exe", "powershell.exe", "notepad.exe", "calc.exe", "svchost.exe"],
        evidence_types=["executables", "system_binaries"],
        notes="Watch for DLL hijacking, malicious replacements"
    ),
    ForensicPath(
        path="C:\\Windows\\SysWOW64\\",
        description="32-bit system files on 64-bit Windows",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.HIGH,
        artifacts=["cmd.exe", "notepad.exe"],
        evidence_types=["executables", "compatibility"],
        notes="32-bit malware may target this directory"
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\drivers\\",
        description="Kernel-mode drivers",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["*.sys", "etc\\hosts"],
        evidence_types=["drivers", "rootkits"],
        notes="Rootkits hide here - check driver signatures"
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\config\\",
        description="Registry hive files",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["SAM", "SYSTEM", "SOFTWARE", "SECURITY", "DEFAULT"],
        evidence_types=["registry", "credentials", "configuration"],
        notes="Contains user credentials, system config, installed software"
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\Tasks\\",
        description="Scheduled Task definitions",
        category=PathCategory.PERSISTENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["*.xml"],
        evidence_types=["persistence", "scheduled_tasks"],
        notes="Common malware persistence mechanism"
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\wbem\\",
        description="WMI Repository",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Repository\\OBJECTS.DATA", "Logs\\"],
        evidence_types=["wmi", "persistence"],
        notes="WMI event subscriptions used for fileless malware"
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\spool\\",
        description="Print Spooler service data",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["PRINTERS\\", "drivers\\"],
        evidence_types=["print_jobs", "documents"],
        notes="May contain printed document metadata"
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\LogFiles\\",
        description="System log files",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Firewall\\", "HTTPERR\\", "WMI\\", "Sum\\"],
        evidence_types=["logs", "firewall", "network"],
        notes="Firewall logs, IIS logs, WMI logs"
    ),
    
    # Windows Subsystem Directories
    ForensicPath(
        path="C:\\Windows\\WinSxS\\",
        description="Windows Side-by-Side assembly cache",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.LOW,
        artifacts=["manifests\\", "*.dll", "*.exe"],
        evidence_types=["system_files", "dlls"],
        notes="Component store - can be very large"
    ),
    ForensicPath(
        path="C:\\Windows\\Temp\\",
        description="System-wide temporary files",
        category=PathCategory.VOLATILE,
        relevance=ForensicRelevance.HIGH,
        artifacts=["*.tmp", "*.log", "installer files"],
        evidence_types=["temp_files", "malware_drops"],
        notes="Malware often drops payloads here first"
    ),
    ForensicPath(
        path="C:\\Windows\\Prefetch\\",
        description="Application prefetch cache",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["*.pf"],
        evidence_types=["execution_evidence", "timeline"],
        notes="CRITICAL: Shows what programs ran and when (last 128)"
    ),
    ForensicPath(
        path="C:\\Windows\\INF\\",
        description="Driver installation files",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["*.inf", "setupapi.dev.log"],
        evidence_types=["drivers", "usb_history"],
        notes="setupapi logs show device installation history"
    ),
    ForensicPath(
        path="C:\\Windows\\Fonts\\",
        description="System fonts directory",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.LOW,
        artifacts=["*.ttf", "*.otf"],
        evidence_types=["system_files"],
        notes="Can hide malicious executables with font extension"
    ),
    ForensicPath(
        path="C:\\Windows\\SoftwareDistribution\\",
        description="Windows Update data",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["Download\\", "DataStore\\"],
        evidence_types=["updates", "system_changes"],
        notes="Track system update history"
    ),
    ForensicPath(
        path="C:\\Windows\\SoftwareDistribution\\Download\\",
        description="Downloaded Windows updates",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["*.cab", "*.msu"],
        evidence_types=["updates"],
    ),
    ForensicPath(
        path="C:\\Windows\\SoftwareDistribution\\DataStore\\",
        description="Windows Update database",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["DataStore.edb", "Logs\\"],
        evidence_types=["updates", "database"],
    ),
    ForensicPath(
        path="C:\\Windows\\servicing\\",
        description="Windows servicing data",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.LOW,
        artifacts=["Sessions\\", "Packages\\"],
        evidence_types=["system_changes"],
    ),
    ForensicPath(
        path="C:\\Windows\\Logs\\",
        description="Windows log directory",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.HIGH,
        artifacts=["CBS\\", "DISM\\", "MoSetup\\", "WindowsUpdate\\"],
        evidence_types=["logs", "system_changes"],
        notes="Detailed logs for CBS, DISM, Windows Update"
    ),
    ForensicPath(
        path="C:\\Windows\\Logs\\CBS\\",
        description="Component Based Servicing logs",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["CBS.log", "CbsPersist_*.log"],
        evidence_types=["logs"],
    ),
    ForensicPath(
        path="C:\\Windows\\Logs\\DISM\\",
        description="DISM operation logs",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["dism.log"],
        evidence_types=["logs", "image_servicing"],
    ),
    ForensicPath(
        path="C:\\Windows\\PolicyDefinitions\\",
        description="Group Policy definitions",
        category=PathCategory.CORE_OS,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["*.admx", "*.adml"],
        evidence_types=["policy"],
        notes="Custom policies may indicate enterprise or attack tools"
    ),
    ForensicPath(
        path="C:\\Windows\\debug\\",
        description="Debug logs directory",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["PASSWD.LOG", "NetSetup.LOG", "dcpromo.log"],
        evidence_types=["logs", "authentication"],
        notes="PASSWD.LOG contains password change events!"
    ),
    ForensicPath(
        path="C:\\Windows\\AppCompat\\",
        description="Application Compatibility database",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Programs\\", "Appraiser\\"],
        evidence_types=["execution_evidence"],
        notes="AmCache.hve contains execution artifacts"
    ),
    ForensicPath(
        path="C:\\Windows\\AppCompat\\Programs\\",
        description="RecentFileCache and AmCache",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["Amcache.hve", "RecentFileCache.bcf"],
        evidence_types=["execution_evidence", "registry"],
        notes="CRITICAL: Amcache tracks all executed programs with SHA1"
    ),
    
    # Program Files
    ForensicPath(
        path="C:\\Program Files\\",
        description="64-bit installed applications",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["application folders"],
        evidence_types=["installed_software"],
        notes="Legitimate software installation location"
    ),
    ForensicPath(
        path="C:\\Program Files (x86)\\",
        description="32-bit installed applications",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["application folders"],
        evidence_types=["installed_software"],
        notes="Legacy 32-bit applications"
    ),
    
    # ProgramData
    ForensicPath(
        path="C:\\ProgramData\\",
        description="Shared application data (hidden)",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Microsoft\\", "application folders"],
        evidence_types=["app_data", "configuration"],
        notes="Often overlooked - contains app databases and configs"
    ),
    ForensicPath(
        path="C:\\ProgramData\\Microsoft\\",
        description="Microsoft shared data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Windows Defender\\", "Search\\", "RAC\\"],
        evidence_types=["antivirus", "search", "reliability"],
    ),
    ForensicPath(
        path="C:\\ProgramData\\Microsoft\\Windows Defender\\",
        description="Windows Defender data",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Scans\\", "Support\\", "Quarantine\\"],
        evidence_types=["antivirus", "malware_detections"],
        notes="Check quarantine for malware samples!"
    ),
    
    # System Recovery
    ForensicPath(
        path="C:\\System Volume Information\\",
        description="System restore and VSS data",
        category=PathCategory.RECOVERY,
        relevance=ForensicRelevance.HIGH,
        artifacts=["SPP\\", "{GUID}\\"],
        evidence_types=["restore_points", "shadow_copies"],
        notes="Contains shadow copies - historical file versions"
    ),
    ForensicPath(
        path="C:\\$Recycle.Bin\\",
        description="Recycle Bin (per-user SIDs)",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["$I* (metadata)", "$R* (data)"],
        evidence_types=["deleted_files"],
        notes="CRITICAL: Contains deleted file metadata and content"
    ),
    
    # Performance Logs
    ForensicPath(
        path="C:\\PerfLogs\\",
        description="Performance monitoring logs",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.LOW,
        artifacts=["*.blg", "*.csv"],
        evidence_types=["performance"],
    ),
]


# =============================================================================
# USER DATA PATHS - Per-user artifacts (replace <username> at runtime)
# =============================================================================

USER_DATA_PATHS = [
    # User Profile Root
    ForensicPath(
        path="C:\\Users\\",
        description="User profiles root directory",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["user folders"],
        evidence_types=["user_data"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\",
        description="Individual user profile root",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["NTUSER.DAT", "desktop.ini"],
        evidence_types=["user_profile", "registry"],
        notes="NTUSER.DAT is the user's registry hive"
    ),
    
    # Standard User Folders
    ForensicPath(
        path="C:\\Users\\<username>\\Desktop\\",
        description="User desktop files",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["shortcuts", "documents", "files"],
        evidence_types=["user_files"],
        notes="User's most visible workspace"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Documents\\",
        description="User documents folder",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["*.doc", "*.pdf", "*.txt"],
        evidence_types=["documents"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Downloads\\",
        description="Browser and app downloads",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["downloaded files", "installers"],
        evidence_types=["downloads", "malware_entry"],
        notes="CRITICAL: Common malware entry point"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Pictures\\",
        description="User pictures",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["*.jpg", "*.png", "Screenshots\\"],
        evidence_types=["images"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Pictures\\Screenshots\\",
        description="Windows screenshots",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["Screenshot *.png"],
        evidence_types=["images", "screenshots"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Videos\\",
        description="User videos",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["*.mp4", "*.avi", "Captures\\"],
        evidence_types=["videos"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Music\\",
        description="User music files",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.LOW,
        artifacts=["*.mp3", "*.wav"],
        evidence_types=["audio"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Contacts\\",
        description="Windows contacts",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["*.contact"],
        evidence_types=["contacts"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Favorites\\",
        description="Internet Explorer favorites",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["*.url"],
        evidence_types=["bookmarks"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Links\\",
        description="Quick access links",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.LOW,
        artifacts=["*.lnk"],
        evidence_types=["shortcuts"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Saved Games\\",
        description="Saved game data",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.LOW,
        artifacts=["game save files"],
        evidence_types=["game_data"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Searches\\",
        description="Saved Windows searches",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["*.search-ms"],
        evidence_types=["searches"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\OneDrive\\",
        description="OneDrive sync folder",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["synced files"],
        evidence_types=["cloud_storage"],
        notes="Cloud-synced files may have additional online history"
    ),
    
    # AppData - The Hidden Goldmine
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\",
        description="Application data root (hidden)",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["Local\\", "Roaming\\", "LocalLow\\"],
        evidence_types=["app_data"],
        notes="CRITICAL: Contains most user-specific artifacts"
    ),
    
    # AppData\Local - Machine-bound data
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\",
        description="Local application data (machine-bound)",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["Temp\\", "Microsoft\\", "application folders"],
        evidence_types=["app_data", "cache"],
        notes="Contains caches, databases, temporary data"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Temp\\",
        description="User temporary files",
        category=PathCategory.VOLATILE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["*.tmp", "malware drops"],
        evidence_types=["temp_files", "malware"],
        notes="CRITICAL: Malware staging area"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Microsoft\\",
        description="Microsoft app data (Local)",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Windows\\", "Office\\", "Edge\\", "Outlook\\"],
        evidence_types=["microsoft_apps"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\",
        description="Windows user data",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["Explorer\\", "UsrClass.dat", "WebCache\\", "Notifications\\"],
        evidence_types=["windows_artifacts"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\Explorer\\",
        description="Windows Explorer data",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["thumbcache_*.db", "iconcache_*.db"],
        evidence_types=["thumbnails", "icons"],
        notes="CRITICAL: Thumbnail cache shows viewed images"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\WebCache\\",
        description="IE/Edge WebCache database",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["WebCacheV01.dat"],
        evidence_types=["browser_history", "cache"],
        notes="CRITICAL: Contains IE/Edge browsing history"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\INetCache\\",
        description="Internet cache files",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.HIGH,
        artifacts=["IE\\", "Low\\"],
        evidence_types=["browser_cache"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\History\\",
        description="Internet history",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.HIGH,
        artifacts=["History.IE5\\"],
        evidence_types=["browser_history"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\Notifications\\",
        description="Windows notification database",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["wpndatabase.db"],
        evidence_types=["notifications"],
        notes="Contains recent notification history"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",
        description="User class registration hive",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["UsrClass.dat"],
        evidence_types=["registry", "shellbags"],
        notes="CRITICAL: Contains ShellBags - folder access history"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\ConnectedDevicesPlatform\\",
        description="Connected devices history",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["*.db"],
        evidence_types=["devices", "timeline"],
    ),
    
    # AppData\Roaming - Profile-synced data
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\",
        description="Roaming application data (profile-synced)",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["Microsoft\\", "application folders"],
        evidence_types=["app_data"],
        notes="Syncs across domain computers"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\",
        description="Microsoft roaming data",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Windows\\", "Office\\", "Outlook\\", "Credentials\\"],
        evidence_types=["microsoft_apps"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\",
        description="Windows roaming data",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["Recent\\", "Start Menu\\", "SendTo\\", "PowerShell\\"],
        evidence_types=["windows_artifacts"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\",
        description="Recent files list",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["*.lnk", "AutomaticDestinations\\", "CustomDestinations\\"],
        evidence_types=["recent_files", "lnk_files", "jump_lists"],
        notes="CRITICAL: Contains LNK files and Jump Lists"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\",
        description="Automatic Jump Lists",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["*.automaticDestinations-ms"],
        evidence_types=["jump_lists"],
        notes="CRITICAL: Shows recently used files per application"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\",
        description="Custom/Pinned Jump Lists",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["*.customDestinations-ms"],
        evidence_types=["jump_lists"],
        notes="User-pinned items in taskbar apps"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\",
        description="Start menu shortcuts",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["Programs\\", "*.lnk"],
        evidence_types=["shortcuts"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
        description="User startup programs",
        category=PathCategory.PERSISTENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["*.lnk", "*.exe", "*.bat"],
        evidence_types=["persistence", "autostart"],
        notes="CRITICAL: Common malware persistence location"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\",
        description="PowerShell user data",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.HIGH,
        artifacts=["PSReadLine\\ConsoleHost_history.txt"],
        evidence_types=["command_history"],
        notes="Contains PowerShell command history!"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Credentials\\",
        description="Windows Credential Manager",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.HIGH,
        artifacts=["encrypted credential files"],
        evidence_types=["credentials"],
        notes="Encrypted credentials for web and network"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Protect\\",
        description="DPAPI Master Keys",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.HIGH,
        artifacts=["master key files"],
        evidence_types=["encryption_keys"],
        notes="Needed to decrypt credentials"
    ),
    
    # AppData\LocalLow - Sandbox/Low-integrity apps
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\LocalLow\\",
        description="Low-integrity application data",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["Microsoft\\", "browser data"],
        evidence_types=["app_data", "sandbox"],
        notes="Used by sandboxed apps (browsers, games)"
    ),
]


# =============================================================================
# BROWSER PATHS - Web browsing artifacts
# =============================================================================

BROWSER_PATHS = [
    # Google Chrome
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Google\\Chrome\\",
        description="Google Chrome data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["User Data\\"],
        evidence_types=["browser"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Google\\Chrome\\User Data\\",
        description="Chrome profiles root",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["Default\\", "Profile *\\", "Local State"],
        evidence_types=["browser"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\",
        description="Chrome default profile",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=[
            "History", "Cookies", "Web Data", "Login Data", "Bookmarks",
            "Favicons", "Top Sites", "Visited Links", "Preferences",
            "Extensions\\", "Local Storage\\", "Session Storage\\",
            "Cache\\", "Code Cache\\", "GPUCache\\"
        ],
        evidence_types=["browser_history", "cookies", "passwords", "bookmarks"],
        notes="CRITICAL: Complete browser forensic artifacts"
    ),
    
    # Microsoft Edge (Chromium)
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Edge\\",
        description="Microsoft Edge data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["User Data\\"],
        evidence_types=["browser"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\",
        description="Edge default profile",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["History", "Cookies", "Web Data", "Login Data", "Bookmarks"],
        evidence_types=["browser_history", "cookies", "passwords"],
    ),
    
    # Mozilla Firefox
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Mozilla\\Firefox\\",
        description="Firefox data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["Profiles\\", "profiles.ini"],
        evidence_types=["browser"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\",
        description="Firefox profiles",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=[
            "places.sqlite", "cookies.sqlite", "formhistory.sqlite",
            "logins.json", "key4.db", "cert9.db", "sessionstore.jsonlz4"
        ],
        evidence_types=["browser_history", "cookies", "passwords"],
        notes="places.sqlite contains history and bookmarks"
    ),
]


# =============================================================================
# EVENT LOGS - Windows Event Logs
# =============================================================================

EVENT_LOG_PATHS = [
    ForensicPath(
        path="C:\\Windows\\System32\\winevt\\",
        description="Windows Event Log root",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["Logs\\"],
        evidence_types=["event_logs"],
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\winevt\\Logs\\",
        description="Event log files (.evtx)",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=[
            "Security.evtx", "System.evtx", "Application.evtx",
            "Setup.evtx", "Microsoft-Windows-PowerShell%4Operational.evtx",
            "Microsoft-Windows-Sysmon%4Operational.evtx",
            "Microsoft-Windows-TaskScheduler%4Operational.evtx",
            "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
            "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
            "Microsoft-Windows-WMI-Activity%4Operational.evtx"
        ],
        evidence_types=["event_logs", "security", "authentication", "execution"],
        notes="CRITICAL: Primary source of security events"
    ),
    # Individual important logs
    ForensicPath(
        path="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
        description="Security Event Log",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["Security.evtx"],
        evidence_types=["authentication", "access_control", "audit"],
        notes="Login events (4624,4625), privilege use, object access"
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
        description="System Event Log",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["System.evtx"],
        evidence_types=["system_events", "drivers", "services"],
        notes="Service changes, driver loads, boot events"
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
        description="Application Event Log",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Application.evtx"],
        evidence_types=["application_events", "crashes"],
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
        description="PowerShell Operational Log",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["PowerShell log"],
        evidence_types=["command_execution", "scripts"],
        notes="CRITICAL: PowerShell script execution (ID 4104)"
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
        description="Sysmon Event Log",
        category=PathCategory.SECURITY_LOGS,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["Sysmon log"],
        evidence_types=["process_creation", "network", "file_changes"],
        notes="If Sysmon installed - comprehensive logging"
    ),
]


# =============================================================================
# EMAIL CLIENT PATHS
# =============================================================================

EMAIL_PATHS = [
    # Microsoft Outlook
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Outlook\\",
        description="Outlook data files",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["*.ost"],
        evidence_types=["email", "offline_cache"],
        notes="OST files for Exchange accounts"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Documents\\Outlook Files\\",
        description="Outlook PST files",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["*.pst"],
        evidence_types=["email", "archive"],
        notes="Local email archives"
    ),
    # Thunderbird
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Thunderbird\\Profiles\\",
        description="Thunderbird profiles",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["*.default\\", "Mail\\"],
        evidence_types=["email"],
    ),
]


# =============================================================================
# MESSAGING & COMMUNICATION APPS
# =============================================================================

MESSAGING_PATHS = [
    # Discord
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\discord\\",
        description="Discord data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Local Storage\\", "Cache\\", "Code Cache\\"],
        evidence_types=["messaging", "cache"],
    ),
    # Slack
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Slack\\",
        description="Slack data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Local Storage\\", "Cache\\"],
        evidence_types=["messaging"],
    ),
    # Teams
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Teams\\",
        description="Microsoft Teams data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Cache\\", "databases\\", "Local Storage\\"],
        evidence_types=["messaging", "meetings"],
    ),
    # Skype
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Skype\\",
        description="Skype data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["main.db", "*.sqlite"],
        evidence_types=["messaging", "calls"],
    ),
    # Telegram
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Telegram Desktop\\",
        description="Telegram Desktop data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["tdata\\"],
        evidence_types=["messaging"],
    ),
    # WhatsApp
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\WhatsApp\\",
        description="WhatsApp Desktop data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["app-*\\", "databases\\"],
        evidence_types=["messaging"],
    ),
]


# =============================================================================
# CLOUD STORAGE PATHS
# =============================================================================

CLOUD_STORAGE_PATHS = [
    # Dropbox
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Dropbox\\",
        description="Dropbox application data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["instance*\\", "host.db", "filecache.db"],
        evidence_types=["cloud_sync", "file_history"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Dropbox\\",
        description="Dropbox sync folder",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["synced files"],
        evidence_types=["cloud_storage"],
    ),
    # Google Drive
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Google\\DriveFS\\",
        description="Google Drive data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["*.db", "content_cache\\"],
        evidence_types=["cloud_sync"],
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\Google Drive\\",
        description="Google Drive sync folder",
        category=PathCategory.USER_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["synced files"],
        evidence_types=["cloud_storage"],
    ),
    # Box
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Box\\",
        description="Box application data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["Box Sync\\"],
        evidence_types=["cloud_sync"],
    ),
    # iCloud
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\Apple Inc\\iCloud\\",
        description="iCloud data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["iCloudDrive\\"],
        evidence_types=["cloud_sync"],
    ),
]


# =============================================================================
# REMOTE ACCESS TOOLS
# =============================================================================

REMOTE_ACCESS_PATHS = [
    # RDP
    ForensicPath(
        path="C:\\Users\\<username>\\Documents\\Default.rdp",
        description="Default RDP connection file",
        category=PathCategory.NETWORK,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Default.rdp"],
        evidence_types=["remote_access"],
        notes="Contains recent RDP connection settings"
    ),
    # TeamViewer
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\TeamViewer\\",
        description="TeamViewer data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["Connections*.txt", "*.log"],
        evidence_types=["remote_access"],
        notes="Connection logs and history"
    ),
    ForensicPath(
        path="C:\\Program Files (x86)\\TeamViewer\\",
        description="TeamViewer installation",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["TeamViewer*_Logfile.log"],
        evidence_types=["remote_access"],
    ),
    # AnyDesk
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\AnyDesk\\",
        description="AnyDesk data",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.HIGH,
        artifacts=["*.trace", "connection_trace.txt"],
        evidence_types=["remote_access"],
    ),
    # PuTTY
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Local\\SimonTatham\\PuTTY\\",
        description="PuTTY configuration",
        category=PathCategory.APP_DATA,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["sessions\\"],
        evidence_types=["ssh_connections"],
        notes="SSH session configurations - check registry too"
    ),
]


# =============================================================================
# PERSISTENCE LOCATIONS - Autostart mechanisms
# =============================================================================

PERSISTENCE_PATHS = [
    ForensicPath(
        path="C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\",
        description="All Users Startup folder",
        category=PathCategory.PERSISTENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["*.lnk", "*.exe", "*.bat", "*.vbs"],
        evidence_types=["persistence", "autostart"],
        notes="CRITICAL: Programs here run for all users at login"
    ),
    ForensicPath(
        path="C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
        description="User Startup folder",
        category=PathCategory.PERSISTENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["*.lnk", "*.exe", "*.bat", "*.vbs"],
        evidence_types=["persistence", "autostart"],
        notes="CRITICAL: User-specific autostart"
    ),
    # Note: Registry Run keys checked via registry analysis, not filesystem
]


# =============================================================================
# USB/REMOVABLE MEDIA ARTIFACTS
# =============================================================================

USB_PATHS = [
    ForensicPath(
        path="C:\\Windows\\INF\\setupapi.dev.log",
        description="Device installation log",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["setupapi.dev.log"],
        evidence_types=["usb_history", "devices"],
        notes="CRITICAL: Complete USB device connection history"
    ),
    ForensicPath(
        path="C:\\Windows\\System32\\LogFiles\\WUDF\\",
        description="User-mode driver framework logs",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["*.log"],
        evidence_types=["devices"],
    ),
]


# =============================================================================
# NTFS SPECIAL FILES
# =============================================================================

NTFS_PATHS = [
    ForensicPath(
        path="C:\\$MFT",
        description="Master File Table",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["$MFT"],
        evidence_types=["filesystem", "file_metadata"],
        notes="CRITICAL: Contains all file metadata, timestamps, resident data"
    ),
    ForensicPath(
        path="C:\\$LogFile",
        description="NTFS Journal",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.HIGH,
        artifacts=["$LogFile"],
        evidence_types=["filesystem", "changes"],
        notes="Recent filesystem changes"
    ),
    ForensicPath(
        path="C:\\$UsnJrnl",
        description="USN Change Journal",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["$J", "$Max"],
        evidence_types=["filesystem", "file_changes"],
        notes="CRITICAL: Detailed file change history"
    ),
    ForensicPath(
        path="C:\\$Extend\\$UsnJrnl",
        description="USN Journal location",
        category=PathCategory.EVIDENCE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["$J"],
        evidence_types=["filesystem", "changes"],
    ),
    ForensicPath(
        path="C:\\pagefile.sys",
        description="Windows Page File",
        category=PathCategory.VOLATILE,
        relevance=ForensicRelevance.HIGH,
        artifacts=["pagefile.sys"],
        evidence_types=["memory", "volatile"],
        notes="May contain memory artifacts, passwords, encryption keys"
    ),
    ForensicPath(
        path="C:\\hiberfil.sys",
        description="Hibernation File",
        category=PathCategory.VOLATILE,
        relevance=ForensicRelevance.CRITICAL,
        artifacts=["hiberfil.sys"],
        evidence_types=["memory", "hibernation"],
        notes="CRITICAL: Complete memory snapshot at hibernation"
    ),
    ForensicPath(
        path="C:\\swapfile.sys",
        description="Modern Apps Swap File",
        category=PathCategory.VOLATILE,
        relevance=ForensicRelevance.MEDIUM,
        artifacts=["swapfile.sys"],
        evidence_types=["memory"],
        notes="UWP app memory swapping"
    ),
]


# =============================================================================
# COMBINED PATH DATABASE
# =============================================================================

ALL_FORENSIC_PATHS: List[ForensicPath] = (
    CORE_OS_PATHS +
    USER_DATA_PATHS +
    BROWSER_PATHS +
    EVENT_LOG_PATHS +
    EMAIL_PATHS +
    MESSAGING_PATHS +
    CLOUD_STORAGE_PATHS +
    REMOTE_ACCESS_PATHS +
    PERSISTENCE_PATHS +
    USB_PATHS +
    NTFS_PATHS
)


def get_paths_by_category(category: PathCategory) -> List[ForensicPath]:
    """Get all paths in a specific category."""
    return [p for p in ALL_FORENSIC_PATHS if p.category == category]


def get_critical_paths() -> List[ForensicPath]:
    """Get all critical forensic paths (must examine)."""
    return [p for p in ALL_FORENSIC_PATHS if p.relevance == ForensicRelevance.CRITICAL]


def get_paths_for_user(username: str) -> List[ForensicPath]:
    """Get all paths with username substituted."""
    result = []
    for p in ALL_FORENSIC_PATHS:
        new_path = ForensicPath(
            path=p.path.replace("<username>", username),
            description=p.description,
            category=p.category,
            relevance=p.relevance,
            artifacts=p.artifacts.copy(),
            evidence_types=p.evidence_types.copy(),
            notes=p.notes
        )
        result.append(new_path)
    return result


def search_paths(keyword: str) -> List[ForensicPath]:
    """Search paths by keyword in path, description, or notes."""
    keyword = keyword.lower()
    return [
        p for p in ALL_FORENSIC_PATHS
        if (keyword in p.path.lower() or 
            keyword in p.description.lower() or 
            keyword in p.notes.lower() or
            any(keyword in a.lower() for a in p.artifacts))
    ]


# =============================================================================
# PATH TREE BUILDER FOR UI
# =============================================================================

def build_path_tree() -> Dict[str, Any]:
    """
    Build a hierarchical tree structure from all forensic paths.
    Used by Files Tab to show forensically-aware folder structure.
    """
    tree = {}
    
    for fp in ALL_FORENSIC_PATHS:
        parts = fp.path.replace("\\", "/").strip("/").split("/")
        current = tree
        
        for i, part in enumerate(parts):
            if part not in current:
                current[part] = {
                    "_info": {
                        "is_leaf": i == len(parts) - 1,
                        "forensic_path": fp if i == len(parts) - 1 else None
                    },
                    "_children": {}
                }
            current = current[part]["_children"]
    
    return tree


# Export summary count
TOTAL_FORENSIC_PATHS = len(ALL_FORENSIC_PATHS)
CRITICAL_PATH_COUNT = len(get_critical_paths())

if __name__ == "__main__":
    print(f"Total Forensic Paths Defined: {TOTAL_FORENSIC_PATHS}")
    print(f"Critical Paths: {CRITICAL_PATH_COUNT}")
    print("\nCategories:")
    for cat in PathCategory:
        count = len(get_paths_by_category(cat))
        print(f"  {cat.value}: {count}")
    
    print("\nCritical Paths:")
    for p in get_critical_paths():
        print(f"  - {p.path}")
