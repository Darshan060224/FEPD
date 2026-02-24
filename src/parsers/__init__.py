"""
FEPD - Forensic Evidence Parser Dashboard
Parser Modules Package

This package contains specialized forensic artifact parsers:
- EVTX Parser: Windows Event Logs
- Registry Parser: Windows Registry Hives
- Prefetch Parser: Windows Prefetch Files
- MFT Parser: NTFS Master File Table
- Browser Parser: Browser History Databases
- macOS Parser: macOS forensic artifacts
- Linux Parser: Linux forensic artifacts
- Mobile Parser: Android/iOS forensic artifacts (NEW)

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

from .evtx_parser import EVTXParser
from .registry_parser import RegistryParser
from .prefetch_parser import PrefetchParser
from .mft_parser import MFTParser
from .browser_parser import BrowserParser
from .macos_parser import MacOSParser
from .linux_parser import LinuxParser
from .mobile_parser import MobileParser

__all__ = [
    'EVTXParser',
    'RegistryParser',
    'PrefetchParser',
    'MFTParser',
    'BrowserParser',
    'MacOSParser',
    'LinuxParser',
    'MobileParser'
]
