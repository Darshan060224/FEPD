"""
FEPD - Forensic Evidence Parser Dashboard
Registry Parser Module

Parses Windows Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT) using python-registry.
Extracts keys, values, modification timestamps for forensic analysis.

Implements FR-11: Parse Registry hives (SYSTEM/SOFTWARE/SAM/NTUSER.DAT)

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable

try:
    from Registry import Registry
except ImportError:
    Registry = None


class RegistryParser:
    """
    Parser for Windows Registry hive files.
    
    Uses python-registry library to extract keys, values, and modification timestamps.
    Focuses on forensically relevant keys (Run, RunOnce, MRU, Services, etc.)
    """
    
    # Forensically interesting key paths
    INTERESTING_PATHS = [
        r"Microsoft\Windows\CurrentVersion\Run",
        r"Microsoft\Windows\CurrentVersion\RunOnce",
        r"Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        r"Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        r"Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
        r"Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        r"ControlSet001\Services",
        r"ControlSet001\Control\Session Manager",
    ]
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize Registry Parser.
        
        Args:
            logger: Optional logger instance for audit trail
        """
        self.logger = logger or logging.getLogger(__name__)
        
        if Registry is None:
            self.logger.error("python-registry library not installed. Install: pip install python-registry")
            raise ImportError("python-registry library required for Registry parsing")
    
    def parse_file(self, hive_path: Path, progress_callback: Optional[Callable[[int, int], None]] = None) -> List[Dict[str, Any]]:
        """Alias for parse method to match pipeline interface."""
        return self.parse(hive_path, progress_callback)
    
    def parse(
        self, 
        hive_path: Path, 
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Parse a Registry hive file and extract forensically relevant keys.
        
        Args:
            hive_path: Path to Registry hive file
            progress_callback: Optional callback(current, total) for progress tracking
            
        Returns:
            List of parsed registry event dictionaries
            
        Raises:
            FileNotFoundError: If hive file doesn't exist
            ValueError: If file is not valid Registry format
        """
        hive_path = Path(hive_path)
        
        if not hive_path.exists():
            raise FileNotFoundError(f"Registry hive not found: {hive_path}")
        
        self.logger.info(f"Parsing Registry hive: {hive_path}")
        
        parsed_events = []
        
        try:
            reg = Registry.Registry(str(hive_path))
            root = reg.root()
            
            self.logger.info(f"Registry hive root: {root.name()}")
            
            # Parse interesting paths
            for idx, interesting_path in enumerate(self.INTERESTING_PATHS):
                try:
                    events = self._parse_key_path(root, interesting_path, hive_path)
                    parsed_events.extend(events)
                    
                    if progress_callback:
                        progress_callback(idx + 1, len(self.INTERESTING_PATHS))
                
                except Registry.RegistryKeyNotFoundException:
                    self.logger.debug(f"Key not found: {interesting_path}")
                    continue
                except Exception as e:
                    self.logger.warning(f"Failed to parse key {interesting_path}: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Failed to open Registry hive {hive_path}: {e}")
            raise ValueError(f"Invalid or corrupted Registry hive: {e}")
        
        self.logger.info(f"Successfully parsed {len(parsed_events)} registry entries from {hive_path.name}")
        return parsed_events
    
    def _parse_key_path(self, root, key_path: str, hive_path: Path) -> List[Dict[str, Any]]:
        """
        Parse a specific registry key path and all its values.
        
        Args:
            root: Registry root key
            key_path: Path to key (relative to root)
            hive_path: Path to source hive file
            
        Returns:
            List of event dictionaries for this key
        """
        events = []
        
        try:
            key = root.find_key(key_path)
        except Registry.RegistryKeyNotFoundException:
            return events
        
        # Get key modification timestamp
        try:
            ts_utc = key.timestamp().isoformat()
        except:
            ts_utc = datetime.now(timezone.utc).isoformat()
        
        # Parse all values in this key
        for value in key.values():
            try:
                event = {
                    'artifact_source': 'Registry',
                    'artifact_path': str(hive_path),
                    'event_type': 'RegKeyModified',
                    'ts_utc': ts_utc,
                    'ts_local': None,
                    'key_path': key.path(),
                    'value_name': value.name(),
                    'value_type': value.value_type_str(),
                    'value_data': self._sanitize_value(value.value()),
                    'description': f"Registry: {key.path()} | {value.name()}",
                    'raw_data_ref': f"{key.path()}\\{value.name()}"
                }
                events.append(event)
            
            except Exception as e:
                self.logger.warning(f"Failed to parse value in {key.path()}: {e}")
                continue
        
        # Also check subkeys (one level deep for services, etc.)
        if "Services" in key_path or "Run" in key_path:
            for subkey in key.subkeys():
                try:
                    subkey_ts = subkey.timestamp().isoformat()
                    
                    event = {
                        'artifact_source': 'Registry',
                        'artifact_path': str(hive_path),
                        'event_type': 'RegKeyCreated',
                        'ts_utc': subkey_ts,
                        'ts_local': None,
                        'key_path': subkey.path(),
                        'value_name': "(KeyCreated)",
                        'value_type': "KEY",
                        'value_data': subkey.name(),
                        'description': f"Registry Key Created: {subkey.path()}",
                        'raw_data_ref': subkey.path()
                    }
                    events.append(event)
                
                except Exception as e:
                    self.logger.warning(f"Failed to parse subkey {subkey.name()}: {e}")
                    continue
        
        return events
    
    def _sanitize_value(self, value: Any) -> str:
        """
        Convert registry value to string safely.
        
        Args:
            value: Registry value (can be binary, string, int, etc.)
            
        Returns:
            String representation
        """
        if value is None:
            return "(none)"
        
        if isinstance(value, bytes):
            # Convert binary to hex string (truncate if too long)
            hex_str = value.hex()
            return hex_str[:200] + "..." if len(hex_str) > 200 else hex_str
        
        if isinstance(value, list):
            return " | ".join(str(v) for v in value[:10])  # Max 10 items
        
        return str(value)[:500]  # Truncate long strings
