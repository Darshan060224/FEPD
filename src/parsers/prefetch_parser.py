"""
FEPD - Forensic Evidence Parser Dashboard
Prefetch Parser Module

Parses Windows Prefetch files (.pf) using python-prefetch-parser.
Extracts executable name, run count, last run time, file references.

Implements FR-12: Parse Prefetch (exe name, run count, last run)

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
import struct
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Callable


class PrefetchParser:
    """
    Parser for Windows Prefetch (.pf) files.
    
    Prefetch files contain program execution traces including:
    - Executable name
    - Run count
    - Last execution times (up to 8)
    - Referenced files/DLLs
    """
    
    # Prefetch format signatures
    PREFETCH_SIGNATURES = {
        b'SCCA': 'Windows XP/Vista/7',
        b'\x17\x00\x00\x00': 'Windows 8',
        b'\x1A\x00\x00\x00': 'Windows 8.1',
        b'\x1E\x00\x00\x00': 'Windows 10',
    }
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize Prefetch Parser.
        
        Args:
            logger: Optional logger instance for audit trail
        """
        self.logger = logger or logging.getLogger(__name__)
    
    def parse_file(self, prefetch_path: Path, progress_callback: Optional[Callable[[int, int], None]] = None) -> List[Dict[str, Any]]:
        """Alias for parse method to match pipeline interface."""
        return self.parse(prefetch_path, progress_callback)
    
    def parse(
        self, 
        prefetch_path: Path, 
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Parse a Prefetch file and extract execution data.
        
        Args:
            prefetch_path: Path to .pf file
            progress_callback: Optional callback for progress tracking
            
        Returns:
            List with single parsed prefetch event dictionary
            
        Raises:
            FileNotFoundError: If prefetch file doesn't exist
            ValueError: If file is not valid Prefetch format
        """
        prefetch_path = Path(prefetch_path)
        
        if not prefetch_path.exists():
            raise FileNotFoundError(f"Prefetch file not found: {prefetch_path}")
        
        if not prefetch_path.suffix.lower() == '.pf':
            raise ValueError(f"File is not .pf format: {prefetch_path}")
        
        self.logger.info(f"Parsing Prefetch file: {prefetch_path}")
        
        try:
            with open(prefetch_path, 'rb') as f:
                data = f.read()
            
            if progress_callback:
                progress_callback(0, 1)
            
            event = self._parse_prefetch_data(data, prefetch_path)
            
            if progress_callback:
                progress_callback(1, 1)
            
            self.logger.info(f"Successfully parsed {prefetch_path.name}")
            return [event] if event else []
        
        except Exception as e:
            self.logger.error(f"Failed to parse Prefetch file {prefetch_path}: {e}")
            raise ValueError(f"Invalid or corrupted Prefetch file: {e}")
    
    def _parse_prefetch_data(self, data: bytes, prefetch_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse raw prefetch file data.
        
        Args:
            data: Raw prefetch file bytes
            prefetch_path: Path to source file
            
        Returns:
            Parsed prefetch event dictionary
        """
        if len(data) < 84:
            self.logger.warning(f"Prefetch file too small: {len(data)} bytes")
            return None
        
        try:
            # Detect version
            version = struct.unpack('<I', data[0:4])[0]
            
            # Extract executable name from filename (format: EXENAME-HASH.pf)
            exe_name = prefetch_path.stem
            if '-' in exe_name:
                exe_name = exe_name.split('-')[0] + '.exe'
            
            # Parse based on version
            if version == 0x17000000:  # Windows 8
                event = self._parse_win8(data, exe_name, prefetch_path)
            elif version == 0x1A000000:  # Windows 8.1
                event = self._parse_win8_1(data, exe_name, prefetch_path)
            elif version == 0x1E000000:  # Windows 10
                event = self._parse_win10(data, exe_name, prefetch_path)
            else:
                # Fallback parser
                event = self._parse_fallback(data, exe_name, prefetch_path)
            
            return event
        
        except Exception as e:
            self.logger.warning(f"Failed to parse prefetch data: {e}")
            return self._create_fallback_record(prefetch_path)
    
    def _parse_win10(self, data: bytes, exe_name: str, prefetch_path: Path) -> Dict[str, Any]:
        """Parse Windows 10 prefetch format."""
        try:
            # Windows 10 format offsets
            run_count_offset = 0xD0
            last_run_offset = 0x80
            
            # Run count (4 bytes at offset 0xD0)
            run_count = struct.unpack('<I', data[run_count_offset:run_count_offset+4])[0]
            
            # Last run time (FILETIME at offset 0x80) - Windows 10 has up to 8 timestamps
            timestamps = []
            for i in range(8):
                offset = last_run_offset + (i * 8)
                if offset + 8 <= len(data):
                    filetime = struct.unpack('<Q', data[offset:offset+8])[0]
                    if filetime > 0:
                        dt = self._filetime_to_datetime(filetime)
                        if dt:
                            timestamps.append(dt)
            
            # Use most recent timestamp
            ts_utc = timestamps[0] if timestamps else datetime.now(timezone.utc).isoformat()
            
            return {
                'artifact_source': 'Prefetch',
                'artifact_path': str(prefetch_path),
                'event_type': 'ProcessExecution',
                'ts_utc': ts_utc,
                'ts_local': None,
                'exe_name': exe_name,
                'run_count': run_count,
                'last_run_times': [str(ts) for ts in timestamps[:3]],  # Store top 3
                'description': f"Prefetch: {exe_name} executed {run_count} times",
                'raw_data_ref': f"{prefetch_path.name}"
            }
        
        except Exception as e:
            self.logger.warning(f"Windows 10 prefetch parse error: {e}")
            return self._create_fallback_record(prefetch_path)
    
    def _parse_win8_1(self, data: bytes, exe_name: str, prefetch_path: Path) -> Dict[str, Any]:
        """Parse Windows 8.1 prefetch format."""
        # Similar structure to Win10, slight offset differences
        return self._parse_win10(data, exe_name, prefetch_path)
    
    def _parse_win8(self, data: bytes, exe_name: str, prefetch_path: Path) -> Dict[str, Any]:
        """Parse Windows 8 prefetch format."""
        try:
            run_count_offset = 0x98
            last_run_offset = 0x80
            
            run_count = struct.unpack('<I', data[run_count_offset:run_count_offset+4])[0]
            
            filetime = struct.unpack('<Q', data[last_run_offset:last_run_offset+8])[0]
            ts_utc = self._filetime_to_datetime(filetime) or datetime.now(timezone.utc).isoformat()
            
            return {
                'artifact_source': 'Prefetch',
                'artifact_path': str(prefetch_path),
                'event_type': 'ProcessExecution',
                'ts_utc': ts_utc,
                'ts_local': None,
                'exe_name': exe_name,
                'run_count': run_count,
                'last_run_times': [str(ts_utc)],
                'description': f"Prefetch: {exe_name} executed {run_count} times",
                'raw_data_ref': f"{prefetch_path.name}"
            }
        
        except Exception as e:
            self.logger.warning(f"Windows 8 prefetch parse error: {e}")
            return self._create_fallback_record(prefetch_path)
    
    def _parse_fallback(self, data: bytes, exe_name: str, prefetch_path: Path) -> Dict[str, Any]:
        """Fallback parser when version is unknown."""
        return {
            'artifact_source': 'Prefetch',
            'artifact_path': str(prefetch_path),
            'event_type': 'ProcessExecution',
            'ts_utc': datetime.now(timezone.utc).isoformat(),
            'ts_local': None,
            'exe_name': exe_name,
            'run_count': 0,
            'last_run_times': [],
            'description': f"Prefetch: {exe_name} (unknown version)",
            'raw_data_ref': f"{prefetch_path.name}"
        }
    
    def _filetime_to_datetime(self, filetime: int) -> Optional[str]:
        """
        Convert Windows FILETIME to UTC ISO 8601 datetime string.
        
        Args:
            filetime: Windows FILETIME (100-nanosecond intervals since 1601-01-01)
            
        Returns:
            ISO 8601 formatted UTC timestamp or None if invalid
        """
        if filetime == 0 or filetime > 0x7FFFFFFFFFFFFFFF:
            return None
        
        try:
            # FILETIME epoch: 1601-01-01
            epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
            dt = epoch + timedelta(microseconds=filetime / 10)
            return dt.isoformat()
        except Exception as e:
            self.logger.warning(f"Failed to convert FILETIME {filetime}: {e}")
            return None
    
    def _create_fallback_record(self, prefetch_path: Path) -> Dict[str, Any]:
        """Create fallback record when parsing completely fails."""
        exe_name = prefetch_path.stem.split('-')[0] + '.exe' if '-' in prefetch_path.stem else prefetch_path.stem
        
        return {
            'artifact_source': 'Prefetch',
            'artifact_path': str(prefetch_path),
            'event_type': 'ProcessExecution',
            'ts_utc': datetime.now(timezone.utc).isoformat(),
            'ts_local': None,
            'exe_name': exe_name,
            'run_count': 0,
            'last_run_times': [],
            'description': f"Prefetch: {exe_name} (corrupted or unknown format)",
            'raw_data_ref': f"{prefetch_path.name}"
        }
