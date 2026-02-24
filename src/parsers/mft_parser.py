"""
FEPD - Forensic Evidence Parser Dashboard
MFT Parser Module

Parses NTFS Master File Table ($MFT) to extract MACB timestamps.
Extracts file activity events: Modified, Accessed, Changed, Birth times.

Implements FR-13: Parse MFT (MACB timestamps)

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
import struct
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Callable


class MFTParser:
    """
    Parser for NTFS Master File Table ($MFT).
    
    Extracts MACB (Modified, Accessed, Changed, Birth) timestamps for all files.
    Essential for timeline reconstruction and file activity analysis.
    """
    
    # MFT Record size
    MFT_RECORD_SIZE = 1024
    
    # NTFS attributes
    ATTR_STANDARD_INFORMATION = 0x10
    ATTR_FILE_NAME = 0x30
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize MFT Parser.
        
        Args:
            logger: Optional logger instance for audit trail
        """
        self.logger = logger or logging.getLogger(__name__)
    
    def parse_file(self, mft_path: Path, max_records: int = 100000, progress_callback: Optional[Callable[[int, int], None]] = None) -> List[Dict[str, Any]]:
        """Alias for parse method to match pipeline interface."""
        return self.parse(mft_path, max_records, progress_callback)
    
    def parse(
        self, 
        mft_path: Path, 
        max_records: int = 100000,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Parse an MFT file and extract MACB timestamps.
        
        Args:
            mft_path: Path to $MFT file
            max_records: Maximum number of records to parse (default 100k)
            progress_callback: Optional callback(current, total) for progress tracking
            
        Returns:
            List of parsed MFT event dictionaries
            
        Raises:
            FileNotFoundError: If MFT file doesn't exist
            ValueError: If file is not valid MFT format
        """
        mft_path = Path(mft_path)
        
        if not mft_path.exists():
            raise FileNotFoundError(f"MFT file not found: {mft_path}")
        
        self.logger.info(f"Parsing MFT file: {mft_path}")
        
        parsed_events = []
        
        try:
            file_size = mft_path.stat().st_size
            total_records = min(file_size // self.MFT_RECORD_SIZE, max_records)
            
            self.logger.info(f"Estimated MFT records: {total_records}")
            
            with open(mft_path, 'rb') as f:
                record_count = 0
                
                while record_count < max_records:
                    data = f.read(self.MFT_RECORD_SIZE)
                    
                    if len(data) < self.MFT_RECORD_SIZE:
                        break  # End of file
                    
                    # Check if valid MFT record (starts with "FILE" signature)
                    if data[:4] != b'FILE':
                        record_count += 1
                        continue
                    
                    try:
                        events = self._parse_mft_record(data, record_count, mft_path)
                        parsed_events.extend(events)
                    except Exception as e:
                        self.logger.debug(f"Failed to parse MFT record {record_count}: {e}")
                    
                    record_count += 1
                    
                    # Progress callback every 10000 records
                    if progress_callback and record_count % 10000 == 0:
                        progress_callback(record_count, total_records)
                
                # Final progress callback
                if progress_callback:
                    progress_callback(record_count, total_records)
        
        except Exception as e:
            self.logger.error(f"Failed to parse MFT file {mft_path}: {e}")
            raise ValueError(f"Invalid or corrupted MFT file: {e}")
        
        self.logger.info(f"Successfully parsed {len(parsed_events)} file events from MFT")
        return parsed_events
    
    def _parse_mft_record(self, data: bytes, record_num: int, mft_path: Path) -> List[Dict[str, Any]]:
        """
        Parse a single MFT record and extract MACB timestamps.
        
        Args:
            data: Raw MFT record bytes (1024 bytes)
            record_num: Record number in MFT
            mft_path: Path to source MFT file
            
        Returns:
            List of event dictionaries (one per timestamp type)
        """
        events = []
        
        try:
            # Check if record is in use (flags at offset 0x16)
            flags = struct.unpack('<H', data[0x16:0x18])[0]
            if not (flags & 0x01):  # Record not in use
                return events
            
            # Parse $STANDARD_INFORMATION attribute
            si_timestamps = self._parse_standard_information(data)
            
            # Parse $FILE_NAME attribute for filename
            filename = self._parse_filename_attribute(data)
            
            if not filename:
                filename = f"MFT_Record_{record_num}"
            
            # Create events for each MACB timestamp
            if si_timestamps:
                # Modified
                if si_timestamps.get('modified'):
                    events.append({
                        'artifact_source': 'MFT',
                        'artifact_path': str(mft_path),
                        'event_type': 'FileModified',
                        'ts_utc': si_timestamps['modified'],
                        'ts_local': None,
                        'filepath': filename,
                        'mft_record': record_num,
                        'macb': 'M',
                        'description': f"File Modified: {filename}",
                        'raw_data_ref': f"MFT Record {record_num}"
                    })
                
                # Accessed
                if si_timestamps.get('accessed'):
                    events.append({
                        'artifact_source': 'MFT',
                        'artifact_path': str(mft_path),
                        'event_type': 'FileAccessed',
                        'ts_utc': si_timestamps['accessed'],
                        'ts_local': None,
                        'filepath': filename,
                        'mft_record': record_num,
                        'macb': 'A',
                        'description': f"File Accessed: {filename}",
                        'raw_data_ref': f"MFT Record {record_num}"
                    })
                
                # Changed (MFT record modified)
                if si_timestamps.get('changed'):
                    events.append({
                        'artifact_source': 'MFT',
                        'artifact_path': str(mft_path),
                        'event_type': 'FileChanged',
                        'ts_utc': si_timestamps['changed'],
                        'ts_local': None,
                        'filepath': filename,
                        'mft_record': record_num,
                        'macb': 'C',
                        'description': f"File Changed (MFT): {filename}",
                        'raw_data_ref': f"MFT Record {record_num}"
                    })
                
                # Born (created)
                if si_timestamps.get('born'):
                    events.append({
                        'artifact_source': 'MFT',
                        'artifact_path': str(mft_path),
                        'event_type': 'FileCreated',
                        'ts_utc': si_timestamps['born'],
                        'ts_local': None,
                        'filepath': filename,
                        'mft_record': record_num,
                        'macb': 'B',
                        'description': f"File Created: {filename}",
                        'raw_data_ref': f"MFT Record {record_num}"
                    })
        
        except Exception as e:
            self.logger.debug(f"Failed to parse MFT record {record_num}: {e}")
        
        return events
    
    def _parse_standard_information(self, data: bytes) -> Optional[Dict[str, str]]:
        """
        Parse $STANDARD_INFORMATION attribute to extract MACB timestamps.
        
        Args:
            data: MFT record data
            
        Returns:
            Dictionary with MACB timestamps or None
        """
        try:
            # Find $STANDARD_INFORMATION attribute (0x10)
            offset = 0x14  # Attributes start at offset 0x14
            
            while offset < len(data) - 4:
                attr_type = struct.unpack('<I', data[offset:offset+4])[0]
                
                if attr_type == 0xFFFFFFFF:  # End of attributes
                    break
                
                if attr_type == self.ATTR_STANDARD_INFORMATION:
                    # Found $STANDARD_INFORMATION
                    attr_length = struct.unpack('<I', data[offset+4:offset+8])[0]
                    
                    if attr_length == 0:
                        break
                    
                    # Non-resident flag
                    non_resident = data[offset+8]
                    
                    if non_resident == 0:  # Resident attribute
                        # Content offset
                        content_offset = struct.unpack('<H', data[offset+0x14:offset+0x16])[0]
                        attr_start = offset + content_offset
                        
                        # MACB timestamps (each 8 bytes, FILETIME format)
                        created = self._filetime_to_datetime(struct.unpack('<Q', data[attr_start:attr_start+8])[0])
                        modified = self._filetime_to_datetime(struct.unpack('<Q', data[attr_start+8:attr_start+16])[0])
                        changed = self._filetime_to_datetime(struct.unpack('<Q', data[attr_start+16:attr_start+24])[0])
                        accessed = self._filetime_to_datetime(struct.unpack('<Q', data[attr_start+24:attr_start+32])[0])
                        
                        return {
                            'born': created,
                            'modified': modified,
                            'changed': changed,
                            'accessed': accessed
                        }
                    
                    break
                
                # Move to next attribute
                attr_length = struct.unpack('<I', data[offset+4:offset+8])[0]
                if attr_length == 0:
                    break
                offset += attr_length
        
        except Exception as e:
            self.logger.debug(f"Failed to parse $STANDARD_INFORMATION: {e}")
        
        return None
    
    def _parse_filename_attribute(self, data: bytes) -> Optional[str]:
        """
        Parse $FILE_NAME attribute to extract filename.
        
        Args:
            data: MFT record data
            
        Returns:
            Filename string or None
        """
        try:
            offset = 0x14  # Attributes start
            
            while offset < len(data) - 4:
                attr_type = struct.unpack('<I', data[offset:offset+4])[0]
                
                if attr_type == 0xFFFFFFFF:
                    break
                
                if attr_type == self.ATTR_FILE_NAME:
                    # Found $FILE_NAME
                    non_resident = data[offset+8]
                    
                    if non_resident == 0:  # Resident
                        content_offset = struct.unpack('<H', data[offset+0x14:offset+0x16])[0]
                        attr_start = offset + content_offset
                        
                        # Filename length (in chars) at offset 0x40
                        filename_length = data[attr_start + 0x40]
                        
                        # Filename starts at offset 0x42 (Unicode)
                        filename_start = attr_start + 0x42
                        filename_bytes = data[filename_start:filename_start + (filename_length * 2)]
                        
                        filename = filename_bytes.decode('utf-16-le', errors='ignore')
                        return filename
                    
                    break
                
                attr_length = struct.unpack('<I', data[offset+4:offset+8])[0]
                if attr_length == 0:
                    break
                offset += attr_length
        
        except Exception as e:
            self.logger.debug(f"Failed to parse $FILE_NAME: {e}")
        
        return None
    
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
            epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
            dt = epoch + timedelta(microseconds=filetime / 10)
            return dt.isoformat()
        except Exception:
            return None
