"""
FEPD - Forensic Evidence Parser Dashboard
EVTX Parser Module

Parses Windows Event Log files (.evtx) using python-evtx library.
Extracts EventID, TimeCreated, Provider, Message, Channel, Computer, UserID.

Implements FR-10: Parse EVTX event logs (timestamp, provider, eventID, message)

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
except ImportError:
    evtx = None
    e_views = None

import xml.etree.ElementTree as ET


class EVTXParser:
    """
    Parser for Windows Event Log (.evtx) files.
    
    Uses python-evtx library to extract forensic event data.
    All timestamps returned in UTC ISO 8601 format.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize EVTX Parser.
        
        Args:
            logger: Optional logger instance for audit trail
        """
        self.logger = logger or logging.getLogger(__name__)
        
        if evtx is None:
            self.logger.error("python-evtx library not installed. Install: pip install python-evtx")
            raise ImportError("python-evtx library required for EVTX parsing")
    
    def parse_file(self, evtx_path: Path, progress_callback: Optional[Callable[[int, int], None]] = None) -> List[Dict[str, Any]]:
        """Alias for parse method to match pipeline interface."""
        return self.parse(evtx_path, progress_callback)
    
    def parse(
        self, 
        evtx_path: Path, 
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Parse an EVTX file and extract all events.
        
        Args:
            evtx_path: Path to .evtx file
            progress_callback: Optional callback(current, total) for progress tracking
            
        Returns:
            List of parsed event dictionaries with normalized fields
            
        Raises:
            FileNotFoundError: If EVTX file doesn't exist
            ValueError: If file is not valid EVTX format
        """
        evtx_path = Path(evtx_path)
        
        if not evtx_path.exists():
            raise FileNotFoundError(f"EVTX file not found: {evtx_path}")
        
        if not evtx_path.suffix.lower() == '.evtx':
            raise ValueError(f"File is not .evtx format: {evtx_path}")
        
        self.logger.info(f"Parsing EVTX file: {evtx_path}")
        
        parsed_events = []
        
        try:
            with evtx.Evtx(str(evtx_path)) as log:
                # python-evtx APIs differ by version; try available counters first
                record_iter = log.records()
                total_records = None
                for method_name in ("get_number_of_records", "get_num_records", "get_record_count"):
                    if hasattr(log, method_name):
                        try:
                            total_records = getattr(log, method_name)()
                            break
                        except Exception:
                            continue
                if total_records is None:
                    # Fallback: exhaust iterator to count, then re-iterate
                    records_cache = list(record_iter)
                    total_records = len(records_cache)
                    record_iter = iter(records_cache)
                
                self.logger.info(f"Total EVTX records: {total_records}")
                
                for idx, record in enumerate(record_iter):
                    try:
                        event_dict = self._parse_record(record, evtx_path)
                        parsed_events.append(event_dict)
                        
                        # Progress callback every 1000 records
                        if progress_callback and idx % 1000 == 0:
                            progress_callback(idx, total_records)
                    
                    except Exception as e:
                        # Error 138 = corrupted/malformed EVTX record (common in forensic images)
                        # Silently skip corrupted records to avoid log spam
                        # Track failures for summary reporting
                        if not hasattr(self, '_parse_failures'):
                            self._parse_failures = 0
                        self._parse_failures += 1
                        continue
                
                # Final progress callback
                if progress_callback:
                    progress_callback(total_records, total_records)
        
        except Exception as e:
            self.logger.error(f"Failed to open EVTX file {evtx_path}: {e}")
            raise ValueError(f"Invalid or corrupted EVTX file: {e}")
        
        # Report parsing summary
        if hasattr(self, '_parse_failures') and self._parse_failures > 0:
            self.logger.info(f"Successfully parsed {len(parsed_events)} events from {evtx_path.name} ({self._parse_failures} corrupted records skipped)")
            self._parse_failures = 0  # Reset counter
        else:
            self.logger.info(f"Successfully parsed {len(parsed_events)} events from {evtx_path.name}")
        
        return parsed_events
    
    def _parse_record(self, record, evtx_path: Path) -> Dict[str, Any]:
        """
        Parse a single EVTX record into normalized dictionary.
        
        Args:
            record: python-evtx record object
            evtx_path: Path to source EVTX file
            
        Returns:
            Dictionary with normalized event fields
        """
        # Get XML representation
        xml_string = record.xml()
        
        # Parse XML
        try:
            root = ET.fromstring(xml_string)
        except ET.ParseError as e:
            self.logger.warning(f"XML parse error: {e}")
            return self._create_fallback_record(record, evtx_path)
        
        # Extract namespaces
        ns = {'event': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        # Extract System fields
        system = root.find('event:System', ns)
        
        event_id = self._get_text(system, 'event:EventID', ns) or "0"
        provider = self._get_attrib(system, 'event:Provider', 'Name', ns) or "Unknown"
        time_created = self._get_attrib(system, 'event:TimeCreated', 'SystemTime', ns)
        computer = self._get_text(system, 'event:Computer', ns) or "Unknown"
        channel = self._get_text(system, 'event:Channel', ns) or "Unknown"
        
        # Extract Security UserID if present
        security = system.find('event:Security', ns)
        user_id = None
        if security is not None:
            user_id = security.get('UserID')
        
        # Extract EventData/UserData for message
        event_data = root.find('event:EventData', ns)
        user_data = root.find('event:UserData', ns)
        
        message = self._extract_message(event_data, user_data, ns)
        
        # Convert timestamp to UTC datetime
        ts_utc = self._parse_timestamp(time_created)
        
        return {
            'artifact_source': 'EVTX',
            'artifact_path': str(evtx_path),
            'event_type': 'WindowsEvent',
            'ts_utc': ts_utc,
            'ts_local': None,  # Will be converted by normalization engine
            'event_id_native': event_id,
            'provider': provider,
            'channel': channel,
            'computer': computer,
            'user_account': user_id,
            'message': message,
            'description': f"EventID {event_id} from {provider}",
            'raw_data_ref': xml_string[:500]  # First 500 chars for reference
        }
    
    def _get_text(self, parent, tag: str, ns: Dict[str, str]) -> Optional[str]:
        """Safely extract text from XML element."""
        if parent is None:
            return None
        element = parent.find(tag, ns)
        return element.text if element is not None else None
    
    def _get_attrib(self, parent, tag: str, attrib: str, ns: Dict[str, str]) -> Optional[str]:
        """Safely extract attribute from XML element."""
        if parent is None:
            return None
        element = parent.find(tag, ns)
        return element.get(attrib) if element is not None else None
    
    def _extract_message(self, event_data, user_data, ns: Dict[str, str]) -> str:
        """Extract message from EventData or UserData."""
        message_parts = []
        
        if event_data is not None:
            for data in event_data.findall('event:Data', ns):
                name = data.get('Name', 'Data')
                value = data.text or ""
                if value:
                    message_parts.append(f"{name}={value}")
        
        if user_data is not None:
            # UserData has custom schema, extract all text
            for elem in user_data.iter():
                if elem.text and elem.text.strip():
                    message_parts.append(elem.text.strip())
        
        return " | ".join(message_parts) if message_parts else "No message data"
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> str:
        """
        Parse Windows timestamp string to UTC ISO 8601.
        
        Args:
            timestamp_str: Timestamp string from EVTX
            
        Returns:
            ISO 8601 formatted UTC timestamp
        """
        if not timestamp_str:
            return datetime.now(timezone.utc).isoformat()
        
        try:
            # Windows EVTX uses ISO 8601 format already
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.astimezone(timezone.utc).isoformat()
        except Exception as e:
            self.logger.warning(f"Failed to parse timestamp '{timestamp_str}': {e}")
            return datetime.now(timezone.utc).isoformat()
    
    def _create_fallback_record(self, record, evtx_path: Path) -> Dict[str, Any]:
        """Create fallback record when XML parsing fails."""
        return {
            'artifact_source': 'EVTX',
            'artifact_path': str(evtx_path),
            'event_type': 'WindowsEvent',
            'ts_utc': datetime.now(timezone.utc).isoformat(),
            'ts_local': None,
            'event_id_native': "0",
            'provider': "Unknown",
            'channel': "Unknown",
            'computer': "Unknown",
            'user_account': None,
            'message': "Failed to parse EVTX record",
            'description': "Corrupted or malformed EVTX record",
            'raw_data_ref': str(record)[:500]
        }
