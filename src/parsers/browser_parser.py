"""
FEPD - Forensic Evidence Parser Dashboard
Browser Parser Module

Parses browser history databases (Chrome, Edge, Firefox) using SQLite3.
Extracts URLs, visit times, page titles for forensic timeline reconstruction.

Implements FR-14: Parse browser history databases (Chrome/Edge/Firefox)

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Callable


class BrowserParser:
    """
    Parser for browser history SQLite databases.
    
    Supports:
    - Google Chrome (History)
    - Microsoft Edge (History)
    - Mozilla Firefox (places.sqlite)
    
    Extracts URL visit events for forensic timeline analysis.
    """
    
    # Browser detection patterns
    BROWSER_PATTERNS = {
        'chrome': ['History', 'chrome'],
        'edge': ['History', 'edge'],
        'firefox': ['places.sqlite', 'firefox']
    }
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize Browser Parser.
        
        Args:
            logger: Optional logger instance for audit trail
        """
        self.logger = logger or logging.getLogger(__name__)
    
    def parse(
        self, 
        db_path: Path, 
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Parse a browser history database and extract visit events.
        
        Args:
            db_path: Path to browser history SQLite database
            progress_callback: Optional callback(current, total) for progress tracking
            
        Returns:
            List of parsed browser history event dictionaries
            
        Raises:
            FileNotFoundError: If database file doesn't exist
            ValueError: If file is not valid SQLite database
        """
        db_path = Path(db_path)
        
        if not db_path.exists():
            raise FileNotFoundError(f"Browser database not found: {db_path}")
        
        self.logger.info(f"Parsing browser history database: {db_path}")
        
        # Detect browser type
        browser_type = self._detect_browser_type(db_path)
        self.logger.info(f"Detected browser type: {browser_type}")
        
        parsed_events = []
        
        try:
            conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
            cursor = conn.cursor()
            
            if browser_type in ['chrome', 'edge']:
                parsed_events = self._parse_chromium(cursor, db_path, progress_callback)
            elif browser_type == 'firefox':
                parsed_events = self._parse_firefox(cursor, db_path, progress_callback)
            else:
                self.logger.warning(f"Unknown browser type, attempting Chromium parser")
                parsed_events = self._parse_chromium(cursor, db_path, progress_callback)
            
            conn.close()
        
        except sqlite3.Error as e:
            self.logger.error(f"SQLite error parsing {db_path}: {e}")
            raise ValueError(f"Invalid or corrupted browser database: {e}")
        except Exception as e:
            self.logger.error(f"Failed to parse browser database {db_path}: {e}")
            raise ValueError(f"Browser database parsing error: {e}")
        
        self.logger.info(f"Successfully parsed {len(parsed_events)} browser history entries from {db_path.name}")
        return parsed_events
    
    def _detect_browser_type(self, db_path: Path) -> str:
        """
        Detect browser type from database path/name.
        
        Args:
            db_path: Path to database file
            
        Returns:
            Browser type string ('chrome', 'edge', 'firefox', 'unknown')
        """
        path_str = str(db_path).lower()
        
        if 'chrome' in path_str and 'edge' not in path_str:
            return 'chrome'
        elif 'edge' in path_str or 'microsoftedge' in path_str:
            return 'edge'
        elif 'firefox' in path_str or 'places.sqlite' in path_str:
            return 'firefox'
        else:
            return 'unknown'
    
    def _parse_chromium(
        self, 
        cursor: sqlite3.Cursor, 
        db_path: Path,
        progress_callback: Optional[Callable[[int, int], None]]
    ) -> List[Dict[str, Any]]:
        """
        Parse Chromium-based browser (Chrome/Edge) history database.
        
        Schema:
        - urls table: id, url, title, visit_count, last_visit_time
        - visits table: id, url, visit_time, from_visit, transition
        
        Args:
            cursor: SQLite cursor
            db_path: Path to database
            progress_callback: Optional progress callback
            
        Returns:
            List of parsed events
        """
        events = []
        
        try:
            # Query visits with URL details
            query = """
            SELECT 
                urls.url,
                urls.title,
                visits.visit_time,
                visits.transition
            FROM visits
            INNER JOIN urls ON visits.url = urls.id
            ORDER BY visits.visit_time DESC
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            total_rows = len(rows)
            self.logger.info(f"Found {total_rows} browser history entries")
            
            for idx, row in enumerate(rows):
                url, title, visit_time, transition = row
                
                # Convert Chromium timestamp (microseconds since 1601-01-01) to UTC
                ts_utc = self._chromium_time_to_datetime(visit_time)
                
                event = {
                    'artifact_source': 'Browser',
                    'artifact_path': str(db_path),
                    'event_type': 'URLVisit',
                    'ts_utc': ts_utc,
                    'ts_local': None,
                    'url': url,
                    'title': title or "(No title)",
                    'transition_type': transition,
                    'description': f"Browser: Visited {url}",
                    'raw_data_ref': f"{db_path.name}:visits"
                }
                events.append(event)
                
                # Progress callback every 5000 records
                if progress_callback and idx % 5000 == 0:
                    progress_callback(idx, total_rows)
            
            if progress_callback:
                progress_callback(total_rows, total_rows)
        
        except sqlite3.Error as e:
            self.logger.error(f"Failed to query Chromium database: {e}")
        
        return events
    
    def _parse_firefox(
        self, 
        cursor: sqlite3.Cursor, 
        db_path: Path,
        progress_callback: Optional[Callable[[int, int], None]]
    ) -> List[Dict[str, Any]]:
        """
        Parse Firefox places.sqlite history database.
        
        Schema:
        - moz_places: id, url, title, visit_count
        - moz_historyvisits: id, place_id, visit_date, visit_type
        
        Args:
            cursor: SQLite cursor
            db_path: Path to database
            progress_callback: Optional progress callback
            
        Returns:
            List of parsed events
        """
        events = []
        
        try:
            query = """
            SELECT 
                moz_places.url,
                moz_places.title,
                moz_historyvisits.visit_date,
                moz_historyvisits.visit_type
            FROM moz_historyvisits
            INNER JOIN moz_places ON moz_historyvisits.place_id = moz_places.id
            ORDER BY moz_historyvisits.visit_date DESC
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            total_rows = len(rows)
            self.logger.info(f"Found {total_rows} Firefox history entries")
            
            for idx, row in enumerate(rows):
                url, title, visit_date, visit_type = row
                
                # Convert Firefox timestamp (microseconds since Unix epoch)
                ts_utc = self._firefox_time_to_datetime(visit_date)
                
                event = {
                    'artifact_source': 'Browser',
                    'artifact_path': str(db_path),
                    'event_type': 'URLVisit',
                    'ts_utc': ts_utc,
                    'ts_local': None,
                    'url': url,
                    'title': title or "(No title)",
                    'visit_type': visit_type,
                    'description': f"Browser: Visited {url}",
                    'raw_data_ref': f"{db_path.name}:moz_historyvisits"
                }
                events.append(event)
                
                if progress_callback and idx % 5000 == 0:
                    progress_callback(idx, total_rows)
            
            if progress_callback:
                progress_callback(total_rows, total_rows)
        
        except sqlite3.Error as e:
            self.logger.error(f"Failed to query Firefox database: {e}")
        
        return events
    
    def _chromium_time_to_datetime(self, chromium_time: int) -> str:
        """
        Convert Chromium timestamp to UTC ISO 8601 datetime string.
        
        Chromium uses microseconds since 1601-01-01 (Windows FILETIME).
        
        Args:
            chromium_time: Chromium timestamp
            
        Returns:
            ISO 8601 formatted UTC timestamp
        """
        if chromium_time == 0:
            return datetime.now(timezone.utc).isoformat()
        
        try:
            # Chromium epoch: 1601-01-01
            epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
            dt = epoch + timedelta(microseconds=chromium_time)
            return dt.isoformat()
        except Exception as e:
            self.logger.warning(f"Failed to convert Chromium time {chromium_time}: {e}")
            return datetime.now(timezone.utc).isoformat()
    
    def _firefox_time_to_datetime(self, firefox_time: int) -> str:
        """
        Convert Firefox timestamp to UTC ISO 8601 datetime string.
        
        Firefox uses microseconds since Unix epoch (1970-01-01).
        
        Args:
            firefox_time: Firefox timestamp
            
        Returns:
            ISO 8601 formatted UTC timestamp
        """
        if firefox_time == 0:
            return datetime.now(timezone.utc).isoformat()
        
        try:
            # Firefox uses microseconds since Unix epoch
            dt = datetime.fromtimestamp(firefox_time / 1000000, tz=timezone.utc)
            return dt.isoformat()
        except Exception as e:
            self.logger.warning(f"Failed to convert Firefox time {firefox_time}: {e}")
            return datetime.now(timezone.utc).isoformat()
