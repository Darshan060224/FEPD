"""
macOS Forensic Artifact Parser
================================

Parses macOS-specific forensic artifacts for timeline analysis:
- bash/zsh history
- Unified Logs (ASL format)
- Safari history and downloads
- System plists (preferences, login items)
- FSEvents (file system events)
- Keychain dumps (with security tool)
- Spotlight metadata
- macOS system logs

References:
- Mac4n6.com (Sarah Edwards' macOS forensics research)
- SANS FOR518 (Mac & iOS Forensics)
- Objective-See tools (Patrick Wardle)
"""

import sqlite3
import plistlib
import logging
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator
from datetime import datetime, timedelta
import re
import json


class MacOSParser:
    """
    Main parser for macOS forensic artifacts.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # macOS epoch: January 1, 2001 00:00:00 UTC
        self.COCOA_EPOCH = datetime(2001, 1, 1)
        
        # Common macOS artifact paths (relative to mount point)
        self.ARTIFACT_PATHS = {
            'bash_history': [
                'Users/*/.*_history',  # .bash_history, .zsh_history
            ],
            'safari_history': [
                'Users/*/Library/Safari/History.db',
            ],
            'safari_downloads': [
                'Users/*/Library/Safari/Downloads.plist',
            ],
            'unified_logs': [
                'var/db/diagnostics/Persist/*.tracev3',
                'var/db/diagnostics/Special/*.tracev3',
            ],
            'system_logs': [
                'var/log/system.log*',
                'private/var/log/system.log*',
            ],
            'fseventsd': [
                '.fseventsd/*',
            ],
            'spotlight': [
                '.Spotlight-V100/Store-V2/*/store.db',
            ],
            'login_items': [
                'Users/*/Library/Preferences/com.apple.loginitems.plist',
            ],
            'recent_items': [
                'Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl2',
            ],
            'quarantine': [
                'Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2',
            ],
        }
    
    def parse_bash_history(self, history_file: Path) -> List[Dict[str, Any]]:
        """
        Parse bash/zsh history file.
        
        Format:
        - bash: plain commands, one per line
        - zsh: `: timestamp:duration;command` format
        
        Returns list of command execution events.
        """
        events = []
        
        try:
            with open(history_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            username = self._extract_username_from_path(history_file)
            shell_type = 'zsh' if 'zsh' in history_file.name else 'bash'
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                
                # Parse zsh extended format
                if shell_type == 'zsh' and line.startswith(':'):
                    match = re.match(r': (\d+):(\d+);(.+)', line)
                    if match:
                        timestamp = int(match.group(1))
                        duration = int(match.group(2))
                        command = match.group(3)
                        
                        events.append({
                            'timestamp': datetime.fromtimestamp(timestamp),
                            'event_type': 'shell_command',
                            'category': 'System',
                            'source': f'{shell_type}_history',
                            'user': username,
                            'command': command,
                            'duration_seconds': duration,
                            'shell': shell_type,
                            'description': f'User {username} executed: {command[:100]}',
                        })
                else:
                    # Plain command (bash or zsh without timestamp)
                    # Use file modification time as approximate timestamp
                    mod_time = datetime.fromtimestamp(history_file.stat().st_mtime)
                    
                    events.append({
                        'timestamp': mod_time,
                        'event_type': 'shell_command',
                        'category': 'System',
                        'source': f'{shell_type}_history',
                        'user': username,
                        'command': line,
                        'shell': shell_type,
                        'description': f'User {username} executed: {line[:100]}',
                        'note': 'Timestamp approximate (file mtime)'
                    })
        
        except Exception as e:
            self.logger.error(f"Error parsing {history_file}: {e}")
        
        return events
    
    def parse_safari_history(self, history_db: Path) -> List[Dict[str, Any]]:
        """
        Parse Safari History.db SQLite database.
        
        Schema:
        - history_visits: id, history_item, visit_time, title
        - history_items: id, url, domain_expansion, visit_count
        
        Returns list of web browsing events.
        """
        events = []
        
        try:
            conn = sqlite3.connect(f'file:{history_db}?mode=ro', uri=True)
            cursor = conn.cursor()
            
            username = self._extract_username_from_path(history_db)
            
            query = """
            SELECT 
                hv.visit_time,
                hi.url,
                hv.title,
                hi.visit_count,
                hi.domain_expansion
            FROM history_visits hv
            JOIN history_items hi ON hv.history_item = hi.id
            ORDER BY hv.visit_time
            """
            
            cursor.execute(query)
            
            for row in cursor.fetchall():
                visit_time_cocoa, url, title, visit_count, domain = row
                
                # Convert Cocoa timestamp
                timestamp = self._cocoa_to_datetime(visit_time_cocoa)
                
                events.append({
                    'timestamp': timestamp,
                    'event_type': 'web_history',
                    'category': 'Web',
                    'source': 'safari_history',
                    'user': username,
                    'url': url,
                    'title': title or 'No title',
                    'domain': domain,
                    'visit_count': visit_count,
                    'description': f'{username} visited: {title or url}'
                })
            
            conn.close()
        
        except Exception as e:
            self.logger.error(f"Error parsing Safari history {history_db}: {e}")
        
        return events
    
    def parse_safari_downloads(self, downloads_plist: Path) -> List[Dict[str, Any]]:
        """
        Parse Safari Downloads.plist.
        
        Contains:
        - DownloadHistory: array of download items
          - DownloadEntryDateAddedKey
          - DownloadEntryURL
          - DownloadEntryPath
          - DownloadEntryProgressBytesSoFar
        
        Returns list of download events.
        """
        events = []
        
        try:
            with open(downloads_plist, 'rb') as f:
                plist_data = plistlib.load(f)
            
            username = self._extract_username_from_path(downloads_plist)
            
            download_history = plist_data.get('DownloadHistory', [])
            
            for item in download_history:
                date_added = item.get('DownloadEntryDateAddedKey')
                url = item.get('DownloadEntryURL', 'Unknown URL')
                path = item.get('DownloadEntryPath', 'Unknown path')
                bytes_downloaded = item.get('DownloadEntryProgressBytesSoFar', 0)
                
                if date_added:
                    # Cocoa date
                    timestamp = self._cocoa_to_datetime(date_added)
                    
                    events.append({
                        'timestamp': timestamp,
                        'event_type': 'file_download',
                        'category': 'Web',
                        'source': 'safari_downloads',
                        'user': username,
                        'url': url,
                        'file_path': path,
                        'bytes': bytes_downloaded,
                        'description': f'{username} downloaded: {Path(path).name} from {url}'
                    })
        
        except Exception as e:
            self.logger.error(f"Error parsing Safari downloads {downloads_plist}: {e}")
        
        return events
    
    def parse_system_log(self, log_file: Path) -> List[Dict[str, Any]]:
        """
        Parse /var/log/system.log (legacy format, pre-10.12).
        
        Format: Month Day HH:MM:SS hostname process[pid]: message
        Example: Jan  1 12:34:56 MacBook loginwindow[123]: User logged in
        
        Returns list of system log events.
        """
        events = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse log line
                    match = re.match(
                        r'(\w+\s+\d+)\s+(\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(\[\d+\])?:\s+(.+)',
                        line
                    )
                    
                    if match:
                        date_str = match.group(1)
                        time_str = match.group(2)
                        hostname = match.group(3)
                        process = match.group(4)
                        message = match.group(6)
                        
                        # Construct timestamp (year from file mtime)
                        year = datetime.fromtimestamp(log_file.stat().st_mtime).year
                        timestamp = datetime.strptime(f"{year} {date_str} {time_str}", "%Y %b %d %H:%M:%S")
                        
                        events.append({
                            'timestamp': timestamp,
                            'event_type': 'system_log',
                            'category': 'System',
                            'source': 'system.log',
                            'hostname': hostname,
                            'process': process,
                            'message': message,
                            'description': f'{process}: {message[:100]}'
                        })
        
        except Exception as e:
            self.logger.error(f"Error parsing system log {log_file}: {e}")
        
        return events
    
    def parse_unified_log(self, tracev3_file: Path) -> List[Dict[str, Any]]:
        """
        Parse Unified Logging tracev3 files (macOS 10.12+).
        
        Note: Binary format requires 'log show' command or binary parsing.
        This is a placeholder for integration with external tools.
        
        Recommended approach:
        1. Use 'log show --archive <path> --style json' to export
        2. Parse JSON output
        
        Returns list of unified log events.
        """
        events = []
        
        self.logger.warning(
            f"Unified log parsing requires 'log show' command. "
            f"File: {tracev3_file}"
        )
        
        # TODO: Implement binary parsing or subprocess call to 'log show'
        # For now, return empty list
        
        return events
    
    def parse_login_items(self, plist_file: Path) -> List[Dict[str, Any]]:
        """
        Parse com.apple.loginitems.plist.
        
        Contains:
        - SessionItems: applications that launch at login
        - Potentially contains malware persistence
        
        Returns list of login item events.
        """
        events = []
        
        try:
            with open(plist_file, 'rb') as f:
                plist_data = plistlib.load(f)
            
            username = self._extract_username_from_path(plist_file)
            mod_time = datetime.fromtimestamp(plist_file.stat().st_mtime)
            
            session_items = plist_data.get('SessionItems', {})
            custom_list_items = session_items.get('CustomListItems', [])
            
            for item in custom_list_items:
                name = item.get('Name', 'Unknown')
                alias_data = item.get('Alias', b'')
                
                # Try to extract path from alias data (complex binary format)
                # For now, just record the name
                
                events.append({
                    'timestamp': mod_time,
                    'event_type': 'login_item',
                    'category': 'System',
                    'source': 'login_items',
                    'user': username,
                    'item_name': name,
                    'description': f'Login item configured: {name}',
                    'note': 'Potential persistence mechanism'
                })
        
        except Exception as e:
            self.logger.error(f"Error parsing login items {plist_file}: {e}")
        
        return events
    
    def parse_quarantine_events(self, quarantine_db: Path) -> List[Dict[str, Any]]:
        """
        Parse com.apple.LaunchServices.QuarantineEventsV2 SQLite database.
        
        Tracks files downloaded from the internet (Gatekeeper quarantine).
        
        Schema:
        - LSQuarantineEvent: 
          - LSQuarantineEventIdentifier (UUID)
          - LSQuarantineTimeStamp (Cocoa timestamp)
          - LSQuarantineAgentName (browser/app)
          - LSQuarantineDataURLString (download URL)
          - LSQuarantineOriginURLString (referring page)
        
        Returns list of quarantine/download events.
        """
        events = []
        
        try:
            conn = sqlite3.connect(f'file:{quarantine_db}?mode=ro', uri=True)
            cursor = conn.cursor()
            
            username = self._extract_username_from_path(quarantine_db)
            
            query = """
            SELECT 
                LSQuarantineEventIdentifier,
                LSQuarantineTimeStamp,
                LSQuarantineAgentName,
                LSQuarantineDataURLString,
                LSQuarantineOriginURLString,
                LSQuarantineTypeNumber
            FROM LSQuarantineEvent
            ORDER BY LSQuarantineTimeStamp
            """
            
            cursor.execute(query)
            
            for row in cursor.fetchall():
                event_id, timestamp_cocoa, agent, data_url, origin_url, type_num = row
                
                if timestamp_cocoa:
                    timestamp = self._cocoa_to_datetime(timestamp_cocoa)
                    
                    events.append({
                        'timestamp': timestamp,
                        'event_type': 'quarantine',
                        'category': 'Security',
                        'source': 'quarantine_events',
                        'user': username,
                        'event_id': event_id,
                        'agent': agent,
                        'download_url': data_url or 'Unknown',
                        'origin_url': origin_url or 'Unknown',
                        'type': type_num,
                        'description': f'{username} downloaded file via {agent}: {data_url}'
                    })
            
            conn.close()
        
        except Exception as e:
            self.logger.error(f"Error parsing quarantine events {quarantine_db}: {e}")
        
        return events
    
    def parse_fseventsd_file(self, fsevent_file: Path) -> List[Dict[str, Any]]:
        """
        Parse FSEvents file system event logs.
        
        Binary format containing:
        - File path changes
        - Creation/deletion/modification events
        - Timestamps
        
        Note: Complex binary format, requires specialized parsing.
        Recommend using fseventer tool or similar.
        
        Returns list of file system events.
        """
        events = []
        
        self.logger.warning(
            f"FSEvents parsing requires specialized tools. "
            f"Consider using fseventer or FSEventsParser. "
            f"File: {fsevent_file}"
        )
        
        # TODO: Implement FSEvents binary parsing
        # For now, return empty list
        
        return events
    
    def parse_spotlight_store(self, store_db: Path) -> List[Dict[str, Any]]:
        """
        Parse Spotlight store.db metadata database.
        
        Contains rich file metadata:
        - kMDItemLastUsedDate
        - kMDItemDownloadedDate
        - kMDItemWhereFroms (download URLs)
        
        Returns list of file metadata events.
        """
        events = []
        
        try:
            conn = sqlite3.connect(f'file:{store_db}?mode=ro', uri=True)
            cursor = conn.cursor()
            
            # Spotlight database schema varies by version
            # Attempt common queries
            
            try:
                # Try to get file metadata
                query = """
                SELECT * FROM metadata
                LIMIT 100
                """
                cursor.execute(query)
                
                # This is a simplified example
                # Real implementation needs detailed schema knowledge
                
            except sqlite3.OperationalError:
                self.logger.warning(f"Unsupported Spotlight schema: {store_db}")
            
            conn.close()
        
        except Exception as e:
            self.logger.error(f"Error parsing Spotlight store {store_db}: {e}")
        
        return events
    
    def parse_all_artifacts(self, mount_point: Path) -> Generator[Dict[str, Any], None, None]:
        """
        Parse all macOS artifacts from a mounted image.
        
        Yields events one at a time for memory efficiency.
        
        Args:
            mount_point: Path to mounted macOS volume
            
        Yields:
            Event dictionaries
        """
        self.logger.info(f"Parsing macOS artifacts from: {mount_point}")
        
        # Parse bash/zsh history
        for pattern in self.ARTIFACT_PATHS['bash_history']:
            for history_file in mount_point.glob(pattern):
                self.logger.info(f"Parsing history: {history_file}")
                for event in self.parse_bash_history(history_file):
                    yield event
        
        # Parse Safari history
        for pattern in self.ARTIFACT_PATHS['safari_history']:
            for history_db in mount_point.glob(pattern):
                self.logger.info(f"Parsing Safari history: {history_db}")
                for event in self.parse_safari_history(history_db):
                    yield event
        
        # Parse Safari downloads
        for pattern in self.ARTIFACT_PATHS['safari_downloads']:
            for downloads_plist in mount_point.glob(pattern):
                self.logger.info(f"Parsing Safari downloads: {downloads_plist}")
                for event in self.parse_safari_downloads(downloads_plist):
                    yield event
        
        # Parse system logs
        for pattern in self.ARTIFACT_PATHS['system_logs']:
            for log_file in mount_point.glob(pattern):
                self.logger.info(f"Parsing system log: {log_file}")
                for event in self.parse_system_log(log_file):
                    yield event
        
        # Parse login items
        for pattern in self.ARTIFACT_PATHS['login_items']:
            for plist_file in mount_point.glob(pattern):
                self.logger.info(f"Parsing login items: {plist_file}")
                for event in self.parse_login_items(plist_file):
                    yield event
        
        # Parse quarantine events
        for pattern in self.ARTIFACT_PATHS['quarantine']:
            for quarantine_db in mount_point.glob(pattern):
                self.logger.info(f"Parsing quarantine events: {quarantine_db}")
                for event in self.parse_quarantine_events(quarantine_db):
                    yield event
        
        self.logger.info("macOS artifact parsing complete")
    
    def _cocoa_to_datetime(self, cocoa_timestamp: float) -> datetime:
        """
        Convert Cocoa/CFAbsoluteTime to Python datetime.
        
        Cocoa epoch: January 1, 2001 00:00:00 UTC
        """
        return self.COCOA_EPOCH + timedelta(seconds=cocoa_timestamp)
    
    def _extract_username_from_path(self, file_path: Path) -> str:
        """Extract username from /Users/username/... path."""
        parts = file_path.parts
        try:
            users_index = parts.index('Users')
            if users_index + 1 < len(parts):
                return parts[users_index + 1]
        except (ValueError, IndexError):
            pass
        
        return 'Unknown'


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    print("macOS Forensic Artifact Parser")
    print("=" * 60)
    print("\nSupported Artifacts:")
    print("  ✓ Shell history (bash/zsh)")
    print("  ✓ Safari browsing history")
    print("  ✓ Safari downloads")
    print("  ✓ System logs (legacy)")
    print("  ✓ Login items (persistence)")
    print("  ✓ Quarantine events (downloads)")
    print("  ⏳ Unified Logs (requires 'log show')")
    print("  ⏳ FSEvents (requires specialized parser)")
    print("  ⏳ Spotlight metadata")
    print("\nUsage:")
    print("  parser = MacOSParser()")
    print("  mount_point = Path('/Volumes/MacOS_Image')")
    print("  for event in parser.parse_all_artifacts(mount_point):")
    print("      print(event)")
    print("\n" + "=" * 60)
