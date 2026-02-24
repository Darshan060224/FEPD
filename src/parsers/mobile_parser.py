"""
Mobile Forensic Artifact Parser for Android and iOS devices.

This module provides parsers for extracting forensic artifacts from mobile device backups
and file system images. Supports SMS/MMS messages, call logs, contacts, browser history,
and application data from both Android and iOS platforms.

Supported Android Artifacts:
    - mmssms.db: SMS and MMS messages from default messaging app
    - calllog.db: Call history including incoming, outgoing, missed calls
    - contacts2.db: Contact information and address book
    - chrome_history: Chrome browser history (SQLite)
    - downloads.db: Download history
    - accounts.db: User account information

Supported iOS Artifacts:
    - sms.db: iMessage and SMS messages
    - CallHistory.storedata: Call logs with duration and status
    - AddressBook.sqlitedb: Contact information
    - History.db: Safari browsing history
    - Downloads.plist: Safari download history

Common Patterns:
    - Cocoa timestamps (iOS): Seconds since 2001-01-01 00:00:00 UTC
    - Unix timestamps (Android): Milliseconds since 1970-01-01 00:00:00 UTC
    - SQLite databases for structured data
    - Property lists (plists) for iOS configuration

Usage:
    from src.parsers.mobile_parser import MobileParser
    
    # Parse Android device
    android_parser = MobileParser(platform='android')
    for event in android_parser.parse_all_artifacts('/path/to/android/data'):
        print(event)
    
    # Parse iOS device
    ios_parser = MobileParser(platform='ios')
    for event in ios_parser.parse_all_artifacts('/path/to/ios/backup'):
        print(event)

Author: FEPD Development Team
Version: 2.0.0
"""

import sqlite3
import plistlib
import re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Iterator, List
import logging

# Configure logger
logger = logging.getLogger(__name__)


class MobileParser:
    """
    Parser for mobile device forensic artifacts from Android and iOS platforms.
    
    This parser handles both structured data (SQLite databases) and semi-structured
    data (property lists) from mobile device backups and file system images.
    
    Attributes:
        platform (str): Target platform ('android' or 'ios')
        username (str): Device owner username (if available)
        device_id (str): Device identifier (IMEI, serial number, etc.)
    """
    
    # Cocoa timestamp epoch (2001-01-01 00:00:00 UTC) used by iOS
    COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
    
    # Common Android artifact paths (relative to backup root or /data/data/)
    ANDROID_PATHS = {
        'sms': [
            'com.android.providers.telephony/databases/mmssms.db',
            'data/data/com.android.providers.telephony/databases/mmssms.db',
            'mmssms.db'
        ],
        'calls': [
            'com.android.providers.contacts/databases/calllog.db',
            'data/data/com.android.providers.contacts/databases/calllog.db',
            'calllog.db'
        ],
        'contacts': [
            'com.android.providers.contacts/databases/contacts2.db',
            'data/data/com.android.providers.contacts/databases/contacts2.db',
            'contacts2.db'
        ],
        'chrome': [
            'com.android.chrome/app_chrome/Default/History',
            'data/data/com.android.chrome/app_chrome/Default/History'
        ],
        'downloads': [
            'com.android.providers.downloads/databases/downloads.db',
            'data/data/com.android.providers.downloads/databases/downloads.db'
        ]
    }
    
    # Common iOS artifact paths (relative to backup root or /private/var/)
    IOS_PATHS = {
        'sms': [
            'Library/SMS/sms.db',
            '3d0d7e5fb2ce288813306e4d4636395e047a3d28',  # Common backup hash
            'sms.db'
        ],
        'calls': [
            'Library/CallHistoryDB/CallHistory.storedata',
            'CallHistory.storedata'
        ],
        'contacts': [
            'Library/AddressBook/AddressBook.sqlitedb',
            'AddressBook.sqlitedb'
        ],
        'safari': [
            'Library/Safari/History.db',
            'History.db'
        ],
        'safari_downloads': [
            'Library/Safari/Downloads.plist',
            'Downloads.plist'
        ]
    }
    
    def __init__(self, platform: str = 'android', username: Optional[str] = None,
                 device_id: Optional[str] = None):
        """
        Initialize mobile parser for specified platform.
        
        Args:
            platform: Target mobile platform ('android' or 'ios')
            username: Device owner username (optional)
            device_id: Device identifier for tracking (optional)
        
        Raises:
            ValueError: If platform is not 'android' or 'ios'
        """
        if platform.lower() not in ['android', 'ios']:
            raise ValueError(f"Unsupported platform: {platform}. Must be 'android' or 'ios'")
        
        self.platform = platform.lower()
        self.username = username or 'unknown_user'
        self.device_id = device_id or 'unknown_device'
        
        logger.info(f"Initialized {platform.upper()} parser for device {self.device_id}")
    
    def _convert_cocoa_timestamp(self, cocoa_time: float) -> datetime:
        """
        Convert iOS Cocoa timestamp to Python datetime.
        
        Cocoa timestamps are seconds since 2001-01-01 00:00:00 UTC (not Unix epoch).
        
        Args:
            cocoa_time: Cocoa timestamp (seconds since 2001-01-01)
        
        Returns:
            Python datetime object in UTC timezone
        """
        return self.COCOA_EPOCH + timedelta(seconds=cocoa_time)
    
    def _convert_android_timestamp(self, unix_millis: int) -> datetime:
        """
        Convert Android Unix timestamp (milliseconds) to Python datetime.
        
        Args:
            unix_millis: Unix timestamp in milliseconds
        
        Returns:
            Python datetime object in UTC timezone
        """
        return datetime.fromtimestamp(unix_millis / 1000.0, tz=timezone.utc)
    
    def _find_artifact_file(self, root_path: Path, artifact_paths: List[str]) -> Optional[Path]:
        """
        Search for artifact file using multiple possible paths.
        
        Args:
            root_path: Root directory to search from
            artifact_paths: List of possible relative paths to try
        
        Returns:
            Path object if found, None otherwise
        """
        for rel_path in artifact_paths:
            full_path = root_path / rel_path
            if full_path.exists():
                logger.debug(f"Found artifact: {full_path}")
                return full_path
        
        logger.warning(f"Could not find artifact in: {artifact_paths}")
        return None
    
    # ===========================
    # Android Parsing Methods
    # ===========================
    
    def parse_android_sms(self, db_path: Path) -> Iterator[Dict[str, Any]]:
        """
        Parse Android SMS/MMS messages from mmssms.db.
        
        Database Schema:
            - sms table: _id, address, date, body, type, read
            - Types: 1=Inbox, 2=Sent, 3=Draft, 4=Outbox, 5=Failed, 6=Queued
        
        Args:
            db_path: Path to mmssms.db SQLite database
        
        Yields:
            Event dictionaries with timestamp, description, category, details
        """
        if not db_path.exists():
            logger.error(f"Android SMS database not found: {db_path}")
            return
        
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            query = """
                SELECT _id, address, date, body, type, read, thread_id
                FROM sms
                ORDER BY date ASC
            """
            
            cursor.execute(query)
            
            # Message type mapping
            msg_types = {
                1: 'Received',
                2: 'Sent',
                3: 'Draft',
                4: 'Outbox',
                5: 'Failed',
                6: 'Queued'
            }
            
            for row in cursor.fetchall():
                msg_id, address, date_ms, body, msg_type, read_status, thread_id = row
                
                # Convert timestamp (milliseconds)
                timestamp = self._convert_android_timestamp(date_ms)
                
                # Get message type
                type_str = msg_types.get(msg_type, f'Unknown({msg_type})')
                
                # Truncate long messages
                body_preview = body[:100] + '...' if len(body) > 100 else body
                
                yield {
                    'timestamp': timestamp,
                    'category': 'Communication',
                    'description': f'SMS {type_str}: {address}',
                    'details': {
                        'message_id': msg_id,
                        'address': address,
                        'body': body,
                        'body_preview': body_preview,
                        'type': type_str,
                        'read': bool(read_status),
                        'thread_id': thread_id,
                        'platform': 'Android'
                    },
                    'source': str(db_path),
                    'user': self.username
                }
            
            conn.close()
            logger.info(f"Parsed Android SMS from {db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Error parsing Android SMS database: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing Android SMS: {e}")
    
    def parse_android_calls(self, db_path: Path) -> Iterator[Dict[str, Any]]:
        """
        Parse Android call logs from calllog.db.
        
        Database Schema:
            - calls table: _id, number, date, duration, type
            - Types: 1=Incoming, 2=Outgoing, 3=Missed, 4=Voicemail, 5=Rejected, 6=Blocked
        
        Args:
            db_path: Path to calllog.db SQLite database
        
        Yields:
            Event dictionaries with timestamp, description, category, details
        """
        if not db_path.exists():
            logger.error(f"Android call log database not found: {db_path}")
            return
        
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            query = """
                SELECT _id, number, date, duration, type, name
                FROM calls
                ORDER BY date ASC
            """
            
            cursor.execute(query)
            
            # Call type mapping
            call_types = {
                1: 'Incoming',
                2: 'Outgoing',
                3: 'Missed',
                4: 'Voicemail',
                5: 'Rejected',
                6: 'Blocked'
            }
            
            for row in cursor.fetchall():
                call_id, number, date_ms, duration, call_type, contact_name = row
                
                # Convert timestamp
                timestamp = self._convert_android_timestamp(date_ms)
                
                # Get call type
                type_str = call_types.get(call_type, f'Unknown({call_type})')
                
                # Format duration (seconds to MM:SS)
                duration_str = f"{duration // 60}m {duration % 60}s" if duration else "0s"
                
                # Use contact name if available, otherwise phone number
                display_name = contact_name if contact_name else number
                
                yield {
                    'timestamp': timestamp,
                    'category': 'Communication',
                    'description': f'Call {type_str}: {display_name}',
                    'details': {
                        'call_id': call_id,
                        'number': number,
                        'contact_name': contact_name,
                        'duration': duration,
                        'duration_formatted': duration_str,
                        'type': type_str,
                        'platform': 'Android'
                    },
                    'source': str(db_path),
                    'user': self.username
                }
            
            conn.close()
            logger.info(f"Parsed Android call logs from {db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Error parsing Android call log database: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing Android calls: {e}")
    
    def parse_android_contacts(self, db_path: Path) -> Iterator[Dict[str, Any]]:
        """
        Parse Android contacts from contacts2.db.
        
        Note: This generates events with file modification time since contacts
        don't have inherent timestamps. Consider using contact creation/modification
        times if available in the database schema.
        
        Args:
            db_path: Path to contacts2.db SQLite database
        
        Yields:
            Event dictionaries with timestamp, description, category, details
        """
        if not db_path.exists():
            logger.error(f"Android contacts database not found: {db_path}")
            return
        
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            # Complex query joining contacts with their details
            query = """
                SELECT c._id, c.display_name, 
                       GROUP_CONCAT(DISTINCT d.data1) as phone_numbers,
                       GROUP_CONCAT(DISTINCT e.data1) as emails
                FROM contacts c
                LEFT JOIN data d ON c._id = d.contact_id AND d.mimetype = 'vnd.android.cursor.item/phone_v2'
                LEFT JOIN data e ON c._id = e.contact_id AND e.mimetype = 'vnd.android.cursor.item/email_v2'
                WHERE c.display_name IS NOT NULL
                GROUP BY c._id, c.display_name
            """
            
            cursor.execute(query)
            
            # Use file modification time as timestamp (contacts don't have creation time)
            file_mtime = datetime.fromtimestamp(db_path.stat().st_mtime, tz=timezone.utc)
            
            for row in cursor.fetchall():
                contact_id, display_name, phone_numbers, emails = row
                
                # Parse phone numbers and emails
                phones = phone_numbers.split(',') if phone_numbers else []
                email_list = emails.split(',') if emails else []
                
                yield {
                    'timestamp': file_mtime,
                    'category': 'Data Export',
                    'description': f'Contact: {display_name}',
                    'details': {
                        'contact_id': contact_id,
                        'name': display_name,
                        'phone_numbers': phones,
                        'emails': email_list,
                        'platform': 'Android',
                        'note': 'Timestamp is file modification time (contacts lack creation dates)'
                    },
                    'source': str(db_path),
                    'user': self.username
                }
            
            conn.close()
            logger.info(f"Parsed Android contacts from {db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Error parsing Android contacts database: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing Android contacts: {e}")
    
    def parse_android_chrome_history(self, db_path: Path) -> Iterator[Dict[str, Any]]:
        """
        Parse Android Chrome browser history.
        
        Database Schema:
            - urls table: id, url, title, visit_count, last_visit_time
            - visits table: id, url, visit_time
        
        Args:
            db_path: Path to Chrome History SQLite database
        
        Yields:
            Event dictionaries with timestamp, description, category, details
        """
        if not db_path.exists():
            logger.error(f"Android Chrome history database not found: {db_path}")
            return
        
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            query = """
                SELECT v.id, v.url, u.title, v.visit_time, u.visit_count
                FROM visits v
                JOIN urls u ON v.url = u.id
                ORDER BY v.visit_time ASC
            """
            
            cursor.execute(query)
            
            for row in cursor.fetchall():
                visit_id, url_id, title, visit_time, visit_count = row
                
                # Chrome timestamps: microseconds since 1601-01-01 (Windows epoch)
                # Convert to Unix timestamp
                unix_timestamp = (visit_time - 11644473600000000) / 1000000
                timestamp = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
                
                # Extract domain
                domain_match = re.search(r'https?://([^/]+)', str(url_id))
                domain = domain_match.group(1) if domain_match else 'unknown'
                
                yield {
                    'timestamp': timestamp,
                    'category': 'Web Activity',
                    'description': f'Chrome: {title or domain}',
                    'details': {
                        'visit_id': visit_id,
                        'url': url_id,
                        'title': title,
                        'domain': domain,
                        'visit_count': visit_count,
                        'platform': 'Android',
                        'browser': 'Chrome'
                    },
                    'source': str(db_path),
                    'user': self.username
                }
            
            conn.close()
            logger.info(f"Parsed Android Chrome history from {db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Error parsing Android Chrome history: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing Android Chrome history: {e}")
    
    # ===========================
    # iOS Parsing Methods
    # ===========================
    
    def parse_ios_sms(self, db_path: Path) -> Iterator[Dict[str, Any]]:
        """
        Parse iOS SMS and iMessage from sms.db.
        
        Database Schema:
            - message table: ROWID, address, date, text, is_from_me, service
            - Services: 'SMS' or 'iMessage'
        
        Args:
            db_path: Path to sms.db SQLite database
        
        Yields:
            Event dictionaries with timestamp, description, category, details
        """
        if not db_path.exists():
            logger.error(f"iOS SMS database not found: {db_path}")
            return
        
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            query = """
                SELECT ROWID, address, date, text, is_from_me, service, cache_has_attachments
                FROM message
                ORDER BY date ASC
            """
            
            cursor.execute(query)
            
            for row in cursor.fetchall():
                msg_id, address, cocoa_date, text, is_from_me, service, has_attachments = row
                
                # Convert Cocoa timestamp
                timestamp = self._convert_cocoa_timestamp(cocoa_date)
                
                # Direction
                direction = 'Sent' if is_from_me else 'Received'
                
                # Service type (iMessage or SMS)
                service_type = service if service else 'SMS'
                
                # Truncate long messages
                text_preview = text[:100] + '...' if text and len(text) > 100 else text
                
                yield {
                    'timestamp': timestamp,
                    'category': 'Communication',
                    'description': f'{service_type} {direction}: {address}',
                    'details': {
                        'message_id': msg_id,
                        'address': address,
                        'text': text,
                        'text_preview': text_preview,
                        'direction': direction,
                        'service': service_type,
                        'has_attachments': bool(has_attachments),
                        'platform': 'iOS'
                    },
                    'source': str(db_path),
                    'user': self.username
                }
            
            conn.close()
            logger.info(f"Parsed iOS SMS from {db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Error parsing iOS SMS database: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing iOS SMS: {e}")
    
    def parse_ios_calls(self, db_path: Path) -> Iterator[Dict[str, Any]]:
        """
        Parse iOS call history from CallHistory.storedata.
        
        Database Schema:
            - ZCALLRECORD table: Z_PK, ZADDRESS, ZDATE, ZDURATION, ZCALLTYPE
            - Call types: Varies by iOS version, typically numeric codes
        
        Args:
            db_path: Path to CallHistory.storedata SQLite database
        
        Yields:
            Event dictionaries with timestamp, description, category, details
        """
        if not db_path.exists():
            logger.error(f"iOS call history database not found: {db_path}")
            return
        
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            # Query varies by iOS version, try common schema
            query = """
                SELECT Z_PK, ZADDRESS, ZDATE, ZDURATION, ZCALLTYPE, ZANSWERED
                FROM ZCALLRECORD
                ORDER BY ZDATE ASC
            """
            
            cursor.execute(query)
            
            # Call type mapping (may vary by iOS version)
            call_types = {
                1: 'Outgoing',
                2: 'Incoming',
                3: 'Missed',
                4: 'FaceTime Audio',
                5: 'FaceTime Video'
            }
            
            for row in cursor.fetchall():
                call_id, address, cocoa_date, duration, call_type, answered = row
                
                # Convert Cocoa timestamp
                timestamp = self._convert_cocoa_timestamp(cocoa_date)
                
                # Get call type
                type_str = call_types.get(call_type, f'Unknown({call_type})')
                
                # Format duration
                duration_str = f"{int(duration) // 60}m {int(duration) % 60}s" if duration else "0s"
                
                # Determine status
                if not answered:
                    type_str = 'Missed'
                
                yield {
                    'timestamp': timestamp,
                    'category': 'Communication',
                    'description': f'Call {type_str}: {address}',
                    'details': {
                        'call_id': call_id,
                        'address': address,
                        'duration': duration,
                        'duration_formatted': duration_str,
                        'type': type_str,
                        'answered': bool(answered),
                        'platform': 'iOS'
                    },
                    'source': str(db_path),
                    'user': self.username
                }
            
            conn.close()
            logger.info(f"Parsed iOS call history from {db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Error parsing iOS call history database: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing iOS calls: {e}")
    
    def parse_ios_contacts(self, db_path: Path) -> Iterator[Dict[str, Any]]:
        """
        Parse iOS contacts from AddressBook.sqlitedb.
        
        Database Schema:
            - ABPerson table: ROWID, First, Last, Organization
            - ABMultiValue table: record_id, value (for phones/emails)
        
        Args:
            db_path: Path to AddressBook.sqlitedb SQLite database
        
        Yields:
            Event dictionaries with timestamp, description, category, details
        """
        if not db_path.exists():
            logger.error(f"iOS contacts database not found: {db_path}")
            return
        
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            query = """
                SELECT p.ROWID, p.First, p.Last, p.Organization,
                       GROUP_CONCAT(DISTINCT mv.value) as contact_values
                FROM ABPerson p
                LEFT JOIN ABMultiValue mv ON p.ROWID = mv.record_id
                GROUP BY p.ROWID
            """
            
            cursor.execute(query)
            
            # Use file modification time
            file_mtime = datetime.fromtimestamp(db_path.stat().st_mtime, tz=timezone.utc)
            
            for row in cursor.fetchall():
                contact_id, first_name, last_name, organization, contact_values = row
                
                # Build display name
                name_parts = [first_name, last_name]
                display_name = ' '.join([n for n in name_parts if n])
                if not display_name:
                    display_name = organization or f'Contact {contact_id}'
                
                # Parse contact values (phones, emails mixed)
                values = contact_values.split(',') if contact_values else []
                
                yield {
                    'timestamp': file_mtime,
                    'category': 'Data Export',
                    'description': f'Contact: {display_name}',
                    'details': {
                        'contact_id': contact_id,
                        'first_name': first_name,
                        'last_name': last_name,
                        'organization': organization,
                        'contact_values': values,
                        'platform': 'iOS',
                        'note': 'Timestamp is file modification time'
                    },
                    'source': str(db_path),
                    'user': self.username
                }
            
            conn.close()
            logger.info(f"Parsed iOS contacts from {db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Error parsing iOS contacts database: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing iOS contacts: {e}")
    
    def parse_ios_safari_history(self, db_path: Path) -> Iterator[Dict[str, Any]]:
        """
        Parse iOS Safari browser history from History.db.
        
        Database Schema:
            - history_visits table: id, history_item, visit_time
            - history_items table: id, url, domain_expansion, visit_count
        
        Args:
            db_path: Path to Safari History.db SQLite database
        
        Yields:
            Event dictionaries with timestamp, description, category, details
        """
        if not db_path.exists():
            logger.error(f"iOS Safari history database not found: {db_path}")
            return
        
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            query = """
                SELECT hv.id, hi.url, hi.domain_expansion, hv.visit_time, hi.visit_count, hi.title
                FROM history_visits hv
                JOIN history_items hi ON hv.history_item = hi.id
                ORDER BY hv.visit_time ASC
            """
            
            cursor.execute(query)
            
            for row in cursor.fetchall():
                visit_id, url, domain, cocoa_time, visit_count, title = row
                
                # Convert Cocoa timestamp
                timestamp = self._convert_cocoa_timestamp(cocoa_time)
                
                yield {
                    'timestamp': timestamp,
                    'category': 'Web Activity',
                    'description': f'Safari: {title or domain}',
                    'details': {
                        'visit_id': visit_id,
                        'url': url,
                        'title': title,
                        'domain': domain,
                        'visit_count': visit_count,
                        'platform': 'iOS',
                        'browser': 'Safari'
                    },
                    'source': str(db_path),
                    'user': self.username
                }
            
            conn.close()
            logger.info(f"Parsed iOS Safari history from {db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Error parsing iOS Safari history: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing iOS Safari history: {e}")
    
    def parse_ios_safari_downloads(self, plist_path: Path) -> Iterator[Dict[str, Any]]:
        """
        Parse iOS Safari download history from Downloads.plist.
        
        Plist Structure:
            - DownloadHistory array containing dictionaries with:
              - DownloadEntryURL, DownloadEntryPath, DownloadEntryDateAddedKey
        
        Args:
            plist_path: Path to Safari Downloads.plist file
        
        Yields:
            Event dictionaries with timestamp, description, category, details
        """
        if not plist_path.exists():
            logger.error(f"iOS Safari downloads plist not found: {plist_path}")
            return
        
        try:
            with open(plist_path, 'rb') as f:
                plist_data = plistlib.load(f)
            
            download_history = plist_data.get('DownloadHistory', [])
            
            for entry in download_history:
                url = entry.get('DownloadEntryURL', 'Unknown URL')
                path = entry.get('DownloadEntryPath', 'Unknown path')
                date_added = entry.get('DownloadEntryDateAddedKey')
                
                # Date may be Cocoa timestamp or datetime object
                if isinstance(date_added, (int, float)):
                    timestamp = self._convert_cocoa_timestamp(date_added)
                elif isinstance(date_added, datetime):
                    timestamp = date_added
                else:
                    # Fallback to file modification time
                    timestamp = datetime.fromtimestamp(plist_path.stat().st_mtime, tz=timezone.utc)
                
                # Extract filename from path
                filename = Path(path).name if path else 'Unknown file'
                
                yield {
                    'timestamp': timestamp,
                    'category': 'File Activity',
                    'description': f'Safari Download: {filename}',
                    'details': {
                        'url': url,
                        'path': path,
                        'filename': filename,
                        'platform': 'iOS',
                        'browser': 'Safari'
                    },
                    'source': str(plist_path),
                    'user': self.username
                }
            
            logger.info(f"Parsed iOS Safari downloads from {plist_path}")
            
        except Exception as e:
            logger.error(f"Error parsing iOS Safari downloads plist: {e}")
    
    # ===========================
    # Unified Interface
    # ===========================
    
    def parse_all_artifacts(self, root_path: str) -> Iterator[Dict[str, Any]]:
        """
        Parse all available mobile artifacts from root directory.
        
        This method automatically detects and parses all supported artifacts
        based on the initialized platform (Android or iOS).
        
        Args:
            root_path: Root directory of mobile device backup or file system
        
        Yields:
            Event dictionaries from all found artifacts
        
        Example:
            parser = MobileParser(platform='android')
            for event in parser.parse_all_artifacts('/data/android_backup'):
                print(f"{event['timestamp']}: {event['description']}")
        """
        root = Path(root_path)
        
        if not root.exists():
            logger.error(f"Root path does not exist: {root_path}")
            return
        
        logger.info(f"Starting {self.platform.upper()} artifact parsing from {root_path}")
        
        if self.platform == 'android':
            # Parse Android artifacts
            paths = self.ANDROID_PATHS
            
            # SMS/MMS
            sms_db = self._find_artifact_file(root, paths['sms'])
            if sms_db:
                yield from self.parse_android_sms(sms_db)
            
            # Call logs
            calls_db = self._find_artifact_file(root, paths['calls'])
            if calls_db:
                yield from self.parse_android_calls(calls_db)
            
            # Contacts
            contacts_db = self._find_artifact_file(root, paths['contacts'])
            if contacts_db:
                yield from self.parse_android_contacts(contacts_db)
            
            # Chrome history
            chrome_db = self._find_artifact_file(root, paths['chrome'])
            if chrome_db:
                yield from self.parse_android_chrome_history(chrome_db)
        
        elif self.platform == 'ios':
            # Parse iOS artifacts
            paths = self.IOS_PATHS
            
            # SMS/iMessage
            sms_db = self._find_artifact_file(root, paths['sms'])
            if sms_db:
                yield from self.parse_ios_sms(sms_db)
            
            # Call history
            calls_db = self._find_artifact_file(root, paths['calls'])
            if calls_db:
                yield from self.parse_ios_calls(calls_db)
            
            # Contacts
            contacts_db = self._find_artifact_file(root, paths['contacts'])
            if contacts_db:
                yield from self.parse_ios_contacts(contacts_db)
            
            # Safari history
            safari_db = self._find_artifact_file(root, paths['safari'])
            if safari_db:
                yield from self.parse_ios_safari_history(safari_db)
            
            # Safari downloads
            downloads_plist = self._find_artifact_file(root, paths['safari_downloads'])
            if downloads_plist:
                yield from self.parse_ios_safari_downloads(downloads_plist)
        
        logger.info(f"Completed {self.platform.upper()} artifact parsing")


# Standalone helper functions
def generate_mobile_timeline(root_path: str, platform: str, 
                             output_format: str = 'csv') -> List[Dict[str, Any]]:
    """
    Generate a complete mobile device timeline from artifacts.
    
    Convenience function for quickly generating timelines without managing parser objects.
    
    Args:
        root_path: Root directory of mobile backup
        platform: 'android' or 'ios'
        output_format: Format for export ('csv', 'json', or 'dict')
    
    Returns:
        List of event dictionaries sorted by timestamp
    
    Example:
        events = generate_mobile_timeline('/data/ios_backup', 'ios')
        for event in events[:10]:  # First 10 events
            print(f"{event['timestamp']}: {event['description']}")
    """
    parser = MobileParser(platform=platform)
    events = list(parser.parse_all_artifacts(root_path))
    
    # Sort by timestamp
    events.sort(key=lambda x: x['timestamp'])
    
    if output_format == 'csv':
        # Flatten for CSV export
        import csv
        import io
        output = io.StringIO()
        if events:
            fieldnames = ['timestamp', 'category', 'description', 'source', 'user']
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for event in events:
                writer.writerow({k: event.get(k, '') for k in fieldnames})
        return output.getvalue()
    
    elif output_format == 'json':
        import json
        # Convert datetime objects to ISO format strings
        for event in events:
            event['timestamp'] = event['timestamp'].isoformat()
        return json.dumps(events, indent=2)
    
    else:  # dict
        return events
