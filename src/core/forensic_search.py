"""
Advanced Forensic Search Query Parser
======================================

Supports forensic search syntax:
- ext:exe              All executables
- size:>10MB           Large files
- owner:Alice          Files owned by user
- hash:abcd...         Find by hash
- deleted:true         Deleted files
- modified:<2026-01-01 Date filters
- name:"sensitive"     Filename contains

Copyright (c) 2026 FEPD Development Team
"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime
import re
import logging

logger = logging.getLogger(__name__)


@dataclass
class SearchQuery:
    """Parsed forensic search query."""
    
    # File filters
    extensions: List[str]           # ['exe', 'dll']
    size_min: Optional[int]         # Bytes
    size_max: Optional[int]         # Bytes
    owner: Optional[str]            # Username
    hash_pattern: Optional[str]     # SHA256 prefix
    name_pattern: Optional[str]     # Filename contains
    
    # Temporal filters
    modified_before: Optional[datetime]
    modified_after: Optional[datetime]
    created_before: Optional[datetime]
    created_after: Optional[datetime]
    
    # Forensic filters
    deleted_only: bool
    orphaned_only: bool
    flagged_by_ml: bool
    
    # Risk filters
    risk_level: Optional[str]       # 'high', 'medium', 'low'
    
    def __post_init__(self):
        """Normalize query values."""
        # Normalize extensions to lowercase
        self.extensions = [ext.lower().lstrip('.') for ext in self.extensions]


class ForensicSearchParser:
    """
    Parse advanced forensic search queries.
    
    Usage:
        parser = ForensicSearchParser()
        query = parser.parse("ext:exe size:>5MB deleted:true")
        results = veos.search(query)
    """
    
    # Size multipliers
    SIZE_MULTIPLIERS = {
        'b': 1,
        'kb': 1024,
        'mb': 1024 ** 2,
        'gb': 1024 ** 3,
        'tb': 1024 ** 4,
    }
    
    def parse(self, query_string: str) -> SearchQuery:
        """
        Parse a forensic search query string.
        
        Args:
            query_string: Search query (e.g., "ext:exe size:>10MB owner:Alice")
            
        Returns:
            Parsed SearchQuery object
        """
        # Initialize query with defaults
        query = SearchQuery(
            extensions=[],
            size_min=None,
            size_max=None,
            owner=None,
            hash_pattern=None,
            name_pattern=None,
            modified_before=None,
            modified_after=None,
            created_before=None,
            created_after=None,
            deleted_only=False,
            orphaned_only=False,
            flagged_by_ml=False,
            risk_level=None
        )
        
        # Split query into tokens
        tokens = self._tokenize(query_string)
        
        for token in tokens:
            self._parse_token(token, query)
        
        logger.debug(f"Parsed query: {query}")
        return query
    
    def _tokenize(self, query_string: str) -> List[str]:
        """
        Split query into tokens, respecting quoted strings.
        
        Example:
            'ext:exe name:"my file.txt" size:>10MB'
            -> ['ext:exe', 'name:"my file.txt"', 'size:>10MB']
        """
        tokens = []
        current_token = ""
        in_quotes = False
        
        for char in query_string:
            if char == '"':
                in_quotes = not in_quotes
                current_token += char
            elif char == ' ' and not in_quotes:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            else:
                current_token += char
        
        if current_token:
            tokens.append(current_token)
        
        return tokens
    
    def _parse_token(self, token: str, query: SearchQuery):
        """Parse a single search token and update query."""
        
        if ':' not in token:
            # Treat as name pattern
            query.name_pattern = token.strip('"')
            return
        
        key, value = token.split(':', 1)
        key = key.lower()
        
        # Extension filter
        if key == 'ext':
            query.extensions.append(value.lower())
        
        # Size filter
        elif key == 'size':
            self._parse_size_filter(value, query)
        
        # Owner filter
        elif key == 'owner':
            query.owner = value.strip('"')
        
        # Hash filter
        elif key == 'hash':
            query.hash_pattern = value.lower()
        
        # Name filter
        elif key == 'name':
            query.name_pattern = value.strip('"')
        
        # Date filters
        elif key == 'modified':
            self._parse_date_filter(value, query, 'modified')
        
        elif key == 'created':
            self._parse_date_filter(value, query, 'created')
        
        # Boolean filters
        elif key == 'deleted':
            query.deleted_only = value.lower() in ('true', '1', 'yes')
        
        elif key == 'orphaned':
            query.orphaned_only = value.lower() in ('true', '1', 'yes')
        
        elif key == 'flagged':
            query.flagged_by_ml = value.lower() in ('true', '1', 'yes')
        
        # Risk level
        elif key == 'risk':
            if value.lower() in ('high', 'medium', 'low'):
                query.risk_level = value.lower()
        
        else:
            logger.warning(f"Unknown search key: {key}")
    
    def _parse_size_filter(self, value: str, query: SearchQuery):
        """
        Parse size filter: >10MB, <5GB, 100KB
        
        Operators: >, <, >=, <=, =
        """
        # Extract operator
        operator = None
        if value.startswith('>='):
            operator = '>='
            value = value[2:]
        elif value.startswith('<='):
            operator = '<='
            value = value[2:]
        elif value.startswith('>'):
            operator = '>'
            value = value[1:]
        elif value.startswith('<'):
            operator = '<'
            value = value[1:]
        else:
            operator = '='
        
        # Parse size value
        size_bytes = self._parse_size_value(value)
        
        if size_bytes is None:
            logger.warning(f"Invalid size value: {value}")
            return
        
        # Apply operator
        if operator in ('>', '>='):
            query.size_min = size_bytes
        elif operator in ('<', '<='):
            query.size_max = size_bytes
        else:  # =
            query.size_min = size_bytes
            query.size_max = size_bytes
    
    def _parse_size_value(self, value: str) -> Optional[int]:
        """
        Parse size value: 10MB, 5.5GB, 100KB
        
        Returns:
            Size in bytes or None if invalid
        """
        # Extract number and unit
        match = re.match(r'([0-9.]+)\s*([a-zA-Z]+)?', value)
        if not match:
            return None
        
        number_str, unit = match.groups()
        
        try:
            number = float(number_str)
        except ValueError:
            return None
        
        # Default to bytes if no unit
        if not unit:
            return int(number)
        
        unit = unit.lower()
        multiplier = self.SIZE_MULTIPLIERS.get(unit, 1)
        
        return int(number * multiplier)
    
    def _parse_date_filter(self, value: str, query: SearchQuery, field: str):
        """
        Parse date filter: <2026-01-01, >2025-12-15
        
        Operators: <, >, =
        """
        # Extract operator
        operator = None
        if value.startswith('>'):
            operator = '>'
            value = value[1:]
        elif value.startswith('<'):
            operator = '<'
            value = value[1:]
        else:
            operator = '='
        
        # Parse date
        try:
            date = datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            logger.warning(f"Invalid date format: {value}")
            return
        
        # Apply operator
        if field == 'modified':
            if operator == '>':
                query.modified_after = date
            elif operator == '<':
                query.modified_before = date
        
        elif field == 'created':
            if operator == '>':
                query.created_after = date
            elif operator == '<':
                query.created_before = date


class SearchQueryExecutor:
    """
    Execute parsed search queries against VEOS.
    
    Usage:
        executor = SearchQueryExecutor(veos)
        results = executor.execute(query)
    """
    
    def __init__(self, vfs, mft_parser=None):
        """
        Initialize search executor.
        
        Args:
            vfs: VirtualFilesystem instance
            mft_parser: MFTParser instance for deleted file search
        """
        self.vfs = vfs
        self.mft_parser = mft_parser
    
    def execute(self, query: SearchQuery, root_path: str = "/") -> List[Dict[str, Any]]:
        """
        Execute search query and return matching files.
        
        Args:
            query: Parsed SearchQuery object
            root_path: Root path to search from
            
        Returns:
            List of file metadata dictionaries
        """
        results = []
        
        try:
            # Include deleted files if requested
            if query.deleted_only or query.orphaned_only:
                results.extend(self._search_deleted_files(query))
            else:
                # Standard filesystem search
                results.extend(self._search_active_files(query, root_path))
            
            logger.info(f"Search returned {len(results)} results")
            
        except Exception as e:
            logger.error(f"Search execution failed: {e}")
        
        return results
    
    def _search_active_files(self, query: SearchQuery, root_path: str) -> List[Dict[str, Any]]:
        """Search active (non-deleted) files."""
        results = []
        
        # Walk filesystem
        try:
            root_node = self.vfs.get_node(root_path)
            if not root_node:
                return results
            
            # Recursive walk
            self._walk_and_filter(root_node, query, results)
            
        except Exception as e:
            logger.error(f"Active file search failed: {e}")
        
        return results
    
    def _search_deleted_files(self, query: SearchQuery) -> List[Dict[str, Any]]:
        """Search deleted/orphaned files via MFT parser."""
        if not self.mft_parser:
            logger.warning("MFT parser not available for deleted file search")
            return []
        
        results = []
        
        try:
            if query.deleted_only:
                deleted_entries = self.mft_parser.scan_deleted_files()
                results.extend([self._mft_entry_to_dict(e) for e in deleted_entries])
            
            if query.orphaned_only:
                orphaned_entries = self.mft_parser.scan_orphaned_entries()
                results.extend([self._mft_entry_to_dict(e) for e in orphaned_entries])
            
        except Exception as e:
            logger.error(f"Deleted file search failed: {e}")
        
        return results
    
    def _walk_and_filter(self, node, query: SearchQuery, results: List[Dict[str, Any]]):
        """Recursively walk filesystem and filter files."""
        # Filter current node
        if self._matches_query(node, query):
            results.append({
                'path': node.path,
                'name': node.name,
                'size': node.size,
                'modified': node.modified_time,
                'is_deleted': False,
                'is_directory': node.is_directory
            })
        
        # Recurse into directories
        if node.is_directory and hasattr(node, 'children'):
            for child in node.children:
                self._walk_and_filter(child, query, results)
    
    def _matches_query(self, node, query: SearchQuery) -> bool:
        """Check if a file node matches the search query."""
        
        # Extension filter
        if query.extensions:
            ext = node.name.rsplit('.', 1)[-1].lower() if '.' in node.name else ''
            if ext not in query.extensions:
                return False
        
        # Size filter
        if query.size_min is not None and node.size < query.size_min:
            return False
        if query.size_max is not None and node.size > query.size_max:
            return False
        
        # Name filter
        if query.name_pattern:
            if query.name_pattern.lower() not in node.name.lower():
                return False
        
        # Date filters
        if query.modified_before and node.modified_time > query.modified_before:
            return False
        if query.modified_after and node.modified_time < query.modified_after:
            return False
        
        return True
    
    def _mft_entry_to_dict(self, entry) -> Dict[str, Any]:
        """Convert MFTEntry to search result dictionary."""
        return {
            'path': entry.full_path or f"[Orphaned MFT Entry {entry.record_number}]",
            'name': entry.filename,
            'size': entry.size,
            'modified': entry.modified_time,
            'is_deleted': entry.is_deleted,
            'is_orphaned': entry.is_orphaned,
            'deletion_time': entry.deletion_time,
            'confidence': entry.confidence,
            'sector_offset': entry.sector_offset
        }
