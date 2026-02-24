"""
Memory Analysis Database Handler

Stores and retrieves memory dump analysis results for FEPD Terminal commands.
Provides simple JSON-based storage for memory artifacts.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime


class MemoryDatabaseHandler:
    """
    Simple JSON-based database for memory analysis artifacts.
    
    Stores:
    - Memory dump metadata
    - Extracted processes
    - Network connections
    - URLs and strings
    - Registry keys
    """
    
    def __init__(self, case_workspace: Path, logger: Optional[logging.Logger] = None):
        """
        Initialize memory database handler.
        
        Args:
            case_workspace: Case workspace directory
            logger: Optional logger instance
        """
        self.case_workspace = Path(case_workspace)
        self.logger = logger or logging.getLogger(__name__)
        
        # Database file
        self.db_file = self.case_workspace / "memory_analysis" / "memory_artifacts.json"
        
        # Initialize database structure
        self.data = {
            "memory_dumps": [],
            "processes": [],
            "network_connections": [],
            "urls": [],
            "registry_keys": [],
            "strings": [],
            "metadata": {
                "created": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat()
            }
        }
        
        # Load existing database if available
        if self.db_file.exists():
            try:
                with open(self.db_file, 'r') as f:
                    self.data = json.load(f)
                self.logger.info(f"Loaded memory database: {self.db_file}")
            except Exception as e:
                self.logger.warning(f"Failed to load memory database: {e}")
    
    def add_memory_dump(self, dump_info: Dict[str, Any]) -> None:
        """
        Add memory dump metadata and artifacts.
        
        Args:
            dump_info: Dictionary with dump metadata
                {
                    'path': str,
                    'size_bytes': int,
                    'processes': List[str],
                    'network': List[str],
                    'analysis_time': str
                }
        """
        # Extract processes
        for proc in dump_info.get('processes', []):
            self.data['processes'].append({
                'name': proc,
                'source': 'memory_dump',
                'timestamp': dump_info.get('analysis_time', datetime.now().isoformat())
            })
        
        # Extract network connections
        for ip in dump_info.get('network', []):
            self.data['network_connections'].append({
                'ip': ip,
                'source': 'memory_dump',
                'timestamp': dump_info.get('analysis_time', datetime.now().isoformat())
            })
        
        # Store dump metadata
        self.data['memory_dumps'].append({
            'path': dump_info.get('path'),
            'size_bytes': dump_info.get('size_bytes'),
            'process_count': len(dump_info.get('processes', [])),
            'network_count': len(dump_info.get('network', [])),
            'analysis_time': dump_info.get('analysis_time')
        })
        
        # Update metadata
        self.data['metadata']['last_updated'] = datetime.now().isoformat()
        
        # Save to disk
        self._save()
        
        self.logger.info(f"Added memory dump: {len(dump_info.get('processes', []))} processes, "
                        f"{len(dump_info.get('network', []))} IPs")
    
    def get_processes(self) -> List[Dict[str, str]]:
        """
        Get all processes from memory analysis.
        
        Returns:
            List of process dictionaries
        """
        return self.data.get('processes', [])
    
    def get_network_connections(self) -> List[Dict[str, str]]:
        """
        Get all network connections from memory analysis.
        
        Returns:
            List of network connection dictionaries
        """
        return self.data.get('network_connections', [])
    
    def get_urls(self) -> List[Dict[str, str]]:
        """
        Get all URLs from memory analysis.
        
        Returns:
            List of URL dictionaries
        """
        return self.data.get('urls', [])
    
    def get_registry_keys(self) -> List[Dict[str, str]]:
        """
        Get all registry keys from memory analysis.
        
        Returns:
            List of registry key dictionaries
        """
        return self.data.get('registry_keys', [])
    
    def get_memory_dumps(self) -> List[Dict[str, Any]]:
        """
        Get metadata for all analyzed memory dumps.
        
        Returns:
            List of memory dump metadata dictionaries
        """
        return self.data.get('memory_dumps', [])
    
    def _save(self) -> None:
        """Save database to disk."""
        try:
            # Create directory if needed
            self.db_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write JSON
            with open(self.db_file, 'w') as f:
                json.dump(self.data, f, indent=2)
            
            self.logger.debug(f"Memory database saved: {self.db_file}")
        
        except Exception as e:
            self.logger.error(f"Failed to save memory database: {e}")
    
    def clear(self) -> None:
        """Clear all database entries (keeps structure)."""
        self.data = {
            "memory_dumps": [],
            "processes": [],
            "network_connections": [],
            "urls": [],
            "registry_keys": [],
            "strings": [],
            "metadata": {
                "created": self.data['metadata']['created'],
                "last_updated": datetime.now().isoformat(),
                "cleared": datetime.now().isoformat()
            }
        }
        self._save()
        self.logger.info("Memory database cleared")
