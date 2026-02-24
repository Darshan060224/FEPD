"""
FEPD - Evidence Relationship Analyzer
Detects relationships between multiple evidence files and combines their data.

This module handles:
1. Relationship Detection between multiple evidence files
   - Same case/investigation correlation
   - Disk + Memory correlation
   - Timeline overlap detection
   - Device/user relationship identification
   
2. Data Combination & Unification
   - Merges artifacts from related evidence
   - Cross-references events across sources
   - Builds unified timeline from all sources
   - Correlates findings for comprehensive analysis

3. Backend Processing
   - Automatic relationship detection on evidence selection
   - Parallel extraction from multiple sources
   - Unified data store for all UI tabs

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

from __future__ import annotations

import os
import re
import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


class EvidenceRelationType(Enum):
    """Types of relationships between evidence files."""
    SAME_DEVICE = "same_device"           # Same physical device (disk + memory)
    SAME_CASE = "same_case"               # Same investigation case
    SAME_USER = "same_user"               # Same user across devices
    TIMELINE_OVERLAP = "timeline_overlap"  # Overlapping time periods
    NETWORK_RELATED = "network_related"    # Network connection between devices
    MULTIPART_SET = "multipart_set"        # Multi-part forensic image (E01+E02)
    UNKNOWN = "unknown"                    # No detected relationship


class EvidenceSourceType(Enum):
    """Types of evidence sources."""
    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    NETWORK_CAPTURE = "network_capture"
    MOBILE_BACKUP = "mobile_backup"
    LOG_FILE = "log_file"
    ARCHIVE = "archive"
    UNKNOWN = "unknown"


@dataclass
class EvidenceMetadata:
    """Metadata extracted from an evidence file for relationship analysis."""
    evidence_id: str
    file_path: Path
    source_type: EvidenceSourceType
    
    # Identifiers for correlation
    device_name: Optional[str] = None
    device_serial: Optional[str] = None
    mac_addresses: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    
    # User information
    usernames: List[str] = field(default_factory=list)
    user_sids: List[str] = field(default_factory=list)
    
    # Temporal information
    earliest_timestamp: Optional[datetime] = None
    latest_timestamp: Optional[datetime] = None
    
    # System information
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    hostname: Optional[str] = None
    
    # Hash for deduplication
    content_hash: Optional[str] = None
    
    # Extracted data references
    artifacts_path: Optional[Path] = None
    events_path: Optional[Path] = None


@dataclass
class EvidenceRelationship:
    """Represents a detected relationship between two evidence sources."""
    source_id: str
    target_id: str
    relation_type: EvidenceRelationType
    confidence: float  # 0.0 - 1.0
    correlation_factors: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class CombinedEvidenceSet:
    """
    Represents a combined set of related evidence with unified data.
    """
    set_id: str
    evidence_items: List[EvidenceMetadata] = field(default_factory=list)
    relationships: List[EvidenceRelationship] = field(default_factory=list)
    
    # Unified data paths
    unified_events_path: Optional[Path] = None
    unified_timeline_path: Optional[Path] = None
    unified_artifacts_path: Optional[Path] = None
    
    # Combined statistics
    total_events: int = 0
    total_artifacts: int = 0
    total_anomalies: int = 0
    
    # Correlation results
    cross_referenced_events: int = 0
    correlated_users: List[str] = field(default_factory=list)
    correlated_devices: List[str] = field(default_factory=list)
    timeline_span: Optional[Tuple[datetime, datetime]] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            'set_id': self.set_id,
            'evidence_count': len(self.evidence_items),
            'evidence_items': [
                {
                    'id': e.evidence_id,
                    'path': str(e.file_path),
                    'type': e.source_type.value,
                    'device': e.device_name,
                    'hostname': e.hostname
                }
                for e in self.evidence_items
            ],
            'relationships': [
                {
                    'source': r.source_id,
                    'target': r.target_id,
                    'type': r.relation_type.value,
                    'confidence': r.confidence,
                    'factors': r.correlation_factors
                }
                for r in self.relationships
            ],
            'total_events': self.total_events,
            'total_artifacts': self.total_artifacts,
            'cross_referenced_events': self.cross_referenced_events,
            'correlated_users': self.correlated_users,
            'correlated_devices': self.correlated_devices
        }


class EvidenceRelationshipAnalyzer:
    """
    Analyzes multiple evidence files to detect relationships and correlations.
    
    Automatically identifies:
    - Evidence from the same device (disk + memory)
    - Evidence from the same user across devices
    - Evidence with overlapping timelines
    - Multi-part forensic images
    - Network-related devices
    """
    
    def __init__(self, case_path: Optional[Path] = None):
        """
        Initialize the relationship analyzer.
        
        Args:
            case_path: Path to case workspace for storing combined data
        """
        self.logger = logging.getLogger(__name__)
        self.case_path = case_path
        
        # Multi-part patterns
        self.multipart_patterns = {
            'E01': re.compile(r'^(.+)\.E(\d{2})$', re.IGNORECASE),
            'L01': re.compile(r'^(.+)\.L(\d{2})$', re.IGNORECASE),
            '001': re.compile(r'^(.+)\.(\d{3})$'),
        }
        
        # Cache for extracted metadata
        self._metadata_cache: Dict[str, EvidenceMetadata] = {}
    
    def analyze_evidence_set(
        self,
        evidence_paths: List[Path],
        extract_metadata: bool = True
    ) -> CombinedEvidenceSet:
        """
        Analyze multiple evidence files to detect relationships.
        
        This is the main entry point called when user selects multiple evidence files.
        
        Args:
            evidence_paths: List of evidence file paths
            extract_metadata: Whether to extract metadata from evidence
            
        Returns:
            CombinedEvidenceSet with detected relationships
        """
        self.logger.info(f"Analyzing {len(evidence_paths)} evidence files for relationships...")
        
        # Create combined set
        set_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        combined_set = CombinedEvidenceSet(set_id=set_id)
        
        # Step 1: Check for multi-part sets first
        multipart_groups = self._detect_multipart_sets(evidence_paths)
        
        # Step 2: Extract metadata from each evidence source
        metadata_list = []
        
        if extract_metadata:
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(self._extract_evidence_metadata, path): path
                    for path in evidence_paths
                }
                
                for future in as_completed(futures):
                    path = futures[future]
                    try:
                        metadata = future.result()
                        if metadata:
                            metadata_list.append(metadata)
                            self._metadata_cache[metadata.evidence_id] = metadata
                    except Exception as e:
                        self.logger.error(f"Failed to extract metadata from {path}: {e}")
        else:
            # Create basic metadata without deep extraction
            for path in evidence_paths:
                metadata = self._create_basic_metadata(path)
                metadata_list.append(metadata)
        
        combined_set.evidence_items = metadata_list
        
        # Step 3: Detect relationships
        relationships = self._detect_relationships(metadata_list, multipart_groups)
        combined_set.relationships = relationships
        
        # Step 4: Log detected relationships
        self._log_relationships(combined_set)
        
        return combined_set
    
    def _detect_multipart_sets(self, paths: List[Path]) -> Dict[str, List[Path]]:
        """
        Detect multi-part forensic image sets.
        
        Groups files like LoneWolf.E01, LoneWolf.E02, etc.
        
        Args:
            paths: List of evidence paths
            
        Returns:
            Dictionary mapping base name to list of parts
        """
        groups: Dict[str, List[Path]] = {}
        
        for path in paths:
            filename = path.name
            
            for pattern_name, pattern in self.multipart_patterns.items():
                match = pattern.match(filename)
                if match:
                    base_name = match.group(1)
                    if base_name not in groups:
                        groups[base_name] = []
                    groups[base_name].append(path)
                    break
        
        # Filter to only groups with multiple parts
        return {k: v for k, v in groups.items() if len(v) > 1}
    
    def _extract_evidence_metadata(self, path: Path) -> Optional[EvidenceMetadata]:
        """
        Extract metadata from an evidence file for relationship analysis.
        
        This performs quick metadata extraction without full processing.
        
        Args:
            path: Path to evidence file
            
        Returns:
            EvidenceMetadata or None if extraction fails
        """
        try:
            evidence_id = f"{path.stem}_{hashlib.md5(str(path).encode()).hexdigest()[:8]}"
            
            # Determine source type
            source_type = self._classify_evidence_type(path)
            
            metadata = EvidenceMetadata(
                evidence_id=evidence_id,
                file_path=path,
                source_type=source_type
            )
            
            # Try to extract identifiers based on evidence type
            if source_type == EvidenceSourceType.DISK_IMAGE:
                self._extract_disk_metadata(path, metadata)
            elif source_type == EvidenceSourceType.MEMORY_DUMP:
                self._extract_memory_metadata(path, metadata)
            elif source_type == EvidenceSourceType.LOG_FILE:
                self._extract_log_metadata(path, metadata)
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error extracting metadata from {path}: {e}")
            return None
    
    def _create_basic_metadata(self, path: Path) -> EvidenceMetadata:
        """Create basic metadata without deep extraction."""
        evidence_id = f"{path.stem}_{hashlib.md5(str(path).encode()).hexdigest()[:8]}"
        source_type = self._classify_evidence_type(path)
        
        return EvidenceMetadata(
            evidence_id=evidence_id,
            file_path=path,
            source_type=source_type
        )
    
    def _classify_evidence_type(self, path: Path) -> EvidenceSourceType:
        """Classify evidence file by type."""
        ext = path.suffix.lower()
        
        # Disk images
        if ext in ['.e01', '.e02', '.e03', '.dd', '.raw', '.img', '.aff', '.vmdk', '.vhd']:
            return EvidenceSourceType.DISK_IMAGE
        
        # Memory dumps
        if ext in ['.mem', '.dmp', '.dump', '.vmem', '.raw']:
            # .raw could be disk or memory - check size heuristic
            if ext == '.raw':
                try:
                    size = path.stat().st_size
                    # Memory dumps are typically < 64GB
                    if size < 64 * 1024 * 1024 * 1024:
                        return EvidenceSourceType.MEMORY_DUMP
                except:
                    pass
            return EvidenceSourceType.MEMORY_DUMP
        
        # Network captures
        if ext in ['.pcap', '.pcapng', '.cap']:
            return EvidenceSourceType.NETWORK_CAPTURE
        
        # Mobile backups
        if ext in ['.ab', '.tar', '.ufed', '.backup']:
            return EvidenceSourceType.MOBILE_BACKUP
        
        # Log files
        if ext in ['.log', '.evtx', '.evt', '.txt', '.csv', '.json']:
            return EvidenceSourceType.LOG_FILE
        
        # Archives
        if ext in ['.zip', '.7z', '.rar', '.tar', '.gz']:
            return EvidenceSourceType.ARCHIVE
        
        return EvidenceSourceType.UNKNOWN
    
    def _extract_disk_metadata(self, path: Path, metadata: EvidenceMetadata):
        """Extract metadata from disk image (quick scan)."""
        try:
            # Try to read E01 header for device info
            if path.suffix.lower() in ['.e01', '.e02']:
                self._parse_e01_header_metadata(path, metadata)
            
            # Try filesystem-level metadata if mounted
            # This would integrate with the VFS
            
        except Exception as e:
            self.logger.debug(f"Could not extract disk metadata: {e}")
    
    def _extract_memory_metadata(self, path: Path, metadata: EvidenceMetadata):
        """Extract metadata from memory dump (quick scan)."""
        try:
            # Look for OS profile indicators
            with open(path, 'rb') as f:
                # Read first few MB for identification
                header = f.read(4 * 1024 * 1024)
                
                # Windows memory signature
                if b'PAGEDUMP' in header or b'MZ' in header:
                    metadata.os_type = 'Windows'
                
                # Look for hostname patterns
                hostname_match = re.search(rb'COMPUTERNAME=([A-Z0-9\-]+)', header)
                if hostname_match:
                    metadata.hostname = hostname_match.group(1).decode('utf-8', errors='ignore')
                
                # Look for username patterns
                user_match = re.search(rb'USERNAME=([A-Za-z0-9\-_]+)', header)
                if user_match:
                    metadata.usernames.append(user_match.group(1).decode('utf-8', errors='ignore'))
                    
        except Exception as e:
            self.logger.debug(f"Could not extract memory metadata: {e}")
    
    def _extract_log_metadata(self, path: Path, metadata: EvidenceMetadata):
        """Extract metadata from log file."""
        try:
            # Try to find timestamps and hostnames
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                first_lines = f.read(10000)  # Read first 10KB
                
                # Extract timestamps
                timestamps = self._extract_timestamps_from_text(first_lines)
                if timestamps:
                    metadata.earliest_timestamp = min(timestamps)
                    metadata.latest_timestamp = max(timestamps)
                
        except Exception as e:
            self.logger.debug(f"Could not extract log metadata: {e}")
    
    def _parse_e01_header_metadata(self, path: Path, metadata: EvidenceMetadata):
        """Parse E01 header for device metadata."""
        try:
            # E01 magic bytes: EVF\x09\x0d\x0a\xff\x00
            E01_MAGIC = b'EVF\x09\x0d\x0a\xff\x00'
            
            with open(path, 'rb') as f:
                header = f.read(512)
                
                if header.startswith(E01_MAGIC):
                    # Parse EnCase Evidence File header
                    # Header contains case info, device info, etc.
                    
                    # Look for device serial in header area
                    # E01 format stores metadata in header sections
                    f.seek(0)
                    header_data = f.read(8192)
                    
                    # Extract acquiry software metadata if present
                    # (This is a simplified version - full parsing would use pyewf)
                    
        except Exception as e:
            self.logger.debug(f"Could not parse E01 header: {e}")
    
    def _extract_timestamps_from_text(self, text: str) -> List[datetime]:
        """Extract timestamps from text content."""
        timestamps = []
        
        # Common timestamp patterns
        patterns = [
            r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})',  # ISO format
            r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})',     # US format
            r'(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})',     # EU format
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches[:10]:  # Limit to first 10
                try:
                    # Try parsing
                    for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', 
                               '%m/%d/%Y %H:%M:%S', '%d-%m-%Y %H:%M:%S']:
                        try:
                            ts = datetime.strptime(match, fmt)
                            timestamps.append(ts)
                            break
                        except ValueError:
                            continue
                except:
                    pass
        
        return timestamps
    
    def _detect_relationships(
        self,
        metadata_list: List[EvidenceMetadata],
        multipart_groups: Dict[str, List[Path]]
    ) -> List[EvidenceRelationship]:
        """
        Detect relationships between evidence items.
        
        Analyzes:
        - Multi-part sets
        - Same device (disk + memory)
        - Same user
        - Timeline overlap
        - Network connections
        
        Args:
            metadata_list: List of evidence metadata
            multipart_groups: Detected multi-part groups
            
        Returns:
            List of detected relationships
        """
        relationships = []
        
        # 1. Multi-part relationships
        for base_name, parts in multipart_groups.items():
            # Find metadata for parts
            part_metas = [
                m for m in metadata_list 
                if m.file_path in parts
            ]
            
            if len(part_metas) > 1:
                for i in range(len(part_metas) - 1):
                    rel = EvidenceRelationship(
                        source_id=part_metas[i].evidence_id,
                        target_id=part_metas[i + 1].evidence_id,
                        relation_type=EvidenceRelationType.MULTIPART_SET,
                        confidence=1.0,
                        correlation_factors=[f"Same base name: {base_name}"],
                        description=f"Multi-part evidence set: {base_name}"
                    )
                    relationships.append(rel)
        
        # 2. Same device relationships (disk + memory)
        disk_items = [m for m in metadata_list if m.source_type == EvidenceSourceType.DISK_IMAGE]
        memory_items = [m for m in metadata_list if m.source_type == EvidenceSourceType.MEMORY_DUMP]
        
        for disk in disk_items:
            for memory in memory_items:
                confidence, factors = self._calculate_same_device_confidence(disk, memory)
                if confidence > 0.5:
                    rel = EvidenceRelationship(
                        source_id=disk.evidence_id,
                        target_id=memory.evidence_id,
                        relation_type=EvidenceRelationType.SAME_DEVICE,
                        confidence=confidence,
                        correlation_factors=factors,
                        description="Disk image and memory dump from same device"
                    )
                    relationships.append(rel)
        
        # 3. Same user relationships
        for i, meta1 in enumerate(metadata_list):
            for meta2 in metadata_list[i + 1:]:
                user_overlap = set(meta1.usernames) & set(meta2.usernames)
                if user_overlap:
                    rel = EvidenceRelationship(
                        source_id=meta1.evidence_id,
                        target_id=meta2.evidence_id,
                        relation_type=EvidenceRelationType.SAME_USER,
                        confidence=0.8,
                        correlation_factors=[f"Common users: {', '.join(user_overlap)}"],
                        description="Evidence contains same user accounts"
                    )
                    relationships.append(rel)
        
        # 4. Timeline overlap
        for i, meta1 in enumerate(metadata_list):
            for meta2 in metadata_list[i + 1:]:
                if meta1.earliest_timestamp and meta2.earliest_timestamp:
                    overlap = self._check_timeline_overlap(
                        meta1.earliest_timestamp, meta1.latest_timestamp,
                        meta2.earliest_timestamp, meta2.latest_timestamp
                    )
                    if overlap:
                        rel = EvidenceRelationship(
                            source_id=meta1.evidence_id,
                            target_id=meta2.evidence_id,
                            relation_type=EvidenceRelationType.TIMELINE_OVERLAP,
                            confidence=0.7,
                            correlation_factors=["Overlapping time periods"],
                            description="Evidence has overlapping time periods"
                        )
                        relationships.append(rel)
        
        # 5. Hostname/device name match
        for i, meta1 in enumerate(metadata_list):
            for meta2 in metadata_list[i + 1:]:
                if meta1.hostname and meta2.hostname:
                    if meta1.hostname.lower() == meta2.hostname.lower():
                        rel = EvidenceRelationship(
                            source_id=meta1.evidence_id,
                            target_id=meta2.evidence_id,
                            relation_type=EvidenceRelationType.SAME_DEVICE,
                            confidence=0.9,
                            correlation_factors=[f"Same hostname: {meta1.hostname}"],
                            description="Evidence from same device (hostname match)"
                        )
                        relationships.append(rel)
        
        return relationships
    
    def _calculate_same_device_confidence(
        self,
        disk: EvidenceMetadata,
        memory: EvidenceMetadata
    ) -> Tuple[float, List[str]]:
        """
        Calculate confidence that disk and memory are from same device.
        
        Args:
            disk: Disk image metadata
            memory: Memory dump metadata
            
        Returns:
            Tuple of (confidence, correlation_factors)
        """
        confidence = 0.0
        factors = []
        
        # Hostname match
        if disk.hostname and memory.hostname:
            if disk.hostname.lower() == memory.hostname.lower():
                confidence += 0.4
                factors.append(f"Hostname match: {disk.hostname}")
        
        # User overlap
        user_overlap = set(disk.usernames) & set(memory.usernames)
        if user_overlap:
            confidence += 0.2
            factors.append(f"Common users: {', '.join(user_overlap)}")
        
        # MAC address overlap
        mac_overlap = set(disk.mac_addresses) & set(memory.mac_addresses)
        if mac_overlap:
            confidence += 0.3
            factors.append(f"Common MAC addresses: {', '.join(mac_overlap)}")
        
        # OS match
        if disk.os_type and memory.os_type:
            if disk.os_type == memory.os_type:
                confidence += 0.1
                factors.append(f"Same OS: {disk.os_type}")
        
        # Default: If both are selected together, assume some relationship
        if confidence == 0.0:
            confidence = 0.3
            factors.append("Selected together (assumed related)")
        
        return min(confidence, 1.0), factors
    
    def _check_timeline_overlap(
        self,
        start1: Optional[datetime],
        end1: Optional[datetime],
        start2: Optional[datetime],
        end2: Optional[datetime]
    ) -> bool:
        """Check if two time ranges overlap."""
        if not all([start1, end1, start2, end2]):
            return False
        
        # Type checking is already satisfied above, but add explicit checks for clarity
        assert start1 is not None and end1 is not None
        assert start2 is not None and end2 is not None
        return not (end1 < start2 or end2 < start1)
    
    def _log_relationships(self, combined_set: CombinedEvidenceSet):
        """Log detected relationships for audit."""
        if not combined_set.relationships:
            self.logger.info("No relationships detected between evidence files")
            return
        
        self.logger.info(f"Detected {len(combined_set.relationships)} relationships:")
        for rel in combined_set.relationships:
            self.logger.info(
                f"  - {rel.source_id} <-> {rel.target_id}: "
                f"{rel.relation_type.value} (confidence: {rel.confidence:.2f})"
            )


class EvidenceDataCombiner:
    """
    Combines data from multiple related evidence sources.
    
    Handles:
    - Merging artifact lists
    - Combining timelines
    - Cross-referencing events
    - Deduplicating entries
    - Creating unified views for UI tabs
    """
    
    def __init__(self, case_path: Path):
        """
        Initialize the data combiner.
        
        Args:
            case_path: Path to case workspace
        """
        self.logger = logging.getLogger(__name__)
        self.case_path = case_path
        self._lock = threading.Lock()
    
    def combine_evidence_data(
        self,
        combined_set: CombinedEvidenceSet,
        extracted_data: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Combine extracted data from multiple evidence sources.
        
        This method is called after individual evidence processing to
        create unified datasets for all UI tabs.
        
        Args:
            combined_set: Combined evidence set with relationships
            extracted_data: Dictionary mapping evidence_id to extracted data
            
        Returns:
            Dictionary with unified data for each tab
        """
        self.logger.info(f"Combining data from {len(extracted_data)} evidence sources...")
        
        unified_data = {
            'timeline': [],
            'artifacts': [],
            'events': [],
            'users': {},
            'files': [],
            'registry': [],
            'network': [],
            'processes': [],
            'anomalies': [],
            'findings': [],
            
            # Metadata
            'sources': [],
            'relationships': [r.relation_type.value for r in combined_set.relationships],
            'combined_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Track seen items for deduplication
        seen_event_hashes: Set[str] = set()
        seen_artifact_hashes: Set[str] = set()
        
        for evidence_id, data in extracted_data.items():
            source_info = {
                'evidence_id': evidence_id,
                'source_type': data.get('source_type', 'unknown'),
                'items_contributed': {}
            }
            
            # Combine timelines
            if 'timeline' in data:
                for event in data['timeline']:
                    event_hash = self._hash_event(event)
                    if event_hash not in seen_event_hashes:
                        event['source_evidence'] = evidence_id
                        unified_data['timeline'].append(event)
                        seen_event_hashes.add(event_hash)
                source_info['items_contributed']['timeline'] = len(data['timeline'])
            
            # Combine artifacts
            if 'artifacts' in data:
                for artifact in data['artifacts']:
                    artifact_hash = self._hash_artifact(artifact)
                    if artifact_hash not in seen_artifact_hashes:
                        artifact['source_evidence'] = evidence_id
                        unified_data['artifacts'].append(artifact)
                        seen_artifact_hashes.add(artifact_hash)
                source_info['items_contributed']['artifacts'] = len(data['artifacts'])
            
            # Combine events
            if 'events' in data:
                for event in data['events']:
                    event['source_evidence'] = evidence_id
                    unified_data['events'].append(event)
                source_info['items_contributed']['events'] = len(data['events'])
            
            # Combine users (merge)
            if 'users' in data:
                for user_id, user_data in data['users'].items():
                    if user_id in unified_data['users']:
                        # Merge user data
                        unified_data['users'][user_id] = self._merge_user_data(
                            unified_data['users'][user_id],
                            user_data,
                            evidence_id
                        )
                    else:
                        user_data['sources'] = [evidence_id]
                        unified_data['users'][user_id] = user_data
            
            # Combine files
            if 'files' in data:
                for file_entry in data['files']:
                    file_entry['source_evidence'] = evidence_id
                    unified_data['files'].append(file_entry)
            
            # Combine registry
            if 'registry' in data:
                for reg_entry in data['registry']:
                    reg_entry['source_evidence'] = evidence_id
                    unified_data['registry'].append(reg_entry)
            
            # Combine network
            if 'network' in data:
                for net_entry in data['network']:
                    net_entry['source_evidence'] = evidence_id
                    unified_data['network'].append(net_entry)
            
            # Combine processes (from memory)
            if 'processes' in data:
                for proc in data['processes']:
                    proc['source_evidence'] = evidence_id
                    unified_data['processes'].append(proc)
            
            # Combine anomalies
            if 'anomalies' in data:
                for anomaly in data['anomalies']:
                    anomaly['source_evidence'] = evidence_id
                    unified_data['anomalies'].append(anomaly)
            
            # Combine findings
            if 'findings' in data:
                for finding in data['findings']:
                    finding['source_evidence'] = evidence_id
                    unified_data['findings'].append(finding)
            
            unified_data['sources'].append(source_info)
        
        # Sort timeline by timestamp
        unified_data['timeline'].sort(
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )
        
        # Cross-reference events between sources
        unified_data['cross_references'] = self._cross_reference_events(
            unified_data,
            combined_set.relationships
        )
        
        # Calculate statistics
        unified_data['statistics'] = {
            'total_events': len(unified_data['events']),
            'total_artifacts': len(unified_data['artifacts']),
            'total_users': len(unified_data['users']),
            'total_files': len(unified_data['files']),
            'total_anomalies': len(unified_data['anomalies']),
            'evidence_sources': len(extracted_data),
            'cross_references': len(unified_data['cross_references'])
        }
        
        # Save unified data
        self._save_unified_data(unified_data)
        
        # Update combined set statistics
        combined_set.total_events = unified_data['statistics']['total_events']
        combined_set.total_artifacts = unified_data['statistics']['total_artifacts']
        combined_set.cross_referenced_events = unified_data['statistics']['cross_references']
        combined_set.correlated_users = list(unified_data['users'].keys())
        
        return unified_data
    
    def _hash_event(self, event: Dict) -> str:
        """Create hash of event for deduplication."""
        key_fields = ['timestamp', 'event_id', 'source', 'message']
        hash_str = '|'.join(str(event.get(f, '')) for f in key_fields)
        return hashlib.md5(hash_str.encode()).hexdigest()
    
    def _hash_artifact(self, artifact: Dict) -> str:
        """Create hash of artifact for deduplication."""
        key_fields = ['path', 'type', 'sha256']
        hash_str = '|'.join(str(artifact.get(f, '')) for f in key_fields)
        return hashlib.md5(hash_str.encode()).hexdigest()
    
    def _merge_user_data(
        self,
        existing: Dict,
        new_data: Dict,
        source_id: str
    ) -> Dict:
        """Merge user data from multiple sources."""
        # Add source
        if 'sources' not in existing:
            existing['sources'] = []
        existing['sources'].append(source_id)
        
        # Merge activity lists
        for key in ['logins', 'file_access', 'network_activity', 'commands']:
            if key in new_data:
                if key not in existing:
                    existing[key] = []
                existing[key].extend(new_data[key])
        
        return existing
    
    def _cross_reference_events(
        self,
        unified_data: Dict,
        relationships: List[EvidenceRelationship]
    ) -> List[Dict]:
        """
        Cross-reference events across evidence sources.
        
        Identifies events that correlate across different sources.
        """
        cross_refs = []
        
        # Group events by timestamp window (5 minute windows)
        events_by_time = {}
        for event in unified_data['events']:
            ts = event.get('timestamp', '')
            if ts:
                # Round to 5-minute window
                try:
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    window = dt.strftime('%Y-%m-%d %H:%M')[:15] + '0'  # 10-min window
                    if window not in events_by_time:
                        events_by_time[window] = []
                    events_by_time[window].append(event)
                except:
                    pass
        
        # Find events in same time window from different sources
        for window, events in events_by_time.items():
            sources = set(e.get('source_evidence') for e in events)
            if len(sources) > 1:
                cross_refs.append({
                    'time_window': window,
                    'event_count': len(events),
                    'sources': list(sources),
                    'events': [e.get('event_id') for e in events[:5]]  # First 5
                })
        
        return cross_refs
    
    def _save_unified_data(self, unified_data: Dict):
        """Save unified data to case workspace."""
        if not self.case_path:
            return
        
        try:
            events_dir = self.case_path / 'events'
            events_dir.mkdir(parents=True, exist_ok=True)
            
            # Save unified data as JSON
            unified_path = events_dir / 'unified_data.json'
            with open(unified_path, 'w') as f:
                json.dump(unified_data, f, indent=2, default=str)
            
            self.logger.info(f"Saved unified data to {unified_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save unified data: {e}")
    
    def get_unified_data_for_tab(self, tab_name: str) -> Dict[str, Any]:
        """
        Get unified data formatted for a specific UI tab.
        
        Args:
            tab_name: Name of the tab (timeline, artifacts, files, etc.)
            
        Returns:
            Data formatted for the specific tab
        """
        if not self.case_path:
            return {}
        
        try:
            unified_path = self.case_path / 'events' / 'unified_data.json'
            if unified_path.exists():
                with open(unified_path, 'r') as f:
                    unified_data = json.load(f)
                
                # Return tab-specific data
                tab_mapping = {
                    'timeline': ['timeline', 'cross_references'],
                    'artifacts': ['artifacts'],
                    'files': ['files'],
                    'registry': ['registry'],
                    'network': ['network'],
                    'users': ['users'],
                    'processes': ['processes'],
                    'anomalies': ['anomalies', 'findings'],
                    'overview': ['statistics', 'sources', 'relationships']
                }
                
                keys = tab_mapping.get(tab_name, [tab_name])
                return {k: unified_data.get(k, []) for k in keys}
                
        except Exception as e:
            self.logger.error(f"Failed to load unified data for tab {tab_name}: {e}")
        
        return {}


# Convenience function for pipeline integration
def analyze_and_combine_evidence(
    case_path: Path,
    evidence_paths: List[Path],
    extracted_data: Optional[Dict[str, Dict]] = None
) -> Tuple[CombinedEvidenceSet, Optional[Dict]]:
    """
    Convenience function to analyze evidence relationships and combine data.
    
    Args:
        case_path: Path to case workspace
        evidence_paths: List of evidence file paths
        extracted_data: Optional pre-extracted data from each source
        
    Returns:
        Tuple of (CombinedEvidenceSet, unified_data or None)
    """
    # Analyze relationships
    analyzer = EvidenceRelationshipAnalyzer(case_path)
    combined_set = analyzer.analyze_evidence_set(evidence_paths)
    
    # Combine data if provided
    unified_data = None
    if extracted_data:
        combiner = EvidenceDataCombiner(case_path)
        unified_data = combiner.combine_evidence_data(combined_set, extracted_data)
    
    return combined_set, unified_data
