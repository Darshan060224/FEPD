"""
FEPD - Comprehensive Feature Engineering Layer
================================================
Convert forensic artifacts into numeric ML features.

Architecture:
- Each artifact type has its own feature extractor
- All features are numeric (no strings)
- Features are documented and versioned
- Compatible with dataa/features/ storage

Supported Artifacts:
- EVTX (Windows Event Logs)
- Registry (persistence, autoruns)
- Files (entropy, metadata, paths)
- Memory (processes, injections)
- Network (flows, connections)
- Timeline (temporal patterns)

Copyright (c) 2026 FEPD Development Team
"""

import pandas as pd
import numpy as np
import math
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import logging
import json


class FeatureSchema:
    """Define and validate feature schemas"""
    
    @staticmethod
    def get_schema(artifact_type: str) -> Dict:
        """Get feature schema for artifact type"""
        schemas = {
            "evtx": {
                "features": [
                    "event_rate_per_hour",
                    "unique_event_ids",
                    "failed_login_count",
                    "off_hours_activity",
                    "event_entropy",
                    "time_variance",
                    "user_diversity"
                ],
                "version": "1.0"
            },
            "registry": {
                "features": [
                    "autorun_count",
                    "persistence_indicators",
                    "path_depth",
                    "value_entropy",
                    "suspicious_locations"
                ],
                "version": "1.0"
            },
            "file": {
                "features": [
                    "entropy",
                    "size_bytes",
                    "path_depth",
                    "extension_entropy",
                    "creation_time_hour",
                    "modification_delta"
                ],
                "version": "1.0"
            },
            "memory": {
                "features": [
                    "process_count",
                    "injection_indicators",
                    "hidden_process_count",
                    "memory_entropy",
                    "network_connections"
                ],
                "version": "1.0"
            },
            "network": {
                "features": [
                    "flow_duration",
                    "bytes_transferred",
                    "unique_ips",
                    "port_entropy",
                    "protocol_distribution"
                ],
                "version": "1.0"
            }
        }
        return schemas.get(artifact_type, {})


class FileFeatureExtractor:
    """Extract ML features from file system artifacts"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    def extract_features(self, files_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from file system data.
        
        Args:
            files_df: DataFrame with columns: path, size, created, modified, content_sample
            
        Returns:
            DataFrame with numeric features
        """
        self.logger.info(f"Extracting features from {len(files_df)} files")
        
        features = pd.DataFrame()
        
        # File entropy (0-8 bits)
        if 'content_sample' in files_df.columns:
            features['entropy'] = files_df['content_sample'].apply(self._calculate_entropy)
        
        # File size (log scale to normalize)
        if 'size' in files_df.columns:
            features['size_log'] = np.log1p(files_df['size'])
        
        # Path depth (number of directory levels)
        if 'path' in files_df.columns:
            features['path_depth'] = files_df['path'].apply(lambda p: len(Path(p).parts))
        
        # Extension entropy (unusual extensions have high entropy)
        if 'path' in files_df.columns:
            features['extension_entropy'] = files_df['path'].apply(self._extension_entropy)
        
        # Time-based features
        if 'created' in files_df.columns:
            features['created_hour'] = pd.to_datetime(files_df['created']).dt.hour
            features['created_weekday'] = pd.to_datetime(files_df['created']).dt.weekday
        
        # Modification delta (time between creation and modification)
        if 'created' in files_df.columns and 'modified' in files_df.columns:
            created = pd.to_datetime(files_df['created'])
            modified = pd.to_datetime(files_df['modified'])
            features['modification_delta'] = (modified - created).dt.total_seconds()
        
        self.logger.info(f"Extracted {len(features.columns)} file features")
        
        return features
    
    def _calculate_entropy(self, data) -> float:
        """Calculate Shannon entropy"""
        if pd.isna(data) or not data:
            return 0.0
        
        if isinstance(data, str):
            data = data.encode()
        
        if len(data) == 0:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data) if isinstance(data, bytes) else 0
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        
        return entropy
    
    def _extension_entropy(self, path: str) -> float:
        """Calculate entropy of file extension"""
        ext = Path(path).suffix.lower()
        if not ext:
            return 0.0
        return self._calculate_entropy(ext)


class RegistryFeatureExtractor:
    """Extract ML features from Windows Registry artifacts"""
    
    # Known persistence locations
    AUTORUN_KEYS = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"System\CurrentControlSet\Services",
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    ]
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    def extract_features(self, registry_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from registry data.
        
        Args:
            registry_df: DataFrame with columns: key_path, value_name, value_data
            
        Returns:
            DataFrame with numeric features
        """
        self.logger.info(f"Extracting features from {len(registry_df)} registry entries")
        
        features = pd.DataFrame()
        
        # Autorun count (persistence indicator)
        features['autorun_count'] = registry_df['key_path'].apply(self._is_autorun).sum()
        
        # Path depth
        features['path_depth'] = registry_df['key_path'].apply(lambda p: len(p.split('\\')))
        
        # Value data entropy
        if 'value_data' in registry_df.columns:
            features['value_entropy'] = registry_df['value_data'].apply(
                lambda v: self._calculate_entropy(str(v)) if pd.notna(v) else 0
            )
        
        # Suspicious location indicators
        features['suspicious_location'] = registry_df['key_path'].apply(
            lambda p: 1 if any(sus in p.lower() for sus in ['run', 'startup', 'winlogon']) else 0
        )
        
        self.logger.info(f"Extracted {len(features.columns)} registry features")
        
        return features
    
    def _is_autorun(self, key_path: str) -> bool:
        """Check if registry key is a known autorun location"""
        return any(autorun in key_path for autorun in self.AUTORUN_KEYS)
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string"""
        if not data:
            return 0.0
        
        counter = Counter(data)
        length = len(data)
        entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
        
        return entropy


class MemoryFeatureExtractor:
    """Extract ML features from memory dumps"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    def extract_features(self, memory_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from memory artifacts.
        
        Args:
            memory_df: DataFrame with columns: process_name, pid, ppid, path, vad_size
            
        Returns:
            DataFrame with numeric features
        """
        self.logger.info(f"Extracting features from {len(memory_df)} memory entries")
        
        features = pd.DataFrame()
        
        # Process count
        features['process_count'] = len(memory_df)
        
        # Hidden processes (no path)
        if 'path' in memory_df.columns:
            features['hidden_process_count'] = memory_df['path'].isna().sum()
        
        # Injection indicators (processes with unusual parent-child relationships)
        if 'pid' in memory_df.columns and 'ppid' in memory_df.columns:
            features['orphan_processes'] = (memory_df['ppid'] == 0).sum()
        
        # Memory size statistics
        if 'vad_size' in memory_df.columns:
            features['total_vad_size'] = memory_df['vad_size'].sum()
            features['avg_vad_size'] = memory_df['vad_size'].mean()
        
        self.logger.info(f"Extracted {len(features.columns)} memory features")
        
        return features


class NetworkFeatureExtractor:
    """Extract ML features from network artifacts"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    def extract_features(self, network_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from network flow data.
        
        Args:
            network_df: DataFrame with columns: src_ip, dst_ip, src_port, dst_port, 
                       protocol, bytes, start_time, end_time
            
        Returns:
            DataFrame with numeric features
        """
        self.logger.info(f"Extracting features from {len(network_df)} network flows")
        
        features = pd.DataFrame()
        
        # Flow duration (seconds)
        if 'start_time' in network_df.columns and 'end_time' in network_df.columns:
            start = pd.to_datetime(network_df['start_time'])
            end = pd.to_datetime(network_df['end_time'])
            features['flow_duration'] = (end - start).dt.total_seconds()
        
        # Bytes transferred (log scale)
        if 'bytes' in network_df.columns:
            features['bytes_log'] = np.log1p(network_df['bytes'])
        
        # Unique IPs
        if 'dst_ip' in network_df.columns:
            features['unique_dst_ips'] = network_df['dst_ip'].nunique()
        
        # Port entropy (common ports vs rare ports)
        if 'dst_port' in network_df.columns:
            features['port_entropy'] = network_df['dst_port'].apply(self._port_entropy)
        
        # Protocol distribution
        if 'protocol' in network_df.columns:
            protocol_counts = network_df['protocol'].value_counts(normalize=True)
            features['protocol_entropy'] = -sum(p * math.log2(p) for p in protocol_counts if p > 0)
        
        self.logger.info(f"Extracted {len(features.columns)} network features")
        
        return features
    
    def _port_entropy(self, port: int) -> float:
        """Calculate entropy based on port commonality"""
        # Common ports have low entropy, unusual ports have high entropy
        common_ports = {80, 443, 22, 21, 25, 53, 110, 143, 3306, 3389}
        return 0.0 if port in common_ports else 1.0


class FeatureEngineeringPipeline:
    """
    Unified pipeline for feature engineering.
    
    Coordinates extraction from all artifact types and saves to dataa/features/.
    """
    
    def __init__(self, output_dir: Path = None, logger=None):
        self.output_dir = Path(output_dir or "dataa/features")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize extractors
        self.extractors = {
            "file": FileFeatureExtractor(logger),
            "registry": RegistryFeatureExtractor(logger),
            "memory": MemoryFeatureExtractor(logger),
            "network": NetworkFeatureExtractor(logger)
        }
    
    def process_artifacts(self, artifact_type: str, artifacts_df: pd.DataFrame, case_id: str) -> Path:
        """
        Process artifacts and extract features.
        
        Args:
            artifact_type: Type of artifact (file, registry, memory, network, evtx)
            artifacts_df: DataFrame with artifact data
            case_id: Case identifier
            
        Returns:
            Path to saved features file
        """
        if artifact_type not in self.extractors:
            raise ValueError(f"Unsupported artifact type: {artifact_type}")
        
        self.logger.info(f"Processing {artifact_type} artifacts for case {case_id}")
        
        # Extract features
        extractor = self.extractors[artifact_type]
        features_df = extractor.extract_features(artifacts_df)
        
        # Add metadata
        features_df['case_id'] = case_id
        features_df['artifact_type'] = artifact_type
        features_df['extracted_at'] = datetime.now().isoformat()
        
        # Save to dataa/features/
        output_file = self.output_dir / f"{case_id}_{artifact_type}_features.parquet"
        features_df.to_parquet(output_file, index=False)
        
        self.logger.info(f"Features saved: {output_file}")
        self.logger.info(f"Feature count: {len(features_df.columns)}")
        
        # Save schema
        schema = FeatureSchema.get_schema(artifact_type)
        schema_file = output_file.with_suffix('.schema.json')
        with open(schema_file, 'w') as f:
            json.dump(schema, f, indent=2)
        
        return output_file


if __name__ == "__main__":
    # Test feature extraction
    logging.basicConfig(level=logging.INFO)
    
    # Test file features
    files_df = pd.DataFrame({
        'path': ['C:\\Windows\\System32\\calc.exe', 'C:\\Users\\test\\malware.exe'],
        'size': [100000, 50000],
        'created': ['2024-01-01 10:00:00', '2024-01-01 03:00:00'],
        'modified': ['2024-01-01 10:30:00', '2024-01-01 03:01:00'],
        'content_sample': [b'\x4d\x5a' * 100, b'\xff\xfe' * 100]
    })
    
    extractor = FileFeatureExtractor()
    features = extractor.extract_features(files_df)
    
    print("\n=== File Features ===")
    print(features)
