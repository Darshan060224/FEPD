"""
FEPD - Feature Extraction Module
==================================
Extract numeric ML features from forensic artifacts

Each artifact type has its own feature extraction pipeline:
- EVTX (Windows Event Logs)
- Registry artifacts
- File system artifacts
- Execution artifacts (Prefetch/Amcache)
- UEBA (User behavior)

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


# Known autorun registry keys for persistence detection
AUTORUN_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"System\CurrentControlSet\Services",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Classes\exefile\shell\open\command",
]


class EVTXFeatureExtractor:
    """Extract ML features from Windows Event Logs (EVTX)"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    def extract_features(self, evtx_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from EVTX data
        
        Args:
            evtx_df: DataFrame with columns: timestamp, event_id, user, source
            
        Returns:
            DataFrame with numeric features
        """
        self.logger.info(f"Extracting EVTX features from {len(evtx_df)} events")
        
        features = pd.DataFrame()
        
        # Temporal features
        timestamps = pd.to_datetime(evtx_df['timestamp'], errors='coerce')
        features['hour'] = timestamps.dt.hour
        features['day_of_week'] = timestamps.dt.dayofweek
        features['is_weekend'] = (timestamps.dt.dayofweek >= 5).astype(int)
        features['is_off_hours'] = ((timestamps.dt.hour < 7) | (timestamps.dt.hour > 19)).astype(int)
        
        # Event frequency features
        features['event_freq'] = evtx_df.groupby('event_id')['timestamp'].transform('count')
        
        # Time delta (automation detection)
        features['delta_prev'] = timestamps.diff().dt.total_seconds().fillna(0)
        features['delta_prev_log'] = np.log1p(features['delta_prev'])  # Log scale for ML
        
        # User activity features
        if 'user' in evtx_df.columns:
            features['user_event_rate'] = evtx_df.groupby('user')['event_id'].transform('count') / len(evtx_df)
            
            # Encode user (categorical)
            from sklearn.preprocessing import LabelEncoder
            le = LabelEncoder()
            features['user_encoded'] = le.fit_transform(evtx_df['user'].fillna('SYSTEM'))
        
        # Event ID encoding
        if 'event_id' in evtx_df.columns:
            # One-hot encode common critical events
            features['is_login_event'] = evtx_df['event_id'].isin([4624, 4625]).astype(int)
            features['is_process_event'] = evtx_df['event_id'].isin([4688, 4689]).astype(int)
            features['is_privilege_event'] = evtx_df['event_id'].isin([4672, 4673]).astype(int)
        
        self.logger.info(f"Extracted {features.shape[1]} EVTX features")
        return features


class RegistryFeatureExtractor:
    """Extract ML features from Registry artifacts"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    def extract_features(self, registry_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from Registry data
        
        Args:
            registry_df: DataFrame with columns: key_path, hive, modified_time, value_type
            
        Returns:
            DataFrame with numeric features
        """
        self.logger.info(f"Extracting Registry features from {len(registry_df)} keys")
        
        features = pd.DataFrame()
        
        # Path depth (deeper = more suspicious)
        features['path_depth'] = registry_df['key_path'].str.count('\\\\')
        
        # Temporal features
        if 'modified_time' in registry_df.columns:
            mod_times = pd.to_datetime(registry_df['modified_time'], errors='coerce')
            features['mod_hour'] = mod_times.dt.hour
            features['mod_day_of_week'] = mod_times.dt.dayofweek
            features['is_off_hours_mod'] = ((mod_times.dt.hour < 7) | (mod_times.dt.hour > 19)).astype(int)
        
        # Autorun detection (persistence indicator)
        features['autorun_flag'] = registry_df['key_path'].apply(
            lambda x: 1 if any(autorun in str(x) for autorun in AUTORUN_KEYS) else 0
        )
        
        # Hive encoding
        if 'hive' in registry_df.columns:
            hive_map = {'HKLM': 0, 'HKCU': 1, 'HKCR': 2, 'HKU': 3, 'HKCC': 4}
            features['hive_encoded'] = registry_df['hive'].map(hive_map).fillna(5)
        
        # Change frequency (abnormal if high)
        features['change_freq'] = registry_df.groupby('key_path')['key_path'].transform('count')
        
        self.logger.info(f"Extracted {features.shape[1]} Registry features")
        return features


class FileFeatureExtractor:
    """Extract ML features from file system artifacts"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of byte sequence
        High entropy (7.5-8.0) = packed/encrypted
        """
        if not data or len(data) == 0:
            return 0.0
        
        counter = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def extract_features(self, file_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from file data
        
        Args:
            file_df: DataFrame with columns: path, size, created, modified, content, extension
            
        Returns:
            DataFrame with numeric features
        """
        self.logger.info(f"Extracting File features from {len(file_df)} files")
        
        features = pd.DataFrame()
        
        # Size features
        features['file_size'] = file_df['size']
        features['file_size_log'] = np.log1p(file_df['size'])  # Log scale
        
        # Entropy (encryption/packing detection)
        if 'content' in file_df.columns:
            features['entropy'] = file_df['content'].apply(
                lambda x: self.calculate_entropy(x) if isinstance(x, bytes) else 0.0
            )
            features['is_high_entropy'] = (features['entropy'] > 7.5).astype(int)
        else:
            features['entropy'] = 0.0
            features['is_high_entropy'] = 0
        
        # Path depth (hidden files deeper)
        features['path_depth'] = file_df['path'].str.count('\\\\')
        
        # Temporal features
        if 'created' in file_df.columns:
            created_times = pd.to_datetime(file_df['created'], errors='coerce')
            features['created_hour'] = created_times.dt.hour
            features['created_day_of_week'] = created_times.dt.dayofweek
            features['is_off_hours_created'] = ((created_times.dt.hour < 7) | (created_times.dt.hour > 19)).astype(int)
        
        # Modification vs creation gap
        if 'modified' in file_df.columns and 'created' in file_df.columns:
            mod_times = pd.to_datetime(file_df['modified'], errors='coerce')
            created_times = pd.to_datetime(file_df['created'], errors='coerce')
            features['mod_create_gap'] = (mod_times - created_times).dt.total_seconds()
        
        # Extension encoding
        if 'extension' in file_df.columns:
            # Common suspicious extensions
            suspicious_ext = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr', '.com']
            features['is_executable'] = file_df['extension'].isin(suspicious_ext).astype(int)
            
            # Encode extension
            from sklearn.preprocessing import LabelEncoder
            le = LabelEncoder()
            features['extension_encoded'] = le.fit_transform(file_df['extension'].fillna('.unknown'))
        
        # Digital signature
        if 'is_signed' in file_df.columns:
            features['signed_flag'] = file_df['is_signed'].astype(int)
        else:
            features['signed_flag'] = 0
        
        self.logger.info(f"Extracted {features.shape[1]} File features")
        return features


class ExecutionFeatureExtractor:
    """Extract ML features from execution artifacts (Prefetch/Amcache)"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    def extract_features(self, exec_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from execution data
        
        Args:
            exec_df: DataFrame with columns: program_name, first_run, last_run, execution_count, file_path
            
        Returns:
            DataFrame with numeric features
        """
        self.logger.info(f"Extracting Execution features from {len(exec_df)} programs")
        
        features = pd.DataFrame()
        
        # Execution frequency
        features['execution_count'] = exec_df['execution_count']
        features['execution_count_log'] = np.log1p(exec_df['execution_count'])
        
        # Temporal features
        if 'first_run' in exec_df.columns:
            first_run = pd.to_datetime(exec_df['first_run'], errors='coerce')
            features['first_run_hour'] = first_run.dt.hour
            features['first_run_day_of_week'] = first_run.dt.dayofweek
            features['is_off_hours_first_run'] = ((first_run.dt.hour < 7) | (first_run.dt.hour > 19)).astype(int)
        
        # Recency
        if 'last_run' in exec_df.columns:
            last_run = pd.to_datetime(exec_df['last_run'], errors='coerce')
            now = pd.Timestamp.now()
            features['last_run_gap'] = (now - last_run).dt.total_seconds()
            features['last_run_gap_log'] = np.log1p(features['last_run_gap'])
        
        # Binary location depth
        if 'file_path' in exec_df.columns:
            features['binary_location_depth'] = exec_df['file_path'].str.count('\\\\')
            
            # Suspicious locations
            suspicious_paths = ['temp', 'appdata', 'downloads', 'recycler']
            features['is_suspicious_location'] = exec_df['file_path'].str.lower().apply(
                lambda x: 1 if any(sus in str(x) for sus in suspicious_paths) else 0
            )
        
        # Rare binary detection (LOLBins, attacker tools)
        features['rare_binary_flag'] = (exec_df['execution_count'] < 5).astype(int)
        
        self.logger.info(f"Extracted {features.shape[1]} Execution features")
        return features


class UEBAFeatureExtractor:
    """Extract ML features for User and Entity Behavior Analytics"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    def extract_features(self, user_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract UEBA features
        
        Args:
            user_df: DataFrame with user activity data
            
        Returns:
            DataFrame with numeric features
        """
        self.logger.info(f"Extracting UEBA features from {len(user_df)} user activities")
        
        # Group by user
        user_groups = user_df.groupby('user_id')
        
        features = pd.DataFrame()
        features['user_id'] = user_groups.groups.keys()
        
        # Login patterns
        if 'login_time' in user_df.columns:
            login_hours = pd.to_datetime(user_df['login_time'], errors='coerce').dt.hour
            features['avg_login_hour'] = user_groups['login_time'].apply(
                lambda x: pd.to_datetime(x, errors='coerce').dt.hour.mean()
            ).values
            features['login_hour_std'] = user_groups['login_time'].apply(
                lambda x: pd.to_datetime(x, errors='coerce').dt.hour.std()
            ).fillna(0).values
        
        # File access patterns
        if 'files_accessed' in user_df.columns:
            features['total_files_accessed'] = user_groups['files_accessed'].sum().values
            features['file_access_rate'] = (
                user_groups['files_accessed'].sum() / user_groups['session_duration'].sum()
            ).fillna(0).values
        
        # Network activity
        if 'bytes_transferred' in user_df.columns:
            features['total_network_volume'] = user_groups['bytes_transferred'].sum().values
            features['avg_network_volume'] = user_groups['bytes_transferred'].mean().values
        
        # Command execution
        if 'commands' in user_df.columns:
            features['total_commands'] = user_groups['commands'].count().values
            features['command_rate'] = (
                user_groups['commands'].count() / user_groups['session_duration'].sum()
            ).fillna(0).values
        
        # Weekend activity (suspicious if suddenly high)
        if 'login_time' in user_df.columns:
            login_times = pd.to_datetime(user_df['login_time'], errors='coerce')
            weekend_activity = login_times.dt.dayofweek >= 5
            features['weekend_activity_ratio'] = user_groups.apply(
                lambda x: weekend_activity[x.index].sum() / len(x) if len(x) > 0 else 0
            ).values
        
        self.logger.info(f"Extracted {features.shape[1]} UEBA features for {len(features)} users")
        return features


class FeatureExtractorFactory:
    """Factory for creating feature extractors"""
    
    @staticmethod
    def get_extractor(artifact_type: str, logger=None):
        """
        Get appropriate feature extractor for artifact type
        
        Args:
            artifact_type: 'evtx', 'registry', 'file', 'execution', 'ueba'
            logger: Optional logger
            
        Returns:
            Feature extractor instance
        """
        extractors = {
            'evtx': EVTXFeatureExtractor,
            'registry': RegistryFeatureExtractor,
            'file': FileFeatureExtractor,
            'execution': ExecutionFeatureExtractor,
            'ueba': UEBAFeatureExtractor,
        }
        
        extractor_class = extractors.get(artifact_type.lower())
        if not extractor_class:
            raise ValueError(f"Unknown artifact type: {artifact_type}")
        
        return extractor_class(logger=logger)


# Example usage
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # Example: Extract EVTX features
    evtx_data = pd.DataFrame({
        'timestamp': pd.date_range('2026-01-01', periods=100, freq='H'),
        'event_id': np.random.choice([4624, 4688, 4672], 100),
        'user': np.random.choice(['alice', 'bob', 'SYSTEM'], 100),
        'source': 'Security'
    })
    
    extractor = FeatureExtractorFactory.get_extractor('evtx')
    features = extractor.extract_features(evtx_data)
    print(f"\nEVTX Features:\n{features.head()}")
    print(f"\nFeature columns: {list(features.columns)}")
