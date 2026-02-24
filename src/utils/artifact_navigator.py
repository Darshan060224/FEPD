"""
Artifact Navigator - Navigate between artifacts and timeline events.
Provides cross-referencing between artifacts and their timeline entries.
"""

import logging
import pandas as pd
from typing import Optional, List, Dict, Any
from datetime import datetime


logger = logging.getLogger(__name__)


class ArtifactNavigator:
    """
    Navigate between artifacts and timeline events.
    
    Features:
    - Find timeline events for specific artifact
    - Filter artifacts by various criteria
    - Get artifact details by hash
    - Cross-reference between artifacts and timeline
    
    Example:
        >>> navigator = ArtifactNavigator(artifacts_df, timeline_df)
        >>> events = navigator.find_artifact_timeline_events('Registry', 'SYSTEM')
        >>> details = navigator.get_artifact_by_hash('abc123...')
    """
    
    def __init__(self, artifacts_df: pd.DataFrame, timeline_df: pd.DataFrame):
        """
        Initialize artifact navigator.
        
        Args:
            artifacts_df: DataFrame with artifact information
            timeline_df: DataFrame with timeline events
        """
        self.artifacts_df = artifacts_df.copy() if artifacts_df is not None else pd.DataFrame()
        self.timeline_df = timeline_df.copy() if timeline_df is not None else pd.DataFrame()
        
        logger.info(f"ArtifactNavigator initialized with {len(self.artifacts_df)} artifacts and {len(self.timeline_df)} timeline events")
    
    def find_artifact_timeline_events(
        self,
        artifact_type: Optional[str] = None,
        artifact_name: Optional[str] = None,
        artifact_path: Optional[str] = None
    ) -> pd.DataFrame:
        """
        Find timeline events related to specific artifact.
        
        Args:
            artifact_type: Type of artifact (e.g., 'Registry', 'Prefetch')
            artifact_name: Name of artifact file
            artifact_path: Path to artifact
        
        Returns:
            DataFrame with matching timeline events
        
        Example:
            >>> events = navigator.find_artifact_timeline_events(
            ...     artifact_type='Registry',
            ...     artifact_name='SYSTEM'
            ... )
            >>> print(f"Found {len(events)} events")
        """
        if self.timeline_df.empty:
            return pd.DataFrame()
        
        # Start with all events
        filtered = self.timeline_df.copy()
        
        # Filter by artifact type
        if artifact_type and 'artifact_source' in filtered.columns:
            filtered = filtered[filtered['artifact_source'].str.contains(artifact_type, case=False, na=False)]
        
        # Filter by artifact name
        if artifact_name and 'artifact_source' in filtered.columns:
            filtered = filtered[filtered['artifact_source'].str.contains(artifact_name, case=False, na=False)]
        
        # Filter by path
        if artifact_path and 'source_path' in filtered.columns:
            filtered = filtered[filtered['source_path'].str.contains(artifact_path, case=False, na=False)]
        
        logger.info(f"Found {len(filtered)} timeline events for artifact")
        return filtered
    
    def filter_artifacts(
        self,
        artifact_type: Optional[str] = None,
        hash_value: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        path_contains: Optional[str] = None
    ) -> pd.DataFrame:
        """
        Filter artifacts by multiple criteria.
        
        Args:
            artifact_type: Type filter (Registry, Prefetch, etc.)
            hash_value: MD5/SHA256 hash to match
            date_from: Start date filter
            date_to: End date filter
            path_contains: Path substring filter
        
        Returns:
            DataFrame with filtered artifacts
        
        Example:
            >>> prefetch_files = navigator.filter_artifacts(
            ...     artifact_type='Prefetch',
            ...     date_from=datetime(2024, 1, 1)
            ... )
        """
        if self.artifacts_df.empty:
            return pd.DataFrame()
        
        filtered = self.artifacts_df.copy()
        
        # Filter by type
        if artifact_type and 'type' in filtered.columns:
            filtered = filtered[filtered['type'].str.contains(artifact_type, case=False, na=False)]
        
        # Filter by hash
        if hash_value:
            if 'md5' in filtered.columns:
                filtered = filtered[filtered['md5'].str.contains(hash_value, case=False, na=False)]
            elif 'sha256' in filtered.columns:
                filtered = filtered[filtered['sha256'].str.contains(hash_value, case=False, na=False)]
        
        # Filter by date range
        if date_from and 'modified' in filtered.columns:
            filtered['modified_dt'] = pd.to_datetime(filtered['modified'], errors='coerce')
            filtered = filtered[filtered['modified_dt'] >= date_from]
        
        if date_to and 'modified' in filtered.columns:
            if 'modified_dt' not in filtered.columns:
                filtered['modified_dt'] = pd.to_datetime(filtered['modified'], errors='coerce')
            filtered = filtered[filtered['modified_dt'] <= date_to]
        
        # Filter by path
        if path_contains and 'path' in filtered.columns:
            filtered = filtered[filtered['path'].str.contains(path_contains, case=False, na=False)]
        
        logger.info(f"Filtered to {len(filtered)} artifacts")
        return filtered
    
    def get_artifact_by_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """
        Get artifact details by hash value.
        
        Args:
            hash_value: MD5 or SHA256 hash
        
        Returns:
            Dictionary with artifact details, or None if not found
        
        Example:
            >>> artifact = navigator.get_artifact_by_hash('abc123...')
            >>> if artifact:
            ...     print(artifact['name'])
        """
        if self.artifacts_df.empty:
            return None
        
        # Check MD5
        if 'md5' in self.artifacts_df.columns:
            matches = self.artifacts_df[self.artifacts_df['md5'] == hash_value]
            if not matches.empty:
                return matches.iloc[0].to_dict()
        
        # Check SHA256
        if 'sha256' in self.artifacts_df.columns:
            matches = self.artifacts_df[self.artifacts_df['sha256'] == hash_value]
            if not matches.empty:
                return matches.iloc[0].to_dict()
        
        return None
    
    def get_artifact_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about artifacts.
        
        Returns:
            Dictionary with statistics
        
        Example:
            >>> stats = navigator.get_artifact_statistics()
            >>> print(f"Total: {stats['total']}, By type: {stats['by_type']}")
        """
        if self.artifacts_df.empty:
            return {'total': 0, 'by_type': {}}
        
        stats = {
            'total': len(self.artifacts_df),
            'by_type': {}
        }
        
        # Count by type
        if 'type' in self.artifacts_df.columns:
            stats['by_type'] = self.artifacts_df['type'].value_counts().to_dict()
        
        # Total size
        if 'size' in self.artifacts_df.columns:
            stats['total_size'] = self.artifacts_df['size'].sum()
        
        return stats
    
    def find_related_artifacts(self, artifact_path: str, max_results: int = 10) -> pd.DataFrame:
        """
        Find artifacts related to given artifact (same directory, similar name).
        
        Args:
            artifact_path: Path to artifact
            max_results: Maximum results to return
        
        Returns:
            DataFrame with related artifacts
        """
        if self.artifacts_df.empty or 'path' not in self.artifacts_df.columns:
            return pd.DataFrame()
        
        # Extract directory
        import os
        directory = os.path.dirname(artifact_path)
        
        # Find artifacts in same directory
        related = self.artifacts_df[
            self.artifacts_df['path'].str.contains(directory, case=False, na=False)
        ]
        
        return related.head(max_results)


if __name__ == '__main__':
    """Quick test of ArtifactNavigator."""
    print("=" * 60)
    print("ArtifactNavigator Test")
    print("=" * 60)
    
    # Create sample data
    artifacts_df = pd.DataFrame({
        'type': ['Registry', 'Registry', 'Prefetch', 'Prefetch', 'MFT'],
        'name': ['SYSTEM', 'SOFTWARE', 'chrome.exe-ABC.pf', 'firefox.exe-XYZ.pf', '$MFT'],
        'path': ['/Windows/System32/config/SYSTEM', '/Windows/System32/config/SOFTWARE',
                 '/Windows/Prefetch/chrome.exe-ABC.pf', '/Windows/Prefetch/firefox.exe-XYZ.pf',
                 '/$MFT'],
        'md5': ['aaa111', 'bbb222', 'ccc333', 'ddd444', 'eee555'],
        'size': [10000, 20000, 5000, 6000, 1000000]
    })
    
    timeline_df = pd.DataFrame({
        'timestamp': pd.date_range('2024-01-01', periods=10, freq='H'),
        'artifact_source': ['Registry/SYSTEM'] * 3 + ['Registry/SOFTWARE'] * 2 + 
                          ['Prefetch/chrome.exe'] * 3 + ['MFT'] * 2,
        'event_type': ['Registry Key Modified'] * 5 + ['Program Executed'] * 3 + ['File Modified'] * 2
    })
    
    print(f"\n✓ Created sample data:")
    print(f"  - {len(artifacts_df)} artifacts")
    print(f"  - {len(timeline_df)} timeline events")
    
    # Initialize navigator
    navigator = ArtifactNavigator(artifacts_df, timeline_df)
    print(f"\n✓ Navigator initialized")
    
    # Test: Find timeline events for Registry
    print("\n1. Finding timeline events for Registry artifacts...")
    events = navigator.find_artifact_timeline_events(artifact_type='Registry')
    print(f"   Found {len(events)} events")
    assert len(events) == 5
    
    # Test: Filter artifacts by type
    print("\n2. Filtering Prefetch artifacts...")
    prefetch = navigator.filter_artifacts(artifact_type='Prefetch')
    print(f"   Found {len(prefetch)} Prefetch files")
    assert len(prefetch) == 2
    
    # Test: Get artifact by hash
    print("\n3. Getting artifact by hash...")
    artifact = navigator.get_artifact_by_hash('ccc333')
    print(f"   Found: {artifact['name']}")
    assert artifact['name'] == 'chrome.exe-ABC.pf'
    
    # Test: Get statistics
    print("\n4. Getting artifact statistics...")
    stats = navigator.get_artifact_statistics()
    print(f"   Total: {stats['total']}")
    print(f"   By type: {stats['by_type']}")
    assert stats['total'] == 5
    
    # Test: Find related artifacts
    print("\n5. Finding related artifacts...")
    related = navigator.find_related_artifacts('/Windows/Prefetch/chrome.exe-ABC.pf')
    print(f"   Found {len(related)} related artifacts")
    assert len(related) >= 1
    
    print("\n" + "=" * 60)
    print("✅ All ArtifactNavigator tests passed!")
    print("=" * 60)
