"""
FEPD - Forensic Evidence Parser Dashboard
Normalization Engine Module

Normalizes heterogeneous parsed artifact data into unified 14-field event schema.
Handles timezone conversion, field mapping, and data standardization.

Implements FR-15: Normalize all parsed outputs into a unified event schema

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from zoneinfo import ZoneInfo

try:
    import pandas as pd
except ImportError:
    pd = None


class NormalizationEngine:
    """
    Normalization Engine for converting heterogeneous forensic artifact data
    into a unified 14-field event schema.
    
    Unified Schema Fields:
    - event_id: UUID unique identifier
    - ts_utc: Timestamp in UTC (ISO 8601)
    - ts_local: Timestamp in local timezone
    - artifact_source: Source artifact type (EVTX/Registry/Prefetch/MFT/Browser)
    - artifact_path: File path to source artifact
    - event_type: Normalized event type
    - user_account: Username (if available)
    - exe_name: Executable name (if available)
    - event_id_native: Native event ID (EVTX EventID)
    - filepath: File path (for file events)
    - macb: MACB timestamp flag (M/A/C/B)
    - rule_class: Classification (assigned by rule engine)
    - severity: Severity score 1-5 (assigned by rule engine)
    - description: Human-readable description
    - raw_data_ref: Reference to full raw data
    """
    
    def __init__(self, local_timezone: str = 'UTC', logger: Optional[logging.Logger] = None):
        """
        Initialize Normalization Engine.
        
        Args:
            local_timezone: Target local timezone (e.g., 'America/New_York', 'Europe/London')
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self.local_timezone = local_timezone
        
        if pd is None:
            self.logger.error("pandas library not installed. Install: pip install pandas")
            raise ImportError("pandas library required for normalization")
        
        self.logger.info(f"Normalization Engine initialized (local timezone: {local_timezone})")
    
    def normalize(
        self, 
        parsed_records: List[Dict[str, Any]],
        artifact_source: Optional[str] = None
    ) -> pd.DataFrame:
        """
        Normalize parsed records into unified schema DataFrame.
        
        Args:
            parsed_records: List of heterogeneous parsed records from any parser
            artifact_source: Optional override for artifact source type
            
        Returns:
            pandas DataFrame with normalized events (14-field schema)
        """
        if not parsed_records:
            self.logger.warning("No records to normalize")
            return self._create_empty_dataframe()
        
        self.logger.info(f"Normalizing {len(parsed_records)} records...")
        
        normalized_events = []
        
        for record in parsed_records:
            try:
                normalized_event = self._normalize_record(record, artifact_source)
                normalized_events.append(normalized_event)
            except Exception as e:
                self.logger.warning(f"Failed to normalize record: {e}")
                continue
        
        # Convert to DataFrame
        df = pd.DataFrame(normalized_events)
        
        # Sort by timestamp
        if not df.empty:
            df = df.sort_values('ts_utc')
            df = df.reset_index(drop=True)
        
        self.logger.info(f"Successfully normalized {len(df)} events")
        return df
    
    def _normalize_record(
        self, 
        record: Dict[str, Any],
        artifact_source_override: Optional[str]
    ) -> Dict[str, Any]:
        """
        Normalize a single parsed record into unified schema.
        
        Args:
            record: Parsed record dictionary
            artifact_source_override: Optional artifact source override
            
        Returns:
            Normalized event dictionary
        """
        # Generate unique event ID
        event_id = str(uuid.uuid4())
        
        # Extract and normalize artifact source
        artifact_source = artifact_source_override or record.get('artifact_source', 'Unknown')
        
        # Extract and normalize timestamp
        ts_utc = self._normalize_timestamp(record.get('ts_utc'))
        ts_local = self._convert_to_local_time(ts_utc)
        
        # Extract artifact path
        artifact_path = record.get('artifact_path', '')
        
        # Normalize event type
        event_type = self._normalize_event_type(record.get('event_type', 'Unknown'), artifact_source)
        
        # Extract user account (different fields depending on source)
        user_account = record.get('user_account') or record.get('user_id') or record.get('username')
        
        # Extract executable name
        exe_name = record.get('exe_name') or record.get('process_name') or record.get('executable')
        
        # Extract native event ID (EVTX specific)
        event_id_native = record.get('event_id_native') or record.get('event_id') or record.get('eventid')
        
        # Extract file path (MFT/file events)
        filepath = record.get('filepath') or record.get('file_path') or record.get('path')
        
        # Extract MACB flag (MFT specific)
        macb = record.get('macb')
        
        # Placeholder for rule classification (will be assigned by rule engine)
        rule_class = None
        severity = None
        
        # Generate description
        description = record.get('description') or self._generate_description(
            artifact_source, event_type, exe_name, filepath, user_account
        )
        
        # Raw data reference
        raw_data_ref = record.get('raw_data_ref', '')
        
        return {
            'event_id': event_id,
            'ts_utc': ts_utc,
            'ts_local': ts_local,
            'artifact_source': artifact_source,
            'artifact_path': artifact_path,
            'event_type': event_type,
            'user_account': user_account,
            'exe_name': exe_name,
            'event_id_native': event_id_native,
            'filepath': filepath,
            'macb': macb,
            'rule_class': rule_class,
            'severity': severity,
            'description': description,
            'raw_data_ref': raw_data_ref
        }
    
    def _normalize_timestamp(self, ts: Any) -> str:
        """
        Normalize timestamp to UTC ISO 8601 format.
        
        Args:
            ts: Timestamp (string, datetime, or None)
            
        Returns:
            ISO 8601 UTC timestamp string
        """
        if ts is None:
            return datetime.now(timezone.utc).isoformat()
        
        if isinstance(ts, str):
            # Already ISO 8601 string
            try:
                # Validate by parsing
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                return dt.astimezone(timezone.utc).isoformat()
            except Exception:
                self.logger.warning(f"Invalid timestamp string: {ts}")
                return datetime.now(timezone.utc).isoformat()
        
        if isinstance(ts, datetime):
            return ts.astimezone(timezone.utc).isoformat()
        
        # Fallback
        return datetime.now(timezone.utc).isoformat()
    
    def _convert_to_local_time(self, ts_utc: str) -> str:
        """
        Convert UTC timestamp to local timezone.
        
        Args:
            ts_utc: UTC ISO 8601 timestamp
            
        Returns:
            Local timezone ISO 8601 timestamp
        """
        if self.local_timezone == 'UTC':
            return ts_utc
        
        try:
            dt_utc = datetime.fromisoformat(ts_utc.replace('Z', '+00:00'))
            local_tz = ZoneInfo(self.local_timezone)
            dt_local = dt_utc.astimezone(local_tz)
            return dt_local.isoformat()
        except Exception as e:
            self.logger.warning(f"Failed to convert to local time: {e}")
            return ts_utc
    
    def _normalize_event_type(self, event_type: str, artifact_source: str) -> str:
        """
        Normalize event type strings for consistency.
        
        Args:
            event_type: Raw event type from parser
            artifact_source: Artifact source type
            
        Returns:
            Normalized event type string
        """
        # Normalize common variations
        type_mapping = {
            'ProcessExecution': 'ProcessExecution',
            'WindowsEvent': 'WindowsEvent',
            'RegKeyModified': 'RegistryModified',
            'RegKeyCreated': 'RegistryCreated',
            'FileModified': 'FileModified',
            'FileAccessed': 'FileAccessed',
            'FileChanged': 'FileChanged',
            'FileCreated': 'FileCreated',
            'URLVisit': 'BrowserURLVisit',
        }
        
        return type_mapping.get(event_type, event_type)
    
    def _generate_description(
        self,
        artifact_source: str,
        event_type: str,
        exe_name: Optional[str],
        filepath: Optional[str],
        user_account: Optional[str]
    ) -> str:
        """
        Generate human-readable description when not provided.
        
        Args:
            artifact_source: Artifact source
            event_type: Event type
            exe_name: Executable name
            filepath: File path
            user_account: User account
            
        Returns:
            Description string
        """
        parts = [artifact_source, event_type]
        
        if exe_name:
            parts.append(f"exe={exe_name}")
        if filepath:
            parts.append(f"file={Path(filepath).name}")
        if user_account:
            parts.append(f"user={user_account}")
        
        return " | ".join(parts)
    
    def _create_empty_dataframe(self) -> pd.DataFrame:
        """
        Create empty DataFrame with correct schema.
        
        Returns:
            Empty DataFrame with 14-field schema
        """
        return pd.DataFrame(columns=[
            'event_id',
            'ts_utc',
            'ts_local',
            'artifact_source',
            'artifact_path',
            'event_type',
            'user_account',
            'exe_name',
            'event_id_native',
            'filepath',
            'macb',
            'rule_class',
            'severity',
            'description',
            'raw_data_ref'
        ])
    
    def export_to_csv(self, df: pd.DataFrame, output_path: Path) -> None:
        """
        Export normalized DataFrame to CSV file.
        
        Args:
            df: Normalized DataFrame
            output_path: Path to output CSV file
        """
        try:
            df.to_csv(output_path, index=False, encoding='utf-8')
            self.logger.info(f"Exported {len(df)} events to {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to export CSV: {e}")
            raise
    
    def get_statistics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Generate statistics about normalized data.
        
        Args:
            df: Normalized DataFrame
            
        Returns:
            Dictionary with statistics
        """
        if df.empty:
            return {'total_events': 0}
        
        stats = {
            'total_events': len(df),
            'artifact_sources': df['artifact_source'].value_counts().to_dict(),
            'event_types': df['event_type'].value_counts().to_dict(),
            'time_range': {
                'earliest': df['ts_utc'].min(),
                'latest': df['ts_utc'].max()
            },
            'unique_users': df['user_account'].nunique() if 'user_account' in df else 0,
            'unique_executables': df['exe_name'].nunique() if 'exe_name' in df else 0
        }
        
        return stats
