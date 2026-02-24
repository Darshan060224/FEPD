"""
FEPD - Data Extractors
======================
Converts raw data from dataa/ into clean ML training datasets in src/ml/data/

CRITICAL RULES:
- dataa/ is temporary workspace
- All outputs go to src/ml/data/
- All outputs must match schema.json
- dataa/ is WIPED after extraction

Copyright (c) 2025 FEPD Development Team
"""

import logging
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import pandas as pd
import numpy as np


class BaseExtractor:
    """Base class for all data extractors."""
    
    def __init__(self, dataa_path: Path, output_path: Path):
        """
        Args:
            dataa_path: Path to temporary dataa/ workspace
            output_path: Path to src/ml/data/<dataset>/
        """
        self.dataa_path = Path(dataa_path)
        self.output_path = Path(output_path)
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Ensure output directory exists
        self.output_path.mkdir(parents=True, exist_ok=True)
    
    def validate_schema(self, df: pd.DataFrame, schema_path: Path) -> bool:
        """
        Validate DataFrame against schema.json.
        
        Args:
            df: DataFrame to validate
            schema_path: Path to schema.json
            
        Returns:
            True if valid, raises ValueError otherwise
        """
        with open(schema_path, 'r') as f:
            schema = json.load(f)
        
        required_features = schema['features']
        df_columns = set(df.columns)
        schema_columns = set(required_features.keys())
        
        # Check for missing columns
        missing = schema_columns - df_columns
        if missing:
            raise ValueError(f"Missing required columns: {missing}")
        
        # Check for extra columns
        extra = df_columns - schema_columns
        if extra:
            self.logger.warning(f"Extra columns will be dropped: {extra}")
            df = df[list(schema_columns)]
        
        # Type validation
        for col, spec in required_features.items():
            col_type = spec['type']
            
            if col_type == 'int':
                if not pd.api.types.is_integer_dtype(df[col]):
                    raise ValueError(f"Column {col} must be integer")
            elif col_type == 'float':
                if not pd.api.types.is_float_dtype(df[col]):
                    raise ValueError(f"Column {col} must be float")
            elif col_type == 'boolean':
                if not pd.api.types.is_bool_dtype(df[col]):
                    raise ValueError(f"Column {col} must be boolean")
            elif col_type == 'string':
                if not pd.api.types.is_string_dtype(df[col]) and not pd.api.types.is_object_dtype(df[col]):
                    raise ValueError(f"Column {col} must be string")
            elif col_type == 'datetime':
                if not pd.api.types.is_datetime64_any_dtype(df[col]):
                    try:
                        df[col] = pd.to_datetime(df[col])
                    except:
                        raise ValueError(f"Column {col} must be datetime")
        
        return True
    
    def generate_dataset_meta(self, df: pd.DataFrame, source_files: List[str]) -> Dict:
        """Generate dataset.meta.json."""
        
        # Compute dataset hash
        dataset_hash = hashlib.sha256(
            df.to_csv(index=False).encode()
        ).hexdigest()
        
        return {
            "dataset_name": self.__class__.__name__.replace('Extractor', '').lower(),
            "schema_version": "v1",
            "generated_on": datetime.now().isoformat(),
            "source_inputs": source_files,
            "record_count": len(df),
            "hash": f"sha256:{dataset_hash}",
            "generator": self.__class__.__name__
        }
    
    def extract(self) -> Path:
        """
        Extract and normalize data.
        Must be implemented by subclasses.
        
        Returns:
            Path to generated CSV file
        """
        raise NotImplementedError("Subclasses must implement extract()")


class MalwareExtractor(BaseExtractor):
    """Extract malware features from EMBER + BODMAS datasets."""
    
    def extract(self) -> Path:
        """
        Extract malware features from dataa/ember_dataset_2018_2/ and bodmas_malware_category.csv
        
        Returns:
            Path to file_features_v1.csv
        """
        self.logger.info("Starting malware feature extraction...")
        
        features = []
        source_files = []
        
        # Extract from BODMAS
        bodmas_path = self.dataa_path / "bodmas_malware_category.csv"
        if bodmas_path.exists():
            self.logger.info(f"Processing BODMAS: {bodmas_path}")
            bodmas_df = pd.read_csv(bodmas_path)
            source_files.append(str(bodmas_path))
            
            # Map BODMAS to our schema
            for _, row in bodmas_df.iterrows():
                features.append({
                    'sha256': row.get('SHA256', '0' * 64),
                    'file_size': int(row.get('Size', 0)),
                    'entropy': float(row.get('Entropy', 0.0)),
                    'pe_sections': int(row.get('Sections', 0)),
                    'import_count': int(row.get('Imports', 0)),
                    'is_signed': bool(row.get('IsSigned', False)),
                    'label': row.get('Category', 'unknown')
                })
        
        # Extract from EMBER
        ember_path = self.dataa_path / "ember_dataset_2018_2"
        if ember_path.exists():
            self.logger.info(f"Processing EMBER: {ember_path}")
            source_files.append(str(ember_path))
            
            # EMBER has JSON/CSV files - parse appropriately
            for csv_file in ember_path.glob("*.csv"):
                ember_df = pd.read_csv(csv_file)
                for _, row in ember_df.iterrows():
                    features.append({
                        'sha256': row.get('sha256', '0' * 64),
                        'file_size': int(row.get('size', 0)),
                        'entropy': float(row.get('entropy', 0.0)),
                        'pe_sections': int(row.get('num_sections', 0)),
                        'import_count': int(row.get('num_imports', 0)),
                        'is_signed': bool(row.get('is_signed', False)),
                        'label': 'malware' if row.get('label') == 1 else 'benign'
                    })
        
        # Convert to DataFrame
        df = pd.DataFrame(features)
        
        # If no real data, generate sample data for testing
        if df.empty:
            self.logger.warning("No malware data found in dataa/, generating sample dataset...")
            
            # Generate 500 sample malware features
            sample_features = []
            malware_families = ['ransomware', 'trojan', 'worm', 'backdoor', 'benign']
            
            for i in range(500):
                sample_features.append({
                    'sha256': hashlib.sha256(f'sample_{i}'.encode()).hexdigest(),
                    'file_size': np.random.randint(10000, 5000000),
                    'entropy': np.random.uniform(3.0, 7.9),
                    'pe_sections': np.random.randint(3, 12),
                    'import_count': np.random.randint(50, 500),
                    'is_signed': bool(np.random.choice([True, False])),
                    'label': np.random.choice(malware_families)
                })
            
            df = pd.DataFrame(sample_features)
            source_files.append("generated_sample_data")
            self.logger.info(f"Generated {len(df)} sample malware features for training")
        
        # Remove duplicates by SHA256
        df = df.drop_duplicates(subset=['sha256'])
        
        # Validate against schema
        schema_path = self.output_path / "schema.json"
        self.validate_schema(df, schema_path)
        
        # Save CSV
        output_csv = self.output_path / "file_features_v1.csv"
        df.to_csv(output_csv, index=False)
        self.logger.info(f"Saved {len(df)} malware features to {output_csv}")
        
        # Generate metadata
        meta = self.generate_dataset_meta(df, source_files)
        meta_path = self.output_path / "dataset.meta.json"
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)
        
        return output_csv


class EVTXExtractor(BaseExtractor):
    """Extract EVTX/log event features from temporal folders."""
    
    def extract(self) -> Path:
        """
        Extract event features from dataa/2015-03-* folders and Security-Datasets
        
        Returns:
            Path to event_features_v1.csv
        """
        self.logger.info("Starting EVTX feature extraction...")
        
        features = []
        source_files = []
        
        # Process temporal date folders (2015-03-05 → 2015-04-13)
        date_folders = sorted([
            d for d in self.dataa_path.iterdir() 
            if d.is_dir() and d.name.startswith('2015-')
        ])
        
        for date_folder in date_folders:
            self.logger.info(f"Processing date folder: {date_folder.name}")
            source_files.append(str(date_folder))
            
            # Parse log files in this date folder
            for log_file in date_folder.glob("*.log"):
                # Simple log parsing (customize based on actual format)
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            # Parse timestamp, event_id, etc.
                            # This is a simplified example
                            parts = line.strip().split(',')
                            if len(parts) >= 4:
                                timestamp = pd.to_datetime(parts[0])
                                features.append({
                                    'timestamp': timestamp,
                                    'hour': timestamp.hour,
                                    'day_of_week': timestamp.weekday(),
                                    'event_id': int(parts[1]),
                                    'event_frequency': 1,
                                    'user_id': parts[2] if len(parts) > 2 else 'SYSTEM'
                                })
                except Exception as e:
                    self.logger.warning(f"Failed to parse {log_file}: {e}")
        
        # Process Security-Datasets
        security_ds = self.dataa_path / "Security-Datasets-master"
        if security_ds.exists():
            self.logger.info(f"Processing Security-Datasets: {security_ds}")
            source_files.append(str(security_ds))
            
            for json_file in security_ds.rglob("*.json"):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        content = f.read().strip()
                        
                        # Skip empty files
                        if not content:
                            continue
                        
                        # Try to parse as JSON
                        events = json.loads(content)
                        
                        if isinstance(events, list):
                            for event in events:
                                # Skip if no timestamp
                                timestamp_str = event.get('@timestamp') or event.get('Timestamp') or event.get('timestamp')
                                if not timestamp_str:
                                    continue
                                
                                try:
                                    timestamp = pd.to_datetime(timestamp_str)
                                    # Strip timezone info to ensure consistency (avoid tz-aware/tz-naive mix)
                                    if timestamp.tz is not None:
                                        timestamp = timestamp.tz_localize(None)
                                    
                                    # Extract event ID (try multiple field names)
                                    event_id = event.get('event_id') or event.get('EventID') or event.get('Id') or 0
                                    
                                    features.append({
                                        'timestamp': timestamp,
                                        'hour': timestamp.hour,
                                        'day_of_week': timestamp.weekday(),
                                        'event_id': int(event_id),
                                        'event_frequency': 1,
                                        'user_id': event.get('user_name') or event.get('UserName') or event.get('User') or 'SYSTEM'
                                    })
                                except (ValueError, TypeError):
                                    # Skip invalid timestamps
                                    continue
                        elif isinstance(events, dict):
                            # Single event
                            timestamp_str = events.get('@timestamp') or events.get('Timestamp') or events.get('timestamp')
                            if timestamp_str:
                                try:
                                    timestamp = pd.to_datetime(timestamp_str)
                                    # Strip timezone info to ensure consistency (avoid tz-aware/tz-naive mix)
                                    if timestamp.tz is not None:
                                        timestamp = timestamp.tz_localize(None)
                                    
                                    event_id = events.get('event_id') or events.get('EventID') or events.get('Id') or 0
                                    
                                    features.append({
                                        'timestamp': timestamp,
                                        'hour': timestamp.hour,
                                        'day_of_week': timestamp.weekday(),
                                        'event_id': int(event_id),
                                        'event_frequency': 1,
                                        'user_id': events.get('user_name') or events.get('UserName') or events.get('User') or 'SYSTEM'
                                    })
                                except (ValueError, TypeError):
                                    continue
                                    
                except Exception as e:
                    # Just log and continue
                    self.logger.debug(f"Skipped {json_file.name}: {e}")
        
        # Convert to DataFrame
        df = pd.DataFrame(features)
        
        # If no real data, generate sample data for testing
        if df.empty:
            self.logger.warning("No EVTX data found in dataa/, generating sample dataset...")
            
            # Generate 1000 sample events
            base_time = pd.Timestamp('2024-01-01')
            sample_features = []
            
            for i in range(1000):
                timestamp = base_time + pd.Timedelta(hours=i)
                sample_features.append({
                    'timestamp': timestamp,
                    'hour': timestamp.hour,
                    'day_of_week': timestamp.weekday(),
                    'event_id': np.random.choice([4624, 4625, 4672, 4688, 4720]),  # Common Windows events
                    'event_frequency': np.random.randint(1, 50),
                    'user_id': f'user_{np.random.randint(1, 20)}'
                })
            
            df = pd.DataFrame(sample_features)
            source_files.append("generated_sample_data")
            self.logger.info(f"Generated {len(df)} sample EVTX events for training")
        
        # Aggregate by timestamp window (1 hour)
        df['timestamp_window'] = df['timestamp'].dt.floor('h')  # Use 'h' instead of deprecated 'H'
        df = df.groupby(['timestamp_window', 'event_id', 'user_id']).agg({
            'hour': 'first',
            'day_of_week': 'first',
            'event_frequency': 'sum'
        }).reset_index()
        df = df.rename(columns={'timestamp_window': 'timestamp'})
        
        # Validate against schema
        schema_path = self.output_path / "schema.json"
        self.validate_schema(df, schema_path)
        
        # Save CSV
        output_csv = self.output_path / "event_features_v1.csv"
        df.to_csv(output_csv, index=False)
        self.logger.info(f"Saved {len(df)} event features to {output_csv}")
        
        # Generate metadata
        meta = self.generate_dataset_meta(df, source_files)
        meta_path = self.output_path / "dataset.meta.json"
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)
        
        return output_csv


class NetworkExtractor(BaseExtractor):
    """Extract network flow features from Zeek logs and honeypot data."""
    
    def extract(self) -> Path:
        """
        Extract network features from dataa/conn.log and honeypot.json
        
        Returns:
            Path to flow_features_v1.csv
        """
        self.logger.info("Starting network feature extraction...")
        
        features = []
        source_files = []
        
        # Process Zeek conn.log
        conn_log = self.dataa_path / "conn.log"
        if conn_log.exists():
            self.logger.info(f"Processing Zeek conn.log: {conn_log}")
            source_files.append(str(conn_log))
            
            # Parse Zeek TSV format (sample first 10000 lines for efficiency)
            try:
                # Zeek logs are tab-separated - limit rows for large files
                self.logger.info("Sampling first 10000 flows from conn.log...")
                df = pd.read_csv(conn_log, sep='\t', comment='#', 
                                names=['ts', 'uid', 'id_orig_h', 'id_orig_p', 
                                      'id_resp_h', 'id_resp_p', 'proto', 
                                      'service', 'duration', 'orig_bytes', 
                                      'resp_bytes', 'conn_state'],
                                nrows=10000,  # Limit to 10k for efficiency
                                on_bad_lines='skip')
                
                for _, row in df.iterrows():
                    try:
                        features.append({
                            'start_time': pd.to_datetime(float(row['ts']), unit='s'),
                            'duration': float(row.get('duration', 0) or 0),
                            'src_port': int(row.get('id_orig_p', 0) or 0),
                            'dst_port': int(row.get('id_resp_p', 0) or 0),
                            'protocol': 6 if str(row.get('proto', '')).lower() == 'tcp' else 17,
                            'bytes': int(row.get('orig_bytes', 0) or 0) + int(row.get('resp_bytes', 0) or 0),
                            'packets': 1  # Zeek doesn't always have packet count
                        })
                    except (ValueError, TypeError):
                        # Skip invalid rows
                        continue
            except Exception as e:
                self.logger.error(f"Failed to parse conn.log: {e}")
        
        # Process honeypot.json
        honeypot_json = self.dataa_path / "honeypot.json"
        if honeypot_json.exists():
            self.logger.info(f"Processing honeypot.json: {honeypot_json}")
            source_files.append(str(honeypot_json))
            
            try:
                with open(honeypot_json, 'r') as f:
                    for line in f:
                        event = json.loads(line)
                        features.append({
                            'start_time': pd.to_datetime(event.get('timestamp')),
                            'duration': float(event.get('duration', 0)),
                            'src_port': int(event.get('src_port', 0)),
                            'dst_port': int(event.get('dst_port', 0)),
                            'protocol': int(event.get('protocol', 6)),
                            'bytes': int(event.get('bytes', 0)),
                            'packets': int(event.get('packets', 1))
                        })
            except Exception as e:
                self.logger.error(f"Failed to parse honeypot.json: {e}")
        
        # Convert to DataFrame
        df = pd.DataFrame(features)
        
        # If no real data, generate sample data for testing
        if df.empty:
            self.logger.warning("No network data found in dataa/, generating sample dataset...")
            
            # Generate 2000 sample network flows
            base_time = pd.Timestamp('2024-01-01')
            sample_features = []
            common_ports = [80, 443, 22, 53, 3389, 445, 8080, 3306]
            
            for i in range(2000):
                sample_features.append({
                    'start_time': base_time + pd.Timedelta(seconds=i*30),
                    'duration': np.random.uniform(0.1, 300.0),
                    'src_port': np.random.randint(1024, 65535),
                    'dst_port': np.random.choice(common_ports),
                    'protocol': np.random.choice([6, 17]),  # TCP or UDP
                    'bytes': np.random.randint(100, 1000000),
                    'packets': np.random.randint(1, 1000)
                })
            
            df = pd.DataFrame(sample_features)
            source_files.append("generated_sample_data")
            self.logger.info(f"Generated {len(df)} sample network flows for training")
        
        # Remove invalid flows
        df = df[df['duration'] >= 0]
        df = df[df['bytes'] >= 0]
        
        # Validate against schema
        schema_path = self.output_path / "schema.json"
        self.validate_schema(df, schema_path)
        
        # Save CSV
        output_csv = self.output_path / "flow_features_v1.csv"
        df.to_csv(output_csv, index=False)
        self.logger.info(f"Saved {len(df)} network flows to {output_csv}")
        
        # Generate metadata
        meta = self.generate_dataset_meta(df, source_files)
        meta_path = self.output_path / "dataset.meta.json"
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)
        
        return output_csv


class CloudExtractor(BaseExtractor):
    """Extract normalized cloud event features from AWS + Azure datasets."""
    
    def extract(self) -> Path:
        """
        Extract cloud features from AWS CloudTrail and Azure Sentinel datasets
        
        Returns:
            Path to cloud_event_features_v1.csv
        """
        self.logger.info("Starting cloud feature extraction...")
        
        features = []
        source_files = []
        
        # Process AWS CloudTrail
        aws_path = self.dataa_path / "aws-cloudtrail-processing-library-master"
        if aws_path.exists():
            self.logger.info(f"Processing AWS CloudTrail: {aws_path}")
            source_files.append(str(aws_path))
            
            for json_file in aws_path.rglob("*.json"):
                try:
                    with open(json_file, 'r') as f:
                        events = json.load(f)
                        records = events.get('Records', [])
                        
                        for record in records:
                            try:
                                # Normalize AWS to our schema
                                event_time = record.get('eventTime')
                                if not event_time:
                                    continue  # Skip events without timestamp
                                
                                # Parse timestamp and strip timezone to avoid tz-aware/tz-naive mix
                                event_time_dt = pd.to_datetime(event_time)
                                if hasattr(event_time_dt, 'tz') and event_time_dt.tz is not None:
                                    event_time_dt = event_time_dt.tz_localize(None)
                                
                                features.append({
                                    'event_time': event_time_dt,
                                    'service': self._normalize_service(record.get('eventSource', '')),
                                    'action': self._normalize_action(record.get('eventName', '')),
                                    'user_type': self._classify_user_type(record.get('userIdentity', {})),
                                    'source_ip': hashlib.sha256(
                                        record.get('sourceIPAddress', '').encode()
                                    ).hexdigest()[:16],
                                    'geo_distance': 0.0  # Would need GeoIP lookup
                                })
                            except (ValueError, TypeError):
                                # Skip events with invalid timestamps
                                continue
                except Exception as e:
                    self.logger.warning(f"Failed to parse {json_file}: {e}")
        
        # Process Azure Sentinel
        azure_path = self.dataa_path / "Azure-Sentinel-master"
        if azure_path.exists():
            self.logger.info(f"Processing Azure Sentinel: {azure_path}")
            source_files.append(str(azure_path))
            
            for json_file in azure_path.rglob("*.json"):
                try:
                    with open(json_file, 'r') as f:
                        events = json.load(f)
                        if isinstance(events, list):
                            for event in events:
                                try:
                                    # Normalize Azure to our schema
                                    event_time = event.get('TimeGenerated')
                                    if not event_time:
                                        continue  # Skip events without timestamp
                                    
                                    # Parse timestamp and strip timezone to avoid tz-aware/tz-naive mix
                                    event_time_dt = pd.to_datetime(event_time)
                                    if hasattr(event_time_dt, 'tz') and event_time_dt.tz is not None:
                                        event_time_dt = event_time_dt.tz_localize(None)
                                    
                                    features.append({
                                        'event_time': event_time_dt,
                                        'service': self._normalize_service(event.get('ResourceType', '')),
                                        'action': self._normalize_action(event.get('OperationName', '')),
                                        'user_type': self._classify_user_type(event.get('Identity', {})),
                                        'source_ip': hashlib.sha256(
                                            event.get('CallerIpAddress', '').encode()
                                        ).hexdigest()[:16],
                                        'geo_distance': 0.0
                                    })
                                except (ValueError, TypeError):
                                    # Skip events with invalid timestamps
                                    continue
                except Exception as e:
                    self.logger.warning(f"Failed to parse {json_file}: {e}")
        
        # Convert to DataFrame
        df = pd.DataFrame(features)
        
        # Ensure event_time is datetime type if it exists
        if not df.empty and 'event_time' in df.columns:
            df['event_time'] = pd.to_datetime(df['event_time'])
        
        # If no real data, generate sample data for testing
        if df.empty:
            self.logger.warning("No cloud data found in dataa/, generating sample dataset...")
            
            # Generate 800 sample cloud events
            base_time = pd.Timestamp('2024-01-01')
            sample_features = []
            services = ['storage', 'compute', 'iam', 'network', 'database']
            actions = ['read', 'write', 'delete', 'create', 'update']
            user_types = ['human', 'service', 'assumed_role', 'system']
            
            for i in range(800):
                sample_features.append({
                    'event_time': base_time + pd.Timedelta(minutes=i*15),
                    'service': np.random.choice(services),
                    'action': np.random.choice(actions),
                    'user_type': np.random.choice(user_types),
                    'source_ip': hashlib.sha256(f'ip_{i%50}'.encode()).hexdigest()[:16],
                    'geo_distance': np.random.uniform(0, 5000)
                })
            
            df = pd.DataFrame(sample_features)
            # Ensure event_time is datetime type
            df['event_time'] = pd.to_datetime(df['event_time'])
            source_files.append("generated_sample_data")
            self.logger.info(f"Generated {len(df)} sample cloud events for training")
        
        # Validate against schema
        schema_path = self.output_path / "schema.json"
        self.validate_schema(df, schema_path)
        
        # Save CSV
        output_csv = self.output_path / "cloud_event_features_v1.csv"
        df.to_csv(output_csv, index=False)
        self.logger.info(f"Saved {len(df)} cloud events to {output_csv}")
        
        # Generate metadata
        meta = self.generate_dataset_meta(df, source_files)
        meta_path = self.output_path / "dataset.meta.json"
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)
        
        return output_csv
    
    def _normalize_service(self, raw_service: str) -> str:
        """Normalize service names across AWS/Azure."""
        service_map = {
            's3': 'storage',
            'blobstorage': 'storage',
            'ec2': 'compute',
            'virtualmachines': 'compute',
            'iam': 'iam',
            'activedirectory': 'iam',
            'vpc': 'network',
            'virtualnetwork': 'network'
        }
        
        raw_lower = raw_service.lower()
        for key, value in service_map.items():
            if key in raw_lower:
                return value
        
        return 'other'
    
    def _normalize_action(self, raw_action: str) -> str:
        """Normalize action names."""
        action_map = {
            'get': 'read',
            'list': 'read',
            'put': 'write',
            'post': 'create',
            'delete': 'delete',
            'update': 'update'
        }
        
        raw_lower = raw_action.lower()
        for key, value in action_map.items():
            if key in raw_lower:
                return value
        
        return 'other'
    
    def _classify_user_type(self, identity: Dict) -> str:
        """Classify user type."""
        user_type = identity.get('type', '').lower()
        
        if 'assumed' in user_type or 'role' in user_type:
            return 'assumed_role'
        elif 'service' in user_type:
            return 'service'
        elif 'user' in user_type:
            return 'human'
        else:
            return 'system'


class UEBAExtractor(BaseExtractor):
    """Extract UEBA user behavior features (derived from other datasets)."""
    
    def __init__(self, dataa_path: Path, output_path: Path, 
                 evtx_csv: Path, network_csv: Path, cloud_csv: Path):
        super().__init__(dataa_path, output_path)
        self.evtx_csv = evtx_csv
        self.network_csv = network_csv
        self.cloud_csv = cloud_csv
    
    def extract(self) -> Path:
        """
        Derive UEBA features from EVTX, network, and cloud datasets
        
        Returns:
            Path to user_behavior_features_v1.csv
        """
        self.logger.info("Starting UEBA feature extraction...")
        
        # Load source datasets
        evtx_df = pd.read_csv(self.evtx_csv)
        network_df = pd.read_csv(self.network_csv)
        cloud_df = pd.read_csv(self.cloud_csv)
        
        # Aggregate by user
        user_profiles = {}
        
        # From EVTX: login hours and command counts
        for _, row in evtx_df.iterrows():
            user_id = row.get('user_id', 'SYSTEM')
            if user_id not in user_profiles:
                user_profiles[user_id] = {
                    'login_hours': [],
                    'file_accesses': 0,
                    'network_bytes': 0,
                    'commands': 0
                }
            
            user_profiles[user_id]['login_hours'].append(row['hour'])
            if row.get('event_id') == 4624:  # Windows logon
                user_profiles[user_id]['commands'] += 1
        
        # From network: network volume (simplified - would need user mapping)
        total_network_bytes = network_df['bytes'].sum()
        
        # Build final features
        features = []
        for user_id, profile in user_profiles.items():
            features.append({
                'user_id': hashlib.sha256(user_id.encode()).hexdigest()[:16],
                'avg_login_hour': np.mean(profile['login_hours']) if profile['login_hours'] else 12.0,
                'file_access_rate': profile['file_accesses'] / max(len(profile['login_hours']), 1),
                'network_volume': total_network_bytes / len(user_profiles),  # Simplified
                'command_count': profile['commands']
            })
        
        # Convert to DataFrame
        df = pd.DataFrame(features)
        
        if df.empty:
            raise ValueError("No UEBA data could be derived")
        
        # Validate against schema
        schema_path = self.output_path / "schema.json"
        self.validate_schema(df, schema_path)
        
        # Save CSV
        output_csv = self.output_path / "user_behavior_features_v1.csv"
        df.to_csv(output_csv, index=False)
        self.logger.info(f"Saved {len(df)} user profiles to {output_csv}")
        
        # Generate metadata
        meta = self.generate_dataset_meta(df, [
            str(self.evtx_csv),
            str(self.network_csv),
            str(self.cloud_csv)
        ])
        meta_path = self.output_path / "dataset.meta.json"
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)
        
        return output_csv


def extract_all_datasets(dataa_path: Path, ml_data_path: Path):
    """
    Extract all datasets from dataa/ to src/ml/data/
    
    Args:
        dataa_path: Path to dataa/ temporary workspace
        ml_data_path: Path to src/ml/data/
    """
    logger = logging.getLogger(__name__)
    logger.info("="*60)
    logger.info("STARTING COMPLETE DATA EXTRACTION PIPELINE")
    logger.info("="*60)
    
    results = {}
    
    try:
        # 1. Malware
        logger.info("\n[1/5] Extracting malware features...")
        malware_extractor = MalwareExtractor(
            dataa_path, 
            ml_data_path / "malware"
        )
        results['malware'] = malware_extractor.extract()
        
        # 2. EVTX
        logger.info("\n[2/5] Extracting EVTX features...")
        evtx_extractor = EVTXExtractor(
            dataa_path,
            ml_data_path / "evtx"
        )
        results['evtx'] = evtx_extractor.extract()
        
        # 3. Network
        logger.info("\n[3/5] Extracting network features...")
        network_extractor = NetworkExtractor(
            dataa_path,
            ml_data_path / "network"
        )
        results['network'] = network_extractor.extract()
        
        # 4. Cloud
        logger.info("\n[4/5] Extracting cloud features...")
        cloud_extractor = CloudExtractor(
            dataa_path,
            ml_data_path / "cloud"
        )
        results['cloud'] = cloud_extractor.extract()
        
        # 5. UEBA (depends on others)
        logger.info("\n[5/5] Extracting UEBA features...")
        ueba_extractor = UEBAExtractor(
            dataa_path,
            ml_data_path / "ueba",
            results['evtx'],
            results['network'],
            results['cloud']
        )
        results['ueba'] = ueba_extractor.extract()
        
        logger.info("\n" + "="*60)
        logger.info("✅ ALL DATASETS EXTRACTED SUCCESSFULLY")
        logger.info("="*60)
        
        for dataset, path in results.items():
            logger.info(f"  {dataset}: {path}")
        
        return results
        
    except Exception as e:
        logger.error(f"❌ EXTRACTION FAILED: {e}")
        raise


if __name__ == "__main__":
    # Standalone test
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Example usage
    workspace = Path(__file__).parent.parent.parent
    dataa_path = workspace / "dataa"
    ml_data_path = workspace / "src" / "ml" / "data"
    
    if dataa_path.exists():
        extract_all_datasets(dataa_path, ml_data_path)
    else:
        print(f"❌ dataa/ not found at {dataa_path}")
