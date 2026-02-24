"""
ML Data Preparation for Forensic Evidence Processing and Detection
Prepares data from dataa folder for machine learning training:
- Malware classification (bodmas_malware_category.csv)
- Network intrusion detection (Snort logs)
- Honeypot attack patterns (honeypot.json)
"""

import pandas as pd
import numpy as np
import json
import os
from pathlib import Path
from datetime import datetime
import struct
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

class ForensicDataPreparation:
    """Prepare forensic data for ML training - Enhanced for large datasets (35GB+)"""
    
    def __init__(self, data_dir='dataa', use_all_data=True):
        self.data_dir = Path(data_dir)
        self.use_all_data = use_all_data  # If True, process ALL data
        self.malware_data = None
        self.honeypot_data = None
        self.snort_data = None
        self.mdb_data = None
        
    def load_malware_data(self):
        """Load and prepare malware categorization data"""
        print("Loading malware categorization data...")
        csv_path = self.data_dir / 'bodmas_malware_category.csv'
        
        if csv_path.exists():
            self.malware_data = pd.read_csv(csv_path)
            print(f"✓ Loaded {len(self.malware_data)} malware samples")
            print(f"  Categories: {self.malware_data['category'].unique()}")
            print(f"  Distribution:\n{self.malware_data['category'].value_counts()}")
            return self.malware_data
        else:
            print(f"✗ File not found: {csv_path}")
            return None
    
    def load_honeypot_data_streaming(self, sample_size=None):
        """Load honeypot data in streaming mode (file is 426MB)
        
        Args:
            sample_size: Number of records to load (None = load ALL data)
        """
        max_records = sample_size if sample_size else float('inf')
        print(f"Loading honeypot data ({'ALL records' if sample_size is None else f'sampling {sample_size} records'})...")
        json_path = self.data_dir / 'honeypot.json'
        
        if not json_path.exists():
            print(f"✗ File not found: {json_path}")
            return None
        
        records = []
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                # Try to read as JSON array
                content = f.read(100)  # Peek at structure
                f.seek(0)
                
                if content.strip().startswith('['):
                    # JSON array - read in chunks
                    import ijson
                    print("  Using streaming JSON parser...")
                    try:
                        items = ijson.items(f, 'item')
                        for i, item in enumerate(items):
                            if i >= max_records:
                                break
                            records.append(item)
                    except:
                        # Fallback to line-by-line
                        f.seek(0)
                        for i, line in enumerate(f):
                            if i >= max_records:
                                break
                            try:
                                records.append(json.loads(line.strip().rstrip(',')))
                            except:
                                continue
                else:
                    # JSONL format - one JSON object per line
                    for i, line in enumerate(f):
                        if i >= max_records:
                            break
                        try:
                            records.append(json.loads(line.strip()))
                        except json.JSONDecodeError:
                            continue
            
            if records:
                self.honeypot_data = pd.DataFrame(records)
                total_size = len(self.honeypot_data)
                print(f"✓ Loaded {total_size:,} honeypot records")
                if sample_size:
                    print(f"  (Sampled from larger dataset)")
                print(f"  Columns: {list(self.honeypot_data.columns)[:10]}...")
                return self.honeypot_data
            else:
                print("✗ No records could be parsed")
                return None
                
        except Exception as e:
            print(f"✗ Error loading honeypot data: {e}")
            return None
    
    def parse_snort_log_file(self, log_path):
        """Parse a single Snort binary log file"""
        try:
            with open(log_path, 'rb') as f:
                data = f.read()
                
            # Basic Snort/tcpdump binary format parsing
            # This is a simplified parser - real implementation would use scapy
            packets = []
            offset = 24  # Skip pcap global header
            
            while offset < len(data) - 16:
                try:
                    # Parse packet header (16 bytes)
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', data[offset:offset+16])
                    offset += 16
                    
                    if incl_len > 65535 or incl_len == 0:  # Sanity check
                        break
                    
                    # Extract packet data
                    packet_data = data[offset:offset+incl_len]
                    offset += incl_len
                    
                    packets.append({
                        'timestamp': datetime.fromtimestamp(ts_sec + ts_usec/1000000),
                        'packet_size': incl_len,
                        'original_size': orig_len,
                        'data_preview': packet_data[:100].hex() if len(packet_data) > 0 else ''
                    })
                    
                except struct.error:
                    break
                except Exception as e:
                    continue
            
            return packets
            
        except Exception as e:
            print(f"  Error parsing {log_path.name}: {e}")
            return []
    
    def load_snort_logs(self, max_files=None):
        """Load Snort IDS logs from dated directories
        
        Args:
            max_files: Maximum number of files to process (None = process ALL files)
        """
        max_files_limit = max_files if max_files else float('inf')
        print(f"Loading Snort IDS logs ({'ALL files' if max_files is None else f'max {max_files} files'})...")
        
        all_packets = []
        file_count = 0
        
        # Get all date directories
        date_dirs = sorted([d for d in self.data_dir.iterdir() if d.is_dir() and d.name.startswith('2015-')])
        total_dirs = len(date_dirs)
        
        print(f"  Found {total_dirs} date directories with Snort logs")
        
        for dir_idx, date_dir in enumerate(date_dirs, 1):
            if file_count >= max_files_limit:
                break
                
            log_files = sorted(date_dir.glob('snort.log.*'))
            for log_file in log_files:
                if file_count >= max_files_limit:
                    break
                
                print(f"  [{file_count+1}] Parsing {date_dir.name}/{log_file.name}...")
                packets = self.parse_snort_log_file(log_file)
                
                for packet in packets:
                    packet['date'] = date_dir.name
                    packet['log_file'] = log_file.name
                
                all_packets.extend(packets)
                file_count += 1
                
                # Progress indicator
                if file_count % 10 == 0:
                    print(f"  Progress: {file_count} files processed, {len(all_packets):,} packets so far...")
        
        if all_packets:
            self.snort_data = pd.DataFrame(all_packets)
            print(f"✓ Loaded {len(self.snort_data):,} network packets from {file_count} log files")
            print(f"  Date range: {self.snort_data['date'].min()} to {self.snort_data['date'].max()}")
            return self.snort_data
        else:
            print("✗ No Snort data loaded")
            return None
    
    def load_mdb_database(self):
        """Load data from Microsoft Access database (data.mdb)"""
        print("Loading data from MDB database...")
        mdb_path = self.data_dir / 'data.mdb'
        
        if not mdb_path.exists():
            print(f"✗ File not found: {mdb_path}")
            return None
        
        try:
            # Try using pyodbc (for Windows)
            try:
                import pyodbc
                
                # Connection string for Access database
                conn_str = (
                    r'DRIVER={Microsoft Access Driver (*.mdb, *.accdb)};'
                    f'DBQ={mdb_path};'
                )
                conn = pyodbc.connect(conn_str)
                cursor = conn.cursor()
                
                # Get all table names
                tables = [row.table_name for row in cursor.tables(tableType='TABLE')]
                print(f"  Found {len(tables)} tables: {tables}")
                
                # Load all tables
                all_data = {}
                for table in tables:
                    df = pd.read_sql(f"SELECT * FROM [{table}]", conn)
                    all_data[table] = df
                    print(f"  ✓ Loaded table '{table}': {len(df):,} rows")
                
                conn.close()
                self.mdb_data = all_data
                
                print(f"✓ Loaded {len(all_data)} tables from MDB database")
                return all_data
                
            except ImportError:
                print("  ⚠️ pyodbc not available")
                
                # Try mdbtools alternative (cross-platform)
                try:
                    import subprocess
                    # This requires mdbtools to be installed
                    # On Windows: choco install mdbtools
                    print("  Trying mdb-export (requires mdbtools)...")
                    result = subprocess.run(['mdb-tables', str(mdb_path)], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        tables = result.stdout.strip().split()
                        print(f"  Found tables: {tables}")
                    else:
                        print("  ⚠️ mdbtools not available")
                except:
                    pass
                
                print("  To use MDB files, install: pip install pyodbc")
                return None
                
        except Exception as e:
            print(f"✗ Error loading MDB database: {e}")
            print("  Note: Access database support requires pyodbc on Windows")
            return None
    
    def prepare_malware_features(self):
        """Prepare features from malware data"""
        if self.malware_data is None:
            return None
        
        print("\nPreparing malware features...")
        df = self.malware_data.copy()
        
        # Extract features from SHA256 hash
        df['hash_length'] = df['sha256'].str.len()
        df['hash_first_char'] = df['sha256'].str[0]
        df['hash_entropy'] = df['sha256'].apply(self._calculate_string_entropy)
        
        # Encode categories
        category_mapping = {cat: idx for idx, cat in enumerate(df['category'].unique())}
        df['category_encoded'] = df['category'].map(category_mapping)
        
        print(f"✓ Prepared {len(df)} malware samples with features")
        print(f"  Feature columns: {list(df.columns)}")
        
        return df, category_mapping
    
    def prepare_network_features(self):
        """Prepare features from network/Snort data"""
        if self.snort_data is None:
            return None
        
        print("\nPreparing network intrusion features...")
        df = self.snort_data.copy()
        
        # Time-based features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        
        # Packet features
        df['size_category'] = pd.cut(df['packet_size'], bins=[0, 100, 500, 1500, 10000], labels=['tiny', 'small', 'medium', 'large'])
        df['truncated'] = (df['packet_size'] != df['original_size']).astype(int)
        
        # Aggregations by date
        daily_stats = df.groupby('date').agg({
            'packet_size': ['mean', 'std', 'min', 'max', 'count'],
            'truncated': 'sum'
        }).reset_index()
        
        print(f"✓ Prepared {len(df)} network packets with features")
        print(f"  Feature columns: {list(df.columns)}")
        
        return df, daily_stats
    
    def prepare_honeypot_features(self):
        """Prepare features from honeypot data"""
        if self.honeypot_data is None:
            return None
        
        print("\nPreparing honeypot attack features...")
        df = self.honeypot_data.copy()
        
        # Common honeypot fields (adjust based on actual structure)
        feature_df = pd.DataFrame()
        
        # Try to extract common fields
        if 'timestamp' in df.columns:
            feature_df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        if 'src_ip' in df.columns or 'source_ip' in df.columns:
            ip_col = 'src_ip' if 'src_ip' in df.columns else 'source_ip'
            feature_df['src_ip'] = df[ip_col]
            
        if 'dst_port' in df.columns or 'port' in df.columns:
            port_col = 'dst_port' if 'dst_port' in df.columns else 'port'
            feature_df['dst_port'] = df[port_col]
        
        print(f"✓ Prepared {len(feature_df)} honeypot records with features")
        print(f"  Available columns in raw data: {list(df.columns)[:20]}")
        
        return feature_df
    
    def create_training_datasets(self):
        """Create ready-to-use training datasets"""
        print("\n" + "="*60)
        print("CREATING ML TRAINING DATASETS")
        print("="*60)
        
        datasets = {}
        
        # 1. Malware Classification Dataset
        if self.malware_data is not None:
            malware_df, category_map = self.prepare_malware_features()
            
            # Features (X) and Labels (y)
            X_malware = malware_df[['hash_length', 'hash_entropy']].values
            y_malware = malware_df['category_encoded'].values
            
            datasets['malware'] = {
                'X': X_malware,
                'y': y_malware,
                'labels': list(category_map.keys()),
                'label_map': category_map,
                'dataframe': malware_df
            }
            print(f"\n✓ Malware Classification Dataset:")
            print(f"  Shape: X={X_malware.shape}, y={y_malware.shape}")
            print(f"  Classes: {list(category_map.keys())}")
        
        # 2. Network Intrusion Detection Dataset
        if self.snort_data is not None:
            network_df, daily_stats = self.prepare_network_features()
            
            # Create features for anomaly detection
            X_network = network_df[['hour', 'day_of_week', 'packet_size', 'truncated']].values
            
            datasets['network'] = {
                'X': X_network,
                'dataframe': network_df,
                'daily_stats': daily_stats
            }
            print(f"\n✓ Network Intrusion Detection Dataset:")
            print(f"  Shape: X={X_network.shape}")
            print(f"  Use for: Anomaly detection, time-series analysis")
        
        # 3. Honeypot Attack Analysis Dataset
        if self.honeypot_data is not None:
            honeypot_df = self.prepare_honeypot_features()
            
            datasets['honeypot'] = {
                'dataframe': honeypot_df
            }
            print(f"\n✓ Honeypot Attack Dataset:")
            print(f"  Shape: {honeypot_df.shape}")
            print(f"  Use for: Attack pattern analysis")
        
        return datasets
    
    def save_processed_data(self, datasets, output_dir='data/processed'):
        """Save processed datasets for ML training"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        print(f"\nSaving processed datasets to {output_path}...")
        
        for name, data in datasets.items():
            if 'dataframe' in data:
                csv_path = output_path / f'{name}_processed.csv'
                data['dataframe'].to_csv(csv_path, index=False)
                print(f"✓ Saved {csv_path}")
            
            if 'X' in data and 'y' in data:
                npz_path = output_path / f'{name}_features.npz'
                np.savez(npz_path, X=data['X'], y=data['y'])
                print(f"✓ Saved {npz_path}")
        
        print("✓ All datasets saved successfully!")
    
    @staticmethod
    def _calculate_string_entropy(s):
        """Calculate Shannon entropy of a string"""
        if not s:
            return 0
        entropy = 0
        for char in set(s):
            p_x = s.count(char) / len(s)
            entropy += - p_x * np.log2(p_x)
        return entropy


def main(use_all_data=False):
    """Main execution
    
    Args:
        use_all_data: If True, process ALL 35GB+ data instead of samples (default: False for testing)
    """
    print("="*70)
    print("FORENSIC DATA PREPARATION FOR ML TRAINING")
    if use_all_data:
        print("MODE: FULL DATASET (ALL 35GB+ DATA)")
        print("⚠️  This will take significant time and memory")
    else:
        print("MODE: SAMPLE DATA (Quick test mode)")
    print("="*70)
    
    # Initialize
    prep = ForensicDataPreparation(data_dir='dataa', use_all_data=use_all_data)
    
    # Load all data sources
    print("\n📁 Loading data sources...")
    
    if use_all_data:
        # FULL DATA MODE - Process everything
        malware_data = prep.load_malware_data()
        honeypot_data = prep.load_honeypot_data_streaming()  # All data with streaming
        snort_data = prep.load_snort_logs()  # All ~70 files
        mdb_data = prep.load_mdb_database()  # MDB database
    else:
        # SAMPLE MODE - Quick testing
        malware_data = prep.load_malware_data()
        honeypot_data = prep.load_honeypot_data_streaming(sample_size=10000)
        snort_data = prep.load_snort_logs(max_files=20)
        mdb_data = None  # Skip MDB in sample mode
    
    # Print statistics
    print("\n" + "="*70)
    print("DATA LOADING SUMMARY")
    print("="*70)
    
    if malware_data is not None:
        print(f"✓ Malware CSV: {len(malware_data):,} samples")
        print(f"  Categories: {malware_data['category'].nunique()}")
        
    if honeypot_data is not None:
        print(f"✓ Honeypot JSON: {len(honeypot_data):,} events")
        
    if snort_data is not None:
        print(f"✓ Snort Logs: {len(snort_data):,} events from {len(snort_data['date'].unique())} days")
        
    if mdb_data is not None:
        total_rows = sum(len(df) for df in mdb_data.values())
        print(f"✓ MDB Database: {len(mdb_data)} tables, {total_rows:,} total rows")
        for table_name, df in mdb_data.items():
            print(f"  - {table_name}: {len(df):,} rows")
    
    # Calculate total data size
    total_records = 0
    if malware_data is not None:
        total_records += len(malware_data)
    if honeypot_data is not None:
        total_records += len(honeypot_data)
    if snort_data is not None:
        total_records += len(snort_data)
    if mdb_data is not None:
        total_records += sum(len(df) for df in mdb_data.values())
        
    print(f"\n📊 TOTAL RECORDS LOADED: {total_records:,}")
    print("="*70)
    
    # Create training datasets
    datasets = prep.create_training_datasets()
    
    # Save processed data
    prep.save_processed_data(datasets)
    
    print("\n" + "="*70)
    print("DATA PREPARATION COMPLETE!")
    print("="*70)
    print("\nNext steps:")
    print("1. Load datasets: data = np.load('data/processed/malware_features.npz')")
    print("2. Train models: Use scikit-learn, TensorFlow, or PyTorch")
    print("3. Suggested models:")
    print("   - Malware: Random Forest, XGBoost, Neural Networks")
    print("   - Network IDS: Isolation Forest, Autoencoders, LSTM")
    print("   - Honeypot: Clustering (K-Means), Sequential models")
    
    return datasets


if __name__ == '__main__':
    import sys
    
    # Check if user wants to process ALL data
    use_all = '--all' in sys.argv or '--full' in sys.argv
    
    if use_all:
        print("\n⚠️  WARNING: You are about to process ALL 35GB+ data!")
        print("This will:")
        print("  - Process ~57K malware samples")
        print("  - Stream entire 426MB honeypot.json file")
        print("  - Process all ~70 Snort log files")
        print("  - Load data.mdb database")
        print("  - Take significant time and memory (8-16GB RAM recommended)")
        print("\nContinuing in 3 seconds... (Ctrl+C to cancel)")
        import time
        time.sleep(3)
    
    datasets = main(use_all_data=use_all)
