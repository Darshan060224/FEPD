"""
Forensic Data Parser Utilities
Handles parsing of various forensic data formats including line-delimited JSON
"""

import json
import csv
import logging
from pathlib import Path
from typing import List, Dict, Any, Generator
from datetime import datetime

logger = logging.getLogger(__name__)


class ForensicDataParser:
    """Parser for forensic data files (honeypot, malware, network logs)."""
    
    @staticmethod
    def parse_line_delimited_json(file_path: Path, max_records: int = None) -> List[Dict[str, Any]]:
        """
        Parse line-delimited JSON file (NDJSON format).
        Each line is a separate JSON object.
        
        Args:
            file_path: Path to the JSON file
            max_records: Maximum number of records to parse (None for all)
            
        Returns:
            List of parsed JSON objects
        """
        records = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f):
                    if max_records and i >= max_records:
                        break
                    
                    line = line.strip()
                    if line:
                        try:
                            record = json.loads(line)
                            records.append(record)
                        except json.JSONDecodeError as e:
                            logger.warning(f"Skipping invalid JSON at line {i+1}: {e}")
                            continue
            
            logger.info(f"Parsed {len(records)} records from {file_path.name}")
            return records
            
        except Exception as e:
            logger.error(f"Error parsing line-delimited JSON: {e}")
            return []
    
    @staticmethod
    def parse_honeypot_data(file_path: Path, max_records: int = 10000) -> Dict[str, Any]:
        """
        Parse honeypot attack data.
        
        Args:
            file_path: Path to honeypot.json
            max_records: Maximum records to parse (default 10000 for performance)
            
        Returns:
            Dictionary with parsed honeypot data and statistics
        """
        logger.info(f"Parsing honeypot data from {file_path}")
        
        records = ForensicDataParser.parse_line_delimited_json(file_path, max_records)
        
        if not records:
            return {
                'total_records': 0,
                'attacks': [],
                'statistics': {}
            }
        
        # Analyze attack patterns
        attack_types = {}
        source_ips = set()
        target_ports = {}
        
        for record in records:
            # Extract attack type
            attack_type = record.get('type', 'unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            # Extract source IP
            src_ip = record.get('src_ip') or record.get('source_ip')
            if src_ip:
                source_ips.add(src_ip)
            
            # Extract target port
            port = record.get('dst_port') or record.get('destination_port')
            if port:
                target_ports[port] = target_ports.get(port, 0) + 1
        
        return {
            'total_records': len(records),
            'attacks': records[:1000],  # Keep first 1000 for analysis
            'statistics': {
                'attack_types': attack_types,
                'unique_source_ips': len(source_ips),
                'target_ports': dict(sorted(target_ports.items(), key=lambda x: x[1], reverse=True)[:10]),
                'parsed_records': len(records),
                'file_size_mb': file_path.stat().st_size / (1024 * 1024)
            }
        }
    
    @staticmethod
    def parse_malware_csv(file_path: Path) -> Dict[str, Any]:
        """
        Parse malware categorization CSV.
        
        Args:
            file_path: Path to bodmas_malware_category.csv
            
        Returns:
            Dictionary with malware data and statistics
        """
        logger.info(f"Parsing malware data from {file_path}")
        
        malware_samples = []
        category_counts = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    malware_samples.append(row)
                    category = row.get('category', 'unknown')
                    category_counts[category] = category_counts.get(category, 0) + 1
            
            logger.info(f"Parsed {len(malware_samples)} malware samples")
            
            return {
                'total_samples': len(malware_samples),
                'samples': malware_samples,
                'statistics': {
                    'category_distribution': dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True)),
                    'unique_categories': len(category_counts),
                    'top_category': max(category_counts.items(), key=lambda x: x[1]) if category_counts else ('unknown', 0)
                }
            }
            
        except Exception as e:
            logger.error(f"Error parsing malware CSV: {e}")
            return {
                'total_samples': 0,
                'samples': [],
                'statistics': {}
            }
    
    @staticmethod
    def parse_snort_logs(data_dir: Path) -> Dict[str, Any]:
        """
        Parse Snort IDS log files organized by date.
        
        Args:
            data_dir: Directory containing dated folders with snort logs
            
        Returns:
            Dictionary with snort log metadata and statistics
        """
        logger.info(f"Analyzing Snort logs in {data_dir}")
        
        dated_dirs = sorted([d for d in data_dir.iterdir() if d.is_dir() and d.name.startswith('2015-')])
        
        daily_logs = []
        total_files = 0
        total_size = 0
        
        for date_dir in dated_dirs:
            snort_files = list(date_dir.glob('snort.log.*'))
            if snort_files:
                day_size = sum(f.stat().st_size for f in snort_files)
                daily_logs.append({
                    'date': date_dir.name,
                    'file_count': len(snort_files),
                    'size_bytes': day_size,
                    'files': [f.name for f in snort_files]
                })
                total_files += len(snort_files)
                total_size += day_size
        
        return {
            'total_days': len(daily_logs),
            'total_files': total_files,
            'total_size_mb': total_size / (1024 * 1024),
            'date_range': {
                'start': dated_dirs[0].name if dated_dirs else None,
                'end': dated_dirs[-1].name if dated_dirs else None
            },
            'daily_logs': daily_logs
        }
    
    @staticmethod
    def get_comprehensive_data_summary(data_dir: Path) -> Dict[str, Any]:
        """
        Get comprehensive summary of all forensic data.
        
        Args:
            data_dir: Path to dataa directory
            
        Returns:
            Complete forensic data summary
        """
        logger.info("Generating comprehensive forensic data summary")
        
        summary = {
            'honeypot': {},
            'malware': {},
            'snort_logs': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Parse honeypot data
        honeypot_file = data_dir / "honeypot.json"
        if honeypot_file.exists():
            summary['honeypot'] = ForensicDataParser.parse_honeypot_data(honeypot_file)
        
        # Parse malware data
        malware_file = data_dir / "bodmas_malware_category.csv"
        if malware_file.exists():
            summary['malware'] = ForensicDataParser.parse_malware_csv(malware_file)
        
        # Parse Snort logs
        summary['snort_logs'] = ForensicDataParser.parse_snort_logs(data_dir)
        
        # Overall statistics
        summary['overall'] = {
            'total_data_sources': sum([
                1 if summary['honeypot'] else 0,
                1 if summary['malware'] else 0,
                1 if summary['snort_logs']['total_files'] > 0 else 0
            ]),
            'total_records': sum([
                summary['honeypot'].get('total_records', 0),
                summary['malware'].get('total_samples', 0),
                summary['snort_logs'].get('total_files', 0)
            ])
        }
        
        logger.info(f"Summary complete: {summary['overall']['total_records']} total records")
        
        return summary
