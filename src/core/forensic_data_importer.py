"""
Forensic Data Import Workflow
Imports and integrates forensic data (malware, honeypot, snort logs) into cases
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from src.utils.forensic_data_parser import ForensicDataParser

logger = logging.getLogger(__name__)


class ForensicDataImporter:
    """Handles importing forensic data into case directories."""
    
    def __init__(self, case_path: Path, data_source_path: Path):
        """
        Initialize the data importer.
        
        Args:
            case_path: Path to the case directory
            data_source_path: Path to the dataa directory
        """
        self.case_path = Path(case_path)
        self.data_source_path = Path(data_source_path)
        self.parser = ForensicDataParser()
        
        # Create forensic data subdirectories in case
        self.forensic_data_dir = self.case_path / "forensic_data"
        self.forensic_data_dir.mkdir(exist_ok=True)
        
        self.malware_dir = self.forensic_data_dir / "malware"
        self.network_dir = self.forensic_data_dir / "network"
        self.honeypot_dir = self.forensic_data_dir / "honeypot"
        
        for d in [self.malware_dir, self.network_dir, self.honeypot_dir]:
            d.mkdir(exist_ok=True)
    
    def import_all_data(self) -> Dict[str, Any]:
        """
        Import all forensic data into the case.
        
        Returns:
            Dictionary with import results and statistics
        """
        logger.info(f"Starting comprehensive data import for case: {self.case_path.name}")
        
        results = {
            'case_id': self.case_path.name,
            'import_timestamp': datetime.now().isoformat(),
            'imports': {},
            'errors': []
        }
        
        try:
            # Import malware data
            logger.info("Importing malware data...")
            results['imports']['malware'] = self.import_malware_data()
            
            # Import honeypot data
            logger.info("Importing honeypot data...")
            results['imports']['honeypot'] = self.import_honeypot_data()
            
            # Import network logs
            logger.info("Importing network traffic logs...")
            results['imports']['network'] = self.import_network_logs()
            
            # Generate summary report
            results['summary'] = self._generate_import_summary(results['imports'])
            
            # Save import manifest
            self._save_import_manifest(results)
            
            logger.info("Data import completed successfully")
            
        except Exception as e:
            logger.error(f"Error during data import: {e}", exc_info=True)
            results['errors'].append(str(e))
        
        return results
    
    def import_malware_data(self) -> Dict[str, Any]:
        """Import malware categorization data."""
        malware_file = self.data_source_path / "bodmas_malware_category.csv"
        
        if not malware_file.exists():
            logger.warning("Malware CSV file not found")
            return {'status': 'skipped', 'reason': 'file_not_found'}
        
        # Parse malware data
        malware_data = self.parser.parse_malware_csv(malware_file)
        
        # Save parsed data to case
        output_file = self.malware_dir / "malware_samples.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(malware_data, f, indent=2)
        
        # Save statistics separately
        stats_file = self.malware_dir / "malware_statistics.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(malware_data['statistics'], f, indent=2)
        
        logger.info(f"Imported {malware_data['total_samples']} malware samples")
        
        return {
            'status': 'success',
            'total_samples': malware_data['total_samples'],
            'output_files': [str(output_file), str(stats_file)],
            'statistics': malware_data['statistics']
        }
    
    def import_honeypot_data(self, max_records: int = 10000) -> Dict[str, Any]:
        """
        Import honeypot attack data.
        
        Args:
            max_records: Maximum records to import (for performance)
        """
        honeypot_file = self.data_source_path / "honeypot.json"
        
        if not honeypot_file.exists():
            logger.warning("Honeypot JSON file not found")
            return {'status': 'skipped', 'reason': 'file_not_found'}
        
        # Parse honeypot data
        honeypot_data = self.parser.parse_honeypot_data(honeypot_file, max_records)
        
        # Save parsed data to case
        output_file = self.honeypot_dir / "honeypot_attacks.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(honeypot_data, f, indent=2)
        
        # Save statistics separately
        stats_file = self.honeypot_dir / "attack_statistics.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(honeypot_data['statistics'], f, indent=2)
        
        logger.info(f"Imported {honeypot_data['total_records']} honeypot attack records")
        
        return {
            'status': 'success',
            'total_records': honeypot_data['total_records'],
            'output_files': [str(output_file), str(stats_file)],
            'statistics': honeypot_data['statistics']
        }
    
    def import_network_logs(self) -> Dict[str, Any]:
        """Import Snort network intrusion detection logs."""
        # Parse Snort logs metadata
        snort_data = self.parser.parse_snort_logs(self.data_source_path)
        
        # Save metadata to case
        output_file = self.network_dir / "snort_logs_metadata.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(snort_data, f, indent=2)
        
        logger.info(f"Imported metadata for {snort_data['total_files']} Snort log files")
        
        return {
            'status': 'success',
            'total_days': snort_data['total_days'],
            'total_files': snort_data['total_files'],
            'total_size_mb': snort_data['total_size_mb'],
            'date_range': snort_data['date_range'],
            'output_files': [str(output_file)]
        }
    
    def _generate_import_summary(self, imports: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of imported data."""
        return {
            'total_malware_samples': imports.get('malware', {}).get('total_samples', 0),
            'total_honeypot_attacks': imports.get('honeypot', {}).get('total_records', 0),
            'total_network_days': imports.get('network', {}).get('total_days', 0),
            'total_network_files': imports.get('network', {}).get('total_files', 0),
            'import_status': {
                'malware': imports.get('malware', {}).get('status', 'unknown'),
                'honeypot': imports.get('honeypot', {}).get('status', 'unknown'),
                'network': imports.get('network', {}).get('status', 'unknown')
            }
        }
    
    def _save_import_manifest(self, results: Dict[str, Any]):
        """Save import manifest to case directory."""
        manifest_file = self.forensic_data_dir / "import_manifest.json"
        with open(manifest_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Import manifest saved to {manifest_file}")
