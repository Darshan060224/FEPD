"""
Threat Intelligence Integration Module
=======================================

Enriches forensic artifacts with threat intelligence:
- Malicious hash databases (VirusTotal, MalwareBazaar)
- YARA rule scanning
- Sigma rule detection (SIEM-style)
- Domain reputation checks
- Known IOC matching

References:
- Belkasoft X threat intelligence integration
- MITRE ATT&CK framework
- YARA pattern matching
- Sigma SIEM rules
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime
from collections import Counter
import logging

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logging.warning("YARA not available. Install: pip install yara-python")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class HashDatabase:
    """
    Malicious hash database for quick lookups.
    
    Supports:
    - Local hash blacklists
    - VirusTotal API queries
    - MalwareBazaar lookups
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path("threat_intel/malware_hashes.json")
        self.malicious_hashes: Dict[str, Dict] = {}
        self.logger = logging.getLogger(__name__)
        
        # API keys (set via environment or config)
        self.vt_api_key = None
        self.mb_api_key = None
        
    def load_database(self):
        """Load local hash database."""
        if self.db_path.exists():
            with open(self.db_path, 'r') as f:
                self.malicious_hashes = json.load(f)
            self.logger.info(f"Loaded {len(self.malicious_hashes)} malicious hashes")
        else:
            self.logger.warning(f"Hash database not found: {self.db_path}")
    
    def add_hash(self, hash_value: str, info: Dict):
        """Add a hash to the database."""
        self.malicious_hashes[hash_value.lower()] = info
    
    def check_hash(self, hash_value: str) -> Optional[Dict]:
        """
        Check if hash is known malicious.
        
        Returns:
            Dictionary with threat info if found, None otherwise
        """
        hash_lower = hash_value.lower()
        
        # Check local database
        if hash_lower in self.malicious_hashes:
            return self.malicious_hashes[hash_lower]
        
        return None
    
    def check_hash_virustotal(self, hash_value: str) -> Optional[Dict]:
        """
        Query VirusTotal API for hash.
        
        Requires API key in self.vt_api_key
        """
        if not REQUESTS_AVAILABLE or not self.vt_api_key:
            return None
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            headers = {"x-apikey": self.vt_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                return {
                    'source': 'VirusTotal',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'is_malicious': stats.get('malicious', 0) > 0
                }
            
        except Exception as e:
            self.logger.error(f"VirusTotal API error: {e}")
        
        return None
    
    def save_database(self):
        """Save hash database to disk."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, 'w') as f:
            json.dump(self.malicious_hashes, f, indent=2)
        
        self.logger.info(f"Saved {len(self.malicious_hashes)} hashes")


class YARAScanner:
    """
    YARA rule scanner for file content analysis.
    
    YARA rules detect malware patterns, packers, crypto, etc.
    """
    
    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or Path("threat_intel/yara_rules")
        self.compiled_rules = None
        self.logger = logging.getLogger(__name__)
        
    def load_rules(self):
        """
        Load and compile YARA rules from directory.
        """
        if not YARA_AVAILABLE:
            self.logger.warning("YARA not available")
            return
        
        if not self.rules_dir.exists():
            self.logger.warning(f"YARA rules directory not found: {self.rules_dir}")
            return
        
        # Collect all .yar files
        rule_files = {}
        for yar_file in self.rules_dir.rglob("*.yar"):
            namespace = yar_file.stem
            rule_files[namespace] = str(yar_file)
        
        if not rule_files:
            self.logger.warning("No YARA rules found")
            return
        
        try:
            self.compiled_rules = yara.compile(filepaths=rule_files)
            self.logger.info(f"Loaded {len(rule_files)} YARA rule files")
        except Exception as e:
            self.logger.error(f"Failed to compile YARA rules: {e}")
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Scan a file with YARA rules.
        
        Returns:
            List of matches with rule names and metadata
        """
        if not YARA_AVAILABLE or not self.compiled_rules:
            return []
        
        try:
            matches = self.compiled_rules.match(str(file_path))
            
            results = []
            for match in matches:
                results.append({
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [(s[0], s[1], s[2].decode('utf-8', errors='ignore')) for s in match.strings[:5]]  # First 5 strings
                })
            
            return results
        
        except Exception as e:
            self.logger.error(f"YARA scan failed for {file_path}: {e}")
            return []
    
    def scan_data(self, data: bytes) -> List[Dict]:
        """
        Scan raw bytes with YARA rules.
        """
        if not YARA_AVAILABLE or not self.compiled_rules:
            return []
        
        try:
            matches = self.compiled_rules.match(data=data)
            
            results = []
            for match in matches:
                results.append({
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta
                })
            
            return results
        
        except Exception as e:
            self.logger.error(f"YARA data scan failed: {e}")
            return []


class SigmaRuleEngine:
    """
    Sigma rule engine for SIEM-style detection.
    
    Sigma rules detect suspicious event patterns in logs.
    Reference: https://github.com/SigmaHQ/sigma
    """
    
    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or Path("threat_intel/sigma_rules")
        self.rules: List[Dict] = []
        self.logger = logging.getLogger(__name__)
        
    def load_rules(self):
        """
        Load Sigma rules from YAML files.
        """
        if not self.rules_dir.exists():
            self.logger.warning(f"Sigma rules directory not found: {self.rules_dir}")
            return
        
        # Load YAML rules
        try:
            import yaml
            
            for rule_file in self.rules_dir.rglob("*.yml"):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                    self.rules.append(rule)
            
            self.logger.info(f"Loaded {len(self.rules)} Sigma rules")
        
        except ImportError:
            self.logger.warning("PyYAML not available. Install: pip install pyyaml")
        except Exception as e:
            self.logger.error(f"Failed to load Sigma rules: {e}")
    
    def match_event(self, event: Dict) -> List[Dict]:
        """
        Check if event matches any Sigma rules.
        
        Returns:
            List of matched rules with metadata
        """
        matches = []
        
        for rule in self.rules:
            if self._check_rule(event, rule):
                matches.append({
                    'rule_id': rule.get('id', 'unknown'),
                    'title': rule.get('title', 'Unknown Rule'),
                    'description': rule.get('description', ''),
                    'level': rule.get('level', 'medium'),
                    'tags': rule.get('tags', []),
                    'references': rule.get('references', []),
                    'author': rule.get('author', ''),
                    'date': rule.get('date', '')
                })
        
        return matches
    
    def _check_rule(self, event: Dict, rule: Dict) -> bool:
        """
        Check if event matches a Sigma rule's detection logic.
        
        Simplified implementation - real Sigma has complex query logic.
        """
        detection = rule.get('detection', {})
        
        if not detection:
            return False
        
        # Extract selection criteria
        selection = detection.get('selection', {})
        
        # Simple field matching
        for field, value in selection.items():
            event_value = event.get(field, '')
            
            if isinstance(value, list):
                # OR logic
                if not any(self._match_value(event_value, v) for v in value):
                    return False
            else:
                if not self._match_value(event_value, value):
                    return False
        
        # Check condition (simplified)
        condition = detection.get('condition', 'selection')
        if condition == 'selection':
            return True
        
        return False
    
    def _match_value(self, event_value: Any, pattern: Any) -> bool:
        """
        Match event value against pattern.
        
        Supports wildcards and regex.
        """
        if pattern is None:
            return event_value is None
        
        event_str = str(event_value).lower()
        pattern_str = str(pattern).lower()
        
        # Wildcard matching
        if '*' in pattern_str:
            regex = pattern_str.replace('*', '.*')
            return re.search(regex, event_str) is not None
        
        # Exact match
        return event_str == pattern_str


class DomainReputationChecker:
    """
    Check domain/IP reputation against threat feeds.
    """
    
    def __init__(self, blacklist_path: Optional[Path] = None):
        self.blacklist_path = blacklist_path or Path("threat_intel/domain_blacklist.txt")
        self.blacklisted_domains: Set[str] = set()
        self.blacklisted_ips: Set[str] = set()
        self.logger = logging.getLogger(__name__)
        
    def load_blacklist(self):
        """Load domain/IP blacklist."""
        if self.blacklist_path.exists():
            with open(self.blacklist_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Determine if IP or domain
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                        self.blacklisted_ips.add(line)
                    else:
                        self.blacklisted_domains.add(line.lower())
            
            self.logger.info(f"Loaded {len(self.blacklisted_domains)} domains, "
                           f"{len(self.blacklisted_ips)} IPs")
    
    def check_domain(self, domain: str) -> Optional[Dict]:
        """
        Check if domain is blacklisted.
        """
        domain_lower = domain.lower()
        
        if domain_lower in self.blacklisted_domains:
            return {
                'is_malicious': True,
                'source': 'Local blacklist',
                'domain': domain
            }
        
        # Check subdomains
        parts = domain_lower.split('.')
        for i in range(len(parts)):
            subdomain = '.'.join(parts[i:])
            if subdomain in self.blacklisted_domains:
                return {
                    'is_malicious': True,
                    'source': 'Local blacklist (parent domain)',
                    'domain': domain,
                    'matched': subdomain
                }
        
        return None
    
    def check_ip(self, ip: str) -> Optional[Dict]:
        """
        Check if IP is blacklisted.
        """
        if ip in self.blacklisted_ips:
            return {
                'is_malicious': True,
                'source': 'Local blacklist',
                'ip': ip
            }
        
        return None


class ThreatIntelligenceEngine:
    """
    Main threat intelligence integration engine.
    
    Enriches forensic artifacts with:
    - Malicious hash lookups
    - YARA pattern matching
    - Sigma rule detection
    - Domain/IP reputation
    """
    
    def __init__(self, intel_dir: Optional[Path] = None):
        self.intel_dir = intel_dir or Path("threat_intel")
        self.intel_dir.mkdir(parents=True, exist_ok=True)
        
        self.hash_db = HashDatabase(self.intel_dir / "malware_hashes.json")
        self.yara_scanner = YARAScanner(self.intel_dir / "yara_rules")
        self.sigma_engine = SigmaRuleEngine(self.intel_dir / "sigma_rules")
        self.domain_checker = DomainReputationChecker(self.intel_dir / "domain_blacklist.txt")
        
        self.logger = logging.getLogger(__name__)
        
    def initialize(self):
        """Load all threat intelligence sources."""
        self.logger.info("Initializing threat intelligence engine")
        
        self.hash_db.load_database()
        self.yara_scanner.load_rules()
        self.sigma_engine.load_rules()
        self.domain_checker.load_blacklist()
        
        self.logger.info("Threat intelligence ready")
    
    def enrich_file(self, file_path: Path, file_hash: Optional[str] = None) -> Dict:
        """
        Enrich file with threat intelligence.
        
        Returns:
            Dictionary with TI findings
        """
        results = {
            'file_path': str(file_path),
            'is_malicious': False,
            'threat_score': 0.0,
            'hash_match': None,
            'yara_matches': [],
            'findings': []
        }
        
        # Compute hash if not provided
        if not file_hash and file_path.exists():
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
        
        if file_hash:
            results['sha256'] = file_hash
            
            # Check hash database
            hash_info = self.hash_db.check_hash(file_hash)
            if hash_info:
                results['is_malicious'] = True
                results['hash_match'] = hash_info
                results['threat_score'] += 0.8
                results['findings'].append(f"Known malicious hash: {hash_info.get('family', 'Unknown')}")
        
        # YARA scan
        if file_path.exists():
            yara_matches = self.yara_scanner.scan_file(file_path)
            if yara_matches:
                results['yara_matches'] = yara_matches
                results['is_malicious'] = True
                results['threat_score'] += 0.6
                
                for match in yara_matches:
                    results['findings'].append(f"YARA: {match['rule']}")
        
        # Cap threat score at 1.0
        results['threat_score'] = min(results['threat_score'], 1.0)
        
        return results
    
    def enrich_event(self, event: Dict) -> Dict:
        """
        Enrich event with threat intelligence.
        
        Returns:
            Dictionary with TI findings
        """
        results = {
            'event': event,
            'is_suspicious': False,
            'threat_score': 0.0,
            'sigma_matches': [],
            'domain_checks': [],
            'ip_checks': [],
            'findings': []
        }
        
        # Sigma rule matching
        sigma_matches = self.sigma_engine.match_event(event)
        if sigma_matches:
            results['sigma_matches'] = sigma_matches
            results['is_suspicious'] = True
            
            # Adjust score based on rule level
            for match in sigma_matches:
                level = match.get('level', 'medium')
                if level == 'critical':
                    results['threat_score'] += 0.8
                elif level == 'high':
                    results['threat_score'] += 0.6
                elif level == 'medium':
                    results['threat_score'] += 0.4
                else:
                    results['threat_score'] += 0.2
                
                results['findings'].append(f"Sigma: {match['title']}")
        
        # Domain reputation checks
        if 'domain' in event:
            domain_check = self.domain_checker.check_domain(event['domain'])
            if domain_check:
                results['domain_checks'].append(domain_check)
                results['is_suspicious'] = True
                results['threat_score'] += 0.7
                results['findings'].append(f"Malicious domain: {event['domain']}")
        
        # IP reputation checks
        if 'destination_ip' in event:
            ip_check = self.domain_checker.check_ip(event['destination_ip'])
            if ip_check:
                results['ip_checks'].append(ip_check)
                results['is_suspicious'] = True
                results['threat_score'] += 0.7
                results['findings'].append(f"Malicious IP: {event['destination_ip']}")
        
        # Cap threat score
        results['threat_score'] = min(results['threat_score'], 1.0)
        
        return results
    
    def scan_artifacts(self, artifacts: List[Dict]) -> List[Dict]:
        """
        Batch scan artifacts with threat intelligence.
        
        Args:
            artifacts: List of artifact dictionaries with 'path' and optional 'hash'
            
        Returns:
            List of enriched artifacts with TI data
        """
        enriched = []
        
        self.logger.info(f"Scanning {len(artifacts)} artifacts with threat intelligence")
        
        for artifact in artifacts:
            file_path = Path(artifact.get('path', ''))
            file_hash = artifact.get('sha256') or artifact.get('md5')
            
            ti_results = self.enrich_file(file_path, file_hash)
            
            # Merge with original artifact
            enriched_artifact = {**artifact, **ti_results}
            enriched.append(enriched_artifact)
        
        malicious_count = sum(1 for a in enriched if a.get('is_malicious'))
        self.logger.info(f"Found {malicious_count} malicious artifacts")
        
        return enriched
    
    def get_summary_report(self, enriched_artifacts: List[Dict]) -> Dict:
        """
        Generate summary report of threat intelligence findings.
        """
        report = {
            'total_artifacts': len(enriched_artifacts),
            'malicious_count': 0,
            'suspicious_count': 0,
            'hash_matches': [],
            'yara_detections': Counter(),
            'sigma_detections': Counter(),
            'malicious_domains': set(),
            'malicious_ips': set()
        }
        
        for artifact in enriched_artifacts:
            if artifact.get('is_malicious'):
                report['malicious_count'] += 1
                
                if artifact.get('hash_match'):
                    report['hash_matches'].append(artifact['file_path'])
                
                for yara_match in artifact.get('yara_matches', []):
                    report['yara_detections'][yara_match['rule']] += 1
            
            if artifact.get('is_suspicious'):
                report['suspicious_count'] += 1
                
                for sigma_match in artifact.get('sigma_matches', []):
                    report['sigma_detections'][sigma_match['title']] += 1
                
                for domain_check in artifact.get('domain_checks', []):
                    report['malicious_domains'].add(domain_check.get('domain'))
                
                for ip_check in artifact.get('ip_checks', []):
                    report['malicious_ips'].add(ip_check.get('ip'))
        
        # Convert sets to lists for JSON serialization
        report['malicious_domains'] = list(report['malicious_domains'])
        report['malicious_ips'] = list(report['malicious_ips'])
        report['yara_detections'] = dict(report['yara_detections'])
        report['sigma_detections'] = dict(report['sigma_detections'])
        
        return report


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("Threat Intelligence Integration Module")
    print("=" * 50)
    
    # Initialize engine
    engine = ThreatIntelligenceEngine()
    
    # Add sample malicious hash
    engine.hash_db.add_hash(
        "44d88612fea8a8f36de82e1278abb02f",
        {'family': 'EICAR Test File', 'severity': 'test'}
    )
    
    # Test file enrichment
    print("\nTesting file enrichment...")
    test_artifact = {
        'path': '/tmp/suspicious.exe',
        'sha256': '44d88612fea8a8f36de82e1278abb02f'
    }
    
    result = engine.enrich_file(Path(test_artifact['path']), test_artifact['sha256'])
    print(f"Malicious: {result['is_malicious']}")
    print(f"Threat Score: {result['threat_score']:.2f}")
    print(f"Findings: {result['findings']}")
    
    print("\n" + "=" * 50)
    print("Setup Instructions:")
    print("1. Create threat_intel/ directory")
    print("2. Add malware_hashes.json with known-bad hashes")
    print("3. Add YARA rules to yara_rules/")
    print("4. Add Sigma rules to sigma_rules/")
    print("5. Create domain_blacklist.txt with malicious domains")
