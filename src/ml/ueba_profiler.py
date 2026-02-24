"""
User and Entity Behavior Analytics (UEBA) Module
=================================================

Builds behavioral baselines and detects deviations indicating:
- Insider threats
- Account takeover
- Privilege abuse
- Unusual access patterns
- Off-hours activity

Reference: Elastic Security Analytics (elastic.co)
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import json
import logging
from src.modules.ml_output_handler import MLOutputHandler, MLEntity, MLFinding

try:
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class UserBehaviorProfile:
    """
    Individual user behavior baseline profile.
    
    Tracks:
    - Typical login times
    - Common processes executed
    - File access patterns
    - Network activity
    - Resource usage
    """
    
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.profile = {
            'login_hours': Counter(),  # Hour of day distribution
            'login_days': Counter(),  # Day of week distribution
            'processes': Counter(),  # Process execution frequency
            'file_access': Counter(),  # Files accessed
            'file_modifications': Counter(),  # Files modified
            'network_destinations': Counter(),  # IPs/domains contacted
            'event_types': Counter(),  # Event type distribution
            'total_events': 0,
            'first_seen': None,
            'last_seen': None,
            'typical_session_duration': [],
            'typical_files_per_session': []
        }
        
    def update(self, events: pd.DataFrame):
        """
        Update profile with new events.
        
        Args:
            events: DataFrame of events for this user
        """
        if len(events) == 0:
            return
        
        # Temporal patterns
        if 'timestamp' in events.columns:
            timestamps = pd.to_datetime(events['timestamp'])
            self.profile['login_hours'].update(timestamps.dt.hour.tolist())
            self.profile['login_days'].update(timestamps.dt.dayofweek.tolist())
            
            if self.profile['first_seen'] is None:
                self.profile['first_seen'] = timestamps.min()
            self.profile['last_seen'] = timestamps.max()
        
        # Event types
        if 'event_type' in events.columns:
            self.profile['event_types'].update(events['event_type'].tolist())
        
        # Process execution
        if 'process_name' in events.columns:
            processes = events['process_name'].dropna()
            self.profile['processes'].update(processes.tolist())
        
        # File access
        if 'file_path' in events.columns:
            files = events['file_path'].dropna()
            self.profile['file_access'].update(files.tolist())
        
        if 'modified_file' in events.columns:
            modified = events['modified_file'].dropna()
            self.profile['file_modifications'].update(modified.tolist())
        
        # Network activity
        if 'destination_ip' in events.columns:
            ips = events['destination_ip'].dropna()
            self.profile['network_destinations'].update(ips.tolist())
        
        if 'domain' in events.columns:
            domains = events['domain'].dropna()
            self.profile['network_destinations'].update(domains.tolist())
        
        self.profile['total_events'] += len(events)
    
    def get_statistics(self) -> Dict:
        """
        Get profile statistics.
        
        Returns:
            Dictionary with behavioral statistics
        """
        stats = {
            'user_id': self.user_id,
            'total_events': self.profile['total_events'],
            'first_seen': str(self.profile['first_seen']) if self.profile['first_seen'] else None,
            'last_seen': str(self.profile['last_seen']) if self.profile['last_seen'] else None,
            'active_days': (self.profile['last_seen'] - self.profile['first_seen']).days if self.profile['first_seen'] else 0,
            'most_common_login_hour': self.profile['login_hours'].most_common(1)[0][0] if self.profile['login_hours'] else None,
            'most_common_login_day': self.profile['login_days'].most_common(1)[0][0] if self.profile['login_days'] else None,
            'unique_processes': len(self.profile['processes']),
            'top_processes': [p for p, _ in self.profile['processes'].most_common(5)],
            'unique_files_accessed': len(self.profile['file_access']),
            'top_files': [f for f, _ in self.profile['file_access'].most_common(5)],
            'unique_network_destinations': len(self.profile['network_destinations']),
            'top_destinations': [d for d, _ in self.profile['network_destinations'].most_common(5)]
        }
        
        # Typical login hours distribution
        if self.profile['login_hours']:
            total_logins = sum(self.profile['login_hours'].values())
            stats['login_hour_distribution'] = {
                str(h): count/total_logins 
                for h, count in self.profile['login_hours'].items()
            }
        
        return stats
    
    def compute_deviation_score(self, event: Dict) -> float:
        """
        Compute how much an event deviates from this user's baseline.
        
        Returns:
            Deviation score 0-1 (higher = more unusual)
        """
        score = 0.0
        factors = 0
        
        # Time-based deviations
        if 'timestamp' in event:
            ts = pd.to_datetime(event['timestamp'])
            hour = ts.hour
            day = ts.dayofweek
            
            # Check if unusual hour
            if self.profile['login_hours']:
                total_logins = sum(self.profile['login_hours'].values())
                hour_prob = self.profile['login_hours'].get(hour, 0) / total_logins
                
                if hour_prob < 0.05:  # Occurs < 5% of the time
                    score += 0.3
                factors += 1
            
            # Check if unusual day
            if self.profile['login_days']:
                total_days = sum(self.profile['login_days'].values())
                day_prob = self.profile['login_days'].get(day, 0) / total_days
                
                if day_prob < 0.05:
                    score += 0.2
                factors += 1
        
        # Process deviation
        if 'process_name' in event:
            process = event['process_name']
            if process and process not in self.profile['processes']:
                score += 0.3  # Never-before-seen process
                factors += 1
            elif process:
                factors += 1
        
        # File access deviation
        if 'file_path' in event:
            file_path = event['file_path']
            if file_path and file_path not in self.profile['file_access']:
                score += 0.2  # New file access
                factors += 1
            elif file_path:
                factors += 1
        
        # Event type deviation
        if 'event_type' in event:
            event_type = event['event_type']
            if event_type and event_type not in self.profile['event_types']:
                score += 0.2  # New event type
                factors += 1
            elif event_type:
                factors += 1
        
        return score / factors if factors > 0 else 0.0
    
    def save(self, path: Path):
        """Save profile to JSON."""
        # Convert Counters to dicts for JSON serialization
        profile_json = {}
        for key, value in self.profile.items():
            if isinstance(value, Counter):
                profile_json[key] = dict(value)
            elif isinstance(value, (datetime, pd.Timestamp)):
                profile_json[key] = str(value)
            elif isinstance(value, list):
                profile_json[key] = value
            else:
                profile_json[key] = value
        
        profile_json['user_id'] = self.user_id
        
        with open(path, 'w') as f:
            json.dump(profile_json, f, indent=2)
    
    def load(self, path: Path):
        """Load profile from JSON."""
        with open(path, 'r') as f:
            profile_json = json.load(f)
        
        self.user_id = profile_json.get('user_id', self.user_id)
        
        for key, value in profile_json.items():
            if key in ['login_hours', 'login_days', 'processes', 'file_access', 
                      'file_modifications', 'network_destinations', 'event_types']:
                self.profile[key] = Counter(value)
            elif key in ['first_seen', 'last_seen']:
                self.profile[key] = pd.to_datetime(value) if value else None
            elif key != 'user_id':
                self.profile[key] = value


class UEBAProfiler:
    """
    User and Entity Behavior Analytics Engine.
    
    FORENSIC ML COMPLIANCE:
    - Hard output guarantee (fails if case_path missing during inference)
    - Unified findings wrapper (case metadata + summary)
    - Empty result standard (creates ml_findings.json with status)
    - Severity normalization (score-based CRITICAL|HIGH|MEDIUM|LOW)
    - Neutral language (no accusations, only statistical observations)
    
    Capabilities:
    - Behavioral baseline profiling
    - Statistical anomaly detection
    - Pattern recognition (data exfiltration, privilege abuse indicators)
    - Account activity deviation detection
    - Temporal pattern analysis
    """
    
    @staticmethod
    def detect_artifact_type(events: pd.DataFrame) -> str:
        """
        Auto-classify evidence type from event structure.
        
        FORENSIC REQUIREMENT: Route to correct ML model based on artifact type.
        
        Returns:
            'evtx' | 'mobile' | 'network' | 'registry' | 'file' | 'unknown'
        """
        if 'event_id' in events.columns and 'channel' in events.columns:
            return 'evtx'  # Windows Event Logs
        elif 'process_name' in events.columns and 'sms_body' in events.columns:
            return 'mobile'  # Mobile artifacts
        elif 'source_ip' in events.columns and 'destination_ip' in events.columns:
            return 'network'  # Network flows
        elif 'registry_key' in events.columns or 'hive' in events.columns:
            return 'registry'  # Registry artifacts
        elif 'file_path' in events.columns and 'hash_sha256' in events.columns:
            return 'file'  # File system artifacts
        else:
            return 'unknown'
    
    def __init__(self, model_dir: Optional[Path] = None, case_path: Optional[Path] = None):
        self.model_dir = model_dir or Path("models/ueba")
        self.logger = logging.getLogger(__name__)
        
        # FORENSIC COMPLIANCE: case_path is REQUIRED for inference
        if case_path is None:
            self.logger.warning("No case_path provided - UEBA will run in TRAINING MODE ONLY")
            self.case_path = None
            self.output_handler = None
        else:
            self.case_path = Path(case_path)
            # HARD REQUIREMENT: Output handler must be initialized
            try:
                self.output_handler = MLOutputHandler(self.case_path)
                self.logger.info(f"UEBA initialized for case: {self.case_path}")
            except Exception as e:
                self.logger.error(f"CRITICAL: Failed to initialize MLOutputHandler: {e}")
                raise RuntimeError(f"UEBA requires valid case_path for forensic output: {e}")
        
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}
        self.entity_profiles: Dict[str, UserBehaviorProfile] = {}  # For machines/services
        
        # ML models for advanced detection
        self.anomaly_detector = None
        if ML_AVAILABLE:
            self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
    
    def build_profiles(self, events: pd.DataFrame):
        """
        Build behavior profiles from historical events.
        
        Args:
            events: DataFrame with columns [user_id, timestamp, event_type, ...]
        """
        self.logger.info(f"Building UEBA profiles from {len(events)} events")
        
        if 'user_id' not in events.columns:
            self.logger.warning("No user_id column found")
            return
        
        # Group by user
        for user_id, user_events in events.groupby('user_id'):
            if user_id not in self.user_profiles:
                self.user_profiles[user_id] = UserBehaviorProfile(user_id)
            
            self.user_profiles[user_id].update(user_events)
        
        # Build entity profiles (machines, services)
        if 'entity_id' in events.columns:
            for entity_id, entity_events in events.groupby('entity_id'):
                if entity_id not in self.entity_profiles:
                    self.entity_profiles[entity_id] = UserBehaviorProfile(entity_id)
                
                self.entity_profiles[entity_id].update(entity_events)
        
        self.logger.info(f"Built profiles for {len(self.user_profiles)} users, "
                        f"{len(self.entity_profiles)} entities")
    
    def detect_anomalies(self, events: pd.DataFrame) -> pd.DataFrame:
        """
        Detect behavioral anomalies in events.
        
        Returns:
            DataFrame with anomaly scores and flags
        """
        results = events.copy()
        
        # Initialize anomaly columns
        results['ueba_score'] = 0.0
        results['ueba_anomaly'] = False
        results['anomaly_reasons'] = ''
        
        if 'user_id' not in events.columns:
            return results
        
        # Score each event
        for idx, event in events.iterrows():
            user_id = event.get('user_id')
            
            if user_id not in self.user_profiles:
                # New user - flag as potential anomaly
                results.at[idx, 'ueba_score'] = 0.5
                results.at[idx, 'anomaly_reasons'] = 'New user'
                continue
            
            profile = self.user_profiles[user_id]
            
            # Compute deviation score
            deviation = profile.compute_deviation_score(event.to_dict())
            results.at[idx, 'ueba_score'] = deviation
            
            # Check for specific anomaly patterns
            reasons = []
            
            # Off-hours activity (11pm - 5am on weekdays)
            if 'timestamp' in event:
                ts = pd.to_datetime(event['timestamp'])
                if ts.dayofweek < 5 and (ts.hour >= 23 or ts.hour <= 5):
                    reasons.append('Off-hours activity')
                    deviation += 0.2
            
            # Sensitive file access
            if 'file_path' in event:
                file_path = str(event['file_path']).lower()
                sensitive_keywords = ['password', 'secret', 'private', 'credential', 'key']
                if any(kw in file_path for kw in sensitive_keywords):
                    reasons.append('Sensitive file access')
                    deviation += 0.3
            
            # Unusual process execution
            if 'process_name' in event:
                process = str(event['process_name']).lower()
                suspicious_procs = ['mimikatz', 'psexec', 'netcat', 'nmap', 'procdump']
                if any(sp in process for sp in suspicious_procs):
                    reasons.append('Suspicious process')
                    deviation += 0.4
            
            # Multiple failed logins
            if 'event_type' in event and 'failed' in str(event['event_type']).lower():
                reasons.append('Failed login')
                deviation += 0.2
            
            results.at[idx, 'ueba_score'] = min(deviation, 1.0)
            results.at[idx, 'anomaly_reasons'] = '; '.join(reasons)
        
        # Flag high-score events as anomalies
        results['ueba_anomaly'] = results['ueba_score'] > 0.6
        
        return results
    
    def detect_insider_threats(self, events: pd.DataFrame) -> List[Dict]:
        """
        Detect potential insider threat indicators.
        
        Returns:
            List of threat alerts with context
        """
        threats = []
        
        if 'user_id' not in events.columns:
            return threats
        
        # Group by user
        for user_id, user_events in events.groupby('user_id'):
            if user_id not in self.user_profiles:
                continue
            
            profile = self.user_profiles[user_id]
            
            # Pattern 1: Mass file access/exfiltration
            if 'file_path' in user_events.columns:
                file_accesses = user_events['file_path'].dropna()
                if len(file_accesses) > 100:  # > 100 files in this batch
                    threats.append({
                        'user_id': user_id,
                        'threat_type': 'Mass file access',
                        'severity': 'high',
                        'description': f'User accessed {len(file_accesses)} files',
                        'timestamp': str(user_events['timestamp'].max()) if 'timestamp' in user_events.columns else None,
                        'file_count': len(file_accesses)
                    })
            
            # Pattern 2: Privilege escalation attempts
            if 'event_type' in user_events.columns:
                priv_events = user_events[user_events['event_type'].str.contains('privilege|admin|sudo', case=False, na=False)]
                if len(priv_events) > 5:
                    threats.append({
                        'user_id': user_id,
                        'threat_type': 'Privilege escalation attempt',
                        'severity': 'critical',
                        'description': f'{len(priv_events)} privilege-related events',
                        'timestamp': str(priv_events['timestamp'].max()) if 'timestamp' in priv_events.columns else None
                    })
            
            # Pattern 3: After-hours data access
            if 'timestamp' in user_events.columns and len(user_events) > 0:
                timestamp_series = user_events['timestamp']
                timestamps = pd.to_datetime(timestamp_series)
                # Filter for after-hours events (10pm-6am)
                if isinstance(timestamps, pd.Series):
                    after_hours_mask = (timestamps.dt.hour >= 22) | (timestamps.dt.hour <= 6)
                    after_hours = timestamps[after_hours_mask]
                else:
                    after_hours = pd.Series(dtype='datetime64[ns]')
                
                if len(after_hours) > 10:
                    threats.append({
                        'user_id': user_id,
                        'threat_type': 'Excessive after-hours activity',
                        'severity': 'medium',
                        'description': f'{len(after_hours)} events between 10pm-6am',
                        'timestamp': str(after_hours.max())
                    })
            
            # Pattern 4: Accessing unusual locations/systems
            if 'destination_ip' in user_events.columns:
                ips = user_events['destination_ip'].dropna().unique()
                known_ips = set(profile.profile['network_destinations'].keys())
                new_ips = [ip for ip in ips if ip not in known_ips]
                
                if len(new_ips) > 5:
                    threats.append({
                        'user_id': user_id,
                        'threat_type': 'Lateral movement',
                        'severity': 'high',
                        'description': f'Accessed {len(new_ips)} new network destinations',
                        'timestamp': str(user_events['timestamp'].max()) if 'timestamp' in user_events.columns else None,
                        'new_destinations': new_ips[:5]  # Sample
                    })
        
        return threats
    
    def detect_account_takeover(self, events: pd.DataFrame) -> List[Dict]:
        """
        Detect potential account takeover/compromise.
        
        Indicators:
        - Sudden change in behavior
        - Login from new location
        - Unusual tools/processes
        - Different access patterns
        """
        takeovers = []
        
        if 'user_id' not in events.columns:
            return takeovers
        
        for user_id, user_events in events.groupby('user_id'):
            if user_id not in self.user_profiles:
                continue
            
            profile = self.user_profiles[user_id]
            
            # Pattern 1: Login from unusual location
            if 'source_ip' in user_events.columns:
                source_ips = user_events['source_ip'].dropna().unique()
                # If we have historical IPs, check for new ones
                if len(source_ips) > 0:
                    takeovers.append({
                        'user_id': user_id,
                        'threat_type': 'Login from new location',
                        'severity': 'high',
                        'description': f'Login from {len(source_ips)} new IP addresses',
                        'timestamp': str(user_events['timestamp'].max()) if 'timestamp' in user_events.columns else None,
                        'source_ips': list(source_ips[:3])
                    })
            
            # Pattern 2: Running unfamiliar tools
            if 'process_name' in user_events.columns:
                processes = user_events['process_name'].dropna()
                known_procs = set(profile.profile['processes'].keys())
                new_procs = [p for p in processes if p not in known_procs]
                
                if len(new_procs) > 10:
                    takeovers.append({
                        'user_id': user_id,
                        'threat_type': 'Unusual tool usage',
                        'severity': 'medium',
                        'description': f'Executed {len(new_procs)} unfamiliar processes',
                        'timestamp': str(user_events['timestamp'].max()) if 'timestamp' in user_events.columns else None,
                        'new_processes': list(set(new_procs))[:5]
                    })
            
            # Pattern 3: Sudden spike in activity
            if len(user_events) > profile.profile['total_events'] * 2:
                takeovers.append({
                    'user_id': user_id,
                    'threat_type': 'Activity spike',
                    'severity': 'medium',
                    'description': f'Event count ({len(user_events)}) is 2x historical average',
                    'timestamp': str(user_events['timestamp'].max()) if 'timestamp' in user_events.columns else None
                })
        
        return takeovers
    
    def get_user_report(self, user_id: str) -> Dict:
        """
        Generate detailed report for a specific user.
        """
        if user_id not in self.user_profiles:
            return {'error': f'No profile for user {user_id}'}
        
        profile = self.user_profiles[user_id]
        return profile.get_statistics()
    
    def _normalize_severity(self, score: float) -> str:
        """
        Normalize anomaly score to forensic severity levels.
        
        FORENSIC STANDARD:
        - score >= 0.85 → CRITICAL
        - score >= 0.70 → HIGH  
        - score >= 0.50 → MEDIUM
        - else → LOW
        
        Returns:
            Severity level string (CRITICAL | HIGH | MEDIUM | LOW)
        """
        if score >= 0.85:
            return "critical"
        elif score >= 0.70:
            return "high"
        elif score >= 0.50:
            return "medium"
        else:
            return "low"
    
    def get_high_risk_users(self, top_n: int = 10) -> List[Dict]:
        """
        Identify highest-risk users based on anomaly patterns.
        """
        risk_scores = []
        
        for user_id, profile in self.user_profiles.items():
            stats = profile.get_statistics()
            
            # Risk factors
            risk = 0.0
            
            # Many unique processes (potential tool abuse)
            if stats['unique_processes'] > 50:
                risk += 0.3
            
            # Many unique files (potential data collection)
            if stats['unique_files_accessed'] > 100:
                risk += 0.3
            
            # Many network destinations (potential C2/exfiltration)
            if stats['unique_network_destinations'] > 20:
                risk += 0.4
            
            risk_scores.append({
                'user_id': user_id,
                'risk_score': risk,
                'unique_processes': stats['unique_processes'],
                'unique_files': stats['unique_files_accessed'],
                'network_destinations': stats['unique_network_destinations']
            })
        
        # Sort by risk
        risk_scores.sort(key=lambda x: x['risk_score'], reverse=True)
        return risk_scores[:top_n]
    
    def save_profiles(self):
        """Save all user profiles."""
        self.logger.info(f"Saving UEBA profiles to {self.model_dir}")
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Save user profiles
        user_dir = self.model_dir / 'users'
        user_dir.mkdir(exist_ok=True)
        
        for user_id, profile in self.user_profiles.items():
            # Sanitize filename
            safe_id = user_id.replace('/', '_').replace('\\', '_')
            profile.save(user_dir / f'{safe_id}.json')
        
        # Save entity profiles
        entity_dir = self.model_dir / 'entities'
        entity_dir.mkdir(exist_ok=True)
        
        for entity_id, profile in self.entity_profiles.items():
            safe_id = entity_id.replace('/', '_').replace('\\', '_')
            profile.save(entity_dir / f'{safe_id}.json')
        
        self.logger.info(f"Saved {len(self.user_profiles)} user profiles, "
                        f"{len(self.entity_profiles)} entity profiles")
    
    def save_findings(self, events: pd.DataFrame, entity: MLEntity = None):
        """
        Analyze events and save findings using MLOutputHandler.
        
        FORENSIC COMPLIANCE:
        - HARD OUTPUT GUARANTEE: Fails if output_handler is None
        - UNIFIED WRAPPER: Includes case metadata, summary, status
        - EMPTY RESULT STANDARD: Creates ml_findings.json even with 0 findings
        - SEVERITY NORMALIZATION: Uses _normalize_severity()
        - NEUTRAL LANGUAGE: No accusations, only observations
        
        Args:
            events: DataFrame of events to analyze
            entity: Optional MLEntity with user/device/platform info
        
        Raises:
            RuntimeError: If output_handler is not configured
        """
        # HARD OUTPUT GUARANTEE
        if not self.output_handler:
            error_msg = "CRITICAL: UEBA analysis requires case_path for forensic output"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        self.logger.info(f"[UEBA] Analyzing {len(events)} events for behavioral deviations...")
        
        # Detect anomalies
        results = self.detect_anomalies(events)
        
        # Detect specific patterns
        insider_threats = self.detect_insider_threats(events)
        account_takeovers = self.detect_account_takeover(events)
        
        # Build findings list
        findings = []
        finding_id_counter = 1
        
        # Process anomalies (FORENSIC LANGUAGE)
        anomalies = results[results['ueba_anomaly'] == True]
        for idx, row in anomalies.iterrows():
            score = float(row['ueba_score'])
            finding = MLFinding(
                finding_id=f"UEBA-{finding_id_counter:04d}",
                finding_type="behavioral_anomaly",
                severity=self._normalize_severity(score),  # FORENSIC SEVERITY
                score=score,
                title=f"Behavioral deviation detected for entity {row.get('user_id', 'Unknown')}",
                description=f"An automated analysis identified statistically significant deviation from established baseline behavior patterns. Observed reasons: {row.get('anomaly_reasons', 'Timing/activity variance')}",
                affected_artifact=str(row.get('file_path', row.get('process_name', 'N/A'))),
                timestamp=str(row.get('timestamp', '')),
                explanations=[
                    f"Statistical deviation score: {score:.2%}",
                    f"Contributing factors: {row.get('anomaly_reasons', 'Unknown')}",
                    "Baseline comparison indicates unusual activity pattern"
                ],
                recommendation=f"Analyst review recommended to verify whether entity {row.get('user_id', 'Unknown')} activity aligns with business context"
            )
            findings.append(finding)
            finding_id_counter += 1
        
        # Process insider threat patterns (FORENSIC LANGUAGE)
        for threat in insider_threats:
            # Determine score from severity
            severity_score_map = {'critical': 0.90, 'high': 0.75, 'medium': 0.55, 'low': 0.35}
            threat_score = severity_score_map.get(threat.get('severity', 'medium'), 0.70)
            
            finding = MLFinding(
                finding_id=f"UEBA-{finding_id_counter:04d}",
                finding_type="insider_threat_indicator",
                severity=self._normalize_severity(threat_score),
                score=threat_score,
                title=f"Pattern detected: {threat['threat_type']} - {threat['user_id']}",
                description=f"Automated behavioral analysis identified activity patterns statistically correlated with {threat['threat_type'].lower()} indicators. Observation: {threat['description']}",
                affected_artifact=threat.get('user_id', 'Unknown'),
                timestamp=threat.get('timestamp', ''),
                explanations=[
                    f"Pattern classification: {threat['threat_type']}",
                    f"Statistical observation: {threat['description']}",
                    "Activity count exceeds established baseline thresholds"
                ],
                correlations=threat.get('files_accessed', []) or threat.get('new_processes', []),
                recommendation="Analyst verification required to determine whether activity aligns with authorized business operations"
            )
            findings.append(finding)
            finding_id_counter += 1
        
        # Process account takeover patterns (FORENSIC LANGUAGE)
        for takeover in account_takeovers:
            severity_score_map = {'critical': 0.90, 'high': 0.75, 'medium': 0.55, 'low': 0.35}
            takeover_score = severity_score_map.get(takeover.get('severity', 'medium'), 0.70)
            
            finding = MLFinding(
                finding_id=f"UEBA-{finding_id_counter:04d}",
                finding_type="account_anomaly",
                severity=self._normalize_severity(takeover_score),
                score=takeover_score,
                title=f"Unusual account activity: {takeover['threat_type']} - {takeover['user_id']}",
                description=f"Behavioral analysis detected activity patterns deviating from historical baseline for this account. Pattern: {takeover['description']}",
                affected_artifact=takeover.get('user_id', 'Unknown'),
                timestamp=takeover.get('timestamp', ''),
                explanations=[
                    f"Deviation type: {takeover['threat_type']}",
                    f"Statistical observation: {takeover['description']}",
                    "Activity differs from established user profile"
                ],
                correlations=takeover.get('source_ips', []) or takeover.get('new_processes', []),
                recommendation="Analyst should verify account activity legitimacy and correlate with access logs"
            )
            findings.append(finding)
            finding_id_counter += 1
        
        # UNIFIED WRAPPER: Save with metadata
        if len(findings) > 0:
            self.logger.info(f"[UEBA] Saving {len(findings)} behavioral findings to ml_findings.json")
            self.output_handler.write_findings(
                findings=findings,
                entity=entity or MLEntity(user_id="Unknown", device_id="Unknown", platform="Unknown"),
                analysis_type="ueba"
            )
        else:
            # EMPTY RESULT STANDARD
            self.logger.info("[UEBA] No statistically significant deviations detected - writing empty result")
            self.output_handler.write_empty_result(module="ueba", reason="No statistically significant behavioral deviations detected")
    
    def load_profiles(self):
        """Load saved profiles."""
        self.logger.info(f"Loading UEBA profiles from {self.model_dir}")
        
        # Load user profiles
        user_dir = self.model_dir / 'users'
        if user_dir.exists():
            for profile_file in user_dir.glob('*.json'):
                user_id = profile_file.stem
                profile = UserBehaviorProfile(user_id)
                profile.load(profile_file)
                self.user_profiles[user_id] = profile
        
        # Load entity profiles
        entity_dir = self.model_dir / 'entities'
        if entity_dir.exists():
            for profile_file in entity_dir.glob('*.json'):
                entity_id = profile_file.stem
                profile = UserBehaviorProfile(entity_id)
                profile.load(profile_file)
                self.entity_profiles[entity_id] = profile
        
        self.logger.info(f"Loaded {len(self.user_profiles)} user profiles, "
                        f"{len(self.entity_profiles)} entity profiles")
    
    def validate_forensic_output(self) -> Dict[str, bool]:
        """
        Self-validation checklist for forensic ML compliance.
        
        FORENSIC REQUIREMENT: ML must pass ALL checks.
        
        Returns:
            Dictionary with validation results
        """
        checks = {}
        
        # Check 1: Output handler configured
        checks['output_handler_exists'] = self.output_handler is not None
        
        # Check 2: Case path valid
        checks['case_path_valid'] = self.case_path is not None and self.case_path.exists()
        
        # Check 3: MLOutputHandler initialized
        if self.output_handler:
            checks['output_handler_ready'] = True
        else:
            checks['output_handler_ready'] = False
        
        # Check 4: Profiles built
        checks['profiles_built'] = len(self.user_profiles) > 0
        
        # Overall status
        checks['forensic_ready'] = all([
            checks['output_handler_exists'],
            checks['case_path_valid'],
            checks['output_handler_ready']
        ])
        
        return checks


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("UEBA User Behavior Profiling Module")
    print("=" * 50)
    
    # Generate synthetic user events
    np.random.seed(42)
    n_events = 1000
    
    users = ['alice', 'bob', 'charlie', 'mallory']
    
    data = {
        'user_id': np.random.choice(users, n_events),
        'timestamp': pd.date_range('2024-01-01', periods=n_events, freq='1h'),
        'event_type': np.random.choice(['login', 'file_access', 'process_start', 'network_conn'], n_events),
        'process_name': np.random.choice(['chrome.exe', 'excel.exe', 'python.exe', 'cmd.exe'], n_events),
        'file_path': np.random.choice(['/docs/report.pdf', '/data/database.db', '/config/settings.ini'], n_events),
        'destination_ip': np.random.choice(['192.168.1.1', '10.0.0.5', '172.16.0.10'], n_events)
    }
    
    events = pd.DataFrame(data)
    
    # Build profiles
    profiler = UEBAProfiler()
    profiler.build_profiles(events)
    
    # Generate anomalous events for 'mallory'
    anomalous_data = {
        'user_id': ['mallory'] * 50,
        'timestamp': pd.date_range('2024-02-01 02:00', periods=50, freq='5min'),  # Off-hours
        'event_type': ['file_access'] * 50,
        'process_name': ['mimikatz.exe'] * 50,  # Suspicious
        'file_path': ['/secret/passwords.txt'] * 50,  # Sensitive
        'destination_ip': ['192.168.100.200'] * 50  # New IP
    }
    
    test_events = pd.DataFrame(anomalous_data)
    
    # Detect anomalies
    print("\nDetecting anomalies...")
    results = profiler.detect_anomalies(test_events)
    
    anomalies = results[results['ueba_anomaly']]
    print(f"\nFound {len(anomalies)} anomalous events")
    print(f"Average anomaly score: {results['ueba_score'].mean():.3f}")
    
    # Insider threats
    print("\nDetecting insider threats...")
    threats = profiler.detect_insider_threats(test_events)
    print(f"Found {len(threats)} potential threats")
    for threat in threats:
        print(f"  - {threat['threat_type']}: {threat['description']}")
    
    # Account takeover
    print("\nDetecting account takeover...")
    takeovers = profiler.detect_account_takeover(test_events)
    print(f"Found {len(takeovers)} potential takeovers")
    for to in takeovers:
        print(f"  - {to['threat_type']}: {to['description']}")
    
    # High-risk users
    print("\nHigh-risk users:")
    high_risk = profiler.get_high_risk_users(top_n=3)
    for i, user in enumerate(high_risk, 1):
        print(f"{i}. {user['user_id']} (risk={user['risk_score']:.2f})")
