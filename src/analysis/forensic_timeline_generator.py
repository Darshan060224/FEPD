"""
Forensic Timeline Generator
Generates comprehensive timelines from network traffic and forensic events
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


class ForensicTimelineGenerator:
    """Generates timelines from forensic data."""
    
    def __init__(self, case_forensic_data_dir: Path):
        """
        Initialize timeline generator.
        
        Args:
            case_forensic_data_dir: Case forensic_data directory
        """
        self.data_dir = Path(case_forensic_data_dir)
        self.timeline_dir = self.data_dir / "timeline"
        self.timeline_dir.mkdir(exist_ok=True)
    
    def generate_network_timeline(self) -> Dict[str, Any]:
        """Generate timeline from network traffic data."""
        logger.info("Generating network traffic timeline")
        
        # Load network metadata
        network_file = self.data_dir / "network" / "snort_logs_metadata.json"
        if not network_file.exists():
            logger.warning("Network data not found")
            return {'status': 'error', 'reason': 'data_not_found'}
        
        with open(network_file, 'r') as f:
            network_data = json.load(f)
        
        # Build timeline
        timeline = self._build_network_timeline(network_data)
        
        # Identify key events
        key_events = self._identify_key_network_events(timeline, network_data)
        
        # Generate visualizable timeline
        visual_timeline = self._create_visual_timeline(timeline, network_data)
        
        results = {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'date_range': network_data.get('date_range', {}),
            'total_days': len(timeline),
            'timeline': timeline,
            'key_events': key_events,
            'visual_timeline': visual_timeline
        }
        
        # Save timeline
        output_file = self.timeline_dir / "network_timeline.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Network timeline generated: {len(timeline)} days")
        
        return results
    
    def _build_network_timeline(self, network_data: Dict) -> Dict[str, Any]:
        """Build day-by-day timeline of network activity."""
        daily_logs = network_data.get('daily_logs', [])
        
        timeline = {}
        for day in daily_logs:
            date = day['date']
            timeline[date] = {
                'date': date,
                'file_count': day['file_count'],
                'size_mb': day['size_bytes'] / (1024 * 1024),
                'files': day.get('files', []),
                'activity_level': self._categorize_activity_level(day['file_count'])
            }
        
        return timeline
    
    def _categorize_activity_level(self, file_count: int) -> str:
        """Categorize activity level based on file count."""
        if file_count >= 10:
            return 'very_high'
        elif file_count >= 5:
            return 'high'
        elif file_count >= 3:
            return 'medium'
        elif file_count >= 1:
            return 'low'
        else:
            return 'none'
    
    def _identify_key_network_events(self, timeline: Dict, network_data: Dict) -> List[Dict]:
        """Identify significant events in network timeline."""
        daily_logs = network_data.get('daily_logs', [])
        
        if not daily_logs:
            return []
        
        # Calculate statistics
        file_counts = [day['file_count'] for day in daily_logs]
        mean_count = sum(file_counts) / len(file_counts)
        
        key_events = []
        
        # Find spikes in activity
        for date, data in timeline.items():
            if data['file_count'] > mean_count * 1.5:
                key_events.append({
                    'date': date,
                    'type': 'traffic_spike',
                    'severity': 'medium',
                    'description': f"High network activity: {data['file_count']} log files",
                    'file_count': data['file_count']
                })
        
        # Find gaps in logging
        dates = sorted(timeline.keys())
        for i in range(len(dates) - 1):
            current = datetime.strptime(dates[i], '%Y-%m-%d')
            next_date = datetime.strptime(dates[i + 1], '%Y-%m-%d')
            gap = (next_date - current).days
            
            if gap > 1:
                key_events.append({
                    'date': dates[i],
                    'type': 'logging_gap',
                    'severity': 'high',
                    'description': f"Gap in logging: {gap} days between {dates[i]} and {dates[i+1]}",
                    'gap_days': gap
                })
        
        # Sort by date
        key_events.sort(key=lambda x: x['date'])
        
        return key_events
    
    def _create_visual_timeline(self, timeline: Dict, network_data: Dict) -> Dict[str, Any]:
        """Create data structure for timeline visualization."""
        dates = sorted(timeline.keys())
        
        # Create time series data
        time_series = []
        for date in dates:
            data = timeline[date]
            time_series.append({
                'date': date,
                'value': data['file_count'],
                'size_mb': data['size_mb'],
                'activity': data['activity_level']
            })
        
        # Calculate weekly aggregates
        weekly_data = self._aggregate_weekly(time_series)
        
        return {
            'daily_series': time_series,
            'weekly_aggregates': weekly_data,
            'date_range': {
                'start': dates[0] if dates else None,
                'end': dates[-1] if dates else None,
                'total_days': len(dates)
            }
        }
    
    def _aggregate_weekly(self, time_series: List[Dict]) -> List[Dict]:
        """Aggregate daily data into weekly summaries."""
        weekly = defaultdict(lambda: {'file_count': 0, 'size_mb': 0, 'days': []})
        
        for entry in time_series:
            date = datetime.strptime(entry['date'], '%Y-%m-%d')
            # Get week number
            week_key = f"{date.year}-W{date.isocalendar()[1]:02d}"
            
            weekly[week_key]['file_count'] += entry['value']
            weekly[week_key]['size_mb'] += entry['size_mb']
            weekly[week_key]['days'].append(entry['date'])
        
        # Convert to list
        result = []
        for week, data in sorted(weekly.items()):
            days_list = data['days']
            # Ensure days_list is a list before indexing
            if isinstance(days_list, list) and days_list:
                date_range = f"{days_list[0]} to {days_list[-1]}"
            else:
                date_range = "No data"
            
            result.append({
                'week': week,
                'file_count': data['file_count'],
                'size_mb': round(data['size_mb'], 2),
                'days_in_week': len(days_list) if isinstance(days_list, list) else 0,
                'date_range': date_range
            })
        
        return result
    
    def generate_comprehensive_timeline(self) -> Dict[str, Any]:
        """Generate comprehensive forensic timeline combining all data sources."""
        logger.info("Generating comprehensive forensic timeline")
        
        timeline_data = {
            'report_timestamp': datetime.now().isoformat(),
            'timelines': {}
        }
        
        # Network timeline
        network_timeline = self.generate_network_timeline()
        if network_timeline.get('status') == 'success':
            timeline_data['timelines']['network'] = network_timeline
        
        # Malware timeline (based on analysis timestamps)
        malware_timeline = self._generate_malware_timeline()
        if malware_timeline.get('status') == 'success':
            timeline_data['timelines']['malware'] = malware_timeline
        
        # Honeypot timeline
        honeypot_timeline = self._generate_honeypot_timeline()
        if honeypot_timeline.get('status') == 'success':
            timeline_data['timelines']['honeypot'] = honeypot_timeline
        
        # Generate unified timeline
        timeline_data['unified'] = self._create_unified_timeline(timeline_data['timelines'])
        
        # Save comprehensive timeline
        output_file = self.timeline_dir / "comprehensive_timeline.json"
        with open(output_file, 'w') as f:
            json.dump(timeline_data, f, indent=2)
        
        logger.info("Comprehensive timeline generated")
        
        return timeline_data
    
    def _generate_malware_timeline(self) -> Dict[str, Any]:
        """Generate timeline from malware analysis."""
        malware_file = self.data_dir / "malware" / "malware_samples.json"
        
        if not malware_file.exists():
            return {'status': 'skipped', 'reason': 'data_not_found'}
        
        with open(malware_file, 'r') as f:
            malware_data = json.load(f)
        
        stats = malware_data.get('statistics', {})
        
        return {
            'status': 'success',
            'total_samples': malware_data.get('total_samples', 0),
            'categories': stats.get('category_distribution', {}),
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _generate_honeypot_timeline(self) -> Dict[str, Any]:
        """Generate timeline from honeypot attacks."""
        honeypot_file = self.data_dir / "honeypot" / "honeypot_attacks.json"
        
        if not honeypot_file.exists():
            return {'status': 'skipped', 'reason': 'data_not_found'}
        
        with open(honeypot_file, 'r') as f:
            honeypot_data = json.load(f)
        
        # Extract attack timeline
        attacks = honeypot_data.get('attacks', [])
        attack_timeline = defaultdict(int)
        
        for attack in attacks:
            # Try to extract timestamp
            timestamp = attack.get('timestamp') or attack.get('time')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    date_key = dt.strftime('%Y-%m-%d')
                    attack_timeline[date_key] += 1
                except:
                    pass
        
        return {
            'status': 'success',
            'total_attacks': honeypot_data.get('total_records', 0),
            'daily_attacks': dict(sorted(attack_timeline.items())),
            'statistics': honeypot_data.get('statistics', {})
        }
    
    def _create_unified_timeline(self, timelines: Dict) -> Dict[str, Any]:
        """Create unified timeline combining all data sources."""
        unified_events = []
        
        # Add network events
        network = timelines.get('network', {})
        if network.get('status') == 'success':
            for event in network.get('key_events', []):
                unified_events.append({
                    'date': event['date'],
                    'source': 'network',
                    'type': event['type'],
                    'severity': event['severity'],
                    'description': event['description']
                })
        
        # Add malware events
        malware = timelines.get('malware', {})
        if malware.get('status') == 'success':
            unified_events.append({
                'date': datetime.now().strftime('%Y-%m-%d'),
                'source': 'malware',
                'type': 'analysis_complete',
                'severity': 'info',
                'description': f"Malware analysis completed: {malware['total_samples']} samples"
            })
        
        # Sort by date
        unified_events.sort(key=lambda x: x['date'])
        
        return {
            'total_events': len(unified_events),
            'events': unified_events,
            'sources': list(set(e['source'] for e in unified_events))
        }
