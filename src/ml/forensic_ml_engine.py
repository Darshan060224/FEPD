"""
FEPD Forensic ML Intelligence Engine
======================================

This module transforms ML from "noise generator" to "forensic intelligence."

Key improvements:
- Meaningful anomaly scores (0.0-1.0 with clear meaning)
- Explains WHY something is anomalous, not just WHAT
- Normalizes events to canonical format
- Court-defensible explanations
- Severity levels with clear definitions

Score Meaning:
    0.0-0.3: Normal baseline behavior
    0.3-0.6: Suspicious - warrants attention
    0.6-0.85: High Risk - likely anomalous
    0.85-1.0: Critical - rare/unique behavior

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import Counter
import hashlib
import json
import logging
import re

logger = logging.getLogger(__name__)


# ============================================================================
# SEVERITY LEVELS
# ============================================================================

class Severity:
    """Forensic severity levels with clear definitions."""
    
    NORMAL = "normal"       # 0.0-0.3: Expected behavior
    SUSPICIOUS = "suspicious"  # 0.3-0.6: Warrants investigation
    HIGH_RISK = "high_risk"    # 0.6-0.85: Likely anomalous
    CRITICAL = "critical"      # 0.85-1.0: Rare/unique behavior
    
    @staticmethod
    def from_score(score: float) -> str:
        """Convert score to severity level."""
        if score < 0.3:
            return Severity.NORMAL
        elif score < 0.6:
            return Severity.SUSPICIOUS
        elif score < 0.85:
            return Severity.HIGH_RISK
        else:
            return Severity.CRITICAL
    
    @staticmethod
    def get_color(severity: str) -> str:
        """Get color for UI display."""
        colors = {
            Severity.NORMAL: "#4CAF50",     # Green
            Severity.SUSPICIOUS: "#FFC107",  # Yellow/Amber
            Severity.HIGH_RISK: "#FF9800",   # Orange
            Severity.CRITICAL: "#F44336"     # Red
        }
        return colors.get(severity, "#9E9E9E")
    
    @staticmethod
    def get_description(severity: str) -> str:
        """Get human-readable description."""
        descriptions = {
            Severity.NORMAL: "Expected baseline behavior",
            Severity.SUSPICIOUS: "Warrants further investigation",
            Severity.HIGH_RISK: "Likely anomalous activity",
            Severity.CRITICAL: "Rare or unique behavior - immediate attention"
        }
        return descriptions.get(severity, "Unknown")


# ============================================================================
# NORMALIZED EVENT
# ============================================================================

@dataclass
class NormalizedEvent:
    """
    Canonical event format for FEPD.
    
    All events from any source (EVTX, Prefetch, Browser, etc.)
    are normalized to this format before ML analysis.
    """
    # Required fields
    timestamp: datetime
    event_type: str  # ProcessStart, FileAccess, LogonSuccess, etc.
    
    # Entity fields
    user: str = "Unknown"
    host: str = "Unknown"
    
    # Action fields
    action: str = ""  # What happened: Created, Executed, Modified, Deleted
    object: str = ""  # What was acted on: powershell.exe, C:\Users\Alice\doc.txt
    
    # Additional context
    source_ip: str = ""
    dest_ip: str = ""
    process_id: int = 0
    parent_process: str = ""
    command_line: str = ""
    
    # Source tracking
    artifact_type: str = ""  # evtx, prefetch, browser, registry
    artifact_path: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    # ML results (populated after analysis)
    anomaly_score: float = 0.0
    severity: str = Severity.NORMAL
    explanations: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "user": self.user,
            "host": self.host,
            "action": self.action,
            "object": self.object,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "process_id": self.process_id,
            "parent_process": self.parent_process,
            "command_line": self.command_line,
            "artifact_type": self.artifact_type,
            "artifact_path": self.artifact_path,
            "anomaly_score": self.anomaly_score,
            "severity": self.severity,
            "explanations": self.explanations,
            "flags": self.flags
        }


# ============================================================================
# EVENT NORMALIZER
# ============================================================================

class EventNormalizer:
    """
    Normalizes events from various artifact types to canonical format.
    """
    
    def __init__(self):
        self._parsers = {
            'evtx': self._parse_evtx_event,
            'prefetch': self._parse_prefetch_event,
            'browser': self._parse_browser_event,
            'registry': self._parse_registry_event,
            'mft': self._parse_mft_event,
            'generic': self._parse_generic_event
        }
    
    def normalize(self, event_data: Dict[str, Any], 
                  artifact_type: str = 'generic') -> NormalizedEvent:
        """
        Normalize an event to canonical format.
        
        Args:
            event_data: Raw event data
            artifact_type: Type of artifact (evtx, prefetch, etc.)
            
        Returns:
            NormalizedEvent in canonical format
        """
        parser = self._parsers.get(artifact_type, self._parse_generic_event)
        return parser(event_data)
    
    def _parse_timestamp(self, value: Any) -> datetime:
        """Parse timestamp from various formats."""
        if isinstance(value, datetime):
            return value
        
        if isinstance(value, str):
            # Try various formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S.%f",
                "%m/%d/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M:%S"
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(value[:26], fmt)
                except (ValueError, IndexError):
                    continue
            
            # Try ISO format
            try:
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            except:
                pass
        
        # Default to now if unparseable
        return datetime.now()
    
    def _parse_evtx_event(self, data: Dict[str, Any]) -> NormalizedEvent:
        """Parse Windows Event Log entry."""
        # Extract timestamp
        timestamp = self._parse_timestamp(
            data.get('ts_local') or data.get('ts_utc') or 
            data.get('TimeCreated') or data.get('timestamp')
        )
        
        # Extract event type from Event ID
        event_id = data.get('EventID') or data.get('event_id') or 0
        event_type = self._evtx_event_id_to_type(event_id)
        
        # Extract user
        user = (data.get('TargetUserName') or data.get('SubjectUserName') or 
                data.get('user_account') or data.get('user') or 'Unknown')
        
        # Extract host
        host = (data.get('Computer') or data.get('Workstation') or 
                data.get('host') or 'Unknown')
        
        # Extract process info
        process = data.get('ProcessName') or data.get('process_name') or ''
        parent = data.get('ParentProcessName') or data.get('parent_name') or ''
        cmd_line = data.get('CommandLine') or data.get('command_line') or ''
        
        return NormalizedEvent(
            timestamp=timestamp,
            event_type=event_type,
            user=user,
            host=host,
            action=self._evtx_event_id_to_action(event_id),
            object=process,
            process_id=int(data.get('ProcessId', 0) or 0),
            parent_process=parent,
            command_line=cmd_line,
            source_ip=data.get('IpAddress') or data.get('SourceNetworkAddress') or '',
            artifact_type='evtx',
            raw_data=data
        )
    
    def _evtx_event_id_to_type(self, event_id: int) -> str:
        """Convert Event ID to event type name."""
        event_types = {
            # Security events
            4624: "LogonSuccess",
            4625: "LogonFailure",
            4634: "LogoffSuccess",
            4648: "ExplicitCredentials",
            4672: "SpecialPrivileges",
            4688: "ProcessStart",
            4689: "ProcessEnd",
            4698: "ScheduledTaskCreate",
            4699: "ScheduledTaskDelete",
            4700: "ScheduledTaskEnable",
            4701: "ScheduledTaskDisable",
            4702: "ScheduledTaskUpdate",
            4720: "AccountCreated",
            4722: "AccountEnabled",
            4723: "PasswordChange",
            4724: "PasswordReset",
            4725: "AccountDisabled",
            4726: "AccountDeleted",
            4728: "GroupMemberAdded",
            4729: "GroupMemberRemoved",
            4732: "LocalGroupMemberAdded",
            4733: "LocalGroupMemberRemoved",
            4738: "AccountModified",
            4740: "AccountLockout",
            4756: "GroupMemberAdded",
            4768: "KerberosAuthRequest",
            4769: "KerberosServiceTicket",
            4776: "CredentialValidation",
            4778: "SessionReconnect",
            4779: "SessionDisconnect",
            
            # System events
            7045: "ServiceInstalled",
            7035: "ServiceControlSent",
            7036: "ServiceStateChanged",
            
            # PowerShell events
            4103: "PowerShellModule",
            4104: "PowerShellScript",
            
            # Sysmon events
            1: "ProcessCreate",
            3: "NetworkConnection",
            7: "ImageLoad",
            8: "CreateRemoteThread",
            10: "ProcessAccess",
            11: "FileCreate",
            12: "RegistryEvent",
            13: "RegistryValueSet",
            22: "DNSQuery",
        }
        return event_types.get(event_id, f"EventID_{event_id}")
    
    def _evtx_event_id_to_action(self, event_id: int) -> str:
        """Convert Event ID to action verb."""
        actions = {
            4624: "LoggedOn", 4625: "FailedLogon", 4634: "LoggedOff",
            4688: "Executed", 4689: "Terminated",
            4720: "Created", 4726: "Deleted",
            4732: "Added", 4733: "Removed",
            7045: "Installed", 1: "Created", 11: "Created"
        }
        return actions.get(event_id, "Observed")
    
    def _parse_prefetch_event(self, data: Dict[str, Any]) -> NormalizedEvent:
        """Parse Prefetch entry."""
        timestamp = self._parse_timestamp(
            data.get('last_run') or data.get('LastRunTime') or data.get('timestamp')
        )
        
        return NormalizedEvent(
            timestamp=timestamp,
            event_type="ProcessExecution",
            user="Unknown",  # Prefetch doesn't track user
            host=data.get('host', 'Unknown'),
            action="Executed",
            object=data.get('executable') or data.get('name') or '',
            artifact_type='prefetch',
            raw_data=data
        )
    
    def _parse_browser_event(self, data: Dict[str, Any]) -> NormalizedEvent:
        """Parse browser history/activity."""
        timestamp = self._parse_timestamp(
            data.get('visit_time') or data.get('timestamp')
        )
        
        return NormalizedEvent(
            timestamp=timestamp,
            event_type="WebVisit",
            user=data.get('profile') or 'Unknown',
            host=data.get('host', 'Unknown'),
            action="Visited",
            object=data.get('url') or '',
            artifact_type='browser',
            raw_data=data
        )
    
    def _parse_registry_event(self, data: Dict[str, Any]) -> NormalizedEvent:
        """Parse registry modification."""
        timestamp = self._parse_timestamp(
            data.get('last_write') or data.get('timestamp')
        )
        
        return NormalizedEvent(
            timestamp=timestamp,
            event_type="RegistryModification",
            user=data.get('user', 'Unknown'),
            host=data.get('host', 'Unknown'),
            action=data.get('operation', 'Modified'),
            object=data.get('key_path') or data.get('key') or '',
            artifact_type='registry',
            raw_data=data
        )
    
    def _parse_mft_event(self, data: Dict[str, Any]) -> NormalizedEvent:
        """Parse MFT entry."""
        timestamp = self._parse_timestamp(
            data.get('si_modified') or data.get('fn_modified') or data.get('timestamp')
        )
        
        return NormalizedEvent(
            timestamp=timestamp,
            event_type="FileActivity",
            user=data.get('owner', 'Unknown'),
            host=data.get('host', 'Unknown'),
            action="Modified",
            object=data.get('full_path') or data.get('filename') or '',
            artifact_type='mft',
            raw_data=data
        )
    
    def _parse_generic_event(self, data: Dict[str, Any]) -> NormalizedEvent:
        """Parse generic event with best-effort field mapping."""
        # Try to find timestamp
        timestamp = datetime.now()
        for field in ['timestamp', 'ts_local', 'ts_utc', 'time', 'datetime', 'date']:
            if field in data:
                timestamp = self._parse_timestamp(data[field])
                break
        
        # Try to find event type
        event_type = "Unknown"
        for field in ['event_type', 'type', 'EventID', 'event_id', 'category']:
            if field in data:
                event_type = str(data[field])
                break
        
        # Try to find user
        user = "Unknown"
        for field in ['user', 'user_account', 'username', 'SubjectUserName', 'TargetUserName']:
            if field in data and data[field]:
                user = str(data[field])
                break
        
        # Try to find host
        host = "Unknown"
        for field in ['host', 'Computer', 'hostname', 'machine']:
            if field in data and data[field]:
                host = str(data[field])
                break
        
        # Try to find object
        obj = ""
        for field in ['process_name', 'ProcessName', 'file_path', 'FilePath', 'object', 'target']:
            if field in data and data[field]:
                obj = str(data[field])
                break
        
        return NormalizedEvent(
            timestamp=timestamp,
            event_type=event_type,
            user=user,
            host=host,
            object=obj,
            artifact_type='generic',
            raw_data=data
        )


# ============================================================================
# FORENSIC ANOMALY EXPLAINER
# ============================================================================

class ForensicAnomalyExplainer:
    """
    Generates human-readable explanations for anomalies.
    
    Turns ML scores into forensic intelligence:
    - Why is this anomalous?
    - What makes it suspicious?
    - What should the investigator look for?
    """
    
    # Suspicious process names
    SUSPICIOUS_PROCESSES = {
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe',
        'bitsadmin.exe', 'msiexec.exe', 'wmic.exe', 'psexec.exe',
        'procdump.exe', 'mimikatz.exe', 'lazagne.exe', 'rubeus.exe'
    }
    
    # Suspicious paths
    SUSPICIOUS_PATHS = [
        r'\\temp\\', r'\\tmp\\', r'\\appdata\\local\\temp\\',
        r'\\programdata\\', r'\\public\\', r'\\perflogs\\',
        r'\\windows\\debug\\', r'\\recycler\\'
    ]
    
    # Off-hours (configurable)
    OFF_HOURS_START = 22  # 10 PM
    OFF_HOURS_END = 6     # 6 AM
    
    def __init__(self, baseline_events: Optional[List[NormalizedEvent]] = None):
        """
        Initialize explainer with optional baseline.
        
        Args:
            baseline_events: Historical events for baseline comparison
        """
        self.baseline_users: set = set()
        self.baseline_processes: set = set()
        self.baseline_hosts: set = set()
        self.baseline_hours: Counter = Counter()
        self.total_baseline_events = 0
        
        if baseline_events:
            self.learn_baseline(baseline_events)
    
    def learn_baseline(self, events: List[NormalizedEvent]):
        """Learn baseline behavior from historical events."""
        for event in events:
            self.baseline_users.add(event.user)
            if event.object:
                self.baseline_processes.add(event.object.lower())
            self.baseline_hosts.add(event.host)
            self.baseline_hours[event.timestamp.hour] += 1
            self.total_baseline_events += 1
        
        logger.info(f"Learned baseline from {self.total_baseline_events} events")
    
    def explain(self, event: NormalizedEvent) -> Tuple[float, List[str], List[str]]:
        """
        Analyze event and generate anomaly score with explanations.
        
        Args:
            event: Normalized event to analyze
            
        Returns:
            (anomaly_score, explanations, flags)
        """
        score = 0.0
        explanations = []
        flags = []
        
        # Check time anomaly
        hour = event.timestamp.hour
        if self.OFF_HOURS_START <= hour or hour < self.OFF_HOURS_END:
            score += 0.15
            explanations.append(
                f"🕐 Rare execution time ({hour:02d}:{event.timestamp.minute:02d} - off-hours)"
            )
            flags.append("OFF_HOURS")
        
        # Check if hour is rare in baseline
        if self.total_baseline_events > 0:
            hour_freq = self.baseline_hours.get(hour, 0) / self.total_baseline_events
            if hour_freq < 0.01:  # Less than 1% of events
                score += 0.1
                explanations.append(
                    f"📊 Event hour ({hour}:00) is rare in baseline (<1%)"
                )
                flags.append("RARE_TIME")
        
        # Check user anomaly
        if event.user and event.user != "Unknown":
            if self.baseline_users and event.user not in self.baseline_users:
                score += 0.2
                explanations.append(
                    f"👤 New user not seen in baseline: {event.user}"
                )
                flags.append("NEW_USER")
        
        # Check process anomaly
        if event.object:
            process_name = event.object.lower()
            
            # Check if in baseline
            if self.baseline_processes and process_name not in self.baseline_processes:
                score += 0.15
                explanations.append(
                    f"📦 New binary not seen before: {event.object}"
                )
                flags.append("NEW_BINARY")
            
            # Check if suspicious process
            base_name = process_name.split('\\')[-1] if '\\' in process_name else process_name
            if base_name in self.SUSPICIOUS_PROCESSES:
                score += 0.2
                explanations.append(
                    f"⚠️ Known attack tool/LOLBin: {base_name}"
                )
                flags.append("LOLBIN")
        
        # Check command line for suspicious patterns
        if event.command_line:
            cmd_lower = event.command_line.lower()
            
            # Encoded commands
            if '-encodedcommand' in cmd_lower or '-enc' in cmd_lower:
                score += 0.25
                explanations.append(
                    "🔐 Encoded/obfuscated command detected"
                )
                flags.append("ENCODED_CMD")
            
            # Download cradles
            if any(p in cmd_lower for p in ['downloadstring', 'downloadfile', 'invoke-webrequest', 'curl', 'wget']):
                score += 0.2
                explanations.append(
                    "📥 Download cradle pattern detected"
                )
                flags.append("DOWNLOAD_CRADLE")
            
            # Suspicious paths
            for path in self.SUSPICIOUS_PATHS:
                if path.lower() in cmd_lower:
                    score += 0.1
                    explanations.append(
                        f"📁 Suspicious path reference: {path}"
                    )
                    flags.append("SUSPICIOUS_PATH")
                    break
        
        # Check for user context switch (SYSTEM → User or vice versa)
        if event.parent_process and event.user:
            parent_lower = event.parent_process.lower()
            if 'system' in parent_lower or 'local service' in parent_lower:
                if event.user.lower() not in ('system', 'local service', 'network service'):
                    score += 0.2
                    explanations.append(
                        f"🔄 User context switch: SYSTEM → {event.user}"
                    )
                    flags.append("CONTEXT_SWITCH")
        
        # Check event type rarity
        high_risk_types = {
            'ScheduledTaskCreate', 'ServiceInstalled', 'AccountCreated',
            'GroupMemberAdded', 'PasswordReset', 'ExplicitCredentials',
            'CreateRemoteThread', 'ProcessAccess'
        }
        if event.event_type in high_risk_types:
            score += 0.15
            explanations.append(
                f"⚡ High-risk event type: {event.event_type}"
            )
            flags.append("HIGH_RISK_EVENT")
        
        # Normalize score to 0-1
        score = min(1.0, score)
        
        # Add summary if no explanations
        if not explanations:
            explanations.append("✓ No anomalies detected - baseline behavior")
        
        return score, explanations, flags


# ============================================================================
# FORENSIC ML ENGINE
# ============================================================================

class ForensicMLEngine:
    """
    Main ML engine that provides forensic intelligence.
    
    Transforms raw events into actionable findings with:
    - Meaningful scores (not always 1.0)
    - Clear explanations (not Unknown, Unknown, Unknown)
    - Court-defensible reasoning
    """
    
    def __init__(self, case_path: Optional[str] = None):
        self.case_path = case_path
        self.normalizer = EventNormalizer()
        self.explainer = ForensicAnomalyExplainer()
        self.trained = False
    
    def train(self, events_df: pd.DataFrame, artifact_type: str = 'generic'):
        """
        Train the baseline from historical events.
        
        Args:
            events_df: DataFrame with events
            artifact_type: Type of artifact
        """
        # Normalize events
        normalized = []
        for _, row in events_df.iterrows():
            event = self.normalizer.normalize(row.to_dict(), artifact_type)
            normalized.append(event)
        
        # Train baseline
        self.explainer.learn_baseline(normalized)
        self.trained = True
        
        logger.info(f"Trained on {len(normalized)} events")
    
    def analyze(self, events_df: pd.DataFrame, 
                artifact_type: str = 'generic') -> pd.DataFrame:
        """
        Analyze events and add anomaly scores with explanations.
        
        Args:
            events_df: DataFrame with events to analyze
            artifact_type: Type of artifact
            
        Returns:
            DataFrame with added columns:
            - anomaly_score (0.0-1.0)
            - severity (normal/suspicious/high_risk/critical)
            - explanations (list of reasons)
            - flags (list of flag codes)
        """
        results = []
        
        for _, row in events_df.iterrows():
            event = self.normalizer.normalize(row.to_dict(), artifact_type)
            
            # Get anomaly analysis
            score, explanations, flags = self.explainer.explain(event)
            
            # Update event
            event.anomaly_score = score
            event.severity = Severity.from_score(score)
            event.explanations = explanations
            event.flags = flags
            
            # Build result row
            result = row.to_dict()
            result['anomaly_score'] = score
            result['severity'] = event.severity
            result['severity_color'] = Severity.get_color(event.severity)
            result['explanations'] = ' | '.join(explanations)
            result['explanations_list'] = explanations
            result['flags'] = ','.join(flags)
            result['flags_list'] = flags
            
            # Normalized fields
            result['norm_user'] = event.user
            result['norm_host'] = event.host
            result['norm_event_type'] = event.event_type
            result['norm_object'] = event.object
            result['norm_action'] = event.action
            
            results.append(result)
        
        return pd.DataFrame(results)
    
    def get_top_anomalies(self, analyzed_df: pd.DataFrame, 
                          top_n: int = 20) -> pd.DataFrame:
        """Get top anomalies sorted by score."""
        return analyzed_df.nlargest(top_n, 'anomaly_score')
    
    def get_anomaly_summary(self, analyzed_df: pd.DataFrame) -> Dict[str, Any]:
        """Generate summary statistics."""
        total = len(analyzed_df)
        
        # Count by severity
        severity_counts = analyzed_df['severity'].value_counts().to_dict()
        
        # Get top flags
        all_flags = []
        for flags in analyzed_df.get('flags_list', []):
            if isinstance(flags, list):
                all_flags.extend(flags)
        flag_counts = Counter(all_flags).most_common(10)
        
        # Score distribution
        scores = analyzed_df['anomaly_score']
        
        return {
            'total_events': total,
            'severity_distribution': {
                'critical': severity_counts.get(Severity.CRITICAL, 0),
                'high_risk': severity_counts.get(Severity.HIGH_RISK, 0),
                'suspicious': severity_counts.get(Severity.SUSPICIOUS, 0),
                'normal': severity_counts.get(Severity.NORMAL, 0)
            },
            'score_stats': {
                'mean': float(scores.mean()),
                'median': float(scores.median()),
                'max': float(scores.max()),
                'min': float(scores.min())
            },
            'top_flags': flag_counts,
            'anomaly_rate': (total - severity_counts.get(Severity.NORMAL, 0)) / total if total > 0 else 0
        }
    
    def generate_forensic_report(self, analyzed_df: pd.DataFrame) -> str:
        """Generate a forensic report of findings."""
        summary = self.get_anomaly_summary(analyzed_df)
        top_anomalies = self.get_top_anomalies(analyzed_df, 10)
        
        report = []
        report.append("=" * 70)
        report.append("FEPD FORENSIC ML ANALYSIS REPORT")
        report.append("=" * 70)
        report.append("")
        
        # Summary
        report.append("📊 SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Events Analyzed: {summary['total_events']}")
        report.append(f"Anomaly Rate: {summary['anomaly_rate']:.1%}")
        report.append("")
        
        # Severity distribution
        report.append("🎯 SEVERITY DISTRIBUTION")
        report.append("-" * 40)
        dist = summary['severity_distribution']
        report.append(f"  🔴 Critical:    {dist['critical']:>5}")
        report.append(f"  🟠 High Risk:   {dist['high_risk']:>5}")
        report.append(f"  🟡 Suspicious:  {dist['suspicious']:>5}")
        report.append(f"  🟢 Normal:      {dist['normal']:>5}")
        report.append("")
        
        # Top findings
        report.append("🔍 TOP ANOMALIES")
        report.append("-" * 40)
        for i, (_, row) in enumerate(top_anomalies.iterrows(), 1):
            report.append(f"\n[{i}] Score: {row['anomaly_score']:.3f} ({row['severity'].upper()})")
            report.append(f"    User: {row.get('norm_user', 'Unknown')}")
            report.append(f"    Event: {row.get('norm_event_type', 'Unknown')}")
            report.append(f"    Object: {row.get('norm_object', 'Unknown')}")
            if row.get('explanations'):
                report.append(f"    Reasons:")
                for exp in row.get('explanations', '').split(' | '):
                    if exp:
                        report.append(f"      - {exp}")
        
        report.append("")
        report.append("=" * 70)
        report.append("End of Report")
        
        return '\n'.join(report)
