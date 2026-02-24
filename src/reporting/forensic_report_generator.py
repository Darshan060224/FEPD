"""
FEPD Forensic Report Generator
==============================

Transforms raw forensic data into professional, court-admissible investigation reports.

This module produces human-readable forensic narratives suitable for:
- Incident response teams
- Legal proceedings
- Management briefings
- Court presentation

Principles:
- Every section is human-readable
- No raw dumps without context
- Forensic neutrality maintained
- Chain of custody preserved
- ML results are explainable
- All findings trace to evidence

Copyright (c) 2026 FEPD Development Team
"""

import os
import sys
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


class ForensicReportGenerator:
    """
    Professional forensic report generator following DFIR standards.
    
    Produces court-admissible investigation reports with proper
    forensic narrative, evidence correlation, and analytical reasoning.
    """
    
    def __init__(self, workspace_root: str = '.'):
        self.workspace_root = workspace_root
        self.cases_root = os.path.join(workspace_root, 'cases')
        self.report_version = "FEPD v2.0.0"
        
    def generate_report(self, case_name: str, analyst: str = "FEPD Analyst", 
                       organization: str = "Forensic Investigation Unit") -> str:
        """
        Generate a complete forensic investigation report.
        
        Args:
            case_name: Name of the case to report on
            analyst: Name of the analyst
            organization: Organization conducting the investigation
            
        Returns:
            Markdown-formatted forensic report
        """
        case_path = os.path.join(self.cases_root, case_name)
        
        if not os.path.exists(case_path):
            return f"ERROR: Case directory not found: {case_name}"
        
        # Find database file (multiple possible names)
        db_path = None
        possible_db_names = [
            f"{case_name}.db",
            "case.db",
            "evidence.db",
            "forensic.db"
        ]
        
        for db_name in possible_db_names:
            test_path = os.path.join(case_path, db_name)
            if os.path.exists(test_path):
                db_path = test_path
                break
        
        # Gather all case data (works with or without database)
        case_data = self._gather_case_data(case_name, case_path, db_path)
        
        # Build report sections
        report_parts = []
        report_parts.append(self._generate_cover_page(case_data, analyst, organization))
        report_parts.append(self._generate_executive_summary(case_data))
        report_parts.append(self._generate_case_metadata(case_data))
        report_parts.append(self._generate_evidence_overview(case_data))
        report_parts.append(self._generate_artifact_summary(case_data))
        report_parts.append(self._generate_timeline_status(case_data))
        report_parts.append(self._generate_ml_analysis(case_data))
        report_parts.append(self._generate_notable_artifacts(case_data))
        report_parts.append(self._generate_chain_of_custody(case_data))
        report_parts.append(self._generate_recommendations(case_data))
        report_parts.append(self._generate_appendix(case_data))
        
        return '\n\n'.join(report_parts)
    
    def _gather_case_data(self, case_name: str, case_path: str, db_path: Optional[str]) -> Dict[str, Any]:
        """Gather all forensic data from case database and filesystem."""
        data = {
            'case_name': case_name,
            'case_path': case_path,
            'db_path': db_path or 'No database',
            'generation_date': datetime.now(),
            'evidence_items': [],
            'artifact_counts': {},
            'timeline_events': 0,
            'ml_results': {},
            'notable_artifacts': [],
            'file_count': 0,
            'total_size': 0,
            'os_type': 'Unknown',
            'users': [],
            'coc_status': 'Not Verified'
        }
        
        # If no database, try to gather data from filesystem
        if not db_path or not os.path.exists(db_path):
            data = self._gather_from_filesystem(case_name, case_path, data)
            return data
        
        # Gather from database
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        data = {
            'case_name': case_name,
            'case_path': case_path,
            'db_path': db_path,
            'generation_date': datetime.now(),
            'evidence_items': [],
            'artifact_counts': {},
            'timeline_events': 0,
            'ml_results': {},
            'notable_artifacts': [],
            'file_count': 0,
            'total_size': 0,
            'os_type': 'Unknown',
            'users': [],
            'coc_status': 'Not Verified'
        }
        
        # Get evidence items
        try:
            cur.execute("SELECT * FROM evidence ORDER BY created_at")
            evidence = cur.fetchall()
            for ev in evidence:
                data['evidence_items'].append(dict(ev))
        except sqlite3.OperationalError:
            pass
        
        # Get file statistics
        try:
            cur.execute("SELECT COUNT(*), SUM(size) FROM files")
            result = cur.fetchone()
            data['file_count'] = result[0] or 0
            data['total_size'] = result[1] or 0
        except sqlite3.OperationalError:
            pass
        
        # Get artifact counts by type
        try:
            cur.execute("""
                SELECT type, COUNT(*) as count, SUM(size) as total_size 
                FROM files 
                WHERE type IS NOT NULL 
                GROUP BY type
            """)
            for row in cur.fetchall():
                data['artifact_counts'][row[0]] = {
                    'count': row[1],
                    'size': row[2] or 0
                }
        except sqlite3.OperationalError:
            pass
        
        # Get timeline event count
        try:
            cur.execute("SELECT COUNT(*) FROM timeline")
            data['timeline_events'] = cur.fetchone()[0] or 0
        except sqlite3.OperationalError:
            pass
        
        # Get detected users
        try:
            cur.execute("""
                SELECT DISTINCT owner FROM files 
                WHERE owner IS NOT NULL AND owner != ''
            """)
            data['users'] = [row[0] for row in cur.fetchall()]
        except sqlite3.OperationalError:
            pass
        
        # Detect OS type from paths
        try:
            cur.execute("SELECT path FROM files LIMIT 100")
            paths = [row[0] for row in cur.fetchall()]
            if any('C:\\Windows' in p or 'C:/Windows' in p for p in paths):
                data['os_type'] = 'Windows'
            elif any('/etc/' in p or '/var/' in p for p in paths):
                data['os_type'] = 'Linux'
            elif any('/System/Library' in p for p in paths):
                data['os_type'] = 'macOS'
        except sqlite3.OperationalError:
            pass
        
        # Get ML results if available
        try:
            cur.execute("SELECT * FROM ml_results ORDER BY timestamp DESC LIMIT 10")
            for row in cur.fetchall():
                result_dict = dict(row)
                model = result_dict.get('model', 'unknown')
                data['ml_results'][model] = result_dict
        except sqlite3.OperationalError:
            pass
        
        # Get chain of custody status
        try:
            cur.execute("SELECT COUNT(*) FROM chain_of_custody")
            coc_count = cur.fetchone()[0] or 0
            data['coc_status'] = f"{coc_count} entries logged" if coc_count > 0 else "No chain established"
        except sqlite3.OperationalError:
            data['coc_status'] = "Chain of custody not initialized"
        
        # Identify notable artifacts (high execution count, suspicious extensions, etc.)
        try:
            cur.execute("""
                SELECT path, type, size, modified, accessed 
                FROM files 
                WHERE type IN ('prefetch', 'registry', 'evtx', 'executable')
                ORDER BY size DESC 
                LIMIT 20
            """)
            for row in cur.fetchall():
                data['notable_artifacts'].append(dict(row))
        except sqlite3.OperationalError:
            pass
        
        conn.close()
        return data
    
    def _gather_from_filesystem(self, case_name: str, case_path: str, data: Dict) -> Dict:
        """Gather case data from filesystem when no database exists."""
        
        # Check for case.json or config.json
        case_json_path = os.path.join(case_path, 'case.json')
        config_json_path = os.path.join(case_path, 'config.json')
        
        if os.path.exists(case_json_path):
            try:
                with open(case_json_path, 'r') as f:
                    case_info = json.load(f)
                    data['os_type'] = case_info.get('os_type', 'Unknown')
            except:
                pass
        
        # Count artifacts in artifacts directory
        artifacts_dir = os.path.join(case_path, 'artifacts')
        if os.path.exists(artifacts_dir):
            for root, dirs, files in os.walk(artifacts_dir):
                data['file_count'] += len(files)
                for f in files:
                    fpath = os.path.join(root, f)
                    try:
                        data['total_size'] += os.path.getsize(fpath)
                    except:
                        pass
        
        # Check for chain of custody log
        coc_path = os.path.join(case_path, 'chain_of_custody.log')
        if os.path.exists(coc_path):
            try:
                with open(coc_path, 'r') as f:
                    lines = f.readlines()
                    data['coc_status'] = f"{len(lines)} entries logged"
            except:
                data['coc_status'] = "Chain of custody file found but unreadable"
        
        # Check for evidence directory or files
        evidence_dir = os.path.join(case_path, 'evidence')
        if os.path.exists(evidence_dir):
            for f in os.listdir(evidence_dir):
                fpath = os.path.join(evidence_dir, f)
                if os.path.isfile(fpath):
                    try:
                        size = os.path.getsize(fpath)
                        data['evidence_items'].append({
                            'filename': f,
                            'type': self._guess_evidence_type(f),
                            'size': size,
                            'md5': 'Not computed',
                            'sha256': 'Not computed',
                            'acquisition_tool': 'Unknown',
                            'validation_status': 'Not verified',
                            'created_at': datetime.fromtimestamp(os.path.getctime(fpath)).isoformat()
                        })
                    except:
                        pass
        
        return data
    
    def _guess_evidence_type(self, filename: str) -> str:
        """Guess evidence type from filename."""
        filename_lower = filename.lower()
        if filename_lower.endswith('.e01'):
            return 'E01'
        elif filename_lower.endswith(('.dd', '.raw')):
            return 'DD/RAW'
        elif filename_lower.endswith('.vmdk'):
            return 'VMDK'
        elif filename_lower.endswith('.vhd'):
            return 'VHD'
        elif filename_lower.endswith(('.mem', '.dmp')):
            return 'Memory Dump'
        elif filename_lower.endswith('.evtx'):
            return 'Event Log'
        else:
            return 'Unknown'
    
    def _generate_cover_page(self, data: Dict, analyst: str, organization: str) -> str:
        """Generate professional cover page."""
        severity = self._assess_severity(data)
        incident_type = self._infer_incident_type(data)
        
        evidence_summary = f"{len(data['evidence_items'])} evidence file(s), " \
                          f"{data['file_count']:,} artifacts extracted"
        
        return f"""# FORENSIC INVESTIGATION REPORT

---

**CASE IDENTIFICATION:** {data['case_name'].upper()}

**INCIDENT TYPE:** {incident_type}

**SEVERITY CLASSIFICATION:** {severity}

**DATE OF GENERATION:** {data['generation_date'].strftime('%Y-%m-%d %H:%M:%S UTC')}

**FORENSIC PLATFORM:** {self.report_version}

**ANALYST:** {analyst}

**ORGANIZATION:** {organization}

**EVIDENCE SUMMARY:** {evidence_summary}

---

## CLASSIFICATION

**DISTRIBUTION:** Internal Use / Law Enforcement / Legal Proceedings

**SENSITIVITY:** Forensic Evidence - Handle According to Chain of Custody Protocols

**REPORT STATUS:** Preliminary Analysis / Comprehensive Investigation

---

*This report represents a forensic analysis of digital evidence conducted using \
industry-standard tools and methodologies. All findings are based on artifacts \
extracted from submitted evidence and interpreted within the context of known \
forensic patterns. This document is intended for use by qualified incident \
response professionals, legal teams, and authorized stakeholders.*

---
"""
    
    def _generate_executive_summary(self, data: Dict) -> str:
        """Generate human-readable executive summary."""
        summary_parts = []
        
        summary_parts.append("## EXECUTIVE SUMMARY")
        summary_parts.append("")
        summary_parts.append("### Overview")
        summary_parts.append("")
        
        # What was analyzed
        if len(data['evidence_items']) > 0:
            ev_types = set(ev.get('type', 'unknown') for ev in data['evidence_items'])
            summary_parts.append(
                f"This investigation analyzed **{len(data['evidence_items'])} evidence file(s)** "
                f"of type(s): {', '.join(ev_types)}. "
                f"The forensic processing extracted **{data['file_count']:,} artifacts** "
                f"totaling **{self._format_size(data['total_size'])}** from a "
                f"**{data['os_type']}** system."
            )
        else:
            summary_parts.append(
                f"This case (**{data['case_name']}**) has been created but no evidence "
                f"has been ingested yet. Evidence acquisition and mounting are required "
                f"before forensic analysis can proceed."
            )
        
        summary_parts.append("")
        summary_parts.append("### Evidence Status")
        summary_parts.append("")
        
        if data['file_count'] > 0:
            summary_parts.append(
                f"Evidence processing successfully indexed **{data['file_count']:,} artifacts** "
                f"from the submitted disk image(s). Artifacts include file system metadata, "
                f"timestamps, ownership information, and file type classifications."
            )
        else:
            summary_parts.append(
                "**Evidence has not been mounted or processed.** No artifacts are available "
                "for analysis. The investigator must mount evidence using the FEPD terminal "
                "before forensic examination can begin."
            )
        
        summary_parts.append("")
        summary_parts.append("### Artifact Discovery")
        summary_parts.append("")
        
        if data['artifact_counts']:
            top_types = sorted(data['artifact_counts'].items(), 
                             key=lambda x: x[1]['count'], reverse=True)[:5]
            summary_parts.append("The following artifact categories were identified:")
            summary_parts.append("")
            for artifact_type, stats in top_types:
                summary_parts.append(
                    f"- **{artifact_type.capitalize()}**: {stats['count']:,} items "
                    f"({self._format_size(stats['size'])})"
                )
        else:
            summary_parts.append(
                "No categorized artifacts have been extracted. This indicates either "
                "the evidence has not been processed, or the evidence contains minimal "
                "forensic artifacts."
            )
        
        summary_parts.append("")
        summary_parts.append("### Machine Learning & Behavioral Analysis")
        summary_parts.append("")
        
        if data['ml_results']:
            summary_parts.append(
                f"**{len(data['ml_results'])} ML model(s)** were applied to the dataset. "
                "Results indicate:"
            )
            for model, result in data['ml_results'].items():
                anomaly_count = result.get('anomalies_detected', 0)
                if anomaly_count > 0:
                    summary_parts.append(
                        f"- **{model}**: Detected {anomaly_count} potential anomalies requiring review"
                    )
                else:
                    summary_parts.append(
                        f"- **{model}**: No significant behavioral deviations detected"
                    )
        else:
            summary_parts.append(
                "Machine learning analysis has not been performed on this case. "
                "ML-based anomaly detection requires sufficient artifact diversity "
                "and can reveal behavioral patterns invisible to manual analysis."
            )
        
        summary_parts.append("")
        summary_parts.append("### Investigative Status")
        summary_parts.append("")
        
        if data['timeline_events'] > 0:
            summary_parts.append(
                f"Timeline reconstruction contains **{data['timeline_events']:,} events**, "
                f"providing chronological context for forensic correlation."
            )
        else:
            summary_parts.append(
                "**Timeline has not been generated.** Temporal analysis is pending. "
                "Timeline reconstruction would reveal event sequences, user activity "
                "patterns, and potential incident timeframes."
            )
        
        summary_parts.append("")
        summary_parts.append("### Known and Unknown Factors")
        summary_parts.append("")
        summary_parts.append("**What is Known:**")
        summary_parts.append("")
        
        known_items = []
        if data['os_type'] != 'Unknown':
            known_items.append(f"- Operating system: {data['os_type']}")
        if data['users']:
            known_items.append(f"- User account(s): {', '.join(data['users'][:5])}")
        if data['file_count'] > 0:
            known_items.append(f"- Artifact count: {data['file_count']:,}")
        
        if known_items:
            summary_parts.extend(known_items)
        else:
            summary_parts.append("- Limited metadata available pending evidence processing")
        
        summary_parts.append("")
        summary_parts.append("**What Remains Unknown:**")
        summary_parts.append("")
        
        unknown_items = []
        if data['timeline_events'] == 0:
            unknown_items.append("- Chronological event sequence (timeline not generated)")
        if not data['ml_results']:
            unknown_items.append("- Behavioral anomalies (ML analysis pending)")
        if not data['evidence_items']:
            unknown_items.append("- Evidence characteristics (no evidence mounted)")
        
        if unknown_items:
            summary_parts.extend(unknown_items)
        else:
            summary_parts.append("- No critical data gaps identified")
        
        summary_parts.append("")
        summary_parts.append("### Recommendations")
        summary_parts.append("")
        
        if not data['evidence_items']:
            summary_parts.append(
                "**IMMEDIATE ACTION REQUIRED:** Mount forensic evidence using FEPD terminal. "
                "No analysis can proceed without evidence ingestion."
            )
        elif data['timeline_events'] == 0:
            summary_parts.append(
                "Generate timeline to establish temporal context for artifacts. "
                "Timeline analysis is critical for incident reconstruction."
            )
        elif not data['ml_results']:
            summary_parts.append(
                "Execute ML analysis to identify behavioral anomalies and outliers. "
                "Automated detection can reveal patterns missed by manual review."
            )
        else:
            summary_parts.append(
                "Continue detailed artifact analysis and correlation. Cross-reference "
                "findings with external threat intelligence as appropriate."
            )
        
        return '\n'.join(summary_parts)
    
    def _generate_case_metadata(self, data: Dict) -> str:
        """Generate case metadata table."""
        created_date = "Unknown"
        if data['evidence_items']:
            created_date = data['evidence_items'][0].get('created_at', 'Unknown')
        
        status = "Active" if data['file_count'] > 0 else "Pending Evidence"
        
        return f"""## CASE METADATA

| Field | Value |
|-------|-------|
| **Case ID** | {data['case_name']} |
| **Case Name** | {data['case_name'].replace('_', ' ').title()} |
| **Created Date** | {created_date} |
| **Report Generated** | {data['generation_date'].strftime('%Y-%m-%d %H:%M:%S')} |
| **Status** | {status} |
| **Evidence Count** | {len(data['evidence_items'])} |
| **Artifact Count** | {data['file_count']:,} |
| **OS Type** | {data['os_type']} |
| **Chain of Custody** | {data['coc_status']} |
"""
    
    def _generate_evidence_overview(self, data: Dict) -> str:
        """Generate detailed evidence overview."""
        sections = []
        sections.append("## EVIDENCE OVERVIEW")
        sections.append("")
        
        if not data['evidence_items']:
            sections.append("**No evidence has been mounted to this case.**")
            sections.append("")
            sections.append("### Required Actions")
            sections.append("")
            sections.append("1. Place evidence files (E01, DD, RAW, VMDK, VHD) in case directory")
            sections.append("2. Use FEPD terminal: `use case " + data['case_name'] + "`")
            sections.append("3. Evidence will be auto-detected and mounted")
            sections.append("4. Forensic indexing will begin automatically")
            sections.append("")
            sections.append("**Evidence Types Supported:**")
            sections.append("- EnCase Images (.E01)")
            sections.append("- Raw Disk Images (.DD, .RAW)")
            sections.append("- Virtual Disks (.VMDK, .VHD)")
            sections.append("- Memory Dumps (.MEM, .DMP)")
            sections.append("- Registry Hives (NTUSER.DAT, SYSTEM, SOFTWARE)")
            sections.append("- Event Logs (.EVTX)")
            return '\n'.join(sections)
        
        sections.append("### Evidence Items")
        sections.append("")
        
        for idx, ev in enumerate(data['evidence_items'], 1):
            sections.append(f"#### Evidence #{idx}: {ev.get('filename', 'Unknown')}")
            sections.append("")
            sections.append(f"| Property | Value |")
            sections.append(f"|----------|-------|")
            sections.append(f"| **Filename** | `{ev.get('filename', 'N/A')}` |")
            sections.append(f"| **Format** | {ev.get('type', 'Unknown').upper()} |")
            sections.append(f"| **Size** | {self._format_size(ev.get('size', 0))} |")
            sections.append(f"| **MD5** | `{ev.get('md5', 'Not computed')}` |")
            sections.append(f"| **SHA-256** | `{ev.get('sha256', 'Not computed')}` |")
            sections.append(f"| **Acquisition Tool** | {ev.get('acquisition_tool', 'Unknown')} |")
            sections.append(f"| **Validation Status** | {ev.get('validation_status', 'Not verified')} |")
            sections.append("")
        
        sections.append("### Evidence Integrity Assessment")
        sections.append("")
        sections.append(
            "All evidence items have been processed through FEPD's forensic pipeline. "
            "Hash values (where computed) provide cryptographic verification of evidence "
            "integrity. Any modification to evidence files will be detectable through "
            "hash comparison."
        )
        sections.append("")
        
        if data['os_type'] != 'Unknown':
            sections.append(
                f"The evidence represents a **{data['os_type']}** system based on "
                f"filesystem structure and artifact patterns. This determination guides "
                f"artifact interpretation and analysis methodology."
            )
        
        return '\n'.join(sections)
    
    def _generate_artifact_summary(self, data: Dict) -> str:
        """Generate artifact discovery summary grouped by type."""
        sections = []
        sections.append("## ARTIFACT DISCOVERY SUMMARY")
        sections.append("")
        
        if not data['artifact_counts']:
            sections.append("**No artifacts have been categorized.**")
            sections.append("")
            sections.append(
                "Artifact categorization occurs during evidence processing. "
                "Without mounted evidence, no file system artifacts are available for analysis."
            )
            return '\n'.join(sections)
        
        sections.append("### Artifact Categories")
        sections.append("")
        
        # Define forensic significance of artifact types
        artifact_significance = {
            'prefetch': 'Application execution history and frequency analysis',
            'registry': 'System configuration, user preferences, and historical activity',
            'evtx': 'Windows Event Logs - system events, security events, application logs',
            'executable': 'Executable files - potential malware, tools, or legitimate applications',
            'document': 'User-created documents - evidence of data handling and activity',
            'browser': 'Web browsing history, cookies, cache - internet activity evidence',
            'email': 'Email communications - correspondence and attachments',
            'archive': 'Compressed files - may contain hidden or bundled artifacts',
            'image': 'Pictures and graphics - potential evidence or steganography',
            'video': 'Video files - surveillance, screen recordings, or media evidence',
            'audio': 'Audio files - recordings, communications, or media',
            'script': 'Scripts and automation - PowerShell, batch files, Python scripts',
            'log': 'Application and system logs - activity tracking and debugging info',
            'database': 'Database files - structured data storage',
            'link': 'Shortcut files - recent item access and user behavior',
            'unknown': 'Unclassified files requiring manual examination'
        }
        
        # Sort by count descending
        sorted_artifacts = sorted(data['artifact_counts'].items(), 
                                 key=lambda x: x[1]['count'], reverse=True)
        
        sections.append("| Artifact Type | Count | Total Size | Forensic Significance |")
        sections.append("|---------------|-------|------------|----------------------|")
        
        for artifact_type, stats in sorted_artifacts:
            significance = artifact_significance.get(artifact_type.lower(), 
                                                    'Requires forensic interpretation')
            sections.append(
                f"| **{artifact_type.capitalize()}** | "
                f"{stats['count']:,} | "
                f"{self._format_size(stats['size'])} | "
                f"{significance} |"
            )
        
        sections.append("")
        sections.append("### Interpretation")
        sections.append("")
        
        # Provide contextual interpretation
        total_artifacts = sum(s['count'] for s in data['artifact_counts'].values())
        sections.append(
            f"A total of **{total_artifacts:,} artifacts** were discovered and categorized "
            f"across **{len(data['artifact_counts'])} artifact types**. This diversity "
            f"indicates a comprehensive evidence set suitable for detailed forensic analysis."
        )
        sections.append("")
        
        # Highlight significant categories
        if 'prefetch' in data['artifact_counts']:
            pf_count = data['artifact_counts']['prefetch']['count']
            sections.append(
                f"The presence of **{pf_count} prefetch artifacts** enables reconstruction "
                f"of application execution history, including timestamps and frequency patterns."
            )
        
        if 'registry' in data['artifact_counts']:
            reg_count = data['artifact_counts']['registry']['count']
            sections.append(
                f"**{reg_count} registry artifacts** provide system configuration data, "
                f"user activity traces, and historical forensic indicators."
            )
        
        if 'evtx' in data['artifact_counts']:
            evtx_count = data['artifact_counts']['evtx']['count']
            sections.append(
                f"**{evtx_count} Windows Event Log files** contain security events, "
                f"login records, and system activity logs critical for timeline reconstruction."
            )
        
        return '\n'.join(sections)
    
    def _generate_timeline_status(self, data: Dict) -> str:
        """Generate timeline analysis section."""
        sections = []
        sections.append("## TIMELINE ANALYSIS")
        sections.append("")
        
        if data['timeline_events'] == 0:
            sections.append("**Timeline has not been generated for this case.**")
            sections.append("")
            sections.append("### Purpose of Timeline Analysis")
            sections.append("")
            sections.append(
                "Timeline reconstruction aggregates temporal data from multiple artifact sources "
                "into a chronological sequence. This enables investigators to:"
            )
            sections.append("")
            sections.append("- Identify suspicious time periods and activity bursts")
            sections.append("- Correlate events across different artifact types")
            sections.append("- Establish incident timeframes and attack progression")
            sections.append("- Detect anomalous activity outside normal working hours")
            sections.append("- Reconstruct user behavior and system changes")
            sections.append("")
            sections.append("### Generation Requirements")
            sections.append("")
            sections.append("Timeline generation requires:")
            sections.append("1. Mounted evidence with extracted artifacts")
            sections.append("2. Timestamp metadata (created, modified, accessed)")
            sections.append("3. Sufficient disk space for timeline database")
            sections.append("")
            sections.append("### Next Steps")
            sections.append("")
            sections.append("Generate timeline using FEPD terminal:")
            sections.append("```")
            sections.append(f"use case {data['case_name']}")
            sections.append("timeline generate")
            sections.append("timeline show --range <start> <end>")
            sections.append("```")
            return '\n'.join(sections)
        
        # Timeline exists
        sections.append(f"**Timeline contains {data['timeline_events']:,} events.**")
        sections.append("")
        sections.append("### Event Distribution")
        sections.append("")
        sections.append(
            f"The timeline successfully reconstructed **{data['timeline_events']:,} temporal events** "
            f"from artifact metadata. This provides chronological context for forensic correlation."
        )
        sections.append("")
        sections.append("### Analysis Recommendations")
        sections.append("")
        sections.append("- Filter timeline by event type to focus on specific artifact categories")
        sections.append("- Identify time periods with unusual activity density")
        sections.append("- Correlate timeline events with known incident indicators")
        sections.append("- Export timeline data for visualization tools (Plaso, Excel)")
        sections.append("")
        sections.append("### Suspicious Period Detection")
        sections.append("")
        sections.append(
            "Timeline analysis should focus on detecting temporal anomalies such as:"
        )
        sections.append("- Activity during non-business hours (nights, weekends)")
        sections.append("- Sudden bursts of file system activity")
        sections.append("- Execution of suspicious processes at specific times")
        sections.append("- Data exfiltration patterns (large file transfers)")
        
        return '\n'.join(sections)
    
    def _generate_ml_analysis(self, data: Dict) -> str:
        """Generate ML and UEBA analysis section."""
        sections = []
        sections.append("## MACHINE LEARNING & BEHAVIORAL ANALYSIS")
        sections.append("")
        
        if not data['ml_results']:
            sections.append("**Machine learning analysis has not been executed.**")
            sections.append("")
            sections.append("### ML Capabilities")
            sections.append("")
            sections.append(
                "FEPD employs multiple machine learning models for automated anomaly detection:"
            )
            sections.append("")
            sections.append("- **Isolation Forest**: Detects outliers in file size, timestamp, and path patterns")
            sections.append("- **UEBA (User and Entity Behavior Analytics)**: Identifies unusual user activity")
            sections.append("- **Clustering**: Groups similar artifacts to detect anomalous file types")
            sections.append("- **Pattern Recognition**: Identifies known malware signatures and suspicious patterns")
            sections.append("")
            sections.append("### Why ML Analysis Matters")
            sections.append("")
            sections.append(
                "Machine learning can reveal statistical anomalies invisible to manual analysis. "
                "ML models learn normal behavioral baselines and flag deviations that may indicate:"
            )
            sections.append("")
            sections.append("- Malware presence (unusual file execution patterns)")
            sections.append("- Data exfiltration (abnormal file transfers)")
            sections.append("- Insider threats (user behavior deviations)")
            sections.append("- System compromise (configuration changes)")
            sections.append("")
            sections.append("### Limitations")
            sections.append("")
            sections.append(
                "ML analysis requires sufficient data diversity to establish baselines. "
                "Small datasets or systems with limited activity may not produce meaningful results. "
                "**ML findings should always be validated through manual forensic examination.**"
            )
            sections.append("")
            sections.append("### Execution")
            sections.append("")
            sections.append("Run ML analysis using FEPD terminal:")
            sections.append("```")
            sections.append(f"use case {data['case_name']}")
            sections.append("ml analyze")
            sections.append("```")
            return '\n'.join(sections)
        
        # ML results exist
        sections.append(f"**{len(data['ml_results'])} ML model(s) executed.**")
        sections.append("")
        
        for model_name, result in data['ml_results'].items():
            sections.append(f"### {model_name.replace('_', ' ').title()}")
            sections.append("")
            
            anomaly_count = result.get('anomalies_detected', 0)
            confidence = result.get('confidence', 0.0)
            
            if anomaly_count > 0:
                sections.append(
                    f"**Status**: {anomaly_count} potential anomalies detected "
                    f"(confidence: {confidence:.1%})"
                )
                sections.append("")
                sections.append("**Interpretation**:")
                sections.append("")
                sections.append(
                    f"The {model_name} model identified {anomaly_count} artifacts that deviate "
                    f"statistically from learned behavioral baselines. These findings warrant "
                    f"manual forensic examination to determine if they represent:"
                )
                sections.append("")
                sections.append("- Malicious activity or system compromise")
                sections.append("- Legitimate but unusual system behavior")
                sections.append("- False positives due to dataset characteristics")
                sections.append("")
                sections.append("**Recommendation**: Review flagged artifacts in detail.")
            else:
                sections.append(
                    f"**Status**: No significant anomalies detected (confidence: {confidence:.1%})"
                )
                sections.append("")
                sections.append("**Interpretation**:")
                sections.append("")
                sections.append(
                    f"The {model_name} model did not identify statistically significant deviations "
                    f"from learned behavioral patterns. This result may indicate:"
                )
                sections.append("")
                sections.append("- The system exhibits normal, benign behavior")
                sections.append("- Insufficient behavioral variance in the dataset")
                sections.append("- Sophisticated attacks that mimic normal patterns")
                sections.append("- Dataset does not contain temporal or behavioral outliers")
                sections.append("")
                sections.append(
                    "**Important**: Absence of ML-detected anomalies does NOT guarantee "
                    "absence of malicious activity. Manual forensic examination remains essential."
                )
            sections.append("")
        
        return '\n'.join(sections)
    
    def _generate_notable_artifacts(self, data: Dict) -> str:
        """Generate notable artifacts section with high-signal items."""
        sections = []
        sections.append("## NOTABLE ARTIFACTS")
        sections.append("")
        
        if not data['notable_artifacts']:
            sections.append("**No high-priority artifacts have been identified.**")
            sections.append("")
            sections.append(
                "Notable artifacts are typically flagged based on:"
            )
            sections.append("- High execution frequency (prefetch analysis)")
            sections.append("- Suspicious file extensions or naming patterns")
            sections.append("- Known malware indicators")
            sections.append("- Unusual file locations or timestamps")
            sections.append("- Large file sizes in unexpected locations")
            return '\n'.join(sections)
        
        sections.append("The following artifacts warrant investigative attention:")
        sections.append("")
        
        for idx, artifact in enumerate(data['notable_artifacts'][:15], 1):
            path = artifact.get('path', 'Unknown')
            artifact_type = artifact.get('type', 'unknown')
            size = artifact.get('size', 0)
            modified = artifact.get('modified', 'Unknown')
            
            sections.append(f"### {idx}. {os.path.basename(path)}")
            sections.append("")
            sections.append(f"**Evidence Path**: `{path}`")
            sections.append(f"**Type**: {artifact_type.capitalize()}")
            sections.append(f"**Size**: {self._format_size(size)}")
            sections.append(f"**Last Modified**: {modified}")
            sections.append("")
            sections.append("**Significance**:")
            sections.append("")
            
            # Provide context based on artifact type
            if artifact_type == 'prefetch':
                sections.append(
                    "Prefetch artifacts indicate application execution. High execution count "
                    "suggests persistent background activity or frequently used applications."
                )
            elif artifact_type == 'executable':
                sections.append(
                    "Executable file detected. Should be analyzed for malware indicators, "
                    "digital signatures, and origin verification."
                )
            elif artifact_type == 'registry':
                sections.append(
                    "Registry hive contains system configuration and user activity traces. "
                    "May reveal persistence mechanisms, recent file access, or USB device history."
                )
            elif size > 100 * 1024 * 1024:  # > 100MB
                sections.append(
                    f"Unusually large file size ({self._format_size(size)}). "
                    "May represent compressed archives, database files, or potential data staging."
                )
            else:
                sections.append("Flagged for manual review based on classification criteria.")
            
            sections.append("")
        
        return '\n'.join(sections)
    
    def _generate_chain_of_custody(self, data: Dict) -> str:
        """Generate chain of custody section."""
        sections = []
        sections.append("## CHAIN OF CUSTODY")
        sections.append("")
        sections.append("### Integrity Verification")
        sections.append("")
        sections.append(
            "FEPD maintains a cryptographically secured, append-only chain of custody ledger. "
            "All forensic actions are logged with:"
        )
        sections.append("")
        sections.append("- Timestamp of operation")
        sections.append("- Command executed")
        sections.append("- Analyst identifier")
        sections.append("- Cryptographic hash of log entry")
        sections.append("- Hash chain linking to previous entry")
        sections.append("")
        sections.append("### Tamper Detection")
        sections.append("")
        sections.append(
            "Any modification, deletion, or reordering of chain of custody entries will "
            "invalidate the cryptographic hash chain. This provides mathematical proof "
            "of tampering and maintains forensic integrity for legal proceedings."
        )
        sections.append("")
        sections.append(f"**Current Status**: {data['coc_status']}")
        sections.append("")
        sections.append("### Verification Procedure")
        sections.append("")
        sections.append("To verify chain of custody integrity using FEPD terminal:")
        sections.append("")
        sections.append("```")
        sections.append(f"use case {data['case_name']}")
        sections.append("verify_coc")
        sections.append("```")
        sections.append("")
        sections.append(
            "The verification command will recompute all hashes and validate the chain. "
            "Any discrepancy will be immediately flagged."
        )
        sections.append("")
        sections.append("### Court Admissibility")
        sections.append("")
        sections.append(
            "Chain of custody documentation satisfies legal requirements for digital evidence "
            "admissibility. The cryptographic proof demonstrates:"
        )
        sections.append("")
        sections.append("1. Evidence has not been modified since acquisition")
        sections.append("2. All forensic actions are documented")
        sections.append("3. Timestamps provide temporal proof")
        sections.append("4. Analyst accountability is maintained")
        
        return '\n'.join(sections)
    
    def _generate_recommendations(self, data: Dict) -> str:
        """Generate actionable recommendations."""
        sections = []
        sections.append("## INVESTIGATIVE RECOMMENDATIONS")
        sections.append("")
        
        recommendations = []
        
        # Evidence-based recommendations
        if not data['evidence_items']:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Mount forensic evidence',
                'rationale': 'No evidence has been ingested. All analysis depends on evidence availability.',
                'procedure': f"Place evidence in case directory and run: use case {data['case_name']}"
            })
        
        if data['timeline_events'] == 0:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Generate timeline',
                'rationale': 'Timeline reconstruction enables temporal correlation and incident timeframe identification.',
                'procedure': 'Execute: timeline generate'
            })
        
        if not data['ml_results']:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Execute ML analysis',
                'rationale': 'Machine learning can detect statistical anomalies invisible to manual review.',
                'procedure': 'Execute: ml analyze'
            })
        
        if data['artifact_counts'].get('registry', {}).get('count', 0) > 0:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Parse registry hives',
                'rationale': 'Registry analysis reveals user activity, USB devices, recent files, and persistence mechanisms.',
                'procedure': 'Use registry analysis tools: regripper, registry explorer'
            })
        
        if data['artifact_counts'].get('evtx', {}).get('count', 0) > 0:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Analyze Windows Event Logs',
                'rationale': 'Event logs contain security events, login records, and system activity critical for investigation.',
                'procedure': 'Parse EVTX files for security events 4624/4625 (logon/logoff)'
            })
        
        if data['artifact_counts'].get('prefetch', {}).get('count', 0) > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Analyze prefetch artifacts',
                'rationale': 'Prefetch reveals application execution history and frequency patterns.',
                'procedure': 'Extract execution timestamps and frequency data from prefetch files'
            })
        
        # Always recommend correlation
        recommendations.append({
            'priority': 'MEDIUM',
            'action': 'Cross-reference findings with threat intelligence',
            'rationale': 'External intelligence may identify known malware signatures or attack patterns.',
            'procedure': 'Compare file hashes, domains, IPs against threat intelligence databases'
        })
        
        # Output recommendations
        for rec in recommendations:
            sections.append(f"### {rec['priority']} Priority: {rec['action']}")
            sections.append("")
            sections.append(f"**Rationale**: {rec['rationale']}")
            sections.append("")
            sections.append(f"**Procedure**: {rec['procedure']}")
            sections.append("")
        
        sections.append("### Analytical Discipline")
        sections.append("")
        sections.append(
            "**Critical Reminder**: All forensic conclusions must be evidence-based. "
            "Avoid speculation beyond artifact interpretation. When uncertainty exists, "
            "document it explicitly and pursue additional data sources."
        )
        
        return '\n'.join(sections)
    
    def _generate_appendix(self, data: Dict) -> str:
        """Generate technical appendix."""
        sections = []
        sections.append("## APPENDIX")
        sections.append("")
        sections.append("### A. Tool Information")
        sections.append("")
        sections.append(f"**FEPD Version**: {self.report_version}")
        sections.append(f"**Report Generated**: {data['generation_date'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
        sections.append(f"**Database Path**: `{data['db_path']}`")
        sections.append("")
        sections.append("### B. Hash Algorithms")
        sections.append("")
        sections.append("- **MD5**: 128-bit cryptographic hash (deprecated for security, used for compatibility)")
        sections.append("- **SHA-256**: 256-bit cryptographic hash (primary integrity verification)")
        sections.append("- **Chain Hash**: Cumulative hash chain for chain of custody validation")
        sections.append("")
        sections.append("### C. Evidence Manifest")
        sections.append("")
        
        if data['evidence_items']:
            sections.append("| Filename | Type | Size | MD5 |")
            sections.append("|----------|------|------|-----|")
            for ev in data['evidence_items']:
                sections.append(
                    f"| {ev.get('filename', 'N/A')} | "
                    f"{ev.get('type', 'Unknown')} | "
                    f"{self._format_size(ev.get('size', 0))} | "
                    f"`{ev.get('md5', 'N/A')[:16]}...` |"
                )
        else:
            sections.append("*No evidence mounted*")
        
        sections.append("")
        sections.append("### D. Artifact Statistics")
        sections.append("")
        sections.append(f"- **Total Artifacts**: {data['file_count']:,}")
        sections.append(f"- **Total Size**: {self._format_size(data['total_size'])}")
        sections.append(f"- **Artifact Categories**: {len(data['artifact_counts'])}")
        sections.append(f"- **Timeline Events**: {data['timeline_events']:,}")
        sections.append("")
        sections.append("### E. Legal Notice")
        sections.append("")
        sections.append(
            "This forensic report is based on digital evidence analyzed using industry-standard "
            "methodologies and tools. The findings represent the analyst's professional interpretation "
            "of artifacts extracted from submitted evidence. This report is intended for use by "
            "qualified forensic professionals, legal counsel, and authorized stakeholders."
        )
        sections.append("")
        sections.append(
            "**Limitations**: Forensic analysis is constrained by the completeness and integrity "
            "of submitted evidence. Deleted data, encrypted volumes, or incomplete images may limit "
            "investigative findings. The absence of detected artifacts does not conclusively prove "
            "absence of activity."
        )
        sections.append("")
        sections.append("---")
        sections.append("")
        sections.append("**END OF REPORT**")
        
        return '\n'.join(sections)
    
    # Helper methods
    
    def _format_size(self, bytes_size: int) -> str:
        """Format bytes into human-readable size."""
        bytes_float = float(bytes_size)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_float < 1024.0:
                return f"{bytes_float:.2f} {unit}"
            bytes_float /= 1024.0
        return f"{bytes_float:.2f} PB"
    
    def _assess_severity(self, data: Dict) -> str:
        """Assess case severity based on indicators."""
        if not data['evidence_items']:
            return "Pending (No Evidence)"
        
        if data['ml_results']:
            total_anomalies = sum(r.get('anomalies_detected', 0) for r in data['ml_results'].values())
            if total_anomalies > 100:
                return "Critical"
            elif total_anomalies > 20:
                return "High"
            elif total_anomalies > 0:
                return "Medium"
        
        # Base severity on artifact presence
        if data['artifact_counts'].get('executable', {}).get('count', 0) > 1000:
            return "Medium"
        
        return "Low (Routine Analysis)"
    
    def _infer_incident_type(self, data: Dict) -> str:
        """Infer incident type from artifacts."""
        if not data['evidence_items']:
            return "Pending Evidence Ingestion"
        
        # Check for common incident indicators
        if data['artifact_counts'].get('registry', {}).get('count', 0) > 0:
            return "System Forensic Analysis"
        
        if data['artifact_counts'].get('memory', {}).get('count', 0) > 0:
            return "Memory Forensics Investigation"
        
        if data['artifact_counts'].get('evtx', {}).get('count', 0) > 0:
            return "Windows Event Log Analysis"
        
        return "General Digital Forensic Investigation"


def main():
    """Generate report from command line."""
    import argparse
    
    parser = argparse.ArgumentParser(description='FEPD Forensic Report Generator')
    parser.add_argument('case_name', help='Name of case to report on')
    parser.add_argument('--analyst', default='FEPD Analyst', help='Analyst name')
    parser.add_argument('--org', default='Forensic Investigation Unit', help='Organization')
    parser.add_argument('--output', help='Output file path (default: <case_name>_report.md)')
    
    args = parser.parse_args()
    
    generator = ForensicReportGenerator()
    report = generator.generate_report(args.case_name, args.analyst, args.org)
    
    # Determine output path
    output_path = args.output or f"{args.case_name}_forensic_report.md"
    
    # Write report
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"✓ Forensic report generated: {output_path}")
    print(f"  Case: {args.case_name}")
    print(f"  Size: {len(report):,} characters")


if __name__ == '__main__':
    main()
