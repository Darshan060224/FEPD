"""
FEPD - Forensic Evidence Parser Dashboard
Report Generator Module

Generates professional PDF forensic analysis reports with embedded evidence metadata.

Implements FR-21, FR-22, FR-35: PDF report generation with SHA-256 hashing

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import pandas as pd

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image as RLImage, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from ..utils.hash_utils import ForensicHasher
from ..utils.chain_of_custody import ChainOfCustody


class ReportGenerator:
    """
    Forensic Analysis Report Generator.
    
    Generates professional PDF reports with:
    - Case summary and metadata
    - Evidence hash table
    - Classification severity matrix
    - Timeline summary (filtered by severity)
    - Chain of Custody log
    - Embedded SHA-256 hashes for audit trail
    """
    
    def __init__(
        self,
        case_id: str,
        analyst_name: str,
        organization: str = "FEPD Forensic Analysis",
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize Report Generator.
        
        Args:
            case_id: Unique case identifier
            analyst_name: Name of forensic analyst
            organization: Organization name for report header
            logger: Optional logger instance
        """
        self.case_id = case_id
        self.analyst_name = analyst_name
        self.organization = organization
        self.logger = logger or logging.getLogger(__name__)
        
        # Report metadata
        self.generation_timestamp = datetime.now(timezone.utc).isoformat()
        self.report_hash: Optional[str] = None
        
        # Styles
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
    
    def _create_custom_styles(self) -> None:
        """Create custom paragraph styles for report."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1A1A2E'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#3C7DD9'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Subsection header
        self.styles.add(ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#555555'),
            spaceAfter=6,
            spaceBefore=6,
            fontName='Helvetica-Bold'
        ))
        
        # Metadata style
        self.styles.add(ParagraphStyle(
            name='Metadata',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            spaceAfter=3
        ))
    
    def generate_report(
        self,
        output_path: Path,
        image_hash: str,
        classified_events: pd.DataFrame,
        artifact_hashes: Dict[str, str],
        coc_log_path: Path,
        case_notes: str = "",
        include_full_timeline: bool = False,
        min_severity: int = 3
    ) -> Path:
        """
        Generate complete forensic analysis PDF report.
        
        Args:
            output_path: Path to output PDF file
            image_hash: SHA-256 hash of forensic image
            classified_events: DataFrame with classified timeline events
            artifact_hashes: Dictionary of artifact paths and their SHA-256 hashes
            coc_log_path: Path to Chain of Custody log file
            case_notes: Optional case notes from analyst
            include_full_timeline: Include complete timeline (default: False)
            min_severity: Minimum severity for timeline summary (default: 3)
            
        Returns:
            Path to generated PDF report
        """
        self.logger.info(f"Generating forensic report: {output_path}")
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create PDF document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.75*inch
        )
        
        # Build report content
        story = []
        
        # Page 1: Title and Case Summary
        story.extend(self._create_title_page(image_hash))
        story.append(PageBreak())
        
        # Page 2: Evidence Hash Table
        story.extend(self._create_hash_table(image_hash, artifact_hashes))
        story.append(PageBreak())
        
        # Page 3: Classification Summary
        story.extend(self._create_classification_summary(classified_events))
        story.append(PageBreak())
        
        # Page 4+: Timeline Summary
        story.extend(self._create_timeline_summary(
            classified_events,
            include_full_timeline,
            min_severity
        ))
        story.append(PageBreak())
        
        # Page N: Case Notes (if provided)
        if case_notes:
            story.extend(self._create_case_notes(case_notes))
            story.append(PageBreak())
        
        # Page N+1: Chain of Custody
        story.extend(self._create_coc_section(coc_log_path))
        
        # Build PDF
        doc.build(story)
        
        # Compute SHA-256 of generated report
        hasher = ForensicHasher()
        self.report_hash = hasher.hash_file(output_path)
        
        self.logger.info(f"Report generated: {output_path}")
        self.logger.info(f"Report SHA-256: {self.report_hash}")
        
        return output_path
    
    def _create_title_page(self, image_hash: str) -> List:
        """Create title page with case summary."""
        elements = []
        
        # Title
        title = Paragraph(
            f"<b>FORENSIC ANALYSIS REPORT</b>",
            self.styles['CustomTitle']
        )
        elements.append(title)
        elements.append(Spacer(1, 0.3*inch))
        
        # Organization
        org = Paragraph(
            f"<b>{self.organization}</b>",
            self.styles['Heading2']
        )
        elements.append(org)
        elements.append(Spacer(1, 0.5*inch))
        
        # Case metadata table
        case_data = [
            ['<b>Case ID:</b>', self.case_id],
            ['<b>Analyst:</b>', self.analyst_name],
            ['<b>Analysis Date:</b>', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['<b>Report Generated:</b>', self.generation_timestamp],
            ['<b>Image SHA-256:</b>', image_hash[:32] + '...'],
        ]
        
        case_table = Table(case_data, colWidths=[2*inch, 4.5*inch])
        case_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#333333')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(case_table)
        elements.append(Spacer(1, 0.5*inch))
        
        # Disclaimer
        disclaimer = Paragraph(
            "<b>CONFIDENTIAL - FORENSIC EVIDENCE</b><br/>"
            "This report contains forensic analysis results and evidence metadata. "
            "All artifacts were processed using read-only access and SHA-256 hashing "
            "to maintain chain of custody integrity. This report is intended for "
            "authorized personnel only.",
            self.styles['Normal']
        )
        elements.append(disclaimer)
        
        return elements
    
    def _create_hash_table(
        self,
        image_hash: str,
        artifact_hashes: Dict[str, str]
    ) -> List:
        """Create evidence hash table."""
        elements = []
        
        # Section header
        header = Paragraph(
            "<b>Evidence Hash Table</b>",
            self.styles['SectionHeader']
        )
        elements.append(header)
        elements.append(Spacer(1, 0.2*inch))
        
        # Description
        desc = Paragraph(
            "SHA-256 cryptographic hashes of all evidence items processed during analysis. "
            "These hashes provide tamper-evident verification of evidence integrity.",
            self.styles['Normal']
        )
        elements.append(desc)
        elements.append(Spacer(1, 0.2*inch))
        
        # Image hash
        image_data = [
            ['<b>Evidence Type</b>', '<b>SHA-256 Hash</b>'],
            ['Forensic Image', image_hash],
        ]
        
        # Artifact hashes (limit to first 20 for page space)
        artifact_count = len(artifact_hashes)
        for idx, (artifact_path, hash_value) in enumerate(list(artifact_hashes.items())[:20]):
            # Truncate long paths
            display_path = artifact_path if len(artifact_path) < 40 else '...' + artifact_path[-37:]
            image_data.append([display_path, hash_value])
        
        if artifact_count > 20:
            image_data.append([
                f'<i>...and {artifact_count - 20} more artifacts</i>',
                '<i>See CoC log for complete list</i>'
            ])
        
        hash_table = Table(image_data, colWidths=[2.5*inch, 4*inch])
        hash_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3C7DD9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F5F5')]),
        ]))
        
        elements.append(hash_table)
        
        return elements
    
    def _create_classification_summary(
        self,
        classified_events: pd.DataFrame
    ) -> List:
        """Create classification severity matrix."""
        elements = []
        
        # Section header
        header = Paragraph(
            "<b>Event Classification Summary</b>",
            self.styles['SectionHeader']
        )
        elements.append(header)
        elements.append(Spacer(1, 0.2*inch))
        
        # Description
        desc = Paragraph(
            f"Forensic analysis identified <b>{len(classified_events)}</b> total events "
            "across all artifacts. Events were classified using deterministic forensic rules.",
            self.styles['Normal']
        )
        elements.append(desc)
        elements.append(Spacer(1, 0.2*inch))
        
        # Classification counts
        class_counts = classified_events['rule_class'].value_counts()
        
        class_data = [
            ['<b>Classification</b>', '<b>Event Count</b>', '<b>Percentage</b>']
        ]
        
        for classification, count in class_counts.items():
            percentage = (count / len(classified_events)) * 100
            class_data.append([
                classification.replace('_', ' '),
                str(count),
                f"{percentage:.1f}%"
            ])
        
        class_table = Table(class_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
        class_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3C7DD9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F5F5')]),
        ]))
        
        elements.append(class_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Severity distribution
        severity_header = Paragraph(
            "<b>Severity Distribution</b>",
            self.styles['SubsectionHeader']
        )
        elements.append(severity_header)
        
        severity_counts = classified_events['severity'].value_counts().sort_index()
        
        severity_data = [
            ['<b>Severity Level</b>', '<b>Event Count</b>', '<b>Description</b>']
        ]
        
        severity_desc = {
            1: 'Informational',
            2: 'Low',
            3: 'Medium',
            4: 'High',
            5: 'Critical'
        }
        
        for severity in range(1, 6):
            count = severity_counts.get(severity, 0)
            severity_data.append([
                str(severity),
                str(count),
                severity_desc.get(severity, 'Unknown')
            ])
        
        severity_table = Table(severity_data, colWidths=[1.5*inch, 1.5*inch, 3*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3C7DD9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F5F5')]),
        ]))
        
        elements.append(severity_table)
        
        return elements
    
    def _create_timeline_summary(
        self,
        classified_events: pd.DataFrame,
        include_full: bool,
        min_severity: int
    ) -> List:
        """Create timeline summary table."""
        elements = []
        
        # Section header
        header = Paragraph(
            "<b>Timeline Summary</b>",
            self.styles['SectionHeader']
        )
        elements.append(header)
        elements.append(Spacer(1, 0.2*inch))
        
        # Filter events by severity
        if not include_full:
            filtered = classified_events[classified_events['severity'] >= min_severity]
            desc = Paragraph(
                f"Displaying <b>{len(filtered)}</b> events with severity ≥ {min_severity}. "
                "Complete timeline available in CSV export.",
                self.styles['Normal']
            )
        else:
            filtered = classified_events
            desc = Paragraph(
                f"Displaying all <b>{len(filtered)}</b> classified events.",
                self.styles['Normal']
            )
        
        elements.append(desc)
        elements.append(Spacer(1, 0.2*inch))
        
        # Sort by timestamp (most recent first)
        filtered_sorted = filtered.sort_values('ts_utc', ascending=False)
        
        # Limit to first 50 events for page space
        display_limit = 50
        events_to_show = filtered_sorted.head(display_limit)
        
        # Timeline table
        timeline_data = [
            ['<b>Timestamp</b>', '<b>Class</b>', '<b>Sev</b>', '<b>Description</b>']
        ]
        
        for _, event in events_to_show.iterrows():
            ts = str(event.get('ts_utc', 'N/A'))[:19]  # Truncate to seconds
            classification = event.get('rule_class', 'UNKNOWN').replace('_', ' ')
            severity = str(event.get('severity', '?'))
            desc = str(event.get('description', 'No description'))[:60]  # Truncate
            
            timeline_data.append([ts, classification, severity, desc])
        
        if len(filtered_sorted) > display_limit:
            timeline_data.append([
                f'<i>...and {len(filtered_sorted) - display_limit} more events</i>',
                '',
                '',
                ''
            ])
        
        timeline_table = Table(
            timeline_data,
            colWidths=[1.8*inch, 1.5*inch, 0.5*inch, 2.7*inch]
        )
        timeline_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3C7DD9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F5F5')]),
        ]))
        
        elements.append(timeline_table)
        
        return elements
    
    def _create_case_notes(self, case_notes: str) -> List:
        """Create case notes section."""
        elements = []
        
        # Section header
        header = Paragraph(
            "<b>Analyst Notes</b>",
            self.styles['SectionHeader']
        )
        elements.append(header)
        elements.append(Spacer(1, 0.2*inch))
        
        # Notes content
        notes = Paragraph(case_notes.replace('\n', '<br/>'), self.styles['Normal'])
        elements.append(notes)
        
        return elements
    
    def _create_coc_section(self, coc_log_path: Path) -> List:
        """Create Chain of Custody section."""
        elements = []
        
        # Section header
        header = Paragraph(
            "<b>Chain of Custody Log</b>",
            self.styles['SectionHeader']
        )
        elements.append(header)
        elements.append(Spacer(1, 0.2*inch))
        
        # Description
        desc = Paragraph(
            "Complete chain of custody log documenting all evidence handling operations. "
            "Each entry includes timestamp, operation type, evidence hash, and metadata.",
            self.styles['Normal']
        )
        elements.append(desc)
        elements.append(Spacer(1, 0.2*inch))
        
        # Read CoC log
        if coc_log_path.exists():
            with open(coc_log_path, 'r') as f:
                coc_content = f.read()
            
            # Display last 100 lines (for space constraints)
            coc_lines = coc_content.strip().split('\n')
            
            if len(coc_lines) > 100:
                display_lines = coc_lines[-100:]
                truncated_msg = f"<i>Displaying last 100 of {len(coc_lines)} total entries</i><br/><br/>"
            else:
                display_lines = coc_lines
                truncated_msg = ""
            
            coc_text = truncated_msg + '<br/>'.join(display_lines)
            
            coc_para = Paragraph(
                f"<font name='Courier' size='7'>{coc_text}</font>",
                self.styles['Normal']
            )
            elements.append(coc_para)
        else:
            no_coc = Paragraph(
                "<i>Chain of Custody log not found</i>",
                self.styles['Normal']
            )
            elements.append(no_coc)
        
        return elements
    
    def get_report_hash(self) -> Optional[str]:
        """
        Get SHA-256 hash of generated report.
        
        Returns:
            Report hash (None if report not yet generated)
        """
        return self.report_hash
    
    def log_to_coc(self, coc: ChainOfCustody, report_path: Path) -> None:
        """
        Log report generation to Chain of Custody.
        
        Args:
            coc: ChainOfCustody instance
            report_path: Path to generated report
        """
        if self.report_hash:
            coc.log_entry(
                event="REPORT_GENERATED",
                hash_value=self.report_hash,
                reason="Final forensic analysis report",
                metadata={
                    'report_path': str(report_path),
                    'case_id': self.case_id,
                    'analyst': self.analyst_name,
                    'generation_timestamp': self.generation_timestamp
                }
            )
            self.logger.info("Report generation logged to Chain of Custody")
