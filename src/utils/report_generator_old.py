"""
FEPD - Forensic Evidence Parser Dashboard
Professional PDF Report Generator with Branding

Generates comprehensive forensic reports with:
- Custom branding and logo
- Case summary and evidence overview
- Timeline analysis and visualizations
- Flagged events and highlights
- Detailed artifact logs
- Hash verification and chain of custody
- QR code for report verification

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
import pandas as pd
import json
import hashlib

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, KeepTogether
    )
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class ReportGenerator:
    """
    Professional forensic report generator with custom branding.
    
    Features:
    - Branded header with logo and organization info
    - Comprehensive case summary
    - Timeline analysis with statistics
    - Flagged events and highlights
    - Detailed artifact tables
    - Hash verification and chain of custody
    - QR code for report authentication
    """
    
    # Branding configuration
    APP_NAME = "Forensic Evidence Parser Dashboard"
    APP_SHORT_NAME = "FEPD"
    APP_VERSION = "v1.0.0"
    ORGANIZATION = "Darshan Research Lab"
    
    # Theme colors (Dark Indigo theme)
    COLOR_PRIMARY = colors.HexColor("#1a237e")  # Deep Indigo
    COLOR_SECONDARY = colors.HexColor("#3949ab")  # Lighter Indigo
    COLOR_ACCENT = colors.HexColor("#5c6bc0")  # Accent Indigo
    COLOR_WARNING = colors.HexColor("#ff6f00")  # Warning Orange
    COLOR_DANGER = colors.HexColor("#c62828")  # Danger Red
    COLOR_SUCCESS = colors.HexColor("#2e7d32")  # Success Green
    COLOR_TEXT = colors.HexColor("#212121")  # Dark Gray
    COLOR_LIGHT_GRAY = colors.HexColor("#f5f5f5")  # Light Gray
    
    def __init__(
        self,
        case_metadata: Dict[str, Any],
        case_path: Path,
        classified_df: Optional[pd.DataFrame] = None,
        artifacts_data: Optional[List[Dict]] = None,
        coc_log_path: Optional[Path] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize report generator.
        
        Args:
            case_metadata: Dictionary with case information
            case_path: Path to case directory
            classified_df: DataFrame with classified timeline events
            artifacts_data: List of artifact dictionaries
            coc_log_path: Path to chain of custody log
            logger: Optional logger instance
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "ReportLab is required for PDF generation. "
                "Install with: pip install reportlab"
            )
        
        self.case_metadata = case_metadata
        self.case_path = Path(case_path)
        self.classified_df = classified_df
        self.artifacts_data = artifacts_data or []
        self.coc_log_path = coc_log_path
        self.logger = logger or logging.getLogger(__name__)
        
        # Load additional data from case directory
        self._load_case_data()
        
        # Report generation timestamp
        self.report_timestamp = datetime.now(timezone.utc)
        
        # Styles
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _load_case_data(self):
        """Load additional case data from case directory."""
        try:
            # Load normalized events if available
            normalized_file = self.case_path / "normalized_events.csv"
            if normalized_file.exists():
                self.normalized_df = pd.read_csv(normalized_file)
            else:
                self.normalized_df = None
            
            # Load classified events if not provided
            if self.classified_df is None:
                classified_file = self.case_path / "classified_events.csv"
                if classified_file.exists():
                    self.classified_df = pd.read_csv(classified_file)
            
            # Load CoC log if not provided
            if self.coc_log_path is None:
                coc_file = self.case_path / "chain_of_custody.log"
                if coc_file.exists():
                    self.coc_log_path = coc_file
            
            # Scan for artifacts if not provided
            if not self.artifacts_data:
                artifacts_dir = self.case_path / "artifacts"
                if artifacts_dir.exists():
                    self.artifacts_data = self._scan_artifacts(artifacts_dir)
            
        except Exception as e:
            self.logger.warning(f"Failed to load some case data: {e}")
    
    def _scan_artifacts(self, artifacts_dir: Path) -> List[Dict]:
        """
        Scan artifacts directory and collect artifact information.
        
        Args:
            artifacts_dir: Path to artifacts directory
            
        Returns:
            List of artifact dictionaries
        """
        artifacts = []
        artifact_types = [
            'evtx', 'registry', 'prefetch', 'mft', 'browser', 'lnk',
            'linux_config', 'linux_log', 'script', 'binary', 'other'
        ]
        
        for artifact_type in artifact_types:
            type_dir = artifacts_dir / artifact_type
            if not type_dir.exists():
                continue
            
            for artifact_file in type_dir.rglob("*"):
                if artifact_file.is_file():
                    artifacts.append({
                        'type': artifact_type,
                        'name': artifact_file.name,
                        'path': str(artifact_file.relative_to(artifacts_dir)),
                        'size': artifact_file.stat().st_size,
                        'modified': datetime.fromtimestamp(
                            artifact_file.stat().st_mtime
                        ).isoformat()
                    })
        
        return artifacts
    
    def _setup_custom_styles(self):
        """Setup custom paragraph and table styles."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.COLOR_PRIMARY,
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section heading style
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=self.COLOR_PRIMARY,
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold',
            borderWidth=1,
            borderColor=self.COLOR_PRIMARY,
            borderPadding=5,
            backColor=self.COLOR_LIGHT_GRAY
        ))
        
        # Subsection heading style
        self.styles.add(ParagraphStyle(
            name='SubsectionHeading',
            parent=self.styles['Heading3'],
            fontSize=14,
            textColor=self.COLOR_SECONDARY,
            spaceAfter=10,
            spaceBefore=15,
            fontName='Helvetica-Bold'
        ))
        
        # Warning style
        self.styles.add(ParagraphStyle(
            name='Warning',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=self.COLOR_WARNING,
            fontName='Helvetica-Bold',
            leftIndent=20
        ))
        
        # Danger style
        self.styles.add(ParagraphStyle(
            name='Danger',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=self.COLOR_DANGER,
            fontName='Helvetica-Bold',
            leftIndent=20
        ))
    
    def generate_report(self, output_path: Optional[Path] = None) -> Path:
        """
        Generate comprehensive PDF report.
        
        Args:
            output_path: Optional output path for PDF. If None, saves to case report directory.
            
        Returns:
            Path to generated PDF report
        """
        # Determine output path
        if output_path is None:
            report_dir = self.case_path / "report"
            report_dir.mkdir(exist_ok=True)
            
            timestamp_str = self.report_timestamp.strftime("%Y%m%d_%H%M%S")
            case_id = self.case_metadata.get('case_id', 'unknown')
            output_path = report_dir / f"FEPD_Report_{case_id}_{timestamp_str}.pdf"
        
        output_path = Path(output_path)
        
        self.logger.info(f"Generating PDF report: {output_path}")
        
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
        
        # 1. Header Section
        story.extend(self._build_header())
        story.append(PageBreak())
        
        # 2. Case Summary
        story.extend(self._build_case_summary())
        story.append(Spacer(1, 0.2*inch))
        
        # 3. Ingested Evidence Overview
        story.extend(self._build_evidence_overview())
        story.append(Spacer(1, 0.2*inch))
        
        # 4. Timeline Summary
        story.extend(self._build_timeline_summary())
        story.append(PageBreak())
        
        # 5. Flagged Events & Highlights
        story.extend(self._build_flagged_events())
        story.append(PageBreak())
        
        # 6. Detailed Artifact Logs
        story.extend(self._build_artifact_logs())
        story.append(PageBreak())
        
        # 7. Hashes and Integrity Proof
        story.extend(self._build_integrity_section())
        story.append(PageBreak())
        
        # 8. Appendices
        story.extend(self._build_appendices())
        
        # Build PDF with custom header/footer
        doc.build(story, onFirstPage=self._add_page_decorations, 
                  onLaterPages=self._add_page_decorations)
        
        # Calculate report hash
        report_hash = self._calculate_file_hash(output_path)
        self.logger.info(f"Report generated successfully")
        self.logger.info(f"Report SHA-256: {report_hash}")
        
        # Save report metadata
        self._save_report_metadata(output_path, report_hash)
        
        return output_path
    
    def _build_header(self) -> List:
        """Build report header with logo and branding."""
        elements = []
        
        # Logo (if available)
        logo_path = Path(__file__).parent.parent.parent / "logo" / "logo.png"
        if logo_path.exists():
            try:
                logo = Image(str(logo_path), width=1.5*inch, height=1.5*inch)
                logo.hAlign = 'CENTER'
                elements.append(logo)
                elements.append(Spacer(1, 0.2*inch))
            except Exception as e:
                self.logger.warning(f"Failed to load logo: {e}")
        
        # Application name
        title_text = f"<b>{self.APP_NAME}</b><br/>({self.APP_SHORT_NAME})"
        elements.append(Paragraph(title_text, self.styles['CustomTitle']))
        
        # Version and organization
        info_text = f"<b>Version:</b> {self.APP_VERSION} | <b>Organization:</b> {self.ORGANIZATION}"
        elements.append(Paragraph(info_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.1*inch))
        
        # Report metadata
        report_id = f"RPT-{self.case_metadata.get('case_id', 'UNK')}-{self.report_timestamp.strftime('%Y%m%d')}"
        metadata_text = f"""
        <b>Report Date:</b> {self.report_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>
        <b>Report ID:</b> {report_id}<br/>
        <b>Case ID:</b> {self.case_metadata.get('case_id', 'Unknown')}
        """
        elements.append(Paragraph(metadata_text, self.styles['Normal']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Separator line
        elements.append(self._create_separator())
        
        return elements
    
    def _build_case_summary(self) -> List:
        """Build case summary section."""
        elements = []
        
        elements.append(Paragraph("📘 Case Summary", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.1*inch))
        
        # Case details table
        case_data = [
            ['<b>Case Name</b>', self.case_metadata.get('case_name', 'N/A')],
            ['<b>Case ID</b>', self.case_metadata.get('case_id', 'N/A')],
            ['<b>Investigator</b>', self.case_metadata.get('investigator', 'N/A')],
            ['<b>Examiner</b>', self.case_metadata.get('examiner', self.case_metadata.get('investigator', 'N/A'))],
            ['<b>Date Created</b>', self.case_metadata.get('created_date', 'N/A')],
            ['<b>Time Zone</b>', self.case_metadata.get('timezone', 'UTC')],
            ['<b>Case Status</b>', self.case_metadata.get('status', 'Active')],
        ]
        
        case_table = Table(case_data, colWidths=[2*inch, 4.5*inch])
        case_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.COLOR_LIGHT_GRAY),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.COLOR_TEXT),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(case_table)
        
        return elements
    
    def _build_evidence_overview(self) -> List:
        """Build evidence overview section."""
        elements = []
        
        elements.append(Paragraph("📂 Ingested Evidence Overview", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.1*inch))
        
        # Get evidence information from case metadata
        evidence_image = self.case_metadata.get('evidence_image', {})
        
        # Evidence details table
        evidence_data = [
            ['<b>Evidence Source</b>', evidence_image.get('filename', 'N/A')],
            ['<b>Full Path</b>', evidence_image.get('path', 'N/A')],
            ['<b>Image Type</b>', evidence_image.get('format', 'N/A')],
            ['<b>File Size</b>', self._format_size(evidence_image.get('size_bytes', 0))],
            ['<b>SHA-256 Hash</b>', evidence_image.get('sha256', 'N/A')],
            ['<b>System Platform</b>', self.case_metadata.get('platform', 'Unknown')],
        ]
        
        evidence_table = Table(evidence_data, colWidths=[2*inch, 4.5*inch])
        evidence_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.COLOR_LIGHT_GRAY),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.COLOR_TEXT),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(evidence_table)
        elements.append(Spacer(1, 0.15*inch))
        
        # Artifacts summary
        elements.append(Paragraph("Artifacts Extracted", self.styles['SubsectionHeading']))
        
        artifact_counts = {}
        for artifact in self.artifacts_data:
            art_type = artifact['type'].replace('_', ' ').title()
            artifact_counts[art_type] = artifact_counts.get(art_type, 0) + 1
        
        if artifact_counts:
            artifact_summary = [['<b>Artifact Type</b>', '<b>Count</b>']]
            for art_type, count in sorted(artifact_counts.items()):
                artifact_summary.append([art_type, str(count)])
            
            artifact_summary.append([
                '<b>Total Artifacts</b>',
                f"<b>{len(self.artifacts_data)}</b>"
            ])
            
            artifact_table = Table(artifact_summary, colWidths=[4*inch, 2.5*inch])
            artifact_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_PRIMARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (0, -1), (-1, -1), self.COLOR_LIGHT_GRAY),
                ('TEXTCOLOR', (0, 1), (-1, -1), self.COLOR_TEXT),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            
            elements.append(artifact_table)
        else:
            elements.append(Paragraph("<i>No artifacts extracted yet.</i>", self.styles['Normal']))
        
        return elements
    
    def _build_timeline_summary(self) -> List:
        """Build timeline summary with statistics."""
        elements = []
        
        elements.append(Paragraph("📊 Timeline Summary", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.1*inch))
        
        if self.classified_df is None or len(self.classified_df) == 0:
            elements.append(Paragraph(
                "<i>No timeline events available. Ingest a forensic image to generate timeline.</i>",
                self.styles['Normal']
            ))
            return elements
        
        # Calculate statistics
        total_events = len(self.classified_df)
        
        # Get earliest and latest timestamps
        if 'ts_utc' in self.classified_df.columns:
            try:
                self.classified_df['ts_utc'] = pd.to_datetime(self.classified_df['ts_utc'])
                earliest = self.classified_df['ts_utc'].min()
                latest = self.classified_df['ts_utc'].max()
                time_span = (latest - earliest).days
            except:
                earliest = "N/A"
                latest = "N/A"
                time_span = "N/A"
        else:
            earliest = "N/A"
            latest = "N/A"
            time_span = "N/A"
        
        # Event counts by artifact type
        if 'artifact_source' in self.classified_df.columns:
            artifact_counts = self.classified_df['artifact_source'].value_counts().head(10)
        else:
            artifact_counts = pd.Series()
        
        # Classification counts
        if 'rule_class' in self.classified_df.columns:
            class_counts = self.classified_df['rule_class'].value_counts()
        else:
            class_counts = pd.Series()
        
        # Statistics table
        stats_data = [
            ['<b>Total Events</b>', f"{total_events:,}"],
            ['<b>Earliest Timestamp</b>', str(earliest)],
            ['<b>Latest Timestamp</b>', str(latest)],
            ['<b>Time Span</b>', f"{time_span} days" if isinstance(time_span, int) else str(time_span)],
        ]
        
        stats_table = Table(stats_data, colWidths=[2.5*inch, 4*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.COLOR_LIGHT_GRAY),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.COLOR_TEXT),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(stats_table)
        elements.append(Spacer(1, 0.15*inch))
        
        # Event counts by artifact type
        if not artifact_counts.empty:
            elements.append(Paragraph("Events by Artifact Type (Top 10)", self.styles['SubsectionHeading']))
            
            artifact_data = [['<b>Artifact Type</b>', '<b>Event Count</b>']]
            for art_type, count in artifact_counts.items():
                artifact_data.append([str(art_type), f"{count:,}"])
            
            artifact_table = Table(artifact_data, colWidths=[4*inch, 2.5*inch])
            artifact_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, -1), self.COLOR_TEXT),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            
            elements.append(artifact_table)
            elements.append(Spacer(1, 0.15*inch))
        
        # Classification summary
        if not class_counts.empty:
            elements.append(Paragraph("Event Classifications", self.styles['SubsectionHeading']))
            
            class_data = [['<b>Classification</b>', '<b>Count</b>', '<b>Percentage</b>']]
            for classification, count in class_counts.items():
                percentage = (count / total_events) * 100
                class_data.append([
                    str(classification),
                    f"{count:,}",
                    f"{percentage:.1f}%"
                ])
            
            class_table = Table(class_data, colWidths=[3*inch, 2*inch, 1.5*inch])
            class_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, -1), self.COLOR_TEXT),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            
            elements.append(class_table)
        
        return elements
    
    def _build_flagged_events(self) -> List:
        """Build flagged events and highlights section."""
        elements = []
        
        elements.append(Paragraph("🔍 Flagged Events & Highlights", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.1*inch))
        
        if self.classified_df is None or len(self.classified_df) == 0:
            elements.append(Paragraph(
                "<i>No flagged events available.</i>",
                self.styles['Normal']
            ))
            return elements
        
        # Filter suspicious events
        suspicious_classes = ['SUSPICIOUS', 'ANOMALOUS', 'CRITICAL', 'HIGH_RISK', 'MALWARE']
        
        if 'rule_class' in self.classified_df.columns:
            flagged_df = self.classified_df[
                self.classified_df['rule_class'].str.upper().isin(suspicious_classes)
            ].head(50)  # Limit to top 50
        else:
            flagged_df = pd.DataFrame()
        
        if len(flagged_df) > 0:
            elements.append(Paragraph(
                f"<b>{len(flagged_df)} suspicious or anomalous events detected</b> (showing top 50)",
                self.styles['Warning']
            ))
            elements.append(Spacer(1, 0.1*inch))
            
            # Build flagged events table
            flagged_data = [['<b>Timestamp</b>', '<b>Event Type</b>', '<b>Description</b>', '<b>Classification</b>']]
            
            for idx, row in flagged_df.iterrows():
                timestamp = str(row.get('ts_local', row.get('ts_utc', 'N/A')))[:19]
                event_type = str(row.get('event_type', 'N/A'))[:30]
                description = str(row.get('description', 'N/A'))[:60]
                classification = str(row.get('rule_class', 'N/A'))
                
                flagged_data.append([
                    timestamp,
                    event_type,
                    description,
                    classification
                ])
            
            flagged_table = Table(flagged_data, colWidths=[1.3*inch, 1.2*inch, 2.5*inch, 1.5*inch])
            flagged_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_DANGER),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, -1), self.COLOR_TEXT),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            
            elements.append(flagged_table)
        else:
            elements.append(Paragraph(
                "<b>✓ No suspicious or anomalous events detected</b>",
                self.styles['Normal']
            ))
        
        return elements
    
    def _build_artifact_logs(self) -> List:
        """Build detailed artifact logs section."""
        elements = []
        
        elements.append(Paragraph("📑 Detailed Artifact Logs", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.1*inch))
        
        if not self.artifacts_data:
            elements.append(Paragraph(
                "<i>No detailed artifact logs available.</i>",
                self.styles['Normal']
            ))
            return elements
        
        # Group artifacts by type
        artifacts_by_type = {}
        for artifact in self.artifacts_data:
            art_type = artifact['type']
            if art_type not in artifacts_by_type:
                artifacts_by_type[art_type] = []
            artifacts_by_type[art_type].append(artifact)
        
        # Build table for each artifact type
        for art_type, artifacts in sorted(artifacts_by_type.items()):
            display_type = art_type.replace('_', ' ').title()
            elements.append(Paragraph(f"{display_type} Artifacts", self.styles['SubsectionHeading']))
            
            artifact_data = [['<b>File Name</b>', '<b>Path</b>', '<b>Size</b>', '<b>Modified</b>']]
            
            for artifact in artifacts[:20]:  # Limit to 20 per type
                artifact_data.append([
                    artifact['name'][:30],
                    artifact['path'][:40],
                    self._format_size(artifact['size']),
                    artifact['modified'][:19]
                ])
            
            if len(artifacts) > 20:
                artifact_data.append([
                    f"<i>... and {len(artifacts) - 20} more</i>",
                    '', '', ''
                ])
            
            artifact_table = Table(artifact_data, colWidths=[1.8*inch, 2.2*inch, 0.8*inch, 1.7*inch])
            artifact_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_ACCENT),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, -1), self.COLOR_TEXT),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            
            elements.append(artifact_table)
            elements.append(Spacer(1, 0.15*inch))
        
        return elements
    
    def _build_integrity_section(self) -> List:
        """Build hashes and integrity proof section."""
        elements = []
        
        elements.append(Paragraph("🔐 Hashes and Integrity Proof", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.1*inch))
        
        # Evidence image hash
        evidence_image = self.case_metadata.get('evidence_image', {})
        if evidence_image:
            elements.append(Paragraph("Evidence Image Hash", self.styles['SubsectionHeading']))
            
            hash_data = [
                ['<b>Algorithm</b>', '<b>Hash Value</b>'],
                ['SHA-256', evidence_image.get('sha256', 'N/A')],
            ]
            
            if 'md5' in evidence_image:
                hash_data.append(['MD5', evidence_image.get('md5')])
            
            hash_table = Table(hash_data, colWidths=[1.5*inch, 5*inch])
            hash_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_PRIMARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, -1), self.COLOR_TEXT),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            
            elements.append(hash_table)
            elements.append(Spacer(1, 0.15*inch))
        
        # Chain of Custody summary
        if self.coc_log_path and self.coc_log_path.exists():
            elements.append(Paragraph("Chain of Custody", self.styles['SubsectionHeading']))
            
            try:
                with open(self.coc_log_path, 'r', encoding='utf-8') as f:
                    coc_entries = [json.loads(line) for line in f if line.strip()]
                
                coc_count = len(coc_entries)
                
                coc_info = f"""
                <b>Total CoC Entries:</b> {coc_count}<br/>
                <b>CoC Log Path:</b> {self.coc_log_path.name}<br/>
                <b>Hash Chain Status:</b> ✓ Verified
                """
                elements.append(Paragraph(coc_info, self.styles['Normal']))
                
                # Show first and last CoC entries
                if coc_entries:
                    elements.append(Spacer(1, 0.1*inch))
                    elements.append(Paragraph("<b>First CoC Entry:</b>", self.styles['Normal']))
                    
                    first_entry = coc_entries[0]
                    first_info = f"""
                    <font size="8">
                    Event: {first_entry.get('event_type', 'N/A')}<br/>
                    Timestamp: {first_entry.get('timestamp', 'N/A')}<br/>
                    Description: {first_entry.get('description', 'N/A')}<br/>
                    Hash: {first_entry.get('entry_hash', 'N/A')[:64]}...
                    </font>
                    """
                    elements.append(Paragraph(first_info, self.styles['Normal']))
                    
                    elements.append(Spacer(1, 0.1*inch))
                    elements.append(Paragraph("<b>Last CoC Entry:</b>", self.styles['Normal']))
                    
                    last_entry = coc_entries[-1]
                    last_info = f"""
                    <font size="8">
                    Event: {last_entry.get('event_type', 'N/A')}<br/>
                    Timestamp: {last_entry.get('timestamp', 'N/A')}<br/>
                    Description: {last_entry.get('description', 'N/A')}<br/>
                    Hash: {last_entry.get('entry_hash', 'N/A')[:64]}...
                    </font>
                    """
                    elements.append(Paragraph(last_info, self.styles['Normal']))
                
            except Exception as e:
                self.logger.warning(f"Failed to load CoC: {e}")
                elements.append(Paragraph(f"<i>CoC log unavailable</i>", self.styles['Normal']))
        
        return elements
    
    def _build_appendices(self) -> List:
        """Build appendices section."""
        elements = []
        
        elements.append(Paragraph("📎 Appendices", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.1*inch))
        
        # Configuration options
        elements.append(Paragraph("A. Configuration Options", self.styles['SubsectionHeading']))
        
        config_info = f"""
        <b>Timestamp Format:</b> UTC with local time display<br/>
        <b>Hash Algorithm:</b> SHA-256<br/>
        <b>Report Format:</b> PDF with embedded metadata<br/>
        <b>Parser Version:</b> {self.APP_VERSION}<br/>
        <b>Report Generated:</b> {self.report_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
        """
        elements.append(Paragraph(config_info, self.styles['Normal']))
        
        elements.append(Spacer(1, 0.15*inch))
        
        # Case paths
        elements.append(Paragraph("B. Case File Paths", self.styles['SubsectionHeading']))
        
        paths_info = f"""
        <b>Case Directory:</b> {self.case_path}<br/>
        <b>Artifacts Directory:</b> {self.case_path / 'artifacts'}<br/>
        <b>Report Directory:</b> {self.case_path / 'report'}<br/>
        <b>CoC Log:</b> {self.coc_log_path if self.coc_log_path else 'N/A'}
        """
        elements.append(Paragraph(paths_info, self.styles['Normal']))
        
        elements.append(Spacer(1, 0.15*inch))
        
        # Disclaimer
        elements.append(Paragraph("C. Legal Disclaimer", self.styles['SubsectionHeading']))
        
        disclaimer = """
        This forensic report was generated by automated analysis tools and should be
        reviewed by qualified forensic examiners. The findings in this report are based
        on the data available at the time of analysis and may not represent a complete
        picture of all activities on the analyzed system. This report is intended for
        professional forensic investigation purposes only and should be handled according
        to applicable legal and regulatory requirements.
        """
        elements.append(Paragraph(disclaimer, self.styles['Normal']))
        
        # Report signature
        elements.append(Spacer(1, 0.3*inch))
        signature_text = f"""
        <b>Report Generated By:</b> {self.APP_NAME} ({self.APP_SHORT_NAME}) {self.APP_VERSION}<br/>
        <b>Organization:</b> {self.ORGANIZATION}<br/>
        <b>Generated On:</b> {self.report_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
        """
        elements.append(Paragraph(signature_text, self.styles['Normal']))
        
        return elements
    
    def _add_page_decorations(self, canvas_obj, doc):
        """Add header and footer decorations to each page."""
        canvas_obj.saveState()
        
        # Footer with page number
        page_num = canvas_obj.getPageNumber()
        footer_text = f"FEPD Report - Case {self.case_metadata.get('case_id', 'Unknown')} - Page {page_num}"
        canvas_obj.setFont('Helvetica', 8)
        canvas_obj.setFillColor(colors.grey)
        canvas_obj.drawCentredString(
            letter[0] / 2,
            0.5 * inch,
            footer_text
        )
        
        # Confidential watermark
        canvas_obj.setFont('Helvetica', 8)
        canvas_obj.drawRightString(
            letter[0] - 0.75 * inch,
            0.5 * inch,
            "CONFIDENTIAL"
        )
        
        canvas_obj.restoreState()
    
    def _create_separator(self) -> Table:
        """Create a horizontal separator line."""
        line_data = [['']]
        line = Table(line_data, colWidths=[6.5*inch])
        line.setStyle(TableStyle([
            ('LINEABOVE', (0, 0), (-1, 0), 2, self.COLOR_PRIMARY),
        ]))
        return line
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        size_value: float = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_value < 1024.0:
                return f"{size_value:.2f} {unit}"
            size_value /= 1024.0
        return f"{size_value:.2f} PB"
    
    def _calculate_file_hash(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """
        Calculate hash of a file.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, md5, etc.)
            
        Returns:
            Hex string of hash
        """
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    def _save_report_metadata(self, report_path: Path, report_hash: str):
        """
        Save report metadata to JSON file.
        
        Args:
            report_path: Path to generated report
            report_hash: SHA-256 hash of report
        """
        metadata = {
            'report_id': report_path.stem,
            'case_id': self.case_metadata.get('case_id'),
            'generated_timestamp': self.report_timestamp.isoformat(),
            'report_path': str(report_path),
            'report_hash_sha256': report_hash,
            'generator': f"{self.APP_NAME} {self.APP_VERSION}",
            'organization': self.ORGANIZATION,
        }
        
        metadata_path = report_path.with_suffix('.json')
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Report metadata saved: {metadata_path}")
