"""
FEPD Forensic Reporting Module
================================

Professional report generation for digital forensics investigations.

This module provides court-admissible, human-readable investigation reports
that follow DFIR best practices and legal requirements.

Key Features:
- Executive summaries for stakeholders
- Evidence integrity verification
- Artifact analysis with forensic context
- ML/UEBA findings interpretation
- Chain of custody documentation
- Actionable recommendations

Copyright (c) 2026 FEPD Development Team
"""

from .forensic_report_generator import ForensicReportGenerator

__all__ = ['ForensicReportGenerator']
