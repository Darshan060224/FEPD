# FEPD Forensic Report Generator

Professional, court-admissible investigation reports for digital forensics.

## Overview

The FEPD Report Engine transforms raw forensic data into comprehensive, human-readable investigation reports suitable for:

- **Legal Proceedings**: Court-admissible format with chain of custody
- **Incident Response**: Executive summaries for stakeholders
- **Management Briefings**: Non-technical summaries with recommendations
- **Forensic Documentation**: Complete technical appendix with evidence details

## Features

### ✓ Professional Formatting
- Cover page with case classification
- Executive summary for non-technical readers
- Structured sections following DFIR standards
- Markdown format for easy conversion (PDF, HTML, DOCX)

### ✓ Forensic Integrity
- Evidence hash verification
- Chain of custody documentation
- Tamper detection
- Court-admissible language

### ✓ Comprehensive Analysis
- Evidence overview and validation status
- Artifact discovery with forensic significance
- Timeline status and recommendations
- ML/UEBA findings interpretation
- Notable artifacts with context

### ✓ Actionable Intelligence
- Next steps for investigators
- Missing data explanations
- Tool guidance
- Best practices

## Usage

### From FEPD Terminal (Recommended)

```bash
# Load your case
use case adcdsc

# Generate report
report

# Generate with custom analyst info
report --analyst "John Smith" --org "Security Team"

# Generate and open automatically
report --open
```

### From Command Line

```bash
# Basic report generation
python generate_report.py adcdsc

# With analyst information
python generate_report.py corp-leak --analyst "Jane Doe" --org "IR Team"
```

### Programmatic Usage

```python
from src.reporting.forensic_report_generator import ForensicReportGenerator

generator = ForensicReportGenerator(workspace_root='.')
report = generator.generate_report(
    case_name='adcdsc',
    analyst='John Smith',
    organization='Forensic Investigation Unit'
)

# Save report
with open('report.md', 'w') as f:
    f.write(report)
```

## Report Structure

### 1. Cover Page
- Case identification
- Incident type and severity
- Analyst and organization
- Evidence summary
- Classification markings

### 2. Executive Summary
Narrative overview including:
- What was analyzed
- What evidence was used
- Key findings
- Known and unknown factors
- High-level recommendations

### 3. Case Metadata
Structured table with:
- Case ID and name
- Created date
- Status
- Evidence count
- Chain of custody status

### 4. Evidence Overview
For each evidence item:
- Filename and format
- Size and segments
- Hash values (MD5/SHA-256)
- Acquisition tool
- Validation status
- Integrity assessment

### 5. Artifact Discovery Summary
Grouped by type with:
- Artifact counts
- Total sizes
- Forensic significance
- Interpretation

### 6. Timeline Analysis
- Event count
- Distribution analysis
- Suspicious period detection
- Generation guidance (if not created)

### 7. ML & UEBA Analysis
- Models executed
- Anomaly counts
- Confidence levels
- Interpretation
- Limitations explained

### 8. Notable Artifacts
High-signal items with:
- Evidence paths
- Artifact types
- Forensic significance
- Risk assessment

### 9. Chain of Custody
- Integrity verification
- Tamper detection
- Verification procedures
- Court admissibility

### 10. Recommendations
Priority-based next steps:
- Critical actions
- High priority items
- Medium priority suggestions
- Best practices

### 11. Technical Appendix
- Tool versions
- Hash algorithms
- Evidence manifest
- Configuration details

## Report Principles

### 1. Human-Readable
Every section is written for understanding, not just documentation.

### 2. Forensically Neutral
No speculation beyond evidence. All claims trace to artifacts.

### 3. Explainable
ML results include interpretation, not just raw scores.

### 4. Context-Aware
Missing data is explained with recommendations, not left blank.

### 5. Court-Safe
Language and structure suitable for legal proceedings.

### 6. Actionable
Recommendations guide next steps, not just observations.

## Output Locations

Reports are saved to:
```
cases/<case_name>/reports/<case_name>_forensic_report_<timestamp>.md
```

Example:
```
cases/adcdsc/reports/adcdsc_forensic_report_20260128_143022.md
```

## Converting Reports

### To PDF (via Pandoc)
```bash
pandoc report.md -o report.pdf --pdf-engine=xelatex
```

### To HTML
```bash
pandoc report.md -o report.html --standalone --toc
```

### To DOCX (Microsoft Word)
```bash
pandoc report.md -o report.docx
```

## Chain of Custody Integration

Every report generation is logged in the chain of custody:

```
Action: REPORT_GENERATED
Details: Forensic report generated: adcdsc_forensic_report_20260128_143022.md
Analyst: John Smith
Timestamp: 2026-01-28 14:30:22
Hash: a3f7c8d9e2b...
```

This provides auditable proof of:
- When the report was generated
- Who generated it
- What data was included

## Best Practices

### 1. Generate Early
Create preliminary reports early in investigation to identify gaps.

### 2. Include Analyst Info
Always specify analyst name and organization for accountability.

### 3. Review Before Distribution
Verify all sections are complete and accurate.

### 4. Version Control
Reports include timestamps - keep multiple versions as investigation progresses.

### 5. Combine with Visualizations
Attach timeline visualizations and graphs to enhance report.

### 6. Export to PDF
Convert to PDF before sharing with non-technical stakeholders.

## Testing

Test report generation:
```bash
python test_report_generation.py
```

This will:
- Generate a test report for the adcdsc case
- Verify all sections are present
- Save to `cases/adcdsc/reports/`

## Architecture

```
src/reporting/
└── forensic_report_generator.py   # Main report engine

Scripts:
- generate_report.py               # CLI tool
- test_report_generation.py        # Testing

Output:
- cases/<case>/reports/*.md        # Generated reports
```

## Legal Considerations

### Court Admissibility
Reports follow forensic documentation standards:
- Chain of custody maintained
- Evidence integrity verified
- Methodology documented
- Analyst accountability established

### Limitations
Reports clearly state:
- What evidence was available
- What analysis was performed
- What remains unknown
- Confidence levels

### Distribution
Control report distribution according to:
- Case sensitivity
- Legal restrictions
- Organizational policies
- Investigation status

## Support

For issues or questions:
1. Check that case database exists
2. Verify evidence has been mounted
3. Ensure chain of custody is initialized
4. Review report output for error messages

## Future Enhancements

Planned features:
- [ ] Automated chart/graph generation
- [ ] Multi-format export (PDF, HTML, DOCX)
- [ ] Template customization
- [ ] Report comparison (before/after analysis)
- [ ] Executive summary auto-generation
- [ ] Finding severity auto-classification

---

**Remember**: A good forensic report tells a story that can be understood by judges, lawyers, and executives - while remaining technically accurate for peer review.
