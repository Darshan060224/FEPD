# FEPD Professional Report Generation Guide

## Overview

The Forensic Evidence Parser Dashboard (FEPD) includes a comprehensive PDF report generation system that produces professional, branded forensic reports suitable for legal proceedings, peer review, and case documentation.

## Features

### 🖼️ Professional Branding
- Custom logo integration (top-left or centered)
- Organization name and contact information
- Version tracking and metadata
- Custom color scheme (Dark Indigo theme)
- Confidential watermarks on each page

### 📘 Comprehensive Content

#### 1. Header Section
- Application name and logo
- Version number (FEPD v1.0.0)
- Organization name
- Report generation date (UTC timestamp)
- Unique report ID and case ID

#### 2. Case Summary
- Case name and ID
- Investigator/examiner information
- Case creation date and time
- Time zone configuration
- Case status

#### 3. Evidence Overview
- Forensic image details:
  - File path and name
  - Image format (E01, RAW, DD, etc.)
  - File size (human-readable)
  - SHA-256 hash (integrity verification)
- System platform identification (Windows/Linux/macOS)
- Artifacts extracted summary:
  - Total artifact count
  - Breakdown by artifact type
  - Registry, EVTX, MFT, Prefetch, Browser history, etc.

#### 4. Timeline Summary
- Total event count
- Earliest and latest timestamps
- Time span coverage
- Event distribution by artifact type (top 10)
- Classification breakdown:
  - Normal events
  - Suspicious events
  - Anomalous events
  - Critical events
- Percentage analysis

#### 5. Flagged Events & Highlights
- Suspicious or anomalous events (color-coded)
- Detailed event table with:
  - Timestamp
  - Event type
  - Description
  - Classification reason
- User activity highlights
- Remote access indicators
- Malware indicators
- File deletion/anti-forensics markers

#### 6. Detailed Artifact Logs
Structured tables for each artifact type:

- **EVTX Logs**: Timestamp, Event ID, Provider, Message
- **Registry Keys**: Key path, Value name, Data, Last write time
- **MFT Entries**: Filename, MACB timestamps, Size, Path
- **Prefetch**: Executable name, Run count, Last executed
- **Browser Artifacts**: URL, Visit timestamp, Browser type
- **LNK Files**: Target path, Access time
- **Linux Configs**: Config files, modification times
- **Linux Logs**: System logs, auth logs, etc.

#### 7. Hashes and Integrity Proof
- SHA-256 hash for evidence image
- SHA-256 hash for generated report
- Chain of Custody summary:
  - Total CoC entries
  - First and last CoC entries
  - Hash chain verification status
- Append-only CoC log reference

#### 8. Appendices
- **Configuration Options**: Timestamp formats, hash algorithms, parser version
- **Case File Paths**: Case directory structure, artifact locations
- **Legal Disclaimer**: Professional usage guidelines
- **Report Signature**: Generator information, timestamp

## Usage

### Generating a Report

1. **From Main Window Menu**:
   ```
   File → Generate Report (or button in Report tab)
   ```

2. **Prerequisites**:
   - Active case must be loaded
   - Forensic image should be ingested (optional but recommended)
   - Artifacts should be extracted (optional)

3. **Process**:
   - Click "Generate PDF Report" button
   - System collects all available data:
     - Case metadata
     - Timeline events (if available)
     - Extracted artifacts
     - Chain of Custody log
   - Progress dialog shows generation status
   - PDF is saved to: `cases/{case_id}/report/FEPD_Report_{case_id}_{timestamp}.pdf`

4. **Output**:
   - PDF report file
   - JSON metadata file (with report hash)

### Installation Requirements

```bash
# Install required dependency
pip install reportlab

# Or install all dependencies
pip install -r requirements.txt
```

### Report Verification

Each report includes:
1. **SHA-256 Hash**: Stored in accompanying `.json` file
2. **Metadata File**: `FEPD_Report_{case_id}_{timestamp}.json`
   - Contains report hash
   - Generation timestamp
   - Case ID reference
   - Generator version

**Verification Process**:
```python
import hashlib
import json

# Load metadata
with open('FEPD_Report_case1_20251110.json', 'r') as f:
    metadata = json.load(f)
    stored_hash = metadata['report_hash_sha256']

# Calculate current hash
hash_obj = hashlib.sha256()
with open('FEPD_Report_case1_20251110.pdf', 'rb') as f:
    while chunk := f.read(8192):
        hash_obj.update(chunk)
    current_hash = hash_obj.hexdigest()

# Verify
if stored_hash == current_hash:
    print("✓ Report integrity verified")
else:
    print("✗ Report has been modified!")
```

## Customization

### Branding Configuration

Edit `src/utils/report_generator.py`:

```python
class ReportGenerator:
    # Branding configuration
    APP_NAME = "Your Organization Name"
    APP_SHORT_NAME = "YOUR_ACRONYM"
    APP_VERSION = "v1.0.0"
    ORGANIZATION = "Your Forensics Lab"
    
    # Theme colors (Hex values)
    COLOR_PRIMARY = colors.HexColor("#1a237e")  # Main color
    COLOR_SECONDARY = colors.HexColor("#3949ab")  # Secondary
    COLOR_ACCENT = colors.HexColor("#5c6bc0")  # Accent
```

### Logo Integration

1. Place your logo at: `logo/logo.png`
2. Recommended size: 150x150 pixels (PNG with transparency)
3. Logo appears on first page header

### Custom Sections

To add custom sections, edit the `generate_report()` method:

```python
# Add custom section
story.extend(self._build_custom_section())
story.append(Spacer(1, 0.2*inch))
```

Implement your custom section builder:

```python
def _build_custom_section(self) -> List:
    """Build custom analysis section."""
    elements = []
    
    elements.append(Paragraph("Custom Section", self.styles['SectionHeading']))
    # Add your content...
    
    return elements
```

## Best Practices

### Report Quality
1. **Always ingest images before generating reports** - provides comprehensive data
2. **Review flagged events** - verify suspicious classifications before distribution
3. **Verify report hash** - ensure report integrity after generation
4. **Store reports securely** - reports contain sensitive forensic data

### Professional Usage
1. **Include case context** - provide complete case metadata during creation
2. **Document examiner actions** - chain of custody captures all modifications
3. **Peer review** - have another examiner review findings before final report
4. **Version control** - keep all report versions with timestamps

### Legal Compliance
1. **Chain of Custody** - maintained automatically, embedded in reports
2. **Hash verification** - evidence integrity tracked from ingestion
3. **Audit trail** - all actions logged with timestamps
4. **Tamper evidence** - report hashes detect any modifications

## Troubleshooting

### Missing ReportLab
```
Error: ReportLab is required for PDF generation
Solution: pip install reportlab
```

### Missing Logo
```
Warning: Logo not found at: logo/logo.png
Solution: Place logo.png in project root/logo/ directory
```

### Empty Report Sections
```
Issue: Some sections show "No data available"
Cause: Image not ingested or pipeline not run
Solution: Ingest forensic image before generating report
```

### Large Reports
```
Issue: Report generation is slow
Cause: Large timeline (>100k events)
Solution: Normal for large cases. Report limits to top results.
```

## Report Example Structure

```
📄 FEPD Forensic Report
├── Header (Logo, Branding, Report ID)
├── Case Summary (2 pages)
│   ├── Case details
│   ├── Investigator info
│   └── Timeline overview
├── Evidence Overview (1-2 pages)
│   ├── Image details
│   ├── Hash verification
│   └── Artifacts summary
├── Timeline Summary (2-3 pages)
│   ├── Statistics
│   ├── Event distribution
│   └── Classification breakdown
├── Flagged Events (Variable)
│   ├── Suspicious events table
│   ├── Anomaly details
│   └── Critical findings
├── Detailed Artifact Logs (10-50 pages)
│   ├── EVTX logs
│   ├── Registry entries
│   ├── MFT records
│   ├── Browser history
│   └── Other artifacts
├── Integrity Proof (1-2 pages)
│   ├── Evidence hashes
│   ├── Chain of custody
│   └── Report hash
└── Appendices (2-3 pages)
    ├── Configuration
    ├── File paths
    └── Legal disclaimer
```

## Future Enhancements

### Planned Features
- [ ] QR code for report verification (links to hash verification portal)
- [ ] Executive summary page with key findings
- [ ] Visual timeline graphs (matplotlib integration)
- [ ] Event heatmaps showing activity bursts
- [ ] Network activity diagrams
- [ ] User behavior analytics
- [ ] Comparison reports (before/after analysis)
- [ ] Export to other formats (HTML, DOCX)
- [ ] Digital signatures for report authentication
- [ ] Template system for custom report formats

### Advanced Options
- [ ] Configurable section ordering
- [ ] Multi-language support
- [ ] Custom branding per organization
- [ ] Report templates library
- [ ] Automated report scheduling

## Support

For issues or feature requests related to report generation:
1. Check logs: `logs/fepd.log`
2. Verify dependencies: `pip list | grep reportlab`
3. Review configuration: `src/utils/report_generator.py`

---

**FEPD Report Generation System**  
Version 1.0.0 | Copyright © 2025 FEPD Development Team  
For Professional Forensic Use Only
