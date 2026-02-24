# 📄 FEPD Report Generation Guide

## Overview

FEPD includes a comprehensive **Professional PDF Report Generator** that creates detailed forensic analysis reports with custom branding, timeline analysis, artifact logs, and integrity verification.

---

## ✨ Report Features

### 🖼️ Header Section with Branding

- **Application Logo**: FEPD logo prominently displayed
- **Application Name**: Forensic Evidence Parser Dashboard (FEPD)
- **Version Number**: Current version (e.g., v1.0.0)
- **Organization**: Darshan Research Lab
- **Report Metadata**:
  - Report ID (auto-generated)
  - Report Date (UTC timestamp)
  - Case ID reference

### 📘 Case Summary

Complete case information including:
- Case Name and ID
- Investigator/Examiner details
- Date created and status
- Time zone configuration
- Evidence source details:
  - Image filename and path
  - SHA-256 hash verification
  - File size and format (E01, RAW, DD, etc.)
  - System platform (Windows/Linux/macOS)

### 📂 Ingested Evidence Overview

Detailed evidence metadata:
- Disk image path and type
- Cryptographic hashes (SHA-256, MD5)
- Chain of Custody file path
- Total artifacts extracted
- Artifact types discovered:
  - Registry hives
  - EVTX logs
  - MFT entries
  - Prefetch files
  - Browser artifacts
  - LNK files
  - Linux configuration files
  - System logs
  - Scripts and binaries

### 📊 Timeline Summary

Statistical analysis of timeline events:
- **Total Event Count**: Number of parsed events
- **Time Span**: Earliest to latest timestamp
- **Events by Artifact Type**: Distribution chart
- **Event Classifications**: 
  - Normal events
  - Suspicious events
  - Anomalous events
  - Critical events
- **Idle Gaps Detection**: Suspicious time gaps
- **Event Bursts**: High-activity periods

### 🔍 Flagged Events & Highlights

Automatically identified suspicious activities:
- **Suspicious Events Table**:
  - Timestamp
  - Event type
  - Description
  - Classification reason
  - Anomaly score
- **Highlighted Categories**:
  - Remote access indicators
  - Malware indicators
  - File deletion events
  - Anti-forensics markers
  - Unusual system modifications
  - Privilege escalations

### 📑 Detailed Artifact Logs

Comprehensive tables for each artifact type:

#### EVTX Logs
- Timestamp
- Event ID
- Provider
- Event message

#### Registry Keys
- Key path
- Value name
- Data content
- Last write time

#### MFT Entries
- Filename
- MACB timestamps (Modified, Accessed, Created, Born)
- File size
- Full path

#### Prefetch Files
- Executable name
- Run count
- Last executed timestamp

#### Browser Artifacts
- URL visited
- Visit timestamp
- Browser type (Chrome, Firefox, Edge, etc.)

#### LNK Files
- Target path
- Access timestamp
- Creation time

#### Additional Artifacts
- SRUM (System Resource Usage Monitor)
- AmCache
- ShimCache
- USB history
- Network connections

### 🔐 Hashes and Integrity Proof

Cryptographic verification section:
- **Evidence Image Hash**:
  - SHA-256 hash value
  - MD5 hash (optional)
- **Artifact Hashes**: Individual hashes for each extracted artifact
- **Report Hash**: SHA-256 of the final PDF report
- **Chain of Custody Summary**:
  - Total CoC entries
  - First and last CoC entry details
  - Hash chain verification status
  - Append-only log integrity proof

### 📎 Appendices

Supporting documentation:
- **A. Configuration Options**:
  - Timestamp format settings
  - Parser versions
  - Analysis parameters
- **B. Artifact Paths**:
  - Full file system paths
  - Case directory structure
- **C. Parsing Errors** (if any):
  - Error descriptions
  - Affected files
  - Recovery attempts
- **D. Classification Rules**:
  - Rule hit summary
  - Suspicious patterns detected
- **E. Legal Disclaimer**:
  - Report usage terms
  - Examiner responsibilities

---

## 🎨 Design and Branding

### Color Scheme (Dark Indigo Theme)

- **Primary**: Deep Indigo (#1a237e) - Section headers
- **Secondary**: Lighter Indigo (#3949ab) - Subsections
- **Accent**: Accent Indigo (#5c6bc0) - Tables
- **Warning**: Orange (#ff6f00) - Warnings
- **Danger**: Red (#c62828) - Critical events
- **Success**: Green (#2e7d32) - Verified items

### Typography

- **Headers**: Helvetica Bold
- **Body Text**: Helvetica Regular
- **Code/Hashes**: Courier (monospace)
- **Sizes**: 8-24pt based on hierarchy

### Layout

- **Page Size**: US Letter (8.5" x 11")
- **Margins**: 0.75" all sides
- **Header Space**: 1" top margin
- **Footer**: Page numbers + case ID
- **Confidentiality Watermark**: On every page

---

## 📋 How to Generate a Report

### Method 1: From Menu Bar

1. Open FEPD application
2. Load or create a case
3. Navigate to **File** → **Generate Report** (or use **Ctrl+R**)
4. Wait for report generation (progress dialog shown)
5. Report saved to `/cases/{case_id}/report/` directory

### Method 2: From Report Tab

1. Navigate to the **Report** tab
2. Click **"Generate PDF Report"** button
3. Review report options (if prompted)
4. Click **"Generate"**
5. Report opens automatically after generation

### Method 3: Programmatic Generation

```python
from src.utils.report_generator import ReportGenerator

# Initialize generator
report_gen = ReportGenerator(
    case_metadata=case_metadata,
    case_path=Path("/path/to/case"),
    classified_df=timeline_dataframe,
    artifacts_data=artifacts_list,
    coc_log_path=Path("/path/to/coc.log")
)

# Generate report
report_path = report_gen.generate_report()
print(f"Report saved to: {report_path}")
```

---

## 🔍 Report Output

### File Structure

```
cases/
└── {case_id}/
    └── report/
        ├── FEPD_Report_{case_id}_{timestamp}.pdf  # Main report
        └── FEPD_Report_{case_id}_{timestamp}.json # Metadata
```

### PDF Metadata

The report includes embedded PDF metadata:
- **Title**: Case ID and report type
- **Author**: Organization name
- **Subject**: Forensic analysis report
- **Creator**: FEPD version
- **Keywords**: Case ID, forensic, evidence

### JSON Metadata File

Accompanying `.json` file contains:
```json
{
  "report_id": "FEPD_Report_case1_20251110_173045",
  "case_id": "case1",
  "generated_timestamp": "2025-11-10T17:30:45.123456+00:00",
  "report_path": "/cases/case1/report/FEPD_Report_case1_20251110_173045.pdf",
  "report_hash_sha256": "abc123...",
  "generator": "Forensic Evidence Parser Dashboard v1.0.0",
  "organization": "Darshan Research Lab"
}
```

---

## 🔐 Report Verification

### Hash Verification

Verify report integrity using the provided hash:

**Windows PowerShell:**
```powershell
Get-FileHash -Algorithm SHA256 "FEPD_Report_case1_20251110_173045.pdf"
```

**Linux/macOS:**
```bash
sha256sum FEPD_Report_case1_20251110_173045.pdf
```

Compare the output with the hash in the `.json` metadata file.

### Chain of Custody Verification

The report includes Chain of Custody verification:
1. Check CoC log path in report
2. Verify hash chain integrity
3. Confirm first and last entry hashes
4. Review all custody events

---

## 🛠️ Customization

### Branding Customization

Edit `src/utils/report_generator.py`:

```python
# Branding configuration
APP_NAME = "Your Organization Name"
APP_SHORT_NAME = "YOUR_ACRONYM"
APP_VERSION = "v2.0.0"
ORGANIZATION = "Your Department/Lab"
```

### Logo Customization

Replace logo file:
```
logo/
└── logo.png  # Must be PNG format, recommended 300x300px
```

### Color Scheme

Modify color constants in `ReportGenerator` class:

```python
COLOR_PRIMARY = colors.HexColor("#your_color")
COLOR_SECONDARY = colors.HexColor("#your_color")
# ... etc
```

### Custom Sections

Add custom sections by extending `_build_custom_section()` method:

```python
def _build_custom_section(self) -> List:
    """Build custom analysis section."""
    elements = []
    elements.append(Paragraph("🔬 Custom Analysis", self.styles['SectionHeading']))
    # Add your content here
    return elements
```

Then add to `generate_report()`:
```python
story.extend(self._build_custom_section())
```

---

## 📊 Report Statistics

Typical report contains:
- **Pages**: 10-50 pages (depending on case size)
- **File Size**: 500KB - 5MB
- **Generation Time**: 5-30 seconds
- **Tables**: 5-20 detailed tables
- **Images**: Logo + optional charts
- **Hashes**: 10-1000+ artifact hashes

---

## ⚠️ Troubleshooting

### Error: "ReportLab not installed"

**Solution:**
```bash
pip install reportlab
```

### Error: "Logo not found"

**Solution:**
- Ensure `logo/logo.png` exists in project root
- Check file permissions
- Verify image format (PNG only)

### Error: "No classified events available"

**Solution:**
- Ingest a forensic image first
- Wait for pipeline to complete
- Check `classified_events.csv` exists

### Error: "Permission denied writing report"

**Solution:**
- Check write permissions on `/cases/` directory
- Close any open PDF viewers
- Run as administrator (if needed)

### Empty/Missing Sections

**Solution:**
- Verify data availability (artifacts, timeline, etc.)
- Check case metadata completeness
- Review logs for data loading errors

---

## 🔒 Legal and Compliance

### Report Integrity

- **SHA-256 hash** calculated for report verification
- **Chain of Custody** embedded and verified
- **Timestamp** in UTC with local time display
- **Immutable**: Reports are read-only after generation

### Court Admissibility

Reports include all necessary elements for court submission:
- ✅ Examiner identification
- ✅ Evidence hash verification
- ✅ Chain of custody documentation
- ✅ Methodology documentation
- ✅ Timestamp verification
- ✅ Integrity proof (cryptographic hashes)

### Data Privacy

- Reports marked as **CONFIDENTIAL**
- Should be encrypted when transmitted
- Access should be logged and restricted
- Follow organizational data handling policies

---

## 📚 Additional Resources

- [FEPD User Manual](./USER_MANUAL.md)
- [Chain of Custody Guide](./CHAIN_OF_CUSTODY.md)
- [Case Management Documentation](./CASE_MANAGEMENT.md)
- [Development Guide](./DEVELOPMENT.md)

---

## 📞 Support

For issues or questions regarding report generation:

- **GitHub Issues**: [FEPD Issues](https://github.com/your-org/fepd/issues)
- **Email**: support@your-organization.com
- **Documentation**: [Online Docs](https://docs.your-organization.com/fepd)

---

**Generated by FEPD v1.0.0**  
**© 2025 Darshan Research Lab**  
**For Forensic Use Only**
