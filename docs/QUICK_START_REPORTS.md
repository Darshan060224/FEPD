# 🚀 Quick Start: Generate Your First FEPD Report

## Prerequisites

✅ ReportLab installed (`pip install reportlab`)  
✅ Case created with forensic image ingested  
✅ Timeline and artifacts processed  

---

## 🎯 3-Step Report Generation

### Step 1: Open Your Case
```
1. Launch FEPD
2. Click "Open Existing Case" or create new case
3. Wait for case data to load
```

### Step 2: Generate Report
```
Method A: Menu Bar
- File → Generate Report (Ctrl+R)

Method B: Report Tab
- Navigate to "Report" tab
- Click "Generate PDF Report" button
```

### Step 3: View Report
```
✅ Report saved to: cases/{case_id}/report/
✅ Automatic hash verification
✅ Metadata JSON included
```

---

## 📋 Report Sections Generated

| Section | Content | Pages |
|---------|---------|-------|
| 🖼️ Header | Logo, branding, case ID | 1 |
| 📘 Case Summary | Case details, examiner info | 1 |
| 📂 Evidence | Image hash, artifacts count | 1 |
| 📊 Timeline | Event statistics, classifications | 2-5 |
| 🔍 Flagged Events | Suspicious activities | 2-10 |
| 📑 Artifacts | Detailed logs by type | 5-20 |
| 🔐 Integrity | Hashes, Chain of Custody | 2-3 |
| 📎 Appendices | Paths, config, disclaimer | 2-3 |

**Total**: ~15-45 pages (varies by case complexity)

---

## ⚡ Performance Tips

| Case Size | Events | Artifacts | Time | Report Size |
|-----------|--------|-----------|------|-------------|
| Small | <10K | <100 | 5-10s | 500KB-1MB |
| Medium | 10K-100K | 100-500 | 10-20s | 1-3MB |
| Large | 100K-1M | 500+ | 20-40s | 3-8MB |
| Very Large | >1M | >1000 | 40-60s | 8-15MB |

---

## 🔍 What's Included

### ✅ Automatically Detected

- **System artifacts**: Registry, EVTX, MFT, Prefetch
- **User activity**: Browser history, LNK files, Recent documents
- **Suspicious events**: Anomalies, malware indicators
- **Timeline analysis**: Event bursts, idle gaps
- **Hash verification**: SHA-256 for all evidence
- **Chain of Custody**: Complete audit trail

### 📊 Visual Elements

- **Tables**: Sortable, color-coded by severity
- **Statistics**: Event counts, time spans
- **Classifications**: Normal/Suspicious/Critical
- **Branding**: Custom logo and colors

---

## 🎨 Customization Quick Guide

### Change Organization Name
```python
# Edit: src/utils/report_generator.py
ORGANIZATION = "Your Lab Name Here"
```

### Change Logo
```bash
# Replace: logo/logo.png
# Recommended: 300x300px PNG
```

### Change Colors
```python
# Edit: src/utils/report_generator.py
COLOR_PRIMARY = colors.HexColor("#your_hex_color")
```

---

## ✅ Quality Checklist

Before distributing reports, verify:

- [ ] Case metadata complete (examiner, case ID, dates)
- [ ] Evidence image hash matches original
- [ ] Chain of Custody verified (no broken links)
- [ ] All artifact sections populated
- [ ] Flagged events reviewed by examiner
- [ ] Report hash calculated and recorded
- [ ] Confidentiality markings present
- [ ] Legal disclaimer included

---

## 🔐 Security Best Practices

### Storage
```
✅ Store in encrypted containers
✅ Use secure file sharing (not email)
✅ Apply access controls
✅ Log all report access
```

### Distribution
```
✅ Password-protect PDFs
✅ Use secure channels only
✅ Mark as CONFIDENTIAL
✅ Track distribution recipients
```

### Retention
```
✅ Follow organizational policies
✅ Archive with case files
✅ Include in CoC log
✅ Secure deletion when disposed
```

---

## 📞 Troubleshooting

### Report Generation Fails

**Check:**
1. ReportLab installed? `pip list | findstr reportlab`
2. Write permissions? Check `/cases/{case_id}/report/`
3. Disk space? Need 10-50MB free
4. Data available? Timeline/artifacts ingested?

**Fix:**
```bash
# Reinstall ReportLab
pip install --upgrade --force-reinstall reportlab

# Check permissions
icacls "C:\path\to\FEPD\cases"

# Clear temp files
rm -rf cases/*/report/*.tmp
```

### Missing Sections

**If timeline empty:**
- Ingest forensic image first
- Wait for pipeline completion
- Check logs: `logs/fepd.log`

**If artifacts missing:**
- Verify extraction completed
- Check `cases/{case_id}/artifacts/` folder
- Re-run ingestion if needed

### Hash Mismatch

**Verify report integrity:**
```powershell
# PowerShell
Get-FileHash -Algorithm SHA256 "report.pdf"

# Compare with metadata JSON
Get-Content "report.json" | Select-String "hash"
```

---

## 📚 Examples

### Example 1: Quick Report for Small Case
```
Case: laptop_seizure
Events: 5,234
Artifacts: 87
Time: 8 seconds
Pages: 18
Size: 1.2 MB
```

### Example 2: Comprehensive Report for Investigation
```
Case: corporate_breach_2024
Events: 234,567
Artifacts: 1,847
Time: 35 seconds
Pages: 42
Size: 6.8 MB
```

### Example 3: Minimal Report (Evidence Only)
```
Case: quick_triage
Events: 0 (no ingestion)
Artifacts: 23 (manual extraction)
Time: 3 seconds
Pages: 8
Size: 450 KB
```

---

## 🎓 Training Resources

- **Video Tutorial**: [YouTube - FEPD Report Generation](https://youtube.com/watch?v=example)
- **Sample Reports**: See `/examples/sample_reports/`
- **Best Practices**: Read [REPORT_GENERATION.md](./REPORT_GENERATION.md)
- **Advanced Topics**: [Customization Guide](./CUSTOMIZATION.md)

---

## 💡 Pro Tips

1. **Generate Early**: Create interim reports during investigation
2. **Version Control**: Keep dated copies of reports
3. **Peer Review**: Have reports reviewed before submission
4. **Test Prints**: Verify formatting with test print
5. **Backup Metadata**: Archive `.json` files with reports
6. **Custom Sections**: Add case-specific notes in appendix
7. **QA Process**: Use quality checklist before delivery

---

## ✨ Feature Highlights

### What Makes FEPD Reports Professional?

✅ **Court-Ready**: Includes all required forensic documentation  
✅ **Branded**: Custom logo and organization details  
✅ **Verified**: Cryptographic hashes for integrity  
✅ **Comprehensive**: All artifacts and timeline in one place  
✅ **Searchable**: PDF text searchable (not scanned images)  
✅ **Printable**: Optimized for professional printing  
✅ **Secure**: Confidentiality markings on every page  
✅ **Traceable**: Complete chain of custody included  

---

**Ready to generate your first report? Open FEPD and press Ctrl+R!**

---

*FEPD v1.0.0 - Professional Forensic Reporting*  
---

*© 2025 Darshan Research Lab*
