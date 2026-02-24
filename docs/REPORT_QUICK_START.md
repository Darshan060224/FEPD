# FEPD Report Generator - Quick Start

## Generate Your First Forensic Report

### Step 1: Load Your Case (FEPD Terminal)

```bash
# Start FEPD and load a case
use case adcdsc
```

The terminal will automatically detect and mount evidence.

### Step 2: Generate Report

```bash
# Simple report generation
report

# Or with your details
report --analyst "Jane Doe" --org "Security Team"
```

### Step 3: Find Your Report

Reports are saved to:
```
cases/adcdsc/reports/adcdsc_forensic_report_YYYYMMDD_HHMMSS.md
```

### Step 4: View the Report

Open the `.md` file in any markdown viewer, or convert to PDF:

```bash
# Convert to PDF (requires Pandoc)
pandoc cases/adcdsc/reports/*.md -o report.pdf
```

## What's in the Report?

✓ **Executive Summary** - For management and legal teams  
✓ **Evidence Overview** - Hash verification and integrity  
✓ **Artifact Analysis** - What was found and why it matters  
✓ **Timeline Status** - Temporal analysis  
✓ **ML Findings** - Behavioral anomalies explained  
✓ **Chain of Custody** - Legal proof of integrity  
✓ **Recommendations** - What to do next  

## Common Use Cases

### 1. Initial Assessment Report
After evidence ingestion, generate a preliminary report:
```bash
use case my_investigation
report --analyst "Analyst Name"
```

### 2. Progress Report
Generate periodic reports as investigation progresses:
```bash
report --analyst "Team Lead" --org "IR Team"
```

### 3. Final Report
After completing all analysis:
```bash
# Run all analysis first
timeline generate
ml analyze

# Then generate comprehensive report
report --analyst "Lead Investigator" --open
```

## Tips

🔍 **Generate Early** - Create reports early to identify data gaps  
📊 **Include Context** - Reports explain missing data, not just present it  
⚖️ **Court-Ready** - Language is forensically neutral and professional  
🔗 **Chain of Custody** - Every report is logged automatically  

## Troubleshooting

**Q: Report says "No evidence mounted"**  
A: Load case first: `use case <name>` - evidence auto-mounts

**Q: Timeline section is empty**  
A: Generate timeline: `timeline generate`

**Q: No ML results**  
A: Run ML analysis: `ml analyze`

**Q: How to convert to PDF?**  
A: Use Pandoc: `pandoc report.md -o report.pdf`

## Next Steps

1. Generate your first report
2. Review all sections
3. Follow recommendations
4. Re-run analysis as needed
5. Generate updated reports

**Remember**: Good forensic reports tell a story backed by evidence!
