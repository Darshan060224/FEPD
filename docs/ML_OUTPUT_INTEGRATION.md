# ML Output Integration - Complete Implementation

## Overview

This document describes the complete integration of **MLOutputHandler** to solve the "nothing returns" problem in mobile UEBA analysis.

## Problem Statement

Previously, ML/UEBA analysis would run but produce no visible output:
- ❌ No JSON files saved
- ❌ No results in UI tables
- ❌ No timeline events  
- ❌ No report sections
- ❌ Silent failure on empty results

## Solution: Standardized Output Contract

All ML modules now use `MLOutputHandler` to write standardized output files that the UI/timeline/reports consume.

---

## Architecture

```
┌──────────────────┐
│  Mobile Events   │ (SMS, calls, contacts from Android DB)
└────────┬─────────┘
         ↓
┌──────────────────┐
│  UEBA Profiler   │ (UEBAProfiler.save_findings())
└────────┬─────────┘
         ↓
┌──────────────────┐
│ MLOutputHandler  │ (write_findings() / write_empty_result())
└────────┬─────────┘
         ↓
┌────────────────────────────────────────┐
│ Output Files (cases/<case_id>/results/)│
│  • ml_findings.json                    │
│  • ml_events.json (timeline)           │
│  • ml_report_section.md                │
└────────┬───────────────────────────────┘
         ↓
┌────────────────────────────────────────┐
│         UI Components Read             │
│  • ML Analytics Tab (tables)           │
│  • Timeline Tab (events)               │
│  • Report Generator (markdown)         │
└────────────────────────────────────────┘
```

---

## File Structure

### 1. **ml_findings.json** (Main Results)

```json
{
  "metadata": {
    "analysis_type": "ueba",
    "timestamp": "2024-01-15T10:30:00Z",
    "entity": {
      "user_id": "user123",
      "device_id": "tracy-phone",
      "platform": "Android 4.0"
    },
    "total_findings": 5
  },
  "findings": [
    {
      "finding_id": "UEBA-0001",
      "finding_type": "behavioral_anomaly",
      "severity": "high",
      "score": 0.87,
      "title": "Behavioral anomaly detected for user user123",
      "description": "Off-hours activity, Sensitive file access",
      "affected_artifact": "/data/passwords.txt",
      "timestamp": "2024-01-15T02:15:00Z",
      "explanations": [
        "Anomaly score: 87.00%",
        "Reasons: Off-hours activity, Sensitive file access"
      ],
      "correlations": [],
      "recommendation": "Investigate user user123 for potential account compromise"
    }
  ]
}
```

### 2. **ml_events.json** (Timeline Events)

```json
[
  {
    "timestamp": "2024-01-15T02:15:00Z",
    "category": "UEBA Alert",
    "description": "Behavioral anomaly detected for user user123",
    "details": {
      "finding_id": "UEBA-0001",
      "severity": "high",
      "score": 0.87
    }
  }
]
```

### 3. **ml_report_section.md** (Forensic Report)

```markdown
## Mobile User Entity Behavior Analytics (UEBA)

**Analysis Date:** 2024-01-15 10:30:00 UTC  
**Subject:** Android 4.0 (Device: tracy-phone, User: user123)

### Executive Summary
Analysis identified **5 behavioral anomalies** potentially indicating unauthorized access or malicious activity.

### Findings

#### UEBA-0001: Behavioral anomaly detected for user user123
- **Severity:** HIGH (Score: 0.87/1.00)
- **Artifact:** /data/passwords.txt
- **Timestamp:** 2024-01-15 02:15:00 UTC

**Details:**
Off-hours activity, Sensitive file access

**Indicators:**
- Anomaly score: 87.00%
- Reasons: Off-hours activity, Sensitive file access

**Recommendation:**
Investigate user user123 for potential account compromise

---
```

---

## Implementation Guide

### Step 1: Create MLOutputHandler Instance

```python
from src.modules.ml_output_handler import MLOutputHandler, MLEntity, MLFinding
from pathlib import Path

# In UEBA profiler initialization
class UEBAProfiler:
    def __init__(self, model_dir=None, case_path=None):
        self.case_path = case_path
        self.output_handler = None
        
        if case_path:
            self.output_handler = MLOutputHandler(case_path)
```

### Step 2: Build Findings from Analysis

```python
def save_findings(self, events: pd.DataFrame, entity: MLEntity = None):
    """Analyze events and save findings using MLOutputHandler."""
    
    # Detect anomalies
    results = self.detect_anomalies(events)
    threats = self.detect_insider_threats(events)
    takeovers = self.detect_account_takeover(events)
    
    # Build findings list
    findings = []
    finding_id_counter = 1
    
    # Convert anomalies to MLFinding objects
    anomalies = results[results['ueba_anomaly'] == True]
    for idx, row in anomalies.iterrows():
        finding = MLFinding(
            finding_id=f"UEBA-{finding_id_counter:04d}",
            finding_type="behavioral_anomaly",
            severity="medium" if row['ueba_score'] < 0.7 else "high",
            score=float(row['ueba_score']),
            title=f"Behavioral anomaly detected for user {row.get('user_id', 'Unknown')}",
            description=row.get('anomaly_reasons', 'Deviation from baseline'),
            affected_artifact=str(row.get('file_path', 'N/A')),
            timestamp=str(row.get('timestamp', '')),
            explanations=[f"Anomaly score: {row['ueba_score']:.2%}"],
            recommendation=f"Investigate user {row.get('user_id', 'Unknown')}"
        )
        findings.append(finding)
        finding_id_counter += 1
    
    # Save findings or write empty result
    if len(findings) > 0:
        self.output_handler.write_findings(
            findings=findings,
            entity=entity or MLEntity(user_id="Unknown", device_id="Unknown", platform="Unknown"),
            analysis_type="ueba"
        )
    else:
        self.output_handler.write_empty_result(analysis_type="ueba")
```

### Step 3: Update ML Analysis Worker

```python
# In MLAnalysisWorker._run_ueba_profiling()

from src.ml.ueba_profiler import UEBAProfiler
from src.modules.ml_output_handler import MLEntity

profiler = UEBAProfiler(case_path=self.case_path)

# ... run analysis ...

# Save findings to ml_findings.json
if self.case_path:
    self.progress.emit(97, "Saving findings to ml_findings.json...")
    
    entity = MLEntity(
        user_id=test_df['user_id'].iloc[0] if 'user_id' in test_df.columns else "Unknown",
        device_id=test_df['device_id'].iloc[0] if 'device_id' in test_df.columns else "Unknown",
        platform=test_df['platform'].iloc[0] if 'platform' in test_df.columns else "Unknown"
    )
    
    profiler.save_findings(test_df, entity=entity)
```

### Step 4: Load Findings in UI

```python
# In MLAnalyticsTab.set_case_context()

def set_case_context(self, case_path: Path, ...):
    self.case_path = Path(case_path)
    
    # Load existing ML findings if available
    self._load_ml_findings()

# New method to load findings
def _load_ml_findings(self):
    """Load ML findings from ml_findings.json if it exists."""
    if not self.case_path:
        return
    
    findings_file = self.case_path / "results" / "ml_findings.json"
    if not findings_file.exists():
        return
    
    with open(findings_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    findings = data.get('findings', [])
    metadata = data.get('metadata', {})
    
    if len(findings) == 0:
        self._show_status("ueba", "ℹ️ No anomalies detected")
        return
    
    # Display in UEBA tab
    self._display_ml_findings(findings, metadata)
```

### Step 5: Display Findings in Tables

```python
def _display_ml_findings(self, findings: list, metadata: dict):
    """Display ML findings in UEBA tab tables."""
    
    # Group findings by user for risk table
    user_risks = {}
    for finding in findings:
        user = finding.get('affected_artifact', 'Unknown')
        severity = finding.get('severity', 'low')
        
        if user not in user_risks:
            user_risks[user] = {'count': 0, 'score': 0.0}
        
        user_risks[user]['count'] += 1
        user_risks[user]['score'] += finding.get('score', 0.0)
    
    # Populate risk table (sorted by score)
    sorted_users = sorted(user_risks.items(), key=lambda x: x[1]['score'], reverse=True)
    for user, risk_info in sorted_users:
        row_idx = self.risk_table.rowCount()
        self.risk_table.insertRow(row_idx)
        
        self.risk_table.setItem(row_idx, 0, QTableWidgetItem(user))
        
        score_item = QTableWidgetItem(f"{risk_info['score']:.2f}")
        # Color code by score
        if risk_info['score'] > 0.8:
            score_item.setBackground(QColor(255, 100, 100))  # Red
        self.risk_table.setItem(row_idx, 1, score_item)
        
        self.risk_table.setItem(row_idx, 2, QTableWidgetItem(str(risk_info['count'])))
    
    # Populate alerts table
    for finding in findings:
        row_idx = self.alerts_table.rowCount()
        self.alerts_table.insertRow(row_idx)
        
        self.alerts_table.setItem(row_idx, 0, QTableWidgetItem(finding.get('finding_type')))
        self.alerts_table.setItem(row_idx, 1, QTableWidgetItem(finding.get('affected_artifact')))
        self.alerts_table.setItem(row_idx, 2, QTableWidgetItem(finding.get('description')))
        
        severity_item = QTableWidgetItem(finding.get('severity'))
        # Color code by severity
        if finding.get('severity') == 'critical':
            severity_item.setBackground(QColor(200, 0, 0))
        elif finding.get('severity') == 'high':
            severity_item.setBackground(QColor(255, 100, 100))
        self.alerts_table.setItem(row_idx, 3, severity_item)
```

---

## Testing Workflow

### 1. Run Android Phone Analysis

```python
# In main application
case_path = Path("cases/a")
image_path = Path("C:/Users/darsh/Downloads/tracy-phone-2012-07-15-final.E01")

# Extract mobile artifacts (SMS, calls, contacts)
# Parse to timeline events
# Feed to UEBA profiler

# Expected output:
# cases/a/results/ml_findings.json
# cases/a/results/ml_events.json
# cases/a/results/ml_report_section.md
```

### 2. Verify File Creation

```bash
ls cases/a/results/
# Should see:
#   ml_findings.json
#   ml_events.json
#   ml_report_section.md
```

### 3. Check UI Display

```
ML Analytics Tab > UEBA Profiling
  ✅ High-Risk Users table populated
  ✅ Detected Threats table populated
  ✅ Color coding by severity
  ✅ Status: "✅ Loaded 5 findings from previous analysis"
```

### 4. Verify Timeline Integration

```
Timeline Tab
  ✅ Events with category "UEBA Alert"
  ✅ Timestamps match findings
  ✅ Expandable details with finding_id
```

---

## Court-Safe Language

All report sections use forensically sound language:

**✅ Correct:**
- "Analysis **identified** 5 behavioral anomalies..."
- "Findings **suggest** potential unauthorized access..."
- "Recommendation: **Investigate** user for potential compromise..."

**❌ Incorrect:**
- "User **was** compromised" (definitive claim)
- "Malicious activity **detected**" (assumes guilt)
- "**Proof** of insider threat" (overreach)

---

## Empty Results Handling

When no anomalies are detected:

```json
{
  "metadata": {
    "analysis_type": "ueba",
    "timestamp": "2024-01-15T10:30:00Z",
    "entity": {...},
    "total_findings": 0,
    "message": "No anomalies detected - all behavior within expected baselines"
  },
  "findings": []
}
```

**UI displays:**
- `ℹ️ No anomalies detected in previous analysis`
- Empty tables (not error message)
- Report section: "No significant deviations observed"

---

## Key Benefits

### Before Integration
- ❌ ML runs silently with no output
- ❌ User confusion ("did it work?")
- ❌ No forensic documentation
- ❌ No timeline events
- ❌ No court-usable reports

### After Integration
- ✅ **Persistent output** (ml_findings.json)
- ✅ **UI visibility** (tables populated)
- ✅ **Timeline integration** (ml_events.json)
- ✅ **Forensic reports** (ml_report_section.md)
- ✅ **Empty result handling** (explicit "no findings")
- ✅ **Court-safe language** (advisory, not definitive)

---

## Files Modified

1. **src/modules/ml_output_handler.py** (NEW)
   - MLOutputHandler class
   - MLEntity, MLFinding dataclasses
   - JSON/timeline/report generation

2. **src/ml/ueba_profiler.py**
   - Added `case_path` parameter
   - Added `save_findings()` method
   - Import MLOutputHandler

3. **src/ui/tabs/ml_analytics_tab.py**
   - Added `_load_ml_findings()` method
   - Added `_display_ml_findings()` method
   - Updated `set_case_context()` to load findings
   - Updated `_display_ueba_results()` to reload findings
   - Updated `MLAnalysisWorker` to accept case_path
   - Updated `_run_ueba_profiling()` to save findings

---

## Next Steps

### Phase 1: Core Integration (COMPLETE ✅)
- [x] Create MLOutputHandler
- [x] Integrate with UEBA profiler
- [x] Update ML Analytics tab UI
- [x] Load/display findings

### Phase 2: Full Pipeline Integration
- [ ] Wire mobile parser → UEBA pipeline
- [ ] Extract Android SMS/calls/contacts
- [ ] Generate UEBA features from mobile data
- [ ] Test end-to-end with tracy-phone image

### Phase 3: Advanced Features
- [ ] Correlation engine (cross-artifact linking)
- [ ] Drift detection (baseline changes over time)
- [ ] Explainability (feature importance)
- [ ] Timeline event enrichment

---

## Troubleshooting

### Issue: "No findings displayed in UI"

**Check:**
1. `ml_findings.json` exists in `cases/<case_id>/results/`
2. JSON is valid (not corrupted)
3. `case_path` is set in ML Analytics tab
4. `_load_ml_findings()` called on case context change

### Issue: "ml_findings.json not created"

**Check:**
1. `case_path` passed to UEBAProfiler
2. `save_findings()` called after analysis
3. Results directory exists: `cases/<case_id>/results/`
4. No exceptions in logs

### Issue: "Empty results showing as error"

**Fix:**
- Use `write_empty_result()` not silent return
- Check UI for "ℹ️ No anomalies detected" status
- Verify tables are empty (not error message)

---

## Conclusion

The **MLOutputHandler** provides a standardized output contract that solves the "nothing returns" problem by:

1. **Writing persistent files** (ml_findings.json, ml_events.json, reports)
2. **Providing UI visibility** (tables, timeline, reports)
3. **Handling empty results** (explicit "no findings" message)
4. **Using court-safe language** (advisory recommendations, not definitive claims)

This enables **forensically sound mobile UEBA analysis** with full transparency and documentation.
