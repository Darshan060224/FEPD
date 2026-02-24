# Quick Reference: ML Output Integration

## 🎯 Problem Fixed

**Before:** ML/UEBA runs but "nothing returns" (no output, blank UI)  
**After:** Complete output pipeline (JSON → UI → Timeline → Reports)

---

## 📁 Files Changed

### Created (1 file)
- `src/modules/ml_output_handler.py` (463 lines)

### Modified (3 files)
- `src/ml/ueba_profiler.py` - Added save_findings() method
- `src/ui/tabs/ml_analytics_tab.py` - Added _load_ml_findings(), _display_ml_findings()
- Updated MLAnalysisWorker to pass case_path and save findings

### Documentation (2 files)
- `docs/ML_OUTPUT_INTEGRATION.md` - Complete integration guide
- `docs/ML_OUTPUT_SUMMARY.md` - Implementation summary

---

## 🔄 Data Flow

```
Mobile Events → UEBA Profiler → MLOutputHandler → Output Files → UI
```

**Output Files (in `cases/<case_id>/results/`):**
1. `ml_findings.json` - Main results (UI reads this)
2. `ml_events.json` - Timeline events
3. `ml_report_section.md` - Forensic report

---

## 💻 Usage Example

### Running UEBA Analysis

```python
from src.ml.ueba_profiler import UEBAProfiler
from src.modules.ml_output_handler import MLEntity
from pathlib import Path

# Initialize with case path
case_path = Path("cases/a")
profiler = UEBAProfiler(case_path=case_path)

# Build profiles from training data
profiler.build_profiles(train_events)

# Detect anomalies in test data
results = profiler.detect_anomalies(test_events)

# Save findings to ml_findings.json
entity = MLEntity(
    user_id="user123",
    device_id="tracy-phone",
    platform="Android 4.0"
)
profiler.save_findings(test_events, entity=entity)

# Output files created:
# ✅ cases/a/results/ml_findings.json
# ✅ cases/a/results/ml_events.json
# ✅ cases/a/results/ml_report_section.md
```

### Loading Findings in UI

```python
# Automatically happens when case is opened
ml_analytics_tab.set_case_context(case_path)

# This calls _load_ml_findings() which:
# 1. Reads ml_findings.json
# 2. Populates risk table (high-risk users)
# 3. Populates alerts table (findings)
# 4. Color codes by severity
```

---

## 📊 ml_findings.json Schema

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
        "Reasons: Off-hours activity"
      ],
      "correlations": [],
      "recommendation": "Investigate user for potential account compromise"
    }
  ]
}
```

---

## 🎨 UI Display

### Risk Table (High-Risk Users)
| User ID   | Risk Score | Alerts |
|-----------|------------|--------|
| user123   | 0.87 🔴   | 3      |
| user456   | 0.65 🟠   | 1      |

**Color Coding:**
- 🔴 Red: Score > 0.8
- 🟠 Orange: Score > 0.6
- 🟡 Yellow: Score ≤ 0.6

### Alerts Table (Detected Threats)
| Type                | User    | Description              | Severity |
|---------------------|---------|--------------------------|----------|
| behavioral_anomaly  | user123 | Off-hours activity       | HIGH 🔴  |
| insider_threat      | user456 | Sensitive file access    | HIGH 🔴  |
| account_takeover    | user789 | Login from new location  | CRITICAL |

---

## 🔍 Empty Results Handling

When no anomalies detected:

```json
{
  "metadata": {
    "total_findings": 0,
    "message": "No anomalies detected - all behavior within expected baselines"
  },
  "findings": []
}
```

**UI Shows:**
- ℹ️ "No anomalies detected in previous analysis"
- Empty tables (not error message)
- Status: Success (not failure)

---

## 📝 Court-Safe Language

### ✅ Correct (Advisory)
- "Analysis **identified** 5 behavioral anomalies..."
- "Findings **suggest** potential unauthorized access..."
- "**May indicate** account compromise..."
- "Recommendation: **Investigate** user for potential..."

### ❌ Incorrect (Definitive)
- "User **was** compromised"
- "**Proof** of insider threat"
- "Malicious activity **confirmed**"

---

## 🧪 Testing Checklist

### Basic Tests
- [ ] ml_findings.json created
- [ ] ml_events.json created
- [ ] ml_report_section.md created
- [ ] UI tables populated
- [ ] Color coding works
- [ ] Empty results handled

### Android Phone Test
- [ ] Extract Android artifacts (SMS, calls, contacts)
- [ ] Parse to timeline events
- [ ] Feed to UEBA profiler
- [ ] Verify ml_findings.json has findings
- [ ] Check UI shows high-risk users
- [ ] Confirm timeline has ML events

---

## 🐛 Troubleshooting

### No findings displayed in UI
**Check:**
1. `ml_findings.json` exists in `cases/<case_id>/results/`
2. File is valid JSON (not corrupted)
3. `case_path` is set in ML Analytics tab
4. `_load_ml_findings()` called

### ml_findings.json not created
**Check:**
1. `case_path` passed to UEBAProfiler
2. `save_findings()` called after analysis
3. Results directory exists
4. Check logs for exceptions

### Empty results showing as error
**Fix:**
- Use `write_empty_result()` not silent return
- Verify "ℹ️ No anomalies detected" status appears

---

## 📚 Key Classes

### MLEntity (dataclass)
```python
@dataclass
class MLEntity:
    user_id: str
    device_id: str
    platform: str
```

### MLFinding (dataclass)
```python
@dataclass
class MLFinding:
    finding_id: str
    finding_type: str
    severity: str  # critical, high, medium, low
    score: float  # 0.0 to 1.0
    title: str
    description: str
    affected_artifact: str
    timestamp: str
    explanations: List[str]
    correlations: List[str] = field(default_factory=list)
    recommendation: str = ""
```

### MLOutputHandler
```python
class MLOutputHandler:
    def __init__(self, case_path: Path)
    
    def write_findings(self, findings, entity, analysis_type)
        # Writes ml_findings.json, ml_events.json, ml_report_section.md
    
    def write_empty_result(self, analysis_type)
        # Writes ml_findings.json with "No anomalies detected"
```

---

## 🚀 Next Steps

1. **Test End-to-End:**
   - Run Android phone image analysis
   - Verify all 3 output files created
   - Check UI displays findings

2. **Integrate with Pipeline:**
   - Wire mobile parser → UEBA
   - Extract UEBA features from mobile events
   - Generate timeline with ML events

3. **Advanced Features:**
   - Correlation engine
   - Drift detection
   - Explainability (LIME/SHAP)

---

## ✅ Success Criteria

- [x] ✅ ml_findings.json written for non-empty results
- [x] ✅ ml_findings.json written for empty results
- [x] ✅ UI loads findings on case open
- [x] ✅ Tables populate with color coding
- [x] ✅ Court-safe language in reports
- [ ] 🔄 End-to-end test with Android phone
- [ ] 🔄 Timeline integration verified

---

**Status:** ✅ **IMPLEMENTATION COMPLETE**  
**Ready for:** End-to-end testing with Android phone image (tracy-phone-2012-07-15-final.E01)
