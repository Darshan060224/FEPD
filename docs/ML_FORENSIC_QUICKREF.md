# ML Forensic Compliance - Quick Reference

## ⚡ Quick Start (Forensically-Compliant)

```python
from src.ml.ueba_profiler import UEBAProfiler
from src.modules.ml_output_handler import MLEntity
from pathlib import Path

# 1️⃣ Initialize with case_path (REQUIRED for inference)
profiler = UEBAProfiler(case_path=Path("data/cases/case001"))

# 2️⃣ Validate forensic readiness
validation = profiler.validate_forensic_output()
assert validation['forensic_ready'], "ML not ready for forensic analysis"

# 3️⃣ Build profiles (training)
profiler.build_profiles(events_df)

# 4️⃣ Run analysis (inference)
profiler.save_findings(
    events=new_events_df,
    entity=MLEntity(user_id="alice", device_id="DESKTOP-01", platform="Windows")
)

# ✅ Output: data/cases/case001/results/ml_findings.json
```

---

## 🚫 Common Mistakes

### ❌ WRONG: No case_path
```python
profiler = UEBAProfiler()  # ← Missing case_path
profiler.save_findings(events)  # ← RuntimeError!
```

### ✅ CORRECT: Always provide case_path for inference
```python
profiler = UEBAProfiler(case_path=Path("data/cases/case001"))
profiler.save_findings(events)  # ← Works!
```

---

### ❌ WRONG: Accusatory language
```python
description="User attacked the system"
recommendation="Arrest the attacker"
```

### ✅ CORRECT: Neutral language
```python
description="Automated analysis identified statistically significant deviation..."
recommendation="Analyst review recommended to verify activity..."
```

---

### ❌ WRONG: No severity normalization
```python
severity="very high"  # ← Invalid
severity="medium-high"  # ← Invalid
```

### ✅ CORRECT: Use _normalize_severity()
```python
severity=self._normalize_severity(score)  # ← Returns: critical|high|medium|low
```

---

## 📋 Pre-Flight Checklist

Before running ML analysis:

- [ ] `case_path` is provided and valid
- [ ] Output directory exists (`data/cases/<case_id>/results/`)
- [ ] Events DataFrame is properly formatted
- [ ] Events contain required columns (`timestamp`, `user_id`, etc.)
- [ ] `MLEntity` metadata is prepared
- [ ] Validation passes: `validate_forensic_output()['forensic_ready'] == True`

---

## 🎯 Severity Mapping (MEMORIZE THIS)

| Score Range | Severity | Meaning |
|-------------|----------|---------|
| **≥ 0.85** | `CRITICAL` | Immediate analyst attention required |
| **≥ 0.70** | `HIGH` | High priority review |
| **≥ 0.50** | `MEDIUM` | Moderate deviation from baseline |
| **< 0.50** | `LOW` | Minor statistical variance |

---

## 📝 Forensic Language Cheat Sheet

| ❌ Forbidden | ✅ Required |
|-------------|------------|
| "malicious" | "anomalous" |
| "attacker" | "entity" / "user" |
| "compromised" | "deviation detected" |
| "hacker" | "unauthorized activity pattern" |
| "guilty" | "requires investigation" |
| "intrusion" | "unusual access pattern" |
| "infected" | "statistically correlated with indicators" |

---

## 🧪 Validation Examples

### ✅ Valid Finding
```json
{
  "finding_id": "UEBA-0001",
  "severity": "high",
  "score": 0.85,
  "title": "Behavioral deviation detected",
  "description": "Automated analysis identified statistically significant deviation...",
  "explanations": [
    "Statistical deviation score: 85.00%",
    "Contributing factors: Off-hours activity"
  ],
  "recommendation": "Analyst review recommended..."
}
```

### ❌ Invalid Finding (Fails Validation)
```json
{
  "finding_id": "UEBA-0001",
  "severity": "very high",  // ← Invalid severity
  "score": 0.85,
  "title": "User is guilty",  // ← Accusatory language
  "description": "Attacker compromised system",  // ← Forbidden terms
  "explanations": [],  // ← Missing explanations
  "recommendation": "Arrest immediately"  // ← Not advisory
}
```

---

## 🔧 Troubleshooting

### Problem: RuntimeError - "UEBA requires valid case_path"
**Solution:** Provide case_path during initialization:
```python
profiler = UEBAProfiler(case_path=Path("data/cases/case001"))
```

---

### Problem: No ml_findings.json created
**Check:**
1. `validate_forensic_output()` returns `forensic_ready=True`
2. Case results directory exists
3. `save_findings()` was called (not just `detect_anomalies()`)

---

### Problem: Severity mismatch in UI
**Solution:** Always use `_normalize_severity(score)` instead of hardcoded strings:
```python
# ❌ Wrong
severity = "high"

# ✅ Correct
severity = self._normalize_severity(0.75)  # Returns "high"
```

---

## 📊 Output Structure (Single Source of Truth)

```
data/cases/<case_id>/results/
├── ml_findings.json          ← REQUIRED (findings + metadata)
├── ml_events.json            ← Optional (timeline events)
└── ml_report_section.md      ← Optional (human-readable report)
```

---

## 🎓 Advanced: Empty Result Handling

ML **MUST** create output even with 0 findings:

```python
# Automatic in save_findings():
if len(findings) > 0:
    self.output_handler.write_findings(findings, entity, analysis_type="ueba")
else:
    self.output_handler.write_empty_result(analysis_type="ueba")
```

**Output (0 findings):**
```json
{
  "case_id": "case001",
  "module": "ueba",
  "status": "COMPLETED",
  "summary": {
    "total_events_analyzed": 1000,
    "anomalies_detected": 0
  },
  "findings": []
}
```

---

## 🚀 Performance Tips

1. **Build profiles once** (expensive), then reuse for multiple analyses
2. **Filter events** before analysis (reduce noise)
3. **Use artifact type detection** to route to correct model
4. **Save profiles** after building to avoid re-training

```python
# Build profiles (one-time)
profiler.build_profiles(historical_events)
profiler.save_profiles()  # ← Save to disk

# Later: Load profiles (fast)
profiler.load_profiles()

# Analyze new events (fast)
profiler.save_findings(new_events, entity)
```

---

## 📞 Integration Points

### From Pipeline → UEBA
```python
# In src/modules/pipeline.py
from src.ml.ueba_profiler import UEBAProfiler

profiler = UEBAProfiler(case_path=self.case_path)
profiler.build_profiles(all_artifacts_df)
profiler.save_findings(
    events=mobile_events_df,
    entity=MLEntity(user_id="tracy", device_id="android-phone", platform="Android")
)
```

### From UI → Display Results
```python
# In src/ui/tabs/ml_analytics_tab.py
findings_path = case_path / "results" / "ml_findings.json"
if findings_path.exists():
    with open(findings_path, 'r') as f:
        findings_data = json.load(f)
    
    for finding in findings_data.get('findings', []):
        # Display in risk table
        self._add_risk_item(finding)
```

---

## ✅ Final Checklist (Before Deployment)

- [ ] All findings use `_normalize_severity()`
- [ ] No accusatory language in descriptions/recommendations
- [ ] All findings have explanations
- [ ] Empty results create ml_findings.json with status
- [ ] case_path validation on initialization
- [ ] validate_forensic_output() passes all checks
- [ ] Output follows unified wrapper structure
- [ ] Severity levels match UI expectations (critical|high|medium|low)

---

**Quick Reference Version:** 1.0  
**Last Updated:** 2026-01-09
