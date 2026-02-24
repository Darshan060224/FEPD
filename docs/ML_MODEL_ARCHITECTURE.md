# FEPD ML Model Architecture Documentation

**Version:** 1.0  
**Last Updated:** January 8, 2026  
**Purpose:** Complete guide to ML model building with forensic artifacts

---

## 🎯 CORE PRINCIPLE (ONE SENTENCE)

**ML never works on E01/DD/IMG directly. ML works on ARTIFACTS extracted from them — and each artifact type has its own ML path.**

---

## 📋 TABLE OF CONTENTS

1. [Evidence Processing Pipeline](#evidence-processing-pipeline)
2. [Feature Extraction Formulas](#feature-extraction-formulas)
3. [Training Strategy](#training-strategy)
4. [Model Evaluation Metrics](#model-evaluation-metrics)
5. [UI Integration Mapping](#ui-integration-mapping)
6. [Court Defensibility](#court-defensibility)

---

## 1️⃣ EVIDENCE PROCESSING PIPELINE

### Step 1: User Uploads Evidence (E01/DD/IMG)
```
User Upload
   ↓
dataa/raw/case_001/disk.E01
```

**What happens:**
- ✅ File stored
- ✅ Hash calculated (MD5, SHA256)
- ✅ Read-only mode activated
- ❌ **NO ML** (pure evidence handling)
- ❌ **NO analysis** (yet)

### Step 2: Disk Image Parsing (NOT ML)
```
Disk Image
   ↓
File System Parser
   ↓
File System View
```

**Output:**
- Partitions identified
- File systems parsed (NTFS, EXT4, FAT32)
- Deleted files recovered
- Metadata extracted
- **Still ❌ NO ML**

### Step 3: Artifact Extraction (THE TURNING POINT)

**Common Forensic Artifacts:**

| Artifact | Source | Purpose |
|----------|--------|---------|
| EVTX | Windows Event Logs | Timeline, user activity |
| Registry | SYSTEM, SOFTWARE, NTUSER.DAT | Persistence, configuration |
| Prefetch | C:\Windows\Prefetch | Program execution |
| Amcache/Shimcache | Registry | Installed/executed apps |
| Browser artifacts | History, downloads, cache | User behavior |
| File metadata | All files | File system analysis |
| Recycle Bin | Deleted items | Deletion timeline |
| LNK files | User profile | User access patterns |
| Log files | Application/system logs | Event correlation |

📌 **This is where data splits into MULTIPLE PATHS**

### Step 4: Artifact → ML Paths

```
┌─────────────┐
│ E01/DD/IMG  │
└──────┬──────┘
       │
       ├─→ EVTX ──────────→ Timeline Anomaly Model
       │
       ├─→ Registry ──────→ Persistence Detection Model
       │
       ├─→ Files ─────────→ Malware Classifier Model
       │
       ├─→ Execution ─────→ Rare Execution Model
       │
       └─→ Browser ───────→ UEBA Model
```

---

## 2️⃣ FEATURE EXTRACTION FORMULAS

### 🟦 A. EVTX (Windows Event Logs)

**Raw EVTX Data:**
- `timestamp`
- `event_id`
- `user`
- `source`
- `description`

**ML Features (Numeric):**

| Feature | Formula/Logic | Purpose |
|---------|---------------|---------|
| `hour` | `hour(timestamp)` | Detect off-hours activity |
| `day_of_week` | `weekday(timestamp)` | Weekly patterns |
| `event_freq` | `count(event_id per hour)` | Burst detection |
| `delta_prev` | `t(current) - t(previous)` | Automation detection |
| `user_event_rate` | `events_by_user / total_events` | User profiling |
| `event_id_encoded` | Categorical encoding | Event type patterns |

**Why:**
- Automation → low `delta_prev`
- Attacks → unusual `hour` (e.g., 3 AM)
- Burst activity → high `event_freq`

**Python Implementation:**
```python
def extract_evtx_features(evtx_df):
    features = pd.DataFrame()
    features['hour'] = pd.to_datetime(evtx_df['timestamp']).dt.hour
    features['day_of_week'] = pd.to_datetime(evtx_df['timestamp']).dt.dayofweek
    features['event_freq'] = evtx_df.groupby('event_id')['timestamp'].transform('count')
    features['delta_prev'] = evtx_df['timestamp'].diff().dt.total_seconds()
    features['user_event_rate'] = evtx_df.groupby('user')['event_id'].transform('count') / len(evtx_df)
    return features
```

### 🟩 B. Registry Artifacts

**Raw Registry Data:**
- `key_path`
- `hive`
- `modified_time`
- `value_type`

**ML Features:**

| Feature | Formula | Purpose |
|---------|---------|---------|
| `path_depth` | `count("\\") in key_path` | Deep = suspicious |
| `mod_hour` | `hour(modified_time)` | Off-hours changes |
| `change_freq` | `modifications per day` | Abnormal activity |
| `autorun_flag` | `1 if key in autorun_list else 0` | Persistence detection |
| `hive_encoded` | Categorical encoding | Registry type |

**Autorun Keys (Examples):**
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\System\CurrentControlSet\Services
```

**Python Implementation:**
```python
AUTORUN_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    # ... more keys
]

def extract_registry_features(registry_df):
    features = pd.DataFrame()
    features['path_depth'] = registry_df['key_path'].str.count('\\\\')
    features['mod_hour'] = pd.to_datetime(registry_df['modified_time']).dt.hour
    features['autorun_flag'] = registry_df['key_path'].apply(
        lambda x: 1 if any(autorun in x for autorun in AUTORUN_KEYS) else 0
    )
    return features
```

### 🟨 C. File System / Malware Artifacts

**Raw File Data:**
- `binary_content`
- `size`
- `timestamps`
- `path`
- `extension`

**ML Features:**

| Feature | Formula | Purpose |
|---------|---------|---------|
| `file_size` | `bytes` | Size anomalies |
| `entropy` | `−Σ(pᵢ log₂ pᵢ)` | Encryption/packing |
| `extension_encoded` | Categorical encoding | File type |
| `path_depth` | Directory depth | Hidden files |
| `created_hour` | `hour(timestamp)` | Creation timing |
| `signed_flag` | `0/1` | Digital signature |
| `pe_characteristics` | PE header features | Executable analysis |

**Entropy Calculation:**
```python
import math
from collections import Counter

def calculate_entropy(data):
    """Calculate Shannon entropy of byte sequence"""
    if not data:
        return 0.0
    
    counter = Counter(data)
    length = len(data)
    
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy
```

**Why High Entropy = Suspicious:**
- Encrypted files: entropy ≈ 7.9-8.0
- Compressed/packed: entropy ≈ 7.5-7.9
- Normal executables: entropy ≈ 5.0-6.5
- Text files: entropy ≈ 3.5-5.0

**Python Implementation:**
```python
def extract_file_features(file_df):
    features = pd.DataFrame()
    features['file_size'] = file_df['size']
    features['entropy'] = file_df['content'].apply(calculate_entropy)
    features['path_depth'] = file_df['path'].str.count('\\\\')
    features['created_hour'] = pd.to_datetime(file_df['created']).dt.hour
    features['signed_flag'] = file_df['is_signed'].astype(int)
    
    # Extension encoding
    from sklearn.preprocessing import LabelEncoder
    le = LabelEncoder()
    features['extension_encoded'] = le.fit_transform(file_df['extension'])
    
    return features
```

### 🟥 D. Execution Artifacts (Prefetch/Amcache)

**Raw Execution Data:**
- `program_name`
- `first_run`
- `last_run`
- `execution_count`
- `file_path`

**ML Features:**

| Feature | Formula | Purpose |
|---------|---------|---------|
| `execution_count` | Number of runs | Frequency analysis |
| `first_run_hour` | `hour(first_run)` | Initial execution timing |
| `last_run_gap` | `now - last_run_time` | Recency |
| `binary_location_depth` | Path depth | Hidden locations |
| `rare_binary_flag` | `1 if count < threshold` | LOLBins detection |

**Python Implementation:**
```python
def extract_execution_features(exec_df):
    features = pd.DataFrame()
    features['execution_count'] = exec_df['run_count']
    features['first_run_hour'] = pd.to_datetime(exec_df['first_run']).dt.hour
    features['last_run_gap'] = (pd.Timestamp.now() - pd.to_datetime(exec_df['last_run'])).dt.total_seconds()
    features['binary_location_depth'] = exec_df['file_path'].str.count('\\\\')
    
    # Rare binary detection (threshold: < 5 executions)
    features['rare_binary_flag'] = (exec_df['run_count'] < 5).astype(int)
    
    return features
```

### 🟪 E. UEBA (User Behavior Analytics)

**Raw User Data:**
- `user_id`
- `login_times`
- `file_accesses`
- `network_activity`
- `commands_executed`

**ML Features:**

| Feature | Formula | Purpose |
|---------|---------|---------|
| `avg_login_hour` | `mean(login hours)` | Typical work hours |
| `file_access_rate` | `files/hour` | Activity level |
| `network_volume` | `bytes/session` | Data transfer |
| `command_rate` | `commands/hour` | Terminal activity |
| `weekend_activity` | `activity on weekends / total` | Work pattern |

**UEBA Principle:**
```
Compare user to THEMSELVES, not others
```

**Python Implementation:**
```python
def extract_ueba_features(user_df):
    features = pd.DataFrame()
    
    # Group by user
    user_groups = user_df.groupby('user_id')
    
    features['avg_login_hour'] = user_groups['login_time'].apply(
        lambda x: pd.to_datetime(x).dt.hour.mean()
    )
    features['file_access_rate'] = user_groups['files_accessed'].sum() / user_groups['session_duration'].sum()
    features['network_volume'] = user_groups['bytes_transferred'].mean()
    features['command_rate'] = user_groups['commands'].count() / user_groups['session_duration'].sum()
    
    return features
```

---

## 3️⃣ TRAINING STRATEGY (WITH YOUR 35GB DATA)

### Data Flow Pipeline
```
dataa/raw/
   ↓
Artifact Extraction
   ↓
Feature CSVs (data/processed/)
   ↓
Model Training (offline)
   ↓
Saved Models (models/)
```

### Training Phases

#### Phase 1: Baseline (Quick Validation)
- **Data:** 5-10 GB sample
- **Purpose:** Validate pipeline, tune features
- **Duration:** 5-10 minutes
- **Output:** Baseline metrics

#### Phase 2: Full Training
- **Data:** Full 35 GB
- **Strategy:** Stratified sampling
- **Duration:** 30-60 minutes
- **Output:** Production models + metadata

#### Phase 3: Model Freeze
- **Action:** Lock models for reproducibility
- **Re-training:** Manual only (not automatic)
- **Versioning:** Git + model hashes

### Model Selection Matrix

| Artifact | Model Type | Why | Training Type |
|----------|------------|-----|---------------|
| EVTX | Isolation Forest | No labels needed | Unsupervised |
| Registry | Isolation Forest | Rare changes | Unsupervised |
| Files | Random Forest | Explainable + accurate | Supervised |
| Execution | K-Means Clustering | Pattern discovery | Unsupervised |
| UEBA | Isolation Forest | Behavior drift | Unsupervised |

### Training Code Structure
```python
# run_ml_training.py
def train_all_models(use_all_data=False):
    """
    Train all artifact-specific models
    
    Args:
        use_all_data: True = 35GB, False = sample
    """
    # 1. EVTX Timeline Anomaly Model
    evtx_df = load_evtx_features(use_all_data)
    evtx_model = IsolationForest(contamination=0.05)
    evtx_model.fit(evtx_df)
    joblib.dump(evtx_model, 'models/evtx_anomaly.pkl')
    
    # 2. Registry Persistence Model
    registry_df = load_registry_features(use_all_data)
    registry_model = IsolationForest(contamination=0.02)
    registry_model.fit(registry_df)
    joblib.dump(registry_model, 'models/registry_anomaly.pkl')
    
    # 3. Malware Classifier (Supervised)
    file_df, labels = load_file_features_with_labels(use_all_data)
    malware_model = RandomForestClassifier(n_estimators=100)
    malware_model.fit(file_df, labels)
    joblib.dump(malware_model, 'models/malware_classifier.pkl')
    
    # 4. Execution Anomaly Model
    exec_df = load_execution_features(use_all_data)
    exec_model = KMeans(n_clusters=5)
    exec_model.fit(exec_df)
    joblib.dump(exec_model, 'models/execution_model.pkl')
    
    # 5. UEBA Model
    ueba_df = load_ueba_features(use_all_data)
    ueba_model = IsolationForest(contamination=0.05)
    ueba_model.fit(ueba_df)
    joblib.dump(ueba_model, 'models/ueba_model.pkl')
```

### Why No Auto-Learning?
```
Forensic ML must be REPRODUCIBLE
Same evidence + same model = same result
Court requirement: Deterministic analysis
```

---

## 4️⃣ MODEL EVALUATION METRICS

### ⚖️ Forensics ≠ Kaggle

**Key Difference:**
- Kaggle: Maximize accuracy
- Forensics: Minimize false negatives (missed threats)

### Minimum Acceptable Metrics

#### Malware Classifier (Supervised)
| Metric | Target | Why |
|--------|--------|-----|
| **Recall** | ≥ 98% | Cannot miss malware |
| **Precision** | ≥ 95% | Minimize false alarms |
| **False Positive Rate** | ≤ 2% | Analyst time expensive |
| **F1 Score** | ≥ 0.96 | Balanced performance |

#### Anomaly / UEBA Models (Unsupervised)
| Metric | Target | Why |
|--------|--------|-----|
| **False Positives** | ≤ 5% | Actionable alerts only |
| **Stability** | 100% | Same input → same output |
| **Explainability** | Mandatory | Court requirement |

### Evaluation Code
```python
from sklearn.metrics import classification_report, confusion_matrix

def evaluate_malware_model(model, X_test, y_test):
    """Evaluate malware classifier"""
    y_pred = model.predict(X_test)
    
    print(classification_report(y_test, y_pred))
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"Confusion Matrix:\n{cm}")
    
    # Calculate metrics
    recall = recall_score(y_test, y_pred, average='weighted')
    precision = precision_score(y_test, y_pred, average='weighted')
    
    assert recall >= 0.98, f"Recall {recall:.2%} below 98% threshold"
    assert precision >= 0.95, f"Precision {precision:.2%} below 95% threshold"
    
    return {
        'recall': recall,
        'precision': precision,
        'f1': f1_score(y_test, y_pred, average='weighted')
    }
```

### ❌ What You NEVER Optimize For
- Raw accuracy alone
- Speed over explainability
- Black-box confidence scores
- Novelty/complexity

---

## 5️⃣ UI INTEGRATION MAPPING

### Critical Rule
```
ML never gives verdicts.
ML gives SIGNALS that humans interpret.
```

### FEPD UI Column Mapping

| UI Column | Source | Example |
|-----------|--------|---------|
| `Timestamp` | Artifact | `2026-01-08 03:47:21` |
| `Event Type` | Artifact | `File Access` |
| `Source` | Artifact | `user_bob` |
| `Anomaly Score` | **ML Model** | `0.91` |
| `Cluster` | **ML Model** | `Cluster 3` |
| `Severity` | Rule Engine | `HIGH` |
| `Flags` | **Explainability Layer** | See below |

### Example: ML Output → UI Display

**ML Model Output:**
```json
{
  "anomaly_score": 0.91,
  "reasons": ["off-hours", "high entropy", "autorun key"],
  "contributing_features": {
    "hour": 3,
    "entropy": 7.8,
    "autorun_flag": 1
  }
}
```

**FEPD UI Shows:**
```
┌─────────────────────────────────────────────────────────┐
│ Severity: HIGH                                           │
│ Anomaly Score: 91%                                       │
│                                                           │
│ Flags:                                                    │
│ • Off-hours activity (3:47 AM vs typical 2:00 PM)       │
│ • High entropy executable (7.8/8.0 - likely packed)     │
│ • Persistence mechanism detected (autorun registry)     │
│                                                           │
│ Recommendation: Investigate immediately                  │
└─────────────────────────────────────────────────────────┘
```

### Explainability Layer (Critical for Court)
```python
# src/ml/explainer.py
class Explainer:
    def explain_anomaly(self, event, model, features):
        """
        Convert ML output to natural language
        
        Returns court-defensible explanation
        """
        explanation = []
        
        # Get SHAP values (feature importance)
        shap_values = self.shap_explainer.explain(features)
        
        # Top 3 contributing features
        top_features = sorted(shap_values, key=abs, reverse=True)[:3]
        
        for feature, importance in top_features:
            if feature == 'hour' and features['hour'] < 6:
                explanation.append(
                    f"Off-hours activity ({features['hour']}:00 vs typical work hours)"
                )
            elif feature == 'entropy' and features['entropy'] > 7.5:
                explanation.append(
                    f"High entropy ({features['entropy']:.1f}/8.0) indicates encryption/packing"
                )
            elif feature == 'autorun_flag' and features['autorun_flag'] == 1:
                explanation.append(
                    "Persistence mechanism detected (registry autorun)"
                )
        
        return {
            'severity': self._calculate_severity(features),
            'flags': explanation,
            'confidence': self._calculate_confidence(shap_values)
        }
```

### Correlation Engine (NOT ML)
```python
def correlate_artifact_signals(artifacts):
    """
    Combine multiple ML model outputs
    Rules-based, explainable
    """
    risk_score = 0
    flags = []
    
    # File flagged as malware
    if artifacts['file']['anomaly_score'] > 0.8:
        risk_score += 40
        flags.append("Malware detected")
    
    # Executed at unusual time
    if artifacts['evtx']['hour_anomaly']:
        risk_score += 30
        flags.append("Off-hours execution")
    
    # Registry persistence
    if artifacts['registry']['autorun_detected']:
        risk_score += 30
        flags.append("Persistence mechanism")
    
    # Calculate severity
    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 50:
        severity = "HIGH"
    else:
        severity = "MEDIUM"
    
    return {
        'severity': severity,
        'risk_score': risk_score,
        'flags': flags
    }
```

---

## 6️⃣ COURT DEFENSIBILITY

### Key Requirements
1. **Reproducibility:** Same evidence + same model = same result
2. **Explainability:** Every detection must be justified
3. **Transparency:** No black boxes
4. **Auditability:** All decisions logged

### Model Documentation Requirements
```python
# Save with each model
model_metadata = {
    'model_type': 'IsolationForest',
    'version': '1.0',
    'training_date': '2026-01-08',
    'training_data_hash': 'sha256:abc123...',
    'hyperparameters': {
        'contamination': 0.05,
        'n_estimators': 100
    },
    'evaluation_metrics': {
        'precision': 0.96,
        'recall': 0.98
    },
    'feature_list': ['hour', 'entropy', 'path_depth', ...]
}

joblib.dump(model_metadata, 'models/evtx_anomaly_metadata.json')
```

### Court-Safe Explanation Template
```
FINDING: Suspicious file detected

BASIS:
1. Machine learning anomaly score: 91%
2. Contributing factors:
   - High entropy (7.8/8.0) indicates file packing/encryption
   - Created at 3:47 AM (outside normal business hours 9AM-5PM)
   - Registry persistence mechanism established
3. Model: Isolation Forest v1.0 (trained 2026-01-08)
4. Reproducible: Re-analysis yields identical result

ANALYST INTERPRETATION:
Characteristics consistent with malware deployment

RECOMMENDATION:
Quarantine system, investigate user activity
```

---

## 📁 PROJECT FILE STRUCTURE

```
FEPD/
├── dataa/                          # Raw forensic data (35GB)
│   ├── raw/                        # E01/DD/IMG uploads
│   ├── malware_sample/             # 57,000 malware samples
│   ├── honeypot.json              # 426MB attack logs
│   ├── 2015-03-05/ ... 2015-04-13/ # Snort IDS logs (70 files)
│   └── data.mdb                    # Database artifacts
│
├── data/processed/                 # Feature CSVs (ML input)
│   ├── evtx_features.csv
│   ├── registry_features.csv
│   ├── file_features.csv
│   ├── execution_features.csv
│   └── ueba_features.csv
│
├── models/                         # Trained ML models
│   ├── evtx_anomaly.pkl
│   ├── registry_anomaly.pkl
│   ├── malware_classifier.pkl
│   ├── execution_model.pkl
│   ├── ueba_model.pkl
│   └── *_metadata.json            # Model documentation
│
├── src/ml/                         # ML modules
│   ├── ml_anomaly_detector.py     # Anomaly detection
│   ├── ueba_profiler.py           # User behavior
│   ├── explainer.py               # Explainability
│   └── feature_extractors/        # Feature engineering
│
├── ml_data_preparation.py          # Feature extraction
├── ml_training_models.py           # Model training
├── run_ml_training.py              # Training pipeline
└── docs/
    └── ML_MODEL_ARCHITECTURE.md    # This document
```

---

## 🔒 MASTER SUMMARY (MEMORIZE THIS)

### One-Sentence Answer
*"We extract numeric features from forensic artifacts stored in dataa/, train multiple specialized ML models offline, and use their explainable outputs during inference to assist investigators without altering evidence."*

### Complete Flow
```
E01/DD/IMG Upload
   ↓
Artifact Extraction (EVTX, Registry, Files, etc.)
   ↓
Feature Engineering (Numbers only)
   ↓
Multiple Specialized ML Models
   ↓
Explainable Outputs
   ↓
Rule-Based Correlation
   ↓
FEPD UI Display (Court-Safe)
```

### Key Principles
✅ Artifact-based ML (not disk images)  
✅ Multiple specialized models (not one big model)  
✅ Feature formulas defined  
✅ Offline training (reproducible)  
✅ Explainable outputs (court-defensible)  
✅ No auto-learning (stability)  
✅ UI shows signals, not verdicts  

---

## 📚 REFERENCES

- NIST Digital Forensics Standards
- SHAP (SHapley Additive exPlanations) Documentation
- scikit-learn Anomaly Detection Guide
- Windows Forensic Artifacts Reference
- Court Admissibility of ML Evidence (2025)

---

**Document Status:** ✅ Complete  
**Review Status:** ✅ Technical Review Complete  
**Court Review:** ⚠️ Pending Legal Review
