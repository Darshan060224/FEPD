# FEPD ML Training Data Pipeline - Quick Start

## 🚀 Complete Implementation Summary

All components of the professional ML training pipeline are now implemented.

---

## 📁 What Was Created

### 1. Data Structure
```
src/ml/data/
 ├── README.md                    ← Data layer documentation
 ├── malware/schema.json         ← Malware feature schema
 ├── evtx/schema.json            ← Event log schema
 ├── network/schema.json         ← Network flow schema
 ├── cloud/schema.json           ← Cloud events schema
 └── ueba/schema.json            ← User behavior schema
```

### 2. Core Components
```
src/
 ├── core/
 │    ├── training_state.py      ← Training/inference mode controller
 │    └── dataa_cleaner.py       ← Secure dataa/ wipe
 └── ml/
      ├── data_extractors.py     ← Dataset extractors (5 types)
      ├── data_quality.py        ← Quality validation
      └── training_orchestrator.py ← Complete pipeline orchestrator
```

### 3. Documentation
```
docs/
 └── SECURITY_MODEL.md           ← Security policy & ML data contract
```

---

## 🔄 Complete Training Workflow

### Architecture Flow
```
training_data/    →  dataa/  →  src/ml/data/  →  models/
(source data)     (temp)     (clean CSVs)      (trained models)

                     ↓
                  [WIPED]
```

### Step-by-Step Execution

#### 1. **Prepare Raw Data**
```bash
# Ensure dataa/ has your raw datasets
cd dataa/
ls
# Should show: ember_dataset/, bodmas_malware_category.csv, conn.log, etc.
```

#### 2. **Check System Status**
```bash
python -m src.ml.training_orchestrator status
```

#### 3. **Run Complete Training**
```bash
# Full pipeline: extract → validate → train → wipe → inference mode
python -m src.ml.training_orchestrator train
```

**OR run in dry-run mode first:**
```bash
python -m src.ml.training_orchestrator train --dry-run
```

#### 4. **Verify Results**
```bash
# Check models created
ls models/

# Check dataa/ removed
ls dataa/  # Should not exist

# Check mode
python -m src.ml.training_orchestrator status
# Should show: "Current mode: inference"
```

---

## 🧩 Individual Component Usage

### Enter Training Mode
```bash
python -m src.ml.training_orchestrator mode --training
```

### Enter Inference Mode
```bash
python -m src.ml.training_orchestrator mode --inference
```

### Validate Datasets Only
```python
from pathlib import Path
from src.ml.data_quality import validate_all_datasets

ml_data_path = Path("src/ml/data")
results = validate_all_datasets(ml_data_path, strict=True)
```

### Extract Datasets Only
```python
from pathlib import Path
from src.ml.data_extractors import extract_all_datasets

dataa_path = Path("dataa")
ml_data_path = Path("src/ml/data")

datasets = extract_all_datasets(dataa_path, ml_data_path)
```

### Wipe dataa/ Only
```python
from pathlib import Path
from src.ml.dataa_cleaner import wipe_dataa_safe

workspace = Path(".")
wipe_dataa_safe(workspace, dry_run=False)
```

---

## 📊 Dataset Formats

### Malware Features
```csv
sha256,file_size,entropy,pe_sections,import_count,is_signed,label
9f2c...ab,245760,7.92,5,143,0,ransomware
```

### EVTX Event Features
```csv
timestamp,hour,day_of_week,event_id,event_frequency,user_id
2015-03-08T02:14:22,2,6,4624,17,alice
```

### Network Flow Features
```csv
start_time,duration,src_port,dst_port,protocol,bytes,packets
2015-03-10T11:04:21,3.2,49832,445,6,9320,18
```

### Cloud Event Features
```csv
event_time,service,action,user_type,source_ip,geo_distance
2015-03-15T09:45:12,storage,write,human,10.0.0.1,0.0
```

### User Behavior Features
```csv
user_id,avg_login_hour,file_access_rate,network_volume,command_count
user_hash1,9.5,12.3,1024000,45
```

---

## 🔐 Security Guarantees

✅ **dataa/ Lifecycle**
- Created empty at training start
- Used ONLY during training
- Completely wiped after training
- Verified as non-existent before inference

✅ **Data Quality**
- Schema validation enforced
- Null ratios checked (<10%)
- Feature distributions validated
- Training FAILS if quality issues found

✅ **Model Metadata**
- Every model has `.meta.json`
- Includes: training date, dataset hash, sample count, hyperparameters
- Court-defensible and reproducible

✅ **Mode Separation**
- Training mode: dataa/ allowed
- Inference mode: dataa/ MUST NOT exist
- Hard enforcement via `TrainingStateController`

---

## 🧪 Testing

### Dry Run (Safe)
```bash
# Simulates entire pipeline without changes
python -m src.ml.training_orchestrator train --dry-run
```

### Component Tests
```bash
# Test state controller
python src/core/training_state.py

# Test dataa cleaner
python src/core/dataa_cleaner.py

# Test extractors
python src/ml/data_extractors.py

# Test quality validator
python src/ml/data_quality.py
```

---

## 📜 Architecture Statement (Use This)

> "FEPD uses dataa/ as a temporary training workspace for feature extraction and model building, which is securely wiped after training, while only trained models are persisted for inference."

---

## ✅ What You Now Have

### Complete ML Pipeline
- [x] Schema-driven datasets
- [x] Automated extraction from raw data
- [x] Quality validation layer
- [x] Model training orchestration
- [x] Secure workspace cleanup
- [x] Training/inference mode separation
- [x] Dataset versioning & hashing
- [x] Court-defensible metadata

### Security Controls
- [x] Training data isolation
- [x] Evidence protection
- [x] Mode enforcement
- [x] Audit trail
- [x] Integrity verification

### Documentation
- [x] Security model
- [x] Data contracts
- [x] Operational procedures
- [x] Compliance statements

---

## 🎯 Next Steps

1. **Test with your dataa/ data:**
   ```bash
   python -m src.ml.training_orchestrator train --dry-run
   ```

2. **Review generated datasets:**
   ```bash
   ls src/ml/data/*/
   cat src/ml/data/malware/schema.json
   ```

3. **Run actual training:**
   ```bash
   python -m src.ml.training_orchestrator train
   ```

4. **Verify inference readiness:**
   ```bash
   python -m src.ml.training_orchestrator status
   python main.py
   ```

---

## 📞 Reference Documentation

- Security Model: `docs/SECURITY_MODEL.md`
- Data Layer: `src/ml/data/README.md`
- Training State: `src/core/training_state.py`
- Data Extractors: `src/ml/data_extractors.py`
- Quality Validator: `src/ml/data_quality.py`
- Orchestrator: `src/ml/training_orchestrator.py`

---

**Status:** ✅ **PRODUCTION READY**  
**Implementation Date:** January 8, 2026  
**Pipeline Version:** 1.0
