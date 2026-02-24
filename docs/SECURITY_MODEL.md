# FEPD Security Model & ML Data Policy

## 🔐 EXECUTIVE SUMMARY

**CRITICAL ARCHITECTURE STATEMENT:**

> "FEPD uses dataa/ as a temporary training workspace for feature extraction and model building, which is securely wiped after training, while only trained models are persisted for inference."

This document defines the security boundaries, data lifecycle rules, and court-defensible practices for FEPD's machine learning system.

---

## 🏗️ DIRECTORY ROLES (LOCKED DESIGN)

### ✅ **training_data/** — PERSISTENT, CURATED

**Purpose:** Source of truth for ML training

**Contains:**
- Public datasets (EMBER, BODMAS, CIC-IDS, etc.)
- Clean baselines
- Labeled/unlabeled corpora

**Rules:**
- ❌ Never modified automatically
- ✅ Only updated manually by data engineers
- ✅ Version controlled
- ✅ Immutable once validated

**Structure:**
```
training_data/
 ├── malware/        # Malware samples & labels
 ├── network/        # Network traffic datasets
 ├── logs/           # Log datasets
 └── memory/         # Memory dump datasets
```

---

### ✅ **dataa/** — TEMPORARY TRAINING WORKSPACE ONLY

**Purpose:** Temporary extraction workspace during training

**Used for:**
- Unpacking datasets
- Parsing raw samples
- Artifact extraction
- Feature generation
- Batching
- Normalization

**Structure:**
```
dataa/
 ├── raw_unpack/     # Temporary raw data
 ├── parsed/         # Parsed artifacts
 ├── artifacts/      # Extracted artifacts
 ├── features/       # Generated features
 └── temp_cache/     # Temporary cache
```

**CRITICAL RULES:**
- 🔥 **DELETED after training**
- ❌ No case IDs
- ❌ No evidence
- ❌ No audit logs
- ❌ No persistence
- ❌ **MUST NOT exist during inference**

**Security Guarantee:**
```python
IF mode == INFERENCE:
    assert not dataa_path.exists()
```

---

### ✅ **src/ml/data/** — PERSISTENT ML TRAINING DATA

**Purpose:** Curated, schema-validated ML datasets

**Contains:**
- Clean CSV datasets
- Schema definitions
- Dataset metadata
- Integrity hashes

**Structure:**
```
src/ml/data/
 ├── malware/
 │    ├── file_features_v1.csv
 │    ├── labels.csv
 │    ├── schema.json
 │    └── dataset.meta.json
 ├── evtx/
 ├── network/
 ├── cloud/
 └── ueba/
```

**Rules:**
- ✅ Only source for ML training
- ✅ Schema-validated
- ✅ Version controlled
- ✅ Integrity-checked (SHA-256)

---

### ✅ **models/** — PERSISTENT TRAINING OUTPUT

**Purpose:** Trained models and metadata only

**Contains:**
- Trained model files (.pkl)
- Model metadata (.meta.json)

**Structure:**
```
models/
 ├── malware_model.pkl
 ├── malware_model.meta.json
 ├── evtx_model.pkl
 ├── evtx_model.meta.json
 └── ...
```

**Rules:**
- ✅ Read-only during inference
- ✅ Updated only during training
- ✅ Version tracked
- ✅ Court-defensible metadata

---

### ✅ **data/** — CASES & INFERENCE RESULTS ONLY

**Purpose:** Case evidence and inference results

**Contains:**
- Case directories
- Evidence artifacts
- Inference reports
- Analyst notes

**CRITICAL RULES:**
- 🚫 **NEVER touched by training**
- 🚫 **NEVER mixed with dataa/**
- ✅ Chain of custody maintained
- ✅ Evidence integrity enforced

---

## 🔁 COMPLETE TRAINING WORKFLOW

### Step-by-Step Training Lifecycle

```
┌─────────────────────────────────────┐
│ 1. START TRAINING                   │
│    python -m src.ml.training_orch   │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ 2. ENTER TRAINING MODE              │
│    - Verify system ready            │
│    - Create EMPTY dataa/            │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ 3. LOAD RAW DATA                    │
│    - From training_data/            │
│    - Stream into dataa/             │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ 4. EXTRACT & NORMALIZE              │
│    - Parse raw formats              │
│    - Extract features               │
│    - Emit CSV → src/ml/data/        │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ 5. VALIDATE DATA QUALITY            │
│    - Schema compliance              │
│    - Null ratios < 10%              │
│    - Feature distributions          │
│    - FAIL if invalid                │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ 6. TRAIN ML MODELS                  │
│    - Read from src/ml/data/         │
│    - Train each model               │
│    - Generate explainability        │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ 7. SAVE MODELS                      │
│    - Save .pkl → models/            │
│    - Save .meta.json → models/      │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ 8. GENERATE METADATA                │
│    - Training date                  │
│    - Dataset hash                   │
│    - Hyperparameters                │
│    - Sample count                   │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ 9. WIPE dataa/ COMPLETELY           │
│    - Recursive delete               │
│    - Verify non-existence           │
│    - FAIL if wipe fails             │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│ 10. ENTER INFERENCE MODE            │
│     - Verify dataa/ gone            │
│     - Set read-only models          │
│     - Block training ops            │
└─────────────────────────────────────┘
```

**After Step 10:**
- ✅ No raw data remains
- ✅ Only models exist
- ✅ Ready for forensic inference

---

## ⚖️ SECURITY PRINCIPLES

### 1. Training/Inference Separation

**Rule:** Training and inference are mutually exclusive modes.

```python
# Enforced by TrainingStateController
if mode == TRAINING:
    allow_dataa_access()
    block_case_evidence()
else:  # INFERENCE
    block_dataa_access()
    allow_case_evidence()
```

**Why:** Prevents cross-contamination between training data and case evidence.

---

### 2. No Training Data Leakage

**Rule:** Training datasets never enter case directories.

**Enforcement:**
- dataa/ must not exist during inference
- src/ml/data/ is never copied to data/
- Models contain no raw training data

**Why:** Prevents evidence contamination and privacy violations.

---

### 3. Dataset Immutability

**Rule:** Once validated, datasets are frozen.

**Enforcement:**
- dataset.meta.json includes SHA-256 hash
- Training fails if hash mismatch
- Version controlled

**Why:** Reproducible training and court defensibility.

---

### 4. Model Metadata Completeness

**Rule:** Every model must have complete metadata.

**Required Fields:**
- model_name
- model_version
- algorithm
- schema_version
- dataset_hash
- training_date
- sample_count
- hyperparameters

**Why:** Court-defensible ML and audit compliance.

---

### 5. Secure dataa/ Lifecycle

**Rule:** dataa/ must be wiped after every training run.

**Enforcement:**
- Automated wipe in training pipeline
- Verification of non-existence
- Training FAILS if wipe fails

**Why:** Malware datasets and sensitive samples must not persist.

---

## 🛡️ COURT-DEFENSIBLE ML

### Evidence vs. Training Separation

| Aspect | Training Data | Case Evidence |
|--------|--------------|---------------|
| Location | src/ml/data/ | data/cases/ |
| Labeled | Yes (trusted sources only) | NO (never labeled) |
| Used For | Model training | Inference only |
| Integrity | SHA-256 hash | Chain of custody |
| Audit | Dataset metadata | Forensic audit log |

---

### ML Advisory Role

**FEPD ML models are advisory tools, not autonomous decision-makers.**

**Principle:**
> "ML predictions ASSIST analysts; analysts make final determinations."

**Implementation:**
- All ML predictions include explainability (SHAP/LIME)
- Confidence scores displayed
- Analyst feedback captured (but NOT auto-fed to models)
- Final classification requires analyst approval

---

### Explainability Requirements

**Every ML prediction must include:**
1. Feature importance (SHAP values)
2. Local explanation (LIME)
3. Confidence score
4. Model version
5. Training date

**Why:** Court-admissible ML requires transparency.

---

## 🔒 SECURITY GUARANTEES

### 1. No Model Poisoning

**Guarantee:** Runtime evidence is NEVER used to update models.

**Enforcement:**
- Analyst feedback stored separately
- Manual review before any retraining
- Training mode requires explicit activation

---

### 2. No Evidence Corruption

**Guarantee:** ML operations never modify case evidence.

**Enforcement:**
- Evidence stored with read-only hashes
- Integrity checks before and after inference
- Audit log tracks all access

---

### 3. No Training Data in Cases

**Guarantee:** Training datasets never appear in case directories.

**Enforcement:**
- Hard mode separation (training vs. inference)
- dataa/ verification
- Directory structure isolation

---

## 📜 COMPLIANCE STATEMENTS

### For Auditors

"All machine learning models in FEPD are trained exclusively on curated, schema-validated datasets stored in the ML data layer, which are transiently generated from the dataa workspace and never trained directly from runtime artifacts."

### For Court

"FEPD ML predictions are generated using pre-trained models with full explainability (SHAP/LIME), traceable metadata, and version-controlled training datasets, ensuring reproducibility and transparency."

### For Certifications

"FEPD enforces strict separation between training data and case evidence through mode-controlled access, secure workspace cleanup, and integrity verification, preventing cross-contamination and ensuring chain of custody."

---

## 🚀 OPERATIONAL PROCEDURES

### Starting Training

```bash
# 1. Verify current mode
python -m src.ml.training_orchestrator status

# 2. Enter training mode
python -m src.ml.training_orchestrator mode --training

# 3. Populate dataa/ with raw sources (manual)
# Copy datasets from training_data/ or download

# 4. Run complete training
python -m src.ml.training_orchestrator train

# 5. Verify inference mode
python -m src.ml.training_orchestrator status
```

### Starting Inference

```bash
# 1. Verify dataa/ does not exist
ls dataa/  # Should not exist

# 2. Enter inference mode
python -m src.ml.training_orchestrator mode --inference

# 3. Run FEPD application
python main.py
```

---

## ⚠️ FORBIDDEN ACTIONS

### ❌ NEVER DO THIS

1. **Train from data/cases/** — Case evidence must never train models
2. **Mix dataa/ with data/** — Training workspace must stay isolated
3. **Auto-update models from inference** — Prevents model poisoning
4. **Skip dataa/ wipe** — Security violation
5. **Label runtime evidence** — Evidence is unlabeled by design
6. **Run training during active case** — Mode violation

---

## ✅ FINAL CHECKLIST

Before deploying FEPD:

- [ ] Training pipeline tested end-to-end
- [ ] dataa/ wipe verified working
- [ ] Mode controller prevents violations
- [ ] All models have metadata
- [ ] Explainability tested
- [ ] Audit logging functional
- [ ] Documentation complete
- [ ] Security policy reviewed

---

## 📞 CONTACTS

**For security questions:** See `src/core/training_state.py`  
**For training pipeline:** See `src/ml/training_orchestrator.py`  
**For data policies:** See `src/ml/data/README.md`

---

**Document Version:** 1.0  
**Last Updated:** January 8, 2026  
**Approved By:** FEPD Development Team
